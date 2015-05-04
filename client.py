import socket
import sys
import uuid
import hashlib
import time
import getpass
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode

class Connection:
	def __init__(self, c, key, n): 
		#conn is tuple: (IP, port)
		self.conn = c
		self.pubkey = key
		self.num = n
		self.lastMsg = None

class ConnectionHandler:
	def __init__(self):
		self.arr = [None] * 5
		self.size = 0
		self.max = 5

	def addConn(self, tup, key):
		num = self.size + 1
		if num > self.max:
			return None #cannot add another connection, already at max

		c = Connection(tup, key, num)
		self.arr[num-1] = c
		self.size = num
		return c

	def getConn(self, tup):
		for c in self.arr:
			if c == None:
				continue
			if str(c.conn[0]) == str(tup[0]) and str(c.conn[1]) == str(tup[1]):
				return c

		return None

	def removeConn(self, tup):
		i = 0
		for c in self.arr:
			if str(c.conn[0]) == str(tup[0]) and str(c.conn[1]) == str(tup[1]):
				self.size = self.size - 1
				self.arr[i] = None
				return True

			i += 1
		return False

#defines
PUB_KEY_FILE = "CLIENTrsa.pub"		#File that stores the client's public key
PRIV_KEY_FILE = "CLIENTrsa"			#File used to store the client's private key
REFRESH_TIMESTEP = 600				#Time 

blockList = None
#end defines

def sendSocket(s, msg, addr):
	sent = False 
	s.settimeout(30)
	while sent == False:
		try:
			numSent = s.sendto(msg, addr)
			sent = True
		except socket.timeout: #socket.error is subclass
			print "Timeout, trying again later..."
			time.sleep(60) #check back in a minute


def hash_password(password, salt):
	hashedpassword = hashlib.sha256(password.encode()).hexdigest() 
	return hashlib.sha256(hashedpassword.encode() + salt.encode()).hexdigest()

def parseMessage(msg):
	x = []
	c = msg.split(":",1)
	x.append(c[0])
	args = c[1].split(",")
	for arg in args:
		x.append(arg)

	return x

def connect(msgnum, salt):
	username = raw_input("username : ")
	password = getpass.getpass("password : ")
	hashed = hash_password(password, salt)
	#print "salt :", salt
	return "ACK:PASS,"+msgnum+","+username+","+hashed

'''
Helper method to initalize the current IOT's public key
'''
def initPub(pubKey):
	#param: pubKey 		The text form public key of this client

	global IOTpubtext

	IOTpubtext = pubKey

'''
Helper method that creates the message used to tell the IOT the public
key of this client.
'''
def getPubMsg():
	msg = "ACK:ENCRYPT,"
	msg += clientPubText
	return msg

'''
Method that initializes the public and private key's of the client as well 
as the connection handler.
'''
def init():
	global clientPub 			#Object form of the client's public key
	global clientPriv			#Object form of the client's private key (never send)
	global clientPubText		#Textual form of client's public key (used for sending and things)
	global handler
	global blockList			#List of (IP, port) tuples to block

	#Initialize global public key for client
	pub = open(PUB_KEY_FILE, "r");
	clientPubText = pub.read()
	clientPub = RSA.importKey(clientPubText)
	clientPub = PKCS1_OAEP.new(clientPub)
	pub.close()

    #Initialize global private key for client
	priv = open(PRIV_KEY_FILE, "r")
	clientPrivText = priv.read()
	clientPriv = RSA.importKey(clientPrivText)
	clientPriv = PKCS1_OAEP.new(clientPriv)
	priv.close()

	handler = ConnectionHandler()
	blockList = list()
'''
This is a method to encrypt a message using a 4096 bit RSA encryption with
OAEP padding.

It uses the public key of the recipient to encrypt the message. The reciever
uses their private key to decrypt the message. This is Asymmetric encryption.
'''
def encrypt_RSA(public_key, message):
    
    #param: public_key 		Textual form of the current IOT's public key
    #param: message 		Message to be securely sent
    #returns: encryptedMsg 	Base64 encoded encrypted string
    
    key = public_key
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted = rsakey.encrypt(message)
    return encrypted.encode('base64')

'''
This is the method to decrypt using 4096 but RSA encryption with PKCS1_OAEP
padding.

It uses this IOT's private key to decrypt the 'package' and return the base64
decoded decrypted string.
'''
def decrypt_RSA(package):
    #param: package String to be decrypted
    #returns: decrypted string

    key = open(PRIV_KEY_FILE, "r").read()
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    decrypted = rsakey.decrypt(b64decode(package))
    return decrypted

'''
Method that abstracts the secure sending of data to the current IOT
'''
def sendSecure(s, msg, conn):
	# param: s 		The socket used to send messages accross the network
	# param: msg 	The uncrypted message to send securely to the client
	# param: conn 	The connection object pertaining to the current connected IOT

	print "The message is:\n"+msg
	encryptedMsg = encrypt_RSA(conn.pubkey, msg)
	#print "The encrypted message is:\n"+encryptedMsg
	sendSocket(s, encryptedMsg, conn.conn)


'''
Method that abstracts the secure communication between the client and the
current IOT
'''
def handleData(s, conn):
	# param: s 		The socket used to send the encrypted data
	# param: conn 	The connection object pertaining to the current connected IOT

	global handler
	print "What would you like to send?, enter 'exit' to end"
	data = raw_input(">")
	if(data == 'exit'):
		sendSecure(s,"FIN:", conn)
		handler.removeConn(conn.conn)
		#sys.exit() #End program if user is done sending data
	else:
		data = "DATA:"+data
		sendSecure(s, data, conn)
			

def recvSecure(data):
	decryptedData = decrypt_RSA(data)
	print "Decrypted data: "
	print decryptedData

#create a UDP socket
init()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('', 50000)
sock.bind(server_address)

refreshListTime = time.time()
loggingOn = False

global handler
#loggedOn = 0
while True:
	# Receive response
	print ""
	
	if(time.time() >= refreshListTime):
		del blockList[:]
		refreshListTime = time.time() + REFRESH_TIMESTEP

	try:
		data, server = sock.recvfrom(8192)
	except socket.timeout:
		continue

	print "Data received from: ", server
	if(server in blockList):
		continue
	if handler.getConn(server) != None:
		c = handler.getConn(server)
		recvSecure(data)
		handleData(sock, c)
		continue

	cmd = parseMessage(data)

	if(cmd[0] == "CONNECT") : 
		if(loggingOn):
			continue
		c = raw_input("Do you want to connect to "+cmd[3]+"? (Y/N) ")
		if(c == 'Y' or c == 'y') :
			msg = connect(cmd[2],cmd[1])
			#changing the port #
			ackaddr = (server[0], 50001)
			print "Sending ", msg, " to ", ackaddr
			loggingOn = True
			sendSocket(sock, msg, ackaddr)
		elif(c == 'N') :
			#put in spam numbers
			blockList.append(server)
	elif(cmd[0] == "ACK") :
		if(cmd[1] == "ENCRYPT") :
			print "Congrats, we logged on."
			loggingOn = False
			conn = ackaddr
			#loggedOn = 1 
			#print "Logged on set!"
			if(cmd[2]):
				initPub(cmd[2])
				msg = getPubMsg()
				newConn = handler.addConn(conn, IOTpubtext)
				if newConn == None:
					print "Unable to add IOT, max connections enabled"
					continue

				sendSocket(sock, msg, ackaddr)

				handleData(sock, newConn) #send something
				
			else:
				print "ERROR: There was an error getting the public key from the IOT"

	elif(cmd[0] == "ERROR") :
		if(cmd[1] == "USERNAME"):
			print "ERROR : Invalid Username"
		if(cmd[1] == "PASSWORD"):
			print "ERROR : Incorrect Password"
		if(cmd[1] == "ARGUMENT"):
			print "ERROR : Bad Argument."
		if(cmd[1] == "NULLPUBKEY"):
			print "ERROR: NULL Public Key Sent"

	else :
		break

'''
if(loggedOn):
	print "About to handle data"
	handleData(sock, ackaddr)
'''
sock.close()



