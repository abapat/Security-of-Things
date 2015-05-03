import socket
import sys
import uuid
import hashlib
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
PUB_KEY_FILE = "CLIENTrsa.pub"
PRIV_KEY_FILE = "CLIENTrsa"
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
	password = raw_input("password : ")
	hashed = hash_password(password, salt)
	#print "salt :", salt
	return "ACK:PASS,"+msgnum+","+username+","+hashed

#Initializes the public key of the IOT
def initPub(pubKey):
	global IOTpubtext

	IOTpubtext = pubKey

#Creates the public key carrying message to the IOT
def getPubMsg():
	msg = "ACK:ENCRYPT,"
	msg += clientPubText
	return msg

#Method to do some setup initializing the public and private keys of the client
def init():
	global clientPub
	global clientPriv
	global clientPubText
	global handler
	#Initialize global public key for IOT
	clientPubText = open(PUB_KEY_FILE, "r").read()
	clientPub = RSA.importKey(clientPubText)
	clientPub = PKCS1_OAEP.new(clientPub)

    #Initialize global private key for IOT
	priv = open(PRIV_KEY_FILE, "r").read()
	clientPriv = RSA.importKey(priv)
	clientPriv = PKCS1_OAEP.new(clientPriv)

	handler = ConnectionHandler()

def encrypt_RSA(public_key, message):
    '''
    param: public_key_loc Path to public key
    param: message String to be encrypted
    return base64 encoded encrypted string
    '''
    key = public_key
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted = rsakey.encrypt(message)
    return encrypted.encode('base64')


def decrypt_RSA(package):
    '''
    param: public_key_loc Path to your private key
    param: package String to be decrypted
    return decrypted string
    '''
    key = open(PRIV_KEY_FILE, "r").read()
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    decrypted = rsakey.decrypt(b64decode(package))
    return decrypted

#Encrypts a message and sends it over socket
def sendSecure(s, msg, conn):
	print "The message is:\n"+msg
	encryptedMsg = encrypt_RSA(conn.pubkey, msg)
	#print "The encrypted message is:\n"+encryptedMsg
	sendSocket(s, encryptedMsg, conn.conn)


def handleData(s, conn):
	global handler
	print "What would you like to send?, enter 'exit' to end"
	data = raw_input(">")
	if(data == 'exit'):
		sendSecure(s,"FIN:", conn)
		handler.removeConn(conn.conn)
		#sys.exit() #End program if user is done sending data
	else:
		data = "DATA:"+data
		#encryptedData = encrypt_RSA(IOTpubtext,data)
		#print "About to send: \n"+data
		#print "This is encrypted into: \n"+encryptedData
		sendSecure(s, data, conn)
			

def recvSecure(data):
	#print "The data received back is:"
	#print data

	decryptedData = decrypt_RSA(data)
	print "Decrypted data: "
	print decryptedData

#create a UDP socket
init()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('', 50000)
sock.bind(server_address)

global handler
#loggedOn = 0
while True:
	# Receive response
	print ""
	
	try:
		data, server = sock.recvfrom(8192)
	except socket.timeout:
		continue


	print "Data received from: ", server

	if handler.getConn(server) != None:
		c = handler.getConn(server)
		recvSecure(data)
		handleData(sock, c)
		continue

	cmd = parseMessage(data)

	if(cmd[0] == "CONNECT") : 
		c = raw_input("Do you want to connect to "+cmd[3]+"? (Y/N) ")
		if(c == 'Y') :
			msg = connect(cmd[2],cmd[1])
			#changing the port #
			ackaddr = (server[0], 50001)
			print "Sending ", msg, " to ", ackaddr
			sendSocket(sock, msg, ackaddr)
		#elif(c == 'N') :
			#put in spam numbers
	elif(cmd[0] == "ACK") :
		if(cmd[1] == "ENCRYPT") :
			print "Congrats, we logged on."
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



