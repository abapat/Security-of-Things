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
LARGE_PRIME = 105341				#Large prime used for the modulo in the diffie helman seq. exchange 
RAND_LIMIT = 500000					#Largest allowed random number

blockList = None
password = None
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


def hash_password(salt):
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
	global password

	username = raw_input("username : ")
	password = getpass.getpass("password : ")
	hashed = hash_password(salt)
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
TODO: Document further
'''
def getPubMsg():
	global secretNum
	salt = str(uuid.uuid4().hex)

	msg = "ACK:ENCRYPT,"
	msg += clientPubText+","
	msg += hash_password+","
	msg += salt+","
	secretNum = long(randint(0,RAND_LIMIT))
	raisedRand = long(pow(long(3),secretNum))
	moddedRand = long(raisedRand % long(LARGE_PRIME))
	msg += moddedRand
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
	global seqNum 				#The sequence number of the next message to send

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
		sendSecure(s,"FIN:"+str(seqNum), conn)
		handler.removeConn(conn.conn)
		#sys.exit() #End program if user is done sending data
	else:
		data = "DATA:"+data+","+str(seqNum)
		sendSecure(s, data, conn)
			
def recvSecure(data):
	decryptedData = decrypt_RSA(data)
	try:
		recievedSeqNum = long(decryptedData.split(",")[5])
		if(recievedSeqNum != seqNum+1):
			print "Incorrect sequence number recieved"
			return
		else:
			seqNum += 2
	except ValueError:
		print "Non Integer Sequence Number recieved"

	print "Decrypted data: "
	print decryptedData

def isLegitServer(pwd, salt):
	#hash (client side) password with given salt
	hashed = hash_password(salt)
	print "The hash should be: "+hashed
	print "What i received is: "+ pwd
	#compare our hashed password w/ server's hashed password
	return pwd == hashed

def setSeqNum(numString):
	global seqNum

	try:
		recievedLong = long(numString)
		raisedLong = pow(recievedLong,secretNum)
		moddedLong = raisedLong % long(LARGE_PRIME)
		seqNum = moddedLong
	except ValueError:
		print "Erroenous sequence number sent"


#create a UDP socket
init()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('', 50000)
sock.bind(server_address)

refreshListTime = time.time()
loggingOn = False

global handler
while True:
	# Receive response
	print ""
	
	#if it's time to refresh the list, clear out the block list and update refresh time
	if(time.time() >= refreshListTime):
		del blockList[:]
		refreshListTime = time.time() + REFRESH_TIMESTEP

	try:
		data, server = sock.recvfrom(8192)
	except socket.timeout:
		continue

	print "Data received from: ", server
	
	#if server is being blocked, don't read message
	if(server in blockList):
		continue

	if handler.getConn(server) != None:
		c = handler.getConn(server)
		recvSecure(data)
		handleData(sock, c)
		continue

	cmd = parseMessage(data)

	if(cmd[0] == "CONNECT") : 
		#if we're currently trying to log on, ignore other connect messages
		if(loggingOn):
			continue

		#give user the option of not connecting to the device - loop to prevent illegal chars
		while True:
			c = raw_input("Do you want to connect to "+cmd[3]+"? (Y/N) ")
			if(c == 'Y' or c == 'y') :
				msg = connect(cmd[2],cmd[1])
				#changing the port # to the port the server would listen to
				ackaddr = (server[0], 50001)
				print "Sending ", msg, " to ", ackaddr
				sendSocket(sock, msg, ackaddr)

				#user is currently trying to log on -> should be true ;P
				loggingOn = True

				break
			elif(c == 'N' or c=='y') :
				#put in spam numbers
				blockList.append(server)

				break
	elif(cmd[0] == "ACK") :
		if(cmd[1] == "ENCRYPT") :
			print cmd
			loggingOn = False
			conn = ackaddr

			if(len(cmd) == 6 and isLegitServer(cmd[3], cmd[4])):
				setSeqNum(cmd[5])
				initPub(cmd[2])
				msg = getPubMsg()

				newConn = handler.addConn(conn, IOTpubtext)
				if newConn == None:
					print "Unable to add IOT, max connections enabled"
					continue

				print "Congrats, we logged on."
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



