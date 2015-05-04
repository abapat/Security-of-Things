import hashlib, uuid
import os, sys, time
from socket import *
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode


#DEFINES
DEVICE_NAME = "Intel Galileo" 	#Name of the device running the script
BROADCAST_PORT = 50000 			#The port used to broadcast device being alive
RECV_PORT = 50001 				#Port used to exchange messages with the client
PASSWORD_FILE = 'passwords'		#File of hashed passwords of clients who use this system i.e. admin
TIMEOUT = 60 #seconds			#
MAX_CACHE = 10 					#
PUB_KEY_FILE = "IOTrsa.pub"		#The file storing the public key of the IOT (4096 bits)
PRIV_KEY_FILE = "IOTrsa"		#The file storing the private key of the IOT (Never send anywhere)

users = []
table = None
sock = None
broadcast = None
#END DEFINES

#TODO error checking on file
def init():
	global users
	global table
	global pubkey 				#Object form of IOT's public key
	global privkey 				#Object form of IOT's private key
	global pubtext 				#Text form of IOT's public key
	global clientPub 			#This is the public key of the client in object form
	global clientPubText 		#This is the textual version of the client's pub key
	global sock
	global broadcast
	global userLoggedIn			#Flag used to track if a user is currently connected to this IOT

	userLoggedIn = False		

	broadcast = socket(AF_INET, SOCK_DGRAM)
	broadcast.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
	broadcast.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

	sock = socket(AF_INET, SOCK_DGRAM)
	sock.bind(('', RECV_PORT))
	sock.settimeout(TIMEOUT)


	table = dict()
	f = open(PASSWORD_FILE, 'r')
	s = f.readline()

	while (s != ""):
		l = s.split(",")
		tup = (l[0], l[1])
		users.append(tup)
		s = f.readline()

	#Initialize global public key for IOT
	pubtext = open(PUB_KEY_FILE, "r").read()
	pubkey = RSA.importKey(pubtext)
	pubkey = PKCS1_OAEP.new(pubkey)

    #Initialize global private key for IOT
	priv = open(PRIV_KEY_FILE, "r").read()
	privkey = RSA.importKey(priv)
	privkey = PKCS1_OAEP.new(privkey)

	f.close()

'''
This is a method to encrypt a message using a 4096 bit RSA encryption with
OAEP padding.

It uses the public key of the recipient to encrypt the message. The reciever
uses their private key to decrypt the message. This is Asymmetric encryption.
'''
def encrypt_RSA(public_key, message):
    
    #param: public_key Public key object
    #param: message String to be encrypted
    #return: base64 encoded encrypted string
    
    pub = public_key
    encrypted = pub.encrypt(message)
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

'''
def send(s, msg, addr):
	sent = False
	while sent == False:
		try:
			numSent = s.sendto(msg, addr)
			print "I sent :"+str(numSent)+" bytes"
			print "The length of the message is: "+str(sys.getsizeof(msg))
			sent = True
		except IOError, e: #socket.error is subclass
			if e.errno == 101:
				print "No Network connection, trying again later..."
				time.sleep(60) #check back in a minute

def cacheSalt(num, salt):
	global table
	num = int(num)
	if len(table) == MAX_CACHE: #table full
		lru = min(table.keys())
		del table[lru]

	table[num] = salt

#takes UDP socket as input, broadcasts salt to be used in encryption
def brocast(s, num):
	msg = "CONNECT:"
	salt = str(uuid.uuid4().hex)
	msg += salt
	msg += ","
	msg += str(num)
	msg += ","
	msg += DEVICE_NAME

	
	print msg
	send(s, msg, ('<broadcast>', BROADCAST_PORT))

	return salt

def parseMessage(msg):

	x = []
	c = msg.split(":")
	x.append(c[0])
	args = c[1].split(",")
	for arg in args:
		x.append(arg)

	return x

def checkPass(tup, salt, addr):
	global userLoggedIn

	for login in users:
		if tup[0] == login[0]: #username match
			pwd = login[1]
			pwd = (hashlib.sha256(pwd.encode() + salt.encode())).hexdigest()

			#success
			if pwd == tup[1]:
				#print "its a match!"

				send(sock, "ACK:ENCRYPT,"+pubtext, addr)
				return True
			else:
				#print "salt :", salt
				#print pwd, "!=", tup[1]

				send(sock, "ERROR:PASSWORD", addr)
				return False
	
	#user not found
	send(sock, "ERROR:USERNAME", addr)
	return False

#TODO ERROR CHECK FIELDS, CANT ASSUME THEY ARE INTS 
def getSalt(num):
	num = int(num)
	salt = table.get(num, None)
	return salt


#TODO needs error checking on cmd (index out of range if bad arg)
def ack(cmd, addr):
	global userLoggedIn
	global clientPubText
	global clientPub

	ret = False
	c = cmd[1] 
	if c == "PASS":
		salt = getSalt(cmd[2])
		if salt == None:
			return False
		tup = (cmd[3], cmd[4])
		ret = checkPass(tup, salt, addr)
		#check passwords
	elif c == "ENCRYPT":
		#Get the pubic key from the client
		
		#Check to see if a key was sent
		if(cmd[2]):
			cpub = cmd[2]
			clientPubText = cpub
			clientPub = RSA.importKey(cpub)
			clientPub = PKCS1_OAEP.new(clientPub)
			userLoggedIn = addr
			ret = True

		#No Public Key Sent
		else:
			send(s, "ERROR:NULLPUBKEY", addr)
			ret = False
	else:
		send(s, "ERROR:ARGUMENT", addr)

	return ret

'''
Method that abstracts the sending of encrypted messages to the 
client.

Basically encrypts a message and use the send method to ship off
the encrypted text.
'''
def sendSecure(s, msg, addr):
	# param: s 		The socket used to send messages accross the network
	# param: msg 	The uncrypted message to send securely to the client
	# param: addr 	The address of the client we wanna communicate with

	encryptedMsg = encrypt_RSA(clientPub,msg)
	send(s, encryptedMsg, addr)

'''
Method that abstracts the handling of data between a connected client and 
IOT. This ensures that all data between IOT and client is encrypted.
'''
#TODO: handle checking if the connection addr is legit
def handleData(s, addr, msg):
	# param: s 		Socket used to talk to the client
	# param: addr 	Address of the client we be talking to
	# param: msg 	Message received from the client

	global sendBrocast, userLoggedIn

	#Decrypt the msg and parse out the command field
	payload = decrypt_RSA(msg)
	payload = payload.split(":",1)

	#Command used by the client to end the connection with the IOT
	if(payload[0] == "FIN"):
		print "FIN command received, exiting!"
		sendBrocast = True
		userLoggedIn = False
		return

	#Otherwise the command was DATA
	payload = payload[1]
	print "Decrypted Payload: \n"+payload
	payload = "You sent IOT: "+payload

	#Securely send back the slightly modified message
	sendSecure(s, payload, addr)

#global sock
#global broadcast

init()
msgCount = 0
sendBrocast = True
while 1:
	print "";
	msgCount += 1
	if sendBrocast == True:
		salt = brocast(broadcast, msgCount)
		cacheSalt(msgCount, salt)
	
	recv = False
	try:
		msg, server = sock.recvfrom(8192) #TODO spam protection?
		recv = True
		#print "message is " + str(msg) + "\nFrom " + str(server)
	except timeout:
		continue

	if recv == False:
		continue

	#If a connection has been established already, handle data securely
	if(userLoggedIn):
		#if the message is from a client != connected client, ignore message
		if(userLoggedIn != server):
			send(s, "Bitch, I'm already connected.", server)
			continue
		handleData(sock, server, msg)
	#Otherwise, data does not have to be encrypted (and shouldn't be)
	else:
		cmd = parseMessage(msg)
		
		if cmd[0] == "ACK":
			success = ack(cmd, server)
			if success:
				sendBrocast = False
				#break

print("Closing socket")
sock.close()
