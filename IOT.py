import hashlib, uuid
import os, sys, time
from socket import *
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode


#defines
DEVICE_NAME = "Intel Galileo"
BROADCAST_PORT = 50000
RECV_PORT = 50001
PASSWORD_FILE = 'passwords'
TIMEOUT = 60 #seconds
MAX_CACHE = 10
PUB_KEY_FILE = "IOTrsa.pub"
PRIV_KEY_FILE = "IOTrsa"

users = []
table = None
sock = None
broadcast = None

#TODO error checking on file
def init():
	global users
	global table
	global pubkey
	global privkey
	global pubtext
	global clientPub
	global sock
	global broadcast
	global userLoggedIn

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


def encrypt_RSA(public_key, message):
    '''
    param: public_key_loc Path to public key
    param: message String to be encrypted
    return base64 encoded encrypted string
    '''
    pub = public_key
    encrypted = pub.encrypt(message)
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


def send(s, msg, addr):
	sent = False
	while sent == False:
		try:
			#if(sys.getsizeof(msg)>300):
			#	staggeredSend(s, msg, addr)
			#else:
			numSent = s.sendto(msg, addr)
			print "I sent :"+str(numSent)+" bytes"
			print "The length of the message is: "+str(sys.getsizeof(msg))
			sent = True
		except IOError, e: #socket.error is subclass
			if e.errno == 101:
				print "No Network connection, trying again later..."
				time.sleep(60) #check back in a minute

def staggeredSend(s, msg, addr):
	msgLength = sys.getsizeof(msg)
	piecesNeeded = msgLength/300
	if(msgLength % 300 != 0):
		piecesNeeded += 1 #To send the last bit of stuff

	appendString = "ACK:ENCRYPT,"
	for i in range(0,piecesNeeded):
		thisChunk = ""
		if(i == 0):
			thisChunk = msg[(300*i):]
		else:
			thisChunk = appendString + msg[(300*i):]

		thisChunk += ","+str((piecesNeeded-i)-1)
		print "Sending the following in staggered form: "+thisChunk
		s.sendto(thisChunk,addr)


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
	if(userLoggedIn):
		return msg

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
				print "its a match!"
				
				userLoggedIn = True
				print "userLoggedIn = "+str(userLoggedIn)

				send(sock, "ACK:ENCRYPT,"+pubtext, addr)
				return True
			else:
				print "salt :", salt
				print pwd, "!=", tup[1]

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

		#print "ENCRYPT statement received"
		#print cmd[2]
		
		#Check to see if a key was sent
		if(cmd[2]):
			cpub = cmd[2]
			clientPub = RSA.importKey(cpub)
			clientPub = PKCS1_OAEP.new(clientPub)
			ret = True
		#No Public Key Sent
		else:
			send(s, "ERROR:NULLPUBKEY", addr)
			ret = False
	else:
		send(s, "ERROR:ARGUMENT", addr)

	return ret

#TODO: handle checking if the connection addr is legit
def handleData(msg):
	print "Handling following cipher text:\n" + msg
	payload = decrypt_RSA(msg)
	print "The decrypted message is: \n" + payload
	"""payload = payload.split(":",1)
	payload = payload[1]
	print payload"""



#global sock
#global broadcast

init()
msgCount = 0
sendBrocast = True
while 1:
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

	print "The message is: \n"+msg

	cmd = parseMessage(msg)
	
	if cmd[0] == "ACK":
		success = ack(cmd, server)
		if success:
			sendBrocast = False
			#break
	####### SHIT GETS WEIRD HERE ######
	### With the below code commented, value of msg is correct ###
	### Otherwise, msg holds the wrong value ###
	#else:
		#handleData(msg)



print("Closing socket")
sock.close()




