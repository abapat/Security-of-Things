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
	global clientPub
	global sock
	global broadcast

	
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
	pub = open(PUB_KEY_FILE, "r").read()
	pubkey = RSA.importKey(pub)
	pubkey = PKCS1_OAEP.new(pubkey)

    #Initialize global private key for IOT
	priv = open(PRIV_KEY_FILE, "r").read()
	privkey = RSA.importKey(priv)
	privkey = PKCS1_OAEP.new(privkey)

	f.close()

def send(s, msg, addr):
	sent = False
	while sent == False:
		try:
			s.sendto(msg, addr)
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
	for login in users:
		if tup[0] == login[0]: #username match
			pwd = login[1]
			pwd = (hashlib.sha256(pwd.encode() + salt.encode())).hexdigest()

			#success
			if pwd == tup[1]:
				print "its a match!"
				
				send(sock, "ACK:ENCRYPT,"+pubkey.publickey().exportKey(), addr)
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
		msg, server = sock.recvfrom(4096) #TODO spam protection?
		recv = True
		#print "message is " + str(msg) + "\nFrom " + str(server)
	except timeout:
		print("Timeout, Broadcasting again...")

	if recv == False:
		continue

	cmd = parseMessage(msg)
	
	if cmd[0] == "ACK":
		success = ack(cmd, server)
		if success:
			sendBrocast = False
			break
	else:
		print("Invalid Command, ignoring")

print("Closing socket")
sock.close()




