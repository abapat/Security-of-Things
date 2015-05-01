import socket
import sys
import uuid
import hashlib
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode

#defines
PUB_KEY_FILE = "CLIENTrsa.pub"
PRIV_KEY_FILE = "CLIENTrsa"
#end defines

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
	print "salt :", salt
	return "ACK:PASS,"+msgnum+","+username+","+hashed

#Initializes the public key of the IOT
def initPub(pubKey):
	global IOTpub
	global IOTpubtext

	#print "The recieved key is below"
	#print pubKey

	IOTpubtext = pubKey
	IOTpub = RSA.importKey(pubKey)
	IOTpub = PKCS1_OAEP.new(clientPub)

#Creates the public key carrying message to the IOT
def getPubMsg():
	msg = "ACK:ENCRYPT,"
	msg += IOTpubtext
	return msg

#Method to do some setup initializing the public and private keys of the client
def init():
	global clientPub
	global clientPriv

	#Initialize global public key for IOT
	pub = open(PUB_KEY_FILE, "r").read()
	clientPub = RSA.importKey(pub)
	clientPub = PKCS1_OAEP.new(clientPub)

    #Initialize global private key for IOT
	priv = open(PRIV_KEY_FILE, "r").read()
	clientPriv = RSA.importKey(priv)
	clientPriv = PKCS1_OAEP.new(clientPriv)

#create a UDP socket
init()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('', 50000)
sock.bind(server_address)

ignoreBrocast = 0
while True:
	# Receive response
	data, server = sock.recvfrom(8192)

	print "\nim getting my data from :", server
	if(ignoreBrocast and server[1] != 50001):
		continue
	cmd = parseMessage(data)

	if(cmd[0] == "CONNECT") : 
		msg = connect(cmd[2],cmd[1])
		#changing the port #
		ackaddr = (server[0], 50001)
		print "sending", msg, "to", ackaddr
		sock.sendto(msg, ackaddr)
		ignoreBrocast = 1
	elif(cmd[0] == "ACK") :
		if(cmd[1] == "ENCRYPT") :
			print "Congrats, we logged on."

			if(cmd[2]):
				initPub(cmd[2])
				msg = getPubMsg()
				#print "Im about to send client pub key below"
				#print msg
				sock.sendto(msg, ackaddr)
			else:
				print "ERROR: There was an error getting the public key from the IOT"

	elif(cmd[0] == "ERROR") :
		if(cmd[1] == "USERNAME"):
			print "ERROR : Invalid Username"
		if(cmd[1] == "PASSWORD"):
			print "ERROR : Incorrect Password."
		if(cmd[1] == "ARGUMENT"):
			print "ERROR : Bad Argument."
		if(cmd[1] == "NULLPUBKEY"):
			print "ERROR: NULL Public Key Sent"
		ignoreBrocast = 0
	else :
		break

sock.close()
