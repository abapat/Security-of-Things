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
	global IOTpubtext

	IOTpubtext = pubKey

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


def handleData(s, addr):
	print "What would you like to send?, enter 'exit' to end"
	while 1:
		data = raw_input("\n>")
		if(data == 'exit\n'):
			sys.exit() #End program if user is done sending data
		else:
			data = "DATA:"+data
			encryptedData = encrypt_RSA(IOTpubtext,data)
			print "About to send: \n"+data
			print "This is encrypted into: \n"+encryptedData
			s.sendto(encryptedData,addr)

#create a UDP socket
init()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('', 50000)
sock.bind(server_address)

ignoreBrocast = 0
loggedOn = 0
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

			loggedOn = 1 
			print "Logged on set!"
			if(cmd[2]):
				initPub(cmd[2])
				msg = getPubMsg()
				sock.sendto(msg, ackaddr)
				break
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


if(loggedOn):
	print "About to handle data"
	handleData(sock, ackaddr)

sock.close()
