import hashlib, uuid
import os, sys, time
from socket import *

#defines
DEVICE_NAME = "Intel Galileo"
BROADCAST_PORT = 50000
RECV_PORT = 50001
PASSWORD_FILE = 'passwords'
TIMEOUT = 60 #seconds
MAX_CACHE = 10

users = []
table = None

#TODO error checking on file
def init():
	global users
	global table
	table = dict()
	f = open(PASSWORD_FILE, 'r')
	s = f.readline()

	while (s != ""):
		l = s.split(",")
		tup = (l[0], l[1])
		users.append(tup)
		s = f.readline()

	f.close()

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
	s.sendto(msg, ('<broadcast>', BROADCAST_PORT))

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
				
				s.sendto("ACK:ENCRYPT", addr)
				return True
			else:
				print "salt :", salt
				print pwd, "!=", tup[1]

				s.sendto("ERROR:PASSWORD", addr)
				return False
	
	#user not found
	s.sendto("ERROR:USERNAME", addr)
	return False

#TODO ERROR CHECK FIELDS, CANT ASSUME THEY ARE INTS 
def getSalt(num):
	num = int(num)
	salt = table.get(num, default=None)
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
		#begin diffy hellman
		ret = True
	else:
		s.sendto("ERROR:ARGUMENT", addr)

	return ret

init()
s = socket(AF_INET, SOCK_DGRAM)
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
s.bind(('', RECV_PORT))
s.settimeout(TIMEOUT)

msgCount = 1
while 1:
	#TODO do i have to keep a table of previous salts to handle the case of a reply to an old broadcast?
	salt = brocast(s, msgCount)
	cacheSalt(msgCount, salt)
	recv = False
	try:
		msg, server = s.recvfrom(4096) #TODO spam protection?
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
			break
	else:
		print("Invalid Command, ignoring")

	msgCount += 1

print("Closing socket")
s.close()




