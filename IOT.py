import hashlib, uuid
import os, sys, time
from socket import *

DEVICE_NAME = "Intel Galileo"
users = []

#TODO error checking on file
def init():
	global users
	f = open('passwords', 'r')
	s = f.readline()

	while (s != ""):
		l = s.split(",")
		tup = (l[0], l[1])
		users.append(tup)
		s = f.readline()

	f.close()

#takes UDP socket as input, broadcasts salt to be used in encryption
def brocast(s):
	msg = "CONNECT:"
	salt = str(uuid.uuid4().hex)
	msg += salt
	msg += DEVICE_NAME
	
	s.sendto(msg, ('<broadcast>', 50000))

	return salt

init()
s = socket(AF_INET, SOCK_DGRAM)
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

salt = brocast(s)


