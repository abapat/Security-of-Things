import sys, time, random, hashlib, uuid
from socket import *

def calc_hash(salt):
	return hashlib.sha256(salt + password.encode()).hexdigest();
s = socket(AF_INET, SOCK_DGRAM)
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

password = hashlib.sha256("varunsucksweewees".encode()).hexdigest()

#generate hash
salt = uuid.uuid4().hex	

s.sendto(salt, ('255.255.255.255', 50000))
hashed = calc_hash(salt)

data, server = s.recvfrom(4096)
if data == hashed : 
	print "its a match"
else :
	print hashed, " != ", data 

s.close()

