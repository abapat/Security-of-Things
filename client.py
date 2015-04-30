import socket
import sys
import uuid
import hashlib

def hash_password(password, salt):

	hashedpassword = hashlib.sha256(password.encode()).hexdigest() 
	return hashlib.sha256(salt.encode() + hashedpassword.encode()).hexdigest()

#create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('', 50000)
sock.bind(server_address)

while True:
	# Receive response
	salt, server = sock.recvfrom(4096)

	password = raw_input("password : ")
	hashed = hash_password(password, salt)
	print hashed

	sock.sendto(hashed, server)

sock.close()
