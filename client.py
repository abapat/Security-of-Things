import socket
import sys
import uuid
import hashlib

def hash_password(password, salt):
	hashedpassword = hashlib.sha256(password.encode()).hexdigest() 
	return hashlib.sha256(hashedpassword.encode() + salt.encode()).hexdigest()

def parseMessage(msg):
	x = []
	c = msg.split(":")
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

#create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('', 50000)
sock.bind(server_address)

while True:
	# Receive response
	data, server = sock.recvfrom(4096)

	cmd = parseMessage(data)

	if(cmd[0] == "CONNECT") : 
		msg = connect(cmd[2],cmd[1])

		print "sending", msg, "to", server
		sock.sendto(msg, server)
	elif(cmd[0] == "ACK") :
		if(cmd[1] == "ENCRYPT") :
			print "Congrats, we logged on."
			#TODO: ummm....what does this mean again?
			break
	elif(cmd[0] == "ERROR") :
		if(cmd[1] == "USERNAME"):
			print "ERROR : Invalid Username"
		if(cmd[1] == "PASSWORD"):
			print "ERROR : Incorrect Password."
		if(cmd[1] == "ARGUMENT"):
			print "ERROR : Bad Argument."
	else :
		break

sock.close()
