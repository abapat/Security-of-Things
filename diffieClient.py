import socket
import sys

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_address = ('', 5000)
sock.bind(server_address)

while True: 
	print 'ready!'
	data, server = sock.recvfrom(4096)
	print data

sock.close()
