import sys, time
from socket import *

s = socket(AF_INET, SOCK_DGRAM)
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
count = 0
while 1:
	msg = "hello world "
	msg += str(count)
	print("Sending Message " + str(count))
	s.sendto(msg, ('255.255.255.255', 50000))
	count += 1
	time.sleep(2)