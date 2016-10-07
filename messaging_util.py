import random

LARGE_PRIME = 105341                            		#Large prime used for the modulo in the diffie helman seq. exchange 
RAND_LIMIT = 500000                                     #Largest allowed random number

'''
Parses message in correct protocol - CMD:param1,param2,...,paramN

	@param msg              message from server to be parsed
	@return list of cmd and params
'''
def parse_message(msg):
	#check for cmd part
	if ":" not in msg:
		return None

	x = []

	#get cmd part
	c = msg.split(":",1)
	x.append(c[0])

	#get params
	args = c[1].split(",")
	for arg in args:
		x.append(arg)

	return x

'''
Sets secret number for key exchange and returns what to send to client

	@return public number to send to client for diffy-hellmann
'''
def get_diffie_nums():
    secret_num = long(random.randint(0,RAND_LIMIT))
    raisedRand = long(pow(long(3),secret_num))
    moddedRand = long(raisedRand % long(LARGE_PRIME))
    return (secret_num, str(moddedRand))

'''
sets the starting sequence number

	@param my_secret_num					secret number portion of diffie hellman
	@param others_public_num                public number portion of diffie hellman
'''
def set_seq_num(my_secret_num, others_public_num):
    global seq_num

    try:
	    recieved_long = long(others_public_num)
	    raised_long = pow(recieved_long,my_secret_num)
	    return raised_long % long(LARGE_PRIME)
    except ValueError:
	    print "Erroneous sequence number sent"
    return None
