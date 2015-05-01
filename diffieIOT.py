import sys, time
from socket import *
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode

s = socket(AF_INET, SOCK_DGRAM)
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

def encrypt_RSA(public_key_loc, message):
    '''
    param: public_key_loc Path to public key
    param: message String to be encrypted
    return base64 encoded encrypted string
    '''
    key = open(public_key_loc, "r").read()
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted = rsakey.encrypt(message)
    return encrypted.encode('base64')


def decrypt_RSA(private_key_loc, package):
    '''
    param: public_key_loc Path to your private key
    param: package String to be decrypted
    return decrypted string
    '''
    key = open(private_key_loc, "r").read()
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    decrypted = rsakey.decrypt(b64decode(package))
    return decrypted

def generateRSAKeys(pubName, privName):
	rng = Random.new().read
	key = RSA.generate(4096,rng)

	binPrivKey = key.exportKey('PEM')
	binPubKey =  key.publickey().exportKey('PEM')

	with open(pubName,"w") as f:
		f.write(binPrivKey)
		f.close()

	with open(privName,"w") as f:
		f.write(binPubKey)
		f.close()

"""msg = "We attack at dawn"

package = encrypt_RSA("/Users/varun/Documents/Stony Brook/Junior Year/2nd Sem/CSE 408/Security-of-Things/IOTrsa.pub",msg)

print "encrypted text = "+package

print "decrypted text = "+decrypt_RSA("/Users/varun/Documents/Stony Brook/Junior Year/2nd Sem/CSE 408/Security-of-Things/IOTrsa",package)"""

generateRSAKeys("IOTrsa","IOTrsa.pub")


#s.sendto(package, ('localhost', 5000))








