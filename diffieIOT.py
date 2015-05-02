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

print decrypt_RSA("/Users/varun/Documents/Stony Brook/Junior Year/2nd Sem/CSE 408/Security-of-Things/CLIENTrsa","NOeVmsg+dFklTIF1bTa8/C3iWp1rcMta4dG17X8+q2XT/itTaEJhLO7bn8rZuc1BBnyg/ajDm6QA6F1AySbccXWtceED/S8ml7Ybkmkz2l5U8nkZCjjjU+Sxw9salbIikQ/3VPeOOVF3zQwHTrE6uySrlJKQ4Oi5Udgsv/7WP+IHJ9KSb5AqcsSJFLKiGOlgi/I80wk2nHz7fMRO8ovKy2oHrMVP7bUACJ9TwKWLE1Z6E7VLxvnntC2ZuhUosQbYjU+eMhi1gY7o16JUeU93c7NLKkf7h1j7eRCRmQtx3XDO0JS02Y5/fYi10xo8B4pyVvBRIC/oeHVAvYMmDfy5uh6oWJTMxtGqB9tqGyZDK0/0XtaMl5B3KcZfRafiFCBaZOWj3V6Cx0N4Iud3Zed4gV/C6nvwW61DvKa8e5985/aaHHnZXx3zYFCF+nHRIUvAZ6GhBjLNQ0y1RLYttsQ61lHISrRfemUcHahF2grFr07yUiGbnkr3xvBuxzIWtwTSsOz5wlsv9YxOznY/5iU0F3U7Hq5vpL7b+bqzfE1AHSm911gVlh56TYt9qJZnm5bt1ImCgjY5Uz1hmmP+3+d5uFFfCpCMfVt1UfoU6Bcd0iR8tMDBVtyxbXCmr6ISwfhok5DIHtXfjFYLsAXDjP6WuyBjcCBubXSFEqTWWZmCc6c=")

#generateRSAKeys("IOTrsa","IOTrsa.pub")


#s.sendto(package, ('localhost', 5000))








