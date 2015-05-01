import hashlib, uuid
import os, sys, time
from socket import *
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode

#Initialize global public key for IOT
pub = open("IOTrsa.pub", "r").read()
pubkey = RSA.importKey(pub)
pubkey = PKCS1_OAEP.new(pubkey)

print pub