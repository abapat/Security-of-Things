import os
import hashlib
from pymongo import MongoClient

'''
f = open('passwords', 'w')
line = []
line.append("admin")
line.append("varunsucksweewees")
comma = False
for field in line:
	m = hashlib.sha1()
	m.update(field)
	f.write(m.hexdigest())
	if comma == False:
		f.write(",")
		comma = True

f.close()
'''
'''
#writes default username and password to file
f = open('passwords', 'w')
f.write("admin,")
m = hashlib.sha256()
m.update("pass")
f.write(m.hexdigest())
f.close()
'''
def add_user(username, password):
  client = MongoClient()
  db = client.IOT

  #TODO:sanitize data

  #check to see if that username is already used
  if db.login_info.find_one({"username": username}) is None:
    #hash password
    m = hashlib.sha256()
    m.update(password)
    db.login_info.insert_one({"username": username, "password": m.hexdigest()})
  else:
    print "Error: Username \""+username+"\" is already in use."

username = raw_input("username : ")
password = raw_input("password : ")
add_user(username, password)
