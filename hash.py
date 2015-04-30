import os
import hashlib
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
f = open('passwords', 'w')
f.write("admin,")
m = hashlib.sha256()
m.update("pass")
f.write(m.hexdigest())
f.close()


