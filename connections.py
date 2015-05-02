

class Connection:
	def __init__(self, c, key, n): 
		#conn is tuple: (IP, port)
		self.conn = c
		self.pubkey = key
		self.num = n
		self.lastMsg = None

class ConnectionHandler:
	def __init__(self):
		self.arr = [None] * 5
		self.size = 0
		self.max = 5

	def addConn(self, tup, key):
		num = self.size + 1
		if num > self.max:
			return None #cannot add another connection, already at max

		c = Connection(tup, key, num)
		self.arr[num-1] = c
		self.size = num
		return c

	def getConn(self, tup):
		for c in self.arr:
			if str(c[0]) == str(tup[0]) and str(c[1]) == str(tup[1]):
				return c

		return None

	def removeConn(self, tup):
		i = 0
		for c in self.arr:
			if str(c[0]) == str(tup[0]) and str(c[1]) == str(tup[1]):
				self.size = self.size - 1
				self.arr[i] = None
				return True

			i += 1
		return False


'''
handler = ConnectionHandler()
for i in range(0,6):
	ip = random.random() * 100
	port = random.random() * 10000
	key = "key"
	tup = (ip, port)
	handler.addConn(tup, key)
'''
