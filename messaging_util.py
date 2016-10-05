
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

