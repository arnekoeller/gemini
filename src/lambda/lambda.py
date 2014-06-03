import os,sys,socket

class Lambda:

	def __init__(self,ip,port):
		self.ip = ip
		self.port = port

	def checkRoot(self):
		if (os.getuid()!= 0):
			print "Not root rights"
			sys.exit()

	def checkOSType(self):
		if sys.platform == "linux" or sys.platform == "linux2":
			return "Linux"
		elif sys.platform == "darwin":
			return "MacOSX"
		elif sys.platform == "win32":
			return "Windows"

	def startClient(self):

		try:
			clientfd = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,0); #like default parameters
			clientfd.connect((self.ip,self.port))

		except socket.error ,msg:
				print "Cannot create socket to server" 
				print msg
				sys.exit()

		return clientfd

	def sendMessageToServer(self,clientfd,message):
		clientfd.send(message)
		

	def recvMessageFromServer(self,clientfd):
		recv = clientfd.recvfrom(1500)
		return recv[0]	#[0] has reply [1] is none

	def closeClient(self,clientfd):
			clientfd.close()

def main():
	
	hostip = "127.0.0.1"
	port = 45681

	mylambda  = Lambda(hostip,port)
	clientfd  = mylambda.startClient()
	mylambda.sendMessageToServer(clientfd,"hi")
	#mylambda.recvMessageFromServer(clientfd)

	mylambda.closeClient(clientfd)



if __name__ == "__main__":
	main()