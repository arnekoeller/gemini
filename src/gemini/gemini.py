import os,sys,socket,threading
from struct import *

class Gemini:

	def __init__(self,serverip,serverport):
		self.serverip = serverip
		self.serverport = serverport

	def getPort(self):
		return self.serverport

	def getIp(self):
		return self.serverip

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
			clientfd = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,0); 
			#like default parameters
			clientfd.connect((self.serverip,self.serverport))

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


	class Sniffer:

		def __init__(self,clientfd,mygemini):
			self.clientfd = clientfd
			self.mygemini = mygemini

		def createRawSocket(self):	

			try:
				rawfd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs((0x0003)))
			except socket.error ,msg:
				print "Cannot create raw socket"
				sys.exit()
			return rawfd


		def startSniffing(self,rawfd):

			while True:
				#print self.mygemini.recvMessageFromServer(self.clientfd)
				packet = rawfd.recvfrom(1500)
				packet = packet[0]
				if self.sortOutPackets(packet,self.mygemini) == True:
					self.mygemini.sendMessageToServer(self.clientfd,packet)
				

		# Sorting out packets to/from localhost, to Server IP or if IPv6 is in use
		def sortOutPackets(self,packet,mygemini):

			eth_length = 14
			eth_header = packet[:eth_length]
			eth = unpack('!6s6sH' , eth_header)
			eth_protocol = socket.ntohs(eth[2])

			if eth_protocol == 8 :

					ip_header = packet[eth_length:20+eth_length]

					iph = unpack('!BBHHHBBH4s4s' , ip_header)

					version_ihl = iph[0]
					version = version_ihl >> 4
					ihl = version_ihl & 0xF
					iph_length = ihl * 4

					# no support for IPv6
					if version == 6:
						return False

					s_addr = socket.inet_ntoa(iph[8]);
					d_addr = socket.inet_ntoa(iph[9]);

					if(str(s_addr) == "127.0.0.1" or str(d_addr) == "127.0.0.1"):
						return False
					if(str(d_addr) == mygemini.getIp() or str(s_addr) == mygemini.getIp() ):
						return False

			return True

# class GeminiThread(threading.Thread):

# 	def __init__(self,threadId,threadName,mygemini,clientfd):
# 		threading.Thread.__init__(self)
# 		self.threadId = threadId
# 		self.threadName = threadName
# 		self.mygemini = mygemini
# 		self.clientfd = clientfd

# 	def run(self):
# 		""" 1 -> Sender 2 -> Listener"""
# 		if self.threadId == 1:
			
# 			try:
# 				mysniffer = Gemini.Sniffer(self.clientfd,self.mygemini)
# 				rawfd = mysniffer.createRawSocket()
# 				mysniffer.startSniffing(rawfd)
# 			except socket.error:
# 				print "oops"
# 				print threading.enumerate()

# 		elif self.threadId == 2:

# 			while True:
# 				recv = self.mygemini.recvMessageFromServer(self.clientfd)
# 				print recv


def main():
	
	serverip = "127.0.0.1"
	serverport = 45681

	mygemini  = Gemini(serverip,serverport)
	clientfd  = mygemini.startClient()

	# t1 = GeminiThread(1,"sender",mygemini,clientfd)
	# t2 = GeminiThread(2,"listener",mygemini,clientfd)

	# t1.start() #start() calls run()
	# t2.start()

	try:
		mysniffer = Gemini.Sniffer(clientfd,mygemini)
		rawfd = mysniffer.createRawSocket()
		mysniffer.startSniffing(rawfd)
	except socket.error:
		print "oops"


	mygemini.closeClient(clientfd)



if __name__ == "__main__":
	main()