import os,sys,socket
from struct import *

class Lambda:

	def __init__(self,ip,port):
		self.ip = ip
		self.port = port

	def getPort(self):
		return self.port

	def getIp(self):
		return self.ip

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


	class Sniffer:

		def __init__(self,clientfd,mylambda):
			self.clientfd = clientfd
			self.mylambda = mylambda

		def createRawSocket(self):	

			try:
				rawfd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs((0x0003)))
			except socket.error ,msg:
				print "Cannot create raw socket"
				sys.exit()
			return rawfd

		def startSniffing(self,rawfd):

			while True:

				packet = rawfd.recvfrom(1500)
				packet = packet[0]
				if self.sortOutPackets(packet,self.mylambda) == True:
					self.mylambda.sendMessageToServer(self.clientfd,packet)
				#print packet

		# Sorting out packets to/from localhost, to Server IP or if IPv6 is in use
		def sortOutPackets(self,packet,mylambda):

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
					if(str(d_addr) == mylambda.getIp() or str(s_addr) == mylambda.getIp() ):
						return False

			return True


def main():
	
	hostip = "127.0.0.1"
	port = 45681

	mylambda  = Lambda(hostip,port)
	clientfd  = mylambda.startClient()

	mysniffer = Lambda.Sniffer(clientfd,mylambda)
	rawfd = mysniffer.createRawSocket()
	mysniffer.startSniffing(rawfd)

	#mylambda.sendMessageToServer(clientfd,"hi")
	#mylambda.recvMessageFromServer(clientfd)

	mylambda.closeClient(clientfd)



if __name__ == "__main__":
	main()