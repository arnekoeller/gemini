import socket,sys           
from struct import *


class Gemini_Server:

	def __init__(self,serverip,serverport):
		self.serverip = serverip
		self.serverport = serverport

	def getPort(self):
		return self.serverport

	def getIp(self):
		return self.serverip

	def startServer(self):
		# this is a UDP Server !	

		try:
			serverfd = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,0)             
			serverfd.bind((self.serverip, self.serverport))

		except socket.error,msg:
			print "Could not create Gemini Server"
			print msg
			sys.exit()

		return serverfd
		            

	def sendMessageToClient(self,serverfd,message):
		serverfd.sendto(message)
		
	def recvMessageFromClient(self,serverfd):

		recv = serverfd.recvfrom(1500)
		return recv[0]	#[0] has reply [1] is none


	def processData(self,packet):


		eth_length = 14
		eth_header = packet[:eth_length]
		eth = unpack('!6s6sH' , eth_header)
		eth_protocol = socket.ntohs(eth[2])

		packet_content = self.buildMac(packet[0:6]) + \
						  self.buildMac(packet[6:12]) + str(eth_protocol)
		print packet_content

		if eth_protocol == 8:
					
					ip_header = packet[eth_length:20+eth_length]

					iph = unpack('!BBHHHBBH4s4s' , ip_header)

					version_ihl = iph[0]
					version = version_ihl >> 4
					ihl = version_ihl & 0xF
					iph_length = ihl * 4

					tos = iph[1]
					tot_len = iph[2]
					ip_id = iph[3]
					
					frag = iph[4]

					ttl = iph[5]
					protocol = iph[6]
					cksm = iph[7]
					s_addr = socket.inet_ntoa(iph[8]);
					d_addr = socket.inet_ntoa(iph[9]);

					# print "iphlength " + str(iph_length)
					# print tos
					# print "total length " + str(tot_len)
					# print ip_id
					# print ttl
					# print "checksum " + str(cksm)
					# print s_addr

					if protocol == 6 :

						t = iph_length + eth_length
						tcp_header = packet[t:t+20]

						tcph = unpack('!HHLLBBHHH' , tcp_header)

						source_port = tcph[0]
						dest_port = tcph[1]
						sequence = tcph[2]
						acknowledgement = tcph[3]
						doff_reserved = tcph[4]
						tcph_length = doff_reserved >> 4

						h_size = eth_length + iph_length + (tcph_length * 4)
						data_size = len(packet) - h_size

						data = packet[h_size:]
						print data


		

	def buildMac(self,data) :
			mac = "%.2x%.2x%.2x%.2x%.2x%.2x" % (ord(data[0]) , ord(data[1]) , 
												ord(data[2]) , ord(data[3]) ,
												ord(data[4]) , ord(data[5]))
			return mac

	def closeServer(self,serverfd):
			serverfd.close()

	def closedownHandshake(self,serverfd):
		self.sendMessageToClient(serverfd,"bye")


def main():
	
	serverip = "127.0.0.1"
	serverport = 45681

	mygemini_server  = Gemini_Server(serverip,serverport)
	serverfd  = mygemini_server.startServer()

	try:
		while True:
			mygemini_server. processData(mygemini_server.recvMessageFromClient(serverfd))
	except KeyboardInterrupt:
		print "\nProgram aborted ........."
		print "Shutting down Server ...."
		mygemini_server.closedownHandshake(serverfd)

	mygemini_server.closeServer(serverfd)




if __name__ == "__main__":
	main()