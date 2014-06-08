import socket,sys,time           
from struct import *


class Gemini_Server:

	def __init__(self,serverip,serverport,clientaddr):
		self.serverip = serverip
		self.serverport = serverport
		self.clientaddr = clientaddr

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
			print " -> " + str(msg)
			sys.exit()

		return serverfd
		            

	def sendMessageToClient(self,serverfd,message):
		try:
			serverfd.sendto(message,self.clientaddr)
		except TypeError, msg:
			print "No client connection was established"
			print " -> " + str(msg)
			sys.exit()
		
	def recvMessageFromClient(self,serverfd):

		recv = (data,addr) = serverfd.recvfrom(2048)
		self.clientaddr = recv[1]
		return recv[0]	#[0] has reply [1] is none

	def atohex(self,string):
		hexstr = ""
		for i in range(0,len(string)):
			if ((i%8 == 0) and (i!=0) ):
				hexstr += "\n"
			hexstr += str(string[i].encode("hex")) + " "

		return hexstr


	def processData(self,packet):


		eth_length = 14
		eth_header = packet[:eth_length]

		try:
			eth = unpack('!6s6sH' , eth_header)
		except Exception , msg:
			print "unpack() error"
			print " -> " + str(msg)
			pass

		eth_protocol = socket.ntohs(eth[2])

		packet_content = self.buildMac(packet[0:6]) + \
						  self.buildMac(packet[6:12]) + str(eth_protocol)
		print eth_protocol

		if eth_protocol == 8:
			#print "--------------------------------------------"
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

			#TCP
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

				print "TCp"
				print "+++++++++++++++++++++++++++++"
				print self.atohex(data)
				print "+++++++++++++++++++++++++++++"

			#ICMP Packets
			elif protocol == 1 :
				u = iph_length + eth_length
				icmph_length = 4
				icmp_header = packet[u:u+4]

				#now unpack them :)
				icmph = unpack('!BBH' , icmp_header)

				icmp_type = icmph[0]
				code = icmph[1]
				checksum = icmph[2]

				#print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)

				h_size = eth_length + iph_length + icmph_length
				data_size = len(packet) - h_size

				#get data from the packet
				data = packet[h_size:]

				print "ICMP"
				print "----------------------------------"
				print self.atohex(data)
				print "----------------------------------"

			#UDP packets
			elif protocol == 17 :
				u = iph_length + eth_length
				udph_length = 8
				udp_header = packet[u:u+8]

				#now unpack them :)
				udph = unpack('!HHHH' , udp_header)

				source_port = udph[0]
				dest_port = udph[1]
				length = udph[2]
				checksum = udph[3]

				print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)

				h_size = eth_length + iph_length + udph_length
				data_size = len(packet) - h_size

				#get data from the packet
				data = packet[h_size:]

				print "UDP"
				print "###################################"
				print self.atohex(data)
				print "###################################"

			#some other IP packet like IGMP
			else :
				#print 'Protocol other than TCP/UDP/ICMP'
				pass

		#ARP
		if eth_protocol == 1544:

			print "--> --> --> ARP <-- <-- <--"

		

	def buildMac(self,data) :
			mac = "%.2x%.2x%.2x%.2x%.2x%.2x" % (ord(data[0]) , ord(data[1]) , 
												ord(data[2]) , ord(data[3]) ,
												ord(data[4]) , ord(data[5]))
			return mac

	def closeServer(self,serverfd):
			serverfd.close()

	def serverClosedownHandshake(self,serverfd):
		#self.sendMessageToClient(serverfd,"STOPSNIFFING")
		self.sendMessageToClient(serverfd,"GEMINISHUTDOWN")


def main():
	
	serverip = "127.0.0.1"
	serverport = 45681

	mygemini_server  = Gemini_Server(serverip,serverport,None)
	serverfd  = mygemini_server.startServer()

	try:
		while True:
			data = mygemini_server.recvMessageFromClient(serverfd)
			if data == "HIYA":
				mygemini_server.sendMessageToClient(serverfd,"STARTSNIFFING")
			else:
				mygemini_server.processData(data)
	except KeyboardInterrupt:
		print "\nProgram aborted ........."
		print "Shutting down Server ...."
		mygemini_server.serverClosedownHandshake(serverfd)
		time.sleep(10)
		#mygemini_server.sendMessageToClient(serverfd,"STARTSNIFFING")

	mygemini_server.closeServer(serverfd)




if __name__ == "__main__":
	main()