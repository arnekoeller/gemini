#!/usr/bin/python

"""
	Description goes here
	
"""


import socket
import sys
import time           
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
		
		""" 
			atohex:
			Returns Hex-String.
			Converts given String into Hex-String.
			Should only be used to display data
			in Hex not Protocol Headers because
			the byte order varies there
		"""

		hexstr = ""
		for i in range(0,len(string)):
			if ((i%8 == 0) and (i!=0) ):
				hexstr += "\n"
			hexstr += str(string[i].encode("hex")) + " "

		return hexstr

	def buildMac(self,data) :
			mac = ""
			for i in range(0,5):
				if i < 4:
					mac += str(data[i].encode("hex")) + ":"
				else:
					mac += str(data[i].encode("hex"))
			return mac


	def processData(self,packet):

		# size of ethernet header in bytes
		ethhdr_len = 14 	

		# get ethhdr from the packet array				
		ethhdr = packet[:ethhdr_len]	

		try:
			# unpack ethhdr so we can address values within 
			ethhdr = unpack("!6s6sH" , ethhdr)		
		except Exception , msg:
			print "unpack() error"				
			print " -> " + str(msg)
			pass

		# get ethernet protocol for further layers
		ethhdr_proto = socket.ntohs(ethhdr[2])		

		print "############# ETH ######################"

		print "MAC DEST: " + self.buildMac(packet[0:6]) 	
		print "MAC SRC:  " + self.buildMac(packet[6:12]) 
		print "ETH PROT: " + str(ethhdr_proto)


		if ethhdr_proto == 8:	# if ethernet packet contains IP packet

			# note: the client software will only send ipv4 packets therefor its 
			# 		not necessary to parse for ipv6 packets

			# size of ipv4 header in bytes
			ipv4_len = 20 	

			# get part of packet where IP header is						
			iphdr = packet[ethhdr_len:ipv4_len+ethhdr_len]	

			# unpack ip header so we can address values within
			iphdr = unpack("!BBHHHBBH4s4s" , iphdr)	

			ip_version_ihl = iphdr[0]
			ip_version = ip_version_ihl >> 4
			ip_ihl = ip_version_ihl & 0xF
			iphdr_len = ip_ihl * 4

			ip_tos = iphdr[1]
			ip_tot_len = iphdr[2]
			ip_id = iphdr[3]
			
			ip_frag = iphdr[4]

			ip_ttl = iphdr[5]
			ip_protocol = iphdr[6]
			ip_cksm = iphdr[7]
			ip_s_addr = socket.inet_ntoa(iphdr[8]);
			ip_d_addr = socket.inet_ntoa(iphdr[9]);

			print "############# IPv4 ######################"

			print "IP Version : " + str(ip_version)
			print "IP IHL : " + str(ip_ihl)
			print "IP TOS : " + str(ip_tos)
			print "IP total length : " + str(ip_tot_len)
			print "IP ID : " + str(ip_id)
			#print "IP FRAG : " + str(ip_frag)
			print "IP TTL : " + str(ip_ttl)
			print "IP checksum : " + str(ip_cksm)
			print "IP SRC: "+ str(ip_s_addr)
			print "IP DEST: " + str(ip_d_addr)


			#ICMP Packets
			if ip_protocol == 1 :		# if IP packet contains UDP packet 

				# size of icmp header in bytes
				icmphdr_len = 4

				# get part of packet where ICMP header is
				icmphdr = packet[(ethhdr_len + iphdr_len):ethhdr_len+iphdr_len+icmphdr_len]

				# unpack udp header so we can address values within
				icmphdr = unpack("!BBH" , icmphdr)	

				icmp_type = icmphdr[0]
				icmp_code = icmphdr[1]
				icmp_cksm = icmphdr[2]

				

				# calculate where data begins
				data_offset = ethhdr_len + iphdr_len + icmphdr_len

				data = packet[data_offset:]

				print "############# ICMP ######################"
				print "ICMP type: " + str(icmp_type)
				if icmp_type == 8:
					print "Ping Echo Request"
				elif icmp_type == 0:
					print "Ping Echo Reply"
				print "ICMP code: " + str(icmp_code)
				print "icmp_cksm:" + str(icmp_cksm)



				print self.atohex(data)

			#TCP
			elif ip_protocol == 6 :	# if IP packet contains TCP packet 

				# size of tcp header in bytes
				tcphdr_len = 20

				# get part of packet where TCP header is
				tcphdr = packet[(ethhdr_len + iphdr_len):ethhdr_len + iphdr_len+tcphdr_len]		

				# unpack tcp header so we can address values within
				tcphdr = unpack("!HHLLBBHHH" , tcphdr)	


				tcp_source_port = tcphdr[0]
				tcp_dest_port = tcphdr[1]
				tcp_sequence = tcphdr[2]
				tcp_acknowledgement = tcphdr[3]
				tcp_doff_reserved = tcphdr[4]
				tcp_length = (tcp_doff_reserved >> 4)*4

				
				print "############# TCP ######################"
				print "TCP SRC PORT: " + str(tcp_source_port)
				print "TCP DEST PORT : "+ str(tcp_dest_port)
				print "TCP SEQ: " + str(tcp_sequence)
				print "TCP ACK: " + str(tcp_acknowledgement)
				print "TCP LEN: " + str(tcp_length)

				# calculate where data begins
				data_offset = ethhdr_len + iphdr_len + tcp_length 

				data = packet[data_offset:]

				

				if tcp_source_port == 80 or tcp_source_port == 8080 or tcp_dest_port == 80 or tcp_dest_port == 8080:
					# because of padding added to the packet check if data > 6
					if len(data) > 6:
						print "################ HTTP #################"
						print self.atohex(data)
						return
				
				if tcp_source_port == 443 or tcp_source_port == 443 or tcp_dest_port == 443 or tcp_dest_port == 443:
					if len(data) > 6:

						tlshdr_len = 5

						tlshdr = packet[ethhdr_len+iphdr_len+tcphdr_len+12:ethhdr_len+iphdr_len+tcphdr_len+12+tlshdr_len]

						#try:
						#	tlshdr = unpack("BHH",tlshdr)
						#except:
						#	return

						#tlshdr_content_type = tlshdr[0]
						#tlshdr_version = tlshdr[1]
						#tlshdr_length = tlshdr[2]

						tlshdr_content_type = tlshdr[0].encode("hex")
						tlshdr_version = tlshdr[1].encode("hex") + tlshdr[2].encode("hex")
						tlshdr_length = tlshdr[3].encode("hex") + tlshdr[4].encode("hex")

						print "################ HTTPS #################"
						print tlshdr_content_type
						if tlshdr_content_type == "14":
							print "Protocol Type: ChangeCipherSpec"
						elif tlshdr_content_type == "15":
							print "Protocol Type: Alert"
						elif tlshdr_content_type == "16":
							print "Protocol Type: Handshake"
						elif tlshdr_content_type == "17":
							print "Protocol Type: Application"

						print tlshdr_version
						print tlshdr_length

						data = packet[ethhdr_len+iphdr_len+tcphdr_len+12+tlshdr_len:]
						print self.atohex(data)

						return
				
				print self.atohex(data)


			#UDP packets
			elif ip_protocol == 17 :	# if UDP packet contains UDP packet

				# size of udp header in bytes
				udphdr_len = 8

				# get part of packet where UDP header is
				udphdr = packet[(ethhdr_len + iphdr_len):ethhdr_len+iphdr_len+udphdr_len]

				# unpack udp header so we can address values within
				udphdr = unpack("!HHHH" , udphdr)

				udp_src_port = udphdr[0]
				udp_dest_port = udphdr[1]
				udp_length = udphdr[2]
				udp_cksm = udphdr[3]



				print "############# UDP ######################"
				print "UDP SRC PORT: " + str(udp_src_port)
				print "UDP DEST PORT: " + str(udp_dest_port)
				print "UDP LENGTH: " + str(udp_length)
				print "UDP CKSM: " + str(udp_cksm)

				
				
				if udp_dest_port == 53 or udp_src_port == 53:	# most likely dns 

					# size of dns header in bytes
					dnshdr_len = 12

					# get part of packet where DNS header is
					dnshdr = packet[ethhdr_len+iphdr_len+udphdr_len:ethhdr_len + iphdr_len+udphdr_len+dnshdr_len]

					dnshdr = unpack("!HHHHHH",dnshdr)

					dns_identifier = dnshdr[0]
					dns_flags = dnshdr[1]
					dns_qcount = dnshdr[2]
					dns_acount = dnshdr[3]
					dns_nscount = dnshdr[4]
					dns_arcount = dnshdr[5]

					print "############### DNS ###############"
					print dns_identifier
					print dns_flags
					print dns_qcount
					print dns_acount
					print dns_nscount
					print dns_arcount


					# pretty hacky but it doesn't have to be perfect
					if dns_flags == 256:
						print "Query"
					elif dns_flags == 33152:
						print "Response no error"

					query_offset = ethhdr_len + iphdr_len + udphdr_len + dnshdr_len

					dns_query_len = 16
					dns_query = packet[query_offset:query_offset+dns_query_len] 
					try:
						dns_query = unpack("12sHH",dns_query)
					except:
						return

					# Name must be decoded later
					print "Name: " + str(dns_query[0].encode("hex"))
					print "Type: " + str(socket.ntohs(dns_query[1]))
					
					if socket.ntohs(dns_query[1]) == 1:
						print "Type A requested"
					elif socket.ntohs(dns_query[1]) == 15:
						print "Type MX requested"
					elif socket.ntohs(dns_query[1]) == 28:
						print "Type AAAA requested"

					print "Class: " + str(socket.ntohs(dns_query[2]))

					# the dns server's answer doesn't matter to us so i'm
					# leaving it out

					return


				# calculate where data begins
				data_offset = ethhdr_len + iphdr_len + udphdr_len

				data = packet[data_offset:]
				print self.atohex(data)


			
			else :	#some other IP packets

				pass

		#ARP
		if ethhdr_proto == 1544:	# if ethernet packet contains ARP packet

			# size of arp header in bytes
			arphdr_len = 28

			# get part of packet where ARP header is
			arphdr = packet[ethhdr_len:arphdr_len+ethhdr_len]

			# unpack ARP header so we can address values within
			arphdr = unpack("HHBBH6s4s6s4s",packet[ethhdr_len:arphdr_len+ethhdr_len])


			print "############# ARP ######################"
			print socket.htons(arphdr[0])
			print arphdr[1]
			print arphdr[2]
			print arphdr[3]
			print socket.ntohs(arphdr[4])
			print "Target MAC" + str(self.buildMac(arphdr[5]))
			print "Sender IP" + str(socket.inet_ntoa(arphdr[6]))
			print "Target MAC" + str(self.buildMac(arphdr[7]))
			print "Target IP" + str(socket.inet_ntoa(arphdr[8]))

	

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