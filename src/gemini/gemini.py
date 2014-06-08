import os,sys,socket,threading,time,Queue
from struct import *



def checkRoot():
	if (os.getuid()!= 0):
		return False
	else:
		return True

def checkOSType():
	if sys.platform == "linux" or sys.platform == "linux2":
		return "Linux"
	elif sys.platform == "darwin":
		return "MacOSX"
	elif sys.platform == "win32":
		return "Windows"


def startClient(serverAddr):

	try:

		clientfd = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,0); 
		clientfd.connect(serverAddr)

	except socket.error ,msg:
		print "[-] Cannot create socket to server" 
		print "    -> " + str(msg)

	return clientfd

def closeClient(clientfd):
	clientfd.close()

def sendMessageToServer(clientfd,message,serverAddr):
	try:
		clientfd.sendto(message,serverAddr)
	except socket.error,msg:
		#print "[!] Error:" + str(msg)
		#error already handled
		pass

def recvMessageFromServer(clientfd):

	try:
		recv = clientfd.recvfrom(2048)
		return recv[0]
	except socket.error:
		return "SERVERNOTUP"


	

def createRawSocket():	

	try:
		rawfd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs((0x0003)))
	except socket.error ,msg:
		print "[-] Cannot create raw socket"
		print "    -> " + str(msg)

	return rawfd

def sniff(rawfd,queue,serverAddr):

	packet = rawfd.recvfrom(2048)
	packet = packet[0]
	if sortOutPackets(packet,serverAddr) == True:
		queue.put(packet)

def stopSniffing(rawfd):
	rawfd.close()

def sortOutPackets(packet,serverAddr):

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
		if(str(d_addr) == serverAddr[0] or str(s_addr) == serverAddr[0] ):
			return False

	return True



class GeminiDelegatorThread(threading.Thread):

	def __init__(self, threadId, queue, serverAddr, threadlist , runmodus = True ) :

		threading.Thread.__init__(self)

		self.id = id
		self.queue = queue
		self.serverAddr = serverAddr
		self.runmodus = runmodus
		self.threadlist = threadlist

		self.server_state = "DOWN"
		self.mySniffer = None

		print "[+] Delegator Thread has been successfully initialized "

	def run(self):

		self.gsockfd = startClient(self.serverAddr)

		print "[!] Delegator Thread started listening for Server " + str(self.serverAddr) + " to communicate"

		self.queue.put("HIYA")	#start Handshake

		while self.runmodus:

			data = recvMessageFromServer(self.gsockfd)
			#print data
			if data == "SERVERNOTUP":
				print "[!] Server is probably not up. Trying to contact server again in 30s"
				time.sleep(30)	# wait for 30secs and try to contact server again
				self.queue.put("HIYA")
				self.server_state = "DOWN"
				continue
			if data == "ISEEU":
				# confirmation that handshake succeeded
				self.server_state = "UP"
				pass
			if data == "STARTSNIFFING":

				mySniffer = GeminiSnifferThread(3, self.queue, self.serverAddr)
				self.mySniffer = mySniffer
				mySniffer.start()
				self.threadlist.append(mySniffer)

			if data == "STOPSNIFFING":

				if self.mySniffer != None:
					self.mySniffer.stop()

			if data == "GEMINISHUTDOWN":
				print "[!] Shutting everything down. Please wait ..."

				# Turn off Sniffer
				if self.mySniffer != None:
					self.mySniffer.stop()

				# Send command to Queue so Transmitter shuts down
				self.queue.put("GEMINISHUTDOWN")

				# Turn Delegator off
				self.stop()


	def stop(self):
		print "[!] Stopping Delegator"
		time.sleep(3)
		closeClient(self.gsockfd)
		self.runmodus = False
		time.sleep(1)


class GeminiTransmitterThread(threading.Thread):

	def __init__(self, threadId , queue, gsockfd, serverAddr, runmodus = True):

		threading.Thread.__init__(self)

		self.threadId = threadId
		self.gsockfd = gsockfd
		self.serverAddr = serverAddr
		self.runmodus = runmodus
		self.queue = queue

		print "[+] Transmitter Thread has been successfully initialized "

	def run(self):

		print "[!] Trying to contact Server at " + str(self.serverAddr)

		while self.runmodus == True:
			while not self.queue.empty():
				data = self.queue.get()
				if data == "GEMINISHUTDOWN":
					self.stop()
				else:
					sendMessageToServer(self.gsockfd,data,self.serverAddr)


	def stop(self):
		print "[!] Stopping Transmitter "
		self.runmodus = False
		time.sleep(1)



class GeminiSnifferThread(threading.Thread):

	def __init__(self, threadId, queue, serverAddr, runmodus = True):

		threading.Thread.__init__(self)

		self.threadId = threadId
		self.queue = queue
		self.runmodus = runmodus
		self.serverAddr = serverAddr

		self.rawfd = None

		print "[+] Sniffer Thread has been successfully initialized "

	def run(self):

	 	rawfd = createRawSocket()
	 	self.rawfd = rawfd

	 	print "[~] Sniffing ..."
	 	while self.runmodus == True:
	 		sniff(rawfd,self.queue,self.serverAddr)

	def stop(self):
		print "[!] Stopping Sniffer"
		self.runmodus = False
		stopSniffing(self.rawfd)
		time.sleep(1)



def main():

	########################################## Start Screen #########################################

	os.system("clear")	#clear screen
	
	print """                           _____                      _           _ 
  			  / ____|                    (_)         (_)
			 | |  __    ___   _ __ ___    _   _ __    _ 
			 | | |_ |  / _ \ | '_ ` _ \  | | | '_ \  | |
			 | |__| | |  __/ | | | | | | | | | | | | | |
			  \_____|  \___| |_| |_| |_| |_| |_| |_| |_| arne.koeller@gmail.de"""
	print "\t\t\t   Network Forensic Toolkit"
	print "\n\n\n"
	print "[+] Starting Gemini Client  "

	#################################################################################################

	if checkRoot() == False:
		print "[!] You need to have root user rights to run Gemini \n\n\n"
		sys.exit()
	if checkOSType() != "Linux":
		print "[!] You need to run this program on a *nix System\n\n\n"
		sys.exit()

	serverAddr = ("127.0.0.1",45681)
	threadlist = []

	transmitqueue = Queue.Queue()

	time.sleep(1)

	delegator = GeminiDelegatorThread(1, transmitqueue , serverAddr, threadlist, True )
	delegator.start()
	threadlist.append(delegator)

	time.sleep(3)
	
	transmitter = GeminiTransmitterThread(2, transmitqueue , delegator.gsockfd, serverAddr, True )
	transmitter.start()
	threadlist.append(transmitter)

	

	# Join all threads 
	for thr in threadlist:
		thr.join()

	print "[+] Thank you for using Gemini"
 



if __name__ == "__main__":
	main()