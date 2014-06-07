import os,sys,socket,threading,time,Queue
from struct import *

class Gemini(object):

	def __init__(self,serverAddr):
		# serverAddr -> (IP,Port)
		self.serverAddr = serverAddr

	def getServerAddr(self):
		return self.serverAddr

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
			clientfd.connect(self.serverAddr)

		except socket.error ,msg:
				print "Cannot create socket to server" 
				print msg

		return clientfd

	def sendMessageToServer(self,clientfd,message):
		clientfd.sendto(message,self.serverAddr)
		

	def recvMessageFromServer(self,clientfd):
		try:
			recv = clientfd.recvfrom(2048)
			return recv[0]
		except socket.error:
			print "Server might not be up"

			#[0] has reply [1] is none

	def closeClient(self,clientfd):
			clientfd.close()


class Sniffer(object):

	def __init__(self,clientfd,mygemini,modus,queue):
		self.clientfd = clientfd
		self.mygemini = mygemini
		self.modus = modus #off-> start sniffing off on-> start sniffing on
		self.queue = queue

	def setModus(self,modus):
		self.modus = modus # modus either true or false

	def createRawSocket(self):	

		try:
			rawfd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs((0x0003)))
			self.rawfd = rawfd
		except socket.error ,msg:
			print "Cannot create raw socket"
			print " -> " + str(msg)
		return rawfd


	def startSniffing(self):
		
		while self.modus == True:
			#print self.modus
			packet = self.rawfd.recvfrom(2048)
			packet = packet[0]
			if self.sortOutPackets(packet,self.mygemini) == True:
				#self.mygemini.sendMessageToServer(self.clientfd,packet)
				self.queue.put(packet)

	def stopSniffing(self):
		self.rawfd.close()
		

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
				if(str(d_addr) == (mygemini.getServerAddr()[0]) or str(s_addr) == (mygemini.getServerAddr()[0]) ):
					return False

		return True

class GeminiMainThread(threading.Thread):

	def __init__(self, threadId, threadName, serverAddr = None ):

		#Checks if thread is of GeminiMainThread Class Type and not Subclass type
		#if so, thread is being initialized within the subclass 
		if serverAddr != None:
			threading.Thread.__init__(self)
			print "Gemini Main Thread has been successfully initialized ..."

		self.threadId = threadId
		self.threadName = threadName

		self.serverAddr = serverAddr
			

	def run(self):

		gemini  = Gemini(self.serverAddr)
		self.geminiClassObj = gemini 	#reference to Gemini Object
		clientfd  = gemini.startClient() 
		self.geminiSocketClientFd = clientfd #returned FD from socket to server


class GeminiDelegatorThread(GeminiMainThread):

	def __init__(self, threadId, threadName, threadtype, mainthread , queue, runmodus = True ):

		super(GeminiDelegatorThread,self).__init__(threadId, threadName, None)

		threading.Thread.__init__(self)

		self.threadtype = threadtype
		self.mainthread = mainthread
		self.runmodus = runmodus
		self.queue = queue

		self.mySniffer = None

		print "Delegator Thread has been successfully initialized ..."

	def run(self):

		try:
			myGemini = self.mainthread.geminiClassObj
			#print myGemini
			myGeminiClientFd = self.mainthread.geminiSocketClientFd
			#print myGeminiClientFd
		except AttributeError,msg:
			time.sleep(2)
			myGeminiClientFd = self.mainthread.geminiSocketClientFd
			myGemini = self.mainthread.geminiClassObj

		print "Delegator Thread started listening ..."

		while self.runmodus:
			
			data = myGemini.recvMessageFromServer(myGeminiClientFd)
			print data
			if data == "ISEEU":
				#print "he said bye"
				pass
			if data == "STARTSNIFFING":

				mySniffer = GeminiSnifferThread(4,"SnifferThread","Sniffer",self.mainthread,self.queue )
				self.mySniffer = mySniffer
				mySniffer.start()

			if data == "STOPSNIFFING":

				if self.mySniffer != None:
					self.mySniffer.stop()

			if data == "BYE":
				print "Shutting everything down"
				print threading.enumerate()
				self.queue.put("GEMINISHUTDOWN")
				
				self.stop()

			#print threading.enumerate()

	def stop(self):
		self.mainthread.geminiClassObj.closeClient(self.mainthread.geminiSocketClientFd)
		self.runmodus = False
		time.sleep(2)
		try:
			self.join()
		except RuntimeError, msg:
			print msg


class GeminiTransmitterThread(GeminiMainThread):

	def __init__(self, threadId, threadName, threadtype, mainthread, queue, runmodus = True):

		super(GeminiTransmitterThread,self).__init__(threadId, threadName, None)

		threading.Thread.__init__(self)

		self.threadtype = threadtype
		self.mainthread = mainthread
		self.runmodus = runmodus
		self.queue = queue

		print "Transmitter Thread has been successfully initialized ..."

	def run(self):

		self.initializeHandshakeToServer()
		while self.runmodus == True:
			while not self.queue.empty():
				data = self.queue.get()
				if data == "GEMINISHUTDOWN":
					self.stop()
				else:
					self.sendMessageToServer(data)


	def initializeHandshakeToServer(self):
		#print self.mainthread.serverAddr
		self.mainthread.geminiSocketClientFd.sendto("HIYA",self.mainthread.serverAddr)

	def sendMessageToServer(self,message):
		self.mainthread.geminiSocketClientFd.sendto(message,self.mainthread.serverAddr)

	def stop(self):
		self.runmodus = False
		time.sleep(2)
		try:
			self.join()
		except RuntimeError, msg:
			print msg


class GeminiSnifferThread(GeminiMainThread):

	def __init__(self, threadId, threadName, threadtype, mainthread, queue):

		super(GeminiSnifferThread,self).__init__(threadId, threadName)

		threading.Thread.__init__(self)

		self.threadtype = threadtype
		self.mainthread = mainthread
		self.queue = queue


		print "Sniffer Thread has been successfully initialized ..."

	def run(self):

		mysniffer = Sniffer(self.mainthread.geminiSocketClientFd,self.mainthread.geminiClassObj,True,self.queue)
		self.mysniffer = mysniffer
		rawfd = mysniffer.createRawSocket()
	 	mysniffer.startSniffing()

	def stop(self):
		self.mysniffer.stopSniffing()
		self.mysniffer.modus = False
		time.sleep(2)
		try:
			self.join()
		except RuntimeError, msg:
			print msg


def main():
	
	serverAddr = ("127.0.0.1",45681)
	threadlist = []

	transmitqueue = Queue.Queue()

	mainthread = GeminiMainThread(1,"GeminiThread",serverAddr)
	mainthread.start()
	threadlist.append(mainthread)


	transmitter = GeminiTransmitterThread(2,"TransmitterThread","transmitter",mainthread , transmitqueue , True )
	transmitter.start()
	threadlist.append(transmitter)

	delegator = GeminiDelegatorThread(3,"DelegatorThread","delegator",mainthread, transmitqueue , True )
	delegator.start()
	threadlist.append(delegator)




	# try:
	# 	mysniffer = Gemini.Sniffer(clientfd,mygemini)
	# 	rawfd = mysniffer.createRawSocket()
	# 	mysniffer.startSniffing(rawfd)
	# except socket.error:
	# 	print "oops"


	# mygemini.closeClient(clientfd)



if __name__ == "__main__":
	main()