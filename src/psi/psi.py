import socket               

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,0)         
host = "127.0.0.1"
port = 45681            
s.bind((host, port))        
            
while True:
 
   msg,addr = s.recvfrom(1500)
   print str(msg) + " FROM " + str(addr)
   
#s.close()  