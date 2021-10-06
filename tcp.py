import socket 
import struct #pack function
import random
from ipv4 import IPv4

'''
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                             |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window           |
   |       |           |G|K|H|T|N|N|                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''
#http://www.daemon.org/tcp.html
#https://en.wikipedia.org/wiki/Transmission_Control_Protocol

class TCP(IPv4):
    def __init__(self, ip_src=socket.gethostbyname_ex(socket.gethostname())[-1][0], ip_dst='127.0.0.1', ip_prot=socket.IPPROTO_TCP, tcp_src=random.randrange(50000, 60000), tcp_dst=80, tcp_flag=1, data=''):
        super().__init__(ip_src, ip_dst, ip_prot)
        self.tcp_src=tcp_src
        self.tcp_dst=tcp_dst
        self.tcp_flag=tcp_flag
        self.data=data
    
    def TCPframe(self):
        TCP_SRC=self.tcp_src                #Source port

        TCP_DST=self.tcp_dst                #Destination port

        TCP_SEQ=0                           #Sequence number

        TCP_ACK=0                           #Acknowledgment number

        TCP_DOFF=5                          #Data offset
                                            #Specifies the size of the TCP header in 32-bit words.

        TCP_RES=0                           #Reserved
        TCP_DOFF_RES=(TCP_DOFF << 4)+TCP_RES

        TCP_FLAG=self.tcp_flag              #Contains 9 1-bit flags (control bits) as follows:
                                                #NS (1 bit): ECN-nonce - concealment protection
                                                #CWR (1 bit): Congestion window reduced (CWR) flag is set by the sending host to indicate that it received a TCP segment with the ECE flag set and had responded in congestion control mechanism.[b]
                                                #ECE (1 bit): ECN-Echo has a dual role, depending on the value of the SYN flag. It indicates:
                                                    #If the SYN flag is set (1), that the TCP peer is ECN capable.
                                                    #If the SYN flag is clear (0), that a packet with Congestion Experienced flag set (ECN=11) in the IP header was received during normal transmission.[b] This serves as an indication of network congestion (or impending congestion) to the TCP sender.
                                                #URG (1 bit): Indicates that the Urgent pointer field is significant
                                                #ACK (1 bit): Indicates that the Acknowledgment field is significant. All packets after the initial SYN packet sent by the client should have this flag set.
                                                #PSH (1 bit): Push function. Asks to push the buffered data to the receiving application.
                                                #RST (1 bit): Reset the connection
                                                #SYN (1 bit): Synchronize sequence numbers. Only the first packet sent from each end should have this flag set. Some other flags and fields change meaning based on this flag, and some are only valid when it is set, and others when it is clear.
                                                #FIN (1 bit): Last packet from sender

        TCP_WIN=socket.htons (5840)	        #Window size - maximum allowed window size
                                            #The following algorithm determines the optimal window size, based on the network delay and the link size:
                                                #Optimal size = (size of the link in MB/s) x (round trip delay in seconds)                         

        TCP_CHECK=0                         #Checksum

        TCP_URG=0                           #Urgent pointer

        TCP_OPT=0                           #Options

        TCP_DATA=self.data                  #Data

        TCP_PAD=0                           #Padding

        
        


        #https://docs.python.org/3/library/struct.html
        TCP_HEADER=struct.pack('!HHLLBBHHH', TCP_SRC, TCP_DST, TCP_SEQ, TCP_ACK, TCP_DOFF_RES, TCP_FLAG, TCP_WIN, TCP_CHECK, TCP_URG)
        
        IP_HEADER=IPv4.IPframe(self, total_length = TCP_DOFF*4 + len(TCP_DATA))

        temp = self.tcpchecksumcalc(TCP_HEADER, total_length = TCP_DOFF*4 + len(TCP_DATA))

        TCP_HEADER=struct.pack('!HHLLBBHHH', TCP_SRC, TCP_DST, TCP_SEQ, TCP_ACK, TCP_DOFF_RES, TCP_FLAG, TCP_WIN, temp, TCP_URG)

        return [IP_HEADER, TCP_HEADER]

    def tcpchecksumcalc(self, TCP_HEADER, total_length):
        output = []
        sum = struct.pack('!4s4sBBH', socket.inet_aton(self.ip_src), socket.inet_aton(self.ip_dst), 0, self.ip_prot, total_length)

        for x in range(0, len(sum), 2):
            output.append((sum[x]<<8)+sum[x+1])

        sum = TCP_HEADER

        for x in range(0, len(sum), 2):
            output.append((sum[x]<<8)+sum[x+1])

        for x in range(1, len(output)):
         output[0]+=output[x]
         if output[0] >= 65536:                 #calculating sum of every 'words'
            output[0] -= 65535

        return 65535-output[0] #16bit compliment of it
       

xd = TCP()
print(xd.TCPframe())
