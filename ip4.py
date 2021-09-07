import socket 
import struct #pack function

'''
     0                   1                   2                   3   
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |   DSCP    |ECN|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |   Padding     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
'''

#https://en.wikipedia.org/wiki/IPv4

class IP():
   def __init__(self, ip_src=socket.gethostbyname_ex(socket.gethostname())[-1][2], ip_dst='127.0.0.1', ip_prot=socket.IPPROTO_TCP ):
      self.ip_src=ip_src
      self.ip_dst=ip_dst
      self.ip_prot=ip_prot

   def frame(self):
      #If we want use struct.pack to pack whole frame we need to group variables to specific length (multiplicity of 8)

      IP_VER=4    

      IP_IHL=5                                     #Internet Header Length
      IP_VER_IHL=(IP_VER << 4) + IP_IHL


      IP_DSCP=0                                    #Differentiated Services Code Point
                                                   #Originally defined as the type of service (ToS), 
                                                   #this field specifies differentiated services (DiffServ) per RFC 2474.
                                                   #Real-time data streaming makes use of the DSCP field. An example is Voice over IP (VoIP), 
                                                   #which is used for interactive voice services.

      IP_ECN=0                                     #Explicit Congestion Notification
                                                   #This field is defined in RFC 3168 and allows end-to-end notification of network congestion without dropping packets. 
                                                   #ECN is an optional feature available when both endpoints support it and effective when also supported by the underlying network.
      IP_DSCP_ECN=(IP_DSCP << 6) + IP_ECN

      IP_TLEN=0                                    #Total Length - kernel probably calculate this correctly on his own
                                                   #This 16-bit field defines the entire packet size in bytes, including header and data.
                                                   #The minimum size is 20 bytes (header without data) and the maximum is 65,535 bytes.

      IP_ID=54321                                  #This field is an identification field and is primarily used for uniquely identifying the group of fragments of a single IP datagram. 

      IP_FLAG=0                                    #A three-bit field follows and is used to control or identify fragments

      IP_FOFF=0                                    #Fragment offset
                                                   #This field specifies the offset of a particular fragment relative to the beginning of the original unfragmented IP datagram in units of eight-byte blocks. 
                                                   #The first fragment has an offset of zero. The 13 bit field allows a maximum offset of (2^13 – 1) × 8 = 65,528 bytes, which, 
                                                   #with the header length included (65,528 + 20 = 65,548 bytes), supports fragmentation of packets exceeding the maximum IP length of 65,535 bytes.
      IP_FLAG_FOFF=(IP_FLAG << 3) + IP_FOFF

      IP_TTL=255                                   #Time to live

      IP_PROT=self.ip_prot                         #IANA maintains a list of IP protocol numbers as directed by RFC 790.
                                                   #https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers

      IP_HCS=0                                     #Header checksum - kernel probably calculate this correctly on his own
                                                   #The 16-bit IPv4 header checksum field is used for error-checking of the header.

      IP_SRC=socket.inet_aton(self.ip_src)         #Source address

      IP_DST=socket.inet_aton(self.ip_dst)         #Destination address

      IP_OPT=0                                     #Options

      IP_PAD=0                                     #Padding

      #https://docs.python.org/3/library/struct.html
      IP_HEADER=struct.pack('!BBHHHBBH4s4s' , IP_VER_IHL, IP_DSCP_ECN, IP_TLEN, IP_ID, IP_FLAG_FOFF, IP_TTL, IP_PROT, IP_HCS, IP_SRC, IP_DST)

      return IP_HEADER
