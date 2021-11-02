from tcp import TCP
from ipv4 import IPv4
import socket
import struct #pack function

#test
tcp = TCP(ip_dst='192.168.1.254')


#Need to run as admin
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

s.sendto(tcp.TCPframe(), ('192.168.1.7',53241))

