from tcp import TCP
from ipv4 import IPv4
import socket 
import struct #pack function


tcp = TCP(ip_dst='192.168.1.254')


print((tcp.IPframe()+tcp.TCPframe()))
print(len(tcp.IPframe()+tcp.TCPframe()))

