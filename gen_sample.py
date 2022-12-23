from random import choice

from scapy.all import sniff, wrpcap
from scapy.all import Ether, IP, TCP, UDP, ICMP

num = input('how many packets: ')

l2 = Ether()
ip1 = IP(src='255.255.255.0')
ip2 = IP(src='220.220.213.3')
tcp = TCP(flags='S')
udp = UDP()
icmp = ICMP()

p1 = l2/ip1/tcp
p2 = l2/ip2/tcp
p3 = l2/ip1/udp
p4 = l2/ip2/udp
p5 = l2/ip1/icmp
p6 = l2/ip2/icmp

packets = [p1,p2,p3,p4,p5,p6]

for i in range(int(num)):
    packet = choice(packets)
    wrpcap('sample.pcap', packet, append=True)
