# This class should be considered as context of strategy pattern
# Based on two factor: 1. Times of connections 2. In a period of time
from datetime import datetime

from scapy.all import IP, TCP
from src.util import ip_table
from src.ip_manager import IPManager
from src.logger import Log

class Detector:
    def __init__(self, strategy):
        this._strategy = strategy

    def execute(self, packet):
        this._strategy.excute(packet)

class Flood:
    def __init__(self, packet):
        self.packet = packet
        self.address = packet[IP].src
#        self.pkt_type = pkt_type
        self.timelimit = 300
        self.conn_limit = 2
#        self.update(self.packet, self.pkt_type)
#
#    def update_iptable(self):
#        IPManager.update(self.packet, self.pkt_type)
#        self.pkt_time = datetime.strptime(ip_table[address]['time']

    def in_time(self, address):
        time = datetime.strptime(ip_table[address]['time'], 
                                 ip_table[address]['format'])
        return (datetime.now() - time).seconds < self.timelimit

    def over_conn_limit(self, address, pkt_type):
        if ip_table[address][pkt_type] >= self.conn_limit:
            return True
        ip_table[address][pkt_type] += 1

    def execute(self):
        pass

class TCPFlood(Flood):
    def __init__(self, packet):
        self.flag = 'S'
        super().__init__(packet)

    def execute(self):
        IPManager.update_ip(self.packet, 'tcp')
        if self.in_time(self.address) and \
                self.over_conn_limit(self.address, 'tcp') and \
                self.packet[TCP].flags == self.flag:
            print(f'[ WARNING ]: tcp syn flood detected: {self.packet[IP].src}')
            log = Log(level = 'medium',
                      content = 'tcp syn flood',
                      time = self.packet[IP].time,
                      ip = self.packet[IP].src)
            log.wrlog('log.txt')

class UDPFlood(Flood):
    def __init__(self, packet):
        super().__init__(packet)

    def execute(self):
        IPManager.update_ip(self.packet, 'udp')
        if self.in_time(self.address) and \
                self.over_conn_limit(self.address, 'udp'):
            print(f'[ WARNING ]: udp flood detected: {self.packet[IP].src}')

class ICMPFlood(Flood):
    def __init__(self, packet):
        super().__init__(packet)

    def execute(self):
        IPManager.update_ip(self.packet, 'icmp')
        if self.in_time(self.address) and \
                self.over_conn_limit(self.address, 'icmp'):
            print(f'[ WARNING ]: icmp flood detected: {self.packet[IP].src}')
