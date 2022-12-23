from datetime import datetime

from scapy.all import IP

from src.util import ip_table

class IPManager:
    def is_empty(self, address):
        return ip_table.get(address) == None

    def init_ip(self, address):
        f = '%m/%d/%y %H:%M:%S'
        ip_table[address] = {}
        ip_table[address]['time'] = None
        ip_table[address]['tcp'] = 0 
        ip_table[address]['udp'] = 0 
        ip_table[address]['icmp'] = 0
        ip_table[address]['format'] = f

    @classmethod
    def update_ip(cls, pkt, pkt_type):
        '''
        interact with ip_table from util file
        address: {time, tcp, udp, icmp, format}
        '''
        address = pkt[IP].src
        if cls.is_empty(cls, address):
            cls.init_ip(cls, address)
        time = datetime.fromtimestamp(pkt[IP].time)
        ip_table[address]['time'] = time.strftime(ip_table[address]['format'])
        ip_table[address][pkt_type] += 1
