from scapy.all import IP, TCP, UDP, ICMP, NoPayload, wrpcap

from src.util import layer_table
from src.detector import TCPFlood, UDPFlood, ICMPFlood

class Classifier:
    def is_unordered(self, packet):
        prev_layer = 0
        while packet != NoPayload():    
	        if packet.name not in layer_table.keys():    
	            return False    
	        if layer_table[packet.name][1] > 0:    
	            return False                        
	        if layer_table[packet.name][0] < prev_layer:      
	            return False                        
	        prev_layer = layer_table[packet.name][0]
	        layer_table[packet.name][1] += 1
	        packet = packet.payload
        return True

    def classify(self, packet):
        if self.is_unordered(packet):
            wrpcap('unknown_packets.pcap', packet, append=True)
            print('[ info ]: unknown packet found')
        if TCP in packet:
            TCPFlood(packet).execute()
        if UDP in packet:
            UDPFlood(packet).execute()
        if ICMP in packet:
            ICMPFlood(packet).execute()

if __name__ == '__main__':
    #c = Classifier()
    from scapy.all import sniff
    sniff(offline='test.pcap', prn=Classifier().classify)
