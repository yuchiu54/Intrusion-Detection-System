from scapy.all import sniff

class Sniffer:
    def __init__(self, offline=None, function=None):
        self.offline = offline 
        self.function = function
        self.result = None

    def set_offline(self, offline):
        self.offline = offline

    def set_function(self, function):
        self.function = function

    def sniff(self):
        self.result = sniff(offline=self.offline, prn=self.function)

if __name__ == '__main__':
    s = Sniffer()
    s.set_offline('test.pcap')
    s.set_function(None)
    s.sniff()
