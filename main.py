from src.classifier import Classifier
#from src.detector import Detector
from src.sniffer import Sniffer

def main(packet):
    # classify
    Classifier().classify(packet)
    # detect

if __name__ == '__main__':
	f = 'sample.pcap'
	sniffer = Sniffer(offline=f, function=main)
	sniffer.sniff()
