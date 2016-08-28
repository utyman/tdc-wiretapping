# wiretapping.py
import logging
import pkt_utils
import inf_utils
import plac
from clint.textui import colored, puts
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import *

ARP_CODE = 0x0806
lfilter = lambda (p): p.haslayer(Ether) 

# creates parent function with passed in arguments
def action(options):
  def savePacket(pkt):
    try:
        file = PcapWriter(options["filename"], append=True, sync=True)
        file.write(pkt)
        pkt_utils.showPktInfo(pkt)
    except Exception,e: 
        puts(colored.red('Error dumping packet'))
        sys.exit(-1)
  return savePacket

# sniffs ARP packets
def sniffARP(filename):
    options = {"filename": filename}
    sniff(prn=action(options), filter="arp", store=0)


# sniffs ethernet packets
def sniffEth(filename, filter):
    options = {"filename": filename}
    sniff(prn=action(options), lfilter=filter, store=0)
   
# sniffs ARP packets from file 
def sniffEthFromFile(filein, arp):
    try:
        pkts = PcapReader(filein)
        for pkt in pkts:
            if arp and pkt.type != ARP_CODE:
                continue
            else:
                pkt_utils.showPktInfo(pkt)
    except Exception,e: 
        puts(colored.red('Error reading file: ' + filein))
        sys.exit(-1)
        
# shows entropy information
def showEntropyARP(filein):
    symbolOccurrences= [] 
    try:
        pkts = PcapReader(filein)
        for pkt in pkts:
            if pkt.type != ARP_CODE:
                continue
            symbolOccurrences.append(pkt.fields['src'])
        
        symbolsInfo = dict(collections.Counter(symbolOccurrences))
        pktsTotal = len(symbolOccurrences)     
        
        inf_utils.entropy(symbolsInfo, float(pktsTotal))
    except Exception,e: 
        puts(colored.red('Error processing file: ' + filein))
        sys.exit(-1)
    
# shows entropy information
def showEntropyEth(filein):
    symbolOccurrences= [] 
    try:
        pkts = PcapReader(filein)
        for pkt in pkts:
            if pkt_utils.isBroadcast(pkt):
                symbolOccurrences.append("BROADCAST")
            else:
                symbolOccurrences.append("UNICAST")
        
        symbolsInfo = dict(collections.Counter(symbolOccurrences))
        pktsTotal = len(symbolOccurrences)     
        
        inf_utils.entropy(symbolsInfo, float(pktsTotal))
    except Exception,e: 
        puts(colored.red('Error processing file: ' + filein))
        sys.exit(-1)
    
@plac.annotations(
 arp=("sniffs arp packets", 'flag', 'a'),
 filein=("read from file", 'option', 'f')
)
def main(filein, arp, fileout='output.pcap'):
    "Ethernet packet sniffing"
    
    if not filein:
        if arp:
            sniffARP(fileout)
        else:
            sniffEth(fileout, lfilter)
    else:
        if arp:
            sniffEthFromFile(filein, True)
            showEntropyARP(filein)
        else:
            sniffEthFromFile(filein, False)
            showEntropyEth(filein)


        
if __name__ == '__main__':
    import plac; plac.call(main)
