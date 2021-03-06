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

def which(program):
    import os
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None

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
def showEntropyARPWhoHAS(filein):
    symbolOccurrences= [] 
    try:
        pkts = PcapReader(filein)
        for pkt in pkts:
            if pkt.type != ARP_CODE:
                continue
            
            if pkt.payload.fields['op'] == 1:
                symbolOccurrences.append("WHO_HAS")

            if pkt.payload.fields['op'] == 2:
                symbolOccurrences.append("IS_AT")
            
            
        symbolsInfo = dict(collections.Counter(symbolOccurrences))
        pktsTotal = len(symbolOccurrences)     
        
        print "H: " + str(inf_utils.entropy(symbolsInfo, float(pktsTotal)))
        print "H_max: " + str(inf_utils.max_entropy(symbolsInfo))
        print "Info Events: " + str(symbolsInfo)
        inf_utils.dump_results(filein, symbolsInfo, inf_utils.entropy(symbolsInfo, float(pktsTotal)), inf_utils.max_entropy(symbolsInfo), float(pktsTotal));

    except Exception,e: 
        puts(colored.red('Error processing file: ' + filein))
        sys.exit(-1)

        
# shows entropy information
def showEntropyARP(filein):
    symbolOccurrences= [] 
    symbolConnections = dict();
    try:
        pkts = PcapReader(filein)
        for pkt in pkts:
            if pkt.type != ARP_CODE:
                continue
            if not pkt.payload.fields['psrc'] in symbolConnections:
                symbolConnections[pkt.payload.fields['psrc']] =[];
            
            if ( not (pkt.payload.fields['pdst']) in symbolConnections.get(pkt.payload.fields['psrc'])):
                symbolConnections.get(pkt.payload.fields['psrc']).append(pkt.payload.fields['pdst'])
            
            symbolOccurrences.append(pkt.payload.fields['pdst'])
        
        symbolsInfo = dict(collections.Counter(symbolOccurrences))
        pktsTotal = len(symbolOccurrences)     
        
        print "H: " + str(inf_utils.entropy(symbolsInfo, float(pktsTotal)))
        print "H_max: " + str(inf_utils.max_entropy(symbolsInfo))
        print "Info Events: " + str(symbolsInfo)
        inf_utils.dump_results(filein, symbolsInfo, inf_utils.entropy(symbolsInfo, float(pktsTotal)), inf_utils.max_entropy(symbolsInfo), float(pktsTotal));
        print inf_utils.dump_graph(filein, symbolConnections);
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
        
        print "H: " + str(inf_utils.entropy(symbolsInfo, float(pktsTotal)))
        print "H_max: " + str(inf_utils.max_entropy(symbolsInfo))
        print "Info Events: " + str(symbolsInfo)
        inf_utils.dump_results(filein, symbolsInfo, inf_utils.entropy(symbolsInfo, float(pktsTotal)), inf_utils.max_entropy(symbolsInfo), float(pktsTotal));
    except Exception,e: 
        puts(colored.red('Error processing file: ' + filein))
        sys.exit(-1)
    
@plac.annotations(
 arp=("sniffs arp packets", 'flag', 'a'),
 typearp=("symbols for arp packets are WHOHAS AND ISAT", 'flag', 't'),
 filein=("read from file", 'option', 'f')
)
def main(filein, arp, typearp, fileout='output.pcap'):
    "Ethernet packet sniffing"
    
    gnuplot = which('gnuplot')
    if gnuplot == None:
        puts(colored.red('Gnuplot must be installed to create graphics'));
    
    if not filein:
        if arp:
            sniffARP(fileout)
        else:
            sniffEth(fileout, lfilter)
    else:
        if arp:
            if not typearp:
                showEntropyARP(filein)
            else:
                showEntropyARPWhoHAS(filein)
        else:
            showEntropyEth(filein)


        
if __name__ == '__main__':
    import plac; plac.call(main)
