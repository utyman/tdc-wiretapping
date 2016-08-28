import inf_utils
from clint.textui import colored, puts

# returns whether a packet is of broadcast type
def isBroadcast(pkt):
    return pkt.fields['dst'] == 'ff:ff:ff:ff:ff:ff'
    
def getPktDescription(code): 
    names = {
        0x0800: "Internet Protocol version 4 (IPv4)",
        0x0806: "Address Resolution Protocol (ARP)",
        0x0842: "Wake-on-LAN[7]",
        0x22F3: "IETF TRILL Protocol",
        0x6003: "DECnet Phase IV",
        0x8035: "Reverse Address Resolution Protocol",
        0x809B: "AppleTalk (Ethertalk)",
        0x80F3: "AppleTalk Address Resolution Protocol (AARP)",
        0x8100: "VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq",
        0x8137: "IPX",
        0x8204: "QNX Qnet",
        0x86DD: "Internet Protocol Version 6 (IPv6)",
        0x8808: "Ethernet flow control",
        0x8819: "CobraNet",
        0x8847: "MPLS unicast",
        0x8848: "MPLS multicast",
        0x8863: "PPPoE Discovery Stage",
        0x8864: "PPPoE Session Stage",
        0x8870: "Jumbo Frames (proposed)",
        0x887B: "HomePlug 1.0 MME",
        0x888E: "EAP over LAN (IEEE 802.1X)",
        0x8892: "PROFINET Protocol",
        0x889A: "HyperSCSI (SCSI over Ethernet)",
        0x88A2: "ATA over Ethernet",
        0x88A4: "EtherCAT Protocol",
        0x88A8: "Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq",
        0x88AB: "Ethernet Powerlink",
        0x88CC: "Link Layer Discovery Protocol (LLDP)",
        0x88CD: "SERCOS III",
        0x88E1: "HomePlug AV MME",
        0x88E3: "Media Redundancy Protocol (IEC62439-2)",
        0x88E5: "MAC security (IEEE 802.1AE)",
        0x88E7: "Provider Backbone Bridges (PBB) (IEEE 802.1ah)",
        0x88F7: "Precision Time Protocol (PTP) over Ethernet (IEEE 1588)",
        0x8902: "IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)",
        0x8906: "Fibre Channel over Ethernet (FCoE)",
        0x8914: "FCoE Initialization Protocol",
        0x8915: "RDMA over Converged Ethernet (RoCE)",
        0x891D: "TTEthernet Protocol Control Frame (TTE)",
        0x892F: "High-availability Seamless Redundancy (HSR)",
        0x9000: "Ethernet Configuration Testing Protocol[10]"
        
    }
    
    return names.get(code, "packet code not found")

def showPktInfo(pkt):
    puts(colored.green('Ethernet packet sniffed'))
    puts(colored.white('type: ' + getPktDescription(pkt.type)))
    puts(colored.white('dst: ' + pkt.fields['dst']))
    puts(colored.white('src: ' + pkt.fields['src']))


