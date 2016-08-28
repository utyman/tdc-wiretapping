# wiretapping.py

def main(arp: ("sniffs arp packets", 'flag', 'a'), filename='output.pcap'):
    "Ethernet packet sniffing"
    print(filename)
    # ...

if __name__ == '__main__':
    import plac; plac.call(main)
