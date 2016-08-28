# wiretapping.py

def main(type: ("packet type", 'option', 't'),
         filename='output.pcap'):
    "Ethernet packet sniffing"
    print(filename)
    # ...

if __name__ == '__main__':
    import plac; plac.call(main)