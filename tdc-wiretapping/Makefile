# ETHFILE es el .pcap que contiene los paq ethernet, con esa linea se devuelven todos los graficos juntos. Idem para ARPFILE pero con ARP.

#Ejemplos de uso: Bajo ETHFILE = ethSniff | ARPFILE = arpSniff
# make ETHFILE="ethSniff" ARPFILE="arpSniff" all
# make ETHFILE="ethSniff" eth
# make ARPFILE="arpSniiff" arp


all:
	sudo python wiretapping.py --f ${ETHFILE}.pcap ${ETHFILE}.pcap
	sudo python wiretapping.py --f ${ARPFILE}.pcap -a ${ARPFILE}.pcap
eth:
	sudo python wiretapping.py --f ${ETHFILE}.pcap ${ETHFILE}.pcap
arp:
	sudo python wiretapping.py --f ${ARPFILE}.pcap -a ${ARPFILE}.pcap	

