TP1 de Teoría de las Comunicaciones
===================================

TP1 de Teoría de las Comunicaciones - Departamento de Computación - UBA.

Para bajar las dependencias del proyecto (scapy, plac, etc.):

make


Ayuda por consola:

usage: wiretapping.py [-h] [-f FILEIN] [-a] [fileout]

Ethernet packet sniffing

positional arguments:
  fileout               [output.pcap]

optional arguments:
  -h, --help            show this help message and exit
  -f FILEIN, --filein FILEIN
                        read from file
  -a, --arp             sniffs arp packets

Ejemplos:

Para escuchar paquetes ethernet y grabarlos en el archivo salida.pcap

sudo python wiretapping.py salida.pcap 

Para escuchar paquetes ARP y grabarlos en el archivo salida.pcap

sudo python wiretapping.py -a salida.pcap

Para leer de un archivo paquetes ethernet y mostrar datos de teoría de la información:

sudo python wiretapping.py --f salida.pcap salida.pcap

Para leer de un archivo paquetes ARP y mostrar datos de teoría de la información:

sudo python wiretapping.py --f salida.pcap -a salida.pcap





