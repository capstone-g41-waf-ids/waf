import scapy.all as scapy
from threading import Thread
#import time

def Sniffer(interface):
    scapy.sniff(iface=interface,store=False, prn=process_packet)

def process_packet(packet):
    print(packet.show()) 

try:
    print('Program started')
    Sniffer_thread1 = Thread(target=Sniffer, args=[None])
    Sniffer_thread1.start()



    #KeyboardInterrupt Exit program
except KeyboardInterrupt:
    print('GOOOD BYE - KeyboardInterrupt')