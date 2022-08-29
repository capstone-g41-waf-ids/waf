from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
from threading import Thread
import argparse
import socket
#import time

host = socket.gethostbyname(socket.gethostname())
methods=['GET','POST','HEAD','PUT','DELETE','CONNECT','OPTIONS','TRACE']#Define http methods

def sniff_packets(iface=None):
    print('Running Sniffer')
    if iface:
        # port 80 for http (generally)
        # `process_packet` is the callback
        sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
    else:
        # sniff with default interface
        sniff(filter="port 80", prn=process_packet, store=False)

    

def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        print(f"\n {ip} Requested {url} with {method}")
        if show_raw and packet.haslayer(Raw) and method == "GET":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print(f"\n[*] Some useful Raw data: {packet[Raw].load}")

try:
    print('Program started')
    print('My IP: ' + host)
    if __name__ == "__main__":
        parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                                                    + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
        parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
        parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")
        # parse arguments
        args = parser.parse_args()
        iface = args.iface
        show_raw = args.show_raw

        
        Sniffer_thread1 = Thread(target=sniff_packets, args=[iface])
        Sniffer_thread1.start()



    #KeyboardInterrupt Exit program
except KeyboardInterrupt:
    print('GOOOD BYE - KeyboardInterrupt')