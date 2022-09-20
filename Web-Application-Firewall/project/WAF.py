
from tabnanny import check
import textwrap
import socket
import struct
from threading import Thread

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


HOST = socket.gethostbyname(socket.gethostname())#gets machines IP address

def sniff_packets():
    print(f"My IP address is: {HOST}")
    Server = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))#set for packets in raw data format, accepts little endian and big endian
    
    while True:
        raw_data, address = Server.recvfrom(65535)#Biggest buffer size available is 65535 
        dest_mac, src_mac, eth_protocol, data = unpack_frame(raw_data)
        print('--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------')
        print('\nPacket Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac,src_mac,eth_protocol))
        
        if eth_protocol == 8:
            version, header_length, time_to_live, IPv4_protocol, src, target, IPv4_data = unpack_IPv4(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'version: {}, header_length: {}, time_to_live: {}'.format(version,header_length,time_to_live))
            print(TAB_2 + 'protocol: {}, Source: {}, target: {}'.format(IPv4_protocol,src,target))
            
            #ICMP
            if IPv4_protocol == 1:
                ICMP_type, code, check_sum, ICMP_data = unpack_ICMP(data)
                print(TAB_1 + 'ICMP Segment:')
                print(TAB_2 + 'Type: {}, Code: {}, Check sum: {}'.format(ICMP_type,code,check_sum))
                print(TAB_2 + 'Data: ')
                print(format_multi_line_data(DATA_TAB_4,ICMP_data))
                
            #TCP
            elif IPv4_protocol == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ark, flag_psh, flag_rst, flag_syn, flag_fin, TCP_data) = unpack_tcp(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port,dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowlegement: {}'.format(sequence,acknowledgement))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK:, PSH: {}, RST: {}, SYN: {}, FIN: {},'.format(flag_urg,flag_ark,flag_psh,flag_rst,flag_syn,flag_fin))
                print(TAB_1 + 'Data: ')
                print(format_multi_line_data(DATA_TAB_4, TCP_data))
               
            #UDP
            elif IPv4_protocol == 17:
                src_port, dest_port, length, UDP_data = unpack_UDP(data)
                print(TAB_1 + 'UDP Segment: ')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {} '.format(src_port,dest_port,length))
                print(TAB_1 + 'Data: ')
                print(format_multi_line_data(DATA_TAB_4, UDP_data))

        else:
            print(TAB_1 + 'Data: ')
            print(format_multi_line_data(DATA_TAB_2, data))



def unpack_frame(data):
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(protocol), data[14:]

def get_mac_address(btyes_stream):
    mac_address = map('{:02x}'.format, btyes_stream)
    return ':'.join(mac_address).upper()

def IP_format(unformatted_address):
    return '.'.join(map(str, unformatted_address))

#upacks IPv4 packet
def unpack_IPv4(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    time_to_live, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, time_to_live, protocol, IP_format(src), IP_format(target), data[header_length:]

def unpack_ICMP(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def unpack_UDP(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def unpack_tcp(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('!H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ark = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ark, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

    #This just makes data easier to read.
def format_multi_line_data(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

try:
    print('Program started')
    if __name__ == "__main__":  
        Sniffer_thread = Thread(target=sniff_packets)#Create Thread
        Sniffer_thread.start()#Start Thread

=======
from scapy.all import *
from scapy.layers.http import HTTPRequest  # import HTTP packet
from threading import Thread
import argparse
import socket

# import time

host = socket.gethostbyname(socket.gethostname())
methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE']  # Define http methods

def


def sniff_packets(iface=None):
    print('Running Sniffer')
    if iface:
        # port 80 for http (generally)
        # `process_packet` is the callback
        print(f"iface on")
        sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
        #sniff(filter="port 443", prn=process_packet, iface=iface, store=False)
        
    else:
        # sniff with default interface
        print(f"iface off")
        sniff(filter="port 80", prn=process_packet, store=False)
        #sniff(filter="port 443", prn=process_packet, store=False)


def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet['IP'].src
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        print(f"\n {ip} Requested {url} with {method}")
        if show_raw and packet.haslayer(Raw) and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print(f"\n[*] Some useful Raw data: {packet[Raw].load}")


try:
    print('Program started')
    print('My IP: ' + host)
    if __name__ == "__main__":
        parser = argparse.ArgumentParser(
            description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                        + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
        parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
        parser.add_argument("--show-raw", dest="show_raw", action="store_true",
                            help="Whether to print POST raw data, such as passwords, search queries, etc.")
        # parse arguments
        args = parser.parse_args()
        iface = args.iface
        show_raw = args.show_raw

        Sniffer_thread1 = Thread(target=sniff_packets, args=[iface])
        Sniffer_thread1.start()

    # KeyboardInterrupt Exit program

except KeyboardInterrupt:
    print('GOOOD BYE - KeyboardInterrupt')
