import socket
import struct
from threading import Thread


HOST = socket.gethostbyname(socket.gethostname())#gets machines IP address

def sniff_packets():
    print(f"My IP address is: {HOST}")
    Server = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))#set for packets in raw data format, accepts little endian and big endian
    
    while True:
        raw_data, address = Server.recvfrom(65535)#Biggest buffer size available is 65535 
        dest_mac, src_mac, protocol, data = unpack_frame(raw_data)
        print('\nPacket Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac,src_mac,protocol))
        version, header_length, time_to_live, protocol_2, src, target, IPv4_data = unpack_IPv4(data)
        print('IP address: {}'.format(src))



def unpack_frame(data):
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(protocol), data[14:]

def get_mac_address(btyes_stream):
    mac_address = map('{:02x}'.format, btyes_stream)
    return ':'.join(mac_address).upper()

def IP_translate(unformatted_address):
    return '.'.join(map(str, unformatted_address))

#upacks IPv4 packet
def unpack_IPv4(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    time_to_live, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, time_to_live, protocol, IP_translate(src), IP_translate(target), data[header_length:]

def unpack_ICMP(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[:4]

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

try:
    print('Program started')
    if __name__ == "__main__":  
        Sniffer_thread = Thread(target=sniff_packets)#Create Thread
        Sniffer_thread.start()#Start Thread

except KeyboardInterrupt:
    print('GOOOD BYE - KeyboardInterrupt')