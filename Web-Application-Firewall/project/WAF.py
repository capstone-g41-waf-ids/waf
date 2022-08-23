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
        print('IP address: {}, Destination: {}, Source: {}, Protocol: {}'.format(address,dest_mac,src_mac,protocol))

def unpack_frame(data):
    dest_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(protocol), data[14:]

def get_mac_address(btyes_stream):
    mac_address = map('{:02x}'.format, btyes_stream)
    return ':'.join(mac_address).upper()
try:
    print('Program started')
    if __name__ == "__main__":  
        Sniffer_thread1 = Thread(target=sniff_packets)#Create Thread
        Sniffer_thread1.start()#Start Thread

except KeyboardInterrupt:
    print('GOOOD BYE - KeyboardInterrupt')