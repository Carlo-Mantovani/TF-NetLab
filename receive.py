import socket
import struct
import binascii
import os
import scapy.all as spy



network_interface = 'br0'

def get_packet_type(packet):
    if packet.haslayer(spy.ARP):
        if packet[spy.ARP].op == 1:
            return 'ARP Request'
        elif packet[spy.ARP].op == 2:
            return 'ARP Reply'
    elif packet.haslayer(spy.UDP):
        return 'UDP'
    elif packet.haslayer(spy.TCP):
        return 'TCP'
    elif packet.haslayer(spy.ICMP):
        return 'ICMP'
    else:
        return 'UNKNOWN'

def get_packet_MAC_addresses(packet):
    src_mac = packet.src
    dst_mac = packet.dst

    return src_mac, dst_mac   

def get_packet_IP_addresses(packet):
    src_ip = packet[spy.IP].src
    dst_ip = packet[spy.IP].dst

    return src_ip, dst_ip

def print_packet_info(packet, packet_type, src_mac, dst_mac, src_ip, dst_ip):
    if packet_type == 'ARP Request' or packet_type == 'ARP Reply':
        print (f'\nPacket Type: {packet_type}')
        #print arp message
        print(f'{packet.getlayer(spy.ARP)}')
  
    elif packet_type == 'ICMP':
        print (f'\nPacket Type: {packet_type}')
        #print icmp message
        print(f'{packet.getlayer(spy.ICMP)}')
    else:
        print (f'\nPacket Type: {packet_type}')
        print (f'{packet.summary()}')
    print (f'Source MAC: {src_mac}, Destination MAC: {dst_mac}')
    if src_ip != '' and dst_ip != '':
        print (f'Source IP: {src_ip}, Destination IP: {dst_ip}')

def get_packet_info(packet):
    packet_type = get_packet_type(packet)
    src_mac, dst_mac = get_packet_MAC_addresses(packet)
    if packet.haslayer(spy.IP):
        src_ip, dst_ip = get_packet_IP_addresses(packet)
    else:
        src_ip = ''
        dst_ip = ''
    print_packet_info(packet, packet_type, src_mac, dst_mac, src_ip, dst_ip)
    return packet_type, src_mac, dst_mac, src_ip, dst_ip

#def get_packet_layers(packet):
#    counter = 0
#    while True:
#        layer = packet.getlayer(counter)
#        if layer is None:
#            break
#
#        yield layer
#        counter += 1






def main():
   # print(os.system("ifconfig"))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print(f'Listening on {network_interface}')
    s.bind((network_interface, 0))
    
    while True:
        print ('Waiting for packet')
        raw_data, addr = s.recvfrom(65536)
        #print (raw_data)
        #use scapy to parse the packet
        packet = spy.Ether(raw_data)
        packet_type, src_mac, dst_mac, src_ip, dst_ip = get_packet_info(packet)
        
        
        
     
if __name__ == "__main__":
    main()
