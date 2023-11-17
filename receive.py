import socket
import struct
import binascii
import os
import time
import scapy.all as spy
from threading import *



lock = Lock()

monitoring_ICMP = False
monitoring_ARP = False
attack_detected = False
icmp_count = 0
arp_count = 0

network_interface = 'br0'


class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDRLINE = '\033[4m'

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

def handle_packet(raw_data):
    global icmp_count, arp_count
    packet = spy.Ether(raw_data)
    packet_type, src_mac, dst_mac, src_ip, dst_ip = get_packet_info(packet)
    if not monitoring_ICMP and packet_type == 'ICMP':
        thread = Thread(target=monitor_ICMP)
        thread.daemon = True
        thread.start()
    elif not monitoring_ARP and (packet_type == 'ARP Request' or packet_type == 'ARP Reply'):
        thread = Thread(target=monitor_ARP)
        thread.daemon = True
        thread.start()
    if packet_type == 'ICMP':
        lock.acquire()
        icmp_count += 1
        lock.release()
    elif packet_type == 'ARP Request' or packet_type == 'ARP Reply':
        lock.acquire()
        arp_count += 1
        lock.release()
    

def monitor_ICMP():
    global monitoring_ICMP, icmp_count, attack_detected
    monitoring_ICMP = True
    print (f'{colors.OKGREEN} Monitoring ICMP {colors.ENDC}')
    time.sleep(10)
    print (f'{colors.OKGREEN} ICMP count (Echo Request/Reply) in 10 seconds: {icmp_count}')
    if icmp_count > 100:
        print (f'{colors.WARNING} ICMP flood detected {colors.ENDC}')
        lock.acquire()
        attack_detected = True
        lock.release()
    else:
        print (f'{colors.OKGREEN} ICMP flood not detected{colors.ENDC}')
    monitoring_ICMP = False
    lock.acquire()
    icmp_count = 0
    lock.release()

def monitor_ARP():
    global monitoring_ARP, arp_count, attack_detected
    monitoring_ARP = True
    print (f'{colors.OKGREEN} Monitoring ARP {colors.ENDC}')
    time.sleep(10)
    print (f'ARP Request/Reply count in 10 seconds: {arp_count}')
    if arp_count > 30:
        print (f'{colors.WARNING} ARP flood detected {colors.ENDC}')
        lock.acquire()
        attack_detected = True
        lock.release()
    else:
        print (f'{colors.OKGREEN} ARP flood not detected {colors.ENDC}')
    monitoring_ARP = False
    lock.acquire()
    arp_count = 0
    lock.release()


def main():
    global attack_detected
   # print(os.system("ifconfig"))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print(f'Listening on {network_interface}')
    s.bind((network_interface, 0))
    
    while True:
        if attack_detected:
            print (f'{colors.FAIL} Attack detected, waiting 10 seconds {colors.ENDC}')
            time.sleep(10)
            attack_detected = False
        print (f'{colors.OKBLUE} Waiting for packet {colors.ENDC}')
        raw_data, addr = s.recvfrom(65536)
        #print (raw_data)
        #use scapy to parse the packet
        thread = Thread(target=handle_packet, args=(raw_data,))
        thread.daemon = True
        thread.start()
    

        
        
     
if __name__ == "__main__":
    main()
