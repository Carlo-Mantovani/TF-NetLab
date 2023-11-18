import socket
import struct
import binascii
import os
import time
import scapy.all as spy
from threading import *


NET_INTERFACE = 'br0'

count_lock = Lock()

attack_detected = False


#counter positions:
#0 = ARP Request Count
#1 = ARP Reply Count
#2 = ICMP count
#3 = ICMPV6 count
#4 = IPV4 count
#5 = IPV6 count
#6 = TCP count
#7 = UDP count

packet_counters = [0,0,0,0,0,0,0,0]
print_packets = False
print_counter = True



class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ORANGE = '\033[38;5;208m'  # Orange
    YELLOW = '\033[93m'  # Yellow
    PINK = '\033[95m'  # Pink
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDRLINE = '\033[4m'

def get_packet_MAC_addresses(packet):
    src_mac = packet.src
    dst_mac = packet.dst

    return src_mac, dst_mac   

def get_packet_IP_addresses(packet):
    src_ip = packet[spy.IP].src
    dst_ip = packet[spy.IP].dst

    return src_ip, dst_ip

def get_packet_info(packet):

    src_mac, dst_mac = get_packet_MAC_addresses(packet)
    if packet.haslayer(spy.IP):
        src_ip, dst_ip = get_packet_IP_addresses(packet)
    else:
        src_ip = ''
        dst_ip = ''
    if print_packets:
        print_packet_info(packet,src_mac, dst_mac, src_ip, dst_ip)
    return src_mac, dst_mac, src_ip, dst_ip

def print_packet_info(packet, src_mac, dst_mac, src_ip, dst_ip):

    print (f'{packet.summary()}')
    print (f'Source MAC: {src_mac}, Destination MAC: {dst_mac}')
    if src_ip != '' and dst_ip != '':
        print (f'Source IP: {src_ip}, Destination IP: {dst_ip}')

def print_packet_counters():
    print('')
    print (f'{colors.OKBLUE}-'*50)
    print (f'\n{colors.FAIL}Packet Counters\n {colors.ENDC}')
    print (f'{colors.ORANGE} Data Link Layer {colors.OKBLUE}')
    print (f'   ARP Request Count: {packet_counters[0]}')
    print (f'   ARP Reply Count: {packet_counters[1]}')
    print (f'{colors.ORANGE} Network Layer {colors.OKBLUE}')
    print (f'   ICMP Count: {packet_counters[2]}')
    print (f'   ICMPv6 Count: {packet_counters[3]}')
    print (f'   IPV4 Count: {packet_counters[4]}')
    print (f'   IPV6 Count: {packet_counters[5]}')
    print (f'{colors.ORANGE} Transport Layer {colors.OKBLUE}')
    print (f'   TCP Count: {packet_counters[6]}')
    print (f'   UDP Count: {packet_counters[7]}')
    print (f'-'*50 )
    print (f'\n{colors.ENDC}')

def handle_packet(raw_data):
    global icmp_count
    packet = spy.Ether(raw_data)
    src_mac, dst_mac, src_ip, dst_ip = get_packet_info(packet)
    count_packets(packet)
  

def count_packets(packet):
    global packet_counters
    if packet.haslayer(spy.ARP):
        if packet[spy.ARP].op == 1:
            count_lock.acquire()
            packet_counters[0] += 1
            count_lock.release()
        elif packet[spy.ARP].op == 2:
            count_lock.acquire()
            packet_counters[1] += 1
            count_lock.release()
    if packet.haslayer(spy.ICMP):
        count_lock.acquire()
        if packet[spy.ICMP].type == 8:
            packet_counters[2] += 1
        elif packet[spy.ICMP].type == 129:
            packet_counters[3] += 1
        count_lock.release()
    if packet.haslayer(spy.IP):
        count_lock.acquire()
        if packet[spy.IP].version == 4:
            packet_counters[4] += 1
        elif packet[spy.IP].version == 6:
            packet_counters[5] += 1
        count_lock.release()
    if packet.haslayer(spy.TCP):
        count_lock.acquire()
        packet_counters[6] += 1
        count_lock.release()
    if packet.haslayer(spy.UDP):
        count_lock.acquire()
        packet_counters[7] += 1
        count_lock.release()

def monitor_ARP():
    global attack_detected
    time.sleep(3)
    while True:
        if not attack_detected:
            print('')
            print (f'{colors.YELLOW}-'*50)
            print (f'{colors.YELLOW} ARP Monitor {colors.ENDC}')
            print (f'{colors.YELLOW}      Monitoring ARP for 15 seconds {colors.ENDC}')
            print (f'{colors.YELLOW}-'*50)
            old_arpRqst_count = packet_counters[0]
            old_arpRply_count = packet_counters[1]
            time.sleep(15)
            arpRqst_diff = packet_counters[0] - old_arpRqst_count
            arpRply_diff = packet_counters[1] - old_arpRply_count
            if arpRqst_diff == 0:
                reply_ratio = 0
            else:
                reply_ratio = arpRply_diff / arpRqst_diff
            print('')
            print (f'{colors.YELLOW}-'*50)
            print(f'{colors.YELLOW} ARP Request/Reply Ratio in 15s: {reply_ratio}{colors.ENDC}')
            if reply_ratio > 3.0:
                print (f'{colors.FAIL}      ARP Spoofing detected {colors.ENDC}')
                count_lock.acquire()
                attack_detected = True
                count_lock.release()
            else:
                print (f'{colors.OKGREEN}      ARP Spoofing not detected {colors.ENDC}')
            print (f'{colors.YELLOW}-'*50 + f'{colors.ENDC}' )


    

def monitor_ICMP():
    global attack_detected
    time.sleep(1.5)
    while True:
        if not attack_detected:
            print('')
            print (f'{colors.PINK}-'*50)
            print (f'{colors.ORANGE} ICMP/ICMPv6 monitor{colors.ENDC}')
            print (f'{colors.PINK}      Monitoring ICMP/ICMPv6 for 10 seconds {colors.ENDC}')
            print (f'{colors.PINK}-'*50)
            old_count = packet_counters[2] + packet_counters[3]
            time.sleep(10)
            icmp_diff = (packet_counters[2] + packet_counters[3]) - old_count
            print('')
            print (f'{colors.PINK}-'*50)
            print (f'{colors.PINK} ICMP/ICMPv6 count in 10s: {icmp_diff}.{colors.ENDC}')
            if icmp_diff > 100:
                print (f'{colors.FAIL}      ICMP flood detected {colors.ENDC}')
                count_lock.acquire()
                attack_detected = True
                count_lock.release()
            else:
                print (f'{colors.OKGREEN}      ICMP flood not detected{colors.ENDC}')
            print (f'{colors.PINK}-'*50 + f'{colors.ENDC}' )
            


def show_packet_counters():
    while True:
        if not attack_detected:
            if print_counter:
                print_packet_counters()
            time.sleep(6)

def receive_packets():
    global attack_detected
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    s.bind((NET_INTERFACE, 0))
    while True:
        if attack_detected:
                    print (f'{colors.FAIL} Attack detected, waiting 10 seconds {colors.ENDC}')
                    time.sleep(10)
                    attack_detected = False
       # print (f'{colors.OKBLUE} Waiting for packet {colors.ENDC}')
        raw_data, addr = s.recvfrom(65536)
        #print (raw_data)
        #use scapy to parse the packet
        thread = Thread(target=handle_packet, args=(raw_data,))
        thread.daemon = True
        thread.start()

def main():
    global attack_detected, print_packets, print_counter


    arp_monitor_thread = Thread(target=monitor_ARP)
    arp_monitor_thread.daemon = True
    arp_monitor_thread.start()
    icmp_monitor_thread = Thread(target=monitor_ICMP)
    icmp_monitor_thread.daemon = True
    icmp_monitor_thread.start()
    counter_thread = Thread(target=show_packet_counters)
    counter_thread.daemon = True
    counter_thread.start()
    receive_thread = Thread(target=receive_packets)
    receive_thread.daemon = True
    receive_thread.start()
    
    while True:

        #Enable/Disable Packet Printing

        _input = input(f"{colors.YELLOW}Control Menu \n1. Enable/Disable Packet Counting Printing \n2. Enable/Disable Packet Details Printing\n3. Exit\n {colors.ENDC}")
        try:
            if _input == "1":
                if print_counter:
                    print_counter = False
                    print (f"{colors.FAIL}Packet Counting Printing Disabled{colors.ENDC}")
                else:
                    print_counter = True
                    print (f"{colors.OKGREEN}Packet Counting Printing Enabled{colors.ENDC}")
            elif _input == "2":
                if print_packets:
                    print_packets = False
                    print (f"{colors.FAIL}Packet Details Printing Disabled{colors.ENDC}")
                else:
                    print_packets = True
                    print (f"{colors.OKGREEN}Packet Details Printing Enabled{colors.ENDC}")
            elif _input == "3":
                exit()
            else:
                print (f"{colors.FAIL}Invalid input{colors.ENDC}")
        except Exception as e:
            print (f"{colors.FAIL}Invalid input{colors.ENDC}")
            
        

        
        
     
if __name__ == "__main__":
    main()
