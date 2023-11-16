import socket
import struct
import binascii
import os
import scapy.layers.all as spy



network_interface = 'eth0'

def parse_ethernet_header(data):
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(eth_proto), data[14:]

def get_mac_address(bytes_address):
    bytes_str = map('{:02x}'.format, bytes_address)
    return ':'.join(bytes_str).upper()

def parse_ip_header(data):
    version_ihl, dscp_ecn, total_length, identification, flags_fragOffset, ttl_protocol, header_checksum, src_ip, dest_ip = struct.unpack('! B B H H H B B H 4s 4s', data[:20])
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4
    return version, ihl, dscp_ecn, total_length, identification, flags_fragOffset, ttl_protocol, header_checksum, socket.inet_ntoa(src_ip), socket.inet_ntoa(dest_ip), data[ihl:]

def parse_tcp_header(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x1FF
    return src_port, dest_port, sequence, acknowledgment, offset, flags, data[offset:]

def parse_udp_header(data):
    src_port, dest_port, length = struct.unpack('! H H H', data[:6])
    return src_port, dest_port, length, data[8:]

def main():
   # print(os.system("ifconfig"))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    print(f'Listening on {network_interface}')
    s.bind((network_interface, 0))
    
    while True:
        raw_data, addr = s.recvfrom(65536)
        #print (raw_data)
        #use scapy to parse the packet
        packet = spy.Ether(raw_data)
        print(packet.show())
       # dest_mac, src_mac, eth_proto, data = parse_ethernet_header(raw_data)
        #print(f'\nEthernet Header:\nDestination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {eth_proto}')
       # print(f' \nData: {data}')

      #  if eth_proto == 8:  # IPv4
           # version, ihl, dscp_ecn, total_length, identification, flags_fragOffset, ttl_protocol, header_checksum, src_ip, dest_ip, data = parse_ip_header(data)

           # if ttl_protocol == 6:  # TCP
               # src_port, dest_port, sequence, acknowledgment, offset, flags, data = parse_tcp_header(data)

                # Aqui você pode adicionar lógica para verificar pacotes TCP e contar a quantidade de pacotes TCP.

           # elif ttl_protocol == 17:  # UDP
                #src_port, dest_port, length, data = parse_udp_header(data)

                # Aqui você pode adicionar lógica para verificar pacotes UDP e contar a quantidade de pacotes UDP.

        # Adicione lógica para outros protocolos, se necessário.
        # print all information
        #print('\nEthernet Header:')
        #print('Destination MAC: {}, Source MAC: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
       # print('\nIP Header:')
        #print('Version: {}, IHL: {}, DSCP/ECN: {}, Total Length: {}, Identification: {}, Flags/Frag Offset: {}, TTL: {}, Protocol: {}, Header Checksum: {}, Source IP: {}, Destination IP: {}'.format(version, ihl, dscp_ecn, total_length, identification, flags_fragOffset, ttl_protocol, header_checksum, src_ip, dest_ip))
       # print('\nTCP Header:')
       #print('Source Port: {}, Destination Port: {}, Sequence: {}, Acknowledgment: {}, Offset: {}, Flags: {}'.format(src_port, dest_port, sequence, acknowledgment, offset, flags))
       # print('\nData:')
       # print(data)
if __name__ == "__main__":
    main()
