import socket      #This library is used to listen for packages
import struct      #This library is used to help with handling binary data
import textwrap    #This library is used to format data packages and put limited data on one line

TAB_1 = '\t - '    #These are to create indentation on our output and make it easier to understand for us
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '                                                            #NOTE: B->1 bit H->2 bits L->4 bits
DATA_TAB_4 = '\t\t\t\t   '

def main():                                                                         #AF_PACKET is for protocol level packet manipulation
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))        #.hton is used to convert bytes in a readable format
    while True:                                                                     #SOCK_RAW allows access to the underlying transport provider.
        raw_data, addr = conn.recvfrom(65536)                                       #we give it biggest buffer size of 65536
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)               #raw data will be disected for dest_mac, src_mac, eth_proto, data
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        #8 for IPv4 -> if our ethernet frame type is 8 that means it's an IPv4 packet, so we unpack accordingly
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            #1 for ICMP -> if our IP Protocol is 1 that means it's an ICMP packet, so we unpack accordingly
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_2 + 'ICMP Packet:')
                print(TAB_3 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum))
                print(TAB_3 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            #6 for TCP -> if our IP Protocol is 6 that means it's a TCP packet, so we unpack accordingly
            elif proto == 6: ############????????????????????????????? ipv4.proto
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print(TAB_2 + 'TCP Segment:')
                print(TAB_3 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_3 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgement))
                print(TAB_3 + 'Flags:')
                print(TAB_4 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_3 + 'Data: ')
                print(format_multi_line(DATA_TAB_4, data))

            #17 for UDP -> if our IP Protocol is 17 that means it's an UDP packet, so we unpack accordingly
            elif proto == 17:
                src_port, dest_port, lenght, data = udp_segment(data)
                print(TAB_2 + 'UDP Segment: ')
                print(TAB_3 + 'Source Port: {}, Destination Port: {}, Lenght: {}'. format(src_port, dest_port, lenght))

            # Other
            else:
                print(TAB_2 + 'Data: ')
                print(format_multi_line(DATA_TAB_3, data))


#Unpack ethernet frame, whenever a packet is detected it's passed in to this function to be unpacked
def ethernet_frame(data):                                            # The reason why we only unpack the first 14 bytes is bc it gives dest, source and type of the Ethernet frame
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14]) #The way packets are stored in computers and the way they travel in networks is different, that's why we convert it from big indien to little indien
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:] #.hton is used to convert bytes in a readable format


#Return formatted readable MAC address (ex: AA:BB:CC:DD:DD:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map ('{:02x}'.format, bytes_addr) #convert each chunk of the mac address to 2 decimal places
    return ':'. join(bytes_str).upper()           #join pieces with a : in between


#Unpack IPv4 packet which was inside of the ethernet packet (IPv4 packet = data or data[:14])
def ipv4_packet(data):
    version_header_lenght = data[0]
    version = version_header_lenght >> 4
    header_length = (version_header_lenght & 15) * 4                                            #we need the header_length to know where the actual useful data starts
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]    #data[header_length:] is the useful daya being transferred such as passwords and usernames
                                                                                                #proto is the protocol which will return a number and tell us if its TCP, UDP and ICMP
                                                                                                #We need to know what kind of protocol it is to get data packages, we need different methods for each protocol
#Returns formatted readable IPv4 address like 172.54.4
def ipv4(addr):
    return '.'.join(map(str, addr))


##################Now we unpack the package according to it's Protocol (Ethernet Frame type) type like ICMP, UDP or TCP ##########################

#Unpacking for ICMP packets, used in network diagnostics
def icmp_packet(data): #ICMP packets are used by network devices, including routers, to send error messages and operational information indicating success or failure when communicating with another IP address.
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[:4]

#Unpacking for TCP segments
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4       #We do bitwise operations to get individual flag values bc they sit together in one pocket
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8)  >> 3
    flag_rst = (offset_reserved_flags & 4)  >> 2
    flag_syn = (offset_reserved_flags & 2)  >> 1
    flag_fin =  offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

#Unpacking UDP segments
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]



#Just formats multi-line data, useful when we are trying to print the data core, instead of a one long line this converts it to multiple shorter lines
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

main()   
