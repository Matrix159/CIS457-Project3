#!/usr/bin/python


# Developers: Joshua Eldridge and Cameron Sprowls


import socket, os, sys
import netifaces
import struct
import binascii
import threading
from threading import Timer
from uuid import getnode as get_mac #to get mac address


ETH_P_ALL = 3
listIP1 = []
listIP2 = []
isRouterOne = None
r1SendSockets = []
r2SendSockets = []
r1IPList = []
r2IPList = []
IPToMACMap = {}
waitingIPv4Packets = []
TTL_ERROR = 0
UNREACHABLE_ERROR = 1

def macToBinary(mac):
    """Convert MAC address to binary."""
    return binascii.unhexlify(mac.replace(':', ''))

def findMac(IP):
    """Finds MAC address of requested IP"""

    #obtain list of addresses on the network
    networkList = netifaces.interfaces()
    print networkList
    for iface in networkList:
        addr = netifaces.ifaddresses(iface)[2][0]['addr']
        # Of format "aa:bb:cc:dd:ee:ff"
        mac = netifaces.ifaddresses(iface)[17][0]['addr']
        print addr
        print mac
        if addr == IP:
            return mac
    print "MAC_NOT_FOUND"
    return None
    

def findNextHop(iplist, destIP):
    """Find next hop"""
    for entry in iplist:
        splitEntry = entry.split(" ")
        ipNumToMatch = splitEntry[0].split('/')
        destIPSplit = destIP.split('.')

        #checking 16 and 24 bit patterns
        if int(ipNumToMatch[1]) == 16:
            ipSplit = ipNumToMatch[0].split('.')
            if ipSplit[0:2] == destIPSplit[0:2]:
                # Return (IP to send to, interface to send on)
                return (splitEntry[1], splitEntry[2])
        elif int(ipNumToMatch[1]) == 24:
            ipSplit = ipNumToMatch[0].split('.')
            if ipSplit[0:3] == destIPSplit[0:3]:
                # Return (IP to send to, interface to send on)
                return (splitEntry[1], splitEntry[2])
    return None


def getRoutingList(isRouterOne):
    """Gets routing tables and puts them into lists"""
    global listIP1
    global listIP2
    
    if isRouterOne:
        table1 = open("r1-table.txt", "r")
        listIP1 = filter(None, table1.read().split("\n"))
        table1.close()
    else:
        table2 = open("r2-table.txt", "r")
        listIP2 = filter(None, table2.read().split("\n"))
        table2.close()
    
def makeARPRequest(ethSourceMAC, arpSourceMAC, arpSourceIP, arpDestIP):
    '''
    "****************_ARP_REQUEST_*******************"
    "************************************************"    
    "****************_ETHERNET_FRAME_****************"
    "Dest MAC:        ", binascii.hexlify(eth_detailed[0])
    "Source MAC:      ", binascii.hexlify(eth_detailed[1])
    "Type:            ", binascii.hexlify(eth_detailed[2])
    "************************************************"
    "******************_ARP_HEADER_******************"
    "Hardware type:   ", binascii.hexlify(arp_detailed[0])
    "Protocol type:   ", binascii.hexlify(arp_detailed[1])
    "Hardware size:   ", binascii.hexlify(arp_detailed[2])
    "Protocol size:   ", binascii.hexlify(arp_detailed[3])
    "Opcode:          ", binascii.hexlify(arp_detailed[4])
    "Source MAC:      ", binascii.hexlify(arp_detailed[5])
    "Source IP:       ", socket.inet_ntoa(arp_detailed[6])
    "Dest MAC:        ", binascii.hexlify(arp_detailed[7])
    "Dest IP:         ", socket.inet_ntoa(arp_detailed[8])
    "************************************************\n"    
    '''
    destMAC = "\xFF\xFF\xFF\xFF\xFF\xFF"
    ethType = "\x08\x06"
    
    arpHardwareType = "\x00\x01"
    arpProtocolType = "\x08\x00"
    arpHardwareSize = "\x06"
    arpProtocolSize = "\x04"
    arpOpCode = "\x00\x01"
    arpDestinationMAC = "\x00\x00\x00\x00\x00\x00"
    # pack back to binary
    new_eth_header = struct.pack("6s6s2s", destMAC, ethSourceMAC, ethType)
    new_arp_header = struct.pack("2s2s1s1s2s6s4s6s4s", arpHardwareType, arpProtocolType, arpHardwareSize, arpProtocolSize, arpOpCode, arpSourceMAC, arpSourceIP, arpDestinationMAC, arpDestIP)
    
    return new_eth_header + new_arp_header


def checkIsArpPacket(packet):
    '''Check to see if packet is of type arp'''
    # Parse the ethernet header
    eth_header = packet[0][0:14]
    eth_detailed = struct.unpack("!6s6s2s", eth_header)
    eth_type = eth_detailed[2]
    
    if eth_type == '\x08\x06':
        return True
    else:
        return False

def processArpPacket(packet): 
    ''' Handle ARP requests and ARP replies '''
    # Parse the ethernet header
    eth_header = packet[0][0:14]
    
    eth_detailed = struct.unpack("!6s6s2s", eth_header)
        
    arp_header = packet[0][14:42]
    arp_detailed = struct.unpack("!2s2s1s1s2s6s4s6s4s", arp_header)


    print "************************************************"    
    print "**************** INCOMING PACKET ***************"
    print "**************** ARP REQUEST *******************"
    print "************************************************"    
    print "**************** ETHERNET FRAME ****************"
    print "Dest MAC:        ", binascii.hexlify(eth_detailed[0])
    print "Source MAC:      ", binascii.hexlify(eth_detailed[1])
    print "Type:            ", binascii.hexlify(eth_detailed[2])
    print "************************************************"
    print "****************** ARP HEADER ******************"
    print "Hardware type:   ", binascii.hexlify(arp_detailed[0])
    print "Protocol type:   ", binascii.hexlify(arp_detailed[1])
    print "Hardware size:   ", binascii.hexlify(arp_detailed[2])
    print "Protocol size:   ", binascii.hexlify(arp_detailed[3])
    print "Opcode:          ", binascii.hexlify(arp_detailed[4])
    print "Source MAC:      ", binascii.hexlify(arp_detailed[5])
    print "Source IP:       ", socket.inet_ntoa(arp_detailed[6])
    print "Dest MAC:        ", binascii.hexlify(arp_detailed[7])
    print "Dest IP:         ", socket.inet_ntoa(arp_detailed[8])
    print "************************************************\n"
    
    # If we are router 1 and destination IP of arp is not us continue
    router1List = ['10.1.0.1', '10.1.1.1', '10.0.0.1']
    if(isRouterOne and socket.inet_ntoa(arp_detailed[8]) not in router1List):
        return None
    # If we are router 2 and destination IP of arp is not us continue
    router2List = ['10.3.0.1', '10.3.1.1', '10.3.4.1', '10.0.0.2']
    if(not isRouterOne and socket.inet_ntoa(arp_detailed[8]) not in router2List):
        return None    
    # If this is an ARP reply packet
    if arp_detailed[4] == '\x00\x02':
        print "MAC ADDRESS OF THE OTHER SIDE: " + binascii.hexlify(arp_detailed[5])
        # Map IP to MAC 
        IPToMACMap[socket.inet_ntoa(arp_detailed[6])] = binascii.hexlify(arp_detailed[5])
        return None
        
    # strings for ip addresses
    source_IP = socket.inet_ntoa(arp_detailed[6])
    dest_IP = socket.inet_ntoa(arp_detailed[8])
    
    # Look up MAC address to find in interfaces
    source_MAC = findMac(dest_IP)
    
    # tuples are immutable in python, copy to list
    new_eth_detailed_list = list(eth_detailed)
    new_arp_detailed_list = list(arp_detailed)
    
    # change ARP code to ARP reply
    new_arp_detailed_list[4] = '\x00\x02'
    
    # swap IPs
    new_arp_detailed_list[6] = arp_detailed[8]
    new_arp_detailed_list[8] = arp_detailed[6]
    
    # source MAC is assigned to dest MAC
    new_eth_detailed_list[0] = eth_detailed[1]
    new_arp_detailed_list[7] = arp_detailed[5]
    
    # fill in hex version of SOURCE MAC
    new_eth_detailed_list[1] = macToBinary(source_MAC)
    new_arp_detailed_list[5] = macToBinary(source_MAC)
    
    # cast back to tuple -- might not be needed?
    new_eth_detailed = tuple(new_eth_detailed_list)
    new_arp_detailed = tuple(new_arp_detailed_list)

    # pack back to binary
    new_eth_header = struct.pack("6s6s2s", *new_eth_detailed)
    new_arp_header = struct.pack("2s2s1s1s2s6s4s6s4s", *new_arp_detailed)
    
    # combine ethernet and arp headers
    new_packet = new_eth_header + new_arp_header     
    
    # Do this for printing purposes
    ethernet_header = new_packet[0:14]
    ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)
    
    arp_header = new_packet[14:42]
    arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)
    
    
    print "************************************************"    
    print "**************** OUTGOING PACKET ***************"
    print "**************** ARP REPLY *********************"
    print "************************************************"    
    print "**************** ETHERNET FRAME ****************"
    print "Dest MAC:        ", binascii.hexlify(ethernet_detailed[0])
    print "Source MAC:      ", binascii.hexlify(ethernet_detailed[1])
    print "Type:            ", binascii.hexlify(ethernet_detailed[2])
    print "************************************************"
    print "****************** ARP HEADER ******************"
    print "Hardware type:   ", binascii.hexlify(arp_detailed[0])
    print "Protocol type:   ", binascii.hexlify(arp_detailed[1])
    print "Hardware size:   ", binascii.hexlify(arp_detailed[2])
    print "Protocol size:   ", binascii.hexlify(arp_detailed[3])
    print "Opcode:          ", binascii.hexlify(arp_detailed[4])
    print "Source MAC:      ", binascii.hexlify(arp_detailed[5])
    print "Source IP:       ", socket.inet_ntoa(arp_detailed[6])
    print "Dest MAC:        ", binascii.hexlify(arp_detailed[7])
    print "Dest IP:         ", socket.inet_ntoa(arp_detailed[8])
    print "************************************************\n"    
    
    return new_packet

    
def processICMPPacketToRouter(icmp_packet): 

    eth_header = icmp_packet[0][0:14]
    eth_detailed = struct.unpack("!6s6s2s", eth_header)
    
    ip_header = icmp_packet[0][14:34]
    ip_detailed = struct.unpack("1s1s2s2s2s1s1s2s4s4s", ip_header)
    
    # TODO: Test this out
    #ip_ver, ip_type, ip_len, ip_id, ip_flags, ip_ttl, ip_proto, \
    #    ip_checksum, ip_srcIP, ip_destIP = struct.unpack("!BBHHHBBHII", ip_header)
    
    icmp_header = icmp_packet[0][34:42]
    icmp_detailed = struct.unpack("1s1s2s4s", icmp_header)
    #icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack("bbHHh", icmp_header)
    
    ip_type = ip_detailed[1]
    ip_protocol = ip_detailed[6]
    
    #print icmp_packet[1]
    #print binascii.hexlify(icmp_packet[1][4])
    print "************************************************"    
    print "**************** INCOMING PACKET ***************"
    print "**************** ICMP ECHO REQUEST *************"
    print "************************************************"    
    print "**************** ETHERNET FRAME ****************"
    print "Dest MAC:        ", binascii.hexlify(eth_detailed[0])
    print "Source MAC:      ", binascii.hexlify(eth_detailed[1])
    print "Type:            ", binascii.hexlify(eth_detailed[2])
    print "************************************************"
    print "**************** IP HEADER *********************"
    print "Version/IHL:     ", binascii.hexlify(ip_detailed[0])
    print "Type of service: ", binascii.hexlify(ip_detailed[1])
    print "Length:          ", binascii.hexlify(ip_detailed[2])
    print "Identification:  ", binascii.hexlify(ip_detailed[3])
    print "Flags/offset:    ", binascii.hexlify(ip_detailed[4])
    print "Time to Live:    ", binascii.hexlify(ip_detailed[5])
    print "Protocol:        ", binascii.hexlify(ip_detailed[6])
    print "Checksum:        ", binascii.hexlify(ip_detailed[7])
    print "Source IP:       ", socket.inet_ntoa(ip_detailed[8])
    print "Dest IP:         ", socket.inet_ntoa(ip_detailed[9])
    print "************************************************"
    print "****************** ICMP HEADER *****************"
    print "Type of Msg:     ", binascii.hexlify(icmp_detailed[0])
    print "Code:            ", binascii.hexlify(icmp_detailed[1])
    print "Checksum:        ", binascii.hexlify(icmp_detailed[2])
    print "Header data:     ", binascii.hexlify(icmp_detailed[3])
    print "************************************************\n"    
    
    
    #continue
    # tuples are immutable in python, copy to list
    new_eth_detailed_list = list(eth_detailed)
    new_ip_detailed_list = list(ip_detailed)
    new_icmp_detailed_list = list(icmp_detailed)
    
    # swap IPs
    new_ip_detailed_list[8] = ip_detailed[9]
    new_ip_detailed_list[9] = ip_detailed[8]
    
    # swap MACs
    new_eth_detailed_list[0] = eth_detailed[1]
    new_eth_detailed_list[1] = eth_detailed[0]
    
    # change type of ICMP to reply
    new_icmp_detailed_list[0] = '\x00'
    
    # cast back to tuple -- might not be needed?
    new_eth_detailed = tuple(new_eth_detailed_list)
    new_ip_detailed = tuple(new_ip_detailed_list)
    new_icmp_detailed = tuple(new_icmp_detailed_list)
    
    # pack back to binary
    new_eth_header = struct.pack("6s6s2s", *new_eth_detailed)
    new_ip_header = struct.pack("1s1s2s2s2s1s1s2s4s4s", *new_ip_detailed)
    new_icmp_header = struct.pack("1s1s2s4s", *new_icmp_detailed)
    
    # combine eth, ip, and icmp headers and icmp data
    new_icmp_packet = new_eth_header + new_ip_header + new_icmp_header + icmp_packet[0][42:]
    
    eth_header = new_icmp_packet[0:14]
    eth_detailed = struct.unpack("!6s6s2s", eth_header)
    
    ip_header = new_icmp_packet[14:34]
    ip_detailed = struct.unpack("1s1s2s2s2s1s1s2s4s4s", ip_header)
    
    icmp_header = new_icmp_packet[34:42]
    icmp_detailed = struct.unpack("1s1s2s4s", icmp_header)
    
    print "************************************************"    
    print "**************** OUTGOING PACKET ***************"
    print "**************** ICMP ECHO REPLY ***************"
    print "************************************************"
    print "**************** ETHERNET FRAME ****************"
    print "Dest MAC:        ", binascii.hexlify(eth_detailed[0])
    print "Source MAC:      ", binascii.hexlify(eth_detailed[1])
    print "Type:            ", binascii.hexlify(eth_detailed[2])
    print "************************************************"
    print "**************** IP HEADER *********************"
    print "Version/IHL:     ", binascii.hexlify(ip_detailed[0])
    print "Type of service: ", binascii.hexlify(ip_detailed[1])
    print "Length:          ", binascii.hexlify(ip_detailed[2])
    print "Identification:  ", binascii.hexlify(ip_detailed[3])
    print "Flags/offset:    ", binascii.hexlify(ip_detailed[4])
    print "Time to Live:    ", binascii.hexlify(ip_detailed[5])
    print "Protocol:        ", binascii.hexlify(ip_detailed[6])
    print "Checksum:        ", binascii.hexlify(ip_detailed[7])
    print "Source IP:       ", socket.inet_ntoa(ip_detailed[8])
    print "Dest IP:         ", socket.inet_ntoa(ip_detailed[9])
    print "************************************************"
    print "****************** ICMP HEADER *****************"
    print "Type of Msg:     ", binascii.hexlify(icmp_detailed[0])
    print "Code:            ", binascii.hexlify(icmp_detailed[1])
    print "Checksum:        ", binascii.hexlify(icmp_detailed[2])
    print "Header data:     ", binascii.hexlify(icmp_detailed[3])
    print "************************************************\n"
    
    return new_icmp_packet

def forwardIPv4Packet(packet):

    eth_header = packet[0][0:14]
    eth_detailed = struct.unpack("!6s6s2s", eth_header)
    eth_detailed = list(eth_detailed)
    ip_header = packet[0][14:34]
    ip_detailed = struct.unpack("!1s1s2s2s2s1s1s2s4s4s", ip_header)
    original_ip_header = ip_header
    ip_detailed = list(ip_detailed)
    # Check checksum in packet
    copy = list(ip_detailed)
    copy[7] = '\x00\x00'
    copy = struct.pack("1s1s2s2s2s1s1s2s4s4s", *copy)
    if(ip_detailed[7] != checksum(copy, len(copy))):
        return None
    # Check TTL
    ttlResult = decrementTTL(ip_detailed[5])
    if(ttlResult is not None):
        # New TTL
        ip_detailed[5] = ttlResult
        # Recalculated checksum
        ip_detailed[7] = checksum(copy, len(copy))
    else:
        # Create the time exceeded ICMP message
        # Swap the MAC addresses
        temp = eth_detailed[0]
        eth_detailed[0] = eth_detailed[1]
        eth_detailed[1] = temp
        # Set TTL to 64 because why not
        ip_detailed[5] = '\x40'
        # Set protocol as ICMP
        ip_detailed[6] = '\x01'
        #Swap the ip addresses
        temp = ip_detailed[8]
        ip_detailed[8] = ip_detailed[9]
        ip_detailed[9] = temp
        
        #recalculate ip checksum 
        copy = list(ip_detailed)
        copy[7] = '\x00\x00'
        ip_detailed[7] = checksum(copy, len(copy))
        # Time exceeded error packet
        return (TTL_ERROR, struct.pack('6s6s2s', *tuple(eth_detailed)) + struct.pack("1s1s2s2s2s1s1s2s4s4s", *tuple(ip_detailed)) + createICMPTimeExceeded(original_ip_header, packet[0][34:43]))
    
    # Return a packet pre-arp request
    return (socket.inet_ntoa(ip_detailed[9]), (packet[0][0:14] + struct.pack("1s1s2s2s2s1s1s2s4s4s", *ip_detailed) + packet[0][34:]))

def createICMPTimeExceeded(ip_packet, data):
    icmp_type = b'\x0B'
    icmp_code = b'\x00'
    icmp_checksum = b'\x00\x00'
    icmp_unused = b'\x00\x00\x00\x00'
    icmp_total = icmp_type + icmp_code + icmp_checksum + icmp_unused + ip_packet + data
    icmp_checksum = ip_checksum(icmp_total, len(icmp_total))
    
    return struct.pack('1s1s2s4s20s8s', icmp_type, icmp_code, icmp_checksum, icmp_unused, ip_packet, data)

def createICMPUnreachable(eth_destination, eth_source, ip_packet, source_ip, destination_ip, data):

    eth_type = b'\x08\x00'
    eth_packed = struct.pack("6s6s2s", eth_destination, eth_source, eth_type)
    
    ip_detailed = struct.unpack("!1s1s2s2s2s1s1s2s4s4s", ip_packet)
    
    ip_header = packet[0][14:34]
    ip_detailed = struct.unpack("!1s1s2s2s2s1s1s2s4s4s", ip_header)
    ip_detailed = list(ip_detailed)
    # TTL to 64
    ip_detailed[5] = '\x40'
    # Protocol to 1 for ICMP
    ip_detailed[6] = '\x01'
    ip_detailed[7] = '\x00\x00'
    ip_detailed[8] = source_ip
    ip_detailed[9] = destination_ip
    checksum_packed = struct.pack("1s1s2s2s2s1s1s2s4s4s", *tuple(ip_detailed))
    ip_detailed[7] = checksum(checksum_packed, len(checksum_packed))
    
    ip_packed = struct.pack("1s1s2s2s2s1s1s2s4s4s", *tuple(ip_detailed))
    
    icmp_type = b'\x03'
    icmp_code = b'\x01'
    icmp_checksum = b'\x00\x00'
    icmp_unused = b'\x00\x00\x00\x00'
    icmp_total = icmp_type + icmp_code + icmp_checksum + icmp_unused + ip_packet + data
    icmp_checksum = ip_checksum(icmp_total, len(icmp_total))
    
    return eth_packed + ip_packed + struct.pack('1s1s2s4s20s8s', icmp_type, icmp_code, icmp_checksum, icmp_unused, ip_packet, data)

# Don't forget to clear out checksum in header before calculating checksum at any point
def checksum(ip_header, size):
    
    cksum = 0
    pointer = 0
    
    hexed = binascii.hexlify(ip_header)
    stringVersion = hexed.decode()
    
    #The main loop adds up each set of 2 bytes. They are first converted to strings and then concatenated
    #together, converted to integers, and then added to the sum.
    while size > 1:
        cksum += int(stringVersion[pointer] + stringVersion[pointer + 1], 16)
        size -= 2
        pointer += 2
    if size: #This accounts for a situation where the header is odd
        cksum += int(stringVersion[pointer], 16)
        
    cksum = (cksum >> 16) + (cksum & 0xffff)
    cksum += (cksum >>16)
    
    return binascii.unhexlify(hex((~cksum) & 0xFFFF)[2:])
    
def decrementTTL(binaryTTL):
    ''' Convert TTL to int, decrement by 1, and then turn it back into 8 bit padded binary '''
    intTTL = int(binascii.hexlify(binaryTTL), 16)
    intTTL = intTTL - 1
    if(intTTL == 0):
        return None
    else:
        return binascii.unhexlify(hex(intTTL)[2:].zfill(8))

def main(argv):

    global isRouterOne
    global socket
    global listIP1
    global listIP2
    global r1SendSockets
    global r2SendSockets
    global IPToMACMap
    global waitingIPv4Packets
    try: 
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x003))
        print "Socket successfully created."
    except:
        print 'Socket could not be created.'
        sys.exit(-1)
        
    r1_interfaces = []
    r2_interfaces = []
    
    print("Interfaces: {0}".format(str(netifaces.interfaces())))
    for interface in netifaces.interfaces():
        if interface[0:2] == "r1":
            r1_interfaces.append(interface)
        elif interface[0:2] == "r2":
            r2_interfaces.append(interface)

    # print("Interfaces: {}".format(str(eth1_interfaces)))

    # SETTING UP SEND SOCKETS
    for i in r1_interfaces:
        # get the addresses associated with this interface
        address = netifaces.ifaddresses(i)
        # get the packet address associated with it
        eth1_packet_address = address[2][0]['addr']
        print("eth1_packet_address: {}".format(str(eth1_packet_address)))

        # python string interpolation
        print("Creating socket on interface {}".format(i))

        # create the packet socket
        try:
            SOCKFD = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except:
            print ('Socket could not be created again')
            sys.exit()
        # bind the packet socket to this interface
        SOCKFD.bind((i, 0))
        global r1SendSockets
        r1SendSockets.append((SOCKFD, i))
        
    for i in r2_interfaces:
        # get the addresses associated with this interface
        address = netifaces.ifaddresses(i)
        # get the packet address associated with it
        eth1_packet_address = address[2][0]['addr']
        print("eth1_packet_address: {}".format(str(eth1_packet_address)))

        # python string interpolation
        print("Creating socket on interface {}".format(i))

        # create the packet socket
        try:
            SOCKFD = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except:
            print ('Socket could not be created again 2')
            sys.exit()
        # bind the packet socket to this interface
        SOCKFD.bind((i, 0))
        global r2SendSockets
        r2SendSockets.append((SOCKFD, i))
        
    while True:

        # Receive packets with a buffer size of 1024 bytes
        packet = s.recvfrom(1024)

        arp_header = packet[0][14:42]
        arp_detailed = struct.unpack("!2s2s1s1s2s6s4s6s4s", arp_header)

        # skip non-ARP packets
        #eth_type = eth_detailed[2]
        
        # Packet handling logic
        isArpPacket = checkIsArpPacket(packet)
        if(isArpPacket):
            returnVal = processArpPacket(packet)
            # Send arp reply
            if(returnVal is not None):
                # send new packet to addr received from old packet
                s.sendto(returnVal, packet[1])
                continue
            continue
        if not isArpPacket:
            
            # Parse the ethernet header
            eth_header = packet[0][0:14]
            eth_detailed = struct.unpack("!6s6s2s", eth_header)
            
            ip_header = packet[0][14:34]
            ip_detailed = struct.unpack("1s1s2s2s2s1s1s2s4s4s", ip_header)
            #ip_ver, ip_type, ip_len, ip_id, ip_flags, ip_ttl, ip_proto, \
            #    ip_checksum, ip_srcIP, ip_destIP = struct.unpack("!BBHHHBBHII", ip_header)

            #icmp_header =  packet[0][34:42]
            #icmp_detailed = struct.unpack("1s1s2s4s", icmp_header)
            #icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack("bbHHh", icmp_header)
            
            ip_ver_length = ip_detailed[0]
            ip_ver = binascii.hexlify(ip_ver_length).decode()[0]
            ip_type = ip_detailed[1]
            ip_protocol = ip_detailed[6]
            # This should hopefully work for checking for any ipv4 packet
            if ip_ver == '4':
                
                #Check if packet is for us
                router1List = ['10.1.0.1', '10.1.1.1', '10.0.0.1']
                router2List = ['10.3.0.1', '10.3.1.1', '10.3.4.1', '10.0.0.2']
                # Check if this packet is for us or not and process it, (we only care to process icmp for us)
                if((isRouterOne and socket.inet_ntoa(ip_detailed[9]) in router1List) 
                or (not isRouterOne and socket.inet_ntoa(ip_detailed[9]) in router2List)):
                    # IP Protocol is ICMP
                    if ip_protocol == '\x01':
                        returnVal = processICMPPacketToRouter(packet)
                        s.sendto(returnVal, packet[1]) 
                        continue
                    
                # If we reached here the packet wasn't for us so forward it
                result = forwardIPv4Packet(packet)
                # Result of None is a bad checksum so discard.
                if(result is None):
                    continue
                elif(result[0] == TTL_ERROR):
                    s.sendto(result[1], packet[1])
                else:
                    if(result[0] in IPToMACMap):
                        
                        # Set the MAC addresses
                        eth_header = result[0:14]
                        eth_detailed = struct.unpack("!6s6s2s", eth_header)
                        eth_detailed = list(eth_detailed)
                        temp = eth_detailed[0]
                        eth_detailed[0] = IPToMACMap[result[0]]
                        eth_detailed[1] = temp
                        result = (result[0], struct.pack("6s6s2s", *tuple(eth_detailed)) + result[14:])
                        # If we have the IP addressed cached forward it via routing lookup
                        if(isRouterOne):
                            nextHop = findNextHop(listIP1, result[0])
                        else:
                            nextHop = findNextHop(listIP2, result[0])
                        if(nextHop is not None):
                            if(isRouterOne):
                                for socket1 in r1SendSockets:
                                    # If socket interface == next hop interface
                                    if socket1[1] == nextHop[1]:
                                        socket1[0].send(result)
                            else:
                                for socket2 in r2SendSockets:
                                    # If socket interface == next hop interface
                                    if socket2[1] == nextHop[1]:
                                        socket2[0].send(result)
                        else:
                            # If for some reason the next hop is None...
                            unreachablePacket = createICMPUnreachable(packet[0][6:12], packet[0][0:6], packet[0][14:34], struct.pack('4s', ip_detailed[9]) , struct.pack('4s', ip_detailed[8]), packet[0][34:43])
                            s.sendto(unreachablePacket, packet[1])
                    else:  
                        #waitingIPv4Packets.append(result)
                        # Make the ARP request
                        if(isRouterOne):
                            nextHop = findNextHop(listIP1, result[0])
                        else:
                            nextHop = findNextHop(listIP2, result[0])
                        if(nextHop is not None):
                            if(isRouterOne):
                                ethSourceMAC = eth_detailed[0]
                                arpSourceMAC = ethSourceMAC
                                
                                # Get the destination IP via interface
                                addr = netifaces.ifaddresses(nextHop[1])[2][0]['addr']

                                arpPacket = makeARPRequest(ethSourceMAC, arpSourceMAC, socket.inet_aton(addr), socket.inet_aton(nextHop[0]))
                                for socket1 in r1SendSockets:
                                    # If socket interface == next hop interface
                                    if socket1[1] == nextHop[1]:
                                        socket1[0].send(arpPacket)
                            else:
                                ethSourceMAC = eth_detailed[0]
                                arpSourceMAC = ethSourceMAC
                                
                                # Get the destination IP via interface
                                addr = netifaces.ifaddresses(nextHop[1])[2][0]['addr']

                                arpPacket = makeARPRequest(ethSourceMAC, arpSourceMAC, socket.inet_aton(addr), socket.inet_aton(nextHop[0]))
                                for socket2 in r2SendSockets:
                                    # If socket interface == next hop interface
                                    if socket2[1] == nextHop[1]:
                                        socket2[0].send(arpPacket)
                        else:
                            # If for some reason the next hop is None...
                            unreachablePacket = createICMPUnreachable(packet[0][6:12], packet[0][0:6], packet[0][14:34], struct.pack('4s', ip_detailed[9]) , struct.pack('4s', ip_detailed[8]), packet[0][34:43])
                            s.sendto(unreachablePacket, packet[1])

                        #           Dest IP    Forward Packet   Original Packet
                        argsList = [result[0], result[1], packet[0]]
    
                        timer = Timer(10, unreachable, argsList) 
                        timer.start()
                    
def unreachable(args):
    global IPToMACMap
    global listIP1
    global listIP2
    if(args[0] not in IPToMACMap):
        packet = args[2]
        ip_header = packet[14:34]
        ip_detailed = struct.unpack("1s1s2s2s2s1s1s2s4s4s", ip_header)
        createICMPUnreachable(packet[6:12], packet[0:6], packet[14:34], struct.pack('4s', ip_detailed[9]) , struct.pack('4s', ip_detailed[8]), packet[34:43])
    else: 
        # If we have the IP addressed cached forward it via routing lookup
        if(isRouterOne):
            nextHop = findNextHop(listIP1, args[0])
        else:
            nextHop = findNextHop(listIP2, args[0])
        if(nextHop is not None):
            if(isRouterOne):
                for socket1 in r1SendSockets:
                    # If socket interface == next hop interface
                    if socket1[1] == nextHop[1]:
                        socket1[0].send(args[1])
            else:
                for socket2 in r2SendSockets:
                    # If socket interface == next hop interface
                    if socket2[1] == nextHop[1]:
                        socket2[0].send(args[1])
    # Send error on the arp request
    # send on socket args[0]

if __name__ == "__main__":
    if(len(sys.argv) != 2):
        print "Incorrect command line argument length."
    if(sys.argv[1] == "r1"):
        isRouterOne = True
        getRoutingList(True)
        main(sys.argv)
    elif(sys.argv[1] == "r2"):
        isRouterOne = False
        getRoutingList(False)
        main(sys.argv)
  
   
