#!/usr/bin/python


# Developers: Joshua Eldridge and Cameron Sprowls


import socket, os, sys
import netifaces
import struct
import binascii
import time


def macToBinary(mac):
    """Convert MAC address to binary."""
    return binascii.unhexlify(mac.replace(':', ''))

"""
Finds MAC address of requested IP
"""
def findMac(IP):
	#obtain list of addresses on the network
	networkList = netifaces.interfaces()
	print networkList
	for iface in networkList:
		addr = netifaces.ifaddresses(iface)[2][0]['addr']
		mac = netifaces.ifaddresses(iface)[17][0]['addr']
		print addr
		print mac
		#print socket.inet_ntoa(targetIP)
		if addr == socket.inet_ntoa(IP):
			return binascii.unhexlify(mac.replace(':', ''))
	print  "MAC_NOT_FOUND"
	return "MAC_NOT_FOUND"
	
	
"""
find next hop
"""
def findNextHop(iplist, destIp):
	for entry in iplist:
		splitEntry = entry.split(" ")
		ipNumToMatch = splitEntry[0].split('/')
		destIpSplit = destIP.split('.')

		#checking 16 and 24 bit patterns
		if ipNumToMatch[1] == 16:
			ipSplit = ipNumToMatch[0].split('.')
			if ipSplit[0:2] == destIpSplit[0:2]:
				# Return (IP to send on, interface to send on)
				return (splitEntry[1], splitEntry[2])
		elif ipNumToMatch[1] == 24:
			ipSplit = ipNumToMatch[0].split('.')
			if ipSplit[0-2] == destIpSplit[0-2]:
				# Return (IP to send on, interface to send on)
				return (splitEntry[1], splitEntry[2])
	return None

"""
gets routing tables and puts them into lists
"""
def getRoutingList():
	table1 = open("r1-table.txt", "r")
	table2 = open("r2-table.txt", "r")
	listIP1 = table1.read().split("\n")
	listIP2 = table2.read().split("\n")
	print listIP1
	print listIP2
	
def makeARPRequest(ethSourceMAC, arpHardwareType, arpProtocolType, arpHardwareSize, arpProtocolSize, arpSourceMAC, arpSourceIP, arpDestIP):
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
	destMac = "\xFF\xFF\xFF\xFF\xFF\xFF"
	ethType = "\x08\x06"
	arpOpCode = "\x00\x01"
	
	# pack back to binary
    new_eth_header = struct.pack("6s6s2s", destMac, ethSourceMAC, ethType)
    new_arp_header = struct.pack("2s2s1s1s2s6s4s6s4s", arpHardwareType, arpProtocolType, arpHardwareSize, arpProtocolSize, arpOpCode, arpSourceMAC, arpSourceIP, arpDestIP)
	
	return new_eth_header + new_arp_header
	
"""
Creates ARP header
"""
def makeArpHeader(reply, hwareType, pcType, hwareSize, pcSize, srcMac, srcIp, destMac, destIp):

	if reply is True:
		opCode = '\x00\x02'

	#this is an ARP request
	else:
		opCode = '\x00\x01'
		nextHop = findNextHop(listIP1, destIp)
		if nextHop is None:
			nextHop = findNextHop(listIP2, destIp)
			#if nextHop is False: send error message.  Part three stuff
			#TODO: Since this means we need to jump to r2's network, we need to do an ARP request

	arpHeader = struct.pack("2s2s1s1s2s6s4s6s4s", hwareType, pcType, hwareSize, pcSize,
		opCode , srcMac, srcIp, destMac, destIp)

	return arpHeader
	
def main(argv):
    try: 
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x003))
        print "Socket successfully created."
    except socket.error as msg:
        print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit(-1)

    while True:

        # Receive packets with a buffer size of 1024 bytes
        packet = s.recvfrom(1024)

        # Parse the ethernet header
        eth_header = packet[0][0:14]
	
        eth_detailed = struct.unpack("!6s6s2s", eth_header)
        
        arp_header = packet[0][14:42]
        arp_detailed = struct.unpack("!2s2s1s1s2s6s4s6s4s", arp_header)

        # skip non-ARP packets
        eth_type = eth_detailed[2]

        if eth_type == '\x08\x06':
            print "************************************************"    
            print "****************_INCOMING_PACKET_***************"
            print "****************_ARP_REQUEST_*******************"
            print "************************************************"    
            print "****************_ETHERNET_FRAME_****************"
            print "Dest MAC:        ", binascii.hexlify(eth_detailed[0])
            print "Source MAC:      ", binascii.hexlify(eth_detailed[1])
            print "Type:            ", binascii.hexlify(eth_detailed[2])
            print "************************************************"
            print "******************_ARP_HEADER_******************"
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

            # strings for ip addresses
            source_IP = socket.inet_ntoa(arp_detailed[6])
            dest_IP = socket.inet_ntoa(arp_detailed[8])

            ## get list of network interfaces 
            #net_list = netifaces.interfaces()
            
			# Look up MAC address in interfaces
			dest_MAC = findMac(dest_IP)
			
            '''# loop over interfaces until find one that matches dest
            for net in net_list:
                net_IP = netifaces.ifaddresses(net)[2][0]['addr']
                net_MAC = netifaces.ifaddresses(net)[17][0]['addr']

                if dest_IP == net_IP:
                    dest_MAC = net_MAC
            '''
			
			# CALL MAKE ARP HEADER HERE? 
			#new_arp_header = makeArpHeader(True, arp_detailed[0], arp_detailed[1], arp_detailed[2], arp_detailed[3]
			#	, eth_detailed[0], arp_detailed[8], macToBinary(dest_MAC), arp_detailed[6])
			
			
            # tuples are immutable in python, copy to list
            new_eth_detailed_list = list(eth_detailed)
            new_arp_detailed_list = list(arp_detailed)

            # change arp op code
            new_arp_detailed_list[4] = '\x00\x02'

            # swap IPs
            new_arp_detailed_list[6] = arp_detailed[8]
            new_arp_detailed_list[8] = arp_detailed[6]

            # source MAC becomes dest MAC
            new_eth_detailed_list[0] = eth_detailed[1]
            new_arp_detailed_list[7] = arp_detailed[5]

            # fill in hex version of dest MAC
            new_eth_detailed_list[1] = macToBinary(dest_MAC)
            new_arp_detailed_list[5] = macToBinary(dest_MAC)

            # cast back to tuple -- might not be needed?
            new_eth_detailed = tuple(new_eth_detailed_list)
            new_arp_detailed = tuple(new_arp_detailed_list)
            '''
            http://stackoverflow.com/questions/16368263/python-struct-pack-for-individual-elements-in-a-list
            '''
            # pack back to binary
            new_eth_header = struct.pack("6s6s2s", *new_eth_detailed)
            new_arp_header = struct.pack("2s2s1s1s2s6s4s6s4s", *new_arp_detailed)

            # combine ethernet and arp headers
            new_packet = new_eth_header + new_arp_header     

            ethernet_header = new_packet[0:14]
            ethernet_detailed = struct.unpack("!6s6s2s", ethernet_header)

            arp_header = new_packet[14:42]
            arp_detailed = struct.unpack("2s2s1s1s2s6s4s6s4s", arp_header)

            ethertype = ethernet_detailed[2]

            print "************************************************"    
            print "****************_OUTGOING_PACKET_***************"
            print "****************_ARP_REPLY_*********************"
            print "************************************************"    
            print "****************_ETHERNET_FRAME_****************"
            print "Dest MAC:        ", binascii.hexlify(ethernet_detailed[0])
            print "Source MAC:      ", binascii.hexlify(ethernet_detailed[1])
            print "Type:            ", binascii.hexlify(ethertype)
            print "************************************************"
            print "******************_ARP_HEADER_******************"
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

            #print len(packet[0]), len(new_packet)

            # send new packet to addr received from old packet
            s.sendto(new_packet, packet[1])
           
            #time.sleep(1)
        
        elif eth_type != '\x08\x06':
            
            #icmp_packet = s.recvfrom(2048)

            icmp_packet = packet

            eth_header = icmp_packet[0][0:14]
            eth_detailed = struct.unpack("!6s6s2s", eth_header)

            ip_header = icmp_packet[0][14:34]
            ip_detailed = struct.unpack("1s1s2s2s2s1s1s2s4s4s", ip_header)
            #ip_ver, ip_type, ip_len, ip_id, ip_flags, ip_ttl, ip_proto, \
            #    ip_checksum, ip_srcIP, ip_destIP = struct.unpack("!BBHHHBBHII", ip_header)

            icmp_header = icmp_packet[0][34:42]
            icmp_detailed = struct.unpack("1s1s2s4s", icmp_header)
            #icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq = struct.unpack("bbHHh", icmp_header)

            ip_type = ip_detailed[1]
            ip_protocol = ip_detailed[6]
            
            if ip_type == '\x00' and ip_protocol == '\x01':
                print "************************************************"    
                print "****************_INCOMING_PACKET_***************"
                print "****************_ICMP_ECHO_REQUEST_*************"
                print "************************************************"    
                print "****************_ETHERNET_FRAME_****************"
                print "Dest MAC:        ", binascii.hexlify(eth_detailed[0])
                print "Source MAC:      ", binascii.hexlify(eth_detailed[1])
                print "Type:            ", binascii.hexlify(eth_detailed[2])
                print "************************************************"
                print "****************_IP_HEADER_*********************"
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
                print "******************_ICMP_HEADER_*****************"
                print "Type of Msg:     ", binascii.hexlify(icmp_detailed[0])
                print "Code:            ", binascii.hexlify(icmp_detailed[1])
                print "Checksum:        ", binascii.hexlify(icmp_detailed[2])
                print "Header data:     ", binascii.hexlify(icmp_detailed[3])
                print "************************************************\n"    
                
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

                # change type of msg
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
                print "****************_OUTGOING_PACKET_***************"
                print "****************_ICMP_ECHO_REPLY_***************"
                print "************************************************"
                print "****************_ETHERNET_FRAME_****************"
                print "Dest MAC:        ", binascii.hexlify(eth_detailed[0])
                print "Source MAC:      ", binascii.hexlify(eth_detailed[1])
                print "Type:            ", binascii.hexlify(eth_detailed[2])
                print "************************************************"
                print "****************_IP_HEADER_*********************"
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
                print "******************_ICMP_HEADER_*****************"
                print "Type of Msg:     ", binascii.hexlify(icmp_detailed[0])
                print "Code:            ", binascii.hexlify(icmp_detailed[1])
                print "Checksum:        ", binascii.hexlify(icmp_detailed[2])
                print "Header data:     ", binascii.hexlify(icmp_detailed[3])
                print "************************************************\n"

                #print len(icmp_packet[0]), len(new_icmp_packet)

                s.sendto(new_icmp_packet, icmp_packet[1])

if __name__ == "__main__":
    main(sys.argv)
