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

            # strings for ip addresses
            source_IP = socket.inet_ntoa(arp_detailed[6])
            dest_IP = socket.inet_ntoa(arp_detailed[8])

            # get list of network interfaces 
            net_list = netifaces.interfaces()
            
            # loop over interfaces until find one that matches dest
            for net in net_list:
                net_IP = netifaces.ifaddresses(net)[2][0]['addr']
                net_MAC = netifaces.ifaddresses(net)[17][0]['addr']

                if dest_IP == net_IP:
                    dest_MAC = net_MAC
            
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
            print "**************** OUTGOING PACKET ***************"
            print "**************** ARP REPLY *********************"
            print "************************************************"    
            print "**************** ETHERNET FRAME ****************"
            print "Dest MAC:        ", binascii.hexlify(ethernet_detailed[0])
            print "Source MAC:      ", binascii.hexlify(ethernet_detailed[1])
            print "Type:            ", binascii.hexlify(ethertype)
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

            #print len(packet[0]), len(new_packet)

            # send new packet to addr received from old packet
            s.sendto(new_packet, packet[1])
           
            #time.sleep(1)
        
        elif eth_type == '\x08\x00':
            
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

                #print len(icmp_packet[0]), len(new_icmp_packet)

                s.sendto(new_icmp_packet, icmp_packet[1])

if __name__ == "__main__":
    main(sys.argv)
