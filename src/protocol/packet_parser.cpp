#include "packet_parser.h"
#include "ethernet.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include <iostream>
#include <iomanip>
#include <arpa/inet.h>

void parse_and_print_packet(const u_char* packet, uint32_t length, int packet_num) {
    // Minimum Ethernet frame size check
    if (length < sizeof(EthernetHeader)) {
        std::cout << "[" << packet_num << "] Packet too small (< Ethernet header)" << std::endl;
        return;
    }

    // Parse Ethernet header
    const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(packet);
    uint16_t ethertype = ntohs(eth->ethertype);

    // Print basic info
    std::cout << "[" << packet_num << "] ";

    // Check if it's IPv4
    if (ethertype == ETHERTYPE_IPV4) {
        const uint8_t* ip_start = packet + sizeof(EthernetHeader);
        
        // Check if we have enough data for IP header
        if (length < sizeof(EthernetHeader) + sizeof(IPv4Header)) {
            std::cout << "IPv4 packet too small" << std::endl;
            return;
        }

        const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(ip_start);
        
        // Verify it's IPv4
        if (get_ip_version(ip) != 4) {
            std::cout << "Not IPv4 (version: " << get_ip_version(ip) << ")" << std::endl;
            return;
        }

        int ip_header_len = get_ip_header_length(ip);
        std::string src_ip_str = format_ip(ip->src_ip);
        std::string dest_ip_str = format_ip(ip->dest_ip);

        // Parse transport layer based on protocol
        if (ip->protocol == IPPROTO_TCP) {
            const uint8_t* tcp_start = ip_start + ip_header_len;
            
            // Check if we have enough data for TCP header
            if (length < sizeof(EthernetHeader) + ip_header_len + sizeof(TCPHeader)) {
                std::cout << "TCP packet too small" << std::endl;
                return;
            }

            const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(tcp_start);
            uint16_t src_port = ntohs(tcp->src_port);
            uint16_t dest_port = ntohs(tcp->dest_port);
            std::string flags = format_tcp_flags(tcp->flags);

            std::cout << src_ip_str << ":" << src_port 
                      << " -> " 
                      << dest_ip_str << ":" << dest_port 
                      << " | TCP [" << flags << "] | " 
                      << length << " bytes"
                      << std::endl;

        } else if (ip->protocol == IPPROTO_UDP) {
            const uint8_t* udp_start = ip_start + ip_header_len;
            
            // Check if we have enough data for UDP header
            if (length < sizeof(EthernetHeader) + ip_header_len + sizeof(UDPHeader)) {
                std::cout << "UDP packet too small" << std::endl;
                return;
            }

            const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(udp_start);
            uint16_t src_port = ntohs(udp->src_port);
            uint16_t dest_port = ntohs(udp->dest_port);

            std::cout << src_ip_str << ":" << src_port 
                      << " -> " 
                      << dest_ip_str << ":" << dest_port 
                      << " | UDP | " 
                      << length << " bytes"
                      << std::endl;

        } else if (ip->protocol == IPPROTO_ICMP) {
            std::cout << src_ip_str 
                      << " -> " 
                      << dest_ip_str 
                      << " | ICMP | " 
                      << length << " bytes"
                      << std::endl;

        } else {
            // Other protocols
            std::cout << src_ip_str 
                      << " -> " 
                      << dest_ip_str 
                      << " | " << protocol_name(ip->protocol) << " | " 
                      << length << " bytes"
                      << std::endl;
        }

    } else if (ethertype == ETHERTYPE_ARP) {
        std::cout << "ARP | " << length << " bytes" << std::endl;
    } else if (ethertype == ETHERTYPE_IPV6) {
        std::cout << "IPv6 | " << length << " bytes (not parsed)" << std::endl;
    } else {
        std::cout << "EtherType: 0x" << std::hex << ethertype << std::dec 
                  << " | " << length << " bytes" << std::endl;
    }
}