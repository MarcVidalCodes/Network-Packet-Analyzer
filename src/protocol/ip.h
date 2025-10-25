#ifndef NETGUARD_IP_H
#define NETGUARD_IP_H

#include <cstdint>
#include <string>
#include <arpa/inet.h>

struct IPv4Header {
    uint8_t version_ihl;     
    uint8_t tos;             
    uint16_t total_length;  
    uint16_t identification; 
    uint16_t flags_offset;   
    uint8_t ttl;              // Time to live
    uint8_t protocol;         // Protocol (6=TCP, 17=UDP, 1=ICMP)
    uint16_t checksum;        
    uint32_t src_ip;         
    uint32_t dest_ip;        
} __attribute__((packed));

#define IPPROTO_ICMP 1
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17

// Helper functions
inline int get_ip_version(const IPv4Header* ip) {
    return (ip->version_ihl >> 4) & 0x0F;
}

inline int get_ip_header_length(const IPv4Header* ip) {
    return (ip->version_ihl & 0x0F) * 4; 
}

inline std::string format_ip(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = ip;
    return std::string(inet_ntoa(addr));
}

inline std::string protocol_name(uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_TCP:  return "TCP";
        case IPPROTO_UDP:  return "UDP";
        default: return "Unknown(" + std::to_string(protocol) + ")";
    }
}

#endif 