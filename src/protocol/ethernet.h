#ifndef NETGUARD_ETHERNET_H
#define NETGUARD_ETHERNET_H

#include <cstdint> 
#include <string>

struct EthernetHeader{
    uint8_t dest_mac[6];
    uint8_t src_mac[6]; 
    uint16_t ethertype; 
}__attribute__((packed));

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_ARP 0x0806

//Format MAC address
inline std::string format_mac(const uint8_t* mac) {
    char buffer[18];
    snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buffer);
}

#endif 