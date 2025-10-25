#ifndef NETGUARD_UDP_H
#define NETGUARD_UDP_H

#include <cstdint>
#include <arpa/inet.h>

struct UDPHeader {
    uint16_t src_port;        
    uint16_t dest_port;       
    uint16_t length;         
    uint16_t checksum;        
} __attribute__((packed));

#endif 