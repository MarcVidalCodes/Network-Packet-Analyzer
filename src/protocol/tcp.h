#ifndef NETGUARD_TCP_H
#define NETGUARD_TCP_H

#include <cstdint>
#include <string>
#include <arpa/inet.h>

struct TCPHeader {
    uint16_t src_port;      
    uint16_t dest_port;     
    uint32_t seq_num;       
    uint32_t ack_num;       
    uint8_t data_offset_reserved; 
    uint8_t flags;            
    uint16_t window;       
    uint16_t checksum;       
    uint16_t urgent_ptr;    
} __attribute__((packed));

#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80

// Helper functions
inline int get_tcp_header_length(const TCPHeader* tcp) {
    return ((tcp->data_offset_reserved >> 4) & 0x0F) * 4;  
}

inline std::string format_tcp_flags(uint8_t flags) {
    std::string result;
    if (flags & TCP_FIN) result += "FIN ";
    if (flags & TCP_SYN) result += "SYN ";
    if (flags & TCP_RST) result += "RST ";
    if (flags & TCP_PSH) result += "PSH ";
    if (flags & TCP_ACK) result += "ACK ";
    if (flags & TCP_URG) result += "URG ";
    if (flags & TCP_ECE) result += "ECE ";
    if (flags & TCP_CWR) result += "CWR ";
    
    if (result.empty()) {
        return "NONE";
    }
    
    result.pop_back();
    return result;
}

#endif 