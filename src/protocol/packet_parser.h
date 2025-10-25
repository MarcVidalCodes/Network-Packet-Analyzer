#ifndef NETGUARD_PACKET_PARSER_H
#define NETGUARD_PACKET_PARSER_H

#include <cstdint>
#include <pcap.h>

// Parse and print packet information
void parse_and_print_packet(const u_char* packet, uint32_t length, int packet_num);

#endif 