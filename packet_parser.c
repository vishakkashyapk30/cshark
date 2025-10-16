/*
 * Packet Parser Module Implementation
 */

#include "packet_parser.h"
#include <string.h>
#include <arpa/inet.h>

void parse_packet(const struct pcap_pkthdr *header, const u_char *packet, parsed_packet_t *parsed) {
    // Will be fully implemented in Phase 2
    (void)header;
    (void)packet;
    (void)parsed;
}

void parse_ethernet(const u_char *packet, parsed_packet_t *parsed) {
    // Will be implemented in Phase 2
    (void)packet;
    (void)parsed;
}

void parse_ipv4(const u_char *packet, int offset, parsed_packet_t *parsed) {
    // Will be implemented in Phase 2
    (void)packet;
    (void)offset;
    (void)parsed;
}

void parse_ipv6(const u_char *packet, int offset, parsed_packet_t *parsed) {
    // Will be implemented in Phase 2
    (void)packet;
    (void)offset;
    (void)parsed;
}

void parse_arp(const u_char *packet, int offset, parsed_packet_t *parsed) {
    // Will be implemented in Phase 2
    (void)packet;
    (void)offset;
    (void)parsed;
}

void parse_tcp(const u_char *packet, int offset, parsed_packet_t *parsed) {
    // Will be implemented in Phase 2
    (void)packet;
    (void)offset;
    (void)parsed;
}

void parse_udp(const u_char *packet, int offset, parsed_packet_t *parsed) {
    // Will be implemented in Phase 2
    (void)packet;
    (void)offset;
    (void)parsed;
}

void parse_payload(const u_char *packet, int offset, parsed_packet_t *parsed) {
    // Will be implemented in Phase 2
    (void)packet;
    (void)offset;
    (void)parsed;
}

