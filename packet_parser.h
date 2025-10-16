/*
 * Packet Parser Module
 * Handles layer-by-layer packet parsing (L2, L3, L4, L7)
 */

#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>
#include <stdint.h>

// Parsed packet information structure
typedef struct {
    // Packet metadata
    uint32_t id;
    struct timeval timestamp;
    uint32_t length;
    
    // Layer 2 (Ethernet)
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t ethertype;
    
    // Layer 3 (IP/ARP)
    int l3_protocol; // IPv4, IPv6, ARP, etc.
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    union {
        struct { // IPv4 specific
            uint8_t ttl;
            uint16_t id;
            uint16_t total_length;
            uint8_t header_length;
            uint8_t flags;
            uint8_t protocol;
        } ipv4;
        struct { // IPv6 specific
            uint8_t hop_limit;
            uint8_t traffic_class;
            uint32_t flow_label;
            uint16_t payload_length;
            uint8_t next_header;
        } ipv6;
        struct { // ARP specific
            uint16_t hw_type;
            uint16_t proto_type;
            uint8_t hw_len;
            uint8_t proto_len;
            uint16_t operation;
            uint8_t sender_mac[6];
            uint8_t sender_ip[4];
            uint8_t target_mac[6];
            uint8_t target_ip[4];
        } arp;
    } l3_data;
    
    // Layer 4 (TCP/UDP)
    int l4_protocol;
    uint16_t src_port;
    uint16_t dst_port;
    union {
        struct { // TCP specific
            uint32_t seq_num;
            uint32_t ack_num;
            uint8_t flags;
            uint16_t window;
            uint16_t checksum;
            uint8_t header_length;
        } tcp;
        struct { // UDP specific
            uint16_t length;
            uint16_t checksum;
        } udp;
    } l4_data;
    
    // Layer 7 (Payload)
    int app_protocol; // HTTP, HTTPS, DNS, etc.
    const uint8_t *payload;
    uint32_t payload_length;
    
    // Raw packet data
    const uint8_t *raw_packet;
    uint32_t raw_length;
} parsed_packet_t;

// Protocol identifiers
enum {
    PROTO_UNKNOWN = 0,
    PROTO_IPv4,
    PROTO_IPv6,
    PROTO_ARP,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_HTTP,
    PROTO_HTTPS,
    PROTO_DNS
};

// Parse a packet and fill the parsed_packet_t structure
void parse_packet(const struct pcap_pkthdr *header, const u_char *packet, parsed_packet_t *parsed);

// Layer-specific parsing functions
void parse_ethernet(const u_char *packet, parsed_packet_t *parsed);
void parse_ipv4(const u_char *packet, int offset, parsed_packet_t *parsed);
void parse_ipv6(const u_char *packet, int offset, parsed_packet_t *parsed);
void parse_arp(const u_char *packet, int offset, parsed_packet_t *parsed);
void parse_tcp(const u_char *packet, int offset, parsed_packet_t *parsed);
void parse_udp(const u_char *packet, int offset, parsed_packet_t *parsed);
void parse_payload(const u_char *packet, int offset, parsed_packet_t *parsed);

#endif // PACKET_PARSER_H

