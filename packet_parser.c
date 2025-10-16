/*
 * Packet Parser Module Implementation
 */

#include "packet_parser.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if_arp.h>

void parse_packet(const struct pcap_pkthdr *header, const u_char *packet, parsed_packet_t *parsed) {
    // Store basic packet info
    parsed->timestamp = header->ts;
    parsed->length = header->len;
    parsed->raw_packet = packet;
    parsed->raw_length = header->len;
    
    // Parse Ethernet header (Layer 2)
    parse_ethernet(packet, parsed);
    
    // Parse Network layer (Layer 3) based on EtherType
    int l3_offset = 14; // Ethernet header is 14 bytes
    
    if (parsed->ethertype == 0x0800) { // IPv4
        parsed->l3_protocol = PROTO_IPv4;
        parse_ipv4(packet, l3_offset, parsed);
    } else if (parsed->ethertype == 0x86DD) { // IPv6
        parsed->l3_protocol = PROTO_IPv6;
        parse_ipv6(packet, l3_offset, parsed);
    } else if (parsed->ethertype == 0x0806) { // ARP
        parsed->l3_protocol = PROTO_ARP;
        parse_arp(packet, l3_offset, parsed);
    } else {
        parsed->l3_protocol = PROTO_UNKNOWN;
    }
}

void parse_ethernet(const u_char *packet, parsed_packet_t *parsed) {
    struct ether_header *eth = (struct ether_header *)packet;
    
    // Copy MAC addresses
    memcpy(parsed->dst_mac, eth->ether_dhost, 6);
    memcpy(parsed->src_mac, eth->ether_shost, 6);
    
    // Get EtherType (convert from network to host byte order)
    parsed->ethertype = ntohs(eth->ether_type);
}

void parse_ipv4(const u_char *packet, int offset, parsed_packet_t *parsed) {
    struct ip *iph = (struct ip *)(packet + offset);
    
    // Convert IP addresses to string format
    inet_ntop(AF_INET, &(iph->ip_src), parsed->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->ip_dst), parsed->dst_ip, INET_ADDRSTRLEN);
    
    // Store IPv4 specific fields
    parsed->l3_data.ipv4.ttl = iph->ip_ttl;
    parsed->l3_data.ipv4.id = ntohs(iph->ip_id);
    parsed->l3_data.ipv4.total_length = ntohs(iph->ip_len);
    parsed->l3_data.ipv4.header_length = iph->ip_hl * 4; // IHL is in 32-bit words
    parsed->l3_data.ipv4.flags = ntohs(iph->ip_off) >> 13; // Top 3 bits are flags
    parsed->l3_data.ipv4.protocol = iph->ip_p;
    
    // Parse transport layer based on protocol
    int l4_offset = offset + parsed->l3_data.ipv4.header_length;
    
    if (iph->ip_p == IPPROTO_TCP) {
        parsed->l4_protocol = PROTO_TCP;
        parse_tcp(packet, l4_offset, parsed);
    } else if (iph->ip_p == IPPROTO_UDP) {
        parsed->l4_protocol = PROTO_UDP;
        parse_udp(packet, l4_offset, parsed);
    } else {
        parsed->l4_protocol = PROTO_UNKNOWN;
    }
}

void parse_ipv6(const u_char *packet, int offset, parsed_packet_t *parsed) {
    struct ip6_hdr *ip6h = (struct ip6_hdr *)(packet + offset);
    
    // Convert IPv6 addresses to string format
    inet_ntop(AF_INET6, &(ip6h->ip6_src), parsed->src_ip, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6h->ip6_dst), parsed->dst_ip, INET6_ADDRSTRLEN);
    
    // Store IPv6 specific fields
    uint32_t flow_label = ntohl(ip6h->ip6_flow);
    parsed->l3_data.ipv6.traffic_class = (flow_label >> 20) & 0xFF;
    parsed->l3_data.ipv6.flow_label = flow_label & 0xFFFFF;
    parsed->l3_data.ipv6.payload_length = ntohs(ip6h->ip6_plen);
    parsed->l3_data.ipv6.next_header = ip6h->ip6_nxt;
    parsed->l3_data.ipv6.hop_limit = ip6h->ip6_hlim;
    
    // Parse transport layer based on next header
    int l4_offset = offset + 40; // IPv6 header is always 40 bytes
    
    if (ip6h->ip6_nxt == IPPROTO_TCP) {
        parsed->l4_protocol = PROTO_TCP;
        parse_tcp(packet, l4_offset, parsed);
    } else if (ip6h->ip6_nxt == IPPROTO_UDP) {
        parsed->l4_protocol = PROTO_UDP;
        parse_udp(packet, l4_offset, parsed);
    } else {
        parsed->l4_protocol = PROTO_UNKNOWN;
    }
}

void parse_arp(const u_char *packet, int offset, parsed_packet_t *parsed) {
    struct arphdr *arph = (struct arphdr *)(packet + offset);
    
    // Store ARP specific fields
    parsed->l3_data.arp.hw_type = ntohs(arph->ar_hrd);
    parsed->l3_data.arp.proto_type = ntohs(arph->ar_pro);
    parsed->l3_data.arp.hw_len = arph->ar_hln;
    parsed->l3_data.arp.proto_len = arph->ar_pln;
    parsed->l3_data.arp.operation = ntohs(arph->ar_op);
    
    // Parse ARP payload (sender/target MAC and IP)
    const u_char *arp_data = packet + offset + sizeof(struct arphdr);
    
    // Sender MAC (6 bytes)
    memcpy(parsed->l3_data.arp.sender_mac, arp_data, 6);
    arp_data += 6;
    
    // Sender IP (4 bytes)
    memcpy(parsed->l3_data.arp.sender_ip, arp_data, 4);
    arp_data += 4;
    
    // Target MAC (6 bytes)
    memcpy(parsed->l3_data.arp.target_mac, arp_data, 6);
    arp_data += 6;
    
    // Target IP (4 bytes)
    memcpy(parsed->l3_data.arp.target_ip, arp_data, 4);
    
    // Convert IPs to string format for display
    struct in_addr sender_addr, target_addr;
    memcpy(&sender_addr, parsed->l3_data.arp.sender_ip, 4);
    memcpy(&target_addr, parsed->l3_data.arp.target_ip, 4);
    inet_ntop(AF_INET, &sender_addr, parsed->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &target_addr, parsed->dst_ip, INET_ADDRSTRLEN);
}

void parse_tcp(const u_char *packet, int offset, parsed_packet_t *parsed) {
    struct tcphdr *tcph = (struct tcphdr *)(packet + offset);
    
    // Store TCP specific fields
    parsed->src_port = ntohs(tcph->th_sport);
    parsed->dst_port = ntohs(tcph->th_dport);
    parsed->l4_data.tcp.seq_num = ntohl(tcph->th_seq);
    parsed->l4_data.tcp.ack_num = ntohl(tcph->th_ack);
    parsed->l4_data.tcp.flags = tcph->th_flags;
    parsed->l4_data.tcp.window = ntohs(tcph->th_win);
    parsed->l4_data.tcp.checksum = ntohs(tcph->th_sum);
    parsed->l4_data.tcp.header_length = tcph->th_off * 4; // Data offset is in 32-bit words
    
    // Parse payload
    int payload_offset = offset + parsed->l4_data.tcp.header_length;
    parse_payload(packet, payload_offset, parsed);
}

void parse_udp(const u_char *packet, int offset, parsed_packet_t *parsed) {
    struct udphdr *udph = (struct udphdr *)(packet + offset);
    
    // Store UDP specific fields
    parsed->src_port = ntohs(udph->uh_sport);
    parsed->dst_port = ntohs(udph->uh_dport);
    parsed->l4_data.udp.length = ntohs(udph->uh_ulen);
    parsed->l4_data.udp.checksum = ntohs(udph->uh_sum);
    
    // Parse payload
    int payload_offset = offset + 8; // UDP header is always 8 bytes
    parse_payload(packet, payload_offset, parsed);
}

void parse_payload(const u_char *packet, int offset, parsed_packet_t *parsed) {
    // Calculate payload length
    if (offset >= (int)parsed->raw_length) {
        parsed->payload_length = 0;
        parsed->payload = NULL;
        return;
    }
    
    parsed->payload_length = parsed->raw_length - offset;
    parsed->payload = packet + offset;
    
    // Identify application protocol based on port numbers
    if (parsed->l4_protocol == PROTO_TCP || parsed->l4_protocol == PROTO_UDP) {
        if (parsed->src_port == 80 || parsed->dst_port == 80) {
            parsed->app_protocol = PROTO_HTTP;
        } else if (parsed->src_port == 443 || parsed->dst_port == 443) {
            parsed->app_protocol = PROTO_HTTPS;
        } else if (parsed->src_port == 53 || parsed->dst_port == 53) {
            parsed->app_protocol = PROTO_DNS;
        } else {
            parsed->app_protocol = PROTO_UNKNOWN;
        }
    } else {
        parsed->app_protocol = PROTO_UNKNOWN;
    }
}

