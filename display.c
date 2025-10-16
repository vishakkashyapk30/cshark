/*
 * Display Module Implementation
 */

#include "display.h"
#include <stdio.h>
#include <ctype.h>

void display_banner(void) {
    printf("\n[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");
    printf("[C-Shark] Searching for available interfaces... Found!\n");
}

void display_main_menu(const char *selected_interface) {
    printf("\n[C-Shark] Interface '%s' selected. What's next?\n", selected_interface);
    printf("\n1. Start Sniffing (All Packets)\n");
    printf("2. Start Sniffing (With Filters)\n");
    printf("3. Inspect Last Session <-- To be implemented later\n");
    printf("4. Exit C-Shark\n");
    printf("\nEnter your choice (1-4): ");
    fflush(stdout);
}

void display_packet_live(const parsed_packet_t *packet) {
    // Display packet header
    printf("\n-----------------------------------------\n");
    printf("Packet #%u | Timestamp: %ld.%06ld | Length: %u bytes\n",
           packet->id,
           packet->timestamp.tv_sec,
           packet->timestamp.tv_usec,
           packet->length);
    
    // Display layer-by-layer information
    display_layer2(packet);
    
    if (packet->l3_protocol != PROTO_UNKNOWN) {
        display_layer3(packet);
    }
    
    if (packet->l4_protocol != PROTO_UNKNOWN) {
        display_layer4(packet);
    }
    
    if (packet->l4_protocol == PROTO_TCP || packet->l4_protocol == PROTO_UDP) {
        display_layer7(packet);
    }
    
    fflush(stdout);
}

void display_packet_summary(const parsed_packet_t *packet) {
    // Implementation for Phase 5
    printf("Packet #%u | %ld.%06ld | %u bytes\n",
           packet->id,
           packet->timestamp.tv_sec,
           packet->timestamp.tv_usec,
           packet->length);
}

void display_packet_detailed(const parsed_packet_t *packet) {
    // Implementation for Phase 5
    printf("\n========================================\n");
    printf("DETAILED PACKET INSPECTION\n");
    printf("========================================\n");
    display_packet_live(packet);
}

void display_hex_dump(const uint8_t *data, uint32_t length, int max_bytes) {
    int bytes_to_show = (max_bytes > 0 && length > (uint32_t)max_bytes) ? max_bytes : (int)length;
    
    for (int i = 0; i < bytes_to_show; i += 16) {
        // Print hex values
        for (int j = 0; j < 16; j++) {
            if (i + j < bytes_to_show) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");
            }
        }
        
        // Print ASCII representation
        printf(" ");
        for (int j = 0; j < 16 && i + j < bytes_to_show; j++) {
            unsigned char c = data[i + j];
            printf("%c", isprint(c) ? c : '.');
        }
        printf("\n");
    }
}

void display_layer2(const parsed_packet_t *packet) {
    printf("L2 (Ethernet): Dst MAC: ");
    display_mac_address(packet->dst_mac);
    printf(" | Src MAC: ");
    display_mac_address(packet->src_mac);
    printf(" | EtherType: ");
    
    switch (packet->ethertype) {
        case 0x0800:
            printf("IPv4 (0x%04X)\n", packet->ethertype);
            break;
        case 0x86DD:
            printf("IPv6 (0x%04X)\n", packet->ethertype);
            break;
        case 0x0806:
            printf("ARP (0x%04X)\n", packet->ethertype);
            break;
        default:
            printf("Unknown (0x%04X)\n", packet->ethertype);
            break;
    }
}

void display_layer3(const parsed_packet_t *packet) {
    if (packet->l3_protocol == PROTO_IPv4) {
        // Display IPv4 information
        printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: ",
               packet->src_ip, packet->dst_ip);
        
        if (packet->l3_data.ipv4.protocol == IPPROTO_TCP) {
            printf("TCP (%d)", packet->l3_data.ipv4.protocol);
        } else if (packet->l3_data.ipv4.protocol == IPPROTO_UDP) {
            printf("UDP (%d)", packet->l3_data.ipv4.protocol);
        } else if (packet->l3_data.ipv4.protocol == IPPROTO_ICMP) {
            printf("ICMP (%d)", packet->l3_data.ipv4.protocol);
        } else {
            printf("Unknown (%d)", packet->l3_data.ipv4.protocol);
        }
        
        printf(" | TTL: %u\n", packet->l3_data.ipv4.ttl);
        printf("   ID: 0x%04X | Total Length: %u | Header Length: %u bytes",
               packet->l3_data.ipv4.id,
               packet->l3_data.ipv4.total_length,
               packet->l3_data.ipv4.header_length);
        
        // Display flags if any
        if (packet->l3_data.ipv4.flags) {
            printf(" | Flags: ");
            if (packet->l3_data.ipv4.flags & 0x02) printf("DF ");
            if (packet->l3_data.ipv4.flags & 0x01) printf("MF ");
        }
        printf("\n");
        
    } else if (packet->l3_protocol == PROTO_IPv6) {
        // Display IPv6 information
        printf("L3 (IPv6): Src IP: %s | Dst IP: %s\n",
               packet->src_ip, packet->dst_ip);
        printf("   Next Header: ");
        
        if (packet->l3_data.ipv6.next_header == IPPROTO_TCP) {
            printf("TCP (%d)", packet->l3_data.ipv6.next_header);
        } else if (packet->l3_data.ipv6.next_header == IPPROTO_UDP) {
            printf("UDP (%d)", packet->l3_data.ipv6.next_header);
        } else {
            printf("Unknown (%d)", packet->l3_data.ipv6.next_header);
        }
        
        printf(" | Hop Limit: %u | Traffic Class: %u | Flow Label: 0x%05X | Payload Length: %u\n",
               packet->l3_data.ipv6.hop_limit,
               packet->l3_data.ipv6.traffic_class,
               packet->l3_data.ipv6.flow_label,
               packet->l3_data.ipv6.payload_length);
        
    } else if (packet->l3_protocol == PROTO_ARP) {
        // Display ARP information
        printf("L3 (ARP): Operation: ");
        
        if (packet->l3_data.arp.operation == 1) {
            printf("Request (1)");
        } else if (packet->l3_data.arp.operation == 2) {
            printf("Reply (2)");
        } else {
            printf("Unknown (%u)", packet->l3_data.arp.operation);
        }
        
        printf(" | Sender IP: %s | Target IP: %s\n", packet->src_ip, packet->dst_ip);
        printf("   Sender MAC: ");
        display_mac_address(packet->l3_data.arp.sender_mac);
        printf(" | Target MAC: ");
        display_mac_address(packet->l3_data.arp.target_mac);
        printf("\n   HW Type: %u | Proto Type: 0x%04X | HW Len: %u | Proto Len: %u\n",
               packet->l3_data.arp.hw_type,
               packet->l3_data.arp.proto_type,
               packet->l3_data.arp.hw_len,
               packet->l3_data.arp.proto_len);
    }
}

void display_layer4(const parsed_packet_t *packet) {
    if (packet->l4_protocol == PROTO_TCP) {
        // Display TCP information
        const char *src_service = get_port_service(packet->src_port);
        const char *dst_service = get_port_service(packet->dst_port);
        
        printf("L4 (TCP): Src Port: %u", packet->src_port);
        if (src_service[0] != '\0') {
            printf(" (%s)", src_service);
        }
        printf(" | Dst Port: %u", packet->dst_port);
        if (dst_service[0] != '\0') {
            printf(" (%s)", dst_service);
        }
        
        printf(" | Seq: %u | Ack: %u | Flags: [",
               packet->l4_data.tcp.seq_num,
               packet->l4_data.tcp.ack_num);
        
        // Display TCP flags
        int first_flag = 1;
        if (packet->l4_data.tcp.flags & 0x02) { // SYN
            if (!first_flag) printf(",");
            printf("SYN");
            first_flag = 0;
        }
        if (packet->l4_data.tcp.flags & 0x10) { // ACK
            if (!first_flag) printf(",");
            printf("ACK");
            first_flag = 0;
        }
        if (packet->l4_data.tcp.flags & 0x08) { // PSH
            if (!first_flag) printf(",");
            printf("PSH");
            first_flag = 0;
        }
        if (packet->l4_data.tcp.flags & 0x01) { // FIN
            if (!first_flag) printf(",");
            printf("FIN");
            first_flag = 0;
        }
        if (packet->l4_data.tcp.flags & 0x04) { // RST
            if (!first_flag) printf(",");
            printf("RST");
            first_flag = 0;
        }
        if (packet->l4_data.tcp.flags & 0x20) { // URG
            if (!first_flag) printf(",");
            printf("URG");
        }
        
        printf("]\n");
        printf("   Window: %u | Checksum: 0x%04X | Header Length: %u bytes\n",
               packet->l4_data.tcp.window,
               packet->l4_data.tcp.checksum,
               packet->l4_data.tcp.header_length);
        
    } else if (packet->l4_protocol == PROTO_UDP) {
        // Display UDP information
        const char *src_service = get_port_service(packet->src_port);
        const char *dst_service = get_port_service(packet->dst_port);
        
        printf("L4 (UDP): Src Port: %u", packet->src_port);
        if (src_service[0] != '\0') {
            printf(" (%s)", src_service);
        }
        printf(" | Dst Port: %u", packet->dst_port);
        if (dst_service[0] != '\0') {
            printf(" (%s)", dst_service);
        }
        
        printf(" | Length: %u | Checksum: 0x%04X\n",
               packet->l4_data.udp.length,
               packet->l4_data.udp.checksum);
    }
}

void display_layer7(const parsed_packet_t *packet) {
    if (packet->payload_length == 0) {
        return; // No payload to display
    }
    
    printf("L7 (Payload): Identified as ");
    
    if (packet->app_protocol == PROTO_HTTP) {
        printf("HTTP on port %u", 
               (packet->dst_port == 80 || packet->src_port == 80) ? 80 : packet->dst_port);
    } else if (packet->app_protocol == PROTO_HTTPS) {
        printf("HTTPS/TLS on port %u", 
               (packet->dst_port == 443 || packet->src_port == 443) ? 443 : packet->dst_port);
    } else if (packet->app_protocol == PROTO_DNS) {
        printf("DNS on port %u", 
               (packet->dst_port == 53 || packet->src_port == 53) ? 53 : packet->dst_port);
    } else {
        printf("Unknown");
    }
    
    printf(" - %u bytes\n", packet->payload_length);
    
    // Display hex dump of first 64 bytes
    if (packet->payload_length > 0) {
        uint32_t bytes_to_show = packet->payload_length < 64 ? packet->payload_length : 64;
        printf("Data (first %u bytes):\n", bytes_to_show);
        
        for (uint32_t i = 0; i < bytes_to_show; i += 16) {
            // Print hex values
            for (uint32_t j = 0; j < 16 && (i + j) < bytes_to_show; j++) {
                printf("%02X ", packet->payload[i + j]);
            }
            
            // Pad if less than 16 bytes
            for (uint32_t j = bytes_to_show - i; j < 16 && i + j >= bytes_to_show; j++) {
                printf("   ");
            }
            
            // Print ASCII representation
            printf(" ");
            for (uint32_t j = 0; j < 16 && (i + j) < bytes_to_show; j++) {
                unsigned char c = packet->payload[i + j];
                printf("%c", isprint(c) ? c : '.');
            }
            printf("\n");
        }
    }
}

void display_mac_address(const uint8_t *mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

const char* get_protocol_name(int protocol) {
    switch (protocol) {
        case PROTO_IPv4: return "IPv4";
        case PROTO_IPv6: return "IPv6";
        case PROTO_ARP: return "ARP";
        case PROTO_TCP: return "TCP";
        case PROTO_UDP: return "UDP";
        case PROTO_ICMP: return "ICMP";
        case PROTO_HTTP: return "HTTP";
        case PROTO_HTTPS: return "HTTPS";
        case PROTO_DNS: return "DNS";
        default: return "Unknown";
    }
}

const char* get_port_service(uint16_t port) {
    switch (port) {
        case 20: return "FTP-DATA";
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "TELNET";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 3306: return "MySQL";
        case 5432: return "PostgreSQL";
        case 8080: return "HTTP-ALT";
        default: return "";
    }
}

