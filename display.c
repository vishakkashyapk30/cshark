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
    printf("2. Start Sniffing (With Filters) <-- To be implemented later\n");
    printf("3. Inspect Last Session <-- To be implemented later\n");
    printf("4. Exit C-Shark\n");
    printf("\nEnter your choice (1-4): ");
    fflush(stdout);
}

void display_packet_live(const parsed_packet_t *packet) {
    // For Phase 1, display basic packet info
    printf("\n-----------------------------------------\n");
    printf("Packet #%u | Timestamp: %ld.%06ld | Length: %u bytes\n",
           packet->id,
           packet->timestamp.tv_sec,
           packet->timestamp.tv_usec,
           packet->length);
    
    // Display first 16 bytes in hex
    printf("Raw Data (first 16 bytes): ");
    int bytes_to_show = packet->length < 16 ? packet->length : 16;
    for (int i = 0; i < bytes_to_show; i++) {
        printf("%02X ", packet->raw_packet[i]);
    }
    printf("\n");
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
    // Will be implemented in Phase 2
    (void)packet;
}

void display_layer3(const parsed_packet_t *packet) {
    // Will be implemented in Phase 2
    (void)packet;
}

void display_layer4(const parsed_packet_t *packet) {
    // Will be implemented in Phase 2
    (void)packet;
}

void display_layer7(const parsed_packet_t *packet) {
    // Will be implemented in Phase 2
    (void)packet;
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

