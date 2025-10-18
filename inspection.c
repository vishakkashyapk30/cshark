/*
 * Inspection Module Implementation
 */

#include "inspection.h"
#include "storage.h"
#include "display.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>

// LLM Generated Code Starts Here

void inspect_session(void) {
    if (!storage_has_session()) {
        printf("\n[C-Shark] No capture session available.\n");
        printf("[C-Shark] Please capture some packets first (Option 1 or 2).\n");
        return;
    }
    
    while (1) {
        // Display list of packets
        list_session_packets();
        
        // Get user input
        printf("\nEnter Packet ID to inspect (or 0 to return to main menu): ");
        fflush(stdout);
        
        int packet_id;
        if (scanf("%d", &packet_id) != 1) {
            // Handle Ctrl+D or invalid input
            if (feof(stdin)) {
                printf("\n[C-Shark] Exiting...\n");
                exit(0);
            }
            clear_input_buffer();
            printf("[C-Shark] Invalid input. Please enter a valid packet ID.\n");
            continue;
        }
        clear_input_buffer();
        
        if (packet_id == 0) {
            printf("[C-Shark] Returning to main menu...\n");
            break;
        }
        
        // Validate packet ID
        if (packet_id < 1 || packet_id > (int)storage_get_count()) {
            printf("[C-Shark] Invalid Packet ID. Please enter a number between 1 and %u.\n", 
                   storage_get_count());
            continue;
        }
        
        // Inspect the selected packet
        inspect_packet_detailed(packet_id);
        
        // Ask if user wants to inspect another
        printf("\n[C-Shark] Press Enter to continue...");
        getchar();
    }
}

void list_session_packets(void) {
    uint32_t count = storage_get_count();
    
    printf("\n========================================\n");
    printf("CAPTURED PACKETS SUMMARY\n");
    printf("========================================\n");
    printf("Total packets in session: %u\n", count);
    printf("----------------------------------------\n");
    printf("%-6s | %-20s | %-8s | %-15s | %-6s\n", 
           "ID", "Timestamp", "Length", "Protocol", "Info");
    printf("----------------------------------------\n");
    
    // Display first 50 packets (or all if less than 50)
    uint32_t display_count = count < 50 ? count : 50;
    
    for (uint32_t i = 0; i < display_count; i++) {
        parsed_packet_t *packet = storage_get_packet(i);
        if (packet == NULL) continue;
        
        // Format timestamp
        char timestamp[32];
        snprintf(timestamp, sizeof(timestamp), "%ld.%06ld", 
                packet->timestamp.tv_sec, packet->timestamp.tv_usec);
        
        // Determine protocol
        const char *protocol = "Unknown";
        char info[128] = "";  // Increased buffer size to accommodate IPv6 addresses
        
        if (packet->l3_protocol == PROTO_ARP) {
            protocol = "ARP";
            snprintf(info, sizeof(info), "%s", packet->src_ip);
        } else if (packet->l4_protocol == PROTO_TCP) {
            protocol = "TCP";
            snprintf(info, sizeof(info), "%s:%u -> %s:%u", 
                    packet->src_ip, packet->src_port, 
                    packet->dst_ip, packet->dst_port);
        } else if (packet->l4_protocol == PROTO_UDP) {
            protocol = "UDP";
            snprintf(info, sizeof(info), "%s:%u -> %s:%u", 
                    packet->src_ip, packet->src_port, 
                    packet->dst_ip, packet->dst_port);
        } else if (packet->l3_protocol == PROTO_IPv4) {
            protocol = "IPv4";
            snprintf(info, sizeof(info), "%s -> %s", packet->src_ip, packet->dst_ip);
        } else if (packet->l3_protocol == PROTO_IPv6) {
            protocol = "IPv6";
            snprintf(info, sizeof(info), "%s", packet->src_ip);
        }
        
        printf("%-6u | %-20s | %-8u | %-15s | %.40s\n", 
               packet->id, timestamp, packet->length, protocol, info);
    }
    
    if (count > 50) {
        printf("... and %u more packets (showing first 50)\n", count - 50);
    }
    
    printf("========================================\n");
}

void inspect_packet_detailed(uint32_t packet_id) {
    // Get packet by ID (packet IDs start from 1, array index from 0)
    parsed_packet_t *packet = storage_get_packet(packet_id - 1);
    
    if (packet == NULL) {
        printf("[C-Shark] Error: Could not retrieve packet #%u\n", packet_id);
        return;
    }
    
    // Display comprehensive packet analysis
    display_packet_detailed(packet);
}

// LLM Generated Code Ends Here