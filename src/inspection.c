/*
 * Inspection Module Implementation
 */

#include "inspection.h"
#include "storage.h"
#include "display.h"
#include "utils.h"
#include "detect.h"
#include "export.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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

void view_security_alerts(void) {
    uint32_t count = detect_get_alert_count();

    printf("\n========================================\n");
    printf("SECURITY ALERTS (this session)\n");
    printf("========================================\n");

    if (count == 0) {
        printf("No alerts raised. No port-scan or ARP-spoof signatures detected.\n");
        printf("========================================\n");
        return;
    }

    printf("Total alerts: %u\n", count);
    printf("----------------------------------------\n");
    printf("%-10s | %-12s | %s\n", "Time", "Type", "Details");
    printf("----------------------------------------\n");

    for (uint32_t i = 0; i < count; i++) {
        const alert_record_t *alert = detect_get_alert(i);
        if (alert == NULL) continue;

        char time_str[16];
        struct tm *tm_info = localtime(&alert->timestamp);
        strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

        printf("%-10s | %-12s | %s\n", time_str, alert->type, alert->details);
    }

    printf("========================================\n");
}

void export_session_menu(void) {
    if (!storage_has_session()) {
        printf("\n[C-Shark] No capture session available to export.\n");
        printf("[C-Shark] Please capture some packets first (Option 1 or 2).\n");
        return;
    }

    printf("\n[C-Shark] Export Session Data:\n");
    printf("=================================\n");
    printf("1. Export packet flows to CSV (Azure NSG flow-log style)\n");
    printf("2. Export security alerts to CSV\n");
    printf("3. Export full session to a .pcap file (opens in Wireshark)\n");
    printf("4. Back to Main Menu\n");
    printf("\nEnter your choice (1-4): ");
    fflush(stdout);

    int choice = get_user_choice(1, 4);
    if (choice == -1 || choice == 4) {
        printf("[C-Shark] Returning to main menu.\n");
        return;
    }

    const char *default_name = (choice == 1) ? "session_flows.csv" :
                                (choice == 2) ? "session_alerts.csv" : "session.pcap";

    char path[256];
    printf("Enter output file path [default: %s]: ", default_name);
    fflush(stdout);

    if (fgets(path, sizeof(path), stdin) == NULL) {
        printf("[C-Shark] No input received. Export cancelled.\n");
        return;
    }

    // Strip trailing newline
    size_t len = strlen(path);
    if (len > 0 && path[len - 1] == '\n') {
        path[len - 1] = '\0';
    }
    if (path[0] == '\0') {
        strncpy(path, default_name, sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
    }

    switch (choice) {
        case 1: export_session_csv(path); break;
        case 2: export_alerts_csv(path); break;
        case 3: export_session_pcap(path); break;
        default: break;
    }
}

// LLM Generated Code Ends Here