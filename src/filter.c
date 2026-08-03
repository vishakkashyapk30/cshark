/*
 * Filter Module Implementation
 */

#include "filter.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// LLM Generated Code Starts Here

int select_filter(void) {
    printf("\n[C-Shark] Select Protocol Filter:\n");
    printf("=================================\n");
    printf("1. HTTP (Port 80)\n");
    printf("2. HTTPS (Port 443)\n");
    printf("3. DNS (Port 53)\n");
    printf("4. ARP\n");
    printf("5. TCP (All TCP traffic)\n");
    printf("6. UDP (All UDP traffic)\n");
    printf("7. Back to Main Menu\n");
    printf("\nEnter your choice (1-7): ");
    fflush(stdout);
    
    int choice = get_user_choice(1, 7);
    
    if (choice == -1 || choice == 7) {
        return FILTER_NONE;
    }
    
    // Map choice to filter type
    switch (choice) {
        case 1: return FILTER_HTTP;
        case 2: return FILTER_HTTPS;
        case 3: return FILTER_DNS;
        case 4: return FILTER_ARP;
        case 5: return FILTER_TCP;
        case 6: return FILTER_UDP;
        default: return FILTER_NONE;
    }
}

char* generate_filter_expression(int filter_type) {
    char *filter = NULL;
    
    switch (filter_type) {
        case FILTER_HTTP:
            // Filter for HTTP traffic on port 80
            filter = strdup("tcp port 80");
            break;
            
        case FILTER_HTTPS:
            // Filter for HTTPS traffic on port 443
            filter = strdup("tcp port 443");
            break;
            
        case FILTER_DNS:
            // Filter for DNS traffic on port 53 (both TCP and UDP)
            filter = strdup("port 53");
            break;
            
        case FILTER_ARP:
            // Filter for ARP packets
            filter = strdup("arp");
            break;
            
        case FILTER_TCP:
            // Filter for all TCP traffic
            filter = strdup("tcp");
            break;
            
        case FILTER_UDP:
            // Filter for all UDP traffic
            filter = strdup("udp");
            break;
            
        case FILTER_NONE:
        default:
            filter = NULL;
            break;
    }
    
    return filter;
}

const char* get_filter_name(int filter_type) {
    switch (filter_type) {
        case FILTER_HTTP: return "HTTP";
        case FILTER_HTTPS: return "HTTPS";
        case FILTER_DNS: return "DNS";
        case FILTER_ARP: return "ARP";
        case FILTER_TCP: return "TCP";
        case FILTER_UDP: return "UDP";
        default: return "None";
    }
}

int packet_matches_filter(const parsed_packet_t *packet, int filter_type) {
    // This function can be used for post-capture filtering if needed
    // For now, BPF filters handle everything at capture time
    
    switch (filter_type) {
        case FILTER_HTTP:
            return (packet->l4_protocol == PROTO_TCP && 
                   (packet->src_port == 80 || packet->dst_port == 80));
            
        case FILTER_HTTPS:
            return (packet->l4_protocol == PROTO_TCP && 
                   (packet->src_port == 443 || packet->dst_port == 443));
            
        case FILTER_DNS:
            return ((packet->l4_protocol == PROTO_TCP || packet->l4_protocol == PROTO_UDP) &&
                   (packet->src_port == 53 || packet->dst_port == 53));
            
        case FILTER_ARP:
            return (packet->l3_protocol == PROTO_ARP);
            
        case FILTER_TCP:
            return (packet->l4_protocol == PROTO_TCP);
            
        case FILTER_UDP:
            return (packet->l4_protocol == PROTO_UDP);
            
        case FILTER_NONE:
        default:
            return 1; // Match all packets
    }
}

// LLM Generated Code Ends Here