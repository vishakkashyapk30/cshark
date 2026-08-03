/*
 * Packet Capture Module Implementation
 */
#include "cshark.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// LLM Generated Code Starts Here
// Global packet counter
static uint32_t packet_id = 0;

pcap_t* init_capture(char *device, char *filter_exp) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net, mask;
    
    // Get network address and mask
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "[C-Shark] Warning: Can't get netmask for device %s: %s\n", device, errbuf);
        net = 0;
        mask = 0;
    }
    
    // Open the device for capturing
    handle = pcap_open_live(device, SNAP_LEN, PROMISC_MODE, TIMEOUT_MS, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[C-Shark] Error opening device %s: %s\n", device, errbuf);
        return NULL;
    }
    
    // Compile and apply the filter if provided
    if (filter_exp != NULL) {
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "[C-Shark] Error compiling filter %s: %s\n", filter_exp, pcap_geterr(handle));
            pcap_close(handle);
            return NULL;
        }
        
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "[C-Shark] Error setting filter %s: %s\n", filter_exp, pcap_geterr(handle));
            pcap_freecode(&fp);
            pcap_close(handle);
            return NULL;
        }
        
        pcap_freecode(&fp);
    }
    
    return handle;
}

void start_sniffing_all(char *device) {
    pcap_t *handle;
    
    printf("\n[C-Shark] Starting packet capture on %s...\n", device);
    printf("[C-Shark] Press Ctrl+C to stop capture and return to menu.\n");
    printf("[C-Shark] Press Ctrl+D to exit C-Shark.\n\n");
    
    // Initialize storage for new session
    storage_init_session();
    
    // Initialize security detection state (port-scan + ARP-spoof heuristics)
    detect_init();
    
    // Reset packet counter for new session
    packet_id = 0;
    
    // Reset interrupt flag
    capture_interrupted = 0;
    
    // Initialize capture
    handle = init_capture(device, NULL);
    if (handle == NULL) {
        return;
    }
    
    // Start capturing packets
    while (!capture_interrupted) {
        struct pcap_pkthdr header;
        const u_char *packet;
        
        packet = pcap_next(handle, &header);
        if (packet != NULL) {
            packet_handler(NULL, &header, packet);
        }
    }
    
    // Clean up
    stop_capture(handle);
    
    // Tear down detection working state (alert log survives for inspection)
    detect_cleanup();
    
    // Display session summary
    printf("\n[C-Shark] Session complete. Captured %u packets (stored for inspection).\n", 
           storage_get_count());
    if (detect_get_alert_count() > 0) {
        printf("[C-Shark] %u security alert(s) raised - see 'View Security Alerts' in the menu.\n",
               detect_get_alert_count());
    }
    
    // Reset interrupt flag for next session
    capture_interrupted = 0;
}

void start_sniffing_filtered(char *device, char *filter) {
    pcap_t *handle;
    
    printf("\n[C-Shark] Starting filtered packet capture on %s...\n", device);
    printf("[C-Shark] Filter: %s\n", filter);
    printf("[C-Shark] Press Ctrl+C to stop capture and return to menu.\n");
    printf("[C-Shark] Press Ctrl+D to exit C-Shark.\n\n");
    
    // Initialize storage for new session
    storage_init_session();
    
    // Initialize security detection state (port-scan + ARP-spoof heuristics)
    detect_init();
    
    // Reset packet counter for new session
    packet_id = 0;
    
    // Reset interrupt flag
    capture_interrupted = 0;
    
    // Initialize capture with filter
    handle = init_capture(device, filter);
    if (handle == NULL) {
        return;
    }
    
    // Start capturing packets
    while (!capture_interrupted) {
        struct pcap_pkthdr header;
        const u_char *packet;
        
        packet = pcap_next(handle, &header);
        if (packet != NULL) {
            packet_handler(NULL, &header, packet);
        }
    }
    
    // Clean up
    stop_capture(handle);
    
    // Tear down detection working state (alert log survives for inspection)
    detect_cleanup();
    
    // Display session summary
    printf("\n[C-Shark] Session complete. Captured %u packets (stored for inspection).\n", 
           storage_get_count());
    if (detect_get_alert_count() > 0) {
        printf("[C-Shark] %u security alert(s) raised - see 'View Security Alerts' in the menu.\n",
               detect_get_alert_count());
    }
    
    // Reset interrupt flag for next session
    capture_interrupted = 0;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args; // Suppress unused parameter warning
    
    // Increment packet ID
    packet_id++;
    
    // Create a parsed packet structure
    parsed_packet_t parsed;
    memset(&parsed, 0, sizeof(parsed_packet_t));
    
    // Set packet ID
    parsed.id = packet_id;
    
    // Parse the packet completely (all layers)
    parse_packet(header, packet, &parsed);
    
    // Run security heuristics on the parsed packet (cheap, O(1) amortized per packet)
    detect_port_scan_observe(&parsed);
    detect_arp_spoof_observe(&parsed);
    
    // Display the parsed packet
    display_packet_live(&parsed);
    
    // Store the packet for later inspection
    int result = storage_add_packet(&parsed);
    if (result == -1) {
        // Storage full or error - just continue capturing without storing
        // This is silent to avoid cluttering the output during live capture
    }
}

void stop_capture(pcap_t *handle) {
    if (handle != NULL) {
        pcap_close(handle);
    }
    printf("\n[C-Shark] Capture stopped.\n");
}
// LLM Generated Code Endss Here