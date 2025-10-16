/*
 * Packet Capture Module Implementation
 */

#include "cshark.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    
    // Reset interrupt flag for next session
    capture_interrupted = 0;
}

void start_sniffing_filtered(char *device, char *filter) {
    pcap_t *handle;
    
    printf("\n[C-Shark] Starting filtered packet capture on %s...\n", device);
    printf("[C-Shark] Filter: %s\n", filter);
    printf("[C-Shark] Press Ctrl+C to stop capture and return to menu.\n");
    printf("[C-Shark] Press Ctrl+D to exit C-Shark.\n\n");
    
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
    
    // Reset interrupt flag for next session
    capture_interrupted = 0;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    (void)args; // Suppress unused parameter warning
    
    // Increment packet ID
    packet_id++;
    
    // Create a parsed packet structure for display
    parsed_packet_t parsed;
    memset(&parsed, 0, sizeof(parsed_packet_t));
    
    parsed.id = packet_id;
    parsed.timestamp = header->ts;
    parsed.length = header->len;
    parsed.raw_packet = packet;
    parsed.raw_length = header->len;
    
    // For Phase 1, just display basic info
    display_packet_live(&parsed);
}

void stop_capture(pcap_t *handle) {
    if (handle != NULL) {
        pcap_close(handle);
    }
    printf("\n[C-Shark] Capture stopped.\n");
}

