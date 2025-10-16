/*
 * Packet Capture Module
 * Handles live packet capture and control flow
 */

#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

// Capture context structure
typedef struct {
    pcap_t *handle;
    char *device;
    char *filter_exp;
    int packet_count;
} capture_context_t;

// Initialize capture session
pcap_t* init_capture(char *device, char *filter_exp);

// Start capturing packets (all packets)
void start_sniffing_all(char *device);

// Start capturing with filters
void start_sniffing_filtered(char *device, char *filter);

// Packet handler callback
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// Stop capture gracefully
void stop_capture(pcap_t *handle);

#endif // CAPTURE_H

