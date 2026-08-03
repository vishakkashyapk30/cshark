/*
 * Detection Module
 * Real-time security heuristics: port-scan detection and ARP-spoof detection.
 * Both detectors are hand-rolled hash tables (no external deps) that observe
 * every parsed packet and raise alerts that are both printed live and kept
 * in an in-memory log for post-capture review (see inspection.c).
 */

#ifndef DETECT_H
#define DETECT_H

#include "packet_parser.h"
#include <stdint.h>
#include <time.h>

// A single raised alert, kept for the "View Security Alerts" inspection menu
typedef struct {
    time_t timestamp;
    char type[32];      // e.g. "PORT_SCAN", "ARP_SPOOF"
    char details[256];
} alert_record_t;

// Initialize detection state for a new capture session (call once before capture starts)
void detect_init(void);

// Feed a TCP/UDP packet to the port-scan heuristic
// (15+ distinct destination ports from the same source IP within a 5s window)
void detect_port_scan_observe(const parsed_packet_t *pkt);

// Feed an ARP packet to the ARP-spoof heuristic
// (an IP's bound MAC changing between ARP replies)
void detect_arp_spoof_observe(const parsed_packet_t *pkt);

// Print a clearly distinguishable alert line to stdout and append it to the alert log
void detect_print_alert(const char *type, const char *details);

// Access the alert log recorded during the current/last session
uint32_t detect_get_alert_count(void);
const alert_record_t *detect_get_alert(uint32_t index);

// Free all hash-table memory allocated during the session
void detect_cleanup(void);

#endif // DETECT_H
