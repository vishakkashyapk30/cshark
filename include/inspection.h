/*
 * Inspection Module
 * Handles in-depth packet inspection and analysis
 */

#ifndef INSPECTION_H
#define INSPECTION_H

#include "packet_parser.h"

// Main inspection interface - lists all packets and allows selection
void inspect_session(void);

// Display list of all packets in the session
void list_session_packets(void);

// Perform detailed inspection of a specific packet
void inspect_packet_detailed(uint32_t packet_id);

// List all security alerts (port-scan/ARP-spoof) raised during the last session
void view_security_alerts(void);

// Interactive prompt to export the current session (CSV flows, CSV alerts, or PCAP)
void export_session_menu(void);

#endif // INSPECTION_H

