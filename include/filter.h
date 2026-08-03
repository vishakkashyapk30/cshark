/*
 * Filter Module
 * Handles packet filtering logic
 */

#ifndef FILTER_H
#define FILTER_H

#include "packet_parser.h"

// Filter types
enum {
    FILTER_NONE = 0,
    FILTER_HTTP,
    FILTER_HTTPS,
    FILTER_DNS,
    FILTER_ARP,
    FILTER_TCP,
    FILTER_UDP
};

// Display filter menu and get user selection
int select_filter(void);

// Generate pcap filter expression based on filter type
char* generate_filter_expression(int filter_type);

// Get human-readable filter name
const char* get_filter_name(int filter_type);

// Check if a packet matches the filter (for post-capture filtering if needed)
int packet_matches_filter(const parsed_packet_t *packet, int filter_type);

#endif // FILTER_H

