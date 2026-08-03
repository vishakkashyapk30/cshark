/*
 * Display Module
 * Handles formatted output of packet information
 */

#ifndef DISPLAY_H
#define DISPLAY_H

#include "packet_parser.h"

// Display banner and welcome message
void display_banner(void);

// Display main menu
void display_main_menu(const char *selected_interface);

// Display a packet in real-time (live capture)
void display_packet_live(const parsed_packet_t *packet);

// Display packet summary (for inspection list)
void display_packet_summary(const parsed_packet_t *packet);

// Display detailed packet inspection
void display_packet_detailed(const parsed_packet_t *packet);

// Display hex dump of data
void display_hex_dump(const uint8_t *data, uint32_t length, int max_bytes);

// Helper functions for specific layers
void display_layer2(const parsed_packet_t *packet);
void display_layer3(const parsed_packet_t *packet);
void display_layer4(const parsed_packet_t *packet);
void display_layer7(const parsed_packet_t *packet);

// Utility display functions
void display_mac_address(const uint8_t *mac);
const char* get_protocol_name(int protocol);
const char* get_port_service(uint16_t port);

#endif // DISPLAY_H

