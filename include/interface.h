/*
 * Interface Discovery and Selection Module
 * Handles network interface enumeration and user selection
 */

#ifndef INTERFACE_H
#define INTERFACE_H

#include <pcap.h>

// Function to discover and list all available network interfaces
// Returns the number of interfaces found
int discover_interfaces(pcap_if_t **alldevs);

// Function to display interfaces to the user
void display_interfaces(pcap_if_t *alldevs, int count);

// Function to get user's interface selection
// Returns the selected device name
char* select_interface(pcap_if_t *alldevs, int count);

// Free the device list
void free_interfaces(pcap_if_t *alldevs);

#endif // INTERFACE_H

