/*
 * Storage Module
 * Handles packet storage and session management
 */

#ifndef STORAGE_H
#define STORAGE_H

#include "packet_parser.h"
#include <stdint.h>

// Storage structure for packet session
typedef struct {
    parsed_packet_t *packets;
    uint32_t count;
    uint32_t capacity;
} packet_session_t;

// Initialize storage for a new session
void storage_init_session(void);

// Store a packet in the current session
int storage_add_packet(const parsed_packet_t *packet);

// Get the number of stored packets
uint32_t storage_get_count(void);

// Retrieve a packet by index
parsed_packet_t* storage_get_packet(uint32_t index);

// Clear the current session and free memory
void storage_clear_session(void);

// Check if a session exists
int storage_has_session(void);

#endif // STORAGE_H

