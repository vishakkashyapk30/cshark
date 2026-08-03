/*
 * Storage Module Implementation
 */

#include "storage.h"
#include "cshark.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>

// LLM Generated Code Starts Here

// Global session storage
static packet_session_t current_session = {NULL, 0, 0};

void storage_init_session(void) {
    // Clear any existing session first
    storage_clear_session();
    
    // Allocate memory for new session
    current_session.packets = (parsed_packet_t *)malloc(MAX_PACKETS * sizeof(parsed_packet_t));
    
    if (current_session.packets == NULL) {
        fprintf(stderr, "[C-Shark Storage] Error: Failed to allocate memory for packet storage.\n");
        current_session.capacity = 0;
        current_session.count = 0;
        return;
    }
    
    current_session.capacity = MAX_PACKETS;
    current_session.count = 0;
    
    // Initialize all packets to zero
    memset(current_session.packets, 0, MAX_PACKETS * sizeof(parsed_packet_t));
}

int storage_add_packet(const parsed_packet_t *packet) {
    // Check if storage is initialized
    if (current_session.packets == NULL) {
        fprintf(stderr, "[C-Shark Storage] Error: Storage not initialized.\n");
        return -1;
    }
    
    // Check if we've reached capacity
    if (current_session.count >= current_session.capacity) {
        // Session is full, can't add more packets
        return -1;
    }
    
    // Deep copy the packet to avoid dangling pointers
    parsed_packet_t *stored_packet = &current_session.packets[current_session.count];
    
    // Copy basic fields
    memcpy(stored_packet, packet, sizeof(parsed_packet_t));
    
    // Allocate and copy raw packet data
    if (packet->raw_packet != NULL && packet->raw_length > 0) {
        uint8_t *raw_copy = (uint8_t *)malloc(packet->raw_length);
        if (raw_copy != NULL) {
            memcpy(raw_copy, packet->raw_packet, packet->raw_length);
            stored_packet->raw_packet = raw_copy;
            
            // Update payload pointer if it exists
            if (packet->payload != NULL && packet->payload_length > 0) {
                // Calculate payload offset in original packet
                ptrdiff_t payload_offset = packet->payload - packet->raw_packet;
                // Update payload pointer to point into our copy
                stored_packet->payload = raw_copy + payload_offset;
            }
        } else {
            // Failed to allocate memory for raw packet
            stored_packet->raw_packet = NULL;
            stored_packet->payload = NULL;
            return -1;
        }
    }
    
    current_session.count++;
    return 0;
}

uint32_t storage_get_count(void) {
    return current_session.count;
}

parsed_packet_t* storage_get_packet(uint32_t index) {
    // Check if index is valid
    if (index >= current_session.count) {
        return NULL;
    }
    
    return &current_session.packets[index];
}

void storage_clear_session(void) {
    if (current_session.packets != NULL) {
        // Free all raw packet data
        for (uint32_t i = 0; i < current_session.count; i++) {
            if (current_session.packets[i].raw_packet != NULL) {
                free((void *)current_session.packets[i].raw_packet);
                current_session.packets[i].raw_packet = NULL;
                current_session.packets[i].payload = NULL;
            }
        }
        
        // Free the packet array
        free(current_session.packets);
        current_session.packets = NULL;
    }
    
    current_session.count = 0;
    current_session.capacity = 0;
}

int storage_has_session(void) {
    return (current_session.count > 0);
}

// LLM Generated Code Ends Here