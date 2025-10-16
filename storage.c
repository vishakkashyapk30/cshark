/*
 * Storage Module Implementation
 */

#include "storage.h"
#include <stdlib.h>
#include <string.h>

// Global session storage
static packet_session_t current_session = {NULL, 0, 0};

void storage_init_session(void) {
    // Will be implemented in Phase 4
}

int storage_add_packet(const parsed_packet_t *packet) {
    // Will be implemented in Phase 4
    (void)packet;
    return 0;
}

uint32_t storage_get_count(void) {
    // Will be implemented in Phase 4
    return current_session.count;
}

parsed_packet_t* storage_get_packet(uint32_t index) {
    // Will be implemented in Phase 4
    (void)index;
    return NULL;
}

void storage_clear_session(void) {
    // Will be implemented in Phase 4
}

int storage_has_session(void) {
    // Will be implemented in Phase 4
    return current_session.count > 0;
}

