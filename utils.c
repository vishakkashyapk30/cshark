/*
 * Utility Module Implementation
 */

#include "utils.h"
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

// Global flag for Ctrl+C handling
volatile sig_atomic_t capture_interrupted = 0;

void setup_signal_handlers(void) {
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    // Handle Ctrl+C (SIGINT)
    sigaction(SIGINT, &sa, NULL);
}

void handle_sigint(int sig) {
    (void)sig; // Suppress unused parameter warning
    capture_interrupted = 1;
    printf("\n\n[C-Shark] Capture interrupted. Returning to menu...\n");
}

int get_user_choice(int min, int max) {
    int choice;
    
    if (scanf("%d", &choice) != 1) {
        // Handle Ctrl+D or invalid input
        if (feof(stdin)) {
            printf("\n[C-Shark] Exiting...\n");
            exit(0);
        }
        // Clear invalid input
        clear_input_buffer();
        return -1;
    }
    
    clear_input_buffer();
    
    if (choice < min || choice > max) {
        return -1;
    }
    
    return choice;
}

void clear_input_buffer(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void format_timestamp(struct timeval tv, char *buffer, size_t size) {
    snprintf(buffer, size, "%ld.%06ld", tv.tv_sec, tv.tv_usec);
}

void format_mac_address(const uint8_t *mac, char *buffer, size_t size) {
    snprintf(buffer, size, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void format_ip_address(const char *ip, char *buffer, size_t size) {
    snprintf(buffer, size, "%s", ip);
}

void decode_tcp_flags(uint8_t flags, char *buffer, size_t size) {
    (void)size; // Size is not checked for simplicity, ensure buffer is large enough
    buffer[0] = '\0';
    int first = 1;
    
    if (flags & 0x01) { // FIN
        strcat(buffer, "FIN");
        first = 0;
    }
    if (flags & 0x02) { // SYN
        if (!first) strcat(buffer, ",");
        strcat(buffer, "SYN");
        first = 0;
    }
    if (flags & 0x04) { // RST
        if (!first) strcat(buffer, ",");
        strcat(buffer, "RST");
        first = 0;
    }
    if (flags & 0x08) { // PSH
        if (!first) strcat(buffer, ",");
        strcat(buffer, "PSH");
        first = 0;
    }
    if (flags & 0x10) { // ACK
        if (!first) strcat(buffer, ",");
        strcat(buffer, "ACK");
        first = 0;
    }
    if (flags & 0x20) { // URG
        if (!first) strcat(buffer, ",");
        strcat(buffer, "URG");
    }
}

uint16_t calculate_checksum(const uint8_t *data, int length) {
    uint32_t sum = 0;
    
    // Sum up 16-bit words
    for (int i = 0; i < length - 1; i += 2) {
        sum += (data[i] << 8) | data[i + 1];
    }
    
    // If odd number of bytes, add last byte
    if (length & 1) {
        sum += data[length - 1] << 8;
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

