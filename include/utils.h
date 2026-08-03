/*
 * Utility Module
 * Helper functions and utilities
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <signal.h>
#include <sys/time.h>

// Global flag for capture interruption
extern volatile sig_atomic_t capture_interrupted;

// Signal handling for Ctrl+C
void setup_signal_handlers(void);
void handle_sigint(int sig);

// Arms a SIGALRM that fires after `seconds` and trips the same
// `capture_interrupted` flag as Ctrl+C - used by headless/scripted capture
// mode (see main.c) to stop a capture loop after a fixed duration without
// requiring an interactive Ctrl+C.
void arm_capture_timeout(int seconds);

// Input handling
int get_user_choice(int min, int max);
void clear_input_buffer(void);

// String formatting helpers
void format_timestamp(struct timeval tv, char *buffer, size_t size);
void format_mac_address(const uint8_t *mac, char *buffer, size_t size);
void format_ip_address(const char *ip, char *buffer, size_t size);

// TCP flags decoding
void decode_tcp_flags(uint8_t flags, char *buffer, size_t size);

// Checksum validation (if needed)
uint16_t calculate_checksum(const uint8_t *data, int length);

#endif // UTILS_H

