/*
 * Subnet Module
 * Standalone IPv4 subnet calculator (CIDR notation). Pure bitwise arithmetic,
 * no external dependencies. Usable without root or a capture session via
 * `cshark --subnet <CIDR>`, since it demonstrates IP addressing/subnetting
 * fundamentals independent of live packet capture.
 */

#ifndef SUBNET_H
#define SUBNET_H

#include <netinet/in.h>
#include <stdint.h>

typedef struct {
    char address[INET_ADDRSTRLEN];      // the IP that was given
    char network[INET_ADDRSTRLEN];
    char broadcast[INET_ADDRSTRLEN];
    char netmask[INET_ADDRSTRLEN];
    char wildcard[INET_ADDRSTRLEN];
    char first_usable[INET_ADDRSTRLEN];
    char last_usable[INET_ADDRSTRLEN];
    uint32_t total_hosts;
    uint32_t usable_hosts;
    int prefix_len;
} subnet_info_t;

// Parses "a.b.c.d/prefix" and fills `out`. Returns 0 on success, -1 on
// malformed input (bad dotted-decimal address or prefix outside 0-32).
int subnet_calculate(const char *cidr, subnet_info_t *out);

// Pretty-prints a computed subnet_info_t to stdout.
void subnet_print(const subnet_info_t *info);

#endif // SUBNET_H
