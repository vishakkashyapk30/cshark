/*
 * Subnet Module Implementation
 */

#include "subnet.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// LLM Generated Code Starts Here

static void ip_to_string(uint32_t ip_host_order, char *buffer, size_t size) {
    struct in_addr addr;
    addr.s_addr = htonl(ip_host_order);
    inet_ntop(AF_INET, &addr, buffer, size);
}

int subnet_calculate(const char *cidr, subnet_info_t *out) {
    if (cidr == NULL || out == NULL) {
        return -1;
    }

    char ip_part[INET_ADDRSTRLEN];
    int prefix_len;

    const char *slash = strchr(cidr, '/');
    if (slash == NULL) {
        fprintf(stderr, "[C-Shark Subnet] Error: expected CIDR notation, e.g. 192.168.1.10/24\n");
        return -1;
    }

    size_t ip_len = (size_t)(slash - cidr);
    if (ip_len == 0 || ip_len >= sizeof(ip_part)) {
        fprintf(stderr, "[C-Shark Subnet] Error: invalid IPv4 address.\n");
        return -1;
    }
    memcpy(ip_part, cidr, ip_len);
    ip_part[ip_len] = '\0';

    prefix_len = atoi(slash + 1);
    if (prefix_len < 0 || prefix_len > 32) {
        fprintf(stderr, "[C-Shark Subnet] Error: prefix length must be between 0 and 32.\n");
        return -1;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_part, &addr) != 1) {
        fprintf(stderr, "[C-Shark Subnet] Error: '%s' is not a valid IPv4 address.\n", ip_part);
        return -1;
    }

    uint32_t ip_host = ntohl(addr.s_addr);
    uint32_t mask_host = (prefix_len == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix_len));
    uint32_t wildcard_host = ~mask_host;
    uint32_t network_host = ip_host & mask_host;
    uint32_t broadcast_host = network_host | wildcard_host;

    memset(out, 0, sizeof(subnet_info_t));
    snprintf(out->address, sizeof(out->address), "%s", ip_part);
    ip_to_string(network_host, out->network, sizeof(out->network));
    ip_to_string(broadcast_host, out->broadcast, sizeof(out->broadcast));
    ip_to_string(mask_host, out->netmask, sizeof(out->netmask));
    ip_to_string(wildcard_host, out->wildcard, sizeof(out->wildcard));
    out->prefix_len = prefix_len;

    // /31 and /32 are special-cased per RFC 3021 / host-route conventions:
    // there is no broadcast/network split to reserve two addresses for.
    if (prefix_len >= 31) {
        out->total_hosts = (prefix_len == 32) ? 1 : 2;
        out->usable_hosts = out->total_hosts;
        ip_to_string(network_host, out->first_usable, sizeof(out->first_usable));
        ip_to_string(broadcast_host, out->last_usable, sizeof(out->last_usable));
    } else {
        out->total_hosts = broadcast_host - network_host + 1;
        out->usable_hosts = out->total_hosts - 2;
        ip_to_string(network_host + 1, out->first_usable, sizeof(out->first_usable));
        ip_to_string(broadcast_host - 1, out->last_usable, sizeof(out->last_usable));
    }

    return 0;
}

void subnet_print(const subnet_info_t *info) {
    if (info == NULL) return;

    printf("\n========================================\n");
    printf("SUBNET CALCULATOR - %s/%d\n", info->address, info->prefix_len);
    printf("========================================\n");
    printf("  Network Address:   %s\n", info->network);
    printf("  Broadcast Address: %s\n", info->broadcast);
    printf("  Subnet Mask:       %s\n", info->netmask);
    printf("  Wildcard Mask:     %s\n", info->wildcard);
    printf("  Usable Host Range: %s - %s\n", info->first_usable, info->last_usable);
    printf("  Total Addresses:   %u\n", info->total_hosts);
    printf("  Usable Hosts:      %u\n", info->usable_hosts);
    printf("========================================\n");
}

// LLM Generated Code Ends Here
