/*
 * Detection Module Implementation
 * Two independent, hand-rolled hash tables:
 *   1. Port-scan heuristic: >=15 distinct destination ports from one source
 *      IP within a 5-second sliding window.
 *   2. ARP-spoof heuristic: an IP's bound MAC address changing between
 *      observed ARP replies (classic ARP cache-poisoning signature).
 * No external dependencies beyond the C standard library.
 */

#include "detect.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// LLM Generated Code Starts Here

#define HASH_BUCKETS        1024
#define PORT_SCAN_WINDOW_S  5
#define PORT_SCAN_THRESHOLD 15
#define PORT_SCAN_COOLDOWN_S 30
#define MAX_ALERTS          512
#define INITIAL_RECORD_CAP  16

// ---- Port-scan tracking ----
typedef struct {
    uint16_t port;
    time_t ts;
} port_record_t;

typedef struct port_scan_entry {
    char src_ip[INET6_ADDRSTRLEN];
    port_record_t *records;
    size_t count;
    size_t capacity;
    time_t last_alert;
    struct port_scan_entry *next;
} port_scan_entry_t;

// ---- ARP binding tracking ----
typedef struct arp_binding_entry {
    uint8_t ip[4];
    uint8_t mac[6];
    struct arp_binding_entry *next;
} arp_binding_entry_t;

static port_scan_entry_t *port_scan_table[HASH_BUCKETS];
static arp_binding_entry_t *arp_binding_table[HASH_BUCKETS];

static alert_record_t alert_log[MAX_ALERTS];
static uint32_t alert_count = 0;

static uint32_t hash_str(const char *s) {
    uint32_t hash = 5381;
    int c;
    while ((c = (unsigned char)*s++)) {
        hash = ((hash << 5) + hash) + (uint32_t)c; // hash * 33 + c
    }
    return hash;
}

static uint32_t hash_ip4(const uint8_t ip[4]) {
    uint32_t v = ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) |
                 ((uint32_t)ip[2] << 8) | (uint32_t)ip[3];
    // Fibonacci hashing to spread bits across the bucket range
    return (v * 2654435761u);
}

static void free_port_scan_table(void) {
    for (int i = 0; i < HASH_BUCKETS; i++) {
        port_scan_entry_t *entry = port_scan_table[i];
        while (entry != NULL) {
            port_scan_entry_t *next = entry->next;
            free(entry->records);
            free(entry);
            entry = next;
        }
        port_scan_table[i] = NULL;
    }
}

static void free_arp_binding_table(void) {
    for (int i = 0; i < HASH_BUCKETS; i++) {
        arp_binding_entry_t *entry = arp_binding_table[i];
        while (entry != NULL) {
            arp_binding_entry_t *next = entry->next;
            free(entry);
            entry = next;
        }
        arp_binding_table[i] = NULL;
    }
}

void detect_init(void) {
    // Fresh working state for the new session
    free_port_scan_table();
    free_arp_binding_table();
    // Fresh alert log for the new session (mirrors storage_init_session())
    alert_count = 0;
    memset(alert_log, 0, sizeof(alert_log));
}

static port_scan_entry_t *find_or_create_port_scan_entry(const char *src_ip) {
    uint32_t bucket = hash_str(src_ip) % HASH_BUCKETS;
    port_scan_entry_t *entry = port_scan_table[bucket];

    while (entry != NULL) {
        if (strncmp(entry->src_ip, src_ip, INET6_ADDRSTRLEN) == 0) {
            return entry;
        }
        entry = entry->next;
    }

    entry = (port_scan_entry_t *)calloc(1, sizeof(port_scan_entry_t));
    if (entry == NULL) {
        return NULL;
    }
    snprintf(entry->src_ip, INET6_ADDRSTRLEN, "%s", src_ip);
    entry->records = (port_record_t *)malloc(INITIAL_RECORD_CAP * sizeof(port_record_t));
    if (entry->records == NULL) {
        free(entry);
        return NULL;
    }
    entry->capacity = INITIAL_RECORD_CAP;
    entry->count = 0;
    entry->last_alert = 0;
    entry->next = port_scan_table[bucket];
    port_scan_table[bucket] = entry;
    return entry;
}

void detect_port_scan_observe(const parsed_packet_t *pkt) {
    if (pkt == NULL) return;
    if (pkt->l4_protocol != PROTO_TCP && pkt->l4_protocol != PROTO_UDP) {
        return;
    }

    time_t now = pkt->timestamp.tv_sec;
    port_scan_entry_t *entry = find_or_create_port_scan_entry(pkt->src_ip);
    if (entry == NULL) {
        return; // allocation failure - fail open, don't crash the capture
    }

    // Prune records older than the sliding window (compact in place)
    size_t write_idx = 0;
    for (size_t i = 0; i < entry->count; i++) {
        if (now - entry->records[i].ts <= PORT_SCAN_WINDOW_S) {
            entry->records[write_idx++] = entry->records[i];
        }
    }
    entry->count = write_idx;

    // Check if this destination port is already tracked in the active window
    int already_seen = 0;
    for (size_t i = 0; i < entry->count; i++) {
        if (entry->records[i].port == pkt->dst_port) {
            entry->records[i].ts = now; // refresh recency
            already_seen = 1;
            break;
        }
    }

    if (!already_seen) {
        if (entry->count >= entry->capacity) {
            size_t new_capacity = entry->capacity * 2;
            port_record_t *grown = (port_record_t *)realloc(entry->records,
                                                              new_capacity * sizeof(port_record_t));
            if (grown == NULL) {
                return; // can't grow further, drop this observation
            }
            entry->records = grown;
            entry->capacity = new_capacity;
        }
        entry->records[entry->count].port = pkt->dst_port;
        entry->records[entry->count].ts = now;
        entry->count++;
    }

    if (entry->count >= PORT_SCAN_THRESHOLD &&
        (now - entry->last_alert) >= PORT_SCAN_COOLDOWN_S) {
        char details[256];
        snprintf(details, sizeof(details),
                 "Source %s contacted %zu distinct destination ports within %ds (threshold: %d)",
                 entry->src_ip, entry->count, PORT_SCAN_WINDOW_S, PORT_SCAN_THRESHOLD);
        detect_print_alert("PORT_SCAN", details);
        entry->last_alert = now;
    }
}

void detect_arp_spoof_observe(const parsed_packet_t *pkt) {
    if (pkt == NULL || pkt->l3_protocol != PROTO_ARP) {
        return;
    }
    // Only trust bindings learned from ARP replies (operation == 2); requests
    // carry the same sender info but replies are the authoritative answer to
    // "who has this IP" and are what a spoofer forges.
    if (pkt->l3_data.arp.operation != 2) {
        return;
    }

    const uint8_t *ip = pkt->l3_data.arp.sender_ip;
    const uint8_t *mac = pkt->l3_data.arp.sender_mac;
    uint32_t bucket = hash_ip4(ip) % HASH_BUCKETS;

    arp_binding_entry_t *entry = arp_binding_table[bucket];
    while (entry != NULL) {
        if (memcmp(entry->ip, ip, 4) == 0) {
            if (memcmp(entry->mac, mac, 6) != 0) {
                char old_mac_str[18], new_mac_str[18], details[256];
                format_mac_address(entry->mac, old_mac_str, sizeof(old_mac_str));
                format_mac_address(mac, new_mac_str, sizeof(new_mac_str));
                snprintf(details, sizeof(details),
                         "IP %s changed MAC binding %s -> %s (possible ARP cache poisoning)",
                         pkt->src_ip, old_mac_str, new_mac_str);
                detect_print_alert("ARP_SPOOF", details);
                memcpy(entry->mac, mac, 6);
            }
            return;
        }
        entry = entry->next;
    }

    // First time we've seen this IP resolved via an ARP reply - learn the binding
    entry = (arp_binding_entry_t *)calloc(1, sizeof(arp_binding_entry_t));
    if (entry == NULL) {
        return; // fail open
    }
    memcpy(entry->ip, ip, 4);
    memcpy(entry->mac, mac, 6);
    entry->next = arp_binding_table[bucket];
    arp_binding_table[bucket] = entry;
}

void detect_print_alert(const char *type, const char *details) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[16];
    strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

    // ANSI red, bold [ALERT] tag - interleaved with the live packet display
    printf("\n\033[1;31m[ALERT]\033[0m %s \033[1m%-10s\033[0m %s\n",
           time_str, type, details);
    fflush(stdout);

    if (alert_count < MAX_ALERTS) {
        alert_log[alert_count].timestamp = now;
        strncpy(alert_log[alert_count].type, type, sizeof(alert_log[alert_count].type) - 1);
        strncpy(alert_log[alert_count].details, details, sizeof(alert_log[alert_count].details) - 1);
        alert_count++;
    }
}

uint32_t detect_get_alert_count(void) {
    return alert_count;
}

const alert_record_t *detect_get_alert(uint32_t index) {
    if (index >= alert_count) {
        return NULL;
    }
    return &alert_log[index];
}

void detect_cleanup(void) {
    // Only free the working hash tables; the alert log intentionally
    // survives so it can be reviewed after the capture stops.
    free_port_scan_table();
    free_arp_binding_table();
}

// LLM Generated Code Ends Here
