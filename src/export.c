/*
 * Export Module Implementation
 */

#include "cshark.h"
#include "export.h"
#include "storage.h"
#include "detect.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

// LLM Generated Code Starts Here

// Writes `field` to `fp` as a quoted CSV field, doubling any embedded quotes,
// so free-text columns (alert details, flow info) can safely contain commas.
static void csv_write_quoted_field(FILE *fp, const char *field) {
    fputc('"', fp);
    for (const char *p = field; *p != '\0'; p++) {
        if (*p == '"') {
            fputc('"', fp);
        }
        fputc(*p, fp);
    }
    fputc('"', fp);
}

static const char *flow_protocol_name(const parsed_packet_t *pkt) {
    if (pkt->l3_protocol == PROTO_ARP) return "ARP";
    if (pkt->l4_protocol == PROTO_TCP) return "TCP";
    if (pkt->l4_protocol == PROTO_UDP) return "UDP";
    if (pkt->l3_protocol == PROTO_IPv4) return "IPv4";
    if (pkt->l3_protocol == PROTO_IPv6) return "IPv6";
    return "Unknown";
}

int export_session_csv(const char *filepath) {
    if (!storage_has_session()) {
        fprintf(stderr, "[C-Shark Export] Error: No capture session available to export.\n");
        return -1;
    }

    FILE *fp = fopen(filepath, "w");
    if (fp == NULL) {
        fprintf(stderr, "[C-Shark Export] Error: Could not open '%s' for writing.\n", filepath);
        return -1;
    }

    fprintf(fp, "packet_id,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,length,tcp_flags,info\n");

    uint32_t count = storage_get_count();
    for (uint32_t i = 0; i < count; i++) {
        parsed_packet_t *pkt = storage_get_packet(i);
        if (pkt == NULL) continue;

        char timestamp[32];
        snprintf(timestamp, sizeof(timestamp), "%ld.%06ld", pkt->timestamp.tv_sec, pkt->timestamp.tv_usec);

        char tcp_flags[32] = "";
        if (pkt->l4_protocol == PROTO_TCP) {
            decode_tcp_flags(pkt->l4_data.tcp.flags, tcp_flags, sizeof(tcp_flags));
        }

        char info[160];
        if (pkt->l4_protocol == PROTO_TCP || pkt->l4_protocol == PROTO_UDP) {
            snprintf(info, sizeof(info), "%s:%u -> %s:%u", pkt->src_ip, pkt->src_port, pkt->dst_ip, pkt->dst_port);
        } else if (pkt->src_ip[0] != '\0' || pkt->dst_ip[0] != '\0') {
            snprintf(info, sizeof(info), "%s -> %s", pkt->src_ip, pkt->dst_ip);
        } else {
            info[0] = '\0';
        }

        fprintf(fp, "%u,%s,%s,%u,%s,%u,%s,%u,",
                pkt->id, timestamp, pkt->src_ip, pkt->src_port,
                pkt->dst_ip, pkt->dst_port, flow_protocol_name(pkt), pkt->length);
        csv_write_quoted_field(fp, tcp_flags);
        fputc(',', fp);
        csv_write_quoted_field(fp, info);
        fputc('\n', fp);
    }

    fclose(fp);
    printf("[C-Shark Export] Wrote %u flow records to '%s'.\n", count, filepath);
    return 0;
}

int export_alerts_csv(const char *filepath) {
    FILE *fp = fopen(filepath, "w");
    if (fp == NULL) {
        fprintf(stderr, "[C-Shark Export] Error: Could not open '%s' for writing.\n", filepath);
        return -1;
    }

    fprintf(fp, "timestamp,type,details\n");

    uint32_t count = detect_get_alert_count();
    for (uint32_t i = 0; i < count; i++) {
        const alert_record_t *alert = detect_get_alert(i);
        if (alert == NULL) continue;

        char time_str[32];
        struct tm *tm_info = localtime(&alert->timestamp);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

        fprintf(fp, "%s,%s,", time_str, alert->type);
        csv_write_quoted_field(fp, alert->details);
        fputc('\n', fp);
    }

    fclose(fp);
    printf("[C-Shark Export] Wrote %u alert records to '%s'.\n", count, filepath);
    return 0;
}

int export_session_pcap(const char *filepath) {
    if (!storage_has_session()) {
        fprintf(stderr, "[C-Shark Export] Error: No capture session available to export.\n");
        return -1;
    }

    // A "dead" pcap handle is a template used only to describe the link-layer
    // type/snap length to pcap_dump_open() - it captures nothing itself.
    pcap_t *dead_handle = pcap_open_dead(DLT_EN10MB, SNAP_LEN);
    if (dead_handle == NULL) {
        fprintf(stderr, "[C-Shark Export] Error: Could not create pcap template handle.\n");
        return -1;
    }

    pcap_dumper_t *dumper = pcap_dump_open(dead_handle, filepath);
    if (dumper == NULL) {
        fprintf(stderr, "[C-Shark Export] Error: Could not open '%s': %s\n",
                filepath, pcap_geterr(dead_handle));
        pcap_close(dead_handle);
        return -1;
    }

    uint32_t written = 0;
    uint32_t count = storage_get_count();
    for (uint32_t i = 0; i < count; i++) {
        parsed_packet_t *pkt = storage_get_packet(i);
        if (pkt == NULL || pkt->raw_packet == NULL || pkt->raw_length == 0) continue;

        struct pcap_pkthdr hdr;
        hdr.ts = pkt->timestamp;
        hdr.caplen = pkt->raw_length;
        hdr.len = pkt->length;

        pcap_dump((u_char *)dumper, &hdr, pkt->raw_packet);
        written++;
    }

    pcap_dump_close(dumper);
    pcap_close(dead_handle);

    printf("[C-Shark Export] Wrote %u packets to '%s' (open with Wireshark/tcpdump).\n", written, filepath);
    return 0;
}

// LLM Generated Code Ends Here
