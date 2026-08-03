/*
 * Regression test for detect.c using synthetic parsed_packet_t fixtures.
 * No live capture / root privileges required - this exercises the
 * port-scan and ARP-spoof heuristics directly against hand-built packets,
 * so it can run in CI or any sandbox without a NIC.
 *
 * Build/run: make test
 */

#include "cshark.h" // resolved via the -Iinclude flag in the Makefile's `test` target
#include <stdio.h>
#include <string.h>

static parsed_packet_t make_tcp_packet(const char *src_ip, uint16_t dst_port, time_t ts_sec) {
    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.timestamp.tv_sec = ts_sec;
    pkt.l3_protocol = PROTO_IPv4;
    pkt.l4_protocol = PROTO_TCP;
    snprintf(pkt.src_ip, sizeof(pkt.src_ip), "%s", src_ip);
    snprintf(pkt.dst_ip, sizeof(pkt.dst_ip), "10.0.0.1");
    pkt.dst_port = dst_port;
    pkt.src_port = 55555;
    return pkt;
}

static parsed_packet_t make_arp_reply(const uint8_t sender_ip[4], const uint8_t sender_mac[6]) {
    parsed_packet_t pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.l3_protocol = PROTO_ARP;
    pkt.l3_data.arp.operation = 2; // reply
    memcpy(pkt.l3_data.arp.sender_ip, sender_ip, 4);
    memcpy(pkt.l3_data.arp.sender_mac, sender_mac, 6);
    snprintf(pkt.src_ip, sizeof(pkt.src_ip), "%u.%u.%u.%u",
             sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);
    return pkt;
}

int main(void) {
    int failures = 0;
    detect_init();

    // --- Port-scan: 16 distinct destination ports from one source, all inside the 5s window ---
    time_t base = 1000000;
    for (int i = 0; i < 16; i++) {
        parsed_packet_t pkt = make_tcp_packet("192.0.2.50", (uint16_t)(20000 + i), base + i / 4);
        detect_port_scan_observe(&pkt);
    }
    int found_port_scan = 0;
    for (uint32_t i = 0; i < detect_get_alert_count(); i++) {
        const alert_record_t *a = detect_get_alert(i);
        if (strcmp(a->type, "PORT_SCAN") == 0 && strstr(a->details, "192.0.2.50") != NULL) {
            found_port_scan = 1;
        }
    }
    if (!found_port_scan) {
        printf("FAIL: port-scan detection did not raise an alert for 16 distinct ports in-window\n");
        failures++;
    } else {
        printf("PASS: port-scan detection fires at/above the 15-port threshold\n");
    }

    // Negative case: fewer than the threshold distinct ports must NOT alert
    uint32_t alerts_before = detect_get_alert_count();
    for (int i = 0; i < 5; i++) {
        parsed_packet_t pkt = make_tcp_packet("192.0.2.99", (uint16_t)(30000 + i), base);
        detect_port_scan_observe(&pkt);
    }
    if (detect_get_alert_count() != alerts_before) {
        printf("FAIL: port-scan detection false-positived on only 5 distinct ports\n");
        failures++;
    } else {
        printf("PASS: port-scan detection stays quiet below the threshold\n");
    }

    // Negative case: 16 distinct ports but spread outside the 5s window should NOT alert
    uint32_t alerts_before_spread = detect_get_alert_count();
    for (int i = 0; i < 16; i++) {
        parsed_packet_t pkt = make_tcp_packet("192.0.2.77", (uint16_t)(40000 + i), base + (i * 10));
        detect_port_scan_observe(&pkt);
    }
    if (detect_get_alert_count() != alerts_before_spread) {
        printf("FAIL: port-scan detection false-positived on ports spread outside the 5s window\n");
        failures++;
    } else {
        printf("PASS: port-scan detection respects the 5s sliding window\n");
    }

    // --- ARP-spoof: binding learned, repeated identical reply is silent, changed MAC alerts ---
    uint8_t ip[4] = {192, 0, 2, 1};
    uint8_t mac1[6] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    uint8_t mac2[6] = {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB};

    parsed_packet_t r1 = make_arp_reply(ip, mac1);
    detect_arp_spoof_observe(&r1); // learns the binding, no alert expected

    uint32_t alerts_after_first = detect_get_alert_count();
    parsed_packet_t r1_repeat = make_arp_reply(ip, mac1);
    detect_arp_spoof_observe(&r1_repeat); // same MAC again - should stay silent
    if (detect_get_alert_count() != alerts_after_first) {
        printf("FAIL: ARP-spoof detection false-positived on a repeated identical reply\n");
        failures++;
    } else {
        printf("PASS: ARP-spoof detection ignores repeated identical replies\n");
    }

    parsed_packet_t r2 = make_arp_reply(ip, mac2); // MAC changed for the same IP - should alert
    detect_arp_spoof_observe(&r2);
    int found_arp_spoof = 0;
    for (uint32_t i = 0; i < detect_get_alert_count(); i++) {
        const alert_record_t *a = detect_get_alert(i);
        if (strcmp(a->type, "ARP_SPOOF") == 0) {
            found_arp_spoof = 1;
        }
    }
    if (!found_arp_spoof) {
        printf("FAIL: ARP-spoof detection did not raise an alert on MAC binding change\n");
        failures++;
    } else {
        printf("PASS: ARP-spoof detection fires when a bound MAC changes\n");
    }

    detect_cleanup();

    if (failures == 0) {
        printf("\nAll detect.c regression tests passed.\n");
        return 0;
    }
    printf("\n%d regression test(s) FAILED.\n", failures);
    return 1;
}
