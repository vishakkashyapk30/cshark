# C-Shark Improvement Plan

This document is written for a coding agent (or contributor) picking up this repo to
implement the next set of features. Read this fully before writing code. Follow the
existing architecture and coding conventions (see "Codebase Conventions" below) —
do not introduce a new framework, build system, or language.

## 1. Current State (as of this plan)

C-Shark is a terminal-based, Wireshark-style packet sniffer/analyzer written in C
using `libpcap`. It captures live traffic in promiscuous mode and parses it
layer-by-layer across the OSI stack.

### Existing modules
| File | Responsibility |
|---|---|
| `main.c` | Entry point, menu loop, orchestrates all modules |
| `interface.c/h` | Enumerates network interfaces via `pcap_findalldevs()` |
| `capture.c/h` | Opens the pcap handle, runs the capture loop, invokes `packet_handler()` per packet |
| `packet_parser.c/h` | Layer-by-layer parsing into `parsed_packet_t` (Ethernet, IPv4/IPv6/ARP, TCP/UDP, HTTP/HTTPS/DNS) |
| `filter.c/h` | Generates and applies BPF filter expressions |
| `storage.c/h` | Session storage (up to `MAX_PACKETS` = 10,000), deep-copies packets |
| `display.c/h` | Live packet display + hex dump + detailed inspection views |
| `inspection.c/h` | Interactive post-capture packet browsing |
| `utils.c/h` | Signal handling (SIGINT), input validation, checksum helpers |

### Key existing types (packet_parser.h)
```c
typedef struct {
    uint32_t id;
    struct timeval timestamp;
    uint32_t length;
    uint8_t src_mac[6], dst_mac[6];
    uint16_t ethertype;
    int l3_protocol;              // PROTO_IPv4 / PROTO_IPv6 / PROTO_ARP
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    union { struct {...} ipv4; struct {...} ipv6; struct {...} arp; } l3_data;
    int l4_protocol;              // PROTO_TCP / PROTO_UDP
    uint16_t src_port, dst_port;
    union { struct { uint32_t seq_num, ack_num; uint8_t flags; ... } tcp; struct {...} udp; } l4_data;
    int app_protocol;             // PROTO_HTTP / PROTO_HTTPS / PROTO_DNS
    const uint8_t *payload; uint32_t payload_length;
    const uint8_t *raw_packet; uint32_t raw_length;
} parsed_packet_t;
```
The ARP union (`l3_data.arp`) already exposes `sender_mac`, `sender_ip`,
`target_mac`, `target_ip`, and `operation` (1 = request, 2 = reply) — this is
what the ARP-spoof detector below will consume.

`capture.c`'s `packet_handler()` is the single callback invoked for every
captured packet (already parses it via `parse_packet()`); this is the
integration point for any new per-packet analysis.

## 2. MUST-HAVE Features (required — these are already committed to externally,
   treat them as non-negotiable scope for this iteration)

### 2.1 Port-Scan Detection
**Behavior**: flag a source IP as a probable port-scanner if it contacts
**15 or more distinct destination ports within a 5-second sliding window**.

**Design**:
- New module `detect.c` / `detect.h`.
- Maintain a hash table keyed by source IP string (`char[INET6_ADDRSTRLEN]`).
  Each entry holds a small ring buffer / dynamic array of `{uint16_t port; time_t ts;}`
  records observed for that source.
- On every TCP or UDP packet (`parsed->l4_protocol == PROTO_TCP || PROTO_UDP`),
  call `detect_port_scan_observe(const parsed_packet_t *pkt)`:
  1. Prune entries older than 5 seconds from that source's record list.
  2. Insert `{dst_port, now}` if not already present in the active window.
  3. If the count of **distinct** ports in the window >= 15, raise an alert
     (see 2.3) and mark that source IP as "flagged" (with a cooldown, e.g.
     don't re-alert for the same IP more than once per 30s, to avoid log spam).
- Use a simple open-addressing or chained hash table (no external deps —
  consistent with the rest of the codebase's "zero external libraries" ethos
  beyond libpcap). A fixed-size table (e.g. 1024 buckets) with linked-list
  collision chains is sufficient; this does not need to be production-grade.

**Function signatures to add (detect.h)**:
```c
void detect_init(void);
void detect_port_scan_observe(const parsed_packet_t *pkt);
void detect_cleanup(void);
```

### 2.2 ARP-Spoofing Detection
**Behavior**: flag a conflict whenever an IP address's bound MAC address
changes without a plausible cause (i.e., a new ARP reply claims a different
MAC for an IP we've already bound).

**Design**:
- Maintain a second hash table: IP (4-byte, from `l3_data.arp.sender_ip`) ->
  last-seen MAC (6 bytes), populated only from ARP **replies**
  (`l3_data.arp.operation == 2`).
- On every ARP packet, call `detect_arp_spoof_observe(const parsed_packet_t *pkt)`:
  1. Look up `sender_ip` in the binding table.
  2. If not present, insert `(sender_ip -> sender_mac)`.
  3. If present and the MAC differs from the stored one, raise an alert
     (a classic ARP cache-poisoning signature) — include both the old and
     new MAC in the alert message.
- Do not flag gratuitous ARP announcements from the same MAC (i.e., only
  flag when the MAC actually *changes*, not every reply).

**Function signatures to add (detect.h)**:
```c
void detect_arp_spoof_observe(const parsed_packet_t *pkt);
```

### 2.3 Alert Surfacing
- Add `void detect_print_alert(const char *type, const char *details);` in
  `detect.c` that prints a clearly distinguishable line (e.g. prefixed with
  a red-colored `[ALERT]` tag using the same box-drawing/ANSI style already
  used in `display.c`) to stdout during live capture, interleaved with the
  normal live packet display.
- Alerts must also be retrievable after the fact: extend `packet_session_t`
  (in `storage.h`) or add a small parallel `alert_log_t` array so that
  `inspection.c`'s menu can show a "View Security Alerts" option listing all
  alerts raised during the last session (timestamp, type, details).

### 2.4 Integration
- Call `detect_init()` once at the start of `start_sniffing_all()` /
  `start_sniffing_filtered()` in `capture.c`.
- Inside `packet_handler()`, after `parse_packet()` succeeds, call
  `detect_port_scan_observe()` and `detect_arp_spoof_observe()` as
  applicable to the parsed protocol.
- Call `detect_cleanup()` on capture stop.
- Add `detect.c` to the `Makefile`'s object list.

### 2.5 Validation (must be done before considering this feature complete)
- **Port-scan test**: on a local test VM/network namespace, run
  `nmap -sS -p 1-100 <target-ip>` against a host C-Shark is capturing on
  the same segment/interface, and confirm an alert fires with the correct
  source IP and port count.
- **ARP-spoof test**: use `arpspoof -i <iface> -t <target-ip> <gateway-ip>`
  (or `ettercap -M arp`) in a controlled lab/VM setup (never on a network
  you don't own or have permission to test) and confirm the MAC-conflict
  alert fires with the correct old/new MAC values.
- Record actual results (screenshots or terminal logs) — these are needed
  to back up the resume claim this feature is tied to, and the specific
  numbers in that claim (15+ ports / 5s window) must match whatever is
  actually implemented and tested. If tuning changes the threshold/window,
  flag that back so the resume bullet can be updated to match.
- Add a basic regression test (a small pcap replay script or unit test using
  a saved `.pcap` sample, if PCAP import exists — otherwise a synthetic
  `parsed_packet_t` fixture test) so this doesn't silently regress.

## 3. Nice-to-Have Features (optional, only pick up after section 2 is fully
   done, tested, and committed)

These were in the original README's "Future Enhancements" list. Do not start
these until the must-have features above are complete:

- **PCAP file import/export** — read/write standard `.pcap` files
  (`pcap_open_offline`, `pcap_dump_open`) for interop with Wireshark/tcpdump.
- **Multi-threaded capture** — producer/consumer with a lock-free or
  mutex-protected ring buffer so parsing/display don't block the capture
  callback on high-throughput interfaces.
- **Live traffic statistics/analytics** — per-protocol packet/byte counters,
  top-talkers table, simple bandwidth-over-time view.
- **Packet replay** — re-inject stored/loaded packets onto an interface for
  automated test-case generation.
- **Compound BPF filters** — allow chaining filter primitives with AND/OR/NOT
  in the existing `filter.c` expression generator.

## 4. Codebase Conventions

- Pure C (C99), built via the existing `Makefile` (`make`, `make clean`,
  `make rebuild`). Do not introduce CMake, Meson, or other build systems.
- No external dependencies beyond `libpcap` (already required). The hash
  tables for detection must be hand-rolled, consistent with the project's
  "zero external libraries beyond libpcap" philosophy.
- Match existing style: modular `.c`/`.h` pairs per concern, header guards,
  functions documented with a short comment block matching the style seen
  in `capture.h`/`packet_parser.h`.
- Update `README.md`'s Features/Architecture sections to document the new
  `detect` module once implemented (do not leave the README stale).
- Free all dynamically allocated memory on `detect_cleanup()` — this project
  cares about memory-leak discipline (see `storage.c`'s deep-copy/free
  pattern for reference).

## 5. Acceptance Checklist

- [ ] `detect.c` / `detect.h` added and wired into `Makefile`
- [ ] Port-scan detection implemented with 5s sliding window, 15-port threshold
- [ ] ARP-spoof detection implemented via IP→MAC binding table
- [ ] Alerts printed live during capture, and viewable post-capture via inspection menu
- [ ] Validated against real `nmap` (port scan) and `arpspoof`/`ettercap` (ARP) tests in a lab/VM
- [ ] No memory leaks (`valgrind --leak-check=full` clean, or equivalent manual audit)
- [ ] README updated to document the new module
- [ ] Resume bullet's specific numbers (15+ ports/5s) reconciled with actual tested thresholds
