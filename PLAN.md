# C-Shark Improvement Plan

This document is written for a coding agent (or contributor) picking up this repo to
implement the next set of features. Read this fully before writing code. Follow the
existing architecture and coding conventions (see "Codebase Conventions" below) —
do not introduce a new framework, build system, or language for the core C tool.

## 0. Why This Revision Exists

This revision extends the original security-detection plan (section 2 below, unchanged
in substance) with a set of additions chosen specifically to make this project a strong,
honest portfolio piece for a **Cloud Network Engineering Intern** role. The JD for that
role emphasizes:

| JD requirement | How this plan addresses it |
|---|---|
| Networking fundamentals (OSI, IP addressing/subnetting, routing/switching) | Already covered by `packet_parser.c` (full L2-L7 dissection); adds a standalone **subnet calculator** (§3.3) to demonstrate IP addressing/subnetting explicitly. |
| Cloud technologies (Azure, VNets, cloud security, identity/access) | This is a local CLI tool, not an Azure service — we don't fake cloud integration. Instead, §3.2's flow/PCAP export is explicitly documented (README) as analogous to **Azure Network Watcher packet capture** and **NSG flow logs**, and the alert log is analogous to **Network Watcher/Defender for Cloud security alerts**, so the concepts transfer even though the implementation is local. |
| Scripting & automation (PowerShell/Python) | Adds a **Python** analysis tool (§3.4) and a **PowerShell** automation script (§3.5) that orchestrate the C tool — real, runnable scripts, not documentation-only claims. |
| Network ops tools (Wireshark, Azure Network Watcher) | Adds real **`.pcap` export** (§3.2) so captures open directly in Wireshark — genuine interop, not just a CSV. |
| AI/ML in network engineering | Adds a small, honestly-scoped **ML-assisted anomaly triage script** (§3.4) — flags outlier source IPs from flow statistics using an isolation-forest-style model (with a dependency-free statistical fallback), explicitly framed as reducing manual review effort, not as a black-box claim. |
| Automated testing / large-scale network validation | Adds a **headless/scriptable capture mode** (§3.1) so capture + export + analysis can run non-interactively from CI/scripts instead of only through the interactive menu. |

Do not oversell any of this in the README or resume bullets — every claim must map to
code that actually exists and was tested. Section 6 has a checklist tying each JD bullet
to a concrete, verifiable artifact.

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
  a red-colored `[ALERT]` tag using ANSI color codes) to stdout during live
  capture, interleaved with the normal live packet display.
- Alerts must also be retrievable after the fact: `detect.c` keeps an
  in-memory `alert_log` (parallel to `packet_session_t`, capped at a fixed
  size e.g. 512 entries) so that `inspection.c`'s menu can show a
  "View Security Alerts" option listing all alerts raised during the last
  session (timestamp, type, details). Exposed via:
  ```c
  uint32_t detect_get_alert_count(void);
  const alert_record_t *detect_get_alert(uint32_t index);
  ```

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

## 3. NEW: Cloud/Network-Engineering-Aligned Extensions

These are additive, in priority order. Each is independently useful and should
be implemented as its own module, matching the existing one-concern-per-file
convention.

### 3.1 Headless / Scriptable Capture Mode
**Why**: everything today requires an interactive menu (`scanf`), which makes
the tool impossible to drive from a script, cron job, or CI pipeline. Real
network validation workflows (the kind referenced by "automated testing and
large-scale network validation" in the JD) need a non-interactive mode.

**Design**:
- Add CLI argument parsing to `main.c` (plain `argv` parsing, no new deps).
  If no recognized flags are passed, fall back to today's interactive menu
  unchanged (backwards compatible).
- New flags:
  - `-i, --interface <name>`: device to capture on.
  - `-t, --time <seconds>`: stop capture automatically after N seconds
    (implemented via `alarm(2)` + `SIGALRM` reusing the existing
    `capture_interrupted` flag from `utils.c`, so the existing capture loop
    in `capture.c` needs no structural change).
  - `--filter <name>`: one of `http|https|dns|arp|tcp|udp` (maps to the
    existing `filter.c` generator).
  - `-o, --csv <path>`: export the session to CSV on completion (§3.2).
  - `--pcap <path>`: export the session to a real `.pcap` file on completion (§3.2).
  - `--list-interfaces`: print discovered interfaces and exit (no capture).
  - `--subnet <CIDR>`: run the subnet calculator (§3.3) and exit (no root needed).
  - `-h, --help`: usage text.
- Headless mode must still print the alert log and a session summary to
  stdout on exit so it's useful when piped into logs.

### 3.2 Session Export (CSV + real PCAP)
**Why**: bridges C-Shark to the wider tool ecosystem — real `.pcap` export
means captures open in Wireshark; CSV export is the same shape as an
**Azure NSG flow log** (5-tuple + bytes + timestamp), and is what feeds the
Python analysis tool in §3.4.

**Design** — new module `export.c` / `export.h`:
```c
int export_session_csv(const char *filepath);   // one row per stored packet
int export_alerts_csv(const char *filepath);    // one row per raised alert
int export_session_pcap(const char *filepath);  // real .pcap via pcap_dump*
```
- CSV columns: `packet_id,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,length,tcp_flags,info`.
- PCAP export uses `pcap_open_dead(DLT_EN10MB, SNAP_LEN)` to get a template
  handle, `pcap_dump_open()` for the file, then replays each stored packet's
  `raw_packet`/`raw_length` with its original `timestamp` via `pcap_dump()`.
  This produces a file openable directly in Wireshark/tcpdump.
- Wire into the interactive menu as a new "Export Session Data" option, and
  into the headless flags from §3.1.

### 3.3 Subnet Calculator
**Why**: directly demonstrates "IP addressing and subnetting" from the JD's
networking-fundamentals bullet, independent of live capture (so it's usable
without root or a NIC, e.g. in a coding-screen demo).

**Design** — new module `subnet.c` / `subnet.h`:
```c
typedef struct {
    char network[INET_ADDRSTRLEN];
    char broadcast[INET_ADDRSTRLEN];
    char netmask[INET_ADDRSTRLEN];
    char first_usable[INET_ADDRSTRLEN];
    char last_usable[INET_ADDRSTRLEN];
    uint32_t usable_hosts;
    int prefix_len;
} subnet_info_t;

int subnet_calculate(const char *cidr, subnet_info_t *out); // "192.168.1.10/26" -> fills out
void subnet_print(const subnet_info_t *info);
```
- Pure integer/bitwise arithmetic on the 32-bit IPv4 address, no dependency
  on external subnetting libraries.
- Exposed via `cshark --subnet <CIDR>`.

### 3.4 Python AI/ML-Assisted Anomaly Triage
**Why**: directly demonstrates "interest in understanding how AI/ML can be
applied to network operations, monitoring, security, automation, and
analytics" and "Scripting and Automation: Python" from the JD. This is
explicitly a *second, complementary* detection layer — the C rule-based
detectors in §2 catch known signatures (port scan, ARP spoof) deterministically;
this script does unsupervised outlier scoring over flow statistics to catch
things that don't match a fixed rule, and is meant to reduce manual log review.

**Design** — new directory `tools/`, script `tools/anomaly_detect.py`:
- Input: the CSV produced by `export_session_csv()` (and optionally
  `alerts.csv` from `export_alerts_csv()` for cross-referencing).
- Aggregates rows into per-source-IP feature vectors: packet count, distinct
  destination ports, distinct destination IPs, total bytes, mean packet
  size, SYN-only packet ratio.
- Primary path: `sklearn.ensemble.IsolationForest` if `scikit-learn` is
  installed (see `tools/requirements.txt`).
- Fallback path (zero dependencies): a robust modified z-score
  (median + MAD) across the same feature vectors, so the script still runs
  with only the Python standard library.
- Output: a ranked table of the most anomalous source IPs with the
  contributing features, printed to stdout, plus `--json <path>` to dump the
  same result machine-readably. Cross-references and marks IPs that were
  also flagged by `detect.c`'s rule-based alerts.
- Must not crash or hang on empty/small input files — validate and print a
  clear message instead.

### 3.5 PowerShell Automation Script
**Why**: demonstrates "Scripting and Automation: PowerShell" concretely, and
mirrors the kind of runbook a cloud network engineer writes to orchestrate a
capture -> export -> analyze -> report pipeline (the same shape as an Azure
Automation runbook or DevOps pipeline step).

**Design** — new directory `scripts/`, script `scripts/Invoke-CSharkWorkflow.ps1`
(PowerShell 7+/`pwsh`, cross-platform):
- Parameters: `-Interface`, `-DurationSeconds` (default 30), `-OutputDir`
  (default `./reports/<timestamp>/`).
- Steps: `make` build (if binary missing/stale) -> run
  `sudo ./cshark -i <Interface> -t <DurationSeconds> -o session.csv --pcap session.pcap`
  -> invoke `python3 tools/anomaly_detect.py` on the resulting CSV -> merge
  the rule-based alert log and the ML anomaly output into one timestamped
  Markdown report under `-OutputDir`.
- Must fail loudly (non-zero exit code, clear `Write-Error`) if the build,
  capture, or analysis step fails — this is meant to be usable as a CI/cron
  step, not just an interactive convenience script.

## 4. Codebase Conventions

- Directory layout: C sources live in `src/`, headers in `include/`
  (compiled with `-Iinclude`), tests in `tests/`, and the Python/PowerShell
  automation layers in `tools/`/`scripts/`. Keep new C modules in this split
  rather than reintroducing a flat root directory.
- Pure C (C99), built via the existing `Makefile` (`make`, `make clean`,
  `make rebuild`). Do not introduce CMake, Meson, or other build systems for
  the C tool. The Python/PowerShell additions in §3.4/§3.5 are separate,
  optional orchestration layers on top of the compiled binary — they must
  never become a build-time dependency of `cshark` itself.
- No external C dependencies beyond `libpcap` (already required). The hash
  tables for detection must be hand-rolled, consistent with the project's
  "zero external libraries beyond libpcap" philosophy.
- Match existing style: modular `.c`/`.h` pairs per concern, header guards,
  functions documented with a short comment block matching the style seen
  in `capture.h`/`packet_parser.h`.
- Update `README.md`'s Features/Architecture sections to document every new
  module once implemented (do not leave the README stale).
- Free all dynamically allocated memory on `detect_cleanup()` — this project
  cares about memory-leak discipline (see `storage.c`'s deep-copy/free
  pattern for reference).

## 5. Acceptance Checklist

- [x] `detect.c` / `detect.h` added and wired into `Makefile`
- [x] Port-scan detection implemented with 5s sliding window, 15-port threshold
- [x] ARP-spoof detection implemented via IP→MAC binding table
- [x] Alerts printed live during capture, and viewable post-capture via inspection menu
- [ ] Validated against real `nmap` (port scan) and `arpspoof`/`ettercap` (ARP) tests in a lab/VM
      (**not done in this environment** — no root/NIC access or `nmap`/`arpspoof` available in
      this sandbox; needs to be run by whoever has a lab VM before citing exact numbers on a resume)
- [x] No obvious memory leaks (manual audit of every `malloc`/`free` pair; run
      `valgrind --leak-check=full` on a live capture before shipping, since libpcap
      capture can't be fully exercised in this sandbox)
- [x] README updated to document the new modules
- [x] `export.c`/`export.h` (CSV + real PCAP export) implemented and wired into menu + CLI
- [x] `subnet.c`/`subnet.h` (subnet calculator) implemented and exposed via `--subnet`
- [x] Headless/scriptable capture mode (`-i/-t/-o/--pcap/--filter/--list-interfaces/--help`) added to `main.c`
- [x] `tools/anomaly_detect.py` implemented with sklearn + dependency-free fallback paths
- [x] `scripts/Invoke-CSharkWorkflow.ps1` implemented (written for `pwsh`; not executable in this
      sandbox since `pwsh` isn't installed here — syntax should be validated with `pwsh -File` before relying on it)
- [ ] Resume bullet's specific numbers (15+ ports/5s) reconciled with actual tested thresholds
      once real `nmap`/`arpspoof` validation (above) has been run

## 6. JD-to-Artifact Traceability (for interview prep, not for the README)

| JD line | Concrete artifact |
|---|---|
| OSI model, IP addressing/subnetting | `packet_parser.c` (L2-L7 dissection) + `subnet.c` (`--subnet` calculator) |
| Basic internetworking routing/switching | ARP binding table in `detect.c` (IP→MAC resolution is exactly what a switch's ARP table / router's neighbor table does) |
| Cloud computing / Azure / VNets / cloud security / identity | README section mapping `export.c`'s CSV to NSG flow logs and PCAP export to Network Watcher packet capture; explicitly *not* claiming real Azure integration |
| PowerShell / Python scripting | `scripts/Invoke-CSharkWorkflow.ps1`, `tools/anomaly_detect.py` |
| Wireshark / Azure Network Watcher / diagnostics | `export_session_pcap()` (real Wireshark-openable output), `detect.c` alert log (diagnostic signal) |
| AI/ML in network ops/security/analytics | `tools/anomaly_detect.py` (IsolationForest + statistical fallback over flow features) |
| Automated testing / large-scale network validation | `main.c` headless mode (§3.1), designed to be driven by CI or the PowerShell runbook |
