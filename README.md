# C-Shark: The Command-Line Packet Predator 🦈

A comprehensive terminal-based network packet sniffer and analyzer built in C using libpcap. C-Shark captures, parses, filters, stores, and provides detailed forensic analysis of network packets across all OSI layers.

---

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Relevance to Cloud/Network Engineering](#relevance-to-cloudnetwork-engineering)
- [Architecture & Design](#architecture--design)
- [Network Concepts](#network-concepts)
- [Security Detection](#security-detection)
- [Export & Interoperability](#export--interoperability)
- [Headless / Scriptable Capture Mode](#headless--scriptable-capture-mode)
- [AI/ML Anomaly Triage (Python)](#aiml-anomaly-triage-python)
- [Automation Runbook (PowerShell)](#automation-runbook-powershell)
- [File Structure](#file-structure)
- [Implementation Details](#implementation-details)
- [Build & Usage](#build--usage)
- [Technical Concepts Used](#technical-concepts-used)

---

## Overview

C-Shark is a professional-grade packet analyzer that provides:
- **Live packet capture** on any network interface
- **Layer-by-layer protocol analysis** (OSI Layers 2-7)
- **BPF filtering** for targeted packet capture
- **Session storage** for forensic analysis
- **Interactive inspection** with comprehensive packet breakdown
- **Real-time security detection** for port scans and ARP spoofing
- **Export to CSV/PCAP** for interop with Wireshark and downstream analysis
- **A headless CLI mode** plus companion Python/PowerShell tooling for
  automated, scriptable network validation

The tool demonstrates advanced systems programming concepts including network programming, memory management, signal handling, and modular software architecture.

---

## Features

### ✅ Core Capabilities
- Network interface discovery and selection
- Real-time packet capture with live display
- Protocol filtering (HTTP, HTTPS, DNS, ARP, TCP, UDP)
- Session storage (up to 10,000 packets in RAM)
- Interactive packet inspection with detailed analysis
- Complete packet hex dump
- Graceful interrupt handling (Ctrl+C, Ctrl+D)
- IPv4 subnet calculator (`--subnet <CIDR>`)

### ✅ Security Detection
- **Port-scan detection**: flags a source IP contacting 15+ distinct destination ports within a 5-second window
- **ARP-spoof detection**: flags an IP's bound MAC address changing between ARP replies (classic cache-poisoning signature)
- Live, color-highlighted `[ALERT]` output plus a post-capture "View Security Alerts" menu

### ✅ Export & Automation
- CSV flow export (Azure NSG flow-log-style 5-tuple rows) and CSV alert export
- Real `.pcap` export, openable directly in Wireshark/tcpdump
- Headless/scriptable CLI mode for CI and automated network validation
- Companion Python AI/ML anomaly-triage script and PowerShell automation runbook

### ✅ Protocol Support
- **Data Link Layer (L2)**: Ethernet
- **Network Layer (L3)**: IPv4, IPv6, ARP
- **Transport Layer (L4)**: TCP, UDP
- **Application Layer (L7)**: HTTP, HTTPS, DNS

---

## Relevance to Cloud/Network Engineering

This project intentionally exercises the fundamentals behind cloud network
engineering roles, even though it's a local CLI tool rather than an Azure
service. The mapping below is deliberately honest about what's real local
implementation versus what's a documented analogy:

| Skill area | What C-Shark does |
|---|---|
| OSI model, IP addressing & subnetting | Full L2-L7 packet dissection (`packet_parser.c`) plus a standalone subnet calculator (`subnet.c`, `--subnet <CIDR>`) |
| Basic internetworking routing/switching | The ARP IP→MAC binding table in `detect.c` implements the same neighbor-resolution bookkeeping a switch/router performs |
| Cloud security fundamentals | Real-time intrusion heuristics (port-scan, ARP-spoof) with a persistent alert log - conceptually the same job as Azure Network Watcher/Defender for Cloud alerts, implemented locally |
| Azure Network Watcher / Wireshark-style diagnostics | `export_session_pcap()` produces a real `.pcap` openable in Wireshark; `export_session_csv()` produces NSG-flow-log-shaped CSV rows |
| PowerShell / Python scripting & automation | `scripts/Invoke-CSharkWorkflow.ps1` (capture → export → analyze → report pipeline) and `tools/anomaly_detect.py` |
| AI/ML in network operations & analytics | `tools/anomaly_detect.py` - unsupervised outlier scoring (IsolationForest, with a dependency-free statistical fallback) over per-source-IP flow statistics |
| Automated testing / large-scale network validation | Headless CLI mode (`-i/-t/-o/--pcap`) makes capture scriptable/CI-friendly instead of menu-only |

See `PLAN.md` for the full traceability table and the reasoning behind each addition.

---

## Architecture & Design

### Design Principles

C-Shark follows a **modular, layered architecture** with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│                    Main Application                      │
│                     (main.c)                            │
└─────────────────┬───────────────────────────────────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
   ┌────▼─────┐      ┌─────▼──────┐
   │ Interface│      │  Capture   │
   │ Discovery│      │  Engine    │
   └────┬─────┘      └─────┬──────┘
        │                  │
        │            ┌─────▼──────┐
        │            │   Packet   │
        │            │   Parser   │
        │            └─────┬──────┘
        │                  │
   ┌────▼─────┐      ┌─────▼──────┐      ┌──────────┐
   │ Display  │◄─────┤  Storage   │◄─────┤ Filter   │
   │ Module   │      │  Manager   │      │  Engine  │
   └────┬─────┘      └─────┬──────┘      └──────────┘
        │                  │
        │            ┌─────▼──────┐
        └────────────┤ Inspection │
                     │  Module    │
                     └────────────┘
```

### Architectural Components

#### 1. **Interface Discovery Layer**
- Enumerates available network interfaces using `pcap_findalldevs()`
- Presents user-friendly selection menu
- Handles interface descriptions and metadata

#### 2. **Capture Engine**
- Opens network interface in promiscuous mode
- Configures packet capture parameters (snap length, timeout)
- Implements BPF (Berkeley Packet Filter) compilation and application
- Manages capture loop with interrupt handling

#### 3. **Packet Parser**
- **Layer-by-layer parsing** following OSI model
- Extracts header fields at each protocol layer
- Handles multiple protocol stacks (IPv4/IPv6, TCP/UDP)
- Identifies application protocols based on port numbers

#### 4. **Filter Engine**
- Generates BPF filter expressions
- Supports protocol-specific filtering
- Kernel-level filtering for efficiency (no userspace overhead)

#### 5. **Storage Manager**
- Non-persistent RAM-based storage
- Deep copy of packet data to avoid dangling pointers
- Dynamic memory allocation with MAX_PACKETS capacity
- Automatic cleanup between sessions

#### 6. **Display Module**
- Real-time packet display during capture
- Formatted output for each protocol layer
- Hex dump functionality with ASCII representation
- Professional UI with box-drawing characters

#### 7. **Inspection Module**
- Interactive packet selection from stored session
- Comprehensive packet breakdown
- Full hex dump of entire packet frame
- Forensic-level detail for analysis
- "View Security Alerts" and "Export Session Data" menu entries

#### 8. **Detection Module**
- Two hand-rolled hash tables (no external deps): port-scan tracker keyed by
  source IP, ARP IP→MAC binding table
- Runs inline in `packet_handler()` on every captured packet
- Raises alerts both live (colored `[ALERT]` line) and into an in-memory log

#### 9. **Export Module**
- CSV flow export, CSV alert export, and real `.pcap` export via `pcap_dump*`
- Bridges C-Shark to Wireshark and to the Python analysis tooling

#### 10. **Subnet Module**
- Standalone IPv4 CIDR subnet calculator, usable without root or a capture session

---

## Network Concepts

### OSI Model & Protocol Stack

C-Shark analyzes packets following the OSI model layers:

#### **Layer 2 - Data Link (Ethernet)**
- **MAC Addresses**: 48-bit hardware addresses (6 bytes)
- **EtherType**: Protocol identifier (0x0800=IPv4, 0x86DD=IPv6, 0x0806=ARP)
- **Frame Structure**: 14-byte header (6-byte dest MAC, 6-byte src MAC, 2-byte type)

#### **Layer 3 - Network**

**IPv4 (Internet Protocol version 4)**
- 32-bit addresses (4 bytes, dotted decimal notation)
- Header fields: Version, IHL, TTL, Protocol, Checksum, Source/Dest IP
- Fragment flags: DF (Don't Fragment), MF (More Fragments)
- Total length, identification for reassembly

**IPv6 (Internet Protocol version 6)**
- 128-bit addresses (16 bytes, hexadecimal notation)
- Simplified header: Version, Traffic Class, Flow Label, Payload Length
- Next Header field (equivalent to IPv4 protocol field)
- Hop Limit (equivalent to IPv4 TTL)

**ARP (Address Resolution Protocol)**
- Maps IP addresses to MAC addresses
- Operations: Request (1), Reply (2)
- Contains sender/target MAC and IP addresses
- Hardware and protocol type/length fields

#### **Layer 4 - Transport**

**TCP (Transmission Control Protocol)**
- Connection-oriented, reliable delivery
- Sequence/Acknowledgment numbers for ordering and reliability
- Flags: SYN (synchronize), ACK (acknowledge), PSH (push), FIN (finish), RST (reset), URG (urgent)
- Window size for flow control
- Checksum for error detection

**UDP (User Datagram Protocol)**
- Connectionless, best-effort delivery
- Minimal overhead (8-byte header)
- No reliability mechanisms
- Used for DNS, streaming, gaming

#### **Layer 7 - Application**
- **HTTP** (Port 80): Unencrypted web traffic
- **HTTPS** (Port 443): TLS-encrypted web traffic
- **DNS** (Port 53): Domain name resolution

### Packet Capture Technology

#### **Promiscuous Mode**
- Network interface accepts ALL packets on the network
- Not just packets addressed to its MAC
- Required for comprehensive network monitoring
- Requires root/administrator privileges

#### **BPF (Berkeley Packet Filter)**
- In-kernel packet filtering language
- Compiled expressions for efficient filtering
- Filters packets before they reach userspace
- Examples:
  - `tcp port 443` - HTTPS traffic
  - `arp` - Only ARP packets
  - `udp port 53` - DNS queries

#### **Packet Structures**
Packets are parsed as layered structures:
```
[Ethernet Header | IP Header | TCP/UDP Header | Application Data]
     14 bytes    | 20-60 bytes|   8-60 bytes   |   Variable
```

---

## Security Detection

C-Shark runs two rule-based, real-time heuristics on every captured packet
(`detect.c`), independent of the OSI-layer display:

### Port-Scan Detection
Flags a source IP as a probable port-scanner if it contacts **15 or more
distinct destination ports within a 5-second sliding window**. Implemented
as a hand-rolled hash table (1024 buckets, chained) keyed by source IP, each
holding a small dynamic array of `{port, timestamp}` observations that gets
pruned to the active window on every packet. Re-alerts for the same source
are suppressed for 30 seconds to avoid log spam.

### ARP-Spoof Detection
Maintains an IP → MAC binding table populated only from ARP **replies**. If
an IP's bound MAC changes between replies, it raises an alert with both the
old and new MAC — the classic ARP cache-poisoning signature. Gratuitous
replies from the *same* MAC are not flagged; only an actual binding change is.

### Alerts
Alerts print live, interleaved with packet output, prefixed with a
bold-red `[ALERT]` tag, and are also retained in an in-memory log for the
current session — viewable afterward via the main menu's **"View Security
Alerts"** option, or exported to CSV (see below).

> **Validating this yourself**: this was implemented and regression-tested
> with synthetic packet fixtures (`make test`, see `tests/test_detect.c`),
> but has *not* been validated against real `nmap`/`arpspoof` traffic in
> this environment (no root/NIC access or those tools available in this
> sandbox). Before citing "detects port scans" on a resume, run it against
> `nmap -sS -p 1-100 <target>` and `arpspoof` in a lab VM you control, and
> confirm the alert output looks correct end-to-end.

---

## Export & Interoperability

`export.c` writes the current session out in formats other tools understand:

| Function | Output | Use case |
|---|---|---|
| `export_session_csv()` | `packet_id,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,length,tcp_flags,info` | Same shape as an **Azure NSG flow log** (5-tuple + bytes); feeds `tools/anomaly_detect.py` |
| `export_alerts_csv()` | `timestamp,type,details` | Feeds the alert cross-reference in `tools/anomaly_detect.py` |
| `export_session_pcap()` | A real `.pcap` file via `pcap_dump*` | Open directly in **Wireshark** or `tcpdump -r` |

Reachable interactively via the main menu's **"Export Session Data"**
option, or non-interactively via the `-o`/`--pcap` CLI flags (see below).

---

## Headless / Scriptable Capture Mode

Everything above is also reachable without the interactive menu, so C-Shark
can be driven from scripts, cron, or CI — the same shape as automated network
validation pipelines:

```bash
# Capture on eth0 for 60 seconds, export flows + a real pcap, then exit
sudo ./cshark -i eth0 -t 60 -o session_flows.csv --pcap session.pcap

# Same, but only TCP traffic
sudo ./cshark -i eth0 -t 60 --filter tcp -o session_flows.csv

# List interfaces without needing to capture
./cshark --list-interfaces

# Subnet calculator - no root needed
./cshark --subnet 10.0.0.0/24
```

The timed stop is implemented with `alarm()` + `SIGALRM`, reusing the exact
same `capture_interrupted` flag as Ctrl+C, so `capture.c`'s capture loop
needed no structural changes. Alerts and a session summary print to stdout
on exit, so headless runs are log-friendly.

Run `./cshark --help` for the full flag reference.

---

## AI/ML Anomaly Triage (Python)

`tools/anomaly_detect.py` is a second, complementary detection layer on top
of `detect.c`'s deterministic rules. It aggregates the CSV flow export into
per-source-IP feature vectors (packet count, distinct destination ports,
distinct destination IPs, total bytes, mean packet size, SYN-only ratio) and
scores them for outliers:

- **With `scikit-learn` installed** (`pip install -r tools/requirements.txt`):
  uses `IsolationForest`.
- **With zero dependencies**: falls back to a robust modified z-score
  (median + MAD) across the same features — the script never hard-fails
  for lack of a Python package.

It also cross-references its ranking against `detect.c`'s alert log, so you
can see where the rule-based and ML-based layers agree.

```bash
python3 tools/anomaly_detect.py session_flows.csv \
    --alerts session_alerts.csv \
    --top 10 \
    --json anomalies.json
```

This is explicitly scoped as *triage assistance*, not a black-box claim —
the output shows the raw features behind every score so a human can verify
the reasoning.

---

## Automation Runbook (PowerShell)

`scripts/Invoke-CSharkWorkflow.ps1` (PowerShell 7+/`pwsh`, cross-platform)
chains the pieces above into one command — build → timed capture → export →
Python analysis → a single Markdown report:

```bash
sudo pwsh ./scripts/Invoke-CSharkWorkflow.ps1 -Interface eth0 -DurationSeconds 60
```

It fails loudly (non-zero exit, `Write-Error`) at the first broken step, so
it's meant to be wired into CI/cron rather than only run interactively — the
same shape as an Azure Automation runbook or DevOps pipeline step for
periodic network health checks.

---

## File Structure

```
cshark/
├── src/            # All .c implementation files
├── include/        # All .h header files (compiled with -Iinclude)
├── build/          # Object files (created by `make`, gitignored)
├── tests/          # Regression tests (make test)
├── tools/          # Python AI/ML analysis tooling
├── scripts/        # PowerShell automation runbook
├── Makefile
├── README.md
└── PLAN.md
```

Section headings below refer to files by name only (e.g. `main.c`); the
actual paths are `src/main.c` and `include/*.h` as laid out above.

### Core Application Files

#### **main.c** (in `src/`)
**Purpose**: Entry point, CLI argument parsing, and main application controller
- Initializes signal handlers
- Parses CLI flags for headless/scriptable mode (see "Headless / Scriptable Capture Mode")
- Manages main menu loop
- Orchestrates all modules
- Handles user interaction flow
- Cleanup on exit

**Key Functions**:
- `main()` - Program entry, CLI parsing, menu loop
- Menu handling for all 6 options (capture, filtered capture, inspect, view alerts, export, exit)

---

#### **cshark.h** (in `include/`)
**Purpose**: Central header file with common includes and constants
- Defines MAX_PACKETS (10,000)
- Includes all standard libraries
- Includes network headers (pcap, ethernet, IP, TCP/UDP)
- Central include point for all modules

**Key Constants**:
- `MAX_PACKETS 10000` - Storage capacity
- `SNAP_LEN 65535` - Maximum packet capture size
- `PROMISC_MODE 1` - Enable promiscuous mode
- `TIMEOUT_MS 1000` - Capture timeout

---

### Interface Discovery Module

#### **interface.c/h** (95 lines)
**Purpose**: Network interface enumeration and selection

**Key Functions**:
- `discover_interfaces()` - Uses `pcap_findalldevs()` to enumerate interfaces
- `display_interfaces()` - Formats and displays interface list
- `select_interface()` - Handles user input with validation
- `free_interfaces()` - Cleans up interface list

**Concepts Used**:
- pcap device enumeration
- Linked list traversal
- Dynamic memory management
- Input validation

---

### Packet Capture Module

#### **capture.c/h** (177 lines)
**Purpose**: Core packet capture engine

**Key Functions**:
- `init_capture()` - Opens pcap handle, applies BPF filters
- `start_sniffing_all()` - Captures all packets
- `start_sniffing_filtered()` - Captures with BPF filter
- `packet_handler()` - Callback for each captured packet
- `stop_capture()` - Closes pcap handle gracefully

**Concepts Used**:
- libpcap programming
- BPF filter compilation and application
- Callback functions
- Signal handling integration
- Network interface configuration

**Technical Details**:
- Opens interface in promiscuous mode
- Sets snap length to capture full packets
- Configures read timeout
- Compiles and applies BPF filters at kernel level
- Stores packets for later inspection

---

### Packet Parser Module

#### **packet_parser.c/h** (207 lines)
**Purpose**: Layer-by-layer protocol parsing

**Data Structures**:
- `parsed_packet_t` - Complete packet information structure
- Union for protocol-specific data (IPv4/IPv6/ARP, TCP/UDP)

**Key Functions**:
- `parse_packet()` - Main parsing coordinator
- `parse_ethernet()` - Extracts Ethernet header
- `parse_ipv4()` - Parses IPv4 header fields
- `parse_ipv6()` - Parses IPv6 header fields
- `parse_arp()` - Parses ARP packet
- `parse_tcp()` - Parses TCP header and flags
- `parse_udp()` - Parses UDP header
- `parse_payload()` - Identifies application protocol

**Concepts Used**:
- Pointer arithmetic for header navigation
- Network byte order conversion (ntohs, ntohl)
- Structure casting for protocol headers
- Protocol identification based on port numbers
- Binary flag manipulation

**Parsing Logic**:
1. Start with Ethernet header (offset 0)
2. Determine L3 protocol from EtherType
3. Parse L3 header, determine L4 protocol
4. Parse L4 header, extract port info
5. Identify application protocol from ports
6. Extract payload data

---

### Display Module

#### **display.c/h** (355 lines)
**Purpose**: Formatted output and visualization

**Key Functions**:
- `display_banner()` - Welcome screen
- `display_main_menu()` - Menu interface
- `display_packet_live()` - Real-time packet display
- `display_packet_detailed()` - Comprehensive packet analysis
- `display_layer2/3/4/7()` - Layer-specific display
- `display_hex_dump()` - Hex/ASCII dump
- `display_mac_address()` - MAC address formatting
- `get_port_service()` - Port to service name mapping

**Concepts Used**:
- Formatted console output
- Box-drawing characters (Unicode)
- Hex dump generation
- Protocol name resolution
- ASCII character filtering (isprint)

**Display Features**:
- Color-coded headers (via box characters)
- Aligned tabular data
- Hex + ASCII side-by-side
- Human-readable protocol names
- Service name resolution for common ports

---

### Filter Module

#### **filter.c/h** (129 lines)
**Purpose**: BPF filter generation and management

**Key Functions**:
- `select_filter()` - Interactive filter menu
- `generate_filter_expression()` - Creates BPF expressions
- `get_filter_name()` - Human-readable filter names
- `packet_matches_filter()` - Post-capture filtering

**Filter Types**:
- HTTP: `tcp port 80`
- HTTPS: `tcp port 443`
- DNS: `port 53` (both TCP and UDP)
- ARP: `arp`
- TCP: `tcp`
- UDP: `udp`

**Concepts Used**:
- BPF expression syntax
- String manipulation
- Protocol filtering logic
- Menu-driven interface

**Technical Notes**:
- Filters applied at kernel level for efficiency
- No CPU overhead for non-matching packets
- Standard tcpdump/Wireshark syntax
- Easily extensible for custom filters

---

### Storage Module

#### **storage.c/h** (118 lines)
**Purpose**: Session packet storage and retrieval

**Data Structure**:
```c
typedef struct {
    parsed_packet_t *packets;  // Dynamic array
    uint32_t count;            // Current count
    uint32_t capacity;         // Max capacity
} packet_session_t;
```

**Key Functions**:
- `storage_init_session()` - Allocates memory for new session
- `storage_add_packet()` - Deep copies packet to storage
- `storage_get_packet()` - Retrieves packet by index
- `storage_get_count()` - Returns packet count
- `storage_clear_session()` - Frees all memory
- `storage_has_session()` - Checks if session exists

**Concepts Used**:
- Dynamic memory allocation (malloc/free)
- Deep copying to avoid dangling pointers
- Static global state management
- Memory leak prevention
- Pointer offset calculation for payload

**Memory Management**:
- Allocates space for MAX_PACKETS at session start
- Deep copies raw packet data
- Recalculates payload pointers in copied data
- Frees old session before starting new one
- Ensures no memory leaks on exit

---

### Inspection Module

#### **inspection.c/h** (134 lines)
**Purpose**: Interactive packet inspection interface

**Key Functions**:
- `inspect_session()` - Main inspection loop
- `list_session_packets()` - Displays packet summary table
- `inspect_packet_detailed()` - Shows detailed analysis

**Concepts Used**:
- Interactive user interface
- Table formatting
- Packet indexing
- Error handling for invalid IDs
- Session validation

**Features**:
- Lists up to 50 packets at a time
- Shows packet ID, timestamp, length, protocol, connection info
- Allows selection by packet ID
- Validates input
- Repeatable inspection (view multiple packets)

---

### Utility Module

#### **utils.c/h** (128 lines)
**Purpose**: Helper functions and signal handling

**Key Functions**:
- `setup_signal_handlers()` - Configures SIGINT handler
- `handle_sigint()` - Ctrl+C handler (stops capture, doesn't exit)
- `get_user_choice()` - Input validation
- `clear_input_buffer()` - Clears stdin
- `format_timestamp()` - Timestamp formatting
- `decode_tcp_flags()` - TCP flag decoding
- `calculate_checksum()` - Checksum computation

**Concepts Used**:
- Signal handling (sigaction)
- Volatile sig_atomic_t for signal safety
- Input validation and sanitization
- String formatting
- Binary flag manipulation

**Signal Handling**:
- Ctrl+C (SIGINT): Sets flag, returns to menu
- Ctrl+D (EOF): Exits application
- Non-blocking capture loop
- Clean interrupt handling

---

### Detection Module

#### **detect.c/h**
**Purpose**: Real-time port-scan and ARP-spoof heuristics

**Key Functions**:
- `detect_init()` / `detect_cleanup()` - session lifecycle (mirrors `storage_init_session()`/`storage_clear_session()`)
- `detect_port_scan_observe()` - hash-table-backed sliding-window port-scan tracker
- `detect_arp_spoof_observe()` - IP→MAC binding table with change detection
- `detect_print_alert()` - live alert output + append to the in-memory alert log
- `detect_get_alert_count()` / `detect_get_alert()` - accessors for post-capture review

**Concepts Used**:
- Hand-rolled chained hash tables (djb2 string hashing, Fibonacci hashing for IPs)
- Sliding-window pruning over dynamic arrays
- Alert-log pattern separate from packet storage (survives `detect_cleanup()`)

---

### Export Module

#### **export.c/h**
**Purpose**: Session export to CSV (flows, alerts) and real `.pcap`

**Key Functions**:
- `export_session_csv()` - Azure-NSG-flow-log-style CSV of every stored packet
- `export_alerts_csv()` - CSV of the security alert log
- `export_session_pcap()` - real pcap file via `pcap_open_dead()` + `pcap_dump_open()`/`pcap_dump()`

**Concepts Used**:
- libpcap's "dead handle" pattern for writing pcap files without a live capture
- CSV field quoting/escaping for free-text columns

---

### Subnet Module

#### **subnet.c/h**
**Purpose**: Standalone IPv4 CIDR subnet calculator

**Key Functions**:
- `subnet_calculate()` - parses `a.b.c.d/prefix`, computes network/broadcast/usable range
- `subnet_print()` - formatted output

**Concepts Used**:
- Pure bitwise arithmetic on 32-bit host-order addresses
- RFC 3021 special-casing for /31 and /32

---

### Companion Tooling (outside the C build)

#### **tools/anomaly_detect.py**
Python AI/ML-assisted anomaly triage over the CSV flow export - see
[AI/ML Anomaly Triage](#aiml-anomaly-triage-python) above.

#### **scripts/Invoke-CSharkWorkflow.ps1**
PowerShell automation runbook chaining build → capture → export → analysis →
report - see [Automation Runbook](#automation-runbook-powershell) above.

#### **tests/test_detect.c**
Regression test for `detect.c` using synthetic `parsed_packet_t` fixtures
(no root/NIC required). Run via `make test`.

---

## Implementation Details

### Memory Management Strategy

#### Packet Storage
1. **Allocation**: Single malloc for MAX_PACKETS array
2. **Deep Copy**: Each packet's raw data is separately allocated
3. **Pointer Fixup**: Payload pointers recalculated for copied data
4. **Cleanup**: All memory freed on new session or exit

#### Memory Safety
- No global packet data (stored in storage module)
- No dangling pointers (deep copy ensures independence)
- Proper cleanup on all exit paths
- Error handling for malloc failures

### Concurrency & Signal Safety

#### Signal Handling Design
```c
volatile sig_atomic_t capture_interrupted = 0;

void handle_sigint(int sig) {
    capture_interrupted = 1;  // Signal-safe flag
}

// In capture loop:
while (!capture_interrupted) {
    // Capture packets
}
```

- Uses `sig_atomic_t` for signal safety
- Non-blocking capture loop checks flag
- Clean shutdown on interrupt
- No race conditions

### Error Handling

#### Robust Error Handling
- pcap errors: Checked and reported with pcap_geterr()
- Memory allocation: NULL checks on all malloc calls
- Input validation: Range checking, EOF handling
- Invalid packet IDs: Bounds checking
- Session validation: Checks before inspection

---

## Build & Usage

### Prerequisites
```bash
# Install libpcap development headers (required for the C tool)
sudo apt-get install libpcap-dev

# For other distros:
# sudo yum install libpcap-devel      # RHEL/CentOS
# sudo pacman -S libpcap              # Arch
```

Optional, only needed for the companion tooling:
- **Python 3** for `tools/anomaly_detect.py` (runs with zero extra packages;
  `pip install -r tools/requirements.txt` upgrades it to use scikit-learn)
- **PowerShell 7+ (`pwsh`)** for `scripts/Invoke-CSharkWorkflow.ps1`

### Build Instructions
```bash
# Clone and enter the repo
git clone https://github.com/vishakkashyapk30/cshark.git
cd cshark

# Build the project (sources in src/, headers in include/, binary in build/)
make

# Clean build artifacts
make clean

# Rebuild from scratch
make rebuild

# Install dependencies (Ubuntu/Debian)
make install-deps
```

### Running C-Shark
```bash
# Run with sudo (required for packet capture)
sudo ./cshark

# Or use make run
make run
```

### Usage Flow
1. **Select Interface**: Choose from discovered network interfaces
2. **Choose Action**:
   - Option 1: Capture all packets (live display)
   - Option 2: Capture with filter (select protocol)
   - Option 3: Inspect last session (view stored packets)
   - Option 4: View security alerts (port-scan / ARP-spoof) from the last session
   - Option 5: Export session data (CSV flows, CSV alerts, or `.pcap`)
   - Option 6: Exit application
3. **During Capture**:
   - View packets in real-time, with `[ALERT]` lines interleaved if a
     port-scan or ARP-spoof signature is detected
   - Press Ctrl+C to stop capture
   - Packets stored for later inspection
4. **Inspection**:
   - View summary of all captured packets
   - Select packet by ID for detailed analysis
   - View complete packet breakdown

### Non-Interactive / Automated Usage
For scripting, CI, or validation pipelines, skip the menu entirely - see
[Headless / Scriptable Capture Mode](#headless--scriptable-capture-mode) and
the companion [Python](#aiml-anomaly-triage-python) and
[PowerShell](#automation-runbook-powershell) tooling above.

---

## Technical Concepts Used

### Systems Programming
- **Process Management**: Signal handling, interrupt handling
- **Memory Management**: Dynamic allocation, deep copying, leak prevention
- **File Descriptors**: Network interface file descriptors via pcap
- **Error Handling**: Comprehensive error checking and reporting

### Network Programming
- **Raw Packet Access**: Via libpcap
- **Promiscuous Mode**: Capture all network traffic
- **BPF Filters**: Kernel-level packet filtering
- **Protocol Parsing**: Multi-layer packet dissection
- **Byte Order**: Network (big-endian) to host byte order conversion

### Data Structures
- **Arrays**: Static and dynamic packet storage
- **Structures**: Protocol headers, parsed packet info
- **Unions**: Protocol-specific data (IPv4/IPv6/ARP, TCP/UDP)
- **Linked Lists**: Interface enumeration (pcap_if_t)
- **Pointers**: Extensive pointer manipulation for parsing

### Algorithms
- **Parsing**: Layer-by-layer protocol parsing
- **Checksum Calculation**: TCP/UDP/IP checksum verification
- **String Manipulation**: Formatting, conversion, display
- **Bit Manipulation**: Flag extraction, field parsing

### Software Engineering
- **Modular Design**: Separation of concerns, single responsibility
- **Encapsulation**: Module-specific state and functions
- **Abstraction**: Clean interfaces between modules
- **Documentation**: Comprehensive inline comments
- **Error Handling**: Defensive programming, validation

### Networking Concepts
- **OSI Model**: 7-layer network model
- **TCP/IP Stack**: Internet protocol suite
- **Ethernet**: Layer 2 framing
- **IP Routing**: IPv4/IPv6 addressing
- **Port Numbers**: Application identification
- **Protocol Headers**: Structure and fields
- **Packet Fragmentation**: IP fragmentation flags
- **Flow Control**: TCP window size
- **Checksums**: Error detection

---

## Performance Considerations

### Efficiency Optimizations
1. **Kernel-Level Filtering**: BPF filters reduce userspace overhead
2. **Direct Memory Access**: Minimal copying via pcap
3. **Efficient Parsing**: Single-pass layer parsing
4. **Static Buffers**: Avoid repeated allocations where possible
5. **Lazy Evaluation**: Only parse when displaying

### Scalability
- **Capacity**: 10,000 packets stored (configurable via MAX_PACKETS)
- **Memory Usage**: ~200MB for full capacity (depends on packet sizes)
- **Capture Rate**: Limited only by network speed and libpcap
- **Display Rate**: Real-time for typical network loads

---

## Future Enhancements

Possible extensions (not implemented):
- PCAP file **import** (export already implemented - see `export_session_pcap()`)
- Advanced filtering (compound BPF expressions)
- Live traffic statistics/analytics (top-talkers, bandwidth-over-time)
- Protocol-specific parsing (HTTP headers, DNS queries)
- Multi-threaded capture for high-speed networks
- TLS decryption with private keys
- Packet replay capabilities
- Time-bucketed (rather than whole-session) features in `tools/anomaly_detect.py`
  for longer-running captures

See `PLAN.md` for the reasoning behind what was prioritized in this iteration.

---

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Solution: Run with sudo
sudo ./cshark
```

**No interfaces found**
```bash
# Check if libpcap is installed
dpkg -l | grep libpcap

# Install if missing
sudo apt-get install libpcap-dev
```

**Compilation errors**
```bash
# Ensure all dependencies are installed
make install-deps

# Clean rebuild
make clean && make
```
---

**End of Documentation** 🦈

