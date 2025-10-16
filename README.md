# C-Shark: The Command-Line Packet Predator 🦈

A modular terminal-based packet sniffer built with libpcap.

## Project Structure

```
B/
├── main.c              # Entry point and main menu logic
├── cshark.h            # Main header with common includes and constants
├── interface.c/h       # Network interface discovery and selection
├── capture.c/h         # Packet capture engine
├── packet_parser.c/h   # Layer-by-layer packet parsing (L2-L7)
├── display.c/h         # Formatted output and display functions
├── filter.c/h          # Packet filtering logic
├── storage.c/h         # Session storage and management
├── inspection.c/h      # Detailed packet inspection
├── utils.c/h           # Utility functions and helpers
├── Makefile            # Build system
└── README.md           # This file
```

## Module Architecture

### 1. **Main Module** (`main.c`)
- Entry point
- Main menu loop
- Orchestrates all modules
- Handles user interaction flow

### 2. **Interface Module** (`interface.c/h`)
- Discovers available network interfaces
- Lists interfaces with descriptions
- Handles user selection
- Uses pcap_findalldevs()

### 3. **Capture Module** (`capture.c/h`)
- Initializes pcap session
- Starts/stops packet capture
- Implements packet handler callback
- Manages capture context
- Handles Ctrl+C gracefully

### 4. **Packet Parser Module** (`packet_parser.c/h`)
- Parses Ethernet headers (Layer 2)
- Parses IP/ARP headers (Layer 3)
  - IPv4 support
  - IPv6 support
  - ARP support
- Parses TCP/UDP headers (Layer 4)
- Extracts payload (Layer 7)
- Stores parsed data in structured format

### 5. **Display Module** (`display.c/h`)
- Formats and displays packets
- Layer-by-layer output
- Hex dump functionality
- Protocol identification
- Port to service name mapping
- MAC address formatting

### 6. **Filter Module** (`filter.c/h`)
- Filter menu interface
- BPF filter expression generation
- Supports: HTTP, HTTPS, DNS, ARP, TCP, UDP
- Post-capture filtering logic

### 7. **Storage Module** (`storage.c/h`)
- Stores packets from current session
- Dynamic memory management
- Session lifecycle management
- Capacity: MAX_PACKETS (10000)
- Prevents memory leaks between sessions

### 8. **Inspection Module** (`inspection.c/h`)
- Lists stored packets
- Allows packet selection by ID
- Displays detailed packet analysis
- Full hex dump of raw packet

### 9. **Utils Module** (`utils.c/h`)
- Signal handlers (Ctrl+C, Ctrl+D)
- Input validation
- String formatting helpers
- TCP flags decoding
- Timestamp formatting

## Implementation Blueprint

### Phase 1: Interface & Basic Capture
**Files to implement:**
- `interface.c`: Device discovery and selection
- `capture.c`: Basic packet capture setup
- `main.c`: Basic menu structure
- `utils.c`: Signal handlers

**Key Functions:**
1. `discover_interfaces()` - Use pcap_findalldevs()
2. `display_interfaces()` - List with numbers
3. `select_interface()` - Get user input
4. `init_capture()` - Open pcap handle
5. `start_sniffing_all()` - Start capture loop
6. `packet_handler()` - Display packet ID, timestamp, length, first 16 bytes

### Phase 2: Layer-by-Layer Dissection
**Files to implement:**
- `packet_parser.c`: All parsing functions
- `display.c`: Layer display functions

**Key Functions:**
1. `parse_ethernet()` - Extract MAC, EtherType
2. `parse_ipv4()` - IPv4 header fields
3. `parse_ipv6()` - IPv6 header fields
4. `parse_arp()` - ARP fields
5. `parse_tcp()` - TCP header fields
6. `parse_udp()` - UDP header fields
7. `parse_payload()` - Extract application data
8. `display_layer2/3/4/7()` - Formatted output for each layer

### Phase 3: Filtering
**Files to implement:**
- `filter.c`: Filter logic

**Key Functions:**
1. `select_filter()` - Display filter menu
2. `generate_filter_expression()` - Create BPF expressions
   - HTTP: "tcp port 80"
   - HTTPS: "tcp port 443"
   - DNS: "udp port 53"
   - ARP: "arp"
   - TCP: "tcp"
   - UDP: "udp"

### Phase 4: Session Storage
**Files to implement:**
- `storage.c`: Packet storage

**Key Functions:**
1. `storage_init_session()` - Allocate storage
2. `storage_add_packet()` - Store parsed packet
3. `storage_clear_session()` - Free previous session
4. Modify `packet_handler()` to store packets

### Phase 5: Inspection
**Files to implement:**
- `inspection.c`: Detailed inspection

**Key Functions:**
1. `inspect_session()` - Main inspection interface
2. `list_session_packets()` - Show all packets
3. `inspect_packet_detailed()` - Detailed view
4. `display_packet_detailed()` - Full breakdown with hex dump

## Build Instructions

```bash
# Install dependencies (Ubuntu/Debian)
make install-deps

# Build the project
make

# Run (requires sudo)
sudo ./cshark
```

## Development Workflow

1. **Wait for section input** - User provides specific phase requirements
2. **Implement that phase** - Complete the relevant modules
3. **Test incrementally** - Verify each phase works before moving on
4. **Maintain modularity** - Keep functions focused and reusable

## Requirements

- libpcap-dev
- gcc
- Linux system
- Root/sudo privileges for execution

## Notes

- All packet parsing uses standard C network headers
- Signal handling prevents abrupt termination
- Memory management prevents leaks
- Modular design allows easy extension
- BPF filters compiled by libpcap for efficiency
