# C-Shark Packet Sniffer Makefile

# Directory layout
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g -O2 -I$(INCLUDE_DIR)
LDFLAGS = -lpcap

# Target executable
TARGET = cshark

# Source files (in src/)
SRC_NAMES = main.c \
            interface.c \
            capture.c \
            packet_parser.c \
            display.c \
            filter.c \
            storage.c \
            inspection.c \
            detect.c \
            export.c \
            subnet.c \
            utils.c

SRCS = $(addprefix $(SRC_DIR)/,$(SRC_NAMES))

# Object files (built into build/, kept separate from source)
OBJS = $(addprefix $(BUILD_DIR)/,$(SRC_NAMES:.c=.o))

# Header files (in include/) - every .o depends on all headers, matching
# the original Makefile's conservative "rebuild everything on any header
# change" behavior.
HEADERS = $(wildcard $(INCLUDE_DIR)/*.h)

# Default target
all: $(TARGET)

# Link object files to create executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete! Run with: sudo ./$(TARGET)"

# Compile source files to object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(TARGET) tests/test_detect
	@echo "Clean complete!"

# Rebuild everything
rebuild: clean all

# Regression test for detect.c (port-scan / ARP-spoof heuristics) using
# synthetic packet fixtures - no root or NIC access required.
test:
	$(CC) $(CFLAGS) tests/test_detect.c $(SRC_DIR)/detect.c $(SRC_DIR)/utils.c -o tests/test_detect $(LDFLAGS)
	./tests/test_detect

# Install libpcap if needed (Ubuntu/Debian)
install-deps:
	@echo "Installing libpcap-dev..."
	sudo apt-get update
	sudo apt-get install -y libpcap-dev

# Run the program (requires sudo)
run: $(TARGET)
	sudo ./$(TARGET)

# Help target
help:
	@echo "C-Shark Packet Sniffer - Makefile Help"
	@echo "========================================"
	@echo "make          - Build the project (sources in src/, headers in include/)"
	@echo "make clean    - Remove build artifacts"
	@echo "make rebuild  - Clean and rebuild"
	@echo "make run      - Build and run (requires sudo)"
	@echo "make test     - Build and run detect.c regression tests (no root needed)"
	@echo "make install-deps - Install libpcap dependency"
	@echo "make help     - Show this help message"
	@echo ""
	@echo "Headless/scriptable capture (for automation, see PLAN.md section 3.1):"
	@echo "  sudo ./cshark -i <iface> -t <seconds> -o flows.csv --pcap session.pcap"
	@echo ""
	@echo "Companion tools (outside this Makefile):"
	@echo "  python3 tools/anomaly_detect.py flows.csv   - AI/ML anomaly triage"
	@echo "  pwsh scripts/Invoke-CSharkWorkflow.ps1 -Interface <iface> - full pipeline"

.PHONY: all clean rebuild install-deps run help test
