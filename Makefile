# C-Shark Packet Sniffer Makefile

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -g -O2
LDFLAGS = -lpcap

# Target executable
TARGET = cshark

# Source files
SRCS = main.c \
       interface.c \
       capture.c \
       packet_parser.c \
       display.c \
       filter.c \
       storage.c \
       inspection.c \
       utils.c

# Object files
OBJS = $(SRCS:.c=.o)

# Header files
HEADERS = cshark.h \
          interface.h \
          capture.h \
          packet_parser.h \
          display.h \
          filter.h \
          storage.h \
          inspection.h \
          utils.h

# Default target
all: $(TARGET)

# Link object files to create executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete! Run with: sudo ./$(TARGET)"

# Compile source files to object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)
	@echo "Clean complete!"

# Rebuild everything
rebuild: clean all

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
	@echo "make          - Build the project"
	@echo "make clean    - Remove build artifacts"
	@echo "make rebuild  - Clean and rebuild"
	@echo "make run      - Build and run (requires sudo)"
	@echo "make install-deps - Install libpcap dependency"
	@echo "make help     - Show this help message"

.PHONY: all clean rebuild install-deps run help

