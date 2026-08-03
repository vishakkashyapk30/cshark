/*
 * C-Shark - Main header file
 * Contains common includes, constants, and data structures
 */

#ifndef CSHARK_H
#define CSHARK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

// Constants
#define MAX_PACKETS 10000
#define SNAP_LEN 65535
#define PROMISC_MODE 1
#define TIMEOUT_MS 1000

// Include module headers
#include "interface.h"
#include "capture.h"
#include "packet_parser.h"
#include "display.h"
#include "filter.h"
#include "storage.h"
#include "detect.h"
#include "inspection.h"
#include "utils.h"

#endif // CSHARK_H
