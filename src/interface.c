/*
 * Interface Discovery and Selection Module Implementation
 */

#include "interface.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// LLM Generated Code Starts Here

int discover_interfaces(pcap_if_t **alldevs) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(alldevs, errbuf) == -1) {
        fprintf(stderr, "[C-Shark] Error finding devices: %s\n", errbuf);
        return -1;
    }
    
    // Count the number of interfaces
    int count = 0;
    pcap_if_t *dev;
    for (dev = *alldevs; dev != NULL; dev = dev->next) {
        count++;
    }
    
    return count;
}

void display_interfaces(pcap_if_t *alldevs, int count) {
    if (count == 0) {
        printf("\n[C-Shark] No interfaces found!\n");
        printf("[C-Shark] Make sure you have the necessary permissions.\n");
        printf("[C-Shark] Try running with sudo.\n");
        return;
    }
    
    printf("\n");
    int i = 1;
    pcap_if_t *dev;
    for (dev = alldevs; dev != NULL; dev = dev->next) {
        printf("%d. %s", i, dev->name);
        if (dev->description) {
            printf(" (%s)", dev->description);
        }
        printf("\n");
        i++;
    }
}

char* select_interface(pcap_if_t *alldevs, int count) {
    if (count == 0) {
        return NULL;
    }
    
    int choice;
    printf("\nSelect an interface to sniff (1-%d): ", count);
    
    if (scanf("%d", &choice) != 1) {
        // Handle Ctrl+D or invalid input
        if (feof(stdin)) {
            return NULL;
        }
        // Clear invalid input
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        printf("[C-Shark] Invalid input. Please enter a number.\n");
        return select_interface(alldevs, count);
    }
    
    // Clear the newline
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
    
    if (choice < 1 || choice > count) {
        printf("[C-Shark] Invalid choice. Please select a number between 1 and %d.\n", count);
        return select_interface(alldevs, count);
    }
    
    // Find the selected interface
    pcap_if_t *dev = alldevs;
    for (int i = 1; i < choice; i++) {
        dev = dev->next;
    }
    
    // Return a copy of the device name
    char *device_name = strdup(dev->name);
    return device_name;
}

void free_interfaces(pcap_if_t *alldevs) {
    if (alldevs != NULL) {
        pcap_freealldevs(alldevs);
    }
}

// LLM Generated Code Ends Here
