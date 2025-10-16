/*
 * C-Shark - The Command-Line Packet Predator
 * Main entry point and menu system
 */

#include "cshark.h"

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    
    pcap_if_t *alldevs;
    int dev_count;
    char *selected_device = NULL;
    int choice;
    
    // Setup signal handlers
    setup_signal_handlers();
    
    // Display banner
    display_banner();
    
    // Discover interfaces
    dev_count = discover_interfaces(&alldevs);
    if (dev_count <= 0) {
        fprintf(stderr, "[C-Shark] No interfaces found or error occurred.\n");
        fprintf(stderr, "[C-Shark] Make sure you're running with sudo.\n");
        return 1;
    }
    
    // Display interfaces
    display_interfaces(alldevs, dev_count);
    
    // Get user selection
    selected_device = select_interface(alldevs, dev_count);
    if (selected_device == NULL) {
        printf("\n[C-Shark] No interface selected or Ctrl+D pressed. Exiting...\n");
        free_interfaces(alldevs);
        return 0;
    }
    
    // Free the interface list (but keep the selected device name)
    free_interfaces(alldevs);
    
    // Main menu loop
    while (1) {
        display_main_menu(selected_device);
        
        choice = get_user_choice(1, 4);
        
        if (choice == -1) {
            printf("[C-Shark] Invalid choice. Please enter a number between 1 and 4.\n");
            continue;
        }
        
        switch (choice) {
            case 1:
                // Start sniffing all packets
                start_sniffing_all(selected_device);
                break;
                
            case 2:
                // Start sniffing with filters (Phase 3)
                printf("\n[C-Shark] This feature will be implemented in Phase 3.\n");
                break;
                
            case 3:
                // Inspect last session (Phase 5)
                printf("\n[C-Shark] This feature will be implemented in Phase 5.\n");
                break;
                
            case 4:
                // Exit
                printf("\n[C-Shark] Thank you for using C-Shark. Goodbye!\n");
                free(selected_device);
                return 0;
                
            default:
                printf("[C-Shark] Invalid choice.\n");
                break;
        }
    }
    
    free(selected_device);
    return 0;
}

