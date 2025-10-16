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
                // Start sniffing with filters
                {
                    int filter_type = select_filter();
                    if (filter_type != FILTER_NONE) {
                        char *filter_expr = generate_filter_expression(filter_type);
                        if (filter_expr != NULL) {
                            printf("\n[C-Shark] Applying filter: %s (%s)\n", 
                                   get_filter_name(filter_type), filter_expr);
                            start_sniffing_filtered(selected_device, filter_expr);
                            free(filter_expr);
                        } else {
                            printf("\n[C-Shark] Error generating filter expression.\n");
                        }
                    } else {
                        printf("\n[C-Shark] No filter selected. Returning to menu.\n");
                    }
                }
                break;
                
            case 3:
                // Inspect last session
                if (!storage_has_session()) {
                    printf("\n[C-Shark] No capture session available.\n");
                    printf("[C-Shark] Please capture some packets first (Option 1 or 2).\n");
                } else {
                    printf("\n[C-Shark] This feature will be fully implemented in Phase 5.\n");
                    printf("[C-Shark] Current session has %u packets stored.\n", storage_get_count());
                }
                break;
                
            case 4:
                // Exit
                printf("\n[C-Shark] Thank you for using C-Shark. Goodbye!\n");
                
                // Clean up storage
                storage_clear_session();
                
                // Free selected device
                free(selected_device);
                return 0;
                
            default:
                printf("[C-Shark] Invalid choice.\n");
                break;
        }
    }
    
    // Clean up storage
    storage_clear_session();
    
    // Free selected device
    free(selected_device);
    return 0;
}

