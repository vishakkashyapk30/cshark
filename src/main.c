/*
 * C-Shark - The Command-Line Packet Predator
 * Main entry point, CLI argument parsing, and interactive menu system
 */

#include "cshark.h"
#include <string.h>

// LLM Generated Code Starts Here

static void print_usage(const char *prog_name) {
    printf("C-Shark - The Command-Line Packet Predator\n\n");
    printf("Interactive mode (default): %s\n", prog_name);
    printf("  Launches the interactive menu (interface selection, live capture, inspection).\n\n");
    printf("Headless/scriptable mode (for automation, CI, and validation pipelines):\n");
    printf("  %s -i <interface> -t <seconds> [--filter <name>] [-o <csv>] [--pcap <path>]\n\n", prog_name);
    printf("Options:\n");
    printf("  -i, --interface <name>   Network interface to capture on (required for headless mode)\n");
    printf("  -t, --time <seconds>     Stop capture automatically after N seconds (default: 30)\n");
    printf("      --filter <name>      Apply a protocol filter: http|https|dns|arp|tcp|udp\n");
    printf("  -o, --csv <path>         Export captured flows to CSV on completion\n");
    printf("      --pcap <path>        Export captured packets to a real .pcap file on completion\n");
    printf("      --list-interfaces    List discovered network interfaces and exit\n");
    printf("      --subnet <CIDR>      Calculate subnet info for an IPv4 CIDR (e.g. 10.0.0.0/24) and exit\n");
    printf("  -h, --help               Show this help message\n");
}

static int filter_type_from_name(const char *name) {
    if (strcmp(name, "http") == 0) return FILTER_HTTP;
    if (strcmp(name, "https") == 0) return FILTER_HTTPS;
    if (strcmp(name, "dns") == 0) return FILTER_DNS;
    if (strcmp(name, "arp") == 0) return FILTER_ARP;
    if (strcmp(name, "tcp") == 0) return FILTER_TCP;
    if (strcmp(name, "udp") == 0) return FILTER_UDP;
    return FILTER_NONE;
}

// Non-interactive capture: builds on the existing interactive capture loop by
// arming an alarm() that trips the same `capture_interrupted` flag used for
// Ctrl+C, so capture.c needs no structural changes. Exports on completion and
// prints a plain-text summary suitable for logs/CI, then exits the process -
// this is the integration point for scripts/Invoke-CSharkWorkflow.ps1 and any
// automated validation pipeline.
static int run_headless_capture(const char *interface, int duration_seconds,
                                 const char *filter_name, const char *csv_path,
                                 const char *pcap_path) {
    printf("[C-Shark] Headless capture: interface=%s duration=%ds filter=%s\n",
           interface, duration_seconds, filter_name ? filter_name : "none");

    arm_capture_timeout(duration_seconds);

    if (filter_name != NULL) {
        int filter_type = filter_type_from_name(filter_name);
        if (filter_type == FILTER_NONE) {
            fprintf(stderr, "[C-Shark] Unknown filter '%s'. Valid: http|https|dns|arp|tcp|udp\n", filter_name);
            return 1;
        }
        char *filter_expr = generate_filter_expression(filter_type);
        start_sniffing_filtered((char *)interface, filter_expr);
        free(filter_expr);
    } else {
        start_sniffing_all((char *)interface);
    }

    if (!storage_has_session()) {
        fprintf(stderr, "[C-Shark] Headless capture produced no session (bad interface or permissions?).\n");
        return 1;
    }

    if (csv_path != NULL) {
        export_session_csv(csv_path);
    }
    if (pcap_path != NULL) {
        export_session_pcap(pcap_path);
    }

    uint32_t alert_count = detect_get_alert_count();
    printf("[C-Shark] Headless capture complete: %u packets, %u security alert(s).\n",
           storage_get_count(), alert_count);
    for (uint32_t i = 0; i < alert_count; i++) {
        const alert_record_t *alert = detect_get_alert(i);
        if (alert != NULL) {
            printf("  [%s] %s\n", alert->type, alert->details);
        }
    }

    storage_clear_session();
    return 0;
}

int main(int argc, char *argv[]) {
    const char *cli_interface = NULL;
    const char *cli_filter = NULL;
    const char *cli_csv = NULL;
    const char *cli_pcap = NULL;
    const char *cli_subnet = NULL;
    int cli_duration = 30;
    int cli_list_interfaces = 0;
    int cli_headless = 0;

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "--help") == 0)) {
            print_usage(argv[0]);
            return 0;
        } else if ((strcmp(argv[i], "-i") == 0) || (strcmp(argv[i], "--interface") == 0)) {
            if (++i >= argc) { fprintf(stderr, "Missing value for %s\n", argv[i - 1]); return 1; }
            cli_interface = argv[i];
            cli_headless = 1;
        } else if ((strcmp(argv[i], "-t") == 0) || (strcmp(argv[i], "--time") == 0)) {
            if (++i >= argc) { fprintf(stderr, "Missing value for %s\n", argv[i - 1]); return 1; }
            cli_duration = atoi(argv[i]);
        } else if (strcmp(argv[i], "--filter") == 0) {
            if (++i >= argc) { fprintf(stderr, "Missing value for --filter\n"); return 1; }
            cli_filter = argv[i];
        } else if ((strcmp(argv[i], "-o") == 0) || (strcmp(argv[i], "--csv") == 0)) {
            if (++i >= argc) { fprintf(stderr, "Missing value for %s\n", argv[i - 1]); return 1; }
            cli_csv = argv[i];
        } else if (strcmp(argv[i], "--pcap") == 0) {
            if (++i >= argc) { fprintf(stderr, "Missing value for --pcap\n"); return 1; }
            cli_pcap = argv[i];
        } else if (strcmp(argv[i], "--list-interfaces") == 0) {
            cli_list_interfaces = 1;
        } else if (strcmp(argv[i], "--subnet") == 0) {
            if (++i >= argc) { fprintf(stderr, "Missing value for --subnet\n"); return 1; }
            cli_subnet = argv[i];
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (cli_subnet != NULL) {
        subnet_info_t info;
        if (subnet_calculate(cli_subnet, &info) != 0) {
            return 1;
        }
        subnet_print(&info);
        return 0;
    }

    if (cli_list_interfaces) {
        pcap_if_t *alldevs;
        int dev_count = discover_interfaces(&alldevs);
        if (dev_count <= 0) {
            fprintf(stderr, "[C-Shark] No interfaces found or error occurred (try sudo).\n");
            return 1;
        }
        display_interfaces(alldevs, dev_count);
        free_interfaces(alldevs);
        return 0;
    }

    if (cli_headless) {
        if (cli_interface == NULL) {
            fprintf(stderr, "[C-Shark] Headless mode requires -i/--interface.\n");
            return 1;
        }
        setup_signal_handlers();
        return run_headless_capture(cli_interface, cli_duration, cli_filter, cli_csv, cli_pcap);
    }

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
        
        choice = get_user_choice(1, 6);
        
        if (choice == -1) {
            printf("[C-Shark] Invalid choice. Please enter a number between 1 and 6.\n");
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
                inspect_session();
                break;
                
            case 4:
                // View security alerts raised during the last session
                view_security_alerts();
                break;
                
            case 5:
                // Export session data (CSV flows, CSV alerts, or PCAP)
                export_session_menu();
                break;
                
            case 6:
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

// LLM Generated Code Starts Here