#include <iostream>
#include <pcap.h>
#include <csignal>
#include "cli.h"
#include "protocol/packet_parser.h"

// Global handle for cleanup
pcap_t* global_handle = nullptr;
int global_packet_count = 0;

void print_banner() {
    std::cout << R"(
╔═══════════════════════════════════════════╗
║                   NetGuard.               ║
║   Network Packet Analyzer & Detector      ║
╚═══════════════════════════════════════════╝
)" << std::endl;
}

void print_usage(const char* program_name) {
    std::cout << "Usage: sudo " << program_name << " [options]\n"
              << "Options:\n"
              << "  -i <interface>  Network interface to capture on\n"
              << "  -c <count>      Number of packets to capture (default: infinite)\n"
              << "  -h              Show this help message\n"
              << "\nNote: Root privileges required for packet capture\n";
}

void signal_handler(int signum) {
    std::cout << "\n[!] Caught signal " << signum << ", stopping capture..." << std::endl;
    if (global_handle) {
        pcap_breakloop(global_handle);
    }
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    (void)user_data;  // Unused

    global_packet_count++;
    
    // Parse and print the packet
    parse_and_print_packet(packet, pkthdr->len, global_packet_count);
}

int main(int argc, char* argv[]) {
    print_banner();

    // Parse command line arguments
    CommandLineArgs args = parse_arguments(argc, argv);

    // Handle errors
    if (args.error) {
        std::cerr << "[ERROR] " << args.error_message << "\n";
        print_usage(argv[0]);
        return 1;
    }

    // Show help if requested
    if (args.show_help) {
        print_usage(argv[0]);
        return 0;
    }

    // Validate interface
    if (!validate_arguments(args)) {
        std::cerr << "[ERROR] No interface specified. Use -i <interface>\n";
        print_usage(argv[0]);
        return 1;
    }

    std::cout << "[*] Initializing NetGuard..." << std::endl;
    std::cout << "[*] Interface: " << args.interface << std::endl;

    if (args.packet_count > 0) {
        std::cout << "[*] Capturing " << args.packet_count << " packets..." << std::endl;
    } else {
        std::cout << "[*] Capturing packets (Ctrl+C to stop)..." << std::endl;
    }

    // Open network interface
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(args.interface, BUFSIZ, 1, 1000, errbuf);

    if (!handle) {
        std::cerr << "[ERROR] Could not open interface " << args.interface << ": " << errbuf << std::endl;
        std::cerr << "[HINT] Try running with sudo or check interface name" << std::endl;
        return 1;
    }

    global_handle = handle;

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    std::cout << "[*] Capture started!\n" << std::endl;

    // Start packet capture
    int result = pcap_loop(handle, args.packet_count, packet_handler, nullptr);

    if (result == -1) {
        std::cerr << "[ERROR] pcap_loop failed: " << pcap_geterr(handle) << std::endl;
    } else if (result == -2) {
        std::cout << "\n[*] Capture stopped by user" << std::endl;
    } else {
        std::cout << "\n[*] Capture complete!" << std::endl;
    }

    // Cleanup
    pcap_close(handle);
    global_handle = nullptr;

    std::cout << "[√] NetGuard shutdown complete" << std::endl;
    std::cout << "[√] Total packets captured: " << global_packet_count << std::endl;

    return 0;
}