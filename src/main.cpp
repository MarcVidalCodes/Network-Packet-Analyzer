#include <iostream>
#include <pcap.h>
#include <cstring>

void print_banner() {
    std::cout << R"(
╔═══════════════════════════════════════════╗
║           NetGuard v0.1.0                ║
║   Network Packet Analyzer & Detector     ║
╚═══════════════════════════════════════════╝
)" << std::endl;
}

void print_usage(const char* program_name) {
    std::cout << "Usage: sudo " << program_name << " [options]\n"
              << "Options:\n"
              << "  -i <interface>  Network interface to capture on\n"
              << "  -h              Show this help message\n"
              << "\nNote: Root privileges required for packet capture\n";
}

int main(int argc, char* argv[]) {
    print_banner();

    // Parse command line arguments
    const char* interface = nullptr;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interface = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    std::cout << "[*] Initializing NetGuard..." << std::endl;
    std::cout << "[*] libpcap is available!" << std::endl;
    std::cout << "[√] Project setup complete!\n" << std::endl;
    std::cout << "[!] Packet capture coming in next phase!" << std::endl;

    return 0;
}