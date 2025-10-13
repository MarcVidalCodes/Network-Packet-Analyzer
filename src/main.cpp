#include <iostream>
#include <pcap.h>
#include <cstring>
#include <csignal> 

//wrap in class later
pcap_t* global_handle = nullptr; 

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
              << " -c <count>       Number of packets to capture (default: infinite)"
              << "  -h              Show this help message\n"
              << "\nNote: Root privileges required for packet capture\n";
}

void signal_handler(int signum){    
    std::cout<< "\n[!] Caught signal " << signum <<", stopping capture..." <<std::endl;
    if(global_handle){
        pcap_breakloop(global_handle);
    }
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    (void)user_data; //unused
    (void)packet; //unused

    static int count = 0; 
    count++; 

    std::cout   << "[" << count << "] "
                <<"Captured packet: " << pkthdr -> len << " bytes, "
                <<"at: " << pkthdr -> ts.tv_sec << "." << pkthdr -> ts.tv_usec
                << std::endl;
}

int main(int argc, char* argv[]) {
    print_banner();

    // Parse command line arguments
    const char* interface = nullptr;
    int packet_count = -1; //-1 for infinite 
    
    for(int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interface = argv[i + 1];
            i++;
        } else if(strcmp(argv[i], "-c") == 0){
            packet_count = atoi(argv[i+1]);
            i++; 
        }else if (strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } 
    }

    //validate interface
    if (!interface){
        std::cerr << "[ERROR] No interface specified. Use -i <interface> \n";
        print_usage(argv[0]);
        return 1; 
    }

    std::cout<< "[*] Initializing NetGuard..." <<std::endl;
    std::cout<<"[*] Interface" << interface << std:: endl;
    
    if(packet_count > 0){
        std::cout<<"[*] Capturing " << packet_count << " packets..." << std::endl;
    }else{
        std::cout<< "[*] Capturing packets..." <<std:: endl; 
    }

    //Open network intrface 
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if(!handle){
        std::cerr<<"ERROR: Could not open interface" << interface << ": " << errbuf <<std::endl;
        return 1; 
    }

    global_handle = handle; 

    //setup signal handler for shutdown 
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler); 

    std::cout<< "[*] Capture started\n" << std::endl;

    //Start packet capture
    int result = pcap_loop(handle, packet_count, packet_handler, nullptr);

    if(result == 1){
        std::cerr << "[ERROR] pcap_loop failed: " << pcap_geterr(handle) << std::endl; 
    }else if(result == -2){
        std::cout << "\n [*] Capture stopped by user" <<std::endl; 
    }else {
        std::cout << "\n [*] Capture complete" <<std::endl; 
    }

    //close
    pcap_close(handle);
    global_handle = nullptr; 

    std::cout << "Program Complete" << std::endl; 

    return 0;
}