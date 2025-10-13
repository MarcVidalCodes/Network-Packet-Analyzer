#ifndef NETGUARD_CLI_H
#define NETGUARD_CLI_H

struct CommandLineArgs {
    const char* interface = nullptr;
    int packet_count = -1;  // -1 = infinite
    bool show_help = false;
    bool error = false;
    const char* error_message = nullptr;
};

CommandLineArgs parse_arguments(int argc, char* argv[]);
bool validate_arguments(const CommandLineArgs& args);

#endif // NETGUARD_CLI_H