#include "cli.h"
#include <cstring>
#include <cstdlib>

CommandLineArgs parse_arguments(int argc, char* argv[]) {
    CommandLineArgs args;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) {
                args.interface = argv[i + 1];
                i++;
            } else {
                args.error = true;
                args.error_message = "-i requires an interface name";
                return args;
            }
        } else if (strcmp(argv[i], "-c") == 0) {
            if (i + 1 < argc) {
                args.packet_count = atoi(argv[i + 1]);
                i++;
            } else {
                args.error = true;
                args.error_message = "-c requires a count";
                return args;
            }
        } else if (strcmp(argv[i], "-h") == 0) {
            args.show_help = true;
            return args;
        } else {
            args.error = true;
            args.error_message = "Unknown argument";
            return args;
        }
    }

    return args;
}

bool validate_arguments(const CommandLineArgs& args) {
    if (args.show_help) {
        return true;
    }
    return args.interface != nullptr;
}