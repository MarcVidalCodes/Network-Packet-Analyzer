#include <gtest/gtest.h>
#include "../cli.h"

// Test: Help flag
TEST(CLIParsingTest, HelpFlag) {
    char* argv[] = {(char*)"netguard", (char*)"-h"};
    int argc = 2;

    CommandLineArgs args = parse_arguments(argc, argv);

    EXPECT_TRUE(args.show_help);
    EXPECT_FALSE(args.error);
}

// Test: Interface flag
TEST(CLIParsingTest, InterfaceFlag) {
    char* argv[] = {(char*)"netguard", (char*)"-i", (char*)"eth0"};
    int argc = 3;

    CommandLineArgs args = parse_arguments(argc, argv);

    EXPECT_STREQ(args.interface, "eth0");
    EXPECT_FALSE(args.error);
}

// Test: Count flag
TEST(CLIParsingTest, CountFlag) {
    char* argv[] = {(char*)"netguard", (char*)"-i", (char*)"eth0", (char*)"-c", (char*)"10"};
    int argc = 5;

    CommandLineArgs args = parse_arguments(argc, argv);

    EXPECT_STREQ(args.interface, "eth0");
    EXPECT_EQ(args.packet_count, 10);
    EXPECT_FALSE(args.error);
}

// Test: Missing interface value
TEST(CLIParsingTest, MissingInterfaceValue) {
    char* argv[] = {(char*)"netguard", (char*)"-i"};
    int argc = 2;

    CommandLineArgs args = parse_arguments(argc, argv);

    EXPECT_TRUE(args.error);
    EXPECT_STREQ(args.error_message, "-i requires an interface name");
}

// Test: Missing count value
TEST(CLIParsingTest, MissingCountValue) {
    char* argv[] = {(char*)"netguard", (char*)"-c"};
    int argc = 2;

    CommandLineArgs args = parse_arguments(argc, argv);

    EXPECT_TRUE(args.error);
    EXPECT_STREQ(args.error_message, "-c requires a count");
}

// Test: Unknown argument
TEST(CLIParsingTest, UnknownArgument) {
    char* argv[] = {(char*)"netguard", (char*)"--unknown"};
    int argc = 2;

    CommandLineArgs args = parse_arguments(argc, argv);

    EXPECT_TRUE(args.error);
    EXPECT_STREQ(args.error_message, "Unknown argument");
}

// Test: Validation - valid with interface
TEST(CLIValidationTest, ValidWithInterface) {
    CommandLineArgs args;
    args.interface = "eth0";

    EXPECT_TRUE(validate_arguments(args));
}

// Test: Validation - help is valid
TEST(CLIValidationTest, HelpIsValid) {
    CommandLineArgs args;
    args.show_help = true;

    EXPECT_TRUE(validate_arguments(args));
}

// Test: Validation - missing interface
TEST(CLIValidationTest, MissingInterface) {
    CommandLineArgs args;

    EXPECT_FALSE(validate_arguments(args));
}