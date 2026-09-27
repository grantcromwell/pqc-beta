#include "qprotect/constants.hpp"
#include "qprotect/crypto_context.hpp"
#include "qprotect/error.hpp"
#include "qprotect/self_test.hpp"

#include <iomanip>
#include <iostream>
#include <span>
#include <string>

namespace {

void print_report(const qprotect::cpp::SelfTestReport& report) {
    std::cout << "{\n";
    std::cout << "  \"module\": \"qprotect-cpp\",\n";
    std::cout << "  \"version\": \"" << qprotect::cpp::constants::module_version << "\",\n";
    std::cout << "  \"provider\": \"" << report.provider << "\",\n";
    std::cout << "  \"passed\": " << (report.passed ? "true" : "false") << ",\n";
    std::cout << "  \"checks\": [\n";
    for (std::size_t i = 0; i < report.checks.size(); ++i) {
        const auto& check = report.checks[i];
        std::cout << "    {\"name\": \"" << check.name
                  << "\", \"passed\": " << (check.passed ? "true" : "false") << "}";
        if (i + 1 != report.checks.size()) {
            std::cout << ",";
        }
        std::cout << "\n";
    }
    std::cout << "  ]\n";
    std::cout << "}\n";
}

}

int main(int argc, char* argv[]) {
    std::string provider = "default";
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--provider" && i + 1 < argc) {
            provider = argv[++i];
        } else {
            std::cerr << "usage: qprotect_cpp_selftest [--provider NAME]\n";
            return 2;
        }
    }

    try {
        const qprotect::cpp::CryptoContext context(provider);
        const qprotect::cpp::SelfTestReport report =
            qprotect::cpp::run_self_tests(context);
        print_report(report);
        return report.passed ? 0 : 1;
    } catch (const qprotect::cpp::CryptoError& error) {
        std::cerr << "error: " << error.what() << "\n";
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "unexpected error: " << error.what() << "\n";
        return 1;
    }
}
