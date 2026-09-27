#define main qprotect_cli_main
#include "../apps/qprotect_tool.cpp"
#undef main

#include <sstream>

int main() {
    using namespace qprotect::cpp;
    try {
        for (const bool full : {false, true}) {
            for (const bool passed : {false, true}) {
                for (const bool round_trip : {false, true}) {
                    for (const std::size_t count : {0U, 1U, 3U}) {
                        SelfTestReport report{passed, "default", {}};
                        for (std::size_t index = 0; index < count; ++index) {
                            report.checks.push_back({"fixture", passed});
                        }
                        std::ostringstream output;
                        auto* original = std::cout.rdbuf(output.rdbuf());
                        print_health_report(report, full, round_trip);
                        std::cout.rdbuf(original);
                        const auto document = json::Value::parse(output.str());
                        const auto& fields = document.as_object();
                        const auto& checks = fields.at("checks").as_array();
                        if (fields.at("ready").as_boolean() != (passed && (!full || round_trip)) ||
                            checks.size() != count + (full ? 1 : 0)) return 1;
                        if (full && (checks.back().as_object().at("passed").as_boolean() != round_trip ||
                            fields.at("envelope_round_trip_passed").as_boolean() != round_trip)) return 1;
                    }
                }
            }
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    std::cout << "diagnostic JSON: 24 cases passed\n";
    return 0;
}
