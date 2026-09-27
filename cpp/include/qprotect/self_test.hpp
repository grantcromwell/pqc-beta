#pragma once

#include <string>
#include <vector>

#include "qprotect/crypto_context.hpp"

namespace qprotect::cpp {

struct SelfTestCheck {
    std::string name;
    bool passed;
};

struct SelfTestReport {
    bool passed = false;
    std::string provider;
    std::vector<SelfTestCheck> checks;
};

SelfTestReport run_self_tests(const CryptoContext& context);

}
