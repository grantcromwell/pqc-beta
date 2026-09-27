#pragma once

#include <memory>
#include <span>
#include <string>

#include "qprotect/secure_bytes.hpp"

namespace qprotect::cpp {

struct CryptoContextHandles;

class CryptoContext {
public:
    explicit CryptoContext(const std::string& provider = "default");
    ~CryptoContext();

    CryptoContext(const CryptoContext&) = delete;
    CryptoContext& operator=(const CryptoContext&) = delete;
    CryptoContext(CryptoContext&&) = delete;
    CryptoContext& operator=(CryptoContext&&) = delete;

    std::string provider_name() const noexcept { return provider_; }

    void assert_ready() const;

    bool provider_self_test() const;

    SecureBytes random_bytes(std::size_t length) const;

    CryptoContextHandles handles() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::string provider_;
};

}
