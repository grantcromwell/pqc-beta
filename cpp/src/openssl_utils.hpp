#pragma once

#include <memory>
#include <string>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include "qprotect/error.hpp"

namespace qprotect::cpp::detail {

[[noreturn]] inline void throw_openssl(const std::string& operation) {
    const unsigned long code = ERR_get_error();
    const char* reason = ERR_reason_error_string(code);
    throw CryptoError(
        operation + ": " +
        (reason != nullptr ? reason : "unknown OpenSSL error")
    );
}

template <typename T, void (*Free)(T*)>
struct FunctionDeleter {
    void operator()(T* value) const noexcept {
        if (value != nullptr) {
            Free(value);
        }
    }
};

template <typename T, void (*Free)(T*)>
using FunctionPtr = std::unique_ptr<T, FunctionDeleter<T, Free>>;

struct OpenSSLFree {
    void operator()(void* value) const noexcept {
        if (value != nullptr) {
            OPENSSL_free(value);
        }
    }
};

using OpenSSLBuffer = std::unique_ptr<unsigned char, OpenSSLFree>;

struct ProviderDeleter {
    void operator()(OSSL_PROVIDER* provider) const noexcept {
        if (provider != nullptr) {
            OSSL_PROVIDER_unload(provider);
        }
    }
};

struct LibraryContextDeleter {
    void operator()(OSSL_LIB_CTX* context) const noexcept {
        if (context != nullptr) {
            OSSL_LIB_CTX_free(context);
        }
    }
};

using ProviderPtr = std::unique_ptr<OSSL_PROVIDER, ProviderDeleter>;
using LibraryContextPtr = std::unique_ptr<OSSL_LIB_CTX, LibraryContextDeleter>;

}
