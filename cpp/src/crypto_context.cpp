#include "qprotect/crypto_context.hpp"
#include "qprotect/self_test.hpp"

#include "crypto_context_handles.hpp"
#include "openssl_utils.hpp"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include <string>

namespace qprotect::cpp {
struct CryptoContext::Impl {
    detail::LibraryContextPtr library_context;
    detail::ProviderPtr base_provider;
    detail::ProviderPtr algorithm_provider;
    std::string properties;
};

CryptoContext::CryptoContext(const std::string& provider)
    : impl_(std::make_unique<Impl>()), provider_(provider) {
    if (provider_.empty()) {
        throw CryptoError("OpenSSL provider name must not be empty");
    }
    impl_->library_context.reset(OSSL_LIB_CTX_new());
    if (impl_->library_context == nullptr) {
        detail::throw_openssl("OSSL_LIB_CTX_new");
    }

    impl_->base_provider.reset(
        OSSL_PROVIDER_load(impl_->library_context.get(), "base")
    );
    if (impl_->base_provider == nullptr) {
        detail::throw_openssl("load OpenSSL base provider");
    }

    impl_->algorithm_provider.reset(
        OSSL_PROVIDER_load(impl_->library_context.get(), provider_.c_str())
    );
    if (impl_->algorithm_provider == nullptr) {
        detail::throw_openssl("load OpenSSL " + provider_ + " provider");
    }

    impl_->properties = "provider=" + provider_;
    const SelfTestReport report = run_self_tests(*this);
    if (!report.passed) {
        throw CryptoError("required algorithm self-test failed");
    }
}

CryptoContext::~CryptoContext() = default;

bool CryptoContext::provider_self_test() const {
    return OSSL_PROVIDER_self_test(impl_->algorithm_provider.get()) == 1;
}

void CryptoContext::assert_ready() const {
    if (!provider_self_test()) {
        throw CryptoError(provider_ + " provider self-test failed");
    }

    const char* properties = impl_->properties.c_str();
    OSSL_LIB_CTX* libctx = impl_->library_context.get();

    detail::FunctionPtr<EVP_MD, EVP_MD_free> sha384(
        EVP_MD_fetch(libctx, "SHA384", properties)
    );
    if (sha384 == nullptr) {
        throw CryptoError("SHA-384 is unavailable from the " + provider_ + " provider");
    }

    detail::FunctionPtr<EVP_MD, EVP_MD_free> sha512(
        EVP_MD_fetch(libctx, "SHA512", properties)
    );
    if (sha512 == nullptr) {
        throw CryptoError("SHA-512 is unavailable from the " + provider_ + " provider");
    }

    detail::FunctionPtr<EVP_CIPHER, EVP_CIPHER_free> aes_gcm(
        EVP_CIPHER_fetch(libctx, "AES-256-GCM", properties)
    );
    if (aes_gcm == nullptr) {
        throw CryptoError("AES-256-GCM is unavailable from the " + provider_ + " provider");
    }

    detail::FunctionPtr<EVP_KDF, EVP_KDF_free> hkdf(
        EVP_KDF_fetch(libctx, "HKDF", properties)
    );
    if (hkdf == nullptr) {
        throw CryptoError("HKDF is unavailable from the " + provider_ + " provider");
    }

    detail::FunctionPtr<EVP_SIGNATURE, EVP_SIGNATURE_free> ml_dsa(
        EVP_SIGNATURE_fetch(libctx, "ML-DSA-87", properties)
    );
    if (ml_dsa == nullptr) {
        throw CryptoError("ML-DSA-87 is unavailable from the " + provider_ + " provider");
    }

    detail::FunctionPtr<EVP_KEM, EVP_KEM_free> ml_kem(
        EVP_KEM_fetch(libctx, "ML-KEM-1024", properties)
    );
    if (ml_kem == nullptr) {
        throw CryptoError("ML-KEM-1024 is unavailable from the " + provider_ + " provider");
    }
}

SecureBytes CryptoContext::random_bytes(std::size_t length) const {
    if (length == 0) {
        return SecureBytes{};
    }

    SecureBytes output(length);
    if (RAND_priv_bytes_ex(impl_->library_context.get(), output.data(), length, 256) != 1) {
        detail::throw_openssl("RAND_priv_bytes_ex");
    }
    return output;
}

CryptoContextHandles CryptoContext::handles() const {
    return CryptoContextHandles{
        impl_->library_context.get(),
        impl_->algorithm_provider.get(),
        impl_->base_provider.get(),
        impl_->properties.c_str(),
    };
}

}
