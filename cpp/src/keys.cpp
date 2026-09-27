#include "qprotect/keys.hpp"

#include "crypto_context_handles.hpp"
#include "openssl_utils.hpp"
#include "secure_file.hpp"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <filesystem>
#include <memory>
#include <sstream>
#include <utility>

#include "qprotect/algorithms.hpp"
#include "qprotect/error.hpp"

namespace qprotect::cpp {
namespace {

using detail::FunctionPtr;
using detail::throw_openssl;

struct BioDeleter {
    void operator()(BIO* bio) const noexcept {
        if (bio != nullptr) {
            BIO_free(bio);
        }
    }
};

using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using PKeyPtr = FunctionPtr<EVP_PKEY, EVP_PKEY_free>;

std::string to_hex(std::span<const unsigned char> input) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const unsigned char byte : input) {
        out << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return out.str();
}

SecureBytes read_file(const std::string& path) {
    BioPtr bio(BIO_new_file(path.c_str(), "rb"));
    if (bio == nullptr) {
        throw EnvelopeError("unable to open key file: " + path);
    }
    std::error_code error;
    const std::uintmax_t file_size = std::filesystem::file_size(path, error);
    constexpr std::uintmax_t kMaximumKeyFile = 1024 * 1024;
    if (error || file_size == 0 || file_size > kMaximumKeyFile) {
        throw EnvelopeError("key file must be between 1 byte and 1 MiB: " + path);
    }
    SecureBytes buffer(static_cast<std::size_t>(file_size));
    std::size_t offset = 0;
    while (offset < buffer.size()) {
        const int length = BIO_read(
            bio.get(),
            buffer.data() + offset,
            static_cast<int>(std::min<std::size_t>(buffer.size() - offset, 64 * 1024))
        );
        if (length <= 0) {
            throw EnvelopeError("unable to read complete key file: " + path);
        }
        offset += static_cast<std::size_t>(length);
    }
    if (buffer.empty()) {
        throw EnvelopeError("key file is empty: " + path);
    }
    return buffer;
}

bool looks_like_pem(const SecureBytes& data) {
    static constexpr char kPemPrefix[] = "-----BEGIN ";
    return data.size() >= sizeof(kPemPrefix) - 1 &&
           std::memcmp(data.data(), kPemPrefix, sizeof(kPemPrefix) - 1) == 0;
}

PKeyPtr parse_private_key(const CryptoContext& context, std::span<const unsigned char> der) {
    const CryptoContextHandles handles = context.handles();
    const unsigned char* cursor = der.data();
    EVP_PKEY* key = d2i_AutoPrivateKey_ex(
        nullptr,
        &cursor,
        static_cast<long>(der.size()),
        handles.libctx,
        handles.properties
    );
    if (key == nullptr) {
        throw EnvelopeError("invalid private key");
    }
    if (cursor != der.data() + der.size()) {
        EVP_PKEY_free(key);
        throw EnvelopeError("trailing data after private key");
    }
    return PKeyPtr(key);
}

PKeyPtr parse_public_key(const CryptoContext& context, std::span<const unsigned char> der) {
    const CryptoContextHandles handles = context.handles();
    const unsigned char* cursor = der.data();
    EVP_PKEY* key = d2i_PUBKEY_ex(
        nullptr,
        &cursor,
        static_cast<long>(der.size()),
        handles.libctx,
        handles.properties
    );
    if (key == nullptr) {
        throw EnvelopeError("invalid public key");
    }
    if (cursor != der.data() + der.size()) {
        EVP_PKEY_free(key);
        throw EnvelopeError("trailing data after public key");
    }
    return PKeyPtr(key);
}

SecureBytes encode_public_key(EVP_PKEY* key) {
    unsigned char* buffer = nullptr;
    const int length = i2d_PUBKEY(key, &buffer);
    if (length <= 0 || buffer == nullptr) {
        if (buffer != nullptr) {
            OPENSSL_free(buffer);
        }
        throw_openssl("i2d_PUBKEY");
    }
    SecureBytes out(buffer, static_cast<std::size_t>(length));
    OPENSSL_cleanse(buffer, static_cast<std::size_t>(length));
    OPENSSL_free(buffer);
    return out;
}

SecureBytes encode_private_key(EVP_PKEY* key) {
    unsigned char* buffer = nullptr;
    const int length = i2d_PrivateKey(key, &buffer);
    if (length <= 0 || buffer == nullptr) {
        if (buffer != nullptr) {
            OPENSSL_free(buffer);
        }
        throw_openssl("i2d_PrivateKey");
    }
    SecureBytes out(buffer, static_cast<std::size_t>(length));
    OPENSSL_cleanse(buffer, static_cast<std::size_t>(length));
    OPENSSL_free(buffer);
    return out;
}

}

SecureBytes load_public_key_file(const CryptoContext& context, const std::string& path) {
    const SecureBytes raw = read_file(path);
    if (!looks_like_pem(raw)) {

        const PKeyPtr key = parse_public_key(context, raw);
        return encode_public_key(key.get());
    }

    const CryptoContextHandles handles = context.handles();
    BioPtr bio(BIO_new_mem_buf(raw.data(), static_cast<int>(raw.size())));
    if (bio == nullptr) {
        throw_openssl("BIO_new_mem_buf");
    }
    PKeyPtr key(PEM_read_bio_PUBKEY_ex(
        bio.get(),
        nullptr,
        nullptr,
        nullptr,
        handles.libctx,
        handles.properties
    ));
    if (key == nullptr) {
        throw EnvelopeError("invalid public key PEM: " + path);
    }
    return encode_public_key(key.get());
}

SecureBytes load_private_key_file(const CryptoContext& context, const std::string& path) {
    const SecureBytes raw = read_file(path);
    if (!looks_like_pem(raw)) {

        parse_private_key(context, raw);
        return raw;
    }

    const CryptoContextHandles handles = context.handles();
    BioPtr bio(BIO_new_mem_buf(raw.data(), static_cast<int>(raw.size())));
    if (bio == nullptr) {
        throw_openssl("BIO_new_mem_buf");
    }
    PKeyPtr key(PEM_read_bio_PrivateKey_ex(
        bio.get(),
        nullptr,
        nullptr,
        nullptr,
        handles.libctx,
        handles.properties
    ));
    if (key == nullptr) {
        throw EnvelopeError("invalid private key PEM: " + path);
    }
    return encode_private_key(key.get());
}

SecureBytes public_key_of_private(
    const CryptoContext& context,
    std::span<const unsigned char> private_key_der
) {
    const PKeyPtr key = parse_private_key(context, private_key_der);
    return encode_public_key(key.get());
}

std::string key_id_for_public_key(
    const CryptoContext& context,
    std::span<const unsigned char> public_key_der
) {
    const SecureBytes hash = digest(
        context,
        DigestAlgorithm::Sha384,
        public_key_der
    );
    return to_hex(std::span<const unsigned char>(hash.data(), 16));
}

void write_private_key_pem(
    const CryptoContext& context,
    std::span<const unsigned char> private_key_der,
    const std::string& path,
    bool overwrite
) {
    const PKeyPtr key = parse_private_key(context, private_key_der);
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (bio == nullptr) {
        throw_openssl("BIO_new");
    }
    if (PEM_write_bio_PrivateKey(
            bio.get(),
            key.get(),
            nullptr,
            nullptr,
            0,
            nullptr,
            nullptr
        ) != 1) {
        throw_openssl("PEM_write_bio_PrivateKey");
    }
    char* data = nullptr;
    const long length = BIO_get_mem_data(bio.get(), &data);
    if (length <= 0 || data == nullptr) {
        throw_openssl("BIO_get_mem_data");
    }

    detail::secure_write_file(
        path,
        std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(data),
            static_cast<std::size_t>(length)
        ),
        0600,
        overwrite
    );
    OPENSSL_cleanse(data, static_cast<std::size_t>(length));
}

void write_public_key_pem(
    const CryptoContext& context,
    std::span<const unsigned char> public_key_der,
    const std::string& path,
    bool overwrite
) {
    const PKeyPtr key = parse_public_key(context, public_key_der);
    BioPtr bio(BIO_new(BIO_s_mem()));
    if (bio == nullptr) {
        throw_openssl("BIO_new");
    }
    if (PEM_write_bio_PUBKEY(bio.get(), key.get()) != 1) {
        throw_openssl("PEM_write_bio_PUBKEY");
    }
    char* data = nullptr;
    const long length = BIO_get_mem_data(bio.get(), &data);
    if (length <= 0 || data == nullptr) {
        throw_openssl("BIO_get_mem_data");
    }
    detail::secure_write_file(
        path,
        std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(data),
            static_cast<std::size_t>(length)
        ),
        0644,
        overwrite
    );
}

}
