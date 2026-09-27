#pragma once

#include <optional>
#include <span>
#include <string>
#include <vector>

#include "qprotect/crypto_context.hpp"
#include "qprotect/secure_bytes.hpp"

namespace qprotect::cpp {

struct EnvelopeRecipient {
    std::string key_id;
    SecureBytes kem_ciphertext;
    SecureBytes wrap_iv;
    SecureBytes wrapped_key;
    SecureBytes wrap_tag;
};

struct Envelope {
    int version = 1;
    std::string context;
    std::string created_at;
    SecureBytes payload_iv;
    SecureBytes ciphertext;
    SecureBytes tag;
    std::vector<EnvelopeRecipient> recipients;
    std::optional<std::string> signer_key_id;
    std::optional<SecureBytes> signature;

    std::string to_json() const;

    static Envelope from_json(const std::string& text);
};

struct EncryptOptions {

    std::string context;

    std::vector<SecureBytes> recipient_public_key_der;

    std::optional<SecureBytes> signer_private_key_der;
};

struct DecryptOptions {

    SecureBytes recipient_private_key_der;

    std::optional<SecureBytes> signer_public_key_der;

    bool require_signature = false;
};

Envelope encrypt_envelope(const CryptoContext& context,
                          std::span<const unsigned char> plaintext,
                          const EncryptOptions& options);

SecureBytes decrypt_envelope(const CryptoContext& context,
                             const Envelope& envelope,
                             const DecryptOptions& options);

}
