#pragma once

#include <span>
#include <string>
#include <vector>

#include "qprotect/crypto_context.hpp"
#include "qprotect/error.hpp"
#include "qprotect/secure_bytes.hpp"

namespace qprotect::cpp {

enum class DigestAlgorithm { Sha384, Sha512 };

struct KEMKeyPair {
    SecureBytes private_key_der;
    SecureBytes public_key_der;
    std::string key_id;
};

struct KEMEncapsulation {
    SecureBytes ciphertext;
    SecureBytes shared_secret;
};

class MlKem1024PublicKey {
public:
    MlKem1024PublicKey(const CryptoContext& context,
                      std::span<const unsigned char> public_key_der);

private:
    SecureBytes der_;
    friend KEMEncapsulation encapsulate_ml_kem_1024(
        const CryptoContext&, const MlKem1024PublicKey&);
};

class MlKem1024PrivateKey {
public:
    MlKem1024PrivateKey(const CryptoContext& context,
                       std::span<const unsigned char> private_key_der);

private:
    SecureBytes der_;
    friend SecureBytes decapsulate_ml_kem_1024(
        const CryptoContext&, const MlKem1024PrivateKey&,
        std::span<const unsigned char>);
};

KEMEncapsulation encapsulate_ml_kem_1024(const CryptoContext& context,
                                       const MlKem1024PublicKey& public_key);

SecureBytes decapsulate_ml_kem_1024(const CryptoContext& context,
                                  const MlKem1024PrivateKey& private_key,
                                  std::span<const unsigned char> ciphertext);

struct SignatureKeyPair {
    SecureBytes private_key_der;
    SecureBytes public_key_der;
    std::string key_id;
};

struct AeadResult {
    SecureBytes ciphertext;
    SecureBytes tag;
};

SecureBytes digest(const CryptoContext& context,
                   DigestAlgorithm algorithm,
                   std::span<const unsigned char> input);

SecureBytes hkdf_sha384(const CryptoContext& context,
                        std::span<const unsigned char> ikm,
                        std::span<const unsigned char> salt,
                        std::span<const unsigned char> info,
                        std::size_t output_length);

AeadResult aes_256_gcm_encrypt(const CryptoContext& context,
                               std::span<const unsigned char> key,
                               std::span<const unsigned char> nonce,
                               std::span<const unsigned char> plaintext,
                               std::span<const unsigned char> aad);

SecureBytes aes_256_gcm_decrypt(const CryptoContext& context,
                                std::span<const unsigned char> key,
                                std::span<const unsigned char> nonce,
                                std::span<const unsigned char> ciphertext,
                                std::span<const unsigned char> tag,
                                std::span<const unsigned char> aad);

KEMKeyPair generate_ml_kem_1024(const CryptoContext& context);

KEMEncapsulation encapsulate_ml_kem_1024(const CryptoContext& context,
                                          std::span<const unsigned char> public_key_der);

SecureBytes decapsulate_ml_kem_1024(const CryptoContext& context,
                                    std::span<const unsigned char> private_key_der,
                                    std::span<const unsigned char> ciphertext);

SignatureKeyPair generate_ml_dsa_87(const CryptoContext& context);

SecureBytes sign_ml_dsa_87(const CryptoContext& context,
                           std::span<const unsigned char> private_key_der,
                           std::span<const unsigned char> message);

bool verify_ml_dsa_87(const CryptoContext& context,
                      std::span<const unsigned char> public_key_der,
                      std::span<const unsigned char> message,
                      std::span<const unsigned char> signature);

}
