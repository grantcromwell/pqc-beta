#include "qprotect/algorithms.hpp"

#include "crypto_context_handles.hpp"
#include "openssl_utils.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <algorithm>
#include <climits>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <utility>

namespace qprotect::cpp {
namespace {

using detail::FunctionPtr;
using detail::throw_openssl;

using MdPtr = FunctionPtr<EVP_MD, EVP_MD_free>;
using MdCtxPtr = FunctionPtr<EVP_MD_CTX, EVP_MD_CTX_free>;
using CipherPtr = FunctionPtr<EVP_CIPHER, EVP_CIPHER_free>;
using CipherCtxPtr = FunctionPtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>;
using KdfPtr = FunctionPtr<EVP_KDF, EVP_KDF_free>;
using KdfCtxPtr = FunctionPtr<EVP_KDF_CTX, EVP_KDF_CTX_free>;
using SignaturePtr = FunctionPtr<EVP_SIGNATURE, EVP_SIGNATURE_free>;
using PKeyPtr = FunctionPtr<EVP_PKEY, EVP_PKEY_free>;
using PKeyCtxPtr = FunctionPtr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;

constexpr std::size_t kMaximumKeyDerLength = 1024 * 1024;
constexpr std::size_t kMlKem1024CiphertextLength = 1568;
constexpr std::size_t kMlKemSharedSecretLength = 32;

struct SecureOpenSSLFree {
    std::size_t length = 0;
    void operator()(unsigned char* value) const noexcept {
        if (value != nullptr) {
            OPENSSL_cleanse(value, length);
            OPENSSL_free(value);
        }
    }
};

using SecureDerBuffer = std::unique_ptr<unsigned char, SecureOpenSSLFree>;

SecureDerBuffer encode_private_key(EVP_PKEY* key) {
    unsigned char* buffer = nullptr;
    const int length = i2d_PrivateKey(key, &buffer);
    if (length <= 0 || buffer == nullptr) {
        if (buffer != nullptr) {
            OPENSSL_free(buffer);
        }
        throw_openssl("i2d_PrivateKey");
    }
    return SecureDerBuffer(buffer, SecureOpenSSLFree{static_cast<std::size_t>(length)});
}

SecureDerBuffer encode_public_key(EVP_PKEY* key) {
    unsigned char* buffer = nullptr;
    const int length = i2d_PUBKEY(key, &buffer);
    if (length <= 0 || buffer == nullptr) {
        if (buffer != nullptr) {
            OPENSSL_free(buffer);
        }
        throw_openssl("i2d_PUBKEY");
    }
    return SecureDerBuffer(buffer, SecureOpenSSLFree{static_cast<std::size_t>(length)});
}

PKeyPtr load_private_key(const CryptoContextHandles& handles,
                         std::span<const unsigned char> private_key_der) {
    if (private_key_der.empty() || private_key_der.size() > kMaximumKeyDerLength) {
        throw CryptoError("private key DER must be between 1 byte and 1 MiB");
    }
    const unsigned char* cursor = private_key_der.data();
    EVP_PKEY* key = d2i_AutoPrivateKey_ex(
        nullptr,
        &cursor,
        static_cast<long>(private_key_der.size()),
        handles.libctx,
        handles.properties
    );
    if (key == nullptr) {
        throw_openssl("d2i_AutoPrivateKey_ex");
    }
    PKeyPtr parsed(key);
    if (cursor != private_key_der.data() + private_key_der.size()) {
        throw CryptoError("trailing data after private key DER");
    }
    return parsed;
}

PKeyPtr load_public_key(const CryptoContextHandles& handles,
                        std::span<const unsigned char> public_key_der) {
    if (public_key_der.empty() || public_key_der.size() > kMaximumKeyDerLength) {
        throw CryptoError("public key DER must be between 1 byte and 1 MiB");
    }
    const unsigned char* cursor = public_key_der.data();
    EVP_PKEY* key = d2i_PUBKEY_ex(
        nullptr,
        &cursor,
        static_cast<long>(public_key_der.size()),
        handles.libctx,
        handles.properties
    );
    if (key == nullptr) {
        throw_openssl("d2i_PUBKEY_ex");
    }
    PKeyPtr parsed(key);
    if (cursor != public_key_der.data() + public_key_der.size()) {
        throw CryptoError("trailing data after public key DER");
    }
    return parsed;
}

std::string to_hex(std::span<const unsigned char> input) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const unsigned char byte : input) {
        output << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return output.str();
}

std::size_t update_encryption_chunks(
    EVP_CIPHER_CTX* context,
    unsigned char* output,
    std::span<const unsigned char> input
) {
    std::size_t output_offset = 0;
    std::size_t input_offset = 0;
    while (input_offset < input.size()) {
        const std::size_t remaining = input.size() - input_offset;
        const int chunk_length = static_cast<int>(
            std::min<std::size_t>(remaining, static_cast<std::size_t>(INT_MAX))
        );
        int chunk_output_length = 0;
        if (EVP_EncryptUpdate(
                context,
                output + output_offset,
                &chunk_output_length,
                input.data() + input_offset,
                chunk_length
            ) != 1) {
            throw_openssl("EVP_EncryptUpdate");
        }
        output_offset += static_cast<std::size_t>(chunk_output_length);
        input_offset += static_cast<std::size_t>(chunk_length);
    }
    return output_offset;
}

std::size_t update_decryption_chunks(
    EVP_CIPHER_CTX* context,
    unsigned char* output,
    std::span<const unsigned char> input
) {
    std::size_t output_offset = 0;
    std::size_t input_offset = 0;
    while (input_offset < input.size()) {
        const std::size_t remaining = input.size() - input_offset;
        const int chunk_length = static_cast<int>(
            std::min<std::size_t>(remaining, static_cast<std::size_t>(INT_MAX))
        );
        int chunk_output_length = 0;
        if (EVP_DecryptUpdate(
                context,
                output + output_offset,
                &chunk_output_length,
                input.data() + input_offset,
                chunk_length
            ) != 1) {
            throw_openssl("EVP_DecryptUpdate");
        }
        output_offset += static_cast<std::size_t>(chunk_output_length);
        input_offset += static_cast<std::size_t>(chunk_length);
    }
    return output_offset;
}

void update_aad(EVP_CIPHER_CTX* context, std::span<const unsigned char> aad, bool encrypting) {
    std::size_t offset = 0;
    while (offset < aad.size()) {
        const std::size_t remaining = aad.size() - offset;
        const int chunk_length = static_cast<int>(
            std::min<std::size_t>(remaining, static_cast<std::size_t>(INT_MAX))
        );
        int output_length = 0;
        const int result = encrypting
            ? EVP_EncryptUpdate(
                context,
                nullptr,
                &output_length,
                aad.data() + offset,
                chunk_length
            )
            : EVP_DecryptUpdate(
                context,
                nullptr,
                &output_length,
                aad.data() + offset,
                chunk_length
            );
        if (result != 1) {
            throw_openssl(encrypting ? "EVP_EncryptUpdate(AAD)" : "EVP_DecryptUpdate(AAD)");
        }
        offset += static_cast<std::size_t>(chunk_length);
    }
}

}

SecureBytes digest(
    const CryptoContext& context,
    DigestAlgorithm algorithm,
    std::span<const unsigned char> input
) {
    const CryptoContextHandles handles = context.handles();
    const char* algorithm_name = algorithm == DigestAlgorithm::Sha384
        ? "SHA384"
        : "SHA512";

    MdPtr message_digest(EVP_MD_fetch(handles.libctx, algorithm_name, handles.properties));
    if (message_digest == nullptr) {
        throw CryptoError(std::string("failed to fetch ") + algorithm_name);
    }

    const int digest_size = EVP_MD_get_size(message_digest.get());
    if (digest_size <= 0) {
        throw CryptoError("unsupported digest output size");
    }

    MdCtxPtr digest_context(EVP_MD_CTX_new());
    if (digest_context == nullptr) {
        throw_openssl("EVP_MD_CTX_new");
    }
    if (EVP_DigestInit_ex2(digest_context.get(), message_digest.get(), nullptr) != 1) {
        throw_openssl("EVP_DigestInit_ex2");
    }
    if (EVP_DigestUpdate(digest_context.get(), input.data(), input.size()) != 1) {
        throw_openssl("EVP_DigestUpdate");
    }

    SecureBytes output(static_cast<std::size_t>(digest_size));
    unsigned int actual_size = 0;
    if (EVP_DigestFinal_ex(
            digest_context.get(),
            output.data(),
            &actual_size
        ) != 1) {
        throw_openssl("EVP_DigestFinal_ex");
    }
    if (actual_size != output.size()) {
        throw CryptoError("unexpected digest output size");
    }
    return output;
}

SecureBytes hkdf_sha384(
    const CryptoContext& context,
    std::span<const unsigned char> ikm,
    std::span<const unsigned char> salt,
    std::span<const unsigned char> info,
    std::size_t output_length
) {
    if (output_length == 0 || output_length > 255 * 48) {
        throw CryptoError("invalid HKDF-SHA-384 output length");
    }

    const CryptoContextHandles handles = context.handles();
    KdfPtr kdf(EVP_KDF_fetch(handles.libctx, "HKDF", handles.properties));
    if (kdf == nullptr) {
        throw CryptoError("failed to fetch HKDF");
    }

    KdfCtxPtr kdf_context(EVP_KDF_CTX_new(kdf.get()));
    if (kdf_context == nullptr) {
        throw_openssl("EVP_KDF_CTX_new");
    }

    SecureBytes ikm_copy(ikm);
    SecureBytes salt_copy(salt);
    SecureBytes info_copy(info);
    char digest_name[] = "SHA384";
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;

    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST,
            digest_name,
            std::strlen(digest_name)
        ),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY,
            ikm_copy.data(),
            ikm_copy.size()
        ),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            salt_copy.data(),
            salt_copy.size()
        ),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO,
            info_copy.data(),
            info_copy.size()
        ),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_end(),
    };

    SecureBytes output(output_length);
    if (EVP_KDF_derive(kdf_context.get(), output.data(), output.size(), parameters) != 1) {
        throw_openssl("EVP_KDF_derive");
    }
    return output;
}

AeadResult aes_256_gcm_encrypt(
    const CryptoContext& context,
    std::span<const unsigned char> key,
    std::span<const unsigned char> nonce,
    std::span<const unsigned char> plaintext,
    std::span<const unsigned char> aad
) {
    if (key.size() != 32) {
        throw CryptoError("AES-256-GCM requires a 32-byte key");
    }
    if (nonce.size() != 12) {
        throw CryptoError("AES-256-GCM requires a 12-byte nonce");
    }

    const CryptoContextHandles handles = context.handles();
    CipherPtr cipher(EVP_CIPHER_fetch(handles.libctx, "AES-256-GCM", handles.properties));
    if (cipher == nullptr) {
        throw CryptoError("failed to fetch AES-256-GCM");
    }

    CipherCtxPtr cipher_context(EVP_CIPHER_CTX_new());
    if (cipher_context == nullptr) {
        throw_openssl("EVP_CIPHER_CTX_new");
    }

    if (EVP_EncryptInit_ex2(
            cipher_context.get(),
            cipher.get(),
            nullptr,
            nullptr,
            nullptr
        ) != 1) {
        throw_openssl("EVP_EncryptInit_ex2(cipher)");
    }
    if (EVP_CIPHER_CTX_ctrl(
            cipher_context.get(),
            EVP_CTRL_GCM_SET_IVLEN,
            static_cast<int>(nonce.size()),
            nullptr
        ) != 1) {
        throw_openssl("EVP_CIPHER_CTX_ctrl(SET_IVLEN)");
    }
    if (EVP_EncryptInit_ex2(
            cipher_context.get(),
            nullptr,
            key.data(),
            nonce.data(),
            nullptr
        ) != 1) {
        throw_openssl("EVP_EncryptInit_ex2(key/IV)");
    }

    update_aad(cipher_context.get(), aad, true);

    SecureBytes ciphertext(plaintext.size() + 16);
    std::size_t ciphertext_length = update_encryption_chunks(
        cipher_context.get(),
        ciphertext.data(),
        plaintext
    );

    int final_length = 0;
    if (EVP_EncryptFinal_ex(
            cipher_context.get(),
            ciphertext.data() + ciphertext_length,
            &final_length
        ) != 1) {
        throw_openssl("EVP_EncryptFinal_ex");
    }
    ciphertext_length += static_cast<std::size_t>(final_length);
    if (ciphertext_length > plaintext.size()) {
        throw CryptoError("unexpected AES-256-GCM ciphertext length");
    }
    ciphertext.resize(ciphertext_length);

    SecureBytes tag(16);
    if (EVP_CIPHER_CTX_ctrl(
            cipher_context.get(),
            EVP_CTRL_GCM_GET_TAG,
            static_cast<int>(tag.size()),
            tag.data()
        ) != 1) {
        throw_openssl("EVP_CIPHER_CTX_ctrl(GET_TAG)");
    }

    return AeadResult{std::move(ciphertext), std::move(tag)};
}

SecureBytes aes_256_gcm_decrypt(
    const CryptoContext& context,
    std::span<const unsigned char> key,
    std::span<const unsigned char> nonce,
    std::span<const unsigned char> ciphertext,
    std::span<const unsigned char> tag,
    std::span<const unsigned char> aad
) {
    if (key.size() != 32) {
        throw CryptoError("AES-256-GCM requires a 32-byte key");
    }
    if (nonce.size() != 12) {
        throw CryptoError("AES-256-GCM requires a 12-byte nonce");
    }
    if (tag.size() != 16) {
        throw CryptoError("AES-256-GCM requires a 16-byte tag");
    }

    const CryptoContextHandles handles = context.handles();
    CipherPtr cipher(EVP_CIPHER_fetch(handles.libctx, "AES-256-GCM", handles.properties));
    if (cipher == nullptr) {
        throw CryptoError("failed to fetch AES-256-GCM");
    }

    CipherCtxPtr cipher_context(EVP_CIPHER_CTX_new());
    if (cipher_context == nullptr) {
        throw_openssl("EVP_CIPHER_CTX_new");
    }

    if (EVP_DecryptInit_ex2(
            cipher_context.get(),
            cipher.get(),
            nullptr,
            nullptr,
            nullptr
        ) != 1) {
        throw_openssl("EVP_DecryptInit_ex2(cipher)");
    }
    if (EVP_CIPHER_CTX_ctrl(
            cipher_context.get(),
            EVP_CTRL_GCM_SET_IVLEN,
            static_cast<int>(nonce.size()),
            nullptr
        ) != 1) {
        throw_openssl("EVP_CIPHER_CTX_ctrl(SET_IVLEN)");
    }
    if (EVP_DecryptInit_ex2(
            cipher_context.get(),
            nullptr,
            key.data(),
            nonce.data(),
            nullptr
        ) != 1) {
        throw_openssl("EVP_DecryptInit_ex2(key/IV)");
    }

    update_aad(cipher_context.get(), aad, false);

    SecureBytes plaintext(ciphertext.size() + 16);
    std::size_t plaintext_length = update_decryption_chunks(
        cipher_context.get(),
        plaintext.data(),
        ciphertext
    );

    SecureBytes tag_copy(tag);
    if (EVP_CIPHER_CTX_ctrl(
            cipher_context.get(),
            EVP_CTRL_GCM_SET_TAG,
            static_cast<int>(tag_copy.size()),
            tag_copy.data()
        ) != 1) {
        throw_openssl("EVP_CIPHER_CTX_ctrl(SET_TAG)");
    }

    int final_length = 0;
    if (EVP_DecryptFinal_ex(
            cipher_context.get(),
            plaintext.data() + plaintext_length,
            &final_length
        ) != 1) {
        throw CryptoError("AES-256-GCM authentication failed");
    }
    plaintext_length += static_cast<std::size_t>(final_length);
    if (plaintext_length > ciphertext.size()) {
        throw CryptoError("unexpected AES-256-GCM plaintext length");
    }
    plaintext.resize(plaintext_length);
    return plaintext;
}

KEMKeyPair generate_ml_kem_1024(const CryptoContext& context) {
    const CryptoContextHandles handles = context.handles();
    EVP_PKEY* raw_key = EVP_PKEY_Q_keygen(
        handles.libctx,
        handles.properties,
        "ML-KEM-1024"
    );
    if (raw_key == nullptr) {
        throw_openssl("EVP_PKEY_Q_keygen(ML-KEM-1024)");
    }
    PKeyPtr key(raw_key);

    SecureDerBuffer private_der = encode_private_key(key.get());
    SecureDerBuffer public_der = encode_public_key(key.get());

    SecureBytes private_key_der(private_der.get(), private_der.get_deleter().length);
    SecureBytes public_key_der(public_der.get(), public_der.get_deleter().length);
    const SecureBytes public_key_digest = digest(
        context,
        DigestAlgorithm::Sha384,
        std::span<const unsigned char>(
            public_key_der.data(),
            public_key_der.size()
        )
    );

    return KEMKeyPair{
        std::move(private_key_der),
        std::move(public_key_der),
        to_hex(std::span<const unsigned char>(public_key_digest.data(), 16)),
    };
}

MlKem1024PublicKey::MlKem1024PublicKey(
    const CryptoContext& context,
    std::span<const unsigned char> public_key_der
) {
    const PKeyPtr key = load_public_key(context.handles(), public_key_der);
    if (EVP_PKEY_is_a(key.get(), "ML-KEM-1024") != 1) {
        throw CryptoError("public key must use ML-KEM-1024");
    }
    der_.assign(public_key_der);
}

MlKem1024PrivateKey::MlKem1024PrivateKey(
    const CryptoContext& context,
    std::span<const unsigned char> private_key_der
) {
    const PKeyPtr key = load_private_key(context.handles(), private_key_der);
    if (EVP_PKEY_is_a(key.get(), "ML-KEM-1024") != 1) {
        throw CryptoError("private key must use ML-KEM-1024");
    }
    der_.assign(private_key_der);
}

KEMEncapsulation encapsulate_ml_kem_1024(
    const CryptoContext& context,
    std::span<const unsigned char> public_key_der
) {
    return encapsulate_ml_kem_1024(context, MlKem1024PublicKey(context, public_key_der));
}

KEMEncapsulation encapsulate_ml_kem_1024(
    const CryptoContext& context,
    const MlKem1024PublicKey& validated_key
) {
    const CryptoContextHandles handles = context.handles();
    PKeyPtr public_key = load_public_key(handles, validated_key.der_);
    PKeyCtxPtr key_context(
        EVP_PKEY_CTX_new_from_pkey(handles.libctx, public_key.get(), handles.properties)
    );
    if (key_context == nullptr) {
        throw_openssl("EVP_PKEY_CTX_new_from_pkey(ML-KEM-1024)");
    }
    if (EVP_PKEY_encapsulate_init(key_context.get(), nullptr) != 1) {
        throw_openssl("EVP_PKEY_encapsulate_init");
    }

    std::size_t ciphertext_length = 0;
    std::size_t shared_secret_length = 0;
    if (EVP_PKEY_encapsulate(
            key_context.get(),
            nullptr,
            &ciphertext_length,
            nullptr,
            &shared_secret_length
        ) != 1) {
        throw_openssl("EVP_PKEY_encapsulate(length)");
    }

    if (ciphertext_length != kMlKem1024CiphertextLength ||
        shared_secret_length != kMlKemSharedSecretLength) {
        throw CryptoError("invalid ML-KEM-1024 encapsulation lengths");
    }
    SecureBytes ciphertext(ciphertext_length);
    SecureBytes shared_secret(shared_secret_length);
    if (EVP_PKEY_encapsulate(
            key_context.get(),
            ciphertext.data(),
            &ciphertext_length,
            shared_secret.data(),
            &shared_secret_length
        ) != 1) {
        throw_openssl("EVP_PKEY_encapsulate");
    }
    if (ciphertext_length != kMlKem1024CiphertextLength ||
        shared_secret_length != kMlKemSharedSecretLength) {
        throw CryptoError("invalid ML-KEM-1024 encapsulation lengths");
    }
    return KEMEncapsulation{std::move(ciphertext), std::move(shared_secret)};
}

SecureBytes decapsulate_ml_kem_1024(
    const CryptoContext& context,
    std::span<const unsigned char> private_key_der,
    std::span<const unsigned char> ciphertext
) {
    return decapsulate_ml_kem_1024(context, MlKem1024PrivateKey(context, private_key_der), ciphertext);
}

SecureBytes decapsulate_ml_kem_1024(
    const CryptoContext& context,
    const MlKem1024PrivateKey& validated_key,
    std::span<const unsigned char> ciphertext
) {
    if (ciphertext.size() != kMlKem1024CiphertextLength) {
        throw CryptoError("ML-KEM-1024 requires a 1568-byte ciphertext");
    }
    const CryptoContextHandles handles = context.handles();
    PKeyPtr private_key = load_private_key(handles, validated_key.der_);
    PKeyCtxPtr key_context(
        EVP_PKEY_CTX_new_from_pkey(handles.libctx, private_key.get(), handles.properties)
    );
    if (key_context == nullptr) {
        throw_openssl("EVP_PKEY_CTX_new_from_pkey(ML-KEM-1024)");
    }
    if (EVP_PKEY_decapsulate_init(key_context.get(), nullptr) != 1) {
        throw_openssl("EVP_PKEY_decapsulate_init");
    }

    std::size_t shared_secret_length = 0;
    if (EVP_PKEY_decapsulate(
            key_context.get(),
            nullptr,
            &shared_secret_length,
            ciphertext.data(),
            ciphertext.size()
        ) != 1) {
        throw_openssl("EVP_PKEY_decapsulate(length)");
    }

    if (shared_secret_length != kMlKemSharedSecretLength) {
        throw CryptoError("invalid ML-KEM-1024 shared-secret length");
    }
    SecureBytes shared_secret(shared_secret_length);
    if (EVP_PKEY_decapsulate(
            key_context.get(),
            shared_secret.data(),
            &shared_secret_length,
            ciphertext.data(),
            ciphertext.size()
        ) != 1) {
        throw_openssl("EVP_PKEY_decapsulate");
    }
    if (shared_secret_length != kMlKemSharedSecretLength) {
        throw CryptoError("invalid ML-KEM-1024 shared-secret length");
    }
    return shared_secret;
}

SignatureKeyPair generate_ml_dsa_87(const CryptoContext& context) {
    const CryptoContextHandles handles = context.handles();
    EVP_PKEY* raw_key = EVP_PKEY_Q_keygen(
        handles.libctx,
        handles.properties,
        "ML-DSA-87"
    );
    if (raw_key == nullptr) {
        throw_openssl("EVP_PKEY_Q_keygen(ML-DSA-87)");
    }
    PKeyPtr key(raw_key);

    SecureDerBuffer private_der = encode_private_key(key.get());
    SecureDerBuffer public_der = encode_public_key(key.get());

    SecureBytes private_key_der(private_der.get(), private_der.get_deleter().length);
    SecureBytes public_key_der(public_der.get(), public_der.get_deleter().length);
    const SecureBytes public_key_digest = digest(
        context,
        DigestAlgorithm::Sha384,
        std::span<const unsigned char>(
            public_key_der.data(),
            public_key_der.size()
        )
    );

    return SignatureKeyPair{
        std::move(private_key_der),
        std::move(public_key_der),
        to_hex(std::span<const unsigned char>(public_key_digest.data(), 16)),
    };
}

SecureBytes sign_ml_dsa_87(
    const CryptoContext& context,
    std::span<const unsigned char> private_key_der,
    std::span<const unsigned char> message
) {
    const CryptoContextHandles handles = context.handles();
    PKeyPtr private_key = load_private_key(handles, private_key_der);
    SignaturePtr signature_algorithm(
        EVP_SIGNATURE_fetch(handles.libctx, "ML-DSA-87", handles.properties)
    );
    if (signature_algorithm == nullptr) {
        throw CryptoError("failed to fetch ML-DSA-87");
    }

    PKeyCtxPtr key_context(
        EVP_PKEY_CTX_new_from_pkey(handles.libctx, private_key.get(), handles.properties)
    );
    if (key_context == nullptr) {
        throw_openssl("EVP_PKEY_CTX_new_from_pkey(ML-DSA-87)");
    }
    if (EVP_PKEY_sign_message_init(
            key_context.get(),
            signature_algorithm.get(),
            nullptr
        ) != 1) {
        throw_openssl("EVP_PKEY_sign_message_init");
    }

    std::size_t signature_length = 0;
    if (EVP_PKEY_sign(
            key_context.get(),
            nullptr,
            &signature_length,
            message.data(),
            message.size()
        ) != 1) {
        throw_openssl("EVP_PKEY_sign(length)");
    }

    SecureBytes signature(signature_length);
    if (EVP_PKEY_sign(
            key_context.get(),
            signature.data(),
            &signature_length,
            message.data(),
            message.size()
        ) != 1) {
        throw_openssl("EVP_PKEY_sign");
    }
    signature.resize(signature_length);
    return signature;
}

bool verify_ml_dsa_87(
    const CryptoContext& context,
    std::span<const unsigned char> public_key_der,
    std::span<const unsigned char> message,
    std::span<const unsigned char> signature
) {
    const CryptoContextHandles handles = context.handles();
    PKeyPtr public_key = load_public_key(handles, public_key_der);
    SignaturePtr signature_algorithm(
        EVP_SIGNATURE_fetch(handles.libctx, "ML-DSA-87", handles.properties)
    );
    if (signature_algorithm == nullptr) {
        throw CryptoError("failed to fetch ML-DSA-87");
    }

    PKeyCtxPtr key_context(
        EVP_PKEY_CTX_new_from_pkey(handles.libctx, public_key.get(), handles.properties)
    );
    if (key_context == nullptr) {
        throw_openssl("EVP_PKEY_CTX_new_from_pkey(ML-DSA-87)");
    }
    if (EVP_PKEY_verify_message_init(
            key_context.get(),
            signature_algorithm.get(),
            nullptr
        ) != 1) {
        throw_openssl("EVP_PKEY_verify_message_init");
    }

    return EVP_PKEY_verify(
        key_context.get(),
        signature.data(),
        signature.size(),
        message.data(),
        message.size()
    ) == 1;
}

}
