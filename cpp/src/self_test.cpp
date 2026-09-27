#include "qprotect/self_test.hpp"

#include "qprotect/algorithms.hpp"
#include "qprotect/constants.hpp"
#include "qprotect/error.hpp"

#include "crypto_context_handles.hpp"
#include "nist_acvp_vectors.hpp"
#include "openssl_utils.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <exception>
#include <iomanip>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

namespace qprotect::cpp {
namespace {

using PKeyPtr = detail::FunctionPtr<EVP_PKEY, EVP_PKEY_free>;
using PKeyCtxPtr = detail::FunctionPtr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using SignaturePtr = detail::FunctionPtr<EVP_SIGNATURE, EVP_SIGNATURE_free>;
using detail::throw_openssl;

SecureBytes from_hex(std::string_view value) {
    if (value.size() % 2 != 0) {
        throw CryptoError("invalid hex test vector length");
    }
    std::vector<unsigned char> output;
    output.reserve(value.size() / 2);
    for (std::size_t i = 0; i < value.size(); i += 2) {
        unsigned int byte = 0;
        const auto result = std::from_chars(
            value.data() + i,
            value.data() + i + 2,
            byte,
            16
        );
        if (result.ec != std::errc{} || result.ptr != value.data() + i + 2) {
            throw CryptoError("invalid hex test vector");
        }
        output.push_back(static_cast<unsigned char>(byte));
    }
    return SecureBytes(output.data(), output.size());
}

bool equal_bytes(std::span<const unsigned char> left,
                 std::span<const unsigned char> right) {
    return left.size() == right.size() &&
           std::equal(left.begin(), left.end(), right.begin());
}

bool matches_sha384(const CryptoContext& context,
                    std::span<const unsigned char> value,
                    std::string_view expected_hex) {
    const SecureBytes actual = digest(context, DigestAlgorithm::Sha384, value);
    const SecureBytes expected = from_hex(expected_hex);
    return equal_bytes(actual, expected);
}

PKeyPtr generate_seeded_key(const CryptoContext& context,
                            const char* algorithm,
                            const char* seed_parameter,
                            SecureBytes& seed) {
    const CryptoContextHandles handles = context.handles();
    PKeyCtxPtr key_context(
        EVP_PKEY_CTX_new_from_name(handles.libctx, algorithm, handles.properties)
    );
    if (key_context == nullptr) {
        throw_openssl(std::string("EVP_PKEY_CTX_new_from_name(") + algorithm + ")");
    }
    if (EVP_PKEY_keygen_init(key_context.get()) != 1) {
        throw_openssl(std::string("EVP_PKEY_keygen_init(") + algorithm + ")");
    }
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(
            seed_parameter,
            seed.data(),
            seed.size()
        ),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_PKEY_CTX_set_params(key_context.get(), params) != 1) {
        throw_openssl(std::string("set deterministic seed for ") + algorithm);
    }
    EVP_PKEY* raw_key = nullptr;
    if (EVP_PKEY_generate(key_context.get(), &raw_key) != 1 || raw_key == nullptr) {
        throw_openssl(std::string("EVP_PKEY_generate(") + algorithm + ")");
    }
    return PKeyPtr(raw_key);
}

SecureBytes raw_public_key(EVP_PKEY* key) {
    std::size_t length = 0;
    if (EVP_PKEY_get_raw_public_key(key, nullptr, &length) != 1) {
        throw_openssl("EVP_PKEY_get_raw_public_key(length)");
    }
    SecureBytes output(length);
    if (EVP_PKEY_get_raw_public_key(key, output.data(), &length) != 1) {
        throw_openssl("EVP_PKEY_get_raw_public_key");
    }
    output.resize(length);
    return output;
}

SecureBytes raw_private_key(EVP_PKEY* key) {
    std::size_t length = 0;
    if (EVP_PKEY_get_raw_private_key(key, nullptr, &length) != 1) {
        throw_openssl("EVP_PKEY_get_raw_private_key(length)");
    }
    SecureBytes output(length);
    if (EVP_PKEY_get_raw_private_key(key, output.data(), &length) != 1) {
        throw_openssl("EVP_PKEY_get_raw_private_key");
    }
    output.resize(length);
    return output;
}

KEMEncapsulation encapsulate_with_ikme(
    const CryptoContext& context,
    std::span<const unsigned char> raw_public,
    SecureBytes& ikme
) {
    const CryptoContextHandles handles = context.handles();
    PKeyPtr public_key(EVP_PKEY_new_raw_public_key_ex(
        handles.libctx,
        "ML-KEM-1024",
        handles.properties,
        raw_public.data(),
        raw_public.size()
    ));
    if (public_key == nullptr) {
        throw_openssl("EVP_PKEY_new_raw_public_key_ex(ML-KEM-1024)");
    }
    PKeyCtxPtr key_context(
        EVP_PKEY_CTX_new_from_pkey(handles.libctx, public_key.get(), handles.properties)
    );
    if (key_context == nullptr ||
        EVP_PKEY_encapsulate_init(key_context.get(), nullptr) != 1) {
        throw_openssl("EVP_PKEY_encapsulate_init(ML-KEM-1024 KAT)");
    }
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_KEM_PARAM_IKME,
            ikme.data(),
            ikme.size()
        ),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_PKEY_CTX_set_params(key_context.get(), params) != 1) {
        throw_openssl("set ML-KEM-1024 KAT encapsulation entropy");
    }

    std::size_t ciphertext_length = 0;
    std::size_t secret_length = 0;
    if (EVP_PKEY_encapsulate(
            key_context.get(), nullptr, &ciphertext_length, nullptr, &secret_length
        ) != 1) {
        throw_openssl("EVP_PKEY_encapsulate(KAT lengths)");
    }
    SecureBytes ciphertext(ciphertext_length);
    SecureBytes secret(secret_length);
    if (EVP_PKEY_encapsulate(
            key_context.get(),
            ciphertext.data(),
            &ciphertext_length,
            secret.data(),
            &secret_length
        ) != 1) {
        throw_openssl("EVP_PKEY_encapsulate(KAT)");
    }
    ciphertext.resize(ciphertext_length);
    secret.resize(secret_length);
    return KEMEncapsulation{std::move(ciphertext), std::move(secret)};
}

SecureBytes deterministic_internal_signature(
    const CryptoContext& context,
    std::span<const unsigned char> raw_private,
    std::span<const unsigned char> message
) {
    const CryptoContextHandles handles = context.handles();
    PKeyPtr private_key(EVP_PKEY_new_raw_private_key_ex(
        handles.libctx,
        "ML-DSA-87",
        handles.properties,
        raw_private.data(),
        raw_private.size()
    ));
    if (private_key == nullptr) {
        throw_openssl("EVP_PKEY_new_raw_private_key_ex(ML-DSA-87)");
    }
    SignaturePtr signature_algorithm(
        EVP_SIGNATURE_fetch(handles.libctx, "ML-DSA-87", handles.properties)
    );
    PKeyCtxPtr key_context(
        EVP_PKEY_CTX_new_from_pkey(handles.libctx, private_key.get(), handles.properties)
    );
    if (signature_algorithm == nullptr || key_context == nullptr ||
        EVP_PKEY_sign_message_init(
            key_context.get(), signature_algorithm.get(), nullptr
        ) != 1) {
        throw_openssl("EVP_PKEY_sign_message_init(ML-DSA-87 KAT)");
    }
    int deterministic = 1;
    int message_encoding = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic
        ),
        OSSL_PARAM_construct_int(
            OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &message_encoding
        ),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_PKEY_CTX_set_params(key_context.get(), params) != 1) {
        throw_openssl("set ML-DSA-87 deterministic internal KAT parameters");
    }
    std::size_t signature_length = 0;
    if (EVP_PKEY_sign(
            key_context.get(), nullptr, &signature_length, message.data(), message.size()
        ) != 1) {
        throw_openssl("EVP_PKEY_sign(ML-DSA-87 KAT length)");
    }
    SecureBytes signature(signature_length);
    if (EVP_PKEY_sign(
            key_context.get(),
            signature.data(),
            &signature_length,
            message.data(),
            message.size()
        ) != 1) {
        throw_openssl("EVP_PKEY_sign(ML-DSA-87 KAT)");
    }
    signature.resize(signature_length);
    return signature;
}

void add_check(SelfTestReport& report, const std::string& name, bool passed) {
    report.checks.push_back(SelfTestCheck{name, passed});
    report.passed = report.passed && passed;
}

template <typename Function>
void run_check(SelfTestReport& report, const std::string& name, Function&& function) {
    bool passed = false;
    try {
        passed = function();
    } catch (const std::exception&) {
        passed = false;
    }
    add_check(report, name, passed);
}

}

SelfTestReport run_self_tests(const CryptoContext& context) {
    SelfTestReport report;
    report.passed = true;
    report.provider = context.provider_name();

    run_check(report, "provider_self_test", [&context]() {
        return context.provider_self_test();
    });

    run_check(report, "provider_algorithm_inventory", [&context]() {
        context.assert_ready();
        return true;
    });

    run_check(report, "random_bytes", [&context]() {
        const SecureBytes first = context.random_bytes(64);
        const SecureBytes second = context.random_bytes(64);

        return first.size() == 64 && second.size() == 64 && first != second;
    });

    run_check(report, "sha384_known_answer", [&context]() {
        const std::string input = "abc";
        const SecureBytes output = digest(
            context,
            DigestAlgorithm::Sha384,
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(input.data()),
                input.size()
            )
        );
        const auto expected = from_hex(
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
            "8086072ba1e7cc2358baeca134c825a7"
        );
        return output.size() == expected.size() &&
               std::equal(output.begin(), output.end(), expected.begin());
    });

    run_check(report, "sha512_known_answer", [&context]() {
        const std::string input = "abc";
        const SecureBytes output = digest(
            context,
            DigestAlgorithm::Sha512,
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(input.data()),
                input.size()
            )
        );
        const auto expected = from_hex(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        return output.size() == expected.size() &&
               std::equal(output.begin(), output.end(), expected.begin());
    });

    run_check(report, "hkdf_sha384_known_answer", [&context]() {
        const std::string ikm = "secret";
        const std::string salt = "salt";
        const std::string info = "info";
        const SecureBytes output = hkdf_sha384(
            context,
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(ikm.data()),
                ikm.size()
            ),
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(salt.data()),
                salt.size()
            ),
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(info.data()),
                info.size()
            ),
            32
        );
        const auto expected = from_hex(
            "29c042775183ec5dbc2c085eb49502b15d9e8abe4a4c1ef98e8e0fb95ad5f6a9"
        );
        return output.size() == expected.size() &&
               std::equal(output.begin(), output.end(), expected.begin());
    });

    run_check(report, "aes_256_gcm_known_answer", [&context]() {
        const auto key = from_hex(
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
        );
        const auto nonce = from_hex("cafebabefacedbaddecaf888");
        const auto plaintext = from_hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
        );
        const auto aad = from_hex(
            "feedfacedeadbeeffeedfacedeadbeefabaddad2"
        );
        const auto expected_ciphertext = from_hex(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
        );
        const auto expected_tag = from_hex(
            "2df7cd675b4f09163b41ebf980a7f638"
        );

        const AeadResult result = aes_256_gcm_encrypt(
            context,
            key,
            nonce,
            plaintext,
            aad
        );
        const SecureBytes recovered = aes_256_gcm_decrypt(
            context,
            key,
            nonce,
            result.ciphertext,
            result.tag,
            aad
        );
        return result.ciphertext.size() == expected_ciphertext.size() &&
               std::equal(
                   result.ciphertext.begin(),
                   result.ciphertext.end(),
                   expected_ciphertext.begin()
               ) &&
               result.tag.size() == expected_tag.size() &&
               std::equal(
                   result.tag.begin(),
                   result.tag.end(),
                   expected_tag.begin()
               ) &&
               recovered.size() == plaintext.size() &&
               std::equal(recovered.begin(), recovered.end(), plaintext.begin());
    });

    run_check(report, "ml_kem_1024_nist_fips203_keygen_kat", [&context]() {
        SecureBytes seed = from_hex(nist_acvp::ml_kem_keygen_seed);
        const PKeyPtr key = generate_seeded_key(
            context, "ML-KEM-1024", OSSL_PKEY_PARAM_ML_KEM_SEED, seed
        );
        const SecureBytes public_key = raw_public_key(key.get());
        const SecureBytes private_key = raw_private_key(key.get());
        return public_key.size() == 1568 && private_key.size() == 3168 &&
               matches_sha384(
                   context, public_key, nist_acvp::ml_kem_keygen_ek_sha384
               ) &&
               matches_sha384(
                   context, private_key, nist_acvp::ml_kem_keygen_dk_sha384
               );
    });

    run_check(report, "ml_kem_1024_nist_fips203_encapsulation_kat", [&context]() {
        const SecureBytes public_key = from_hex(nist_acvp::ml_kem_encap_ek);
        SecureBytes ikme = from_hex(nist_acvp::ml_kem_encap_m);
        const KEMEncapsulation result = encapsulate_with_ikme(
            context, public_key, ikme
        );
        const SecureBytes expected_secret = from_hex(nist_acvp::ml_kem_encap_k);
        return result.ciphertext.size() == 1568 &&
               matches_sha384(
                   context, result.ciphertext, nist_acvp::ml_kem_encap_c_sha384
               ) &&
               equal_bytes(result.shared_secret, expected_secret);
    });

    run_check(report, "ml_dsa_87_nist_fips204_keygen_kat", [&context]() {
        SecureBytes seed = from_hex(nist_acvp::ml_dsa_keygen_seed);
        const PKeyPtr key = generate_seeded_key(
            context, "ML-DSA-87", OSSL_PKEY_PARAM_ML_DSA_SEED, seed
        );
        const SecureBytes public_key = raw_public_key(key.get());
        const SecureBytes private_key = raw_private_key(key.get());
        return public_key.size() == 2592 && private_key.size() == 4896 &&
               matches_sha384(
                   context, public_key, nist_acvp::ml_dsa_keygen_pk_sha384
               ) &&
               matches_sha384(
                   context, private_key, nist_acvp::ml_dsa_keygen_sk_sha384
               );
    });

    run_check(report, "ml_dsa_87_nist_fips204_siggen_kat", [&context]() {
        const SecureBytes private_key = from_hex(nist_acvp::ml_dsa_siggen_sk);
        const SecureBytes message = from_hex(nist_acvp::ml_dsa_siggen_message);
        const SecureBytes signature = deterministic_internal_signature(
            context, private_key, message
        );
        return signature.size() == 4627 &&
               matches_sha384(
                   context,
                   signature,
                   nist_acvp::ml_dsa_siggen_signature_sha384
               );
    });

    run_check(report, "ml_kem_1024_pairwise_consistency", [&context]() {
        const KEMKeyPair key_pair = generate_ml_kem_1024(context);
        const KEMEncapsulation encapsulation = encapsulate_ml_kem_1024(
            context,
            key_pair.public_key_der
        );
        const SecureBytes recovered_secret = decapsulate_ml_kem_1024(
            context,
            key_pair.private_key_der,
            encapsulation.ciphertext
        );
        return key_pair.key_id.size() == 32 &&
               encapsulation.ciphertext.size() == 1568 &&
               encapsulation.shared_secret.size() == 32 &&
               recovered_secret.size() == 32 &&
               encapsulation.shared_secret == recovered_secret;
    });

    run_check(report, "ml_dsa_87_pairwise_consistency", [&context]() {
        const SignatureKeyPair key_pair = generate_ml_dsa_87(context);
        const std::string message = "qprotect C++ module self-test";
        const SecureBytes signature = sign_ml_dsa_87(
            context,
            key_pair.private_key_der,
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(message.data()),
                message.size()
            )
        );
        const bool valid = verify_ml_dsa_87(
            context,
            key_pair.public_key_der,
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(message.data()),
                message.size()
            ),
            signature
        );

        SecureBytes invalid_signature(signature);
        if (!invalid_signature.empty()) {
            invalid_signature[0] ^= 0x01;
        }
        const bool invalid_rejected = !verify_ml_dsa_87(
            context,
            key_pair.public_key_der,
            std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(message.data()),
                message.size()
            ),
            invalid_signature
        );

        return key_pair.key_id.size() == 32 && signature.size() == 4627 &&
               valid && invalid_rejected;
    });

    return report;
}

}
