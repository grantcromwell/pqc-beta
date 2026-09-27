#include "qprotect/algorithms.hpp"
#include "qprotect/crypto_context.hpp"
#include "qprotect/envelope.hpp"
#include "qprotect/disk.hpp"
#include "qprotect/hardware.hpp"
#include "qprotect/error.hpp"
#include "qprotect/keys.hpp"
#include "qprotect/secure_bytes.hpp"

#include "json_minimal.hpp"
#include "identity.hpp"
#include "hardware_internal.hpp"
#include "disk_internal.hpp"
#include "crypto_context_handles.hpp"

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

using qprotect::cpp::AeadResult;
using qprotect::cpp::CryptoContext;
using qprotect::cpp::CryptoError;
using qprotect::cpp::DecryptOptions;
using qprotect::cpp::DigestAlgorithm;
using qprotect::cpp::Envelope;
using qprotect::cpp::EnvelopeError;
using qprotect::cpp::EncryptOptions;
using qprotect::cpp::KEMEncapsulation;
using qprotect::cpp::KEMKeyPair;
using qprotect::cpp::SecureBytes;
using qprotect::cpp::SignatureKeyPair;
using qprotect::cpp::aes_256_gcm_decrypt;
using qprotect::cpp::aes_256_gcm_encrypt;
using qprotect::cpp::decapsulate_ml_kem_1024;
using qprotect::cpp::decrypt_envelope;
using qprotect::cpp::digest;
using qprotect::cpp::encapsulate_ml_kem_1024;
using qprotect::cpp::encrypt_envelope;
using qprotect::cpp::generate_ml_dsa_87;
using qprotect::cpp::generate_ml_kem_1024;
using qprotect::cpp::hkdf_sha384;
using qprotect::cpp::key_id_for_public_key;
using qprotect::cpp::load_private_key_file;
using qprotect::cpp::load_public_key_file;
using qprotect::cpp::sign_ml_dsa_87;
using qprotect::cpp::verify_ml_dsa_87;
using qprotect::cpp::write_private_key_pem;
using qprotect::cpp::write_public_key_pem;

int g_failures = 0;
int g_checks = 0;

void report(bool condition, const char* file, int line, const char* expression) {
    ++g_checks;
    if (!condition) {
        ++g_failures;
        std::cerr << "FAIL " << file << ":" << line << ": " << expression << "\n";
    }
}

#define CHECK(condition) report((condition), __FILE__, __LINE__, #condition)

#define CHECK_THROWS(exception_type, expression)                       \
    do {                                                                \
        bool threw = false;                                             \
        try {                                                           \
            static_cast<void>(expression);                              \
        } catch (const exception_type&) {                               \
            threw = true;                                               \
        } catch (...) {                                                \
        }                                                               \
        report(threw, __FILE__, __LINE__, "throws: " #expression);      \
    } while (false)

#define CHECK_NO_THROW(expression)                                      \
    do {                                                                \
        bool threw = false;                                             \
        try {                                                           \
            static_cast<void>(expression);                              \
        } catch (const std::exception& error) {                         \
            threw = true;                                               \
            std::cerr << "unexpected: " << error.what() << "\n";         \
        }                                                               \
        report(!threw, __FILE__, __LINE__, "no-throw: " #expression);  \
    } while (false)

SecureBytes bytes(const std::string& value) {
    return SecureBytes(
        reinterpret_cast<const unsigned char*>(value.data()),
        value.size()
    );
}

SecureBytes bytes(const char* value) {
    return bytes(std::string(value));
}

bool same(const SecureBytes& left, const std::string& right) {
    return left.size() == right.size() &&
           std::memcmp(left.data(), right.data(), right.size()) == 0;
}

void test_digests(const CryptoContext& context) {
    CHECK(context.random_bytes(0).empty());

    const SecureBytes abc = bytes("abc");
    CHECK(digest(context, DigestAlgorithm::Sha384, abc).size() == 48);
    CHECK(digest(context, DigestAlgorithm::Sha512, abc).size() == 64);
    CHECK(digest(context, DigestAlgorithm::Sha384, SecureBytes{}).size() == 48);

    const SecureBytes sha384_abc = digest(context, DigestAlgorithm::Sha384, abc);
    CHECK(same(
        sha384_abc,
        std::string(
            "\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50\x07"
            "\x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff\x5b\xed"
            "\x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34\xc8\x25\xa7",
            48
        )
    ));
}

void test_hkdf(const CryptoContext& context) {
    const SecureBytes ikm = bytes("secret");
    const SecureBytes salt = bytes("salt");
    const SecureBytes info = bytes("info");

    CHECK_THROWS(
        CryptoError,
        hkdf_sha384(context, ikm, salt, info, 0));
    CHECK_THROWS(
        CryptoError,
        hkdf_sha384(context, ikm, salt, info, 255 * 48 + 1));

    CHECK_NO_THROW(
        hkdf_sha384(context, ikm, salt, info, 255 * 48));

    const SecureBytes derived = hkdf_sha384(context, ikm, salt, info, 32);
    CHECK(derived.size() == 32);
    CHECK(same(
        derived,
        std::string(
            "\x29\xc0\x42\x77\x51\x83\xec\x5d\xbc\x2c\x08\x5e\xb4\x95\x02\xb1"
            "\x5d\x9e\x8a\xbe\x4a\x4c\x1e\xf9\x8e\x8e\x0f\xb9\x5a\xd5\xf6\xa9",
            32
        )
    ));
}

void test_aes_gcm(const CryptoContext& context) {
    const SecureBytes key = context.random_bytes(32);
    const SecureBytes nonce = context.random_bytes(12);
    const SecureBytes plaintext = bytes("attack at dawn");
    const SecureBytes aad = bytes("header");

    const SecureBytes short_key = context.random_bytes(16);
    const SecureBytes bad_nonce = context.random_bytes(16);

    CHECK_THROWS(CryptoError, aes_256_gcm_encrypt(context, short_key, nonce, plaintext, aad));
    CHECK_THROWS(CryptoError, aes_256_gcm_encrypt(context, key, bad_nonce, plaintext, aad));
    CHECK_THROWS(CryptoError, aes_256_gcm_decrypt(context, short_key, nonce, plaintext, SecureBytes(16), aad));
    CHECK_THROWS(CryptoError, aes_256_gcm_decrypt(context, key, nonce, plaintext, SecureBytes(15), aad));

    const AeadResult sealed = aes_256_gcm_encrypt(context, key, nonce, plaintext, aad);
    CHECK(sealed.ciphertext.size() == plaintext.size());
    CHECK(sealed.tag.size() == 16);
    CHECK(same(aes_256_gcm_decrypt(context, key, nonce, sealed.ciphertext, sealed.tag, aad), "attack at dawn"));

    const AeadResult empty_sealed =
        aes_256_gcm_encrypt(context, key, nonce, SecureBytes{}, SecureBytes{});
    CHECK(empty_sealed.ciphertext.empty());
    CHECK_NO_THROW(
        aes_256_gcm_decrypt(context, key, nonce, empty_sealed.ciphertext, empty_sealed.tag, SecureBytes{}));

    const SecureBytes large = context.random_bytes(300 * 1024);
    const AeadResult large_sealed = aes_256_gcm_encrypt(context, key, nonce, large, aad);
    const SecureBytes large_recovered =
        aes_256_gcm_decrypt(context, key, nonce, large_sealed.ciphertext, large_sealed.tag, aad);
    CHECK(large_recovered == large);

    SecureBytes broken_ciphertext(sealed.ciphertext);
    broken_ciphertext[0] ^= 0x01;
    CHECK_THROWS(CryptoError,
        aes_256_gcm_decrypt(context, key, nonce, broken_ciphertext, sealed.tag, aad));

    SecureBytes broken_tag(sealed.tag);
    broken_tag[15] ^= 0x01;
    CHECK_THROWS(CryptoError,
        aes_256_gcm_decrypt(context, key, nonce, sealed.ciphertext, broken_tag, aad));

    CHECK_THROWS(CryptoError,
        aes_256_gcm_decrypt(context, key, nonce, sealed.ciphertext, sealed.tag, bytes("headex")));

    CHECK_THROWS(CryptoError,
        aes_256_gcm_decrypt(
            context,
            key,
            nonce,
            SecureBytes(sealed.ciphertext.data(), sealed.ciphertext.size() - 1),
            sealed.tag,
            aad));
}

void test_ml_kem(const CryptoContext& context) {
    const KEMKeyPair key_pair = generate_ml_kem_1024(context);
    const KEMEncapsulation encapsulation =
        encapsulate_ml_kem_1024(context, key_pair.public_key_der);
    CHECK(encapsulation.ciphertext.size() == 1568);
    CHECK(encapsulation.shared_secret.size() == 32);
    CHECK(decapsulate_ml_kem_1024(
              context, key_pair.private_key_der, encapsulation.ciphertext) ==
          encapsulation.shared_secret);

    CHECK_THROWS(CryptoError, encapsulate_ml_kem_1024(context, bytes("not a key")));
    CHECK_THROWS(CryptoError, decapsulate_ml_kem_1024(context, bytes("not a key"), encapsulation.ciphertext));

    CHECK_THROWS(CryptoError,
        decapsulate_ml_kem_1024(context, key_pair.private_key_der, SecureBytes(16)));
    CHECK_THROWS(CryptoError,
        decapsulate_ml_kem_1024(context, key_pair.private_key_der, SecureBytes(1567)));

    const KEMKeyPair other = generate_ml_kem_1024(context);
    const SecureBytes other_secret = decapsulate_ml_kem_1024(
        context, other.private_key_der, encapsulation.ciphertext);
    CHECK(other_secret.size() == 32);
    CHECK(!(other_secret == encapsulation.shared_secret));
}

void test_ml_kem_key_validation(const CryptoContext& context) {
    using qprotect::cpp::MlKem1024PublicKey;
    using qprotect::cpp::MlKem1024PrivateKey;
    const KEMKeyPair key_pair = generate_ml_kem_1024(context);
    SecureBytes public_source = key_pair.public_key_der;
    SecureBytes private_source = key_pair.private_key_der;
    const MlKem1024PublicKey public_key(context, public_source);
    const MlKem1024PrivateKey private_key(context, private_source);
    public_source.clear();
    private_source.clear();
    const KEMEncapsulation encapsulation = encapsulate_ml_kem_1024(context, public_key);
    CHECK(encapsulation.ciphertext.size() == 1568);
    CHECK(encapsulation.shared_secret.size() == 32);
    CHECK(decapsulate_ml_kem_1024(context, private_key, encapsulation.ciphertext) ==
          encapsulation.shared_secret);
    CHECK(decapsulate_ml_kem_1024(context, key_pair.private_key_der, encapsulation.ciphertext) ==
          encapsulation.shared_secret);

    for (const std::size_t length : {0, 768, 1088, 1567, 1569}) {
        CHECK_THROWS(CryptoError, decapsulate_ml_kem_1024(context, private_key, SecureBytes(length)));
    }
    CHECK_THROWS(CryptoError, MlKem1024PublicKey(context, key_pair.private_key_der));
    CHECK_THROWS(CryptoError, MlKem1024PrivateKey(context, key_pair.public_key_der));
    CHECK_THROWS(CryptoError, MlKem1024PublicKey(context, SecureBytes{}));
    CHECK_THROWS(CryptoError, MlKem1024PrivateKey(context, SecureBytes{}));
    CHECK_THROWS(CryptoError, MlKem1024PublicKey(context, SecureBytes(1024 * 1024 + 1)));
    CHECK_THROWS(CryptoError, MlKem1024PrivateKey(context, SecureBytes(1024 * 1024 + 1)));

    SecureBytes trailing_public = key_pair.public_key_der;
    SecureBytes trailing_private = key_pair.private_key_der;
    trailing_public.resize(trailing_public.size() + 1);
    trailing_private.resize(trailing_private.size() + 1);
    CHECK_THROWS(CryptoError, MlKem1024PublicKey(context, trailing_public));
    CHECK_THROWS(CryptoError, MlKem1024PrivateKey(context, trailing_private));
    CHECK_THROWS(CryptoError, encapsulate_ml_kem_1024(context, trailing_public));
    CHECK_THROWS(CryptoError,
        decapsulate_ml_kem_1024(context, trailing_private, encapsulation.ciphertext));

    const auto handles = context.handles();
    for (const char* algorithm : {"ML-KEM-512", "ML-KEM-768", "ML-DSA-87"}) {
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> other(
            EVP_PKEY_Q_keygen(handles.libctx, handles.properties, algorithm), EVP_PKEY_free);
        if (!other) throw CryptoError("unable to generate validation fixture");
        const int public_length = i2d_PUBKEY(other.get(), nullptr);
        const int private_length = i2d_PrivateKey(other.get(), nullptr);
        if (public_length <= 0 || private_length <= 0) {
            throw CryptoError("unable to size validation fixture");
        }
        SecureBytes other_public(static_cast<std::size_t>(public_length));
        SecureBytes other_private(static_cast<std::size_t>(private_length));
        unsigned char* public_cursor = other_public.data();
        unsigned char* private_cursor = other_private.data();
        if (i2d_PUBKEY(other.get(), &public_cursor) != public_length ||
            i2d_PrivateKey(other.get(), &private_cursor) != private_length) {
            throw CryptoError("unable to encode validation fixture");
        }
        CHECK_THROWS(CryptoError, MlKem1024PublicKey(context, other_public));
        CHECK_THROWS(CryptoError, MlKem1024PrivateKey(context, other_private));
        CHECK_THROWS(CryptoError, encapsulate_ml_kem_1024(context, other_public));
        CHECK_THROWS(CryptoError,
            decapsulate_ml_kem_1024(context, other_private, encapsulation.ciphertext));
        EncryptOptions options;
        options.context = "key-validation";
        options.recipient_public_key_der.push_back(other_public);
        CHECK_THROWS(CryptoError, encrypt_envelope(context, bytes("test payload"), options));
    }
}

void test_ml_dsa(const CryptoContext& context) {
    const SignatureKeyPair key_pair = generate_ml_dsa_87(context);
    const SecureBytes message = bytes("classified");

    const SecureBytes signature = sign_ml_dsa_87(context, key_pair.private_key_der, message);
    CHECK(signature.size() == 4627);
    CHECK(verify_ml_dsa_87(context, key_pair.public_key_der, message, signature));
    CHECK(!verify_ml_dsa_87(context, key_pair.public_key_der, bytes("tampered"), signature));
    CHECK(!verify_ml_dsa_87(context, key_pair.public_key_der, message, SecureBytes(signature.size() - 1, 0)));

    const SecureBytes empty_signature =
        sign_ml_dsa_87(context, key_pair.private_key_der, SecureBytes{});
    CHECK(empty_signature.size() == 4627);
    CHECK(verify_ml_dsa_87(context, key_pair.public_key_der, SecureBytes{}, empty_signature));

    CHECK_THROWS(CryptoError, sign_ml_dsa_87(context, bytes("not a key"), message));
    CHECK_THROWS(CryptoError, verify_ml_dsa_87(context, bytes("not a key"), message, signature));

    const SignatureKeyPair other = generate_ml_dsa_87(context);
    CHECK(!verify_ml_dsa_87(context, other.public_key_der, message, signature));
}

void test_secure_bytes() {
    SecureBytes value = bytes("sensitive");
    value.zeroize();
    CHECK(value.empty());
    for (const unsigned char byte : value) {
        static_cast<void>(byte);
    }

    SecureBytes original = bytes("sensitive");
    SecureBytes moved = std::move(original);
    CHECK(original.empty());
    CHECK(same(moved, "sensitive"));

    SecureBytes assigned = bytes("first");
    assigned.assign(bytes("second"));
    CHECK(same(assigned, "second"));

    const SecureBytes left = bytes("same");
    const SecureBytes right = bytes("same");
    CHECK(left == right);
    CHECK(!(left == bytes("different")));
}

void test_context() {
    CHECK_THROWS(CryptoError, CryptoContext("bogus"));
    CHECK_THROWS(CryptoError, CryptoContext("base"));
    const CryptoContext context;
    CHECK(context.provider_name() == "default");
    CHECK_NO_THROW(context.assert_ready());
}

void test_json_canonical() {

    const qprotect::cpp::json::Object object = {
        {"b", qprotect::cpp::json::Value(1)},
        {"a", qprotect::cpp::json::Value("x")},
    };
    CHECK(qprotect::cpp::json::Value(object).canonical() == R"({"a":"x","b":1})");

    const qprotect::cpp::json::Array array = {
        qprotect::cpp::json::Value(2),
        qprotect::cpp::json::Value(nullptr),
        qprotect::cpp::json::Value(true),
        qprotect::cpp::json::Value("s"),
    };
    CHECK(qprotect::cpp::json::Value(array).canonical() == R"([2,null,true,"s"])");

    const std::string tricky = std::string("q\"uote\\back") + '\x1f' + '\x7f' + '\n';
    const qprotect::cpp::json::Object escape_object = {
        {"a", qprotect::cpp::json::Value(tricky)},
    };
    CHECK(qprotect::cpp::json::Value(escape_object).canonical() ==
          "{\"a\":\"q\\\"uote\\\\back\\u001f\x7f\\n\"}");

    const qprotect::cpp::json::Object inner = {
        {"z", qprotect::cpp::json::Value(1)},
        {"a", qprotect::cpp::json::Value(2)},
    };
    const qprotect::cpp::json::Object outer = {
        {"nested", qprotect::cpp::json::Value(inner)},
    };
    CHECK(qprotect::cpp::json::Value(outer).canonical() ==
          R"({"nested":{"a":2,"z":1}})");

    const qprotect::cpp::json::Object pretty_object = {
        {"b", qprotect::cpp::json::Value(1)},
        {"a", qprotect::cpp::json::Value("x")},
    };
    CHECK(qprotect::cpp::json::Value(pretty_object).pretty(2) ==
          "{\n  \"a\": \"x\",\n  \"b\": 1\n}");
}

void test_json_parse() {
    using qprotect::cpp::json::Value;

    CHECK_THROWS(EnvelopeError, Value::parse(""));
    CHECK_THROWS(EnvelopeError, Value::parse("{"));
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":1,}"));
    CHECK_THROWS(EnvelopeError, Value::parse("[1,2]x"));
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":1 \"b\":2}"));
    CHECK(Value::parse("{\"a\":1.5}").canonical() == R"({"a":1.5})");
    CHECK(Value::parse("{\"a\":1e-5}").canonical() == R"({"a":1e-05})");
    CHECK(Value(1.0).canonical() == "1.0");
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":01}"));
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":1.}"));
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":1e+}"));
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":1e9999}"));
    std::string deeply_nested(66, '[');
    deeply_nested += "0";
    deeply_nested.append(66, ']');
    CHECK_THROWS(EnvelopeError, Value::parse(deeply_nested));
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":\x01}"));
    CHECK_THROWS(EnvelopeError, Value::parse("{\"a\":\"\\q\"}"));
    CHECK_THROWS(EnvelopeError, Value::parse("nul"));
    CHECK_THROWS(EnvelopeError, Value::parse("\"\\ud800\""));

    const Value parsed = Value::parse(
        R"({"a":1,"b":[true,null,"x"],"c":{"d":"é"}})");
    CHECK(parsed.is_object());
    CHECK(parsed.as_object().at("a").as_integer() == 1);
    CHECK(parsed.as_object().at("b").as_array().size() == 3);
    CHECK(parsed.as_object().at("c").as_object().at("d").as_string() == "é");
}

void test_identity_normalization() {
    using qprotect::cpp::detail::normalize_identity;
    using qprotect::cpp::json::Value;

    const Value normalized = normalize_identity(Value::parse(
        R"({"ip":"2001:0DB8:0:0:0:0:0:1","mac":"02-00-00-00-00-0A","serial":" TEST-DEVICE ","uuid":"00000000-0000-4000-A000-000000000001","wifi_bssid":"02.00.00.00.00.0B","gps":{"latitude":0,"longitude":0,"accuracy_m":8},"browser_fingerprint":{"timezone":"UTC"},"site":"test-site"})"));
    const auto& fields = normalized.as_object();
    CHECK(fields.at("ip_address").as_string() == "2001:db8::1");
    CHECK(fields.at("mac_address").as_string() == "02:00:00:00:00:0a");
    CHECK(fields.at("hardware_serial").as_string() == "TEST-DEVICE");
    CHECK(fields.at("uuid").as_string() == "00000000-0000-4000-a000-000000000001");
    CHECK(fields.at("wifi_bssid").as_string() == "02:00:00:00:00:0b");
    CHECK(fields.at("gps").as_object().at("latitude").as_number() == 0.0);
    CHECK(fields.at("gps").as_object().at("longitude").as_number() == 0.0);
    CHECK(fields.at("additional").as_object().at("site").as_string() == "test-site");
    CHECK(fields.at("browser_fingerprint").as_object().at("timezone").as_string() == "UTC");
    CHECK(fields.at("guid").is_null());
    const Value timestamped = normalize_identity(Value::parse(
        R"({"gps":{"latitude":0,"longitude":0,"timestamp":"2026-09-22T12:30:45.123Z"}})"));
    CHECK(timestamped.as_object().at("gps").as_object().at("timestamp").as_string() ==
          "2026-09-22T12:30:45.123Z");

    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"ip":"not-an-ip"})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"mac":"00:11"})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"uuid":"bad"})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"serial":"\u0000"})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"gps":{"latitude":91,"longitude":0}})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"gps":{"latitude":true,"longitude":0}})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"gps":{"latitude":0,"longitude":0,"timestamp":"2026-02-30T00:00:00Z"}})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"ip":"127.0.0.1"," ip ":"127.0.0.2"})")));
    CHECK_THROWS(EnvelopeError, normalize_identity(Value::parse(R"({"additional":[]})")));
}

void test_json_utf8() {
    using qprotect::cpp::json::Value;
    const std::vector<std::string> invalid = {
        "\x80", "\xBF", "\xC0\x80", "\xC1\xBF", "\xC2", "\xC2x",
        "\xE0\x80\x80", "\xE1\x80", "\xE1x\x80", "\xED\xA0\x80",
        "\xED\xBF\xBF", "\xF0\x80\x80\x80", "\xF1\x80\x80",
        "\xF4\x90\x80\x80", "\xF5\x80\x80\x80", "\xFF"
    };
    for (const auto& value : invalid) {
        CHECK_THROWS(EnvelopeError, Value::parse("\"" + value + "\""));
        CHECK_THROWS(EnvelopeError, Value::parse("{\"" + value + "\":0}"));
        CHECK_THROWS(EnvelopeError, Value(value).canonical());
        CHECK_THROWS(EnvelopeError, Value(value).pretty(2));
        CHECK_THROWS(EnvelopeError, Value(qprotect::cpp::json::Object{{value, Value(0)}}).canonical());
        CHECK_THROWS(EnvelopeError, qprotect::cpp::detail::normalize_identity(
            Value::parse("{\"serial\":\"" + value + "\"}")));
    }
    const std::vector<std::string> valid = {
        "ASCII", "\xC2\x80", "\xDF\xBF", "\xE0\xA0\x80", "\xED\x9F\xBF",
        "\xEE\x80\x80", "\xEF\xBF\xBF", "\xF0\x90\x80\x80", "\xF4\x8F\xBF\xBF"
    };
    for (const auto& value : valid) {
        CHECK(Value::parse(Value(value).canonical()).as_string() == value);
        CHECK(Value::parse(Value(value).pretty(2)).as_string() == value);
    }
    CHECK(Value::parse("\"\\ud83d\\ude00\"").as_string() == "\xF0\x9F\x98\x80");
}

EncryptOptions options_for(
    const std::vector<SecureBytes>& recipients,
    const std::string& context_value,
    const SecureBytes* signer_private = nullptr
) {
    EncryptOptions options;
    options.context = context_value;
    options.recipient_public_key_der = recipients;
    if (signer_private != nullptr) {
        options.signer_private_key_der = *signer_private;
    }
    return options;
}

void test_envelope_roundtrip(const CryptoContext& context) {
    const KEMKeyPair alice = generate_ml_kem_1024(context);
    const KEMKeyPair bob = generate_ml_kem_1024(context);
    const SignatureKeyPair signer = generate_ml_dsa_87(context);

    const SecureBytes payload = bytes("top secret identity record");

    const Envelope single = encrypt_envelope(
        context, payload, options_for({alice.public_key_der}, "test"));
    CHECK(single.context == "test");
    CHECK(single.signer_key_id == std::nullopt);
    const SecureBytes single_recovered = decrypt_envelope(
        context,
        single,
        DecryptOptions{alice.private_key_der, std::nullopt});
    CHECK(single_recovered == payload);

    const Envelope dual = encrypt_envelope(
        context,
        payload,
        options_for({alice.public_key_der, bob.public_key_der}, "test", &signer.private_key_der));
    CHECK(dual.recipients.size() == 2);
    CHECK(dual.signer_key_id.has_value());
    CHECK(*dual.signer_key_id == signer.key_id);

    const DecryptOptions signed_decrypt{
        alice.private_key_der, signer.public_key_der};
    CHECK(decrypt_envelope(context, dual, signed_decrypt) == payload);
    const DecryptOptions bob_decrypt{bob.private_key_der, signer.public_key_der};
    CHECK(decrypt_envelope(context, dual, bob_decrypt) == payload);

    const Envelope empty = encrypt_envelope(
        context, SecureBytes{}, options_for({alice.public_key_der}, "test"));
    CHECK(empty.ciphertext.empty());
    const SecureBytes empty_recovered = decrypt_envelope(
        context, empty, DecryptOptions{alice.private_key_der, std::nullopt});
    CHECK(empty_recovered.empty());
}

void test_envelope_failures(const CryptoContext& context) {
    const KEMKeyPair alice = generate_ml_kem_1024(context);
    const KEMKeyPair mallory = generate_ml_kem_1024(context);
    const SignatureKeyPair signer = generate_ml_dsa_87(context);
    const SignatureKeyPair other_signer = generate_ml_dsa_87(context);

    const SecureBytes payload = bytes("payload");
    const Envelope envelope = encrypt_envelope(
        context,
        payload,
        options_for({alice.public_key_der}, "test", &signer.private_key_der));

    CHECK_THROWS(EnvelopeError,
        encrypt_envelope(context, payload, options_for({}, "test")));

    CHECK_THROWS(EnvelopeError,
        encrypt_envelope(
            context,
            payload,
            options_for({alice.public_key_der, alice.public_key_der}, "test")));

    CHECK_THROWS(EnvelopeError,
        encrypt_envelope(context, payload, options_for({alice.public_key_der}, "")));
    CHECK_THROWS(EnvelopeError,
        encrypt_envelope(context, payload, options_for({alice.public_key_der}, std::string(129, 'x'))));
    CHECK_THROWS(EnvelopeError,
        encrypt_envelope(context, payload, options_for({alice.public_key_der}, "bad\x01context")));
    CHECK_THROWS(EnvelopeError,
        encrypt_envelope(context, payload, options_for({alice.public_key_der}, "não-ascii")));

    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            envelope,
            DecryptOptions{mallory.private_key_der, signer.public_key_der}));

    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            envelope,
            DecryptOptions{alice.private_key_der, std::nullopt}));

    const Envelope unsigned_for_signer = encrypt_envelope(
        context, payload, options_for({alice.public_key_der}, "test"));
    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            unsigned_for_signer,
            DecryptOptions{alice.private_key_der, signer.public_key_der}));

    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            envelope,
            DecryptOptions{alice.private_key_der, other_signer.public_key_der}));

    Envelope broken = envelope;
    broken.ciphertext[0] ^= 0x01;
    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            broken,
            DecryptOptions{alice.private_key_der, signer.public_key_der}));

    Envelope broken_wrap = envelope;
    broken_wrap.recipients[0].wrapped_key[0] ^= 0x01;
    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            broken_wrap,
            DecryptOptions{alice.private_key_der, signer.public_key_der}));

    Envelope broken_sig = envelope;
    (*broken_sig.signature)[0] ^= 0x01;
    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            broken_sig,
            DecryptOptions{alice.private_key_der, signer.public_key_der}));

    Envelope broken_context = envelope;
    broken_context.context = "other";
    CHECK_THROWS(EnvelopeError,
        decrypt_envelope(
            context,
            broken_context,
            DecryptOptions{alice.private_key_der, signer.public_key_der}));
}

void test_envelope_serialization(const CryptoContext& context) {
    const KEMKeyPair alice = generate_ml_kem_1024(context);
    const SignatureKeyPair signer = generate_ml_dsa_87(context);

    const Envelope envelope = encrypt_envelope(
        context,
        bytes("roundtrip"),
        options_for({alice.public_key_der}, "serial", &signer.private_key_der));

    const std::string json = envelope.to_json();
    const Envelope reparsed = Envelope::from_json(json);
    for (const std::string encoded : {"AA=!", "AA= ", "AA=\n", "AA=A", "AA", "A===", "AB==", "AAB="}) {
        auto document = qprotect::cpp::json::Value::parse(json).as_object();
        document["ciphertext"] = qprotect::cpp::json::Value(encoded);
        CHECK_THROWS(EnvelopeError, Envelope::from_json(qprotect::cpp::json::Value(document).canonical()));
    }
    for (const std::string encoded : {"", "AA==", "AAA=", "AAAA"}) {
        auto document = qprotect::cpp::json::Value::parse(json).as_object();
        document["ciphertext"] = qprotect::cpp::json::Value(encoded);
        CHECK_NO_THROW(Envelope::from_json(qprotect::cpp::json::Value(document).canonical()));
    }
    for (const char* field : {"tag", "signature"}) {
        auto document = qprotect::cpp::json::Value::parse(json).as_object();
        std::string encoded = document.at(field).as_string();
        CHECK(encoded.ends_with("=="));
        encoded.back() = '!';
        document[field] = qprotect::cpp::json::Value(encoded);
        CHECK_THROWS(EnvelopeError, Envelope::from_json(qprotect::cpp::json::Value(document).canonical()));
    }

    CHECK(reparsed.to_json() == json);

    CHECK(decrypt_envelope(
              context,
              reparsed,
              DecryptOptions{alice.private_key_der, signer.public_key_der}) ==
          bytes("roundtrip"));

    CHECK_THROWS(EnvelopeError, Envelope::from_json(""));
    CHECK_THROWS(EnvelopeError, Envelope::from_json("[]"));
    CHECK_THROWS(EnvelopeError, Envelope::from_json("{"));

    const auto replace_once = [](std::string text,
                                 const std::string& from,
                                 const std::string& to) {
        const std::size_t position = text.find(from);
        if (position == std::string::npos) {
            return text;
        }
        text.replace(position, from.size(), to);
        return text;
    };

    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(json, "\"version\": 1", "\"version\": 2")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(json, "qprotect-envelope-v1", "qprotect-envelope-v2")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(json, "\"kem\": \"ML-KEM-1024\"", "\"kem\": \"ML-KEM-512\"")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(json, "\"aead\": \"AES-256-GCM\"", "\"aead\": \"AES-128-GCM\"")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(json, "\"ciphertext\": \"", "\"ciphertext\": \"!!!")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(json, "\"key_id\": \"", "\"key_id\": \"ZZZZ")));
    qprotect::cpp::json::Object invalid_nonce = qprotect::cpp::json::Value::parse(json).as_object();
    invalid_nonce["payload_iv"] = qprotect::cpp::json::Value("AAAA");
    const std::string invalid_nonce_json = qprotect::cpp::json::Value(std::move(invalid_nonce)).canonical();
    CHECK_NO_THROW(qprotect::cpp::json::Value::parse(invalid_nonce_json));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(invalid_nonce_json));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(
        json, "\"version\": 1", "\"unknown\": 1,\n  \"version\": 1")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(
        json, envelope.created_at, "not-a-timestamp")));
    CHECK_THROWS(EnvelopeError, Envelope::from_json(replace_once(
        json, envelope.created_at, "2026-02-30T12:00:00.000000Z")));

    const KEMKeyPair bob = generate_ml_kem_1024(context);
    const Envelope two = encrypt_envelope(
        context,
        bytes("dup"),
        options_for({alice.public_key_der, bob.public_key_der}, "serial"));
    const std::string two_json = two.to_json();
    std::string duplicated = two_json;
    const std::size_t first = duplicated.find("    {\n");
    const std::size_t second = duplicated.find("    {\n", first + 1);
    const std::string block = duplicated.substr(first, second - first);
    duplicated.insert(second, block);
    CHECK_THROWS(EnvelopeError, Envelope::from_json(duplicated));

    const Envelope unsigned_envelope = encrypt_envelope(
        context, bytes("unsigned"), options_for({alice.public_key_der}, "serial"));
    const std::string unsigned_json = unsigned_envelope.to_json();
    CHECK_THROWS(EnvelopeError,
        Envelope::from_json(replace_once(
            unsigned_json,
            "\"signature_algorithm\": null",
            "\"signature_algorithm\": \"ML-DSA-87\"")));
}

void test_key_files(const CryptoContext& context) {
    char temporary[] = "./qprotect-cpp-unit-keys-XXXXXX";
    char* created = ::mkdtemp(temporary);
    CHECK(created != nullptr);
    if (created == nullptr) return;
    const std::string directory = created;
    const std::string private_pem = directory + "/device-private.pem";
    const std::string public_pem = directory + "/device-public.pem";

    const KEMKeyPair key_pair = generate_ml_kem_1024(context);
    write_private_key_pem(context, key_pair.private_key_der, private_pem);
    write_public_key_pem(context, key_pair.public_key_der, public_pem);

    const SecureBytes loaded_public = load_public_key_file(context, public_pem);
    CHECK(key_id_for_public_key(context, loaded_public) == key_pair.key_id);
    const SecureBytes loaded_private = load_private_key_file(context, private_pem);
    CHECK(qprotect::cpp::public_key_of_private(context, loaded_private) == loaded_public);
    struct stat status {};
    CHECK(::stat(private_pem.c_str(), &status) == 0 && (status.st_mode & 0777) == 0600);
    CHECK_THROWS(EnvelopeError,
        write_private_key_pem(context, key_pair.private_key_der, private_pem));
    CHECK(load_private_key_file(context, private_pem) == loaded_private);

    CHECK_THROWS(EnvelopeError, load_public_key_file(context, private_pem));
    CHECK_THROWS(EnvelopeError, load_private_key_file(context, public_pem));

    ::unlink(private_pem.c_str());
    ::unlink(public_pem.c_str());
    ::rmdir(directory.c_str());
}

void test_private_key_envelopes(const CryptoContext& context) {

    const KEMKeyPair recipient = generate_ml_kem_1024(context);
    const SignatureKeyPair signer = generate_ml_dsa_87(context);
    const KEMKeyPair kem_owner = generate_ml_kem_1024(context);
    const SignatureKeyPair signing_owner = generate_ml_dsa_87(context);
    const DecryptOptions decrypt_options{recipient.private_key_der, signer.public_key_der, true};
    const auto protect_and_recover = [&](const SecureBytes& private_key) {
        const EncryptOptions options = options_for(
            {recipient.public_key_der}, "private-key", &signer.private_key_der);
        const Envelope sealed = encrypt_envelope(context, private_key, options);
        const Envelope parsed = Envelope::from_json(sealed.to_json());
        const SecureBytes recovered = decrypt_envelope(context, parsed, decrypt_options);
        CHECK(recovered == private_key);

        Envelope tampered = parsed;
        tampered.ciphertext[0] ^= 1;
        CHECK_THROWS(EnvelopeError, decrypt_envelope(context, tampered, decrypt_options));
        tampered = parsed;
        tampered.signature.reset();
        tampered.signer_key_id.reset();
        CHECK_THROWS(EnvelopeError, decrypt_envelope(context, tampered, decrypt_options));
        CHECK_THROWS(EnvelopeError, decrypt_envelope(context, parsed,
            (DecryptOptions{kem_owner.private_key_der, signer.public_key_der, true})));
        CHECK_THROWS(EnvelopeError, decrypt_envelope(context, parsed,
            (DecryptOptions{recipient.private_key_der, signing_owner.public_key_der, true})));
        return recovered;
    };

    const SecureBytes recovered_kem = protect_and_recover(kem_owner.private_key_der);
    const KEMEncapsulation encapsulation = encapsulate_ml_kem_1024(context, kem_owner.public_key_der);
    CHECK(decapsulate_ml_kem_1024(context, recovered_kem, encapsulation.ciphertext) ==
          encapsulation.shared_secret);

    const SecureBytes recovered_signer = protect_and_recover(signing_owner.private_key_der);
    const SecureBytes message = bytes("recovered signing key test");
    const SecureBytes signature = sign_ml_dsa_87(context, recovered_signer, message);
    CHECK(verify_ml_dsa_87(context, signing_owner.public_key_der, message, signature));
}

void test_disk_plan_helpers() {
    qprotect::cpp::DiskPlanOptions options;
    options.device = "/dev/example";
    options.mapper_name = "secure-root";
    const auto arguments = qprotect::cpp::format_luks2_arguments(options);
    CHECK(arguments.front() == "cryptsetup");
    CHECK(arguments[1] == "luksFormat");
    CHECK(arguments.back() == "/dev/example");
    CHECK(std::find(arguments.begin(), arguments.end(), "--verify-passphrase") != arguments.end());
    CHECK(qprotect::cpp::format_confirmation(arguments, "example", 8, 1).starts_with("FORMAT-example-"));
    CHECK(qprotect::cpp::format_confirmation(arguments, "example", 8, 1) !=
          qprotect::cpp::format_confirmation(arguments, "example", 8, 2));
    CHECK(qprotect::cpp::shell_quote("a'b") == "'a'\\''b'");
    options.mapper_name = "bad/name";
    CHECK_THROWS(EnvelopeError, qprotect::cpp::format_luks2_arguments(options));
    options.mapper_name = "valid";
    options.iter_time_ms = 999;
    CHECK_THROWS(EnvelopeError, qprotect::cpp::format_luks2_arguments(options));

    options.iter_time_ms = 5000;
    for (const std::string name : {"--help", ".", ".."}) {
        options.mapper_name = name;
        CHECK_THROWS(EnvelopeError, qprotect::cpp::format_luks2_arguments(options));
    }

    options.mapper_name = "valid";
    for (int parallelism : {0, 5, 1024}) {
        options.argon2_parallelism = parallelism;
        CHECK_THROWS(EnvelopeError, qprotect::cpp::format_luks2_arguments(options));
    }

    options.argon2_parallelism = 4;
    options.argon2_memory_kib = 31;
    CHECK_THROWS(EnvelopeError, qprotect::cpp::format_luks2_arguments(options));

    options.argon2_memory_kib = 32;
    CHECK_NO_THROW(qprotect::cpp::format_luks2_arguments(options));

    const auto changed = qprotect::cpp::format_luks2_arguments(options);
    CHECK(qprotect::cpp::format_confirmation(arguments, "example", 8, 1) !=
          qprotect::cpp::format_confirmation(changed, "example", 8, 1));

    const qprotect::cpp::Luks2Plan unvalidated;
    CHECK_THROWS(EnvelopeError, qprotect::cpp::execute_luks2_format(unvalidated, ""));
    CHECK_THROWS(EnvelopeError, qprotect::cpp::execute_luks2_open(unvalidated));
    CHECK_THROWS(EnvelopeError, qprotect::cpp::execute_luks2_close(unvalidated));
}

void test_disk_header_and_mapping_validation() {
    namespace fs = std::filesystem;
    using qprotect::cpp::detail::header_identity;
    using qprotect::cpp::detail::open_validated_header;
    using qprotect::cpp::detail::validate_mapping_device;

    std::string directory_template = (fs::canonical(fs::current_path()) / "disk-validation-XXXXXX").string();
    const char* created = ::mkdtemp(directory_template.data());
    if (created == nullptr) throw EnvelopeError("unable to create disk test directory");

    const fs::path root(created);
    struct Cleanup {
        fs::path path;
        ~Cleanup() { std::error_code error; fs::remove_all(path, error); }
    } cleanup{root};

    const auto header = root / "header";
    const auto identity = header_identity(header.string(), true);
    CHECK(!fs::exists(header));
    CHECK_THROWS(EnvelopeError, header_identity("relative-header", true));

    const int descriptor = open_validated_header(header.string(), true, identity);
    struct stat status {};
    CHECK(::fstat(descriptor, &status) == 0 && status.st_size == 32 * 1024 * 1024 &&
          (status.st_mode & 0777) == 0600);
    CHECK(::close(descriptor) == 0);

    CHECK_THROWS(EnvelopeError, open_validated_header(header.string(), true, identity));
    const auto existing = header_identity(header.string(), false);
    const int opened = open_validated_header(header.string(), false, existing);
    CHECK(opened >= 0);

    fs::rename(header, root / "old-header");
    { std::ofstream file(header); file << "replacement"; }
    CHECK(::chmod(header.c_str(), 0600) == 0);
    CHECK_THROWS(EnvelopeError, open_validated_header(header.string(), false, existing));
    CHECK(::fstat(opened, &status) == 0 && status.st_size == 32 * 1024 * 1024);
    CHECK(::close(opened) == 0);

    qprotect::cpp::DiskPlanOptions options;
    options.device = "/dev/example";
    options.mapper_name = "fixture";
    options.key_file = header.string();
    const auto arguments = qprotect::cpp::format_luks2_arguments(options);
    CHECK(std::find(arguments.begin(), arguments.end(), "--verify-passphrase") == arguments.end());
    CHECK(arguments.back() == header.string());

    CHECK(::chmod(header.c_str(), 0644) == 0);
    CHECK_THROWS(EnvelopeError, header_identity(header.string(), false));
    CHECK(::chmod(header.c_str(), 0600) == 0);

    fs::create_symlink(header, root / "linked-header");
    CHECK_THROWS(EnvelopeError, header_identity((root / "linked-header").string(), true));
    CHECK_THROWS(EnvelopeError, header_identity((root / "linked-header").string(), false));

    fs::create_hard_link(header, root / "hard-header");
    CHECK_THROWS(EnvelopeError, header_identity(header.string(), false));
    fs::remove(root / "hard-header");

    CHECK(::mkfifo((root / "fifo-header").c_str(), 0600) == 0);
    CHECK_THROWS(EnvelopeError, header_identity((root / "fifo-header").string(), false));

    CHECK(::chmod(root.c_str(), 0777) == 0);
    CHECK_THROWS(EnvelopeError, header_identity((root / "new-header").string(), true));
    CHECK(::chmod(root.c_str(), 0700) == 0);

    const auto parent = root / "parent";
    fs::create_directory(parent);
    CHECK(::chmod(parent.c_str(), 0700) == 0);
    const auto parent_identity = header_identity((parent / "header").string(), true);
    fs::rename(parent, root / "old-parent");
    fs::create_directory(parent);
    CHECK_THROWS(EnvelopeError, open_validated_header((parent / "header").string(), true, parent_identity));

    const auto sysfs = root / "sysfs";
    fs::create_directories(sysfs / "253:0" / "dm");
    fs::create_directories(sysfs / "253:0" / "slaves" / "child");
    const auto write = [](const fs::path& path, const std::string& value) { std::ofstream(path) << value; };

    write(sysfs / "253:0" / "dm" / "uuid", "CRYPT-LUKS2-fixture\n");
    write(sysfs / "253:0" / "slaves" / "child" / "dev", "8:1\n");
    CHECK_NO_THROW(validate_mapping_device(sysfs, 253, 0, 8, 1));
    CHECK_THROWS(EnvelopeError, validate_mapping_device(sysfs, 253, 0, 8, 2));

    fs::create_directories(sysfs / "253:0" / "slaves" / "extra");
    write(sysfs / "253:0" / "slaves" / "extra" / "dev", "8:2\n");
    CHECK_THROWS(EnvelopeError, validate_mapping_device(sysfs, 253, 0, 8, 1));
    fs::remove_all(sysfs / "253:0" / "slaves" / "extra");

    write(sysfs / "253:0" / "dm" / "uuid", "unrelated-mapping\n");
    CHECK_THROWS(EnvelopeError, validate_mapping_device(sysfs, 253, 0, 8, 1));
    write(sysfs / "253:0" / "dm" / "uuid", "CRYPT-LUKS2-fixture\n");

    fs::create_directories(sysfs / "253:1" / "slaves" / "child");
    write(sysfs / "253:0" / "slaves" / "child" / "dev", "253:1\n");
    write(sysfs / "253:1" / "slaves" / "child" / "dev", "8:1\n");
    CHECK_NO_THROW(validate_mapping_device(sysfs, 253, 0, 8, 1));

    write(sysfs / "253:1" / "slaves" / "child" / "dev", "253:0\n");
    CHECK_THROWS(EnvelopeError, validate_mapping_device(sysfs, 253, 0, 8, 1));

    CHECK_THROWS(EnvelopeError, qprotect::cpp::detail::trusted_disk_executable("sh"));

    const auto resolve = [](const std::string& name) {
        try { return qprotect::cpp::detail::trusted_disk_executable(name); }
        catch (const EnvelopeError&) { return std::string{}; }
    };
    const auto cryptsetup = resolve("cryptsetup");
    const auto lsblk = resolve("lsblk");
    const char* environment_path = std::getenv("PATH");
    const std::optional<std::string> old_path = environment_path ?
        std::optional<std::string>(environment_path) : std::nullopt;

    write(root / "cryptsetup", "untrusted executable");
    CHECK(::chmod((root / "cryptsetup").c_str(), 0700) == 0);
    CHECK(::setenv("PATH", root.c_str(), 1) == 0);
    CHECK(resolve("cryptsetup") == cryptsetup);
    CHECK(resolve("lsblk") == lsblk);

    if (old_path) CHECK(::setenv("PATH", old_path->c_str(), 1) == 0);
    else CHECK(::unsetenv("PATH") == 0);

    fs::remove_all(root);
}

void test_disk_safety_report_validation() {
    using qprotect::cpp::json::Value;
    using qprotect::cpp::json::Object;
    using qprotect::cpp::json::Array;
    const auto validate = [](const std::string& input) {
        qprotect::cpp::detail::validate_lsblk_safety_json(input, "/dev/fake", 8, 1);
    };
    const Object device = Value::parse(
        R"({"path":"/dev/fake","type":"disk","maj:min":"8:1","mountpoints":[null]})").as_object();
    const auto document = [](const Object& entry) {
        return Value(Object{{"blockdevices", Value(Array{Value(entry)})}}).canonical();
    };
    CHECK_NO_THROW(validate(document(device)));
    CHECK_THROWS(EnvelopeError, validate("not json"));
    CHECK_THROWS(EnvelopeError, validate(R"({"blockdevices":[]})"));
    CHECK_THROWS(EnvelopeError, validate(R"({"blockdevices":[{}]})"));
    for (const char* field : {"path", "type", "maj:min", "mountpoints"}) {
        Object missing = device;
        missing.erase(field);
        CHECK_THROWS(EnvelopeError, validate(document(missing)));
    }
    const std::vector<std::pair<std::string, Value>> invalid_fields = {
        {"path", Value("/dev/other")},
        {"path", Value(nullptr)},
        {"type", Value(42)},
        {"type", Value("")},
        {"maj:min", Value("8:2")},
        {"maj:min", Value("9:1")},
        {"maj:min", Value(8)},
        {"mountpoints", Value(nullptr)},
        {"mountpoints", Value(42)},
        {"mountpoints", Value("")},
        {"mountpoints", Value(Array{Value(true)})},
        {"mountpoints", Value(Array{Value(42)})},
        {"mountpoints", Value(Array{Value("/fixture-mount")})},
        {"children", Value(Object{})},
        {"children", Value(nullptr)},
        {"children", Value(Array{Value(Object{})})},
        {"children", Value(Array{Value::parse(R"({"mountpoints":["/fixture-mount"]})")})},
    };
    for (const auto& [field, value] : invalid_fields) {
        Object invalid = device;
        invalid[field] = value;
        CHECK_THROWS(EnvelopeError, validate(document(invalid)));
    }
    CHECK_THROWS(EnvelopeError, validate(Value(Object{
        {"blockdevices", Value(Array{Value(device), Value(device)})}}).canonical()));
    Object no_children = device;
    no_children["children"] = Value(Array{});
    CHECK_NO_THROW(validate(document(no_children)));
}

void test_unsigned_envelope_tampering(const CryptoContext& context) {
    const KEMKeyPair recipient = generate_ml_kem_1024(context);
    const SecureBytes payload = bytes("unsigned envelope authentication test");
    const Envelope envelope = encrypt_envelope(
        context, payload, options_for({recipient.public_key_der}, "tamper-test"));
    const DecryptOptions options{recipient.private_key_der, std::nullopt};
    CHECK(!envelope.signature.has_value());
    CHECK(decrypt_envelope(context, Envelope::from_json(envelope.to_json()), options) == payload);
    const auto reject = [&](const Envelope& changed) {
        const Envelope parsed = Envelope::from_json(changed.to_json());
        CHECK_THROWS(EnvelopeError, decrypt_envelope(context, parsed, options));
    };
    Envelope changed = envelope;
    changed.ciphertext[0] ^= 1;
    reject(changed);
    changed = envelope;
    changed.tag[0] ^= 1;
    reject(changed);
    changed = envelope;
    changed.payload_iv[0] ^= 1;
    reject(changed);
    changed = envelope;
    changed.recipients[0].kem_ciphertext[0] ^= 1;
    reject(changed);
    changed = envelope;
    changed.recipients[0].wrap_iv[0] ^= 1;
    reject(changed);
    changed = envelope;
    changed.recipients[0].wrapped_key[0] ^= 1;
    reject(changed);
    changed = envelope;
    changed.recipients[0].wrap_tag[0] ^= 1;
    reject(changed);
    changed = envelope;
    changed.context = "different-context";
    reject(changed);
}

void test_hardware_report_schema(const std::string& report_text) {
    std::istringstream input_stream(report_text);
    std::string line;
    CHECK(static_cast<bool>(std::getline(input_stream, line)) && line == "qprotect-hardware-v1");
    std::string previous;
    std::size_t records = 0;
    while (std::getline(input_stream, line)) {
        if (line.empty()) continue;
        std::size_t separators = 0;
        for (const char character : line) if (character == '\t') ++separators;
        CHECK(separators == 4);
        CHECK(previous.empty() || previous <= line);
        CHECK(line.find('\r') == std::string::npos);
        previous = line;
        ++records;
    }
    CHECK(records > 0);
}

void test_hardware_fixture_discovery() {
    char temporary[] = "./qprotect-hardware-fixture-XXXXXX";
    char* directory = ::mkdtemp(temporary);
    CHECK(directory != nullptr);
    if (directory == nullptr) return;
    const std::filesystem::path root = std::filesystem::absolute(directory);
    qprotect::cpp::detail::HardwarePaths paths;
    paths.efi_root = root / "efi";
    paths.pci_root = root / "pci";
    paths.net_root = root / "net";
    paths.usb_root = root / "usb";
    paths.dev_root = root / "dev";
    paths.tpm_root = root / "tpm";
    paths.iommu_root = root / "iommu";
    paths.rng_root = root / "rng";
    paths.block_root = root / "block";
    paths.cpu_vulnerabilities = root / "cpu-vulnerabilities";

    const auto write = [](const std::filesystem::path& file, const std::string& value, bool binary = false) {
        std::filesystem::create_directories(file.parent_path());
        std::ofstream stream(file, binary ? std::ios::binary : std::ios::out);
        stream.write(value.data(), static_cast<std::streamsize>(value.size()));
    };
    const auto efi_variable = [](unsigned char value) {
        return std::string(4, '\0') + static_cast<char>(value);
    };
    const std::filesystem::path variables = paths.efi_root / "efivars";
    write(variables / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", efi_variable(1), true);
    write(variables / "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c", efi_variable(0), true);

    const std::filesystem::path pci_device = paths.pci_root / "0000:00:01.0";
    write(pci_device / "class", "0x020000\n");
    write(pci_device / "vendor", "0x1234\n");
    write(pci_device / "device", "0xabcd\n");
    std::filesystem::create_directories(paths.iommu_root / "17");
    std::filesystem::create_symlink(paths.iommu_root / "17", pci_device / "iommu_group");
    const std::filesystem::path driver = root / "drivers" / "sample_net";
    std::filesystem::create_directories(driver);
    std::filesystem::create_directories(paths.net_root / "eth-test" / "wireless");
    std::filesystem::create_symlink(pci_device, paths.net_root / "eth-test" / "device");
    std::filesystem::create_symlink(driver, pci_device / "driver");
    write(paths.net_root / "eth-test" / "operstate", "up\tfixture\n");
    write(paths.net_root / "eth-test" / "carrier", "1\n");

    write(paths.usb_root / "2-1" / "idVendor", "beef\n");
    write(paths.usb_root / "2-1" / "idProduct", "cafe\n");
    write(paths.dev_root / "tpm0", "not a device node");
    write(paths.tpm_root / "tpm0" / "tpm_version_major", "2\n");
    write(paths.rng_root / "rng_available", "sample-rng none\n");
    write(paths.rng_root / "rng_current", "sample-rng\n");
    write(paths.block_root / "disk-test" / "dev", "8:0\n");
    write(paths.block_root / "disk-test" / "ro", "0\n");
    write(paths.block_root / "disk-test" / "size", "1024\n");
    write(paths.cpu_vulnerabilities / "sample-vulnerability", "Mitigated\tby fixture\n");

    const std::string parsed_fixture = qprotect::cpp::detail::hardware_report_text(paths);
    test_hardware_report_schema(parsed_fixture);
    CHECK(parsed_fixture.find("boot\tsecure_boot\tenabled") != std::string::npos);
    CHECK(parsed_fixture.find("network\tpci_controller\tpresent") != std::string::npos);
    CHECK(parsed_fixture.find("iommu_group=17") != std::string::npos);
    CHECK(parsed_fixture.find("dma_security\tiommu_groups\tavailable") != std::string::npos);
    CHECK(parsed_fixture.find("network\tinterface\tpresent") != std::string::npos);
    CHECK(parsed_fixture.find("kind=wireless") != std::string::npos);
    CHECK(parsed_fixture.find("driver=sample_net") != std::string::npos);
    CHECK(parsed_fixture.find("%09") != std::string::npos);
    CHECK(parsed_fixture.find("bus\tusb_device\tpresent") != std::string::npos);
    CHECK(parsed_fixture.find("entropy\thardware_rng\tavailable") != std::string::npos);
    CHECK(parsed_fixture.find("storage\tblock_device\tpresent") != std::string::npos);
    CHECK(parsed_fixture.find("cpu_security\tvulnerability\treported") != std::string::npos);
    CHECK(parsed_fixture.find("trust\ttpm_device_nodes\tunavailable") != std::string::npos);
    CHECK(parsed_fixture.find("trust\ttpm_sysfs_device\tpresent") != std::string::npos);

    std::filesystem::remove(variables / "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    const std::string unknown_boot = qprotect::cpp::detail::hardware_report_text(paths);
    CHECK(unknown_boot.find("boot\tsecure_boot\tunknown") != std::string::npos);

    std::error_code cleanup_error;
    std::filesystem::remove_all(root, cleanup_error);
    CHECK(!cleanup_error);
}

}

int main() {
    try {
        const CryptoContext context;
        context.assert_ready();

        test_digests(context);
        test_hkdf(context);
        test_aes_gcm(context);
        test_ml_kem(context);
        test_ml_kem_key_validation(context);
        test_ml_dsa(context);
        test_secure_bytes();
        test_context();
        test_json_canonical();
        test_json_parse();
        test_json_utf8();
        test_identity_normalization();
        test_envelope_roundtrip(context);
        test_envelope_failures(context);
        test_unsigned_envelope_tampering(context);
        test_envelope_serialization(context);
        test_key_files(context);
        test_private_key_envelopes(context);
        test_disk_plan_helpers();
        test_disk_header_and_mapping_validation();
        test_disk_safety_report_validation();
        test_hardware_fixture_discovery();
    } catch (const std::exception& error) {
        std::cerr << "unit test harness error: " << error.what() << "\n";
        return 1;
    }

    std::cout << "unit tests: " << g_checks << " checks, " << g_failures
              << " failures\n";
    return g_failures == 0 ? 0 : 1;
}
