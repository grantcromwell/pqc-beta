#include "qprotect/envelope.hpp"

#include "crypto_context_handles.hpp"
#include "json_minimal.hpp"
#include "openssl_utils.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <ctime>
#include <set>
#include <regex>
#include <span>
#include <utility>

#include "qprotect/algorithms.hpp"
#include "qprotect/keys.hpp"

namespace qprotect::cpp {
namespace {

constexpr int kEnvelopeVersion = 1;
constexpr char kEnvelopeFormat[] = "qprotect-envelope-v1";
constexpr char kSignatureAlgorithm[] = "ML-DSA-87";
constexpr char kWrapInfoPrefix[] = "qprotect/v1/wrap/";

constexpr std::size_t kKemCiphertextLength = 1568;
constexpr std::size_t kWrapIvLength = 12;
constexpr std::size_t kWrappedKeyLength = 32;
constexpr std::size_t kWrapTagLength = 16;
constexpr std::size_t kPayloadIvLength = 12;
constexpr std::size_t kTagLength = 16;
constexpr std::size_t kKeyIdHexLength = 32;
constexpr std::size_t kSignatureLength = 4627;
constexpr std::size_t kMaximumRecipients = 32;
constexpr std::size_t kMaximumPayload = 64ULL * 1024 * 1024;
constexpr std::size_t kMaximumEnvelope = 96ULL * 1024 * 1024;

bool is_base64_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/';
}

std::string base64_encode(std::span<const unsigned char> input) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((input.size() + 2) / 3 * 4);
    std::size_t i = 0;
    while (i + 3 <= input.size()) {
        const unsigned int v =
            (static_cast<unsigned int>(input[i]) << 16) |
            (static_cast<unsigned int>(input[i + 1]) << 8) |
            static_cast<unsigned int>(input[i + 2]);
        out.push_back(alphabet[(v >> 18) & 0x3F]);
        out.push_back(alphabet[(v >> 12) & 0x3F]);
        out.push_back(alphabet[(v >> 6) & 0x3F]);
        out.push_back(alphabet[v & 0x3F]);
        i += 3;
    }
    const std::size_t remaining = input.size() - i;
    if (remaining == 1) {
        const unsigned int v = static_cast<unsigned int>(input[i]) << 16;
        out.push_back(alphabet[(v >> 18) & 0x3F]);
        out.push_back(alphabet[(v >> 12) & 0x3F]);
        out += "==";
    } else if (remaining == 2) {
        const unsigned int v =
            (static_cast<unsigned int>(input[i]) << 16) |
            (static_cast<unsigned int>(input[i + 1]) << 8);
        out.push_back(alphabet[(v >> 18) & 0x3F]);
        out.push_back(alphabet[(v >> 12) & 0x3F]);
        out.push_back(alphabet[(v >> 6) & 0x3F]);
        out.push_back('=');
    }
    return out;
}

SecureBytes base64_decode(const std::string& value, const char* field) {

    if (!value.empty() && value.back() == '\n') {
        throw EnvelopeError(std::string("invalid base64 field: ") + field);
    }
    std::string data;
    std::size_t padding = 0;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '=') {
            padding = value.size() - i;
            if (!std::all_of(value.begin() + static_cast<std::ptrdiff_t>(i), value.end(),
                             [](char c) { return c == '='; })) {
                throw EnvelopeError(std::string("invalid base64 field: ") + field);
            }
            break;
        }
        if (!is_base64_char(value[i])) {
            throw EnvelopeError(std::string("invalid base64 field: ") + field);
        }
        data.push_back(value[i]);
    }
    if (padding > 2 || data.size() % 4 == 1) {
        throw EnvelopeError(std::string("invalid base64 field: ") + field);
    }
    const std::size_t decoded_length = data.size() / 4 * 3;
    const std::size_t leftover = data.size() % 4;
    const std::size_t total = decoded_length + (leftover == 2 ? 1 : (leftover == 3 ? 2 : 0));
    if ((padding == 0 && leftover != 0) ||
        (padding == 2 && leftover != 2) ||
        (padding == 1 && leftover != 3)) {
        throw EnvelopeError(std::string("invalid base64 field: ") + field);
    }

    auto decode_char = [](char c) -> unsigned int {
        if (c >= 'A' && c <= 'Z') return static_cast<unsigned int>(c - 'A');
        if (c >= 'a' && c <= 'z') return static_cast<unsigned int>(c - 'a' + 26);
        if (c >= '0' && c <= '9') return static_cast<unsigned int>(c - '0' + 52);
        if (c == '+') return 62;
        return 63;
    };

    if ((leftover == 2 && (decode_char(data.back()) & 0x0F) != 0) ||
        (leftover == 3 && (decode_char(data.back()) & 0x03) != 0)) {
        throw EnvelopeError(std::string("invalid base64 field: ") + field);
    }

    SecureBytes out(total);
    std::size_t offset = 0;
    std::size_t i = 0;
    while (i + 4 <= data.size()) {
        const unsigned int v = (decode_char(data[i]) << 18) |
                                (decode_char(data[i + 1]) << 12) |
                                (decode_char(data[i + 2]) << 6) |
                                decode_char(data[i + 3]);
        out[offset++] = static_cast<unsigned char>((v >> 16) & 0xFF);
        out[offset++] = static_cast<unsigned char>((v >> 8) & 0xFF);
        out[offset++] = static_cast<unsigned char>(v & 0xFF);
        i += 4;
    }
    if (leftover == 2) {
        const unsigned int v = (decode_char(data[i]) << 18) |
                               (decode_char(data[i + 1]) << 12);
        out[offset++] = static_cast<unsigned char>((v >> 16) & 0xFF);
    } else if (leftover == 3) {
        const unsigned int v = (decode_char(data[i]) << 18) |
                               (decode_char(data[i + 1]) << 12) |
                               (decode_char(data[i + 2]) << 6);
        out[offset++] = static_cast<unsigned char>((v >> 16) & 0xFF);
        out[offset++] = static_cast<unsigned char>((v >> 8) & 0xFF);
    }
    return out;
}

bool is_valid_key_id(const std::string& key_id) {
    if (key_id.size() != kKeyIdHexLength) {
        return false;
    }
    return std::all_of(key_id.begin(), key_id.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

void validate_context(const std::string& context) {

    if (context.empty() || context.size() > 128) {
        throw EnvelopeError("context must be a non-empty string of at most 128 characters");
    }
    for (const char c : context) {
        const unsigned char byte = static_cast<unsigned char>(c);
        if (byte < 0x20 || byte > 0x7E) {
            throw EnvelopeError("context contains control or non-ASCII characters");
        }
    }
}

bool valid_created_at(const std::string& value) {
    static const std::regex pattern(
        R"(^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{6}Z$)"
    );
    if (!std::regex_match(value, pattern)) {
        return false;
    }

    const int year_value = std::stoi(value.substr(0, 4));
    const unsigned month_value = static_cast<unsigned>(std::stoul(value.substr(5, 2)));
    const unsigned day_value = static_cast<unsigned>(std::stoul(value.substr(8, 2)));
    const std::chrono::year_month_day date{
        std::chrono::year{year_value},
        std::chrono::month{month_value},
        std::chrono::day{day_value},
    };
    return date.ok();
}

SecureBytes wrap_info_bytes(const std::string& context, const std::string& key_id) {
    const std::string info = std::string(kWrapInfoPrefix) + context + "/" + key_id;
    return SecureBytes(
        reinterpret_cast<const unsigned char*>(info.data()),
        info.size()
    );
}

std::string utc_now_iso8601() {

    const auto now = std::chrono::system_clock::now();
    const std::time_t seconds = std::chrono::system_clock::to_time_t(now);
    const auto fraction = std::chrono::duration_cast<std::chrono::microseconds>(
        now.time_since_epoch()
    );
    std::tm tm{};
    gmtime_r(&seconds, &tm);
    char buffer[64];
    std::snprintf(
        buffer,
        sizeof(buffer),
        "%04d-%02d-%02dT%02d:%02d:%02d.%06lldZ",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        static_cast<long long>(fraction.count() % 1'000'000)
    );
    return buffer;
}

json::Object suite_object() {
    json::Object suite;
    suite["aead"] = json::Value("AES-256-GCM");
    suite["digest"] = json::Value("SHA-384");
    suite["kem"] = json::Value("ML-KEM-1024");
    suite["kdf"] = json::Value("HKDF-SHA-384");
    suite["signature"] = json::Value(kSignatureAlgorithm);
    return suite;
}

json::Value envelope_to_dict(const Envelope& envelope, bool include_signature) {
    json::Object out;
    out["version"] = json::Value(envelope.version);
    out["format"] = json::Value(kEnvelopeFormat);
    out["context"] = json::Value(envelope.context);
    out["created_at"] = json::Value(envelope.created_at);
    out["suite"] = json::Value(suite_object());
    out["payload_iv"] = json::Value(base64_encode(envelope.payload_iv));
    out["ciphertext"] = json::Value(base64_encode(envelope.ciphertext));
    out["tag"] = json::Value(base64_encode(envelope.tag));

    json::Array recipients;
    recipients.reserve(envelope.recipients.size());
    for (const EnvelopeRecipient& recipient : envelope.recipients) {
        json::Object item;
        item["key_id"] = json::Value(recipient.key_id);
        item["kem_ciphertext"] = json::Value(base64_encode(recipient.kem_ciphertext));
        item["wrap_iv"] = json::Value(base64_encode(recipient.wrap_iv));
        item["wrapped_key"] = json::Value(base64_encode(recipient.wrapped_key));
        item["wrap_tag"] = json::Value(base64_encode(recipient.wrap_tag));
        recipients.push_back(json::Value(std::move(item)));
    }
    out["recipients"] = json::Value(std::move(recipients));

    out["signer_key_id"] = envelope.signer_key_id
        ? json::Value(*envelope.signer_key_id)
        : json::Value(nullptr);
    if (envelope.signer_key_id.has_value() || envelope.signature.has_value()) {
        out["signature_algorithm"] = json::Value(kSignatureAlgorithm);
    } else {
        out["signature_algorithm"] = json::Value(nullptr);
    }
    if (include_signature && envelope.signature.has_value()) {
        out["signature"] = json::Value(base64_encode(*envelope.signature));
    }
    return json::Value(std::move(out));
}

std::string signature_material(const Envelope& envelope) {
    return envelope_to_dict(envelope, false).canonical();
}

std::string payload_aad(const Envelope& envelope) {
    json::Object header = envelope_to_dict(envelope, false).as_object();
    header.erase("ciphertext");
    header.erase("tag");
    return json::Value(std::move(header)).canonical();
}

EnvelopeRecipient recipient_from_json(const json::Value& value, std::size_t index) {
    const json::Object& item = value.expect_object("recipient");
    static const std::set<std::string> fields = {
        "key_id", "kem_ciphertext", "wrap_iv", "wrapped_key", "wrap_tag"
    };
    if (item.size() != fields.size() ||
        !std::all_of(item.begin(), item.end(), [](const auto& entry) {
            return fields.contains(entry.first);
        })) {
        throw EnvelopeError("recipient fields do not match the envelope specification");
    }
    const auto require = [&](const char* key) -> const json::Value& {
        const auto it = item.find(key);
        if (it == item.end()) {
            throw EnvelopeError(std::string("missing recipient field: ") + key);
        }
        return it->second;
    };

    EnvelopeRecipient recipient;
    const json::Value& key_id = require("key_id");
    if (!key_id.is_string() || !is_valid_key_id(key_id.as_string())) {
        throw EnvelopeError("invalid key_id");
    }
    recipient.key_id = key_id.as_string();

    const auto field = [&](const char* name, std::size_t expected) {
        const json::Value& raw = require(name);
        if (!raw.is_string()) {
            throw EnvelopeError(std::string("invalid base64 field: ") + name);
        }
        SecureBytes decoded = base64_decode(raw.as_string(), name);
        if (decoded.size() != expected) {
            throw EnvelopeError("invalid recipient wrapping parameters");
        }
        return decoded;
    };

    recipient.kem_ciphertext = field("kem_ciphertext", kKemCiphertextLength);
    recipient.wrap_iv = field("wrap_iv", kWrapIvLength);
    recipient.wrapped_key = field("wrapped_key", kWrappedKeyLength);
    recipient.wrap_tag = field("wrap_tag", kWrapTagLength);
    static_cast<void>(index);
    return recipient;
}

const json::Value& require_field(const json::Object& data, const char* key) {
    const auto it = data.find(key);
    if (it == data.end()) {
        throw EnvelopeError(std::string("missing envelope field: ") + key);
    }
    return it->second;
}

}

std::string Envelope::to_json() const {
    if (context.empty() || created_at.empty()) {
        throw EnvelopeError("incomplete envelope cannot be serialized");
    }
    return envelope_to_dict(*this, true).pretty(2);
}

Envelope Envelope::from_json(const std::string& text) {
    if (text.size() > kMaximumEnvelope) {
        throw EnvelopeError("envelope document exceeds the format limit");
    }
    const json::Value document = json::Value::parse(text);
    const json::Object& data = document.expect_object("envelope");
    static const std::set<std::string> required_fields = {
        "version", "format", "context", "created_at", "suite", "payload_iv",
        "ciphertext", "tag", "recipients", "signer_key_id", "signature_algorithm"
    };
    static const std::set<std::string> allowed_fields = [] {
        std::set<std::string> result = required_fields;
        result.insert("signature");
        return result;
    }();
    if (!std::all_of(data.begin(), data.end(), [](const auto& entry) {
            return allowed_fields.contains(entry.first);
        })) {
        throw EnvelopeError("envelope contains unknown fields");
    }
    for (const std::string& field : required_fields) {
        if (!data.contains(field)) {
            throw EnvelopeError("missing envelope field: " + field);
        }
    }

    const json::Value& version = require_field(data, "version");
    const json::Value& format = require_field(data, "format");
    const json::Value& context = require_field(data, "context");
    const json::Value& created_at = require_field(data, "created_at");
    const json::Value& suite = require_field(data, "suite");
    const json::Value& payload_iv = require_field(data, "payload_iv");
    const json::Value& ciphertext = require_field(data, "ciphertext");
    const json::Value& tag = require_field(data, "tag");
    const json::Value& recipients_raw = require_field(data, "recipients");

    if (!version.is_integer() || version.as_integer() != kEnvelopeVersion ||
        !format.is_string() || format.as_string() != kEnvelopeFormat) {
        throw EnvelopeError("unsupported envelope version or format");
    }
    if (!context.is_string()) {
        throw EnvelopeError("invalid context");
    }
    validate_context(context.as_string());
    if (!created_at.is_string() || !valid_created_at(created_at.as_string())) {
        throw EnvelopeError("invalid created_at");
    }

    if (!suite.is_object() ||
        suite.canonical() != json::Value(suite_object()).canonical()) {
        throw EnvelopeError("algorithm suite does not match CNSA 2.0 target");
    }
    if (!recipients_raw.is_array() || recipients_raw.as_array().empty() ||
        recipients_raw.as_array().size() > kMaximumRecipients) {
        throw EnvelopeError("envelope must have 1..32 recipients");
    }

    Envelope envelope;
    envelope.version = kEnvelopeVersion;
    envelope.context = context.as_string();
    envelope.created_at = created_at.as_string();

    const auto payload_field = [&](const json::Value& raw, const char* name) {
        if (!raw.is_string()) {
            throw EnvelopeError(std::string("invalid base64 field: ") + name);
        }
        return base64_decode(raw.as_string(), name);
    };
    envelope.payload_iv = payload_field(payload_iv, "payload_iv");
    envelope.ciphertext = payload_field(ciphertext, "ciphertext");
    envelope.tag = payload_field(tag, "tag");
    if (envelope.ciphertext.size() > kMaximumPayload) {
        throw EnvelopeError("envelope payload exceeds the format limit");
    }

    std::set<std::string> seen_key_ids;
    for (const json::Value& item : recipients_raw.as_array()) {
        EnvelopeRecipient recipient = recipient_from_json(item, 0);
        if (!seen_key_ids.insert(recipient.key_id).second) {
            throw EnvelopeError("duplicate recipient key_id");
        }
        envelope.recipients.push_back(std::move(recipient));
    }

    const auto signer_key_id_it = data.find("signer_key_id");
    if (signer_key_id_it != data.end() && !signer_key_id_it->second.is_null()) {
        if (!signer_key_id_it->second.is_string() ||
            !is_valid_key_id(signer_key_id_it->second.as_string())) {
            throw EnvelopeError("invalid signer_key_id");
        }
        envelope.signer_key_id = signer_key_id_it->second.as_string();
    }

    const auto signature_it = data.find("signature");
    if (signature_it != data.end() && !signature_it->second.is_null()) {
        envelope.signature = payload_field(signature_it->second, "signature");
    }

    const auto algorithm_it = data.find("signature_algorithm");
    const bool has_algorithm = algorithm_it != data.end() && !algorithm_it->second.is_null();
    if (envelope.signature.has_value()) {
        if (has_algorithm &&
            (!algorithm_it->second.is_string() ||
             algorithm_it->second.as_string() != kSignatureAlgorithm)) {
            throw EnvelopeError("invalid signature algorithm");
        }
        if (!has_algorithm) {
            throw EnvelopeError("invalid signature algorithm");
        }
        if (!envelope.signer_key_id.has_value()) {
            throw EnvelopeError("signed envelope missing signer_key_id");
        }
        if (envelope.signature->size() != kSignatureLength) {
            throw EnvelopeError("invalid ML-DSA-87 signature length");
        }
    } else if (has_algorithm) {
        throw EnvelopeError("signature metadata without a signature");
    }

    if (envelope.payload_iv.size() != kPayloadIvLength ||
        envelope.tag.size() != kTagLength) {
        throw EnvelopeError("invalid payload AEAD parameters");
    }
    return envelope;
}

Envelope encrypt_envelope(
    const CryptoContext& context,
    std::span<const unsigned char> plaintext,
    const EncryptOptions& options
) {
    if (options.recipient_public_key_der.empty() ||
        options.recipient_public_key_der.size() > kMaximumRecipients) {
        throw EnvelopeError("1..32 recipient keys are required");
    }
    if (plaintext.size() > kMaximumPayload) {
        throw EnvelopeError("payload exceeds the 64 MiB envelope-v1 limit");
    }
    validate_context(options.context);

    const SecureBytes content_key = context.random_bytes(32);

    std::vector<EnvelopeRecipient> recipients;
    std::set<std::string> recipient_ids;
    recipients.reserve(options.recipient_public_key_der.size());
    for (const SecureBytes& public_key_der : options.recipient_public_key_der) {
        const std::string key_id = key_id_for_public_key(context, public_key_der);
        if (!recipient_ids.insert(key_id).second) {
            throw EnvelopeError("duplicate recipient public key");
        }
        const KEMEncapsulation encapsulation =
            encapsulate_ml_kem_1024(context, public_key_der);
        const SecureBytes info = wrap_info_bytes(options.context, key_id);
        const SecureBytes wrapping_key = hkdf_sha384(
            context,
            encapsulation.shared_secret,
            encapsulation.ciphertext,
            info,
            32
        );
        const SecureBytes wrap_iv = context.random_bytes(12);
        const AeadResult wrapped = aes_256_gcm_encrypt(
            context,
            wrapping_key,
            wrap_iv,
            content_key,
            info
        );
        recipients.push_back(EnvelopeRecipient{
            key_id,
            encapsulation.ciphertext,
            wrap_iv,
            wrapped.ciphertext,
            wrapped.tag,
        });
    }

    Envelope envelope;
    envelope.version = kEnvelopeVersion;
    envelope.context = options.context;
    envelope.created_at = utc_now_iso8601();
    envelope.payload_iv = context.random_bytes(12);
    envelope.recipients = std::move(recipients);
    if (options.signer_private_key_der.has_value()) {
        const SecureBytes signer_public =
            public_key_of_private(context, *options.signer_private_key_der);
        envelope.signer_key_id = key_id_for_public_key(context, signer_public);
    }

    const std::string aad = payload_aad(envelope);
    const AeadResult payload = aes_256_gcm_encrypt(
        context,
        content_key,
        envelope.payload_iv,
        plaintext,
        SecureBytes(reinterpret_cast<const unsigned char*>(aad.data()), aad.size())
    );
    envelope.ciphertext = payload.ciphertext;
    envelope.tag = payload.tag;

    if (options.signer_private_key_der.has_value()) {
        const std::string material = signature_material(envelope);
        envelope.signature = sign_ml_dsa_87(
            context,
            *options.signer_private_key_der,
            SecureBytes(reinterpret_cast<const unsigned char*>(material.data()), material.size())
        );
    }
    return envelope;
}

SecureBytes decrypt_envelope(
    const CryptoContext& context,
    const Envelope& envelope,
    const DecryptOptions& options
) {
    if (envelope.version != kEnvelopeVersion) {
        throw EnvelopeError("unsupported envelope version");
    }

    if ((options.require_signature || options.signer_public_key_der.has_value()) &&
        !envelope.signature.has_value()) {
        throw EnvelopeError("sender signature is required");
    }

    if (envelope.signature.has_value()) {
        if (!options.signer_public_key_der.has_value()) {
            throw EnvelopeError("signed envelope requires a signer public key");
        }
        const std::string expected_signer_id =
            key_id_for_public_key(context, *options.signer_public_key_der);
        if (!envelope.signer_key_id.has_value() ||
            expected_signer_id != *envelope.signer_key_id) {
            throw EnvelopeError("signer public key does not match signer_key_id");
        }
        const std::string material = signature_material(envelope);
        if (!verify_ml_dsa_87(
                context,
                *options.signer_public_key_der,
                SecureBytes(reinterpret_cast<const unsigned char*>(material.data()), material.size()),
                *envelope.signature
            )) {
            throw EnvelopeError("ML-DSA-87 signature verification failed");
        }
    }

    const SecureBytes recipient_public =
        public_key_of_private(context, options.recipient_private_key_der);
    const std::string private_key_id = key_id_for_public_key(context, recipient_public);
    const auto recipient_it = std::find_if(
        envelope.recipients.begin(),
        envelope.recipients.end(),
        [&](const EnvelopeRecipient& item) { return item.key_id == private_key_id; }
    );
    if (recipient_it == envelope.recipients.end()) {
        throw EnvelopeError("recipient private key does not match any envelope recipient");
    }

    try {

        const SecureBytes info = wrap_info_bytes(envelope.context, recipient_it->key_id);
        const SecureBytes secret = decapsulate_ml_kem_1024(
            context,
            options.recipient_private_key_der,
            recipient_it->kem_ciphertext
        );
        const SecureBytes wrapping_key = hkdf_sha384(
            context,
            secret,
            recipient_it->kem_ciphertext,
            info,
            32
        );
        const SecureBytes content_key = aes_256_gcm_decrypt(
            context,
            wrapping_key,
            recipient_it->wrap_iv,
            recipient_it->wrapped_key,
            recipient_it->wrap_tag,
            info
        );
        const std::string aad = payload_aad(envelope);
        return aes_256_gcm_decrypt(
            context,
            content_key,
            envelope.payload_iv,
            envelope.ciphertext,
            envelope.tag,
            SecureBytes(reinterpret_cast<const unsigned char*>(aad.data()), aad.size())
        );
    } catch (const EnvelopeError&) {
        throw;
    } catch (const CryptoError& error) {
        throw EnvelopeError(error.what());
    }
}

}
