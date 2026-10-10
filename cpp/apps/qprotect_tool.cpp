#include "qprotect/algorithms.hpp"
#include "qprotect/constants.hpp"
#include "qprotect/crypto_context.hpp"
#include "qprotect/disk.hpp"
#include "qprotect/envelope.hpp"
#include "qprotect/error.hpp"
#include "qprotect/hardware.hpp"
#include "qprotect/keys.hpp"
#include "qprotect/secure_bytes.hpp"
#include "qprotect/self_test.hpp"

#include "identity.hpp"
#include "secure_file.hpp"

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/crypto.h>
#include <span>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

using qprotect::cpp::CryptoContext;
using qprotect::cpp::CryptoError;
using qprotect::cpp::Envelope;
using qprotect::cpp::EnvelopeError;
using qprotect::cpp::SecureBytes;

struct Arguments {
    std::string command;
    std::string provider = "default";
    bool force = false;
    std::string key_type;
    std::string private_path;
    std::string public_path;
    std::string input_path;
    std::string output_path;
    std::vector<std::string> recipients;
    std::string signer_private_path;
    std::string recipient_private_path;
    std::string signer_public_path;
    std::string context = "file";
    std::string disk_action;
    std::string disk_device;
    std::string disk_mapper;
    std::string disk_key_file;
    std::string disk_header_file;
    std::string disk_backup_file;
    std::string disk_integrity;
    std::string disk_confirmation;
    std::string hardware_action;
    int disk_iter_time = 5000;
    std::optional<int> disk_argon_memory;
    std::optional<int> disk_argon_parallelism;
    int disk_sector_size = 4096;
    bool disk_execute = false;
    bool disk_format_options = false;
};

void usage(std::ostream& out) {
    out << "usage: qprotect <command> [options]\n"
        << "\n"
        << "commands:\n"
        << "  doctor   report provider readiness and algorithm self-tests\n"
        << "  selftest run cryptographic self-tests and an envelope round trip\n"
        << "  keygen   --type kem|sign --private PATH --public PATH\n"
        << "  encrypt  --input PATH --output PATH --recipient PEM [--recipient PEM ...]\n"
        << "           [--signer PRIVPEM] [--context STR]\n"
        << "  decrypt  --input PATH --output PATH --recipient-private PRIVPEM\n"
        << "           [--signer-public PUBPEM]\n"
        << "  key-encrypt --input PRIVATE-PEM --output QPE --recipient KEM-PUBPEM\n"
        << "              --signer ML-DSA-PRIVPEM [--recipient KEM-PUBPEM ...]\n"
        << "  key-decrypt --input QPE --output PRIVATE-PEM --recipient-private KEM-PRIVPEM\n"
        << "              --signer-public ML-DSA-PUBPEM\n"
        << "  identity-encrypt --input JSON --output QPE --recipient PEM [--signer PRIVPEM]\n"
        << "  identity-decrypt --input QPE --output JSON --recipient-private PRIVPEM\n"
        << "           [--signer-public PUBPEM]\n"
        << "  disk plan|format|open|close --device PATH --mapper NAME [options]\n"
        << "           format requires --execute --confirmation TOKEN\n"
        << "           --header PATH uses a new private file for format, an existing file for open\n"
        << "           --header-backup PATH is a plan-only preview for backing up the new header\n"
        << "  hardware doctor          read-only dynamic platform inventory\n"
        << "\n"
        << "options:\n"
        << "  --provider NAME           select an installed OpenSSL provider\n"
        << "  --force                   atomically replace an existing output\n";
}

std::string json_escape(const std::string& value) {
    std::string output;
    output.reserve(value.size() + 2);
    for (const unsigned char c : value) {
        switch (c) {
            case '"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:
                if (c < 0x20) {
                    static constexpr char hex[] = "0123456789abcdef";
                    output += "\\u00";
                    output.push_back(hex[(c >> 4) & 0x0f]);
                    output.push_back(hex[c & 0x0f]);
                } else {
                    output.push_back(static_cast<char>(c));
                }
        }
    }
    return output;
}

void print_health_report(
    const qprotect::cpp::SelfTestReport& report,
    bool full_selftest,
    bool round_trip
) {
    std::cout << "{\n"
              << "  \"tool_version\": \"" << qprotect::cpp::constants::module_version << "\",\n"
              << "  \"openssl_version\": \"" << json_escape(OpenSSL_version(OPENSSL_VERSION)) << "\",\n"
              << "  \"provider\": \"" << json_escape(report.provider) << "\",\n"
              << "  \"ready\": " << (report.passed && (!full_selftest || round_trip) ? "true" : "false") << ",\n"
              << "  \"algorithm_self_tests_passed\": " << (report.passed ? "true" : "false");
    if (full_selftest) {
        std::cout << ",\n  \"envelope_round_trip_passed\": "
                  << (round_trip ? "true" : "false");
    }
    std::cout << ",\n  \"checks\": [\n";
    for (std::size_t index = 0; index < report.checks.size(); ++index) {
        const auto& check = report.checks[index];
        std::cout << "    {\"name\": \"" << json_escape(check.name)
                  << "\", \"passed\": " << (check.passed ? "true" : "false") << "}";
        if (index + 1 != report.checks.size() || full_selftest) {
            std::cout << ",";
        }
        std::cout << "\n";
    }
    if (full_selftest) {
        std::cout << "    {\"name\": \"signed_envelope_round_trip\", \"passed\": "
                  << (round_trip ? "true" : "false") << "}\n";
    }
    std::cout << "  ]\n}\n";
}

int run_diagnostics(const CryptoContext& context, bool full_selftest) {
    qprotect::cpp::SelfTestReport report = qprotect::cpp::run_self_tests(context);
    bool round_trip = false;
    if (full_selftest && report.passed) {
        try {
            const qprotect::cpp::KEMKeyPair recipient = qprotect::cpp::generate_ml_kem_1024(context);
            const qprotect::cpp::SignatureKeyPair signer = qprotect::cpp::generate_ml_dsa_87(context);
            qprotect::cpp::EncryptOptions encrypt_options;
            encrypt_options.context = "selftest";
            encrypt_options.recipient_public_key_der.push_back(recipient.public_key_der);
            encrypt_options.signer_private_key_der = signer.private_key_der;
            static constexpr unsigned char message[] = "qprotect native self-test";
            const auto plaintext = std::span<const unsigned char>(message, sizeof(message) - 1);
            const Envelope envelope = qprotect::cpp::encrypt_envelope(context, plaintext, encrypt_options);
            const Envelope parsed = Envelope::from_json(envelope.to_json());
            qprotect::cpp::DecryptOptions decrypt_options;
            decrypt_options.recipient_private_key_der = recipient.private_key_der;
            decrypt_options.signer_public_key_der = signer.public_key_der;
            const SecureBytes recovered = qprotect::cpp::decrypt_envelope(context, parsed, decrypt_options);
            round_trip = recovered.size() == plaintext.size() &&
                std::equal(recovered.begin(), recovered.end(), plaintext.begin());
        } catch (const std::exception&) {
            round_trip = false;
        }
    }
    print_health_report(report, full_selftest, round_trip);
    return report.passed && (!full_selftest || round_trip) ? 0 : 1;
}

bool parse_arguments(int argc, char* argv[], Arguments& args) {
    if (argc < 2) {
        usage(std::cerr);
        return false;
    }
    args.command = argv[1];
    int first_option = 2;
    if (args.command == "disk") {
        if (argc < 3) { std::cerr << "error: disk requires plan|format|open|close\n"; return false; }
        args.disk_action = argv[2];
        first_option = 3;
    }
    if (args.command == "hardware") {
        if (argc < 3) { std::cerr << "error: hardware requires doctor\n"; return false; }
        args.hardware_action = argv[2];
        first_option = 3;
    }
    for (int i = first_option; i < argc; ++i) {
        const std::string argument = argv[i];
        const auto value = [&]() -> std::string {
            if (i + 1 >= argc) {
                throw std::string("missing value for ") + argument;
            }
            return argv[++i];
        };

        const auto integer = [&](int minimum, int maximum) {
            const std::string input = value();
            int parsed = 0;
            const auto result = std::from_chars(input.data(), input.data() + input.size(), parsed);

            if (result.ec != std::errc{} || result.ptr != input.data() + input.size() ||
                parsed < minimum || parsed > maximum) {
                throw std::string("invalid value for ") + argument;
            }

            args.disk_format_options = true;
            return parsed;
        };

        try {
            if (argument == "--provider") {
                args.provider = value();
            } else if (argument == "--force") {
                args.force = true;
            } else if (argument == "--type") {
                args.key_type = value();
            } else if (argument == "--private") {
                args.private_path = value();
            } else if (argument == "--public") {
                args.public_path = value();
            } else if (argument == "--input") {
                args.input_path = value();
            } else if (argument == "--output") {
                args.output_path = value();
            } else if (argument == "--recipient") {
                args.recipients.push_back(value());
            } else if (argument == "--signer") {
                args.signer_private_path = value();
            } else if (argument == "--recipient-private") {
                args.recipient_private_path = value();
            } else if (argument == "--signer-public") {
                args.signer_public_path = value();
            } else if (argument == "--context") {
                args.context = value();
            } else if (argument == "--device") {
                args.disk_device = value();
            } else if (argument == "--mapper") {
                args.disk_mapper = value();
            } else if (argument == "--key-file") {
                args.disk_key_file = value();
            } else if (argument == "--header") {
                args.disk_header_file = value();
            } else if (argument == "--header-backup") {
                args.disk_backup_file = value();
            } else if (argument == "--integrity") {
                args.disk_integrity = value();
                args.disk_format_options = true;
            } else if (argument == "--confirmation") {
                args.disk_confirmation = value();
            } else if (argument == "--iter-time") {
                args.disk_iter_time = integer(1000, 10000);
            } else if (argument == "--pbkdf-memory") {
                args.disk_argon_memory = integer(32, 4194304);
            } else if (argument == "--pbkdf-parallel") {
                args.disk_argon_parallelism = integer(1, 4);
            } else if (argument == "--sector-size") {
                args.disk_sector_size = integer(512, 4096);
            } else if (argument == "--execute") {
                args.disk_execute = true;
            } else {
                std::cerr << "unknown option: " << argument << "\n";
                usage(std::cerr);
                return false;
            }
        } catch (const std::string& error) {
            std::cerr << "error: " << error << "\n";
            return false;
        }
    }
    return true;
}

SecureBytes read_binary_file(
    const std::string& path,
    std::streamoff maximum = 64LL * 1024 * 1024
) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw EnvelopeError("unable to open input file: " + path);
    }
    file.seekg(0, std::ios::end);
    const std::streamoff size = file.tellg();
    if (size < 0 || size > maximum) {
        throw EnvelopeError("input exceeds the format size limit");
    }
    file.seekg(0, std::ios::beg);
    SecureBytes data(static_cast<std::size_t>(size));
    if (size > 0) {
        file.read(reinterpret_cast<char*>(data.data()), size);
        if (!file) {
            throw EnvelopeError("unable to read input file: " + path);
        }
    }
    if (file.peek() != std::char_traits<char>::eof()) {
        throw EnvelopeError("input changed while it was being read");
    }
    return data;
}

void write_binary_file(
    const std::string& path,
    std::span<const unsigned char> data,
    bool overwrite
) {
    qprotect::cpp::detail::secure_write_file(path, data, 0600, overwrite);
}

std::string read_text_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw EnvelopeError("unable to open envelope file: " + path);
    }
    constexpr std::streamoff kMaximumEnvelope = 96LL * 1024 * 1024;
    file.seekg(0, std::ios::end);
    const std::streamoff size = file.tellg();
    if (size < 0 || size > kMaximumEnvelope) {
        throw EnvelopeError("envelope document exceeds the format limit");
    }
    file.seekg(0, std::ios::beg);
    std::string contents(static_cast<std::size_t>(size), '\0');
    if (size > 0) {
        file.read(contents.data(), size);
        if (!file) {
            throw EnvelopeError("unable to read envelope file: " + path);
        }
    }
    if (file.peek() != std::char_traits<char>::eof()) {
        throw EnvelopeError("envelope changed while it was being read");
    }
    return contents;
}

void reject_same_path(const std::string& input, const std::string& output) {
    std::error_code error;
    const auto left = std::filesystem::weakly_canonical(input, error);
    if (error) {
        throw EnvelopeError("unable to resolve input path");
    }
    const auto right = std::filesystem::weakly_canonical(output, error);
    if (error) {
        throw EnvelopeError("unable to resolve output path");
    }
    if (left == right) {
        throw EnvelopeError("input and output must be different paths");
    }
}

void write_key_pair(const CryptoContext& context,
                    std::span<const unsigned char> privateKey,
                    std::span<const unsigned char> publicKey,
                    const std::string& privatePath,
                    const std::string& publicPath,
                    bool force) {
    const std::string suffix = ".qprotect-stage-" + std::to_string(::getpid());
    const std::filesystem::path privateTemp = privatePath + suffix;
    const std::filesystem::path publicTemp = publicPath + suffix;
    const std::filesystem::path privateBackup = privatePath + suffix + ".backup";
    const std::filesystem::path publicBackup = publicPath + suffix + ".backup";
    bool privateSaved = false;
    bool publicSaved = false;
    bool privateCommitted = false;
    bool publicCommitted = false;
    try {
        qprotect::cpp::write_private_key_pem(context, privateKey, privateTemp.string(), false);
        qprotect::cpp::write_public_key_pem(context, publicKey, publicTemp.string(), false);
        if (force && std::filesystem::exists(privatePath)) {
            std::filesystem::rename(privatePath, privateBackup);
            privateSaved = true;
        }
        if (force && std::filesystem::exists(publicPath)) {
            std::filesystem::rename(publicPath, publicBackup);
            publicSaved = true;
        }
        if (force) {
            std::filesystem::rename(privateTemp, privatePath);
            privateCommitted = true;
            std::filesystem::rename(publicTemp, publicPath);
            publicCommitted = true;
        } else {
            if (::link(privateTemp.c_str(), privatePath.c_str()) != 0) {
                throw EnvelopeError("unable to commit private key output");
            }
            privateCommitted = true;
            if (::link(publicTemp.c_str(), publicPath.c_str()) != 0) {
                throw EnvelopeError("unable to commit public key output");
            }
            publicCommitted = true;
        }
        std::error_code cleanupError;
        std::filesystem::remove(privateTemp, cleanupError);
        std::filesystem::remove(publicTemp, cleanupError);
        if (privateSaved) std::filesystem::remove(privateBackup, cleanupError);
        if (publicSaved) std::filesystem::remove(publicBackup, cleanupError);
    } catch (...) {
        std::error_code error;
        if (privateCommitted) std::filesystem::remove(privatePath, error);
        if (publicCommitted) std::filesystem::remove(publicPath, error);
        if (privateSaved) std::filesystem::rename(privateBackup, privatePath, error);
        if (publicSaved) std::filesystem::rename(publicBackup, publicPath, error);
        std::filesystem::remove(privateTemp, error);
        std::filesystem::remove(publicTemp, error);
        throw;
    }
}

int run_keygen(const CryptoContext& context, const Arguments& args) {
    if (args.key_type != "kem" && args.key_type != "sign") {
        std::cerr << "error: --type must be kem or sign\n";
        return 2;
    }
    if (args.private_path.empty() || args.public_path.empty()) {
        std::cerr << "error: keygen requires --private and --public\n";
        return 2;
    }
    reject_same_path(args.private_path, args.public_path);
    if (!args.force &&
        (std::filesystem::exists(args.private_path) || std::filesystem::exists(args.public_path))) {
        throw EnvelopeError("key output exists (use --force)");
    }

    if (args.key_type == "kem") {
        const qprotect::cpp::KEMKeyPair key_pair =
            qprotect::cpp::generate_ml_kem_1024(context);
        write_key_pair(context, key_pair.private_key_der, key_pair.public_key_der,
                       args.private_path, args.public_path, args.force);
        std::cout << "generated ML-KEM-1024 keypair, key_id " << key_pair.key_id << "\n";
    } else {
        const qprotect::cpp::SignatureKeyPair key_pair =
            qprotect::cpp::generate_ml_dsa_87(context);
        write_key_pair(context, key_pair.private_key_der, key_pair.public_key_der,
                       args.private_path, args.public_path, args.force);
        std::cout << "generated ML-DSA-87 keypair, key_id " << key_pair.key_id << "\n";
    }
    return 0;
}

int run_encrypt(const CryptoContext& context, const Arguments& args) {
    if (args.input_path.empty() || args.output_path.empty() || args.recipients.empty()) {
        std::cerr << "error: encrypt requires --input, --output, and at least one --recipient\n";
        return 2;
    }
    reject_same_path(args.input_path, args.output_path);

    const SecureBytes plaintext = read_binary_file(args.input_path);

    qprotect::cpp::EncryptOptions options;
    options.context = args.context;
    for (const std::string& recipient : args.recipients) {
        options.recipient_public_key_der.push_back(
            qprotect::cpp::load_public_key_file(context, recipient));
    }
    if (!args.signer_private_path.empty()) {
        options.signer_private_key_der =
            qprotect::cpp::load_private_key_file(context, args.signer_private_path);
    }

    const Envelope envelope = qprotect::cpp::encrypt_envelope(
        context,
        std::span<const unsigned char>(plaintext.data(), plaintext.size()),
        options
    );
    const std::string json = envelope.to_json();
    write_binary_file(
        args.output_path,
        std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(json.data()),
            json.size()
        ),
        args.force
    );
    return 0;
}

int run_decrypt(const CryptoContext& context, const Arguments& args) {
    if (args.input_path.empty() || args.output_path.empty() ||
        args.recipient_private_path.empty()) {
        std::cerr << "error: decrypt requires --input, --output, and --recipient-private\n";
        return 2;
    }
    reject_same_path(args.input_path, args.output_path);

    const std::string json = read_text_file(args.input_path);
    const Envelope envelope = Envelope::from_json(json);

    qprotect::cpp::DecryptOptions options;
    options.recipient_private_key_der =
        qprotect::cpp::load_private_key_file(context, args.recipient_private_path);
    if (!args.signer_public_path.empty()) {
        options.signer_public_key_der =
            qprotect::cpp::load_public_key_file(context, args.signer_public_path);
    }

    const SecureBytes plaintext = qprotect::cpp::decrypt_envelope(
        context, envelope, options);
    write_binary_file(
        args.output_path,
        std::span<const unsigned char>(plaintext.data(), plaintext.size()),
        args.force
    );
    return 0;
}

int run_key_encrypt(const CryptoContext& context, const Arguments& args) {
    if (args.input_path.empty() || args.output_path.empty() || args.recipients.empty() ||
        args.signer_private_path.empty()) {
        std::cerr << "error: key-encrypt requires --input, --output, --recipient, and --signer\n";
        return 2;
    }
    reject_same_path(args.input_path, args.output_path);

    const SecureBytes private_key = qprotect::cpp::load_private_key_file(context, args.input_path);
    qprotect::cpp::EncryptOptions options;
    options.context = "private-key";
    for (const std::string& recipient : args.recipients) {
        options.recipient_public_key_der.push_back(
            qprotect::cpp::load_public_key_file(context, recipient));
    }
    options.signer_private_key_der = qprotect::cpp::load_private_key_file(
        context, args.signer_private_path);

    const Envelope envelope = qprotect::cpp::encrypt_envelope(context, private_key, options);
    const std::string json = envelope.to_json();
    write_binary_file(
        args.output_path,
        std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(json.data()), json.size()),
        args.force);
    return 0;
}

int run_key_decrypt(const CryptoContext& context, const Arguments& args) {
    if (args.input_path.empty() || args.output_path.empty() ||
        args.recipient_private_path.empty() || args.signer_public_path.empty()) {
        std::cerr << "error: key-decrypt requires --input, --output, --recipient-private, and --signer-public\n";
        return 2;
    }
    reject_same_path(args.input_path, args.output_path);

    const Envelope envelope = Envelope::from_json(read_text_file(args.input_path));
    if (envelope.context != "private-key") {
        throw EnvelopeError("envelope is not a protected private key");
    }
    qprotect::cpp::DecryptOptions options;
    options.recipient_private_key_der = qprotect::cpp::load_private_key_file(
        context, args.recipient_private_path);
    options.signer_public_key_der = qprotect::cpp::load_public_key_file(
        context, args.signer_public_path);
    options.require_signature = true;

    const SecureBytes private_key = qprotect::cpp::decrypt_envelope(context, envelope, options);
    qprotect::cpp::write_private_key_pem(context, private_key, args.output_path, args.force);
    return 0;
}

struct WipeString {
    std::string& value;
    ~WipeString() {
        if (!value.empty()) {
            OPENSSL_cleanse(value.data(), value.size());
        }
    }
};

int run_identity_encrypt(const CryptoContext& context, const Arguments& args) {
    if (args.input_path.empty() || args.output_path.empty() || args.recipients.empty()) {
        std::cerr << "error: identity-encrypt requires --input, --output, and at least one --recipient\n";
        return 2;
    }
    reject_same_path(args.input_path, args.output_path);
    const SecureBytes input = read_binary_file(args.input_path, 1024 * 1024);
    std::string input_text(reinterpret_cast<const char*>(input.data()), input.size());
    WipeString wipe_input{input_text};
    const qprotect::cpp::json::Value record = qprotect::cpp::detail::normalize_identity(
        qprotect::cpp::json::Value::parse(input_text));
    std::string payload = record.canonical();
    WipeString wipe_payload{payload};

    qprotect::cpp::EncryptOptions options;
    options.context = "identity";
    for (const std::string& recipient : args.recipients) {
        options.recipient_public_key_der.push_back(qprotect::cpp::load_public_key_file(context, recipient));
    }
    if (!args.signer_private_path.empty()) {
        options.signer_private_key_der = qprotect::cpp::load_private_key_file(
            context, args.signer_private_path);
    }
    const Envelope envelope = qprotect::cpp::encrypt_envelope(
        context,
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(payload.data()), payload.size()),
        options);
    const std::string json = envelope.to_json();
    write_binary_file(args.output_path,
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(json.data()), json.size()),
        args.force);
    return 0;
}

int run_identity_decrypt(const CryptoContext& context, const Arguments& args) {
    if (args.input_path.empty() || args.output_path.empty() || args.recipient_private_path.empty()) {
        std::cerr << "error: identity-decrypt requires --input, --output, and --recipient-private\n";
        return 2;
    }
    reject_same_path(args.input_path, args.output_path);
    const Envelope envelope = Envelope::from_json(read_text_file(args.input_path));
    qprotect::cpp::DecryptOptions options;
    options.recipient_private_key_der = qprotect::cpp::load_private_key_file(
        context, args.recipient_private_path);
    if (!args.signer_public_path.empty()) {
        options.signer_public_key_der = qprotect::cpp::load_public_key_file(
            context, args.signer_public_path);
    }
    const SecureBytes decrypted = qprotect::cpp::decrypt_envelope(context, envelope, options);
    std::string plaintext(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
    WipeString wipe_plaintext{plaintext};
    const qprotect::cpp::json::Value record = qprotect::cpp::detail::normalize_identity(
        qprotect::cpp::json::Value::parse(plaintext));
    const std::string rendered = record.pretty(2) + "\n";
    write_binary_file(args.output_path,
        std::span<const unsigned char>(reinterpret_cast<const unsigned char*>(rendered.data()), rendered.size()),
        args.force);
    return 0;
}

int run_disk(const Arguments& args) {
    if (args.disk_action != "plan" && args.disk_action != "format" &&
        args.disk_action != "open" && args.disk_action != "close") {
        std::cerr << "error: disk action must be plan, format, open, or close\n";
        return 2;
    }

    if (!args.disk_backup_file.empty() && args.disk_action != "plan") {
        throw EnvelopeError("--header-backup is a plan-only preview; no backup has been executed");
    }

    if ((args.disk_action == "open" || args.disk_action == "close") && args.disk_format_options) {
        throw EnvelopeError("format options are not accepted by open or close");
    }

    if (args.disk_action == "close" && (!args.disk_header_file.empty() || !args.disk_key_file.empty())) {
        throw EnvelopeError("close does not accept a header or key file");
    }

    if (args.disk_device.empty() || args.disk_mapper.empty()) {
        std::cerr << "error: disk requires --device and --mapper\n";
        return 2;
    }
    qprotect::cpp::DiskPlanOptions options;
    if (args.disk_action == "open") options.action = qprotect::cpp::DiskAction::Open;
    if (args.disk_action == "close") options.action = qprotect::cpp::DiskAction::Close;

    options.device = args.disk_device;
    options.mapper_name = args.disk_mapper;
    if (!args.disk_key_file.empty()) options.key_file = args.disk_key_file;
    if (!args.disk_header_file.empty()) options.header_file = args.disk_header_file;
    options.iter_time_ms = args.disk_iter_time;
    options.argon2_memory_kib = args.disk_argon_memory;
    options.argon2_parallelism = args.disk_argon_parallelism;
    options.sector_size = args.disk_sector_size;
    if (!args.disk_integrity.empty()) options.integrity = args.disk_integrity;
    const auto plan = qprotect::cpp::build_luks2_plan(options);
    if (args.disk_action == "format") {
        if (!args.disk_execute) throw EnvelopeError("format only runs when --execute is supplied");
        qprotect::cpp::execute_luks2_format(plan, args.disk_confirmation);
        return 0;
    }
    if (args.disk_action == "open") {
        if (!args.disk_execute) throw EnvelopeError("open only runs when --execute is supplied");
        qprotect::cpp::execute_luks2_open(plan);
        return 0;
    }
    if (args.disk_action == "close") {
        if (!args.disk_execute) throw EnvelopeError("close only runs when --execute is supplied");
        qprotect::cpp::execute_luks2_close(plan);
        return 0;
    }
    const auto commands = qprotect::cpp::disk_command_strings(
        plan, args.disk_backup_file.empty() ? std::nullopt : std::optional<std::string>(args.disk_backup_file));
    std::cout << "{\"commands_are_previews\":true,\"header_backup_scope\":\"new_header_after_format\","
              << "\"device\":\"" << json_escape(plan.device()) << "\",\"profile\":"
              << qprotect::cpp::disk_profile_json() << ",\"confirmation\":\""
              << plan.confirmation() << "\",\"commands\":[";
    for (std::size_t index = 0; index < commands.size(); ++index) {
        if (index != 0) std::cout << ',';
        std::cout << '"' << json_escape(commands[index]) << '"';
    }
    std::cout << "]}\n";
    return 0;
}

}

int main(int argc, char* argv[]) {
    if (argc == 1 || std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
        usage(std::cout);
        return 0;
    }
    if (std::string(argv[1]) == "--version") {
        std::cout << "qprotect " << qprotect::cpp::constants::module_version << "\n";
        return 0;
    }
    Arguments args;
    if (!parse_arguments(argc, argv, args)) {
        return 2;
    }

    try {
        const CryptoContext context(args.provider);
        if (args.command == "disk") return run_disk(args);
        if (args.command == "hardware") {
            if (args.hardware_action != "doctor") {
                std::cerr << "error: hardware action must be doctor\n";
                return 2;
            }
            std::cout << qprotect::cpp::hardware_report_text();
            return 0;
        }
        if (args.command == "doctor") {
            return run_diagnostics(context, false);
        }
        if (args.command == "selftest") {
            return run_diagnostics(context, true);
        }
        if (args.command == "keygen") {
            return run_keygen(context, args);
        }
        if (args.command == "encrypt") {
            return run_encrypt(context, args);
        }
        if (args.command == "decrypt") {
            return run_decrypt(context, args);
        }
        if (args.command == "key-encrypt") {
            return run_key_encrypt(context, args);
        }
        if (args.command == "key-decrypt") {
            return run_key_decrypt(context, args);
        }
        if (args.command == "identity-encrypt") {
            return run_identity_encrypt(context, args);
        }
        if (args.command == "identity-decrypt") {
            return run_identity_decrypt(context, args);
        }
        std::cerr << "unknown command: " << args.command << "\n";
        usage(std::cerr);
        return 2;
    } catch (const EnvelopeError& error) {
        std::cerr << "error: " << error.what() << "\n";
        return 1;
    } catch (const CryptoError& error) {
        std::cerr << "crypto error: " << error.what() << "\n";
        return 1;
    } catch (const std::exception& error) {
        std::cerr << "unexpected error: " << error.what() << "\n";
        return 1;
    }
}
