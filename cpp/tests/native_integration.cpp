#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

namespace {

int run(const std::vector<std::string>& arguments, const std::string& output_path = {}) {
    const pid_t child = ::fork();
    if (child < 0) return -1;
    if (child == 0) {
        if (!output_path.empty()) {
            const int output = ::open(output_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
            if (output < 0) _exit(127);
            if (::dup2(output, STDOUT_FILENO) < 0 || ::dup2(output, STDERR_FILENO) < 0) _exit(127);
            ::close(output);
        }
        std::vector<char*> argv;
        argv.reserve(arguments.size() + 1);
        for (const std::string& item : arguments) argv.push_back(const_cast<char*>(item.c_str()));
        argv.push_back(nullptr);
        ::execv(argv[0], argv.data());
        _exit(127);
    }
    int status = 0;
    while (::waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128;
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

bool check(bool passed, const char* name) {
    std::cout << (passed ? "PASS " : "FAIL ") << name << '\n';
    return passed;
}

}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: qprotect_native_integration /path/to/qprotect\n";
        return 2;
    }
    char temporary[] = "./qprotect-native-integration-XXXXXX";
    char* directory = ::mkdtemp(temporary);
    if (directory == nullptr) return 1;
    const std::filesystem::path root(directory);
    const auto path = [&root](const char* name) { return root / name; };
    bool passed = true;
    const std::string tool = std::filesystem::absolute(argv[1]).string();
    passed &= check(run({tool, "--version"}) == 0, "native version command");
    passed &= check(run({tool, "doctor"}) == 0, "native doctor command");
    passed &= check(run({tool, "selftest"}) == 0, "native selftest command");
    for (const std::string command : {"disk", "hardware"}) {
        const std::string action = command == "disk" ? "plan" : "doctor";
        const auto output = path("startup-failure.log");
        passed &= check(run({tool, command, action, "--provider", "base"}, output.string()) != 0 &&
                        read_file(output).find("required algorithm self-test failed") != std::string::npos,
                        "startup failure blocks command dispatch");
    }
    passed &= check(run({tool, "hardware", "doctor"}) == 0, "read-only hardware inventory command");

    passed &= check(run({tool, "keygen", "--type", "kem", "--private", path("recipient.pem").string(),
                         "--public", path("recipient.pub").string()}) == 0,
                    "native KEM key generation");
    passed &= check(run({tool, "keygen", "--type", "kem", "--private", path("other.pem").string(),
                         "--public", path("other.pub").string()}) == 0,
                    "second recipient key generation");
    passed &= check(run({tool, "keygen", "--type", "kem", "--private", path("wrong.pem").string(),
                         "--public", path("wrong.pub").string()}) == 0,
                    "unrelated recipient key generation");
    passed &= check(run({tool, "keygen", "--type", "sign", "--private", path("signer.pem").string(),
                         "--public", path("signer.pub").string()}) == 0,
                    "native signing key generation");

    passed &= check(run({tool, "key-encrypt", "--input", path("recipient.pem").string(),
                         "--output", path("recipient.qpe").string(), "--recipient",
                         path("other.pub").string(), "--signer", path("signer.pem").string()}) == 0 &&
                    read_file(path("recipient.qpe")).find("BEGIN PRIVATE KEY") == std::string::npos,
                    "private key encryption with KEM and signature");
    passed &= check(run({tool, "key-decrypt", "--input", path("recipient.qpe").string(),
                         "--output", path("recovered-key.pem").string(), "--recipient-private",
                         path("other.pem").string(), "--signer-public", path("signer.pub").string()}) == 0 &&
                    read_file(path("recovered-key.pem")).find("BEGIN PRIVATE KEY") != std::string::npos,
                    "signed private key decryption");
    passed &= check(run({tool, "encrypt", "--input", path("recipient.pem").string(), "--output",
                         path("unsigned-key.qpe").string(), "--recipient", path("other.pub").string(),
                         "--context", "private-key"}) == 0 &&
                    run({tool, "key-decrypt", "--input", path("unsigned-key.qpe").string(),
                         "--output", path("unsigned-recovered.pem").string(), "--recipient-private",
                         path("other.pem").string(), "--signer-public", path("signer.pub").string()}) != 0 &&
                    !std::filesystem::exists(path("unsigned-recovered.pem")),
                    "unsigned private key envelope rejected");

    const std::string message = "qprotect C++20 integration payload\n";
    { std::ofstream stream(path("plain.bin"), std::ios::binary); stream << message; }
    passed &= check(run({tool, "encrypt", "--input", path("plain.bin").string(), "--output",
                         path("payload.qpe").string(), "--recipient", path("recipient.pub").string(),
                         "--recipient", path("other.pub").string(), "--signer", path("signer.pem").string(),
                         "--context", "native-integration"}) == 0,
                    "signed multi-recipient encryption");
    passed &= check(run({tool, "decrypt", "--input", path("payload.qpe").string(), "--output",
                         path("recovered.bin").string(), "--recipient-private", path("recipient.pem").string(),
                         "--signer-public", path("signer.pub").string()}) == 0 &&
                    read_file(path("recovered.bin")) == message,
                    "signed envelope decrypt and payload comparison");
    passed &= check(run({tool, "decrypt", "--input", path("payload.qpe").string(), "--output",
                         path("wrong.bin").string(), "--recipient-private", path("wrong.pem").string(),
                         "--signer-public", path("signer.pub").string()}) != 0 && !std::filesystem::exists(path("wrong.bin")),
                    "wrong recipient rejected without plaintext output");

    const std::string identity = R"({"ip":"192.0.2.10","serial":"SN-7","gps":{"latitude":12.5,"longitude":-7.25}})";
    { std::ofstream stream(path("identity.json")); stream << identity; }
    passed &= check(run({tool, "identity-encrypt", "--input", path("identity.json").string(), "--output",
                         path("identity.qpe").string(), "--recipient", path("recipient.pub").string()}) == 0,
                    "identity encryption");
    passed &= check(run({tool, "identity-decrypt", "--input", path("identity.qpe").string(), "--output",
                         path("identity.out.json").string(), "--recipient-private", path("recipient.pem").string()}) == 0 &&
                    read_file(path("identity.out.json")).find("\"hardware_serial\": \"SN-7\"") != std::string::npos,
                    "identity normalization after authenticated decryption");

    struct stat status {};
    passed &= check(::stat(path("recipient.pem").c_str(), &status) == 0 && (status.st_mode & 0077) == 0,
                    "private key file permissions");
    passed &= check(run({tool, "disk", "plan", "--device", "/dev/null", "--mapper", "integration-test"}) != 0,
                    "disk planner rejects a non-block device");

    for (const std::string value : {"invalid", "4096junk", "", "999999999999999999999999", "0", "-1"}) {
        const auto output = path("disk-arguments.log");
        passed &= check(run({tool, "disk", "plan", "--sector-size", value}, output.string()) == 2 &&
                        read_file(output).find("invalid value for --sector-size") != std::string::npos,
                        "disk numeric input is rejected without aborting");
    }

    for (const std::string option : {"--pbkdf-parallel", "--pbkdf-memory"}) {
        passed &= check(run({tool, "disk", "plan", option, "0"}, path("disk-arguments.log").string()) == 2,
                        "explicit zero does not select a PBKDF default");
    }

    for (const std::string action : {"format", "open", "close"}) {
        const auto output = path("disk-backup.log");
        passed &= check(run({tool, "disk", action, "--header-backup", path("backup").string()},
                            output.string()) != 0 && read_file(output).find("plan-only preview") != std::string::npos,
                        "disk execution rejects the preview-only backup option");
    }

    std::error_code cleanup_error;
    std::filesystem::remove_all(root, cleanup_error);
    return passed && !cleanup_error ? 0 : 1;
}
