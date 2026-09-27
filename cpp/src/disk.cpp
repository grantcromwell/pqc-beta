#include "qprotect/disk.hpp"

#include "json_minimal.hpp"
#include "disk_internal.hpp"
#include "qprotect/error.hpp"

#include <openssl/evp.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <cstdlib>
#include <array>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string_view>

namespace qprotect::cpp {
namespace {

struct DeviceIdentity {
    std::string canonical_path;
    unsigned int major;
    unsigned int minor;
};

struct ProcessResult {
    int exit_code;
    std::string output;
};

class FileDescriptor {
public:
    explicit FileDescriptor(int fd) : fd_(fd) {}
    ~FileDescriptor() { if (fd_ >= 0) ::close(fd_); }

    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;

    int get() const { return fd_; }
    int release() { const int fd = fd_; fd_ = -1; return fd; }

private:
    int fd_;
};

ProcessResult run_process(const std::vector<std::string>& arguments,
                          bool capture,
                          int timeout_seconds = 0,
                          int inherited_fd = -1) {
    if (arguments.empty()) {
        throw EnvelopeError("empty external command");
    }
    int pipe_fds[2] = {-1, -1};
    if (capture && ::pipe2(pipe_fds, O_CLOEXEC) != 0) {
        throw EnvelopeError("unable to create process output pipe");
    }
    const pid_t child = ::fork();
    if (child < 0) {
        if (capture) {
            ::close(pipe_fds[0]);
            ::close(pipe_fds[1]);
        }
        throw EnvelopeError("unable to start external command");
    }
    if (child == 0) {
        if (capture) {
            ::close(pipe_fds[0]);
            ::dup2(pipe_fds[1], STDOUT_FILENO);
            ::dup2(pipe_fds[1], STDERR_FILENO);
            ::close(pipe_fds[1]);
        }
        std::vector<char*> argv;
        argv.reserve(arguments.size() + 1);
        for (const std::string& argument : arguments) {
            argv.push_back(const_cast<char*>(argument.c_str()));
        }
        argv.push_back(nullptr);
        if (inherited_fd >= 0 && ::fcntl(inherited_fd, F_SETFD, 0) < 0) _exit(127);

        char locale[] = "LC_ALL=C";
        char language[] = "LANG=C";
        char path[] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
        char* environment[] = {locale, language, path, nullptr};

        ::execve(argv[0], argv.data(), environment);
        _exit(127);
    }

    std::string output;
    if (capture) {
        ::close(pipe_fds[1]);
        const int flags = ::fcntl(pipe_fds[0], F_GETFL, 0);
        if (flags >= 0) static_cast<void>(::fcntl(pipe_fds[0], F_SETFL, flags | O_NONBLOCK));
        const auto deadline = std::chrono::steady_clock::now() +
            std::chrono::seconds(timeout_seconds > 0 ? timeout_seconds : 30);
        bool exited = false;
        int status = 0;
        while (true) {
            struct pollfd descriptor { pipe_fds[0], POLLIN | POLLHUP, 0 };
            static_cast<void>(::poll(&descriptor, 1, 50));
            char buffer[4096];
            while (true) {
                const ssize_t count = ::read(pipe_fds[0], buffer, sizeof(buffer));
                if (count > 0) {
                    if (output.size() + static_cast<std::size_t>(count) > 1024 * 1024) {
                        ::kill(child, SIGKILL);
                        ::waitpid(child, &status, 0);
                        ::close(pipe_fds[0]);
                        throw EnvelopeError("external command output exceeds 1 MiB");
                    }
                    output.append(buffer, static_cast<std::size_t>(count));
                } else {
                    break;
                }
            }
            if (!exited) {
                const pid_t waited = ::waitpid(child, &status, WNOHANG);
                exited = waited == child;
            }
            if (exited) {
                break;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                ::kill(child, SIGKILL);
                ::waitpid(child, &status, 0);
                ::close(pipe_fds[0]);
                throw EnvelopeError("external command timed out");
            }
        }
        ::close(pipe_fds[0]);
        if (!WIFEXITED(status)) {
            return {128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0), std::move(output)};
        }
        return {WEXITSTATUS(status), std::move(output)};
    }

    int status = 0;
    while (::waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            throw EnvelopeError("unable to wait for external command");
        }
    }
    if (!WIFEXITED(status)) {
        return {128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0), {}};
    }
    return {WEXITSTATUS(status), {}};
}

DeviceIdentity validate_device(const std::string& path) {
    if (path.empty() || path.front() != '/') {
        throw EnvelopeError("device must be an absolute path");
    }
    std::error_code error;
    const std::filesystem::path canonical = std::filesystem::canonical(path, error);
    if (error || canonical.string().compare(0, 5, "/dev/") != 0) {
        throw EnvelopeError("resolved device must be accessible under /dev");
    }
    struct stat status {};
    if (::stat(canonical.c_str(), &status) != 0 || !S_ISBLK(status.st_mode)) {
        throw EnvelopeError("path is not an accessible block device");
    }
    if (::access(canonical.c_str(), W_OK) != 0) {
        throw EnvelopeError("block device is not writable by this user");
    }
    return {canonical.string(), static_cast<unsigned int>(major(status.st_rdev)),
            static_cast<unsigned int>(minor(status.st_rdev))};
}

void validate_key_file(const std::string& path) {
    const std::filesystem::path file(path);
    if (!file.is_absolute() || path.find('\0') != std::string::npos) {
        throw EnvelopeError("key file must be an absolute path");
    }
    std::error_code error;
    const auto link_status = std::filesystem::symlink_status(file, error);
    if (error || std::filesystem::is_symlink(link_status) || !std::filesystem::is_regular_file(link_status)) {
        throw EnvelopeError("key file must be a regular non-symbolic file");
    }
    struct stat status {};
    if (::stat(file.c_str(), &status) != 0 || status.st_size == 0) {
        throw EnvelopeError("key file is missing or empty");
    }
    if ((status.st_mode & 0077) != 0) {
        throw EnvelopeError("key file permissions must be 0600 or stricter");
    }
}

void validate_mapper(const std::string& name) {
    if (name.empty() || name.size() > 64 || name.front() == '-' || name == "." || name == "..") {
        throw EnvelopeError("mapper name must be 1..64 characters");
    }
    for (const unsigned char c : name) {
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) {
            throw EnvelopeError("mapper name may contain only letters, digits, '.', '-', and '_'");
        }
    }
}

void validate_options(const DiskPlanOptions& options) {
    validate_mapper(options.mapper_name);
    if (options.iter_time_ms < 1000 || options.iter_time_ms > 10000) {
        throw EnvelopeError("iter_time_ms must be between 1000 and 10000");
    }
    if (options.sector_size != 512 && options.sector_size != 1024 &&
        options.sector_size != 2048 && options.sector_size != 4096) {
        throw EnvelopeError("sector size must be 512, 1024, 2048, or 4096");
    }
    if (options.argon2_memory_kib &&
        (*options.argon2_memory_kib < 32 || *options.argon2_memory_kib > 4 * 1024 * 1024)) {
        throw EnvelopeError("Argon2 memory must be between 32 and 4194304 KiB");
    }
    if (options.argon2_parallelism &&
        (*options.argon2_parallelism < 1 || *options.argon2_parallelism > 4)) {
        throw EnvelopeError("Argon2 parallelism must be between 1 and 4");
    }
    if (options.integrity) {
        if (options.integrity->empty() || options.integrity->size() > 64) {
            throw EnvelopeError("integrity must be a supported algorithm name");
        }
        for (const unsigned char c : *options.integrity) {
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == ':' || c == '+' || c == '_' || c == '.' || c == '-')) {
                throw EnvelopeError("integrity must be a supported algorithm name");
            }
        }
    }
    if (options.key_file) {
        validate_key_file(*options.key_file);
    }
}

}

std::string detail::trusted_disk_executable(const std::string& name) {
    if (name != "cryptsetup" && name != "lsblk") {
        throw EnvelopeError("unsupported disk utility");
    }

    for (const char* directory : {"/usr/sbin", "/usr/bin", "/sbin", "/bin"}) {
        std::error_code error;
        const auto executable = std::filesystem::canonical(std::filesystem::path(directory) / name, error);
        if (error) continue;

        struct stat status {};
        if (::stat(executable.c_str(), &status) != 0 || !S_ISREG(status.st_mode) ||
            ::access(executable.c_str(), X_OK) != 0) continue;

        bool trusted = true;
        for (auto path = executable; !path.empty(); path = path.parent_path()) {
            if (::stat(path.c_str(), &status) != 0 || status.st_uid != 0 || (status.st_mode & 0022) != 0) {
                trusted = false;
                break;
            }
            if (path == path.root_path()) break;
        }

        if (trusted) return executable.string();
    }

    throw EnvelopeError("trusted system executable unavailable: " + name);
}

namespace {

std::string file_identity(const struct stat& status) {
    return std::to_string(status.st_dev) + ":" + std::to_string(status.st_ino);
}

int open_header_directory(const std::string& value) {
    const std::filesystem::path path(value);
    if (value.find('\0') != std::string::npos || !path.is_absolute() ||
        path.filename().empty() || path.filename() == "." || path.filename() == "..") {
        throw EnvelopeError("header path must be an absolute file path");
    }

    std::error_code error;
    const auto parent = std::filesystem::canonical(path.parent_path(), error);
    if (error || parent != path.parent_path()) {
        throw EnvelopeError("header directory must be canonical and accessible");
    }

    FileDescriptor directory(::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    struct stat status {};
    if (directory.get() < 0 || ::fstat(directory.get(), &status) != 0 ||
        status.st_uid != ::geteuid() || (status.st_mode & 0022) != 0) {
        throw EnvelopeError("header directory must be owned by this user and not writable by others");
    }

    return directory.release();
}

std::string inspect_header(int directory, const std::string& name, bool creating) {
    struct stat parent {};
    if (::fstat(directory, &parent) != 0) throw EnvelopeError("unable to inspect header directory");

    struct stat status {};
    const int result = ::fstatat(directory, name.c_str(), &status, AT_SYMLINK_NOFOLLOW);

    if (creating) {
        if (result == 0 || errno != ENOENT) {
            throw EnvelopeError("format requires a new detached header file");
        }
        return file_identity(parent);
    }

    if (result != 0 || !S_ISREG(status.st_mode) || status.st_uid != ::geteuid() ||
        (status.st_mode & 0077) != 0 || status.st_nlink != 1 || status.st_size == 0) {
        throw EnvelopeError("header must be a nonempty private regular file owned by this user");
    }

    return file_identity(parent) + "/" + file_identity(status);
}

}

std::string detail::header_identity(const std::string& path, bool creating) {
    FileDescriptor directory(open_header_directory(path));
    return inspect_header(directory.get(), std::filesystem::path(path).filename().string(), creating);
}

int detail::open_validated_header(const std::string& path, bool creating, const std::string& identity) {
    FileDescriptor directory(open_header_directory(path));
    const auto name = std::filesystem::path(path).filename().string();

    if (inspect_header(directory.get(), name, creating) != identity) {
        throw EnvelopeError("detached header identity changed after planning");
    }

    const int flags = O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | (creating ? O_RDWR | O_CREAT | O_EXCL : O_RDONLY);
    FileDescriptor header(::openat(directory.get(), name.c_str(), flags, 0600));
    if (header.get() < 0) throw EnvelopeError("unable to open validated detached header");

    struct stat status {};
    struct stat parent {};
    if (::fstat(header.get(), &status) != 0 || ::fstat(directory.get(), &parent) != 0 ||
        !S_ISREG(status.st_mode) || status.st_uid != ::geteuid() || (status.st_mode & 0077) != 0 ||
        status.st_nlink != 1 || (!creating && file_identity(parent) + "/" + file_identity(status) != identity)) {
        throw EnvelopeError("detached header changed while opening");
    }

    if (creating && ::ftruncate(header.get(), 32 * 1024 * 1024) != 0) {
        throw EnvelopeError("unable to allocate detached header");
    }

    return header.release();
}

void detail::validate_mapping_device(const std::filesystem::path& root,
                                    unsigned int mapping_major, unsigned int mapping_minor,
                                    unsigned int device_major, unsigned int device_minor) {
    std::string current = std::to_string(mapping_major) + ":" + std::to_string(mapping_minor);
    const std::string expected = std::to_string(device_major) + ":" + std::to_string(device_minor);

    std::ifstream uuid_file(root / current / "dm" / "uuid");
    std::string uuid;
    if (!std::getline(uuid_file, uuid) || !uuid.starts_with("CRYPT-LUKS2-")) {
        throw EnvelopeError("mapping is not a LUKS2 device");
    }

    for (int depth = 0; depth < 16; ++depth) {
        std::error_code error;
        std::filesystem::directory_iterator entry(root / current / "slaves", error), end;
        if (error || entry == end) throw EnvelopeError("unable to verify mapping backing device");

        std::ifstream device_file(entry->path() / "dev");
        std::string device;
        if (!std::getline(device_file, device) || device.find_first_not_of("0123456789:") != std::string::npos ||
            device.find(':') == std::string::npos) {
            throw EnvelopeError("invalid mapping backing device");
        }

        entry.increment(error);
        if (error || entry != end) throw EnvelopeError("mapping must have exactly one backing device");
        if (device == expected) return;

        current = device;
    }

    throw EnvelopeError("mapping does not resolve to the planned device");
}

void validate_luks2_plan_internal(const Luks2Plan& plan) {
    if (!plan.validated_) {
        throw EnvelopeError("operation requires a validated plan from build_luks2_plan");
    }
    const DeviceIdentity current = validate_device(plan.device_);
    if (current.canonical_path != plan.device_ || current.major != plan.major_ || current.minor != plan.minor_) {
        throw EnvelopeError("block-device identity changed after planning");
    }
    if (plan.options_.key_file) {
        validate_key_file(*plan.options_.key_file);
    }

    if (plan.options_.header_file &&
        detail::header_identity(*plan.options_.header_file, plan.options_.action == DiskAction::Format) !=
            plan.header_identity_) {
        throw EnvelopeError("detached header identity changed after planning");
    }
}

void detail::validate_lsblk_safety_json(const std::string& report,
                                       const std::string& expected_device,
                                       unsigned int expected_major,
                                       unsigned int expected_minor) {
    json::Value parsed;
    try {
        parsed = json::Value::parse(report);
    } catch (const std::exception&) {
        throw EnvelopeError("unable to parse block-device safety information");
    }
    const auto& root = parsed.expect_object("lsblk report");
    const auto block_devices = root.find("blockdevices");
    if (block_devices == root.end() || !block_devices->second.is_array() ||
        block_devices->second.as_array().size() != 1) {
        throw EnvelopeError("safety report must contain exactly one target device");
    }
    const auto& object = block_devices->second.as_array().front().expect_object("lsblk device");
    const auto require_string = [&](const char* name) -> const std::string& {
        const auto field = object.find(name);
        if (field == object.end() || !field->second.is_string() || field->second.as_string().empty()) {
            throw EnvelopeError(std::string("missing or invalid safety field: ") + name);
        }
        return field->second.as_string();
    };
    if (require_string("path") != expected_device ||
        require_string("maj:min") != std::to_string(expected_major) + ":" + std::to_string(expected_minor)) {
        throw EnvelopeError("safety report does not match the planned block device");
    }
    require_string("type");
    const auto mounts = object.find("mountpoints");
    if (mounts == object.end() || !mounts->second.is_array()) {
        throw EnvelopeError("missing or invalid mount state in safety report");
    }
    for (const auto& mount : mounts->second.as_array()) {
        if (!mount.is_null() && !mount.is_string()) {
            throw EnvelopeError("invalid mount entry in safety report");
        }
        if (mount.is_string() && !mount.as_string().empty()) {
            throw EnvelopeError("refusing to format a mounted device");
        }
    }
    const auto children = object.find("children");
    if (children != object.end()) {
        if (!children->second.is_array()) {
            throw EnvelopeError("invalid child-device state in safety report");
        }
        if (!children->second.as_array().empty()) {
            throw EnvelopeError("refusing to format a device with child devices");
        }
    }
}

void validate_format_target_unused_internal(const Luks2Plan& plan) {
    const ProcessResult probe = run_process(
        {detail::trusted_disk_executable("lsblk"), "--json", "--tree", "--paths", "--output",
         "PATH,TYPE,MAJ:MIN,MOUNTPOINTS", plan.device()}, true, 10);
    if (probe.exit_code != 0) {
        throw EnvelopeError("unable to verify block-device mount and holder state");
    }
    detail::validate_lsblk_safety_json(probe.output, plan.device_, plan.major_, plan.minor_);

    const std::filesystem::path holders = std::filesystem::path("/sys/dev/block") /
        (std::to_string(plan.major_) + ":" + std::to_string(plan.minor_)) / "holders";
    std::error_code error;
    const bool holders_directory = std::filesystem::is_directory(holders, error);
    if (error || !holders_directory) throw EnvelopeError("unable to inspect block-device holders");
    if (holders_directory) {
        for (std::filesystem::directory_iterator item(holders, error), end; !error && item != end; item.increment(error)) {
            throw EnvelopeError("refusing to format a block device with active holders");
        }
        if (error) {
            throw EnvelopeError("unable to inspect block-device holders");
        }
    }
    if (std::filesystem::exists(std::filesystem::path("/dev/mapper") / plan.options().mapper_name)) {
        throw EnvelopeError("requested mapper name is already active");
    }
}

namespace {

void execute(const std::vector<std::string>& arguments, int inherited_fd = -1) {
    const ProcessResult result = run_process(arguments, false, 0, inherited_fd);
    if (result.exit_code != 0) {
        throw EnvelopeError(arguments.front() + " failed with exit code " + std::to_string(result.exit_code));
    }
}

void execute_with_header(std::vector<std::string> arguments, const DiskPlanOptions& options,
                         const std::string& identity) {
    if (!options.header_file) {
        execute(arguments);
        return;
    }

    FileDescriptor header(detail::open_validated_header(*options.header_file,
                          options.action == DiskAction::Format, identity));
    const auto option = std::find(arguments.begin(), arguments.end(), "--header");
    if (option == arguments.end() || std::next(option) == arguments.end()) {
        throw EnvelopeError("missing detached header argument");
    }

    *std::next(option) = "/proc/self/fd/" + std::to_string(header.get());
    execute(arguments, header.get());
}

}

std::vector<std::string> format_luks2_arguments(const DiskPlanOptions& options) {
    validate_options(options);
    std::vector<std::string> arguments{
        "cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", "--cipher", "aes-xts-plain64",
        "--key-size", "512", "--hash", "sha512", "--pbkdf", "argon2id", "--iter-time",
        std::to_string(options.iter_time_ms), "--sector-size", std::to_string(options.sector_size), "--use-random",
    };

    if (!options.key_file) arguments.push_back("--verify-passphrase");

    if (options.argon2_memory_kib) {
        arguments.insert(arguments.end(), {"--pbkdf-memory", std::to_string(*options.argon2_memory_kib)});
    }
    if (options.argon2_parallelism) {
        arguments.insert(arguments.end(), {"--pbkdf-parallel", std::to_string(*options.argon2_parallelism)});
    }
    if (options.header_file) {
        arguments.insert(arguments.end(), {"--header", *options.header_file});
    }
    if (options.integrity) {
        arguments.insert(arguments.end(), {"--integrity", *options.integrity});
    }
    arguments.push_back("--");
    arguments.push_back(options.device);
    if (options.key_file) {
        arguments.push_back(*options.key_file);
    }
    return arguments;
}

std::string format_confirmation(const std::vector<std::string>& args,
                                const std::string& device_basename,
                                unsigned int major_number,
                                unsigned int minor_number) {
    std::string material;
    for (const std::string& argument : args) {
        if (!material.empty()) {
            material.push_back('\0');
        }
        material += argument;
    }
    material.push_back('\0');
    material += std::to_string(major_number);
    material.push_back('\0');
    material += std::to_string(minor_number);
    EVP_MD_CTX* raw_context = EVP_MD_CTX_new();
    if (raw_context == nullptr) {
        throw EnvelopeError("unable to allocate plan digest context");
    }
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_length = 0;
    const bool success = EVP_DigestInit_ex(raw_context, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(raw_context, material.data(), material.size()) == 1 &&
        EVP_DigestFinal_ex(raw_context, digest.data(), &digest_length) == 1;
    EVP_MD_CTX_free(raw_context);
    if (!success || digest_length != 32) {
        throw EnvelopeError("unable to calculate plan confirmation");
    }
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string short_digest;
    for (std::size_t index = 0; index < 8; ++index) {
        short_digest.push_back(hex[digest[index] >> 4]);
        short_digest.push_back(hex[digest[index] & 0x0f]);
    }
    return "FORMAT-" + device_basename + "-" + short_digest;
}

std::string shell_quote(const std::string& value) {
    if (value.empty()) {
        return "''";
    }
    std::string quoted = "'";
    for (const char c : value) {
        if (c == '\'') {
            quoted += "'\\''";
        } else {
            quoted.push_back(c);
        }
    }
    quoted.push_back('\'');
    return quoted;
}

Luks2Plan build_luks2_plan(const DiskPlanOptions& options) {
    const auto cryptsetup = detail::trusted_disk_executable("cryptsetup");
    validate_options(options);
    const DeviceIdentity device = validate_device(options.device);

    Luks2Plan plan;
    plan.options_ = options;
    plan.options_.device = device.canonical_path;
    plan.device_ = device.canonical_path;
    plan.major_ = device.major;
    plan.minor_ = device.minor;
    if (options.action != DiskAction::Format && options.action != DiskAction::Open &&
        options.action != DiskAction::Close) {
        throw EnvelopeError("invalid disk action");
    }

    if (options.header_file) {
        if (options.action == DiskAction::Close) throw EnvelopeError("close does not accept a header file");

        plan.header_identity_ = detail::header_identity(*options.header_file, options.action == DiskAction::Format);
    }

    plan.format_args_ = format_luks2_arguments(plan.options_);
    plan.format_args_.front() = cryptsetup;

    plan.open_args_ = {cryptsetup, "open", "--type", "luks2", "--batch-mode"};
    if (plan.options_.header_file) {
        plan.open_args_.insert(plan.open_args_.end(), {"--header", *plan.options_.header_file});
    }
    if (plan.options_.key_file) {
        plan.open_args_.insert(plan.open_args_.end(), {"--key-file", *plan.options_.key_file});
    }
    plan.open_args_.insert(plan.open_args_.end(), {"--", plan.device_, plan.options_.mapper_name});
    plan.close_args_ = {cryptsetup, "close", "--", plan.options_.mapper_name};

    auto confirmation_material = plan.format_args_;
    if (options.header_file) confirmation_material.push_back(plan.header_identity_);

    plan.confirmation_ = format_confirmation(confirmation_material,
        std::filesystem::path(plan.device_).filename().string(), device.major, device.minor);
    plan.validated_ = true;
    return plan;
}

std::vector<std::string> Luks2Plan::backup_header_args(const std::string& path) const {
    if (!validated_) throw EnvelopeError("backup preview requires a validated plan");
    detail::header_identity(path, true);
    if (options_.header_file && std::filesystem::path(path) == std::filesystem::path(*options_.header_file)) {
        throw EnvelopeError("backup and detached header paths must differ");
    }

    std::vector<std::string> arguments{format_args_.front(), "luksHeaderBackup", device_};
    if (options_.header_file) {
        arguments.insert(arguments.end(), {"--header", *options_.header_file});
    }
    arguments.insert(arguments.end(), {"--header-backup-file", path});
    return arguments;
}

std::vector<std::string> disk_command_strings(
    const Luks2Plan& plan,
    const std::optional<std::string>& backup_path) {
    std::vector<std::string> commands;
    const auto render = [](const std::vector<std::string>& arguments) {
        std::string output;
        for (const std::string& item : arguments) {
            if (!output.empty()) output.push_back(' ');
            output += shell_quote(item);
        }
        return output;
    };
    commands.push_back(render(plan.format_args()));
    commands.push_back(render(plan.open_args()));
    commands.push_back(render(plan.close_args()));
    if (backup_path) {
        commands.push_back(render(plan.backup_header_args(*backup_path)));
    }
    return commands;
}

std::string disk_profile_json() {
    return R"({"cipher":"aes-xts-plain64","key_bits":512,"keyslot_hash":"SHA-512","pbkdf":"argon2id","rng":"Linux /dev/random-backed cryptsetup key generation","type":"LUKS2"})";
}

void execute_luks2_format(const Luks2Plan& plan, const std::string& confirmation) {
    if (plan.options_.action != DiskAction::Format) throw EnvelopeError("format requires a format plan");

    validate_luks2_plan_internal(plan);
    if (confirmation != plan.confirmation_) {
        throw EnvelopeError("destructive operation refused; pass the exact confirmation from the reviewed plan");
    }
    validate_format_target_unused_internal(plan);
    execute_with_header(plan.format_args_, plan.options_, plan.header_identity_);
}

void execute_luks2_open(const Luks2Plan& plan) {
    if (plan.options_.action != DiskAction::Open) throw EnvelopeError("open requires an open plan");

    validate_luks2_plan_internal(plan);
    if (std::filesystem::exists(std::filesystem::path("/dev/mapper") / plan.options_.mapper_name)) {
        throw EnvelopeError("requested mapper name is already active");
    }
    execute_with_header(plan.open_args_, plan.options_, plan.header_identity_);
}

void execute_luks2_close(const Luks2Plan& plan) {
    if (plan.options_.action != DiskAction::Close) throw EnvelopeError("close requires a close plan");

    validate_luks2_plan_internal(plan);
    const auto mapping_path = (std::filesystem::path("/dev/mapper") / plan.options_.mapper_name).string();
    const auto mapping = validate_device(mapping_path);

    detail::validate_mapping_device("/sys/dev/block", mapping.major, mapping.minor, plan.major_, plan.minor_);

    const auto current = validate_device(mapping_path);
    if (current.canonical_path != mapping.canonical_path || current.major != mapping.major ||
        current.minor != mapping.minor) throw EnvelopeError("mapping changed before close");

    auto arguments = plan.close_args_;
    arguments.back() = mapping.canonical_path;
    execute(arguments);
}

}
