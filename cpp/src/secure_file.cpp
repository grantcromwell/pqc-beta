#include "secure_file.hpp"

#include "qprotect/error.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <filesystem>
#include <vector>

namespace qprotect::cpp::detail {
namespace {

void close_checked(int fd, const std::string& path) {
    if (::close(fd) != 0) {
        throw EnvelopeError("unable to close output file: " + path);
    }
}

void sync_directory(const std::filesystem::path& directory) {
    const int fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        throw EnvelopeError("unable to open output directory for sync");
    }
    if (::fsync(fd) != 0) {
        ::close(fd);
        throw EnvelopeError("unable to sync output directory");
    }
    close_checked(fd, directory.string());
}

}

void secure_write_file(
    const std::string& path,
    std::span<const unsigned char> data,
    mode_t mode,
    bool overwrite
) {
    const std::filesystem::path destination(path);
    const std::filesystem::path directory = destination.has_parent_path()
        ? destination.parent_path()
        : std::filesystem::path(".");
    std::filesystem::create_directories(directory);

    std::string pattern =
        (directory / ("." + destination.filename().string() + ".XXXXXX")).string();
    std::vector<char> mutable_pattern(pattern.begin(), pattern.end());
    mutable_pattern.push_back('\0');
    int fd = ::mkstemp(mutable_pattern.data());
    if (fd < 0) {
        throw EnvelopeError("unable to create temporary output file: " + path);
    }
    const std::string temporary(mutable_pattern.data());
    bool committed = false;
    try {
        if (::fchmod(fd, mode) != 0) {
            throw EnvelopeError("unable to set output permissions: " + path);
        }
        std::size_t offset = 0;
        while (offset < data.size()) {
            const ssize_t written = ::write(fd, data.data() + offset, data.size() - offset);
            if (written < 0 && errno == EINTR) {
                continue;
            }
            if (written <= 0) {
                throw EnvelopeError("unable to write output file: " + path);
            }
            offset += static_cast<std::size_t>(written);
        }
        if (::fsync(fd) != 0) {
            throw EnvelopeError("unable to sync output file: " + path);
        }
        close_checked(fd, path);
        fd = -1;

        const int result = overwrite
            ? ::rename(temporary.c_str(), destination.c_str())
            : ::link(temporary.c_str(), destination.c_str());
        if (result != 0) {
            if (!overwrite && errno == EEXIST) {
                throw EnvelopeError("output already exists (use --force): " + path);
            }
            throw EnvelopeError("unable to commit output file: " + path);
        }
        if (!overwrite && ::unlink(temporary.c_str()) != 0) {
            throw EnvelopeError("unable to remove temporary output link: " + path);
        }
        committed = true;
        sync_directory(directory);
    } catch (...) {
        if (fd >= 0) {
            ::close(fd);
        }
        if (!committed) {
            ::unlink(temporary.c_str());
        }
        throw;
    }
}

}
