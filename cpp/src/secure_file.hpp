#pragma once

#include <span>
#include <string>

#include <sys/types.h>

namespace qprotect::cpp::detail {

void secure_write_file(
    const std::string& path,
    std::span<const unsigned char> data,
    mode_t mode,
    bool overwrite
);

}
