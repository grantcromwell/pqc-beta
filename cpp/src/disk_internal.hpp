#pragma once

#include <string>
#include <filesystem>

namespace qprotect::cpp::detail {

std::string trusted_disk_executable(const std::string& name);

std::string header_identity(const std::string& path, bool creating);
int open_validated_header(const std::string& path, bool creating, const std::string& identity);

void validate_mapping_device(const std::filesystem::path& sysfs_root,
                             unsigned int mapping_major, unsigned int mapping_minor,
                             unsigned int device_major, unsigned int device_minor);

void validate_lsblk_safety_json(const std::string& report,
                                const std::string& expected_device,
                                unsigned int expected_major,
                                unsigned int expected_minor);

}
