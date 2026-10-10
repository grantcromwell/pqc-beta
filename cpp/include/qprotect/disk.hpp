#pragma once

#include <optional>
#include <string>
#include <vector>
#include "qprotect/secure_bytes.hpp"

namespace qprotect::cpp {

enum class DiskAction { Format, Open, Close };

struct DiskPlanOptions {
    DiskAction action = DiskAction::Format;

    std::string device;
    std::string mapper_name;
    std::optional<std::string> key_file;
    std::optional<std::string> header_file;
    int iter_time_ms = 5000;
    std::optional<int> argon2_memory_kib;
    std::optional<int> argon2_parallelism;
    int sector_size = 4096;
    std::optional<std::string> integrity;
};

class Luks2Plan {
public:
    const DiskPlanOptions& options() const noexcept { return options_; }
    const std::string& device() const noexcept { return device_; }
    const std::vector<std::string>& format_args() const noexcept { return format_args_; }
    const std::vector<std::string>& open_args() const noexcept { return open_args_; }
    const std::vector<std::string>& close_args() const noexcept { return close_args_; }
    std::vector<std::string> backup_header_args(const std::string& path) const;
    const std::string& confirmation() const noexcept { return confirmation_; }

private:
    friend Luks2Plan build_luks2_plan(const DiskPlanOptions&);
    friend void execute_luks2_format(const Luks2Plan&, const std::string&);
    friend void execute_luks2_open(const Luks2Plan&);
    friend void execute_luks2_close(const Luks2Plan&);
    friend void validate_luks2_plan_internal(const Luks2Plan&);
    friend void validate_format_target_unused_internal(const Luks2Plan&);

    DiskPlanOptions options_;
    std::string device_;
    unsigned int major_ = 0;
    unsigned int minor_ = 0;
    std::vector<std::string> format_args_;
    std::vector<std::string> open_args_;
    std::vector<std::string> close_args_;
    std::string confirmation_;
    std::string header_identity_;
    SecureBytes key_material_;

    bool validated_ = false;
};

Luks2Plan build_luks2_plan(const DiskPlanOptions& options);
std::vector<std::string> format_luks2_arguments(const DiskPlanOptions& options);
std::string format_confirmation(const std::vector<std::string>& args,
                                const std::string& device_basename,
                                unsigned int major,
                                unsigned int minor);
std::vector<std::string> disk_command_strings(const Luks2Plan& plan,
                                              const std::optional<std::string>& backup_path = std::nullopt);
std::string shell_quote(const std::string& value);
std::string disk_profile_json();

void execute_luks2_format(const Luks2Plan& plan, const std::string& confirmation);
void execute_luks2_open(const Luks2Plan& plan);
void execute_luks2_close(const Luks2Plan& plan);

}
