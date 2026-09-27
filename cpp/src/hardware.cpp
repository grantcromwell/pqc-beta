#include "qprotect/hardware.hpp"
#include "hardware_internal.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string_view>
#include <vector>

namespace qprotect::cpp {
namespace {

struct Capability {
    std::string domain;
    std::string name;
    std::string state;
    std::string source;
    std::string evidence;
};

std::string escape_field(std::string_view value) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string escaped;
    for (const unsigned char ch : value) {
        if (ch == '%' || ch == '\t' || ch == '\n' || ch == '\r' || ch < 0x20) {
            escaped.push_back('%');
            escaped.push_back(digits[ch >> 4]);
            escaped.push_back(digits[ch & 0x0f]);
        } else {
            escaped.push_back(static_cast<char>(ch));
        }
    }
    return escaped;
}

std::string read_text(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) return {};
    std::string value;
    std::getline(input, value);
    return value;
}

std::string link_target(const std::filesystem::path& path) {
    std::error_code error;
    const auto target = std::filesystem::canonical(path, error);
    return error ? std::string{} : target.string();
}

#if defined(__linux__)

void discover_boot(std::vector<Capability>& output, const std::filesystem::path& efi_root) {
    std::error_code error;
    if (!std::filesystem::is_directory(efi_root, error)) {
        output.push_back({"boot", "uefi", "unavailable", efi_root.string(),
                          "UEFI sysfs interface is not present"});
        output.push_back({"boot", "secure_boot", "unknown", efi_root.string(),
                          "Secure Boot state cannot be read without UEFI variables"});
        return;
    }
    output.push_back({"boot", "uefi", "available", efi_root.string(),
                      "UEFI sysfs interface is present"});

    const std::filesystem::path variables = efi_root / "efivars";
    std::string secure_boot;
    std::string setup_mode;
    for (std::filesystem::directory_iterator item(variables, error), end;
         !error && item != end; item.increment(error)) {
        const std::string name = item->path().filename().string();
        const auto read_variable = [&item]() -> std::string {
            std::ifstream input(item->path(), std::ios::binary);
            if (!input) return {};
            std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(input)), {});
            if (bytes.size() < 5) return {};
            return bytes[4] == 0 ? "0" : "1";
        };
        if (name.starts_with("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")) {
            secure_boot = read_variable();
        } else if (name.starts_with("SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c")) {
            setup_mode = read_variable();
        }
    }
    if (!secure_boot.empty() && !setup_mode.empty()) {
        const std::string state = secure_boot == "1" && setup_mode == "0" ? "enabled" : "disabled";
        const std::string reason = setup_mode == "1" ? "firmware is in Setup Mode" :
            (secure_boot == "1" ? "EFI SecureBoot variable is enabled" : "EFI SecureBoot variable is disabled");
        output.push_back({"boot", "secure_boot", state, variables.string(), reason});
    } else {
        output.push_back({"boot", "secure_boot", "unknown", variables.string(),
                          error ? "UEFI variable access failed" : "required EFI variables are unavailable"});
    }
}

void discover_devices(std::vector<Capability>& output, const detail::HardwarePaths& paths) {
    const auto& pci_root = paths.pci_root;
    std::error_code error;
    std::size_t pci_count = 0;
    std::size_t network_count = 0;
    std::vector<std::string> pci_entries;
    std::vector<std::string> network_pci_entries;
    for (std::filesystem::directory_iterator item(pci_root, error), end;
         !error && item != end; item.increment(error)) {
        const std::string id = item->path().filename().string();
        const std::string class_code = read_text(item->path() / "class");
        const std::string vendor = read_text(item->path() / "vendor");
        const std::string device = read_text(item->path() / "device");
        const std::string driver = link_target(item->path() / "driver");
        const std::string iommu_group = link_target(item->path() / "iommu_group");
        ++pci_count;
        const std::string normalized = "id=" + id + ";class=" + (class_code.empty() ? "unknown" : class_code) +
            ";vendor=" + (vendor.empty() ? "unknown" : vendor) + ";device=" +
            (device.empty() ? "unknown" : device) + ";driver=" +
            (driver.empty() ? "unbound" : std::filesystem::path(driver).filename().string()) +
            ";iommu_group=" + (iommu_group.empty() ? "unassigned-or-unavailable" : std::filesystem::path(iommu_group).filename().string());
        pci_entries.push_back(normalized);
        if (class_code.starts_with("0x02")) {
            ++network_count;
            network_pci_entries.push_back(normalized);
        }
    }
    std::sort(pci_entries.begin(), pci_entries.end());
    output.push_back({"bus", "pci_devices", error ? "unknown" : "available", pci_root.string(),
                      error ? "PCI inventory is unavailable" : std::to_string(pci_count) + " devices"});
    for (const std::string& entry : pci_entries) {
        output.push_back({"bus", "pci_device", "present", pci_root.string(), entry});
    }
    output.push_back({"network", "pci_controllers", error ? "unknown" : "available", pci_root.string(),
                      error ? "PCI network inventory is unavailable" : std::to_string(network_count) + " class-02 controllers"});
    for (const std::string& entry : network_pci_entries) {
        output.push_back({"network", "pci_controller", "present", pci_root.string(), entry});
    }

    const auto& net_root = paths.net_root;
    error.clear();
    std::vector<std::string> interface_entries;
    std::size_t interface_count = 0;
    for (std::filesystem::directory_iterator item(net_root, error), end;
         !error && item != end; item.increment(error)) {
        ++interface_count;
        const std::string name = item->path().filename().string();
        const std::string device_path = link_target(item->path() / "device");
        const std::string driver_path = link_target(item->path() / "device" / "driver");
        std::error_code wireless_error;
        const bool wireless = std::filesystem::exists(item->path() / "wireless", wireless_error);
        std::ostringstream entry;
        entry << "name=" << name << ";device=" << (device_path.empty() ? "virtual-or-unavailable" : device_path)
              << ";driver=" << (driver_path.empty() ? "unbound-or-virtual" : std::filesystem::path(driver_path).filename().string())
              << ";kind=" << (wireless ? "wireless" : "other")
              << ";state=" << (read_text(item->path() / "operstate").empty() ? "unknown" : read_text(item->path() / "operstate"))
              << ";carrier=" << (read_text(item->path() / "carrier").empty() ? "unknown" : read_text(item->path() / "carrier"));
        interface_entries.push_back(entry.str());
    }
    std::sort(interface_entries.begin(), interface_entries.end());
    for (const std::string& entry : interface_entries) {
        output.push_back({"network", "interface", "present", net_root.string(), entry});
    }
    output.push_back({"network", "interfaces", error ? "unknown" : "available", net_root.string(),
                      error ? "network interface inventory is unavailable" : std::to_string(interface_count) + " interfaces"});

    const auto& usb_root = paths.usb_root;
    error.clear();
    std::vector<std::string> usb_entries;
    for (std::filesystem::directory_iterator item(usb_root, error), end;
         !error && item != end; item.increment(error)) {
        const std::string vendor = read_text(item->path() / "idVendor");
        if (vendor.empty()) continue;
        const std::string product = read_text(item->path() / "idProduct");
        const std::string driver_path = link_target(item->path() / "driver");
        usb_entries.push_back("id=" + item->path().filename().string() + ";vendor=" + vendor + ";product=" + product +
            ";driver=" + (driver_path.empty() ? "unbound" : std::filesystem::path(driver_path).filename().string()));
    }
    std::sort(usb_entries.begin(), usb_entries.end());
    for (const std::string& entry : usb_entries) {
        output.push_back({"bus", "usb_device", "present", usb_root.string(), entry});
    }
    output.push_back({"bus", "usb_devices", error ? "unknown" : "available", usb_root.string(),
                      error ? "USB inventory is unavailable" : std::to_string(usb_entries.size()) + " USB devices"});

    const auto& tpm_root = paths.dev_root;
    error.clear();
    std::vector<std::string> tpm_entries;
    std::size_t tpm_count = 0;
    for (std::filesystem::directory_iterator item(tpm_root, error), end;
         !error && item != end; item.increment(error)) {
        const std::string name = item->path().filename().string();
        const bool numbered_tpm = name.starts_with("tpm") &&
            (name.size() > 3 && std::all_of(name.begin() + 3, name.end(), [](unsigned char ch) { return std::isdigit(ch) != 0; }));
        const bool resource_manager = name.starts_with("tpmrm") &&
            (name.size() > 5 && std::all_of(name.begin() + 5, name.end(), [](unsigned char ch) { return std::isdigit(ch) != 0; }));
        if (!numbered_tpm && !resource_manager) continue;
        std::error_code type_error;
        if (!std::filesystem::is_character_file(item->path(), type_error)) {
            if (type_error) {
                error = type_error;
                break;
            }
            continue;
        }
        ++tpm_count;
        tpm_entries.push_back(name);
    }
    std::sort(tpm_entries.begin(), tpm_entries.end());
    for (const std::string& entry : tpm_entries) {
        output.push_back({"trust", "tpm_device", "present", tpm_root.string(), "path=/dev/" + entry});
    }
    output.push_back({"trust", "tpm_device_nodes", error ? "unknown" : (tpm_count ? "available" : "unavailable"),
                      tpm_root.string(), error ? "device inventory access failed" :
                      (tpm_count ? std::to_string(tpm_count) + " nodes found; TPM capabilities not attested" : "no TPM character device node found")});

    error.clear();
    const auto& tpm_sysfs_root = paths.tpm_root;
    std::size_t tpm_sysfs_count = 0;
    for (std::filesystem::directory_iterator item(tpm_sysfs_root, error), end;
         !error && item != end; item.increment(error)) {
        std::error_code type_error;
        if (!std::filesystem::is_directory(item->path(), type_error)) {
            if (type_error) { error = type_error; break; }
            continue;
        }
        ++tpm_sysfs_count;
        const std::string name = item->path().filename().string();
        output.push_back({"trust", "tpm_sysfs_device", "present", tpm_sysfs_root.string(),
                          "name=" + name + ";version=" +
                          (read_text(item->path() / "tpm_version_major").empty() ? "unknown" : read_text(item->path() / "tpm_version_major")) +
                          ";device=" + (link_target(item->path() / "device").empty() ? "unavailable" : link_target(item->path() / "device"))});
    }
    output.push_back({"trust", "tpm_sysfs_inventory", error ? "unknown" : (tpm_sysfs_count ? "available" : "unavailable"),
                      tpm_sysfs_root.string(), error ? "TPM sysfs inventory access failed" :
                      std::to_string(tpm_sysfs_count) + " TPM devices exposed by sysfs"});

    const auto& rng_root = paths.rng_root;
    const std::string available_rngs = read_text(rng_root / "rng_available");
    const std::string current_rng = read_text(rng_root / "rng_current");
    output.push_back({"entropy", "hardware_rng", available_rngs.empty() ? "unavailable" : "available", rng_root.string(),
                      available_rngs.empty() ? "no hardware RNG list exposed; OpenSSL still uses its configured DRBG" :
                      "available=" + available_rngs + "; current=" + (current_rng.empty() ? "unknown" : current_rng) + "; output quality not tested"});

    const auto& block_root = paths.block_root;
    error.clear();
    std::vector<std::string> block_entries;
    std::size_t block_count = 0;
    for (std::filesystem::directory_iterator item(block_root, error), end;
         !error && item != end; item.increment(error)) {
        const std::string name = item->path().filename().string();
        ++block_count;
        std::ostringstream entry;
        entry << "name=" << name << ";dev=" << read_text(item->path() / "dev")
              << ";ro=" << read_text(item->path() / "ro")
              << ";sectors=" << read_text(item->path() / "size");
        block_entries.push_back(entry.str());
    }
    std::sort(block_entries.begin(), block_entries.end());
    for (const std::string& entry : block_entries) {
        output.push_back({"storage", "block_device", "present", block_root.string(), entry});
    }
    output.push_back({"storage", "block_devices", error ? "unknown" : "available", block_root.string(),
                      error ? "block device inventory is unavailable" : std::to_string(block_count) + " devices"});

    const auto& cpu_vulnerabilities = paths.cpu_vulnerabilities;
    error.clear();
    std::vector<std::string> cpu_security_entries;
    for (std::filesystem::directory_iterator item(cpu_vulnerabilities, error), end;
         !error && item != end; item.increment(error)) {
        const std::string status = read_text(item->path());
        cpu_security_entries.push_back(item->path().filename().string() + "=" + (status.empty() ? "unknown" : status));
    }
    std::sort(cpu_security_entries.begin(), cpu_security_entries.end());
    for (const std::string& entry : cpu_security_entries) {
        output.push_back({"cpu_security", "vulnerability", "reported", cpu_vulnerabilities.string(), entry});
    }
    output.push_back({"cpu_security", "kernel_vulnerability_status", error ? "unknown" : "available",
                      cpu_vulnerabilities.string(), error ? "kernel mitigation status is unavailable" :
                      std::to_string(cpu_security_entries.size()) + " kernel-reported entries; physical side-channel resistance is not established"});

    error.clear();
    std::size_t iommu_group_count = 0;
    for (std::filesystem::directory_iterator item(paths.iommu_root, error), end;
         !error && item != end; item.increment(error)) {
        std::error_code type_error;
        if (std::filesystem::is_directory(item->path(), type_error)) ++iommu_group_count;
        else if (type_error) { error = type_error; break; }
    }
    output.push_back({"dma_security", "iommu_groups", error ? "unknown" : (iommu_group_count ? "available" : "unavailable"),
                      paths.iommu_root.string(), error ? "IOMMU group inventory access failed" :
                      std::to_string(iommu_group_count) + " groups; membership is reported per PCI device and is not a security guarantee"});
}

#endif

}

std::string detail::hardware_report_text(const HardwarePaths& paths) {
    std::vector<Capability> capabilities;
#if defined(__linux__)
    capabilities.push_back({"platform", "os", "linux", "compile-time adapter", "Linux sysfs and EFI variable provider"});
    discover_boot(capabilities, paths.efi_root);
    discover_devices(capabilities, paths);
    capabilities.push_back({"physical_security", "side_channel_controls", "not_assessed", "platform-specific validation",
                            "software inventory cannot establish physical resistance"});
    capabilities.push_back({"registers", "safe_register_inventory", "unsupported", "no platform register provider",
                            "requires a platform driver and an explicit read-only register allowlist"});
#else
    capabilities.push_back({"platform", "os", "unknown", "compile-time adapter", "no operating-system provider"});
    capabilities.push_back({"platform", "hardware_inventory", "unsupported", "no adapter for this operating system",
                            "capability provider interface is platform neutral; an OS adapter is required"});
#endif

    std::vector<std::string> lines;
    lines.reserve(capabilities.size());
    for (const Capability& item : capabilities) {
        lines.push_back(escape_field(item.domain) + "\t" + escape_field(item.name) + "\t" +
            escape_field(item.state) + "\t" + escape_field(item.source) + "\t" + escape_field(item.evidence));
    }
    std::sort(lines.begin(), lines.end());
    std::ostringstream report;
    report << "qprotect-hardware-v1\n";
    for (const std::string& line : lines) report << line << '\n';
    return report.str();
}

std::string hardware_report_text() {
    return detail::hardware_report_text(detail::HardwarePaths{});
}

}
