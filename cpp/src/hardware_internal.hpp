#pragma once

#include <filesystem>
#include <string>

namespace qprotect::cpp::detail {

struct HardwarePaths {
    std::filesystem::path efi_root{"/sys/firmware/efi"};
    std::filesystem::path pci_root{"/sys/bus/pci/devices"};
    std::filesystem::path net_root{"/sys/class/net"};
    std::filesystem::path usb_root{"/sys/bus/usb/devices"};
    std::filesystem::path dev_root{"/dev"};
    std::filesystem::path tpm_root{"/sys/class/tpm"};
    std::filesystem::path iommu_root{"/sys/kernel/iommu_groups"};
    std::filesystem::path rng_root{"/sys/class/misc/hw_random"};
    std::filesystem::path block_root{"/sys/class/block"};
    std::filesystem::path cpu_vulnerabilities{"/sys/devices/system/cpu/vulnerabilities"};
};

std::string hardware_report_text(const HardwarePaths& paths);

}
