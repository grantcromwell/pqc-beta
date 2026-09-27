#include "identity.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cmath>
#include <regex>
#include <set>
#include <tuple>

namespace qprotect::cpp::detail {
namespace {

using json::Object;
using json::Value;

std::string trim_ascii(const std::string& value) {
    std::size_t begin = 0;
    std::size_t end = value.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(value[begin]))) {
        ++begin;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    return value.substr(begin, end - begin);
}

const Value* first(const Object& object, std::initializer_list<const char*> names) {
    for (const char* name : names) {
        const auto found = object.find(name);
        if (found != object.end()) {
            return &found->second;
        }
    }
    return nullptr;
}

const std::string& require_string(const Value* value, const char* field) {
    if (value == nullptr || !value->is_string()) {
        throw EnvelopeError(std::string(field) + " must be a string");
    }
    return value->as_string();
}

std::string normalize_mac(const Value* value, const char* field) {
    if (value == nullptr || value->is_null()) {
        return {};
    }
    std::string compact;
    for (const unsigned char raw : trim_ascii(require_string(value, field))) {
        if (raw == ':' || raw == '.' || raw == '-' || raw == ' ') {
            continue;
        }
        if (!std::isxdigit(raw)) {
            throw EnvelopeError(std::string(field) + " is not a 48-bit EUI value");
        }
        compact.push_back(static_cast<char>(std::tolower(raw)));
    }
    if (compact.size() != 12) {
        throw EnvelopeError(std::string(field) + " is not a 48-bit EUI value");
    }
    std::string normalized;
    for (std::size_t index = 0; index < compact.size(); index += 2) {
        if (!normalized.empty()) {
            normalized.push_back(':');
        }
        normalized.append(compact, index, 2);
    }
    return normalized;
}

std::string normalize_ip(const Value* value) {
    if (value == nullptr || value->is_null()) {
        return {};
    }
    const std::string input = trim_ascii(require_string(value, "IP address"));
    std::array<unsigned char, 16> address{};
    char rendered[INET6_ADDRSTRLEN]{};
    if (inet_pton(AF_INET, input.c_str(), address.data()) == 1) {
        if (inet_ntop(AF_INET, address.data(), rendered, sizeof(rendered)) == nullptr) {
            throw EnvelopeError("unable to normalize IP address");
        }
        return rendered;
    }
    if (inet_pton(AF_INET6, input.c_str(), address.data()) == 1) {
        if (inet_ntop(AF_INET6, address.data(), rendered, sizeof(rendered)) == nullptr) {
            throw EnvelopeError("unable to normalize IP address");
        }
        std::string normalized(rendered);
        std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return normalized;
    }
    throw EnvelopeError("invalid IP address");
}

std::string normalize_uuid(const Value* value, const char* field) {
    if (value == nullptr || value->is_null()) {
        return {};
    }
    std::string input = trim_ascii(require_string(value, field));
    std::transform(input.begin(), input.end(), input.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (input.starts_with("urn:uuid:")) {
        input.erase(0, 9);
    }
    if (input.size() == 38 && input.front() == '{' && input.back() == '}') {
        input = input.substr(1, 36);
    }
    std::string hex;
    for (const char c : input) {
        if (c == '-') {
            continue;
        }
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            throw EnvelopeError(std::string("invalid ") + field);
        }
        hex.push_back(c);
    }
    if (hex.size() != 32) {
        throw EnvelopeError(std::string("invalid ") + field);
    }
    return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" +
        hex.substr(16, 4) + "-" + hex.substr(20, 12);
}

std::string normalize_serial(const Value* value) {
    if (value == nullptr || value->is_null()) {
        return {};
    }
    const std::string serial = trim_ascii(require_string(value, "hardware serial"));
    if (serial.empty() || serial.size() > 512) {
        throw EnvelopeError("hardware serial must be 1..512 bytes");
    }
    for (const unsigned char c : serial) {
        if (c < 0x20 || c == 0x7f) {
            throw EnvelopeError("hardware serial contains control characters");
        }
    }
    return serial;
}

void validate_timestamp(const std::string& text) {
    static const std::regex pattern(
        R"(^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$)");
    std::string whole_seconds = text;
    const std::size_t fraction = whole_seconds.find('.', 19);
    if (fraction != std::string::npos) {
        const std::size_t zone = whole_seconds.find_first_of("Z+-", fraction + 1);
        if (zone == std::string::npos || zone == fraction + 1 ||
            !std::all_of(whole_seconds.begin() + static_cast<std::ptrdiff_t>(fraction + 1),
                         whole_seconds.begin() + static_cast<std::ptrdiff_t>(zone),
                         [](unsigned char c) { return std::isdigit(c); })) {
            throw EnvelopeError("GPS timestamp has an invalid fractional second");
        }
        whole_seconds.erase(fraction, zone - fraction);
    }
    if (!std::regex_match(whole_seconds, pattern)) {
        throw EnvelopeError("GPS timestamp must be RFC 3339 with a timezone");
    }
    const auto number = [&text](std::size_t at, std::size_t length) {
        return std::stoi(text.substr(at, length));
    };
    const std::chrono::year_month_day date{
        std::chrono::year(number(0, 4)),
        std::chrono::month(static_cast<unsigned>(number(5, 2))),
        std::chrono::day(static_cast<unsigned>(number(8, 2))),
    };
    if (!date.ok() || number(11, 2) > 23 || number(14, 2) > 59 || number(17, 2) > 59) {
        throw EnvelopeError("GPS timestamp is not a valid date and time");
    }
    const std::size_t zone = text.find_first_of("Z+-", 19);
    if (zone != std::string::npos && text[zone] != 'Z' &&
        (number(zone + 1, 2) > 23 || number(zone + 4, 2) > 59)) {
        throw EnvelopeError("GPS timestamp has an invalid timezone offset");
    }
}

Value normalize_gps(const Value* value) {
    if (value == nullptr || value->is_null()) {
        return Value(nullptr);
    }
    const Object& input = value->expect_object("GPS data");
    Object output;
    for (const char* field : {"latitude", "longitude"}) {
        const auto found = input.find(field);
        if (found == input.end() || !found->second.is_number()) {
            throw EnvelopeError(std::string("GPS data missing or invalid ") + field);
        }
        const double number = found->second.as_number();
        const double minimum = std::string(field) == "latitude" ? -90.0 : -180.0;
        const double maximum = -minimum;
        if (!std::isfinite(number) || number < minimum || number > maximum) {
            throw EnvelopeError(std::string("GPS ") + field + " is outside its accepted range");
        }
        output.emplace(field, Value(number));
    }
    for (const auto& [field, minimum, maximum] : {
             std::tuple<const char*, double, double>{"altitude_m", -10000.0, 100000.0},
             {"accuracy_m", 0.0, 1000000.0}}) {
        const auto found = input.find(field);
        if (found == input.end() || found->second.is_null()) {
            continue;
        }
        if (!found->second.is_number()) {
            throw EnvelopeError(std::string("GPS ") + field + " is not numeric");
        }
        const double number = found->second.as_number();
        if (!std::isfinite(number) || number < minimum || number > maximum) {
            throw EnvelopeError(std::string("GPS ") + field + " is outside its accepted range");
        }
        output.emplace(field, Value(number));
    }
    const auto timestamp = input.find("timestamp");
    if (timestamp != input.end() && !timestamp->second.is_null()) {
        const std::string& text = require_string(&timestamp->second, "GPS timestamp");
        validate_timestamp(text);
        output.emplace("timestamp", Value(text));
    }
    if (Value(output).canonical().size() > 4096) {
        throw EnvelopeError("GPS data exceeds 4 KiB");
    }
    return Value(std::move(output));
}

}

json::Value normalize_identity(const json::Value& input_value) {
    const Object& input = input_value.expect_object("identity input");
    Object normalized;
    for (const auto& [key, value] : input) {
        const std::string name = trim_ascii(key);
        if (!normalized.emplace(name, value).second) {
            throw EnvelopeError("identity input contains duplicate normalized keys");
        }
    }

    const std::set<std::string> known{
        "ip", "ip_address", "mac", "mac_address", "hardware_mac", "bssid", "wifi_bssid",
        "serial", "hardware_serial", "serial_number", "uuid", "guid", "browser_fingerprint",
        "browser_fingerprint_hash", "gps", "location", "additional",
    };
    Object additional;
    const auto supplied_additional = normalized.find("additional");
    if (supplied_additional != normalized.end()) {
        const Object& values = supplied_additional->second.expect_object("additional identity data");
        additional = values;
    }
    for (const auto& [key, value] : normalized) {
        if (known.contains(key)) {
            continue;
        }
        additional.insert_or_assign(key, value);
    }
    if (Value(additional).canonical().size() > 64 * 1024) {
        throw EnvelopeError("additional identity data exceeds 64 KiB");
    }

    Value fingerprint(nullptr);
    const Value* supplied_fingerprint = first(normalized, {"browser_fingerprint", "browser_fingerprint_hash"});
    if (supplied_fingerprint != nullptr) {
        fingerprint = *supplied_fingerprint;
        if (fingerprint.canonical().size() > 64 * 1024) {
            throw EnvelopeError("browser fingerprint exceeds 64 KiB");
        }
    }

    Object result;
    const std::string ip = normalize_ip(first(normalized, {"ip", "ip_address"}));
    const std::string mac = normalize_mac(first(normalized, {"mac", "mac_address", "hardware_mac"}), "MAC address");
    const std::string bssid = normalize_mac(first(normalized, {"bssid", "wifi_bssid"}), "Wi-Fi BSSID");
    const std::string serial = normalize_serial(first(normalized, {"serial", "hardware_serial", "serial_number"}));
    const std::string uuid = normalize_uuid(first(normalized, {"uuid"}), "UUID");
    const std::string guid = normalize_uuid(first(normalized, {"guid"}), "GUID");
    result.emplace("additional", Value(std::move(additional)));
    result.emplace("browser_fingerprint", std::move(fingerprint));
    result.emplace("gps", normalize_gps(first(normalized, {"gps", "location"})));
    result.emplace("guid", guid.empty() ? Value(nullptr) : Value(guid));
    result.emplace("hardware_serial", serial.empty() ? Value(nullptr) : Value(serial));
    result.emplace("ip_address", ip.empty() ? Value(nullptr) : Value(ip));
    result.emplace("mac_address", mac.empty() ? Value(nullptr) : Value(mac));
    result.emplace("uuid", uuid.empty() ? Value(nullptr) : Value(uuid));
    result.emplace("wifi_bssid", bssid.empty() ? Value(nullptr) : Value(bssid));
    return Value(std::move(result));
}

}
