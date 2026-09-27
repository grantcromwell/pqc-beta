#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace qprotect::cpp {

class SecureBytes {
public:
    using value_type = unsigned char;
    using iterator = std::vector<value_type>::iterator;
    using const_iterator = std::vector<value_type>::const_iterator;

    SecureBytes() = default;
    explicit SecureBytes(std::size_t size, value_type value = 0)
        : data_(size, value) {}
    SecureBytes(std::span<const value_type> input)
        : data_(input.begin(), input.end()) {}
    SecureBytes(const value_type* input, std::size_t size)
        : data_(input, input + size) {}

    SecureBytes(const SecureBytes&) = default;
    SecureBytes& operator=(const SecureBytes& other) {
        if (this != &other) {
            zeroize();
            data_ = other.data_;
        }
        return *this;
    }
    SecureBytes(SecureBytes&& other) noexcept
        : data_(std::move(other.data_)) {
        other.data_.clear();
    }
    SecureBytes& operator=(SecureBytes&& other) noexcept {
        if (this != &other) {
            zeroize();
            data_ = std::move(other.data_);
            other.data_.clear();
        }
        return *this;
    }

    ~SecureBytes() { zeroize(); }

    value_type* data() noexcept { return data_.data(); }
    const value_type* data() const noexcept { return data_.data(); }
    std::size_t size() const noexcept { return data_.size(); }
    bool empty() const noexcept { return data_.empty(); }

    value_type& operator[](std::size_t index) noexcept { return data_[index]; }
    const value_type& operator[](std::size_t index) const noexcept { return data_[index]; }

    iterator begin() noexcept { return data_.begin(); }
    iterator end() noexcept { return data_.end(); }
    const_iterator begin() const noexcept { return data_.begin(); }
    const_iterator end() const noexcept { return data_.end(); }

    void assign(std::span<const value_type> input) {
        zeroize();
        data_.assign(input.begin(), input.end());
    }

    void resize(std::size_t size) {
        std::vector<value_type> replacement(size);
        const std::size_t retained = size < data_.size() ? size : data_.size();
        for (std::size_t index = 0; index < retained; ++index) {
            replacement[index] = data_[index];
        }
        zeroize();
        data_.swap(replacement);
    }

    void clear() noexcept { zeroize(); }

    void zeroize() noexcept {
        volatile value_type* p = data_.data();
        for (std::size_t i = 0; i < data_.size(); ++i) {
            p[i] = 0;
        }
        data_.clear();
    }

    bool operator==(const SecureBytes&) const = default;

private:
    std::vector<value_type> data_;
};

}
