#pragma once

#include <stdexcept>

namespace qprotect::cpp {

class CryptoError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class EnvelopeError : public CryptoError {
public:
    using CryptoError::CryptoError;
};

}
