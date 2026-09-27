#pragma once

#include <span>
#include <string>

#include "qprotect/crypto_context.hpp"
#include "qprotect/secure_bytes.hpp"

namespace qprotect::cpp {

SecureBytes load_public_key_file(const CryptoContext& context,
                                 const std::string& path);

SecureBytes load_private_key_file(const CryptoContext& context,
                                  const std::string& path);

SecureBytes public_key_of_private(const CryptoContext& context,
                                  std::span<const unsigned char> private_key_der);

std::string key_id_for_public_key(const CryptoContext& context,
                                  std::span<const unsigned char> public_key_der);

void write_private_key_pem(const CryptoContext& context,
                           std::span<const unsigned char> private_key_der,
                           const std::string& path,
                           bool overwrite = false);

void write_public_key_pem(const CryptoContext& context,
                          std::span<const unsigned char> public_key_der,
                          const std::string& path,
                          bool overwrite = false);

}
