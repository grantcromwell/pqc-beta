#pragma once

#include <openssl/provider.h>
#include <openssl/types.h>

namespace qprotect::cpp {

struct CryptoContextHandles {
    OSSL_LIB_CTX* libctx = nullptr;
    OSSL_PROVIDER* algorithm_provider = nullptr;
    OSSL_PROVIDER* base_provider = nullptr;
    const char* properties = nullptr;
};

}
