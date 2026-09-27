#pragma once

#include "json_minimal.hpp"

namespace qprotect::cpp::detail {

json::Value normalize_identity(const json::Value& input);

}
