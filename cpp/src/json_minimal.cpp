#include "json_minimal.hpp"

#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <system_error>

namespace qprotect::cpp::json {
namespace {

void validate_utf8(const std::string& text) {
    for (std::size_t offset = 0; offset < text.size();) {
        const auto first = static_cast<unsigned char>(text[offset++]);
        if (first < 0x80) continue;
        unsigned int codepoint;
        unsigned int minimum;
        std::size_t remaining;
        if (first >= 0xC2 && first <= 0xDF) {
            codepoint = first & 0x1F;
            minimum = 0x80;
            remaining = 1;
        } else if (first >= 0xE0 && first <= 0xEF) {
            codepoint = first & 0x0F;
            minimum = 0x800;
            remaining = 2;
        } else if (first >= 0xF0 && first <= 0xF4) {
            codepoint = first & 0x07;
            minimum = 0x10000;
            remaining = 3;
        } else {
            throw EnvelopeError("invalid JSON: invalid UTF-8");
        }
        if (remaining > text.size() - offset) {
            throw EnvelopeError("invalid JSON: truncated UTF-8");
        }
        while (remaining-- > 0) {
            const auto next = static_cast<unsigned char>(text[offset++]);
            if ((next & 0xC0) != 0x80) {
                throw EnvelopeError("invalid JSON: invalid UTF-8 continuation");
            }
            codepoint = (codepoint << 6) | (next & 0x3F);
        }
        if (codepoint < minimum || codepoint > 0x10FFFF ||
            (codepoint >= 0xD800 && codepoint <= 0xDFFF)) {
            throw EnvelopeError("invalid JSON: invalid Unicode codepoint");
        }
    }
}

class Parser {
public:
    explicit Parser(const std::string& text) : text_(text) {}

    Value parse_document() {
        skip_whitespace();
        Value value = parse_value();
        skip_whitespace();
        if (position_ != text_.size()) {
            throw EnvelopeError("trailing data after JSON document");
        }
        return value;
    }

private:
    const std::string& text_;
    std::size_t position_ = 0;

    [[noreturn]] void fail(const char* message) const {
        throw EnvelopeError(std::string("invalid JSON: ") + message);
    }

    void skip_whitespace() {
        while (position_ < text_.size()) {
            const char c = text_[position_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                ++position_;
            } else {
                break;
            }
        }
    }

    bool consume(char expected) {
        if (position_ < text_.size() && text_[position_] == expected) {
            ++position_;
            return true;
        }
        return false;
    }

    void expect(char expected) {
        if (!consume(expected)) {
            fail("unexpected character");
        }
    }

    char peek() const {
        if (position_ >= text_.size()) {
            fail("unexpected end of input");
        }
        return text_[position_];
    }

    Value parse_value(std::size_t depth = 0) {
        if (depth > 64) {
            fail("maximum nesting depth exceeded");
        }
        const char c = peek();
        switch (c) {
            case '{': return parse_object(depth);
            case '[': return parse_array(depth);
            case '"': return Value(parse_string());
            case 't': return parse_literal("true", Value(true));
            case 'f': return parse_literal("false", Value(false));
            case 'n': return parse_literal("null", Value(nullptr));
            default: return parse_number();
        }
    }

    Value parse_literal(const char* literal, Value value) {
        for (const char* p = literal; *p != '\0'; ++p) {
            if (position_ >= text_.size() || text_[position_] != *p) {
                fail("invalid literal");
            }
            ++position_;
        }
        return value;
    }

    Value parse_object(std::size_t depth) {
        expect('{');
        Object object;
        skip_whitespace();
        if (consume('}')) {
            return Value(std::move(object));
        }
        while (true) {
            skip_whitespace();
            if (peek() != '"') {
                fail("object keys must be strings");
            }
            std::string key = parse_string();
            skip_whitespace();
            expect(':');
            skip_whitespace();
            Value value = parse_value(depth + 1);
            if (!object.emplace(std::move(key), std::move(value)).second) {
                fail("duplicate object key");
            }
            skip_whitespace();
            if (consume(',')) {
                continue;
            }
            expect('}');
            return Value(std::move(object));
        }
    }

    Value parse_array(std::size_t depth) {
        expect('[');
        Array array;
        skip_whitespace();
        if (consume(']')) {
            return Value(std::move(array));
        }
        while (true) {
            skip_whitespace();
            array.push_back(parse_value(depth + 1));
            skip_whitespace();
            if (consume(',')) {
                continue;
            }
            expect(']');
            return Value(std::move(array));
        }
    }

    static void append_utf8(std::string& out, unsigned int codepoint) {
        if (codepoint < 0x80) {
            out.push_back(static_cast<char>(codepoint));
        } else if (codepoint < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (codepoint >> 6)));
            out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
        } else if (codepoint < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (codepoint >> 12)));
            out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (codepoint >> 18)));
            out.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
        }
    }

    unsigned int parse_hex4() {
        unsigned int value = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = peek();
            unsigned int digit = 0;
            if (c >= '0' && c <= '9') {
                digit = static_cast<unsigned int>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                digit = static_cast<unsigned int>(c - 'a' + 10);
            } else if (c >= 'A' && c <= 'F') {
                digit = static_cast<unsigned int>(c - 'A' + 10);
            } else {
                fail("invalid \\u escape");
            }
            value = (value << 4) | digit;
            ++position_;
        }
        return value;
    }

    std::string parse_string() {
        expect('"');
        std::string out;
        while (true) {
            if (position_ >= text_.size()) {
                fail("unterminated string");
            }
            const unsigned char c = static_cast<unsigned char>(text_[position_++]);
            if (c == '"') {
                validate_utf8(out);
                return out;
            }
            if (c < 0x20) {
                fail("control character in string");
            }
            if (c != '\\') {
                out.push_back(static_cast<char>(c));
                continue;
            }
            if (position_ >= text_.size()) {
                fail("unterminated escape");
            }
            const char escaped = text_[position_++];
            switch (escaped) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    unsigned int codepoint = parse_hex4();
                    if (codepoint >= 0xD800 && codepoint <= 0xDBFF) {

                        if (position_ + 1 >= text_.size() ||
                            text_[position_] != '\\' || text_[position_ + 1] != 'u') {
                            fail("unpaired surrogate");
                        }
                        position_ += 2;
                        const unsigned int low = parse_hex4();
                        if (low < 0xDC00 || low > 0xDFFF) {
                            fail("unpaired surrogate");
                        }
                        codepoint = 0x10000 + ((codepoint - 0xD800) << 10) + (low - 0xDC00);
                    } else if (codepoint >= 0xDC00 && codepoint <= 0xDFFF) {
                        fail("unpaired surrogate");
                    }
                    append_utf8(out, codepoint);
                    break;
                }
                default: fail("invalid escape");
            }
        }
    }

    Value parse_number() {
        const std::size_t start = position_;
        consume('-');
        if (consume('0')) {
            if (position_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[position_]))) {
                fail("leading zero in number");
            }
        } else {
            if (position_ >= text_.size() || text_[position_] < '1' || text_[position_] > '9') {
                fail("invalid number");
            }
            while (position_ < text_.size() &&
                   std::isdigit(static_cast<unsigned char>(text_[position_]))) {
                ++position_;
            }
        }
        bool fractional = false;
        if (consume('.')) {
            fractional = true;
            const std::size_t fraction_start = position_;
            while (position_ < text_.size() &&
                   std::isdigit(static_cast<unsigned char>(text_[position_]))) {
                ++position_;
            }
            if (position_ == fraction_start) {
                fail("fraction requires digits");
            }
        }
        if (position_ < text_.size() && (text_[position_] == 'e' || text_[position_] == 'E')) {
            fractional = true;
            ++position_;
            if (position_ < text_.size() && (text_[position_] == '+' || text_[position_] == '-')) {
                ++position_;
            }
            const std::size_t exponent_start = position_;
            while (position_ < text_.size() &&
                   std::isdigit(static_cast<unsigned char>(text_[position_]))) {
                ++position_;
            }
            if (position_ == exponent_start) {
                fail("exponent requires digits");
            }
        }
        const char* first = text_.data() + start;
        const char* last = text_.data() + position_;
        if (fractional) {
            double value = 0.0;
            const auto parsed = std::from_chars(first, last, value, std::chars_format::general);
            if (parsed.ec != std::errc{} || parsed.ptr != last || !std::isfinite(value)) {
                fail("number is out of range");
            }
            return Value(value);
        }
        long long value = 0;
        const auto parsed = std::from_chars(first, last, value);
        if (parsed.ec != std::errc{} || parsed.ptr != last) {
            fail("integer out of range");
        }
        return Value(value);
    }
};

void append_escaped(std::string& out, const std::string& value) {
    validate_utf8(value);

    static const char hex[] = "0123456789abcdef";
    out.push_back('"');
    for (const char raw : value) {
        const unsigned char c = static_cast<unsigned char>(raw);
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    out += "\\u00";
                    out.push_back(hex[(c >> 4) & 0xF]);
                    out.push_back(hex[c & 0xF]);
                } else {
                    out.push_back(raw);
                }
        }
    }
    out.push_back('"');
}

void append_scalar(std::string& out, const Value& value) {
    switch (value.type()) {
        case Value::Type::Null: out += "null"; break;
        case Value::Type::Boolean: out += value.as_boolean() ? "true" : "false"; break;
        case Value::Type::Integer:
            out += std::to_string(value.as_integer());
            break;
        case Value::Type::Number: {
            char buffer[64]{};
            const auto rendered = std::to_chars(
                buffer, buffer + sizeof(buffer), value.as_number(), std::chars_format::general);
            if (rendered.ec != std::errc{}) {
                throw EnvelopeError("unable to serialize JSON number");
            }
            std::string number(buffer, rendered.ptr);
            if (number.find_first_of(".eE") == std::string::npos) {
                number += ".0";
            }
            out += number;
            break;
        }
        case Value::Type::String: append_escaped(out, value.as_string()); break;
        default: break;
    }
}

void append_indentation(std::string& out, int indent, int depth) {
    out.append(static_cast<std::size_t>(indent) * static_cast<std::size_t>(depth), ' ');
}

void append_canonical(std::string& out, const Value& value) {
    switch (value.type()) {
        case Value::Type::Array: {
            out.push_back('[');
            const Array& items = value.as_array();
            for (std::size_t i = 0; i < items.size(); ++i) {
                if (i != 0) {
                    out.push_back(',');
                }
                append_canonical(out, items[i]);
            }
            out.push_back(']');
            break;
        }
        case Value::Type::Object: {
            out.push_back('{');
            bool first = true;
            for (const auto& [key, item] : value.as_object()) {
                if (!first) {
                    out.push_back(',');
                }
                first = false;
                append_escaped(out, key);
                out.push_back(':');
                append_canonical(out, item);
            }
            out.push_back('}');
            break;
        }
        default: append_scalar(out, value); break;
    }
}

void append_pretty(std::string& out, const Value& value, int indent, int depth) {
    switch (value.type()) {
        case Value::Type::Array: {
            const Array& items = value.as_array();
            if (items.empty()) {
                out += "[]";
                return;
            }
            out.push_back('[');
            for (std::size_t i = 0; i < items.size(); ++i) {
                if (i != 0) {
                    out.push_back(',');
                }
                out.push_back('\n');
                append_indentation(out, indent, depth + 1);
                append_pretty(out, items[i], indent, depth + 1);
            }
            out.push_back('\n');
            append_indentation(out, indent, depth);
            out.push_back(']');
            break;
        }
        case Value::Type::Object: {
            const Object& members = value.as_object();
            if (members.empty()) {
                out += "{}";
                return;
            }
            out.push_back('{');
            bool first = true;
            for (const auto& [key, item] : members) {
                if (!first) {
                    out.push_back(',');
                }
                first = false;
                out.push_back('\n');
                append_indentation(out, indent, depth + 1);
                append_escaped(out, key);
                out += ": ";
                append_pretty(out, item, indent, depth + 1);
            }
            out.push_back('\n');
            append_indentation(out, indent, depth);
            out.push_back('}');
            break;
        }
        default: append_scalar(out, value); break;
    }
}

}

bool Value::as_boolean() const {
    if (type_ != Type::Boolean) {
        throw EnvelopeError("JSON value is not a boolean");
    }
    return boolean_;
}

long long Value::as_integer() const {
    if (type_ != Type::Integer) {
        throw EnvelopeError("JSON value is not an integer");
    }
    return integer_;
}

double Value::as_number() const {
    if (type_ == Type::Integer) {
        return static_cast<double>(integer_);
    }
    if (type_ != Type::Number) {
        throw EnvelopeError("JSON value is not a number");
    }
    return number_;
}

const std::string& Value::as_string() const {
    if (type_ != Type::String) {
        throw EnvelopeError("JSON value is not a string");
    }
    return string_;
}

const Array& Value::as_array() const {
    if (type_ != Type::Array) {
        throw EnvelopeError("JSON value is not an array");
    }
    return array_;
}

const Object& Value::as_object() const {
    if (type_ != Type::Object) {
        throw EnvelopeError("JSON value is not an object");
    }
    return object_;
}

const Object& Value::expect_object(const char* what) const {
    if (type_ != Type::Object) {
        throw EnvelopeError(std::string(what) + " must be a JSON object");
    }
    return object_;
}

std::string Value::canonical() const {
    std::string out;
    append_canonical(out, *this);
    return out;
}

std::string Value::pretty(int indent) const {
    std::string out;
    append_pretty(out, *this, indent, 0);
    return out;
}

Value Value::parse(const std::string& text) {
    return Parser(text).parse_document();
}

}
