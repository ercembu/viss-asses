#pragma once
// VISS — exception types shared across vissapp. PROVIDED CODE.

#include <stdexcept>
#include <string>

namespace vissapp {

// Base class for every error this library raises.
struct VissappError : std::runtime_error {
    explicit VissappError(const std::string& what) : std::runtime_error(what) {}
};

// A bundle's dm-verity hash tree is malformed, unreadable, or does not match.
struct HashTreeError : VissappError {
    explicit HashTreeError(const std::string& what) : VissappError(what) {}
};

// A key, a signature encoding, or a signature itself was rejected.
struct SignatureError : VissappError {
    explicit SignatureError(const std::string& what) : VissappError(what) {}
};

// A token or challenge response was rejected.
struct TokenError : VissappError {
    explicit TokenError(const std::string& what) : VissappError(what) {}
};

} // namespace vissapp
