#pragma once
// VISS — hashing and encoding primitives. PROVIDED CODE.
//
// Backed by libcrypto. Complete, no TODOs. These are the building blocks the
// rest of the exercise is written in — you are implementing protocols and
// encodings on top of them, not re-implementing SHA-256.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace vissapp {

// One-shot SHA-256. *out* receives 32 bytes.
void Sha256(const uint8_t* data, size_t len, uint8_t out[32]);

// One-shot HMAC-SHA-256. *out* receives 32 bytes.
void HmacSha256(const uint8_t* key, size_t key_len,
                const uint8_t* data, size_t data_len, uint8_t out[32]);

// Lowercase hex encoding.
std::string ToHex(const uint8_t* data, size_t len);

// Decode lowercase or uppercase hex. Throws VissappError on odd length or a
// non-hex character.
std::vector<uint8_t> FromHex(const std::string& hex);

// Decode standard base64, ignoring ASCII whitespace. Throws VissappError on
// an invalid character or bad padding.
std::vector<uint8_t> Base64Decode(const std::string& text);

// Read a whole file. Throws VissappError if it cannot be read.
std::vector<uint8_t> ReadFile(const std::filesystem::path& path);
std::string ReadTextFile(const std::filesystem::path& path);

} // namespace vissapp
