// VISS — hashing and encoding primitives. PROVIDED CODE.

#include "vissapp/crypto_util.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <fstream>
#include <sstream>

#include "vissapp/errors.h"

namespace vissapp {
namespace {

int HexVal(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int B64Val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

} // namespace

void Sha256(const uint8_t* data, size_t len, uint8_t out[32])
{
    unsigned int out_len = 0;
    if (EVP_Digest(data, len, out, &out_len, EVP_sha256(), nullptr) != 1 ||
        out_len != 32) {
        throw VissappError("SHA-256 failed");
    }
}

void HmacSha256(const uint8_t* key, size_t key_len,
                const uint8_t* data, size_t data_len, uint8_t out[32])
{
    unsigned int out_len = 0;
    if (HMAC(EVP_sha256(), key, static_cast<int>(key_len), data, data_len,
             out, &out_len) == nullptr || out_len != 32) {
        throw VissappError("HMAC-SHA-256 failed");
    }
}

std::string ToHex(const uint8_t* data, size_t len)
{
    static const char* kDigits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out.push_back(kDigits[data[i] >> 4]);
        out.push_back(kDigits[data[i] & 0x0F]);
    }
    return out;
}

std::vector<uint8_t> FromHex(const std::string& hex)
{
    if (hex.size() % 2 != 0) throw VissappError("hex string has odd length");
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const int hi = HexVal(hex[i]), lo = HexVal(hex[i + 1]);
        if (hi < 0 || lo < 0) throw VissappError("invalid hex character");
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::vector<uint8_t> Base64Decode(const std::string& text)
{
    std::vector<uint8_t> out;
    uint32_t acc = 0;
    int bits = 0, pad = 0;
    for (char c : text) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
        if (c == '=') { pad++; continue; }
        if (pad) throw VissappError("base64: data after padding");
        const int v = B64Val(c);
        if (v < 0) throw VissappError("base64: invalid character");
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    if (pad > 2) throw VissappError("base64: too much padding");
    return out;
}

std::vector<uint8_t> ReadFile(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) throw VissappError("cannot read file: " + path.string());
    std::ostringstream ss;
    ss << in.rdbuf();
    const std::string s = ss.str();
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::string ReadTextFile(const std::filesystem::path& path)
{
    const std::vector<uint8_t> raw = ReadFile(path);
    return std::string(raw.begin(), raw.end());
}

} // namespace vissapp
