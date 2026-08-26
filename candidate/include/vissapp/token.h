#pragma once
// VISS — maintenance tokens and service-mode challenge/response.
//                                        [Part 3 of 3 — authorisation]
//
// IMPLEMENT src/token.cpp. See SPEC.md section 5.

#include <cstdint>
#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include "keyring.h"

namespace vissapp {

// A parsed maintenance token.
struct Token {
    std::string purpose;
    std::string device;
    int64_t     created = 0;
    int64_t     expires = 0;
    std::string nonce;
};

// Parse the key=value token format. Throws TokenError on a malformed
// document, a missing field, a duplicate key or an unknown key.
// See SPEC.md section 5.2 — the parsing rules are the security boundary here,
// not an afterthought.
Token ParseToken(const std::vector<uint8_t>& document);

// The policy a token is judged against.
struct TokenPolicy {
    std::string required_purpose = "maintenance";
    std::string device_id;            // this unit's serial; must match exactly
    int64_t     now              = 0; // trusted time, seconds since epoch
    int64_t     max_window       = 24 * 3600;  // longest permitted validity
    int64_t     max_clock_skew   = 300;        // tolerance for a future created
};

// Verify a maintenance token end to end: work out which trusted signer
// produced it, check that signer is allowed to authorise this purpose, then
// judge the token against the policy. Returns the parsed token on success and
// throws TokenError otherwise.
//
// *token_path* is covered by <token_path>.sig. Section 5.3 gives the required
// order of operations and explains why the order is the point.
//
// Note what the keyring does and does not tell you: that a trusted key signed
// these bytes is not the same as that key being permitted to unlock
// maintenance mode. Separate keys sign catalogues and tokens.
Token VerifyMaintenanceToken(const std::filesystem::path& token_path,
                             const Keyring& keyring,
                             const TokenPolicy& policy);

// Verify a service-mode challenge response.
//
// The device holds a per-unit secret. A technician's tool returns the hex
// HMAC-SHA-256 over the challenge fields. Returns true iff *response_hex* is
// the expected tag. See SPEC.md section 5.4 for the exact input encoding, and
// for the two mistakes this function exists to test.
bool VerifyServiceResponse(const std::vector<uint8_t>& secret,
                           const std::string& device_id,
                           const std::string& nonce,
                           const std::string& purpose,
                           const std::string& response_hex);

} // namespace vissapp
