// VISS — maintenance tokens and service-mode challenge/response.
//                                        [Part 3 of 3 — authorisation]

#include "vissapp/token.h"

#include "vissapp/crypto_util.h"
#include "vissapp/ecdsa.h"
#include "vissapp/keyring.h"
#include "vissapp/errors.h"

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include <openssl/crypto.h>

namespace vissapp {
namespace {

bool IsDecimal(const std::string& s)
{
    if (s.empty()) {
        return false;
    }

    for (char c : s) {
        if (c < '0' || c > '9') {
            return false;
        }
    }

    return true;
}

int64_t ParseInt64(const std::string& s)
{
    if (!IsDecimal(s)) {
        throw TokenError("token: invalid integer");
    }

    try {
        size_t pos = 0;
        const long long value = std::stoll(s, &pos, 10);

        if (pos != s.size()) {
            throw TokenError("token: invalid integer");
        }

        return static_cast<int64_t>(value);
    } catch (const std::invalid_argument&) {
        throw TokenError("token: invalid integer");
    } catch (const std::out_of_range&) {
        throw TokenError("token: integer out of range");
    }
}

} // namespace

Token ParseToken(const std::vector<uint8_t>& document)
{
    // Reject NUL and CR anywhere in the document.
    for (uint8_t c : document) {
        if (c == 0) {
            throw TokenError("token: NUL byte");
        }

        if (c == '\r') {
            throw TokenError("token: carriage return");
        }
    }

    Token token;

    bool have_purpose = false;
    bool have_device = false;
    bool have_created = false;
    bool have_expires = false;
    bool have_nonce = false;

    size_t pos = 0;

    while (pos < document.size()) {
        const size_t line_start = pos;

        while (pos < document.size() && document[pos] != '\n') {
            ++pos;
        }

        const size_t line_len = pos - line_start;

        // Blank lines are forbidden.
        if (line_len == 0) {
            throw TokenError("token: blank line");
        }

        const std::string line(
            reinterpret_cast<const char*>(document.data() + line_start),
            line_len);

        const size_t equals = line.find('=');

        // A line must contain '=' and the key must be non-empty.
        if (equals == std::string::npos || equals == 0) {
            throw TokenError("token: malformed line");
        }

        const std::string key = line.substr(0, equals);
        const std::string value = line.substr(equals + 1);

        // All values must be non-empty.
        if (value.empty()) {
            throw TokenError("token: empty value");
        }

        if (key == "purpose") {
            if (have_purpose) {
                throw TokenError("token: duplicate purpose");
            }

            have_purpose = true;
            token.purpose = value;
        } else if (key == "device") {
            if (have_device) {
                throw TokenError("token: duplicate device");
            }

            have_device = true;
            token.device = value;
        } else if (key == "created") {
            if (have_created) {
                throw TokenError("token: duplicate created");
            }

            have_created = true;
            token.created = ParseInt64(value);
        } else if (key == "expires") {
            if (have_expires) {
                throw TokenError("token: duplicate expires");
            }

            have_expires = true;
            token.expires = ParseInt64(value);
        } else if (key == "nonce") {
            if (have_nonce) {
                throw TokenError("token: duplicate nonce");
            }

            have_nonce = true;
            token.nonce = value;
        } else {
            // Unknown fields are forbidden.
            throw TokenError("token: unknown key");
        }

        // Consume the LF if present. The final line may omit it.
        if (pos < document.size() && document[pos] == '\n') {
            ++pos;
        }
    }

    // Exactly these five fields are required.
    if (!have_purpose ||
        !have_device ||
        !have_created ||
        !have_expires ||
        !have_nonce) {
        throw TokenError("token: missing field");
    }

    return token;
}

Token VerifyMaintenanceToken(const std::filesystem::path& token_path,
                             const Keyring& keyring,
                             const TokenPolicy& policy)
{
    // Read the exact bytes covered by the detached signature.
    std::vector<uint8_t> document;

    try {
        document = ReadFile(token_path);
    } catch (const std::exception& e) {
        throw TokenError(
            std::string("token: cannot read token: ") + e.what());
    }

    std::vector<uint8_t> signature;

    try {
        signature = ReadFile(
            std::filesystem::path(token_path.string() + ".sig"));
    } catch (const std::exception& e) {
        throw TokenError(
            std::string("token: cannot read signature: ") + e.what());
    }

    /*
     * Step 1:
     * Establish which trusted signer signed the exact token bytes.
     *
     * Do not parse the token before authentication succeeds.
     */
    const TrustedSigner* matching_signer = nullptr;

    for (const auto& signer : keyring.signers) {
        try {
            VerifyDetached(signer.public_key, signature, document);
            matching_signer = &signer;
            break;
        } catch (const SignatureError&) {
            // This trusted signer did not sign the document.
        }
    }

    if (matching_signer == nullptr) {
        throw TokenError("token: signature not trusted");
    }

    /*
     * Step 2:
     * The signer must be authorised for the required purpose.
     */
    if (matching_signer->purposes.find(policy.required_purpose) ==
        matching_signer->purposes.end()) {
        throw TokenError("token: signer not authorised for purpose");
    }

    /*
     * Step 3:
     * Only parse the token after its signature and signer authorisation
     * have been established.
     */
    const Token token = ParseToken(document);

    /*
     * Step 4:
     * Apply the token policy.
     */

    if (token.purpose != policy.required_purpose) {
        throw TokenError("token: wrong purpose");
    }

    // Wildcard devices are deliberately forbidden.
    if (token.device == "*" || token.device != policy.device_id) {
        throw TokenError("token: wrong device");
    }

    if (token.expires <= token.created) {
        throw TokenError("token: invalid validity interval");
    }

    // Reject an invalid negative policy window.
    if (policy.max_window < 0) {
        throw TokenError("token: invalid maximum window");
    }

    /*
     * expires > created has already been checked, so this subtraction
     * is safe for ordinary valid intervals. Check the upper boundary
     * explicitly to avoid signed overflow.
     */
    if (token.expires > token.created &&
        token.expires - token.created > policy.max_window) {
        throw TokenError("token: validity window too long");
    }

    // created must not be more than max_clock_skew seconds in the future.
    if (policy.max_clock_skew < 0) {
        throw TokenError("token: invalid clock skew");
    }

    if (token.created > policy.now) {
        if (token.created - policy.now > policy.max_clock_skew) {
            throw TokenError("token: created in the future");
        }
    }

    // The token must still be valid at the trusted current time.
    if (policy.now >= token.expires) {
        throw TokenError("token: expired");
    }

    return token;
}

bool VerifyServiceResponse(const std::vector<uint8_t>& secret,
                           const std::string& device_id,
                           const std::string& nonce,
                           const std::string& purpose,
                           const std::string& response_hex)
{
    /*
     * HMAC input:
     *
     * "viss-service-v1" || 0x00 ||
     * device_id         || 0x00 ||
     * nonce             || 0x00 ||
     * purpose
     */

    const std::string prefix = "viss-service-v1";

    std::vector<uint8_t> message;
    message.reserve(prefix.size() +
                    1 +
                    device_id.size() +
                    1 +
                    nonce.size() +
                    1 +
                    purpose.size());

    message.insert(message.end(), prefix.begin(), prefix.end());
    message.push_back(0);

    message.insert(message.end(), device_id.begin(), device_id.end());
    message.push_back(0);

    message.insert(message.end(), nonce.begin(), nonce.end());
    message.push_back(0);

    message.insert(message.end(), purpose.begin(), purpose.end());

    uint8_t expected[32];

    HmacSha256(secret.data(),
               secret.size(),
               message.data(),
               message.size(),
               expected);

    // ToHex produces the required lowercase hexadecimal representation.
    const std::string expected_hex = ToHex(expected, sizeof(expected));

    // Different lengths cannot match.
    if (response_hex.size() != expected_hex.size()) {
        return false;
    }

    // Constant-time comparison; do not use == here.
    return CRYPTO_memcmp(response_hex.data(),
                         expected_hex.data(),
                         expected_hex.size()) == 0;
}

} // namespace vissapp
