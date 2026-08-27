// VISS — maintenance tokens and service-mode challenge/response.
//                                        [Part 3 of 3 — authorisation]
//
// IMPLEMENT THIS FILE. See SPEC.md section 5 and include/vissapp/token.h.

#include "vissapp/token.h"

#include "vissapp/crypto_util.h"
#include "vissapp/ecdsa.h"
#include "vissapp/errors.h"
#include "vissapp/keyring.h"
#include <openssl/crypto.h>
#include <unordered_map>

namespace vissapp {

int64_t ParseDecimal(const std::string &s, const char *field) {
  if (s.empty())
    throw TokenError(std::string(field) + ": empty");
  for (unsigned char c : s) {
    if (!std::isdigit(c))
      throw TokenError(std::string(field) + ": not a decimal integer");
  }
  try {
    return std::stoll(s);
  } catch (const std::exception &) {
    throw TokenError(std::string(field) + ": not a decimal integer");
  }
}

const char *allowedKeys[] = {"purpose", "device", "created", "expires",
                             "nonce"};

bool isValidKey(const std::string &key) {
  for (const char *k : allowedKeys) {
    if (key == k)
      return true;
  }
  return false;
}

Token ParseToken(const std::vector<uint8_t> &document) {
  for (uint8_t b : document) {
    if (b == '\r') // if CR is detected
      throw TokenError("CR not allowed");
    if (b == '\0')
      throw TokenError("NUL not allowed");
  }

  std::vector<std::string> lines;
  std::string current;
  for (uint8_t b : document) {
    if (b == '\n') {
      lines.push_back(std::move(current));
      current.clear();
    } else {
      current.push_back(static_cast<char>(b));
    }
  }

  // Check for trailing newline allowed
  if (!current.empty() || (!document.empty() && document.back() != '\n')) {
    if (!document.empty() && document.back() != '\n')
      lines.push_back(std::move(current));
  }

  std::unordered_map<std::string, std::string> fields;
  for (const std::string &line : lines) {
    if (line.empty())
      throw TokenError("token has blank line");

    const auto eq = line.find('=');
    if (eq == std::string::npos)
      throw TokenError("line is not key=value pair");
    if (eq == 0)
      throw TokenError("token has empty key");

    const std::string key = line.substr(0, eq);
    const std::string value = line.substr(eq + 1);

    // for (auto allowedKey : allowedKeys) {
    //   if (key == allowedKey)
    //     break;
    //   throw TokenError("unknown key" + key);
    // }
    if (!isValidKey(key))
      throw TokenError("unknown key " + key);

    if (fields.count(key))
      throw TokenError("duplicate key");
    if (value.empty())
      throw TokenError("empty value for key" + key);

    fields.emplace(key, value);
  }

  for (const char *k : allowedKeys) {
    if (!fields.count(k))
      throw TokenError("missing key" + std::string(k));
  }

  Token t;
  t.purpose = fields["purpose"];
  t.device = fields["device"];
  t.nonce = fields["nonce"];
  t.created = ParseDecimal(fields["created"], "created");
  t.expires = ParseDecimal(fields["expires"], "expires");
  return t;
}

Token VerifyMaintenanceToken(const std::filesystem::path &token_path,
                             const Keyring &keyring,
                             const TokenPolicy &policy) {
  const std::vector<uint8_t> token_bytes = ReadFile(token_path);
  const std::vector<uint8_t> sig_bytes = ReadFile(token_path.string() + ".sig");

  const TrustedSigner *matched = nullptr;
  for (const TrustedSigner &signer : keyring.signers) {
    try {
      VerifyDetached(signer.public_key, sig_bytes, token_bytes);
      matched = &signer;
      break;
    } catch (const SignatureError &) {
    }
  }

  if (matched == nullptr)
    throw TokenError("not signed by any trusted key");

  if (matched->purposes.count(policy.required_purpose) == 0) {
    throw TokenError("signer not authorised");
  }

  const Token token = ParseToken(token_bytes);

  if (token.purpose != policy.required_purpose)
    throw TokenError("wrong purpose");

  if (token.device == "*" || token.device != policy.device_id)
    throw TokenError("token: device mismatch");

  if (!(token.expires > token.created))
    throw TokenError("token: expires must be after created");

  if (token.expires - token.created > policy.max_window)
    throw TokenError("token: validity window too long");

  if (token.created > policy.now + policy.max_clock_skew)
    throw TokenError("token: created too far in the future");

  if (!(policy.now < token.expires))
    throw TokenError("token: expired");

  return token;
}

bool VerifyServiceResponse(const std::vector<uint8_t> &secret,
                           const std::string &device_id,
                           const std::string &nonce, const std::string &purpose,
                           const std::string &response_hex) {
  const char prefix[] = "viss-service-v1";

  std::vector<uint8_t> msg;

  // msg = "viss-service-v1" || 0x00 || device_id || 0x00 || nonce  || 0x00 ||
  // purpose
  msg.reserve(sizeof(prefix) - 1 + 1 + device_id.size() + 1 + nonce.size() + 1 +
              purpose.size());
  msg.insert(msg.end(), prefix, prefix + sizeof(prefix) - 1);
  msg.push_back(0x00);
  msg.insert(msg.end(), device_id.begin(), device_id.end());
  msg.push_back(0x00);
  msg.insert(msg.end(), nonce.begin(), nonce.end());
  msg.push_back(0x00);
  msg.insert(msg.end(), purpose.begin(), purpose.end());

  uint8_t tag[32];
  HmacSha256(secret.data(), secret.size(), msg.data(), msg.size(), tag);

  const std::string expected = ToHex(tag, 32);

  if (response_hex.size() != expected.size())
    return false;

  return CRYPTO_memcmp(response_hex.data(), expected.data(), expected.size()) ==
         0;
}

} // namespace vissapp
