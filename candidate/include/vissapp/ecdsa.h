#pragma once
// VISS — ECDSA P-256 signature verification.  [Part 2 of 3 — signatures]
//
// IMPLEMENT src/ecdsa.cpp. See SPEC.md section 4.
//
// You implement the encodings and the verification equation. libcrypto's
// BIGNUM / EC_POINT are available for the field and group arithmetic, and
// using them is the expected approach — you are not being asked to write
// modular arithmetic. What you must not use is a one-shot verify such as
// EVP_DigestVerify or ECDSA_do_verify: that is the function you are writing.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vissapp {

// An uncompressed P-256 point: 32-byte big-endian affine coordinates.
struct PublicKey {
    std::array<uint8_t, 32> x{};
    std::array<uint8_t, 32> y{};
};

// The two ECDSA scalars, 32-byte big-endian.
struct Signature {
    std::array<uint8_t, 32> r{};
    std::array<uint8_t, 32> s{};
};

// Parse a PEM SubjectPublicKeyInfo holding an uncompressed P-256 point.
//
// PROVIDED — implemented in src/pubkey.cpp. Throws SignatureError if the PEM
// is malformed, if the algorithm or curve is anything other than
// id-ecPublicKey over prime256v1, or if the point is not on the curve.
PublicKey ParsePublicKeyPem(const std::string& pem);

// Parse a DER ECDSA-Sig-Value: SEQUENCE { INTEGER r, INTEGER s }.
//
// Throws SignatureError on anything that is not valid, minimal DER, or on a
// scalar outside [1, n-1]. SPEC.md section 4.2 lists what "minimal" rules out
// and why each rule is there.
Signature ParseSignatureDer(const uint8_t* der, size_t len);

// Verify a signature over *msg* using SHA-256 as the message digest.
// Returns true when the signature is valid, false when it is not.
//
// A malformed input is an exception, not a false return: reject encodings in
// the parsers above, and let this function do arithmetic on values already
// known to be well-formed. See SPEC.md section 4.3 for the equation and for
// the checks that are easy to leave out.
bool Verify(const PublicKey& key, const Signature& sig,
            const uint8_t* msg, size_t msg_len);

// Convenience: parse both encodings, verify, and throw SignatureError on any
// failure. This is what the rest of the library calls.
void VerifyDetached(const std::string& pubkey_pem,
                    const std::vector<uint8_t>& signature_der,
                    const std::vector<uint8_t>& message);

} // namespace vissapp
