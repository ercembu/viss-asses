// VISS — ECDSA P-256 signature verification.   [Part 2 of 3 — signatures]
//
// IMPLEMENT THIS FILE. See SPEC.md section 4 and include/vissapp/ecdsa.h.

#include "vissapp/ecdsa.h"

#include "vissapp/crypto_util.h"
#include "vissapp/errors.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <memory>

namespace vissapp {
namespace {

using BNPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using BNCTXPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using ECGroupPtr = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
using ECPointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;

uint32_t ReadDerLength(const uint8_t*& p, const uint8_t* end)
{
    if (p >= end) {
        throw SignatureError("truncated DER length");
    }

    const uint8_t first = *p++;

    // DER short form.
    if ((first & 0x80) == 0) {
        return first;
    }

    // Indefinite-length encoding is BER, not DER.
    const size_t count = first & 0x7F;

    if (count == 0) {
        throw SignatureError("indefinite DER length");
    }

    // ECDSA P-256 signatures are tiny. More than four length bytes
    // is invalid for our purposes and avoids overflow.
    if (count > 4 || static_cast<size_t>(end - p) < count) {
        throw SignatureError("invalid DER length");
    }

    // DER requires the shortest length representation.
    if (*p == 0) {
        throw SignatureError("non-minimal DER length");
    }

    uint32_t value = 0;

    for (size_t i = 0; i < count; ++i) {
        value = (value << 8) | *p++;
    }

    // Long form is only valid for lengths >= 128.
    if (value < 128) {
        throw SignatureError("long-form DER length when short form fits");
    }

    return value;
}

const uint8_t* ReadDerInteger(const uint8_t*& p,
                              const uint8_t* end,
                              size_t& integer_len)
{
    if (p >= end || *p++ != 0x02) {
        throw SignatureError("expected DER INTEGER");
    }

    const uint32_t len = ReadDerLength(p, end);

    if (len == 0 || static_cast<size_t>(end - p) < len) {
        throw SignatureError("empty or truncated DER INTEGER");
    }

    const uint8_t* value = p;
    p += len;

    // Negative INTEGERs are not valid ECDSA scalars.
    if ((value[0] & 0x80) != 0) {
        throw SignatureError("negative ECDSA scalar");
    }

    // A leading zero is allowed only when required to keep the
    // INTEGER positive.
    if (len > 1 && value[0] == 0x00 &&
        (value[1] & 0x80) == 0) {
        throw SignatureError("non-minimal DER INTEGER");
    }

    integer_len = len;
    return value;
}

BIGNUM* BytesToBN(const uint8_t* data, size_t len)
{
    BIGNUM* bn = BN_bin2bn(data, static_cast<int>(len), nullptr);

    if (bn == nullptr) {
        throw SignatureError("failed to create BIGNUM");
    }

    return bn;
}

} // namespace

Signature ParseSignatureDer(const uint8_t* der, size_t len)
{
    if (der == nullptr || len == 0) {
        throw SignatureError("empty DER signature");
    }

    const uint8_t* p = der;
    const uint8_t* end = der + len;

    // ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
    if (p >= end || *p++ != 0x30) {
        throw SignatureError("ECDSA signature is not a SEQUENCE");
    }

    const uint32_t sequence_len = ReadDerLength(p, end);

    // The outer SEQUENCE must consume the entire input.
    if (static_cast<size_t>(end - p) != sequence_len) {
        throw SignatureError("invalid ECDSA SEQUENCE length");
    }

    const uint8_t* sequence_end = p + sequence_len;

    size_t r_len = 0;
    const uint8_t* r_bytes =
        ReadDerInteger(p, sequence_end, r_len);

    size_t s_len = 0;
    const uint8_t* s_bytes =
        ReadDerInteger(p, sequence_end, s_len);

    // No bytes may remain inside the SEQUENCE.
    if (p != sequence_end) {
        throw SignatureError("trailing data in ECDSA signature");
    }

    // Parse the two integers.
    BNPtr r_bn(BytesToBN(r_bytes, r_len), &BN_free);
    BNPtr s_bn(BytesToBN(s_bytes, s_len), &BN_free);

    BNCTXPtr ctx(BN_CTX_new(), &BN_CTX_free);
    ECGroupPtr group(
        EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1),
        &EC_GROUP_free);

    if (!ctx || !group) {
        throw SignatureError("failed to initialise P-256");
    }

    const BIGNUM* order = EC_GROUP_get0_order(group.get());

    if (order == nullptr) {
        throw SignatureError("failed to obtain P-256 order");
    }

    // ECDSA requires 1 <= r,s <= n-1.
    if (BN_is_zero(r_bn.get()) ||
        BN_cmp(r_bn.get(), order) >= 0 ||
        BN_is_zero(s_bn.get()) ||
        BN_cmp(s_bn.get(), order) >= 0) {
        throw SignatureError("ECDSA scalar outside [1,n-1]");
    }

    Signature result{};

    // P-256 scalars are exactly 32 bytes.
    if (r_len > 33 || s_len > 33) {
        throw SignatureError("ECDSA scalar too large");
    }

    // Convert the validated integers to exactly 32-byte big-endian values.
    if (BN_bn2binpad(r_bn.get(), result.r.data(), 32) != 32 ||
        BN_bn2binpad(s_bn.get(), result.s.data(), 32) != 32) {
        throw SignatureError("failed to encode ECDSA scalar");
    }

    return result;
}

bool Verify(const PublicKey& key, const Signature& sig,
            const uint8_t* msg, size_t msg_len)
{
    if (msg == nullptr && msg_len != 0) {
        throw SignatureError("null message");
    }

    ECGroupPtr group(
        EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1),
        &EC_GROUP_free);

    BNCTXPtr ctx(BN_CTX_new(), &BN_CTX_free);

    if (!group || !ctx) {
        throw SignatureError("failed to initialise P-256");
    }

    const BIGNUM* order = EC_GROUP_get0_order(group.get());

    if (order == nullptr) {
        throw SignatureError("failed to obtain P-256 order");
    }

    // Convert the fixed-width public key coordinates into BIGNUMs.
    BNPtr qx(BN_bin2bn(key.x.data(), 32, nullptr), &BN_free);
    BNPtr qy(BN_bin2bn(key.y.data(), 32, nullptr), &BN_free);

    if (!qx || !qy) {
        throw SignatureError("failed to create public key coordinates");
    }

    // Construct the public key point Q.
    ECPointPtr Q(EC_POINT_new(group.get()), &EC_POINT_free);

    if (!Q) {
        throw SignatureError("failed to allocate public key point");
    }

    if (EC_POINT_set_affine_coordinates(
            group.get(), Q.get(), qx.get(), qy.get(), ctx.get()) != 1) {
        throw SignatureError("invalid public key point");
    }

    // Hash the message using SHA-256.
    uint8_t digest[32];
    Sha256(msg, msg_len, digest);

    BNPtr e(BN_bin2bn(digest, 32, nullptr), &BN_free);

    // Convert r and s from the fixed-width arrays.
    BNPtr r(BN_bin2bn(sig.r.data(), 32, nullptr), &BN_free);
    BNPtr s(BN_bin2bn(sig.s.data(), 32, nullptr), &BN_free);

    if (!e || !r || !s) {
        throw SignatureError("failed to create ECDSA values");
    }

    // Verify() receives a Signature structure rather than the DER
    // encoding, so validate its scalar range here too.
    if (BN_is_zero(r.get()) ||
        BN_cmp(r.get(), order) >= 0 ||
        BN_is_zero(s.get()) ||
        BN_cmp(s.get(), order) >= 0) {
        throw SignatureError("ECDSA scalar outside [1,n-1]");
    }

    // w = s^-1 mod n
    BNPtr w(
        BN_mod_inverse(nullptr, s.get(), order, ctx.get()),
        &BN_free);

    if (!w) {
        throw SignatureError("failed to calculate s inverse");
    }

    // u1 = e*w mod n
    BNPtr u1(BN_new(), &BN_free);

    // u2 = r*w mod n
    BNPtr u2(BN_new(), &BN_free);

    if (!u1 || !u2) {
        throw SignatureError("failed to allocate ECDSA scalars");
    }

    if (BN_mod_mul(u1.get(), e.get(), w.get(),
                   order, ctx.get()) != 1 ||
        BN_mod_mul(u2.get(), r.get(), w.get(),
                   order, ctx.get()) != 1) {
        throw SignatureError("failed to calculate ECDSA scalars");
    }

    // R = u1*G + u2*Q
    ECPointPtr R(EC_POINT_new(group.get()), &EC_POINT_free);

    if (!R) {
        throw SignatureError("failed to allocate result point");
    }

    if (EC_POINT_mul(group.get(),
                     R.get(),
                     u1.get(),
                     Q.get(),
                     u2.get(),
                     ctx.get()) != 1) {
        throw SignatureError("EC_POINT_mul failed");
    }

    // The point at infinity must be rejected.
    if (EC_POINT_is_at_infinity(group.get(), R.get()) == 1) {
        return false;
    }

    BNPtr rx(BN_new(), &BN_free);
    BNPtr ry(BN_new(), &BN_free);

    if (!rx || !ry) {
        throw SignatureError("failed to allocate coordinates");
    }

    if (EC_POINT_get_affine_coordinates(
            group.get(), R.get(),
            rx.get(), ry.get(), ctx.get()) != 1) {
        throw SignatureError("failed to obtain R coordinates");
    }

    // Accept iff (R.x mod n) == r.
    if (BN_nnmod(rx.get(), rx.get(), order, ctx.get()) != 1) {
        throw SignatureError("failed to reduce R.x");
    }

    return BN_cmp(rx.get(), r.get()) == 0;
}

void VerifyDetached(const std::string& pubkey_pem,
                    const std::vector<uint8_t>& signature_der,
                    const std::vector<uint8_t>& message)
{
    PublicKey key = ParsePublicKeyPem(pubkey_pem);

    Signature sig =
        ParseSignatureDer(signature_der.data(), signature_der.size());

    if (!Verify(key, sig, message.data(), message.size())) {
        throw SignatureError("signature verification failed");
    }
}

} // namespace vissapp
