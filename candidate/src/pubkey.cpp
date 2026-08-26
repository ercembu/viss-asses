// VISS — P-256 public key parsing. PROVIDED CODE.
//
// Complete, no TODOs. Walks a PEM SubjectPublicKeyInfo, checks the algorithm
// and curve OIDs, and confirms the point lies on the curve.
//
// The DER cursor below is file-local on purpose: the signature parser in
// ecdsa.cpp is yours to write, and its rules are stricter than these.

#include "vissapp/ecdsa.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <cstring>
#include <memory>
#include <vector>

#include "vissapp/crypto_util.h"
#include "vissapp/errors.h"

namespace vissapp {
namespace {

using BnPtr    = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using CtxPtr   = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using GroupPtr = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
using PointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;

BnPtr NewBn() { return BnPtr(BN_new(), &BN_free); }

// id-ecPublicKey 1.2.840.10045.2.1
const uint8_t kOidEcPublicKey[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
// prime256v1 1.2.840.10045.3.1.7
const uint8_t kOidPrime256v1[]  = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};

// A cursor over a DER buffer that refuses non-minimal and truncated encodings.
class Der {
public:
    Der(const uint8_t* p, size_t n) : p_(p), end_(p + n) {}

    size_t remaining() const { return static_cast<size_t>(end_ - p_); }
    bool   empty() const { return p_ == end_; }

    // Read one TLV with the expected tag; returns a cursor over its contents.
    Der Read(uint8_t tag, const char* what)
    {
        if (remaining() < 2) throw SignatureError(std::string(what) + ": truncated");
        if (*p_++ != tag)
            throw SignatureError(std::string(what) + ": unexpected DER tag");

        const uint8_t first = *p_++;
        size_t length = 0;
        if (first < 0x80) {
            length = first;
        } else {
            const uint8_t count = first & 0x7F;
            // DER requires the shortest possible length encoding, and forbids
            // the indefinite form outright.
            if (count == 0 || count > 4)
                throw SignatureError(std::string(what) + ": bad DER length form");
            if (remaining() < count)
                throw SignatureError(std::string(what) + ": truncated length");
            for (uint8_t i = 0; i < count; i++) length = (length << 8) | *p_++;
            if (length < 0x80)
                throw SignatureError(std::string(what) +
                                     ": non-minimal DER length");
        }
        if (remaining() < length)
            throw SignatureError(std::string(what) + ": truncated contents");

        Der inner(p_, length);
        p_ += length;
        return inner;
    }

    // A DER INTEGER holding a non-negative, minimally-encoded value.
    std::vector<uint8_t> ReadUnsignedInteger(const char* what)
    {
        Der v = Read(0x02, what);
        const size_t n = v.remaining();
        if (n == 0) throw SignatureError(std::string(what) + ": empty INTEGER");
        const uint8_t* b = v.p_;
        if (b[0] & 0x80)
            throw SignatureError(std::string(what) + ": negative INTEGER");
        // A leading zero is only permitted to clear the sign bit.
        if (n > 1 && b[0] == 0x00 && !(b[1] & 0x80))
            throw SignatureError(std::string(what) +
                                 ": non-minimal INTEGER encoding");
        std::vector<uint8_t> out(b, b + n);
        if (out.size() > 1 && out[0] == 0x00) out.erase(out.begin());
        return out;
    }

    void ExpectOid(const uint8_t* oid, size_t oid_len, const char* what)
    {
        Der v = Read(0x06, what);
        if (v.remaining() != oid_len ||
            std::memcmp(v.p_, oid, oid_len) != 0)
            throw SignatureError(std::string(what) + ": unexpected OID");
    }

    const uint8_t* data() const { return p_; }

private:
    const uint8_t* p_;
    const uint8_t* end_;
};


GroupPtr P256()
{
    GroupPtr g(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), &EC_GROUP_free);
    if (!g) throw SignatureError("cannot construct P-256 group");
    return g;
}

BnPtr BnFrom(const uint8_t* be, size_t len)
{
    BnPtr n = NewBn();
    if (!n || !BN_bin2bn(be, static_cast<int>(len), n.get()))
        throw SignatureError("cannot load big-endian integer");
    return n;
}


} // namespace

PublicKey ParsePublicKeyPem(const std::string& pem)
{
    const std::string kBegin = "-----BEGIN PUBLIC KEY-----";
    const std::string kEnd   = "-----END PUBLIC KEY-----";
    const size_t b = pem.find(kBegin);
    const size_t e = pem.find(kEnd);
    if (b == std::string::npos || e == std::string::npos || e <= b)
        throw SignatureError("public key: PEM armour not found");

    const std::string body = pem.substr(b + kBegin.size(),
                                        e - b - kBegin.size());
    std::vector<uint8_t> der;
    try {
        der = Base64Decode(body);
    } catch (const VissappError& ex) {
        throw SignatureError(std::string("public key: ") + ex.what());
    }

    // SubjectPublicKeyInfo ::= SEQUENCE {
    //     algorithm  SEQUENCE { OID id-ecPublicKey, OID prime256v1 },
    //     publicKey  BIT STRING }
    Der top(der.data(), der.size());
    Der spki = top.Read(0x30, "public key");
    if (!top.empty()) throw SignatureError("public key: trailing data");

    Der alg = spki.Read(0x30, "public key algorithm");
    alg.ExpectOid(kOidEcPublicKey, sizeof(kOidEcPublicKey), "public key algorithm");
    alg.ExpectOid(kOidPrime256v1, sizeof(kOidPrime256v1), "public key curve");
    if (!alg.empty())
        throw SignatureError("public key: trailing algorithm parameters");

    Der bits = spki.Read(0x03, "public key bit string");
    if (!spki.empty()) throw SignatureError("public key: trailing data in SPKI");
    if (bits.remaining() != 1 + 65)
        throw SignatureError("public key: unexpected point length");

    const uint8_t* raw = bits.data();
    if (raw[0] != 0x00)
        throw SignatureError("public key: unused bits in BIT STRING");
    if (raw[1] != 0x04)
        throw SignatureError("public key: point is not uncompressed");

    PublicKey key;
    std::memcpy(key.x.data(), raw + 2, 32);
    std::memcpy(key.y.data(), raw + 34, 32);

    // The point must actually lie on the curve; a point that does not is a
    // classic route to leaking a private key in schemes that use one.
    GroupPtr group = P256();
    CtxPtr ctx(BN_CTX_new(), &BN_CTX_free);
    PointPtr point(EC_POINT_new(group.get()), &EC_POINT_free);
    BnPtr x = BnFrom(key.x.data(), key.x.size());
    BnPtr y = BnFrom(key.y.data(), key.y.size());
    if (!EC_POINT_set_affine_coordinates(group.get(), point.get(), x.get(),
                                         y.get(), ctx.get()) ||
        !EC_POINT_is_on_curve(group.get(), point.get(), ctx.get()) ||
        EC_POINT_is_at_infinity(group.get(), point.get())) {
        throw SignatureError("public key: point is not on the P-256 curve");
    }
    return key;
}

} // namespace vissapp
