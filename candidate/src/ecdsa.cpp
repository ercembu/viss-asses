// VISS — ECDSA P-256 signature verification.   [Part 2 of 3 — signatures]
//
// IMPLEMENT THIS FILE. See SPEC.md section 4 and include/vissapp/ecdsa.h.
//
// ParsePublicKeyPem is already written for you in src/pubkey.cpp. What is
// left is the signature encoding and the verification equation.
//
// libcrypto's BIGNUM and EC_POINT are available and are the expected way to
// do the arithmetic:
//
//   #include <openssl/bn.h>
//   #include <openssl/ec.h>
//   EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)
//   EC_GROUP_get0_order, BN_mod_inverse, BN_mod_mul, BN_nnmod
//   EC_POINT_mul, EC_POINT_get_affine_coordinates, EC_POINT_is_at_infinity
//
// What you must NOT use is a one-shot verify — EVP_DigestVerify,
// ECDSA_do_verify, ECDSA_verify. Those are the function you are writing.

#include "vissapp/ecdsa.h"

#include "vissapp/crypto_util.h"
#include "vissapp/errors.h"
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <string>
#include <vector>

namespace vissapp {
// Use same rules as pubkey.cpp for DER Cursor

namespace {

using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using CtxPtr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using GroupPtr = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
using PointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;

BnPtr NewBn() { return BnPtr(BN_new(), &BN_free); }

GroupPtr P256() {
  GroupPtr g(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), &EC_GROUP_free);
  if (!g)
    throw SignatureError("cannot construct P-256 group");
  return g;
}

BnPtr BnFrom(const uint8_t *be, size_t len) {
  BnPtr n = NewBn();
  if (!n || !BN_bin2bn(be, static_cast<int>(len), n.get()))
    throw SignatureError("cannot load big-endian integer");
  return n;
}

class Der {
public:
  Der(const uint8_t *p, size_t n) : p_(p), end_(p + n) {}
  size_t remaining() const { return static_cast<size_t>(end_ - p_); }
  bool empty() const { return p_ == end_; }
  Der Read(uint8_t tag, const char *what) {
    if (remaining() < 2)
      throw SignatureError(std::string(what) + ": truncated");
    if (*p_++ != tag)
      throw SignatureError(std::string(what) + ": unexpected DER tag");
    const uint8_t first = *p_++;
    size_t length = 0;
    if (first < 0x80) {
      length = first;
    } else {
      const uint8_t count = first & 0x7F;
      if (count == 0 || count > 4)
        throw SignatureError(std::string(what) + ": bad DER length form");
      if (remaining() < count)
        throw SignatureError(std::string(what) + ": truncated length");
      for (uint8_t i = 0; i < count; i++)
        length = (length << 8) | *p_++;
      // Long form when short form would fit → non-minimal DER.
      if (length < 0x80)
        throw SignatureError(std::string(what) + ": non-minimal DER length");
    }
    if (remaining() < length)
      throw SignatureError(std::string(what) + ": truncated contents");
    Der inner(p_, length);
    p_ += length;
    return inner;
  }
  std::vector<uint8_t> ReadUnsignedInteger(const char *what) {
    Der v = Read(0x02, what);
    const size_t n = v.remaining();
    if (n == 0)
      throw SignatureError(std::string(what) + ": empty INTEGER");
    const uint8_t *b = v.p_;
    if (b[0] & 0x80)
      throw SignatureError(std::string(what) + ": negative INTEGER");
    // Leading 0x00 only allowed to clear the sign bit of the next byte.
    if (n > 1 && b[0] == 0x00 && !(b[1] & 0x80))
      throw SignatureError(std::string(what) +
                           ": non-minimal INTEGER encoding");
    std::vector<uint8_t> out(b, b + n);
    if (out.size() > 1 && out[0] == 0x00)
      out.erase(out.begin());
    return out;
  }

private:
  const uint8_t *p_;
  const uint8_t *end_;
};

void RequireScalarInRange(const BIGNUM *v, const BIGNUM *n, const char *what) {
  if (BN_is_zero(v) || BN_cmp(v, n) >= 0)
    throw SignatureError(std::string(what) + ": out of range");
}

void BnToFixed32(const BIGNUM *v, std::array<uint8_t, 32> &out) {
  if (BN_bn2binpad(v, out.data(), 32) != 32)
    throw SignatureError("Cannot encode scalar");
}
} // namespace

Signature ParseSignatureDer(const uint8_t *der, size_t len) {

  Der top(der, len);
  Der seq = top.Read(0x30, "signature");
  if (!top.empty())
    throw SignatureError("signature: trailing data");

  const std::vector<uint8_t> r_bytes = seq.ReadUnsignedInteger("signature r");
  const std::vector<uint8_t> s_bytes = seq.ReadUnsignedInteger("signature s");
  if (!seq.empty())
    throw SignatureError("signature: trailling data in SEQUENCE");

  GroupPtr group = P256();
  const BIGNUM *n = EC_GROUP_get0_order(group.get());
  if (!n)
    throw SignatureError("cannot get P-256 order");

  BnPtr r = BnFrom(r_bytes.data(), r_bytes.size());
  BnPtr s = BnFrom(s_bytes.data(), s_bytes.size());

  RequireScalarInRange(r.get(), n, "signature r");
  RequireScalarInRange(s.get(), n, "signature s");

  Signature sig{};
  BnToFixed32(r.get(), sig.r);
  BnToFixed32(s.get(), sig.s);

  return sig;
}

bool Verify(const PublicKey &key, const Signature &sig, const uint8_t *msg,
            size_t msg_len) {
  uint8_t digest[32];
  Sha256(msg, msg_len, digest);

  GroupPtr group = P256();
  CtxPtr ctx(BN_CTX_new(), &BN_CTX_free);
  if (!ctx)
    throw SignatureError("cannot allocate BN_CTX");

  const BIGNUM *n = EC_GROUP_get0_order(group.get());
  if (!n)
    throw SignatureError("cannot get P-256 order");

  BnPtr e = BnFrom(digest, sizeof(digest));
  BnPtr r = BnFrom(sig.r.data(), sig.r.size());
  BnPtr s = BnFrom(sig.s.data(), sig.s.size());

  // verification equation
  // w  := s⁻¹ mod n
  // u1 := e·w mod n
  // u2 := r·w mod n
  // R  := u1·G + u2·Q          -- EC_POINT_mul does both terms at once
  // reject if R is the point at infinity
  // accept iff (R.x mod n) == r

  BnPtr w = NewBn();
  if (!BN_mod_inverse(w.get(), s.get(), n, ctx.get()))
    return false;

  BnPtr u1 = NewBn();
  BnPtr u2 = NewBn();
  if (!BN_mod_mul(u1.get(), e.get(), w.get(), n, ctx.get()) ||
      !BN_mod_mul(u2.get(), r.get(), w.get(), n, ctx.get()))
    return false;

  PointPtr Q(EC_POINT_new(group.get()), &EC_POINT_free);
  BnPtr qx = BnFrom(key.x.data(), key.x.size());
  BnPtr qy = BnFrom(key.y.data(), key.y.size());
  if (!Q || !EC_POINT_set_affine_coordinates(group.get(), Q.get(), qx.get(),
                                             qy.get(), ctx.get()))
    throw SignatureError("public key: invalid point");

  PointPtr R(EC_POINT_new(group.get()), &EC_POINT_free);
  if (!R || !EC_POINT_mul(group.get(), R.get(), u1.get(), Q.get(), u2.get(),
                          ctx.get()))
    return false;

  // Check point at infinity
  if (EC_POINT_is_at_infinity(group.get(), R.get()))
    return false;

  BnPtr rx = NewBn();
  BnPtr ry = NewBn();
  if (!EC_POINT_get_affine_coordinates(group.get(), R.get(), rx.get(), ry.get(),
                                       ctx.get()))
    return false;

  // Check for rx mod n
  if (!BN_nnmod(rx.get(), rx.get(), n, ctx.get()))
    return false;

  return BN_cmp(rx.get(), r.get()) == 0;
}

void VerifyDetached(const std::string &pubkey_pem,
                    const std::vector<uint8_t> &signature_der,
                    const std::vector<uint8_t> &message) {
  const PublicKey pubkey = ParsePublicKeyPem(pubkey_pem);
  const Signature sig =
      ParseSignatureDer(signature_der.data(), signature_der.size());

  if (!Verify(pubkey, sig, message.data(), message.size()))
    throw SignatureError("Signature verification failed");
}

} // namespace vissapp
