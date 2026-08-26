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

namespace vissapp {

Signature ParseSignatureDer(const uint8_t* der, size_t len)
{
    (void)der; (void)len;
    throw SignatureError("TODO: ParseSignatureDer");
}

bool Verify(const PublicKey& key, const Signature& sig,
            const uint8_t* msg, size_t msg_len)
{
    (void)key; (void)sig; (void)msg; (void)msg_len;
    throw SignatureError("TODO: Verify");
}

void VerifyDetached(const std::string& pubkey_pem,
                    const std::vector<uint8_t>& signature_der,
                    const std::vector<uint8_t>& message)
{
    (void)pubkey_pem; (void)signature_der; (void)message;
    throw SignatureError("TODO: VerifyDetached");
}

} // namespace vissapp
