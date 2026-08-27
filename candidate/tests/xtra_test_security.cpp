// VISS — additional security and negative tests.
//
// These tests exercise the hostile/malformed fixture corpus and edge cases
// described in SPEC.md. The basic happy-path tests live in test_public.cpp.

#include "viss_test.h"
#include "test_support.h"

#include "vissapp/crypto_util.h"
#include "vissapp/ecdsa.h"
#include "vissapp/errors.h"
#include "vissapp/hashtree.h"
#include "vissapp/json.h"
#include "vissapp/token.h"

#include <string>
#include <vector>

using namespace vissapp;
using namespace vissapp_test;


// ── Part 1: hash tree ───────────────────────────────────────────────────────

TEST(Hash, AllManifestBundlesHaveExpectedRoot)
{
    JsonDoc doc =
        JsonDoc::ParseFile(Fixtures() / "bundles" / "manifest.json");

    const cJSON* bundles =
        cJSON_GetObjectItemCaseSensitive(doc.root(), "bundles");

    ASSERT_TRUE(bundles != nullptr);

    const int count = cJSON_GetArraySize(bundles);
    ASSERT_TRUE(count > 0);

    for (int i = 0; i < count; ++i) {
        const cJSON* bundle =
            cJSON_GetArrayItem(bundles, i);

        ASSERT_TRUE(bundle != nullptr);

        const cJSON* file_item =
            cJSON_GetObjectItemCaseSensitive(bundle, "file");

        const cJSON* offset_item =
            cJSON_GetObjectItemCaseSensitive(bundle, "hash_offset");

        const cJSON* root_item =
            cJSON_GetObjectItemCaseSensitive(bundle, "root_hash");

        ASSERT_TRUE(file_item != nullptr);
        ASSERT_TRUE(offset_item != nullptr);
        ASSERT_TRUE(root_item != nullptr);

        const std::string file = file_item->valuestring;

        const int64_t hash_offset =
            static_cast<int64_t>(offset_item->valuedouble);

        const std::string expected =
            root_item->valuestring;

        const std::string actual =
            ComputeRootHash(
                Fixtures() / "bundles" / file,
                hash_offset);

        const cJSON* mismatch_item =
            cJSON_GetObjectItemCaseSensitive(
                bundle, "expect_mismatch");

        const bool expect_mismatch =
            mismatch_item != nullptr &&
            cJSON_IsTrue(mismatch_item);

        if (expect_mismatch) {
            EXPECT_TRUE(actual != expected);
        } else {
            EXPECT_STREQ(actual.c_str(), expected.c_str());
        }
    }
}


// ── Part 2: DER signature parsing ──────────────────────────────────────────

TEST(Sig, MalformedDerSignaturesAreRejected)
{
    const std::vector<std::string> malformed = {
        "empty.der",
        "leading-zero-r.der",
        "long-form-length.der",
        "negative-r.der",
        "not-a-sequence.der",
        "r-equals-n.der",
        "r-zero.der",
        "s-equals-n.der",
        "s-zero.der",
        "trailing-byte.der",
        "truncated.der"
    };

    for (const std::string& name : malformed) {
        const std::vector<uint8_t> der =
            ReadFile(Sig(name));

        bool rejected = false;

        try {
            (void)ParseSignatureDer(
                der.data(),
                der.size());
        } catch (const SignatureError&) {
            rejected = true;
        }

        EXPECT_TRUE(rejected);
    }
}


TEST(Sig, MalformedDerIsRejectedByDetachedVerifier)
{
    const std::string public_key =
        ReadTextFile(Sig("signer.pub"));

    const std::vector<uint8_t> message =
        ReadFile(Sig("message.bin"));

    const std::vector<std::string> malformed = {
        "empty.der",
        "leading-zero-r.der",
        "long-form-length.der",
        "negative-r.der",
        "not-a-sequence.der",
        "r-equals-n.der",
        "r-zero.der",
        "s-equals-n.der",
        "s-zero.der",
        "trailing-byte.der",
        "truncated.der"
    };

    for (const std::string& name : malformed) {
        bool rejected = false;

        try {
            VerifyDetached(
                public_key,
                ReadFile(Sig(name)),
                message);
        } catch (const SignatureError&) {
            rejected = true;
        }

        EXPECT_TRUE(rejected);
    }
}


// ── Part 2: ECDSA verification ──────────────────────────────────────────────

TEST(Sig, WrongKeySignatureReturnsFalse)
{
    const PublicKey key =
        ParsePublicKeyPem(
            ReadTextFile(Sig("signer.pub")));

    const std::vector<uint8_t> der =
        ReadFile(Sig("wrong-key.der"));

    const Signature signature =
        ParseSignatureDer(
            der.data(),
            der.size());

    const std::vector<uint8_t> message =
        ReadFile(Sig("message.bin"));

    EXPECT_FALSE(
        Verify(
            key,
            signature,
            message.data(),
            message.size()));
}


TEST(Sig, WrongMessageSignatureReturnsFalse)
{
    const PublicKey key =
        ParsePublicKeyPem(
            ReadTextFile(Sig("signer.pub")));

    const std::vector<uint8_t> der =
        ReadFile(Sig("wrong-message.der"));

    const Signature signature =
        ParseSignatureDer(
            der.data(),
            der.size());

    const std::vector<uint8_t> message =
        ReadFile(Sig("message.bin"));

    EXPECT_FALSE(
        Verify(
            key,
            signature,
            message.data(),
            message.size()));
}


TEST(Sig, OtherSignerDoesNotVerifyGenuineSignature)
{
    const std::vector<uint8_t> der =
        ReadFile(Sig("valid.der"));

    const std::vector<uint8_t> message =
        ReadFile(Sig("message.bin"));

    const PublicKey other_key =
        ParsePublicKeyPem(
            ReadTextFile(Sig("other-signer.pub")));

    const Signature signature =
        ParseSignatureDer(
            der.data(),
            der.size());

    EXPECT_FALSE(
        Verify(
            other_key,
            signature,
            message.data(),
            message.size()));
}


TEST(Sig, SMinusSignatureIsStillValid)
{
    bool rejected = false;

    try {
        VerifyDetached(
            ReadTextFile(Sig("signer.pub")),
            ReadFile(Sig("s-malleable.der")),
            ReadFile(Sig("message.bin")));
    } catch (const VissappError&) {
        rejected = true;
    }

    EXPECT_FALSE(rejected);
}


// ── Part 2: public-key validation ──────────────────────────────────────────

TEST(Sig, InvalidPublicKeysAreRejected)
{
    const std::vector<std::string> invalid_keys = {
        "not-a-key.pub",
        "off-curve.pub",
        "truncated-key.pub",
        "wrong-curve.pub"
    };

    for (const std::string& name : invalid_keys) {
        bool rejected = false;

        try {
            (void)ParsePublicKeyPem(
                ReadTextFile(Sig(name)));
        } catch (const SignatureError&) {
            rejected = true;
        }

        EXPECT_TRUE(rejected);
    }
}


TEST(Sig, InvalidPublicKeysAreRejectedByDetachedVerifier)
{
    const std::vector<uint8_t> signature =
        ReadFile(Sig("valid.der"));

    const std::vector<uint8_t> message =
        ReadFile(Sig("message.bin"));

    const std::vector<std::string> invalid_keys = {
        "not-a-key.pub",
        "off-curve.pub",
        "truncated-key.pub",
        "wrong-curve.pub"
    };

    for (const std::string& name : invalid_keys) {
        bool rejected = false;

        try {
            VerifyDetached(
                ReadTextFile(Sig(name)),
                signature,
                message);
        } catch (const SignatureError&) {
            rejected = true;
        }

        EXPECT_TRUE(rejected);
    }
}


// ── Part 3: token parsing ──────────────────────────────────────────────────

TEST(Token, MalformedTokenDocumentsAreRejected)
{
    const std::vector<std::string> malformed = {
        "crlf",
        "duplicate-purpose",
        "empty",
        "missing-device",
        "missing-expires",
        "unknown-field"
    };

    for (const std::string& name : malformed) {
        bool rejected = false;

        try {
            (void)ParseToken(
                ReadFile(TokenPath(name)));
        } catch (const TokenError&) {
            rejected = true;
        }

        EXPECT_TRUE(rejected);
    }
}


// ── Part 3: end-to-end maintenance-token policy ─────────────────────────────

TEST(Token, InvalidMaintenanceTokensAreRejected)
{
    const std::vector<std::string> invalid = {
        "crlf",
        "duplicate-purpose",
        "empty",
        "expired",
        "expires-before-created",
        "future-created",
        "missing-device",
        "missing-expires",
        "over-long-window",
        "signed-by-catalog-signer",
        "signed-by-unknown-key",
        "tampered",
        "unknown-field",
        "wildcard-device",
        "wrong-purpose"
    };

    TokenPolicy policy;
    policy.device_id = "CM5-0001-A7F3";
    policy.now = FixtureNow();

    const Keyring keyring =
        DeviceKeyring();

    for (const std::string& name : invalid) {
        bool rejected = false;

        try {
            (void)VerifyMaintenanceToken(
                TokenPath(name),
                keyring,
                policy);
        } catch (const TokenError&) {
            rejected = true;
        }

        EXPECT_TRUE(rejected);
    }
}


TEST(Token, TokenWithoutFinalNewlineIsAccepted)
{
    TokenPolicy policy;
    policy.device_id = "CM5-0001-A7F3";
    policy.now = FixtureNow();

    bool rejected = false;

    try {
        (void)VerifyMaintenanceToken(
            TokenPath("no-newline"),
            DeviceKeyring(),
            policy);
    } catch (const TokenError&) {
        rejected = true;
    }

    EXPECT_FALSE(rejected);
}


TEST(Token, CatalogSignerCannotAuthoriseMaintenance)
{
    TokenPolicy policy;
    policy.device_id = "CM5-0001-A7F3";
    policy.now = FixtureNow();

    bool rejected = false;

    try {
        (void)VerifyMaintenanceToken(
            TokenPath("signed-by-catalog-signer"),
            DeviceKeyring(),
            policy);
    } catch (const TokenError&) {
        rejected = true;
    }

    EXPECT_TRUE(rejected);
}


TEST(Token, WildcardDeviceIsRejected)
{
    TokenPolicy policy;
    policy.device_id = "CM5-0001-A7F3";
    policy.now = FixtureNow();

    bool rejected = false;

    try {
        (void)VerifyMaintenanceToken(
            TokenPath("wildcard-device"),
            DeviceKeyring(),
            policy);
    } catch (const TokenError&) {
        rejected = true;
    }

    EXPECT_TRUE(rejected);
}


TEST(Token, ValidTokenHasExpectedFields)
{
    TokenPolicy policy;
    policy.device_id = "CM5-0001-A7F3";
    policy.now = FixtureNow();

    const Token token =
        VerifyMaintenanceToken(
            TokenPath("valid"),
            DeviceKeyring(),
            policy);

    EXPECT_STREQ(
        token.purpose.c_str(),
        "maintenance");

    EXPECT_STREQ(
        token.device.c_str(),
        "CM5-0001-A7F3");

    EXPECT_TRUE(token.created > 0);
    EXPECT_TRUE(token.expires > token.created);
    EXPECT_FALSE(token.nonce.empty());
}


// ── Part 3: service-mode HMAC ───────────────────────────────────────────────

TEST(Token, AllServiceVectorsMatchExpectedResults)
{
    JsonDoc doc =
        JsonDoc::ParseFile(
            Fixtures() / "service" / "vectors.json");

    const cJSON* secret_item =
        cJSON_GetObjectItemCaseSensitive(
            doc.root(),
            "secret_hex");

    ASSERT_TRUE(secret_item != nullptr);

    const std::vector<uint8_t> secret =
        FromHex(secret_item->valuestring);

    const cJSON* cases =
        cJSON_GetObjectItemCaseSensitive(
            doc.root(),
            "cases");

    ASSERT_TRUE(cases != nullptr);

    const int count =
        cJSON_GetArraySize(cases);

    ASSERT_TRUE(count > 0);

    for (int i = 0; i < count; ++i) {
        const cJSON* item =
            cJSON_GetArrayItem(cases, i);

        ASSERT_TRUE(item != nullptr);

        const cJSON* device =
            cJSON_GetObjectItemCaseSensitive(
                item, "device_id");

        const cJSON* nonce =
            cJSON_GetObjectItemCaseSensitive(
                item, "nonce");

        const cJSON* purpose =
            cJSON_GetObjectItemCaseSensitive(
                item, "purpose");

        const cJSON* response =
            cJSON_GetObjectItemCaseSensitive(
                item, "response");

        const cJSON* expect_valid =
            cJSON_GetObjectItemCaseSensitive(
                item, "expect_valid");

        ASSERT_TRUE(device != nullptr);
        ASSERT_TRUE(nonce != nullptr);
        ASSERT_TRUE(purpose != nullptr);
        ASSERT_TRUE(response != nullptr);
        ASSERT_TRUE(expect_valid != nullptr);

        const bool actual =
            VerifyServiceResponse(
                secret,
                device->valuestring,
                nonce->valuestring,
                purpose->valuestring,
                response->valuestring);

        const bool expected =
            cJSON_IsTrue(expect_valid);

        EXPECT_TRUE(actual == expected);
    }
}


TEST(Token, ServiceFieldSeparationPreventsCollision)
{
    const std::vector<uint8_t> secret =
        FromHex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f");

    const std::string response =
        "9c7b2013fa52695451eaf6843092032d"
        "31ed7c30774f4c8ee92c0ceda3baf012";

    EXPECT_TRUE(
        VerifyServiceResponse(
            secret,
            "AB",
            "CD",
            "service",
            response));

    EXPECT_FALSE(
        VerifyServiceResponse(
            secret,
            "ABC",
            "D",
            "service",
            response));
}


TEST(Token, ServiceResponseRejectsUppercaseHex)
{
    const std::vector<uint8_t> secret =
        FromHex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f");

    const std::string lowercase =
        "587b1fe20f50dfca45b499305869e252"
        "3267690d26aaac6d3f4ff6a03f78e59d";

    const std::string uppercase =
        "587B1FE20F50DFCA45B499305869E252"
        "3267690D26AAAC6D3F4FF6A03F78E59D";

    EXPECT_TRUE(
        VerifyServiceResponse(
            secret,
            "CM5-0001-A7F3",
            "9f2c4a71",
            "service",
            lowercase));

    EXPECT_FALSE(
        VerifyServiceResponse(
            secret,
            "CM5-0001-A7F3",
            "9f2c4a71",
            "service",
            uppercase));
}
