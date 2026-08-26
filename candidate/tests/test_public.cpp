// VISS — vissapp starter tests.
//
// One test per part, covering the happy path only. These are NOT the tests
// your submission is graded with, and passing all four does not mean you are
// done — a verifier that accepts everything passes every one of them.
//
// The fixture corpus is mostly things that must be REJECTED. Finding those
// and writing tests for them is a graded part of the exercise.

#include "viss_test.h"
#include "test_support.h"

#include "vissapp/keyring.h"
#include "vissapp/crypto_util.h"
#include "vissapp/ecdsa.h"
#include "vissapp/errors.h"
#include "vissapp/hashtree.h"
#include "vissapp/json.h"
#include "vissapp/token.h"

using namespace vissapp;
using namespace vissapp_test;

// ── Part 1: hashing ─────────────────────────────────────────────────────────

TEST(Hash, KnownBundleRootMatches)
{
    // Every bundle's expected root is in fixtures/bundles/manifest.json.
    JsonDoc doc = JsonDoc::ParseFile(Fixtures() / "bundles" / "manifest.json");
    const cJSON* list = cJSON_GetObjectItemCaseSensitive(doc.root(), "bundles");
    const cJSON* first = cJSON_GetArrayItem(list, 0);
    ASSERT_TRUE(first != nullptr);

    const std::string file =
        cJSON_GetObjectItemCaseSensitive(first, "file")->valuestring;
    const int64_t offset = static_cast<int64_t>(
        cJSON_GetObjectItemCaseSensitive(first, "hash_offset")->valuedouble);
    const std::string expected =
        cJSON_GetObjectItemCaseSensitive(first, "root_hash")->valuestring;

    const std::string actual =
        ComputeRootHash(Fixtures() / "bundles" / file, offset);
    EXPECT_STREQ(actual.c_str(), expected.c_str());
}

// ── Part 2: signatures ──────────────────────────────────────────────────────

TEST(Sig, GenuineSignatureVerifies)
{
    bool threw = false;
    try {
        VerifyDetached(ReadTextFile(Sig("signer.pub")),
                       ReadFile(Sig("valid.der")),
                       ReadFile(Sig("message.bin")));
    } catch (const VissappError&) {
        threw = true;
    }
    EXPECT_FALSE(threw);
}

// ── Part 3: authorisation ──────────────────────────────────────────────────

TEST(Token, ValidTokenAccepted)
{
    TokenPolicy policy;
    policy.device_id = "CM5-0001-A7F3";
    policy.now       = FixtureNow();

    const Token t = VerifyMaintenanceToken(TokenPath("valid"), DeviceKeyring(), policy);
    EXPECT_STREQ(t.purpose.c_str(), "maintenance");
    EXPECT_STREQ(t.device.c_str(), "CM5-0001-A7F3");
}

TEST(Token, ServiceResponseAccepted)
{
    JsonDoc doc = JsonDoc::ParseFile(Fixtures() / "service" / "vectors.json");
    const std::vector<uint8_t> secret = FromHex(
        cJSON_GetObjectItemCaseSensitive(doc.root(), "secret_hex")->valuestring);

    const cJSON* cases = cJSON_GetObjectItemCaseSensitive(doc.root(), "cases");
    const cJSON* first = cJSON_GetArrayItem(cases, 0);
    ASSERT_TRUE(first != nullptr);

    EXPECT_TRUE(VerifyServiceResponse(
        secret,
        cJSON_GetObjectItemCaseSensitive(first, "device_id")->valuestring,
        cJSON_GetObjectItemCaseSensitive(first, "nonce")->valuestring,
        cJSON_GetObjectItemCaseSensitive(first, "purpose")->valuestring,
        cJSON_GetObjectItemCaseSensitive(first, "response")->valuestring));
}
