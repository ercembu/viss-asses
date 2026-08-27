#include "test_support.h"
#include "viss_test.h"

#include "vissapp/crypto_util.h"
#include "vissapp/ecdsa.h"
#include "vissapp/errors.h"
#include "vissapp/hashtree.h"
#include "vissapp/json.h"
#include "vissapp/keyring.h"
#include "vissapp/token.h"

using namespace vissapp;
using namespace vissapp_test;

TEST(Token, ExpiredTokenReject) {
  TokenPolicy policy;
  policy.device_id = "CM5-0001-A7F3";
  policy.now = FixtureNow();
  bool threw = false;

  try {
    VerifyMaintenanceToken(TokenPath("expired"), DeviceKeyring(), policy);
  } catch (const TokenError &) {
    threw = true;
  }
  EXPECT_TRUE(threw);
}

TEST(Token, CrReject) {
  TokenPolicy policy;
  policy.device_id = "CM5-0001-A7F3";
  policy.now = FixtureNow();
  bool threw = false;

  try {
    VerifyMaintenanceToken(TokenPath("crlf"), DeviceKeyring(), policy);
  } catch (const TokenError &) {
    threw = true;
  }
  EXPECT_TRUE(threw);
}

TEST(Token, ServiceResponseAcceptedOtherDevice) {
  JsonDoc doc = JsonDoc::ParseFile(Fixtures() / "service" / "vectors.json");
  const std::vector<uint8_t> secret = FromHex(
      cJSON_GetObjectItemCaseSensitive(doc.root(), "secret_hex")->valuestring);

  const cJSON *cases = cJSON_GetObjectItemCaseSensitive(doc.root(), "cases");
  const cJSON *first = cJSON_GetArrayItem(cases, 1);
  ASSERT_TRUE(first != nullptr);

  EXPECT_TRUE(VerifyServiceResponse(
      secret, cJSON_GetObjectItemCaseSensitive(first, "device_id")->valuestring,
      cJSON_GetObjectItemCaseSensitive(first, "nonce")->valuestring,
      cJSON_GetObjectItemCaseSensitive(first, "purpose")->valuestring,
      cJSON_GetObjectItemCaseSensitive(first, "response")->valuestring));
}

TEST(Token, ServiceResponseWrongNonceRejected) {
  JsonDoc doc = JsonDoc::ParseFile(Fixtures() / "service" / "vectors.json");
  const std::vector<uint8_t> secret = FromHex(
      cJSON_GetObjectItemCaseSensitive(doc.root(), "secret_hex")->valuestring);

  const cJSON *cases = cJSON_GetObjectItemCaseSensitive(doc.root(), "cases");
  const cJSON *first = cJSON_GetArrayItem(cases, 2);
  ASSERT_TRUE(first != nullptr);

  EXPECT_FALSE(VerifyServiceResponse(
      secret, cJSON_GetObjectItemCaseSensitive(first, "device_id")->valuestring,
      cJSON_GetObjectItemCaseSensitive(first, "nonce")->valuestring,
      cJSON_GetObjectItemCaseSensitive(first, "purpose")->valuestring,
      cJSON_GetObjectItemCaseSensitive(first, "response")->valuestring));
}
