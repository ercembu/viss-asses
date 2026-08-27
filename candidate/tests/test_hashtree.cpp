
// Custom tests to check hash values for all files.

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

// Test viss-notes-0.9.1.vissapp
TEST(Hash, KnownBundleRootMatchesVissNotes) {
  // Every bundle's expected root is in fixtures/bundles/manifest.json.
  JsonDoc doc = JsonDoc::ParseFile(Fixtures() / "bundles" / "manifest.json");
  const cJSON *list = cJSON_GetObjectItemCaseSensitive(doc.root(), "bundles");
  const cJSON *first = cJSON_GetArrayItem(list, 1);
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

// Test viss-tiny
TEST(Hash, KnownBundleRootMatchesVissTiny) {
  // Every bundle's expected root is in fixtures/bundles/manifest.json.
  JsonDoc doc = JsonDoc::ParseFile(Fixtures() / "bundles" / "manifest.json");
  const cJSON *list = cJSON_GetObjectItemCaseSensitive(doc.root(), "bundles");
  const cJSON *first = cJSON_GetArrayItem(list, 2);
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

// Test corrupted.vissapp, SHOULD FAIL
TEST(Hash, KnownBundleRootMatchesCorrupted) {
  // Every bundle's expected root is in fixtures/bundles/manifest.json.
  JsonDoc doc = JsonDoc::ParseFile(Fixtures() / "bundles" / "manifest.json");
  const cJSON *list = cJSON_GetObjectItemCaseSensitive(doc.root(), "bundles");
  const cJSON *first = cJSON_GetArrayItem(list, 4);
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
