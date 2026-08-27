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

// check for s-mealleable.der should verify
TEST(Sig, SMalleableVerifies) {
  bool threw = false;
  try {
    VerifyDetached(ReadTextFile(Sig("signer.pub")),
                   ReadFile(Sig("s-malleable.der")),
                   ReadFile(Sig("message.bin")));
  } catch (const VissappError &) {
    threw = true;
  }
  EXPECT_FALSE(threw);
}

// Check for empty.der
TEST(Sig, EmptyDer) {
  bool threw = false;
  try {
    const auto in = ReadFile(Sig("empty.der"));

    ParseSignatureDer(in.data(), in.size());
  } catch (const SignatureError &) {
    threw = true;
  }
  EXPECT_TRUE(threw);
}

// leading zero r der
TEST(Sig, LoadingZeroDer) {
  bool threw = false;
  try {
    const auto in = ReadFile(Sig("leading-zero-r.der"));

    ParseSignatureDer(in.data(), in.size());
  } catch (const SignatureError &) {
    threw = true;
  }
  EXPECT_TRUE(threw);
}

// Trailiing byte der
TEST(Sig, TrailingByteDerReject) {
  bool threw = false;
  try {
    const auto in = ReadFile(Sig("trailing-byte.der"));

    ParseSignatureDer(in.data(), in.size());
  } catch (const SignatureError &) {
    threw = true;
  }
  EXPECT_TRUE(threw);
}

// Not a sequence der
TEST(Sig, NotASequenceDer) {
  bool threw = false;
  try {
    const auto in = ReadFile(Sig("not-a-sequence.der"));

    ParseSignatureDer(in.data(), in.size());
  } catch (const SignatureError &) {
    threw = true;
  }
  EXPECT_TRUE(threw);
}

// Wrong message refect
TEST(Sig, WrongMessageDoesNotVerify) {
  bool threw = false;
  try {
    VerifyDetached(ReadTextFile(Sig("signer.pub")),
                   ReadFile(Sig("wrong-message.der")),
                   ReadFile(Sig("message.bin")));
  } catch (const VissappError &) {
    threw = true;
  }
  EXPECT_TRUE(threw);
}
