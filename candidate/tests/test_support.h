#pragma once
// VISS — shared helpers for the vissapp tests. PROVIDED CODE.

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#include "vissapp/keyring.h"
#include "vissapp/crypto_util.h"

namespace vissapp_test {

namespace fs = std::filesystem;

inline fs::path Fixtures() { return fs::path(VISSAPP_FIXTURES); }
inline fs::path Keys()     { return fs::path(VISSAPP_KEYS); }

// The fixed "now" the validity windows were generated around.
inline int64_t FixtureNow()
{
    return std::stoll(vissapp::ReadTextFile(Fixtures() / "now.txt"));
}

// Named DeviceKeyring, not Keyring: vissapp::Keyring is a type.
inline vissapp::Keyring DeviceKeyring()
{
    return vissapp::LoadKeyring(Keys() / "keyring.json");
}

// Named TokenPath, not Token: vissapp::Token is a type.
inline fs::path TokenPath(const std::string& name)
{
    return Fixtures() / "tokens" / (name + ".token");
}

inline fs::path Sig(const std::string& name)
{
    return Fixtures() / "sigs" / name;
}

} // namespace vissapp_test
