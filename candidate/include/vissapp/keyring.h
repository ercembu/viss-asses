#pragma once
// VISS — the device's trusted signer keyring. PROVIDED CODE.
//
// A VISS unit ships a small keyring in its read-only rootfs: the public keys
// it will accept signatures from, and what each of them is allowed to sign.
// Separate keys sign app catalogues, OS manifests and maintenance tokens, so
// holding a trusted key is not the same as being allowed to do a given thing.
//
// Loading is done for you. Deciding what a signer may do is Part 3.

#include <filesystem>
#include <set>
#include <string>
#include <vector>

namespace vissapp {

struct TrustedSigner {
    std::string           name;
    std::string           public_key;   // PEM SubjectPublicKeyInfo
    std::set<std::string> purposes;     // e.g. {"maintenance"}, {"catalog"}
};

struct Keyring {
    std::vector<TrustedSigner> signers;
};

// Load the keyring shipped with the image. Throws VissappError if the file is
// missing or malformed. The keyring itself is not signed: it lives in the
// dm-verity-protected rootfs, so its integrity is already established.
Keyring LoadKeyring(const std::filesystem::path& path);

} // namespace vissapp
