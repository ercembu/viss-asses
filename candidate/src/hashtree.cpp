// VISS — dm-verity hash tree verification.   [Part 1 of 3 — hashing]
//
// IMPLEMENT THIS FILE. See SPEC.md section 3 and include/vissapp/hashtree.h.
//
// vissapp::Sha256() and vissapp::ToHex() are provided in crypto_util.h.

#include "vissapp/hashtree.h"

#include "vissapp/crypto_util.h"
#include "vissapp/errors.h"

namespace vissapp {

Superblock ParseSuperblock(const uint8_t* raw, size_t len)
{
    (void)raw; (void)len;
    throw HashTreeError("TODO: ParseSuperblock");
}

std::string ComputeRootHash(const std::filesystem::path& path,
                            int64_t hash_offset)
{
    (void)path; (void)hash_offset;
    throw HashTreeError("TODO: ComputeRootHash");
}

void VerifyBundle(const std::filesystem::path& path, int64_t hash_offset,
                  const std::string& expected_root_hash)
{
    (void)path; (void)hash_offset; (void)expected_root_hash;
    throw HashTreeError("TODO: VerifyBundle");
}

} // namespace vissapp
