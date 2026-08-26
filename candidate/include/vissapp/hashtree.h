#pragma once
// VISS — dm-verity hash tree verification.  [Part 1 of 3 — hashing]
//
// IMPLEMENT src/hashtree.cpp. See SPEC.md section 3.

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace vissapp {

// The superblock fields this exercise needs.
struct Superblock {
    uint32_t             data_block_size = 0;
    uint32_t             hash_block_size = 0;
    uint64_t             data_blocks     = 0;
    std::vector<uint8_t> salt;
};

// Parse the dm-verity superblock at the start of a hash area. *len* is at
// least 512. Throws HashTreeError if the magic is wrong or a field is
// unsupported. Field offsets are in SPEC.md section 3.1.
Superblock ParseSuperblock(const uint8_t* raw, size_t len);

// Recompute the Merkle root of the bundle at *path*, as lowercase hex.
// Throws HashTreeError if the bundle cannot be read or the hash area is not
// a valid superblock.
//
// The tree construction is in SPEC.md section 3.2. Read the note about the
// single-data-block case before assuming your loop is right.
std::string ComputeRootHash(const std::filesystem::path& path,
                            int64_t hash_offset);

// Throws HashTreeError unless the recomputed root matches.
void VerifyBundle(const std::filesystem::path& path, int64_t hash_offset,
                  const std::string& expected_root_hash);

} // namespace vissapp
