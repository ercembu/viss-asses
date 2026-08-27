// VISS — dm-verity hash tree verification.   [Part 1 of 3 — hashing]
//
// IMPLEMENT THIS FILE. See SPEC.md section 3 and include/vissapp/hashtree.h.
//
// vissapp::Sha256() and vissapp::ToHex() are provided in crypto_util.h.

#include "vissapp/hashtree.h"

#include "vissapp/crypto_util.h"
#include "vissapp/errors.h"
#include <cstring>

namespace vissapp {

uint16_t ReadLe16(const uint8_t *p) {
  return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t ReadLe32(const uint8_t *p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t ReadLe64(const uint8_t *p) {
  return static_cast<uint64_t>(ReadLe32(p)) |
         (static_cast<uint64_t>(ReadLe32(p + 4)) << 32);
}

Superblock ParseSuperblock(const uint8_t *raw, size_t len) {
  (void)raw;
  (void)len;

  if (raw == nullptr || len < 88) {
    throw HashTreeError("Superblock too short");
  }

  // verify magic word: "verity\0\0"
  const uint8_t magic[8] = {'v', 'e', 'r', 'i', 't', 'y', 0, 0};
  if (std::memcmp(raw, magic, 8) != 0) {
    throw HashTreeError("Bad magic");
  }

  // check version. Must be 1
  const uint32_t version = ReadLe32(raw + 8);
  if (version != 1) {
    throw HashTreeError("Unsupported version");
  }

  // check hash type. Must be 1
  const uint32_t hash_type = ReadLe32(raw + 12);
  if (hash_type != 1) {
    throw HashTreeError("Wrong hash type");
  }

  // Read UUID, not required currently
  // const uint16_t _uuid = ReadLe16(raw + 16);

  // Read algorithm name, must be "sha256" null padded
  char algo[33] = {};
  std::memcpy(algo, raw + 32, 32);
  if (std::strcmp(algo, "sha256") != 0) {
    throw HashTreeError("Unsupported hash algorithm");
  }

  // Read data and hash block sizes
  const uint32_t data_block_size = ReadLe32(raw + 64);
  const uint32_t hash_block_size = ReadLe32(raw + 68);
  if (data_block_size != 4096 || hash_block_size != 4096) {
    throw HashTreeError("Wrong block size");
  }

  // Read data block count
  const uint64_t data_blocks = ReadLe64(raw + 72);
  const uint16_t salt_size = ReadLe16(raw + 80);

  Superblock sb;
  sb.data_block_size = data_block_size;
  sb.hash_block_size = hash_block_size;
  sb.data_blocks = data_blocks;

  sb.salt.assign(raw + 88, raw + 88 + salt_size);
  return sb;
}

std::string ComputeRootHash(const std::filesystem::path &path,
                            int64_t hash_offset) {

  if (hash_offset < 0) {
    throw HashTreeError("Negative hash offset");
  }

  const std::vector<uint8_t> file = ReadFile(path);
  const size_t offset = static_cast<size_t>(hash_offset);

  // check if superblock is correctly present in file
  if (offset + 4096 > file.size()) {
    throw HashTreeError("Hash area truncated");
  }

  const Superblock sb =
      ParseSuperblock(file.data() + offset, file.size() - offset);

  const uint32_t B = sb.data_block_size;
  const uint64_t N = sb.data_blocks;
  const std::vector<uint8_t> &salt = sb.salt;

  // Should I check for 0 block size?
  if (B == 0) {
    throw HashTreeError("Invalid block size");
  }

  const uint64_t data_bytes = N * static_cast<uint64_t>(B);
  if (static_cast<uint64_t>(file.size()) < data_bytes) {
    throw HashTreeError("Not enough data blocks");
  }

  const size_t kDigest = 32;
  const size_t hashes_per_block = B / kDigest;

  // SHA245(salt || payload) helper lambda
  auto hash_salted = [&](const uint8_t *payload, size_t len) {
    std::vector<uint8_t> buf;
    buf.reserve(salt.size() + len);
    buf.insert(buf.end(), salt.begin(), salt.end());
    buf.insert(buf.end(), payload, payload + len);

    std::vector<uint8_t> out(kDigest);
    Sha256(buf.data(), buf.size(), out.data());
    return out;
  };

  // Calculate hash per data block
  std::vector<std::vector<uint8_t>> digests;
  digests.reserve(static_cast<size_t>(N));
  for (uint64_t i = 0; i < N; i++) {
    const uint8_t *block = file.data() + static_cast<size_t>(i * B);
    digests.push_back(hash_salted(block, B));
  }

  // Fold hashes until a single remains
  while (digests.size() > 1) {
    const size_t n = digests.size();
    const size_t blocks = (n + hashes_per_block - 1) / hashes_per_block;

    // concatenate digests to blocks * B
    std::vector<uint8_t> packed(blocks * B, 0);
    for (size_t i = 0; i < n; ++i) {
      std::memcpy(packed.data() + i * kDigest, digests[i].data(), kDigest);
    }

    std::vector<std::vector<uint8_t>> next;

    next.reserve(blocks);
    for (size_t i = 0; i < blocks; ++i) {
      next.push_back(hash_salted(packed.data() + i * B, B));
    }
    digests = std::move(next);
  }

  return ToHex(digests[0].data(), kDigest);
}

void VerifyBundle(const std::filesystem::path &path, int64_t hash_offset,
                  const std::string &expected_root_hash) {
  (void)expected_root_hash;
  std::string computed_hash = ComputeRootHash(path, hash_offset);

  throw HashTreeError("TODO: VerifyBundle");
}

} // namespace vissapp
