// VISS — dm-verity hash tree verification.  [Part 1 of 3 — hashing]

#include "vissapp/hashtree.h"

#include "vissapp/crypto_util.h"
#include "vissapp/errors.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <limits>
#include <stdexcept>

namespace vissapp {
namespace {

constexpr size_t kBlockSize = 4096;
constexpr size_t kDigestSize = 32;
constexpr size_t kDigestsPerBlock = kBlockSize / kDigestSize;

uint32_t ReadLe32(const uint8_t* p)
{
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t ReadLe64(const uint8_t* p)
{
    return static_cast<uint64_t>(p[0]) |
           (static_cast<uint64_t>(p[1]) << 8) |
           (static_cast<uint64_t>(p[2]) << 16) |
           (static_cast<uint64_t>(p[3]) << 24) |
           (static_cast<uint64_t>(p[4]) << 32) |
           (static_cast<uint64_t>(p[5]) << 40) |
           (static_cast<uint64_t>(p[6]) << 48) |
           (static_cast<uint64_t>(p[7]) << 56);
}

uint16_t ReadLe16(const uint8_t* p)
{
    return static_cast<uint16_t>(
        static_cast<uint16_t>(p[0]) |
        (static_cast<uint16_t>(p[1]) << 8));
}

std::vector<uint8_t> SaltedHash(const std::vector<uint8_t>& salt,
                                const uint8_t* data,
                                size_t len)
{
    std::vector<uint8_t> input;
    input.reserve(salt.size() + len);

    input.insert(input.end(), salt.begin(), salt.end());
    input.insert(input.end(), data, data + len);

    std::vector<uint8_t> digest(kDigestSize);
    Sha256(input.data(), input.size(), digest.data());

    return digest;
}

} // namespace

Superblock ParseSuperblock(const uint8_t* raw, size_t len)
{
    if (raw == nullptr || len < kBlockSize) {
        throw HashTreeError("superblock is too short");
    }

    // Magic: "verity\0\0"
    static const uint8_t kMagic[8] = {
        'v', 'e', 'r', 'i', 't', 'y', 0, 0
    };

    if (std::memcmp(raw, kMagic, sizeof(kMagic)) != 0) {
        throw HashTreeError("invalid verity magic");
    }

    const uint32_t version = ReadLe32(raw + 8);
    if (version != 1) {
        throw HashTreeError("unsupported verity version");
    }

    const uint32_t hash_type = ReadLe32(raw + 12);
    if (hash_type != 1) {
        throw HashTreeError("unsupported hash type");
    }

    // Algorithm name at offset 32, NUL padded.
    char algorithm[33] = {};
    std::memcpy(algorithm, raw + 32, 32);

    if (std::strncmp(algorithm, "sha256", 32) != 0) {
        throw HashTreeError("unsupported hash algorithm");
    }

    const uint32_t data_block_size = ReadLe32(raw + 64);
    const uint32_t hash_block_size = ReadLe32(raw + 68);

    if (data_block_size != kBlockSize) {
        throw HashTreeError("unsupported data block size");
    }

    if (hash_block_size != kBlockSize) {
        throw HashTreeError("unsupported hash block size");
    }

    const uint64_t data_blocks = ReadLe64(raw + 72);

    const uint16_t salt_size = ReadLe16(raw + 80);

    // Salt begins at offset 88.
    if (88ULL + salt_size > len) {
        throw HashTreeError("truncated superblock salt");
    }

    Superblock sb;
    sb.data_block_size = data_block_size;
    sb.hash_block_size = hash_block_size;
    sb.data_blocks = data_blocks;
    sb.salt.assign(raw + 88, raw + 88 + salt_size);

    return sb;
}

std::string ComputeRootHash(const std::filesystem::path& path,
                            int64_t hash_offset)
{
    if (hash_offset < 0) {
        throw HashTreeError("negative hash offset");
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw HashTreeError("cannot read bundle: " + path.string());
    }

    // Find the end of the file.
    file.seekg(0, std::ios::end);
    const std::streamoff file_size = file.tellg();

    if (file_size < 0) {
        throw HashTreeError("cannot determine bundle size");
    }

    if (static_cast<uint64_t>(hash_offset) >
        static_cast<uint64_t>(file_size)) {
        throw HashTreeError("hash offset is beyond end of bundle");
    }

    // The superblock occupies one 4096-byte block.
    if (static_cast<uint64_t>(hash_offset) + kBlockSize >
        static_cast<uint64_t>(file_size)) {
        throw HashTreeError("truncated superblock");
    }

    file.seekg(static_cast<std::streamoff>(hash_offset), std::ios::beg);

    std::vector<uint8_t> raw_superblock(kBlockSize);

    file.read(reinterpret_cast<char*>(raw_superblock.data()),
              static_cast<std::streamsize>(raw_superblock.size()));

    if (file.gcount() != static_cast<std::streamsize>(kBlockSize)) {
        throw HashTreeError("cannot read complete superblock");
    }

    const Superblock sb =
        ParseSuperblock(raw_superblock.data(), raw_superblock.size());

    if (sb.data_blocks == 0) {
        throw HashTreeError("zero data blocks");
    }

    // The data area is [0, hash_offset).
    //
    // Every data block is 4096 bytes. If the final data block is shorter
    // because the producer did not pad the image, the missing bytes are
    // treated as zero bytes for hashing.
    const uint64_t data_area_size = static_cast<uint64_t>(hash_offset);

    if (sb.data_blocks >
        (std::numeric_limits<uint64_t>::max() / kBlockSize)) {
        throw HashTreeError("data block count is too large");
    }

    const uint64_t required_data_size =
        sb.data_blocks * static_cast<uint64_t>(kBlockSize);

    if (required_data_size < data_area_size) {
        // Bytes after the final covered block are intentionally not covered
        // by the tree. This is allowed by the specification.
    } else if (required_data_size > data_area_size + kBlockSize) {
        throw HashTreeError("data block count exceeds data area");
    }

    std::vector<std::vector<uint8_t>> digests;
    digests.reserve(
        sb.data_blocks > std::numeric_limits<size_t>::max()
            ? 0
            : static_cast<size_t>(sb.data_blocks));

    for (uint64_t i = 0; i < sb.data_blocks; ++i) {
        std::vector<uint8_t> block(kBlockSize, 0);

        const uint64_t offset = i * kBlockSize;

        if (offset < data_area_size) {
            const uint64_t available =
                std::min<uint64_t>(
                    kBlockSize,
                    data_area_size - offset);

            file.seekg(
                static_cast<std::streamoff>(offset),
                std::ios::beg);

            file.read(
                reinterpret_cast<char*>(block.data()),
                static_cast<std::streamsize>(available));

            if (file.gcount() !=
                static_cast<std::streamsize>(available)) {
                throw HashTreeError("cannot read data block");
            }
        }

        digests.push_back(
            SaltedHash(sb.salt, block.data(), block.size()));
    }

    // IMPORTANT:
    // Do not use do/while here.
    //
    // For exactly one data block, that block's digest IS the root.
    while (digests.size() > 1) {
        const size_t blocks =
            (digests.size() + kDigestsPerBlock - 1) /
            kDigestsPerBlock;

        std::vector<std::vector<uint8_t>> next;
        next.reserve(blocks);

        for (size_t block_index = 0;
             block_index < blocks;
             ++block_index) {

            std::vector<uint8_t> packed(kBlockSize, 0);

            const size_t first =
                block_index * kDigestsPerBlock;

            const size_t count =
                std::min(
                    kDigestsPerBlock,
                    digests.size() - first);

            for (size_t i = 0; i < count; ++i) {
                std::copy(
                    digests[first + i].begin(),
                    digests[first + i].end(),
                    packed.begin() + i * kDigestSize);
            }

            next.push_back(
                SaltedHash(
                    sb.salt,
                    packed.data(),
                    packed.size()));
        }

        digests = std::move(next);
    }

    return ToHex(digests[0].data(), digests[0].size());
}

void VerifyBundle(const std::filesystem::path& path,
                  int64_t hash_offset,
                  const std::string& expected_root_hash)
{
    const std::string actual =
        ComputeRootHash(path, hash_offset);

    if (actual != expected_root_hash) {
        throw HashTreeError(
            "bundle root hash mismatch");
    }
}

} // namespace vissapp
