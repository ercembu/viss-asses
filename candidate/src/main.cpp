// VISS — vissapp command line entry point. PROVIDED CODE, no TODOs.
//
//   vissapp roothash <bundle> --hash-offset N [--expect HEX]
//   vissapp verifysig <message> <signature.der> <pubkey.pem>
//   vissapp token <token> --keyring FILE --device ID --now EPOCH
//
// Exit codes: 0 accepted, 1 rejected, 2 usage error.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

#include "vissapp/keyring.h"
#include "vissapp/crypto_util.h"
#include "vissapp/ecdsa.h"
#include "vissapp/errors.h"
#include "vissapp/hashtree.h"
#include "vissapp/token.h"

namespace fs = std::filesystem;

namespace {

const char* kUsage =
    "usage:\n"
    "  vissapp roothash  <bundle> --hash-offset N [--expect HEX]\n"
    "  vissapp verifysig <message> <signature.der> <pubkey.pem>\n"
    "  vissapp token     <token> --keyring FILE --device ID --now EPOCH\n";

} // namespace

int main(int argc, char** argv)
{
    if (argc < 2) { fputs(kUsage, stderr); return 2; }
    const std::string cmd = argv[1];

    std::string keyring_path, device, expect;
    int64_t hash_offset = -1, now = -1;
    std::vector<std::string> positional;

    for (int i = 2; i < argc; i++) {
        const std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) { fprintf(stderr, "%s needs a value\n", name); std::exit(2); }
            return argv[++i];
        };
        if      (a == "--keyring")     keyring_path = next("--keyring");
        else if (a == "--device")      device      = next("--device");
        else if (a == "--expect")      expect      = next("--expect");
        else if (a == "--hash-offset") hash_offset = std::atoll(next("--hash-offset").c_str());
        else if (a == "--now")         now         = std::atoll(next("--now").c_str());
        else if (a.rfind("--", 0) == 0) { fputs(kUsage, stderr); return 2; }
        else positional.push_back(a);
    }

    try {
        if (cmd == "roothash" && positional.size() == 1 && hash_offset >= 0) {
            const std::string actual =
                vissapp::ComputeRootHash(positional[0], hash_offset);
            printf("%s\n", actual.c_str());
            if (!expect.empty() && actual != expect) {
                fprintf(stderr, "MISMATCH: expected %s\n", expect.c_str());
                return 1;
            }
            return 0;
        }

        if (cmd == "verifysig" && positional.size() == 3) {
            vissapp::VerifyDetached(vissapp::ReadTextFile(positional[2]),
                                    vissapp::ReadFile(positional[1]),
                                    vissapp::ReadFile(positional[0]));
            printf("signature OK\n");
            return 0;
        }

        if (cmd == "token" && positional.size() == 1 &&
            !keyring_path.empty() && now >= 0) {
            vissapp::TokenPolicy policy;
            policy.device_id = device;
            policy.now       = now;
            const vissapp::Token t = vissapp::VerifyMaintenanceToken(
                positional[0], vissapp::LoadKeyring(keyring_path), policy);
            printf("token OK: device=%s expires=%lld\n", t.device.c_str(),
                   static_cast<long long>(t.expires));
            return 0;
        }
    } catch (const vissapp::VissappError& e) {
        fprintf(stderr, "rejected: %s\n", e.what());
        return 1;
    }

    fputs(kUsage, stderr);
    return 2;
}
