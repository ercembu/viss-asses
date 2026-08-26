// VISS — the device's trusted signer keyring. PROVIDED CODE.

#include "vissapp/keyring.h"

#include "vissapp/crypto_util.h"
#include "vissapp/errors.h"
#include "vissapp/json.h"

namespace vissapp {

Keyring LoadKeyring(const std::filesystem::path& path)
{
    JsonDoc doc = JsonDoc::ParseFile(path);
    const cJSON* root = doc.root();
    if (!cJSON_IsObject(root)) throw VissappError("keyring must be an object");

    const cJSON* format = cJSON_GetObjectItemCaseSensitive(root, "format");
    if (!cJSON_IsNumber(format) || format->valuedouble != 1.0)
        throw VissappError("keyring.format must be 1");

    const cJSON* signers = cJSON_GetObjectItemCaseSensitive(root, "signers");
    if (!cJSON_IsArray(signers))
        throw VissappError("keyring.signers must be an array");

    Keyring keyring;
    const cJSON* item = nullptr;
    cJSON_ArrayForEach(item, signers) {
        TrustedSigner signer;
        const cJSON* name = cJSON_GetObjectItemCaseSensitive(item, "name");
        const cJSON* key  = cJSON_GetObjectItemCaseSensitive(item, "public_key");
        if (!cJSON_IsString(name) || !cJSON_IsString(key))
            throw VissappError("keyring: signer needs a name and a public_key");
        signer.name       = name->valuestring;
        signer.public_key = key->valuestring;

        const cJSON* purposes =
            cJSON_GetObjectItemCaseSensitive(item, "purposes");
        if (!cJSON_IsArray(purposes))
            throw VissappError("keyring: signer.purposes must be an array");
        const cJSON* p = nullptr;
        cJSON_ArrayForEach(p, purposes) {
            if (!cJSON_IsString(p))
                throw VissappError("keyring: purposes must be strings");
            signer.purposes.insert(p->valuestring);
        }
        keyring.signers.push_back(std::move(signer));
    }
    if (keyring.signers.empty()) throw VissappError("keyring is empty");
    return keyring;
}

} // namespace vissapp
