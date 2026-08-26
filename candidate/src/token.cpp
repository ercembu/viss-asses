// VISS — maintenance tokens and service-mode challenge/response.
//                                        [Part 3 of 3 — authorisation]
//
// IMPLEMENT THIS FILE. See SPEC.md section 5 and include/vissapp/token.h.

#include "vissapp/token.h"

#include "vissapp/crypto_util.h"
#include "vissapp/ecdsa.h"
#include "vissapp/keyring.h"
#include "vissapp/errors.h"

namespace vissapp {

Token ParseToken(const std::vector<uint8_t>& document)
{
    (void)document;
    throw TokenError("TODO: ParseToken");
}

Token VerifyMaintenanceToken(const std::filesystem::path& token_path,
                             const Keyring& keyring,
                             const TokenPolicy& policy)
{
    (void)token_path; (void)keyring; (void)policy;
    throw TokenError("TODO: VerifyMaintenanceToken");
}

bool VerifyServiceResponse(const std::vector<uint8_t>& secret,
                           const std::string& device_id,
                           const std::string& nonce,
                           const std::string& purpose,
                           const std::string& response_hex)
{
    (void)secret; (void)device_id; (void)nonce; (void)purpose; (void)response_hex;
    throw TokenError("TODO: VerifyServiceResponse");
}

} // namespace vissapp
