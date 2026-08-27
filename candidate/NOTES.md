# NOTES

## Status

All three implementation parts are complete, along with additional negative
and security tests.

| Part | State | Notes |
|---|---|---|
| 1 — `hashtree.cpp` | Complete | Implemented dm-verity parsing and SHA-256 hash-tree recomputation, including salt, padding, and the single-block case. |
| 2 — `ecdsa.cpp` | Complete | Implemented strict DER parsing and ECDSA P-256 verification using BIGNUM/EC_POINT. |
| 3 — `token.cpp` | Complete | Implemented token parsing, signer/purpose checks, time/device policy, and HMAC service-response verification. |
| Tests | Complete | Added negative/security tests for malformed signatures, invalid keys, tokens, and service responses. 22 tests passed, 181 assertions. |

## What I would do next

The implementation and additional tests are complete.

With more time, I would add a few more boundary tests and run the code with
AddressSanitizer and UndefinedBehaviorSanitizer.

## Spec ambiguities, errors and dangers

- Only the data blocks specified by the superblock are covered by the hash
  tree. Bytes after the final block are not covered.
- Hash-tree levels are zero-padded to 4096 bytes before hashing.
- The tree stops when one digest remains, which is important for a
  single-block bundle.
- DER signatures must be minimally encoded. Negative integers, unnecessary
  leading zeroes, bad lengths, trailing bytes, and invalid scalar values are
  rejected.
- I did not reject high-s signatures because `(r, n-s)` is also valid ECDSA,
  and the specification requires `s-malleable.der` to verify.
- Token bytes are authenticated before being parsed, as required by section
  5.3.
- A trusted key must also be authorised for the requested purpose.
- `device=*` is rejected because it would allow the same token to work on
  every device.
- Service-response fields use NUL separators, and the response comparison is
  done without an early exit.
- The remaining limitations are replay within the token validity period, no
  key revocation, and maintenance keys being trusted by every device using
  the same keyring.

## Question 1 — signature malleability

`r,s` and `r,n-s` are both valid ECDSA signatures for the same message. This
means the same bundle can have different `.sig` hashes even though the bundle
itself has not changed.

I would use a hash of the bundle contents as the bundle identifier, and use
the signature only to prove that the contents were approved by a trusted key.

## Question 2 — the tokens already in the field

`device=*` means a stolen token could be used on any device using the same
keyring. Without `expires`, an old token could also remain valid indefinitely
under the old implementation.

I would first roll out support for the new format and update the issuing
system to create device-specific tokens with expiry times. During a short
migration period, old tokens could be accepted through a limited compatibility
path. Once technicians have moved to the new tokens, remove that old path.

## Anything else

I used AI assistance to help understand the specification and review the
implementation. I verified the result by building the project and running the
tests.

## Final test result

Tests: 22 total, 22 passed, 0 failed (181 assertions)
