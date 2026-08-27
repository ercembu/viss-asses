# NOTES

## Status

All three implementation parts are complete and the provided tests pass.

| Part | State | Notes |
|---|---|---|
| 1 — `hashtree.cpp` | Complete | Implemented dm-verity superblock parsing and SHA-256 hash-tree recomputation, including salt, block padding, and the single-data-block case. |
| 2 — `ecdsa.cpp` | Complete | Implemented strict minimal DER signature parsing and ECDSA P-256 verification using libcrypto BIGNUM/EC_POINT arithmetic. |
| 3 — `token.cpp` | Complete | Implemented token parsing, trusted-signer verification, purpose/device/time policy checks, and HMAC-SHA-256 service-response verification. |
| Tests | Complete | `./build/tests/viss-tests`: 4 passed, 0 failed, 7 assertions. |

## What I would do next

The required implementation is complete and the provided tests pass.

With more time, I would add additional negative and boundary tests for malformed encodings, integer overflow/underflow, unusual file sizes, and policy edge cases. I would also run the code with AddressSanitizer and UndefinedBehaviorSanitizer.

## Spec ambiguities, errors and dangers

- For the hash tree, only the number of data blocks specified by the superblock is covered. Bytes after the final covered block are not included in the tree.
- Hash-tree levels are zero-padded to complete 4096-byte hash blocks before being hashed.
- The hash-tree loop stops when one digest remains. This is important for the single-data-block case.
- ECDSA signatures must use minimal DER encoding. Non-minimal lengths, negative integers, unnecessary leading zeroes, empty INTEGERs, trailing bytes, and out-of-range scalars are rejected.
- I did not reject high-`s` signatures because `(r, n-s)` is also a valid ECDSA signature and the specification explicitly requires the malleable signature fixture to verify.
- Maintenance-token bytes are authenticated before they are parsed, following the required order in section 5.3.
- A trusted signing key must also have the required purpose. Being trusted does not automatically mean it can authorise maintenance.
- `device=*` is rejected because it would allow the same maintenance token to be used on every device in the fleet.
- Service-response fields are separated with NUL bytes so that different field combinations cannot become the same authenticated message through simple concatenation.
- The service-response comparison checks the complete value without an early exit.
- The specification also identifies remaining system-level limitations: token nonces are not bound to a particular request, there is no key revocation mechanism, and a maintenance key is trusted by every unit using the same keyring.

## Question 1 — signature malleability

`fixtures/sigs/s-malleable.der` is a second valid signature over the same
message, produced without the private key. Our app catalog identifies each
bundle by `bundle_sig_hash` — the SHA-256 of its `.sig` file. What goes wrong,
and what would you use as the identifier instead?

 ECDSA allows `(r, s)` and `(r, n-s)` to both be valid signatures for the same
 message and public key. Therefore the signature file is not a unique
 identifier for the signed content. A valid signature can be transformed into
 another valid signature without knowing the private key.

 If `bundle_sig_hash` is used as the bundle identity, the same bundle can have
 different identifiers depending only on which valid signature is attached.

 I would identify the bundle using a cryptographic hash of the signed bundle
 content itself, or another canonical content identifier. The signature
 should prove that the content was approved by a trusted signer, rather than
 being used as the content's identity.

## Question 2 — the tokens already in the field

The token format is taken from a script we actually ship, which emits
`device=*` and no `expires` field at all. Section 5.3 rejects both. A fleet of
units is already running with those tokens in circulation. What is the
exploit, and how would you roll out the fix without bricking the technicians'
access?

`device=*` makes a valid maintenance token usable on every unit that trusts
 the same maintenance signing key. If the token is stolen, it could therefore
 be used to gain maintenance access across the fleet.

 Omitting `expires` also removes an important time limit, allowing an old
 token to remain useful indefinitely if the old implementation accepts it.

 I would roll out the fix in stages rather than immediately rejecting every
 existing token. First, deploy support for the new token format and update
 the issuing system to create device-specific tokens with explicit expiration
 times. During a controlled migration period, old tokens could be accepted
 only under a tightly limited compatibility policy while new tokens are
 issued. Old tokens would then be retired and the compatibility path removed
 in a later update.

 This preserves legitimate technician access during the migration while
 preventing the unsafe token format from becoming a permanent exception.

## Anything else

I used the provided specification, source code, build system, compiler output,
Git, and public test suite to implement and validate the three parts.

I also used AI assistance to help understand the specification, reason through
the cryptographic requirements, and review implementation details. I verified
the implementation by building it and running the provided tests.

Final test result:

    Tests: 4 total, 4 passed, 0 failed (7 assertions)
