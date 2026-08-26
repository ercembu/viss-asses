# VISS OS device-side cryptography

This is the authoritative specification for the exercise. Where a code comment
and this document disagree, this document wins.

Everything here was verified against the fixtures you have been given. They
are real: real ECDSA P-256 keys, real signatures produced by OpenSSL, real
dm-verity hash trees produced by `veritysetup`. Nothing is mocked, and no
fixture is "close enough".

---

## 1. What the device is deciding

A VISS OS unit refuses to act on anything it cannot authenticate. Three
questions stand between an input and the device acting on it, and you
implement the answer to each:

```
   Part 1  hash tree     do these bytes still hash to what was signed?
   Part 2  signature     was this produced by the holder of a private key?
   Part 3  token         and is that holder allowed to do THIS, HERE, NOW?
```

None substitutes for another. A valid signature over a stale token authorises
nothing. A key the device genuinely trusts, but trusts to sign app
catalogues, cannot unlock maintenance mode.

The device's trust is a **keyring** in its read-only rootfs: `keys/keyring.json`,
listing each public key it will accept signatures from and what that key is
permitted to authorise. The keyring itself needs no signature — it sits inside
the dm-verity-protected rootfs, so Part 1's mechanism is what protects it.

```json
{ "format": 1, "signers": [
    { "name": "viss-maint-signer",   "purposes": ["maintenance"],
      "public_key": "-----BEGIN PUBLIC KEY-----\n..." },
    { "name": "viss-catalog-signer", "purposes": ["catalog"],
      "public_key": "-----BEGIN PUBLIC KEY-----\n..." } ] }
```

`LoadKeyring` is provided in `src/keyring.cpp`. Reading it is one minute well
spent; you do not need to change it.

---

## 2. What you are given

`include/vissapp/crypto_util.h`, implemented over libcrypto:

| Function | Does |
|---|---|
| `Sha256` | one-shot SHA-256 |
| `HmacSha256` | one-shot HMAC-SHA-256 |
| `ToHex` / `FromHex` | lowercase hex encode / decode |
| `Base64Decode` | standard base64, whitespace-tolerant |
| `ReadFile` / `ReadTextFile` | whole-file reads |

`include/vissapp/json.h` gives `JsonDoc`, an RAII wrapper over the vendored
cJSON parser. `include/vissapp/keyring.h` and `src/keyring.cpp` load the
keyring. `src/pubkey.cpp` parses a P-256 public key out of PEM.

You are not re-implementing SHA-256, HMAC, base64 or JSON. You are
implementing the encodings and the protocols on top of them, which is where
the bugs in real systems actually are.

**Detached signatures throughout.** Wherever this document says a file is
signed, the signature is a separate file at the same path plus `.sig`, holding
DER, over the signed file's bytes exactly as they sit on disk. There is no
canonicalisation step anywhere in this system — you verify the bytes you read.

---

## 3. Part 1 — the bundle hash tree

An application bundle is a SquashFS image with a dm-verity hash area appended:

```
 byte 0                        hash_offset                    end of file
 ├──────── SquashFS data ─────────┼───── verity hash area ─────────┤
                                  ├── superblock (4096 B) ── tree ─┤
```

`fixtures/bundles/manifest.json` lists each bundle with the `hash_offset` to
use and the `root_hash` it must produce. One entry carries
`"expect_mismatch": true` — it is a bundle with a single flipped byte, and its
recomputed root must NOT match.

**Take `hash_offset` from the manifest; never recompute it.** Two producers
build these bundles and they disagree: one pads the SquashFS up to a 4096
boundary, so `hash_offset == data_blocks * 4096`; the other does not, so
`hash_offset` is the raw image size and is not a multiple of 4096. Both appear
in the corpus.

### 3.1 The superblock

4096 bytes, at `hash_offset`. All integers little-endian.

| Offset | Size | Field |
|-------:|-----:|-------|
| 0      | 8    | magic, `"verity\0\0"` |
| 8      | 4    | version — must be `1` |
| 12     | 4    | hash type — must be `1` |
| 16     | 16   | UUID |
| 32     | 32   | algorithm name, NUL-padded — must be `"sha256"` |
| 64     | 4    | data block size — 4096 |
| 68     | 4    | hash block size — 4096 |
| 72     | 8    | data block count |
| 80     | 2    | salt size, in bytes |
| 88     | *n*  | salt |

The data block count comes from **this superblock**, not from the manifest.

### 3.2 Computing the root

Let `salt` be the superblock salt, `B = 4096`, and `N` the superblock's data
block count. A SHA-256 digest is 32 bytes, so a hash block holds `B / 32 = 128`
of them.

```
digests := [ SHA256(salt || data_block[i]) for i in 0 .. N-1 ]

while len(digests) > 1:
    blocks  := ceil(len(digests) / 128)
    packed  := concat(digests) zero-padded up to blocks * B
    digests := [ SHA256(salt || packed[j*B : (j+1)*B]) for j in 0 .. blocks-1 ]

root := digests[0]
```

Three details decide whether this works:

* **Data blocks are read from offset 0, and only `N` of them.** An unpadded
  bundle has a tail of bytes after block `N-1` that the tree does not cover.
  That is a real property of these bundles — and worth a sentence in your
  write-up.
* **Zero-padding is to the whole level**, not per digest: the last hash block
  of a level is padded out to 4096 bytes before being hashed.
* **The loop is `while len(digests) > 1`.** A bundle of exactly one data block
  produces no hash blocks at all, and its root is simply
  `SHA256(salt || data_block[0])`. Written as a do/while, every single-block
  bundle comes out wrong. `viss-tiny` in the corpus is exactly this case.

You never read the stored tree to verify a bundle — you recompute it. The
stored tree exists so the kernel can check one page without reading the file.

---

## 4. Part 2 — ECDSA P-256 signature verification

You implement the encodings and the verification equation. libcrypto's
`BIGNUM` and `EC_POINT` are there for the arithmetic and using them is the
expected approach.

**You may not call `EVP_DigestVerify`, `ECDSA_do_verify` or `ECDSA_verify`.**
Those are the function you are writing. `grade.sh` greps for them.

Curve parameters come from `EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)`;
the group order `n` from `EC_GROUP_get0_order`.

### 4.1 The public key — provided

`ParsePublicKeyPem` is implemented for you in `src/pubkey.cpp`. It is
documented here because Part 2 depends on what it guarantees: the key you are
handed has already been checked to be an uncompressed point on P-256, under
the right algorithm and curve OIDs.

A PEM `SubjectPublicKeyInfo`:

```
SEQUENCE {
  SEQUENCE { OBJECT IDENTIFIER 1.2.840.10045.2.1     -- id-ecPublicKey
             OBJECT IDENTIFIER 1.2.840.10045.3.1.7 } -- prime256v1
  BIT STRING { 0x00, 0x04 || X(32) || Y(32) } }
```

Anything that is not exactly this is rejected: a different algorithm, a
different curve, a compressed point, trailing data. The point is also checked
to lie on the curve — `fixtures/sigs/off-curve.pub` is a structurally perfect
SPKI whose point does not, and `wrong-curve.pub` is a P-384 key.

The DER cursor in `pubkey.cpp` is file-local on purpose. The signature parser
below is yours, and its rules are stricter.

### 4.2 The signature

```
ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
```

DER, not BER, and the distinguishing rules are the point of this section.
Reject:

| Condition | Why it matters |
|---|---|
| any byte after the outer SEQUENCE | the signature bytes can be varied without touching `(r, s)` |
| length in long form when short form fits | same: two encodings of one signature |
| an INTEGER whose first byte has bit 7 set | that is a negative integer, not a scalar |
| a leading `0x00` not needed to clear bit 7 | non-minimal; another spare encoding |
| an empty INTEGER, or a truncated TLV | malformed |
| `r` or `s` outside `[1, n-1]` | `0` and `n` are not valid scalars |

Every one of these has a fixture in `fixtures/sigs/`, all re-encodings of one
genuine signature, so the encoding is the only thing that varies.

> **`s-malleable.der` must VERIFY.** For any valid `(r, s)`, `(r, n-s)` is
> also valid — that is a property of ECDSA, not a defect in the fixture.
> Rejecting it rejects genuine signatures. It is in the corpus to catch
> over-eager hardening, and question 1 in `NOTES.md` is about what it
> implies.

### 4.3 The verification equation

With `e` the SHA-256 digest of the message as a big-endian integer (P-256's
order is 256 bits, so the whole digest is used):

```
w  := s⁻¹ mod n
u1 := e·w mod n
u2 := r·w mod n
R  := u1·G + u2·Q          -- EC_POINT_mul does both terms at once
reject if R is the point at infinity
accept iff (R.x mod n) == r
```

Two things are easy to leave out and neither shows up on a valid signature:
the infinity check, and the `mod n` on `R.x`.

### 4.4 Errors versus false

A malformed key or encoding is a `SignatureError`. A well-formed signature
that simply does not match is `Verify()` returning `false`. Keep those apart:
collapsing them makes "this input was nonsense" indistinguishable from "this
input was a forgery attempt", and only one of those is worth an alert.

---

## 5. Part 3 — authorisation

### 5.1 The maintenance token

A technician's USB stick carries `maintenance.token` and its `.sig`. The
device's initramfs verifies it before unlocking maintenance mode.

```
purpose=maintenance
device=CM5-0001-A7F3
created=1785196740
expires=1785200400
nonce=7b1f4c02d9a34e18
```

### 5.2 Parsing rules

The parser is the security boundary here, not an afterthought.

* LF line endings. A carriage return anywhere is a rejection.
* No NUL bytes.
* Each line is `key=value` with a non-empty key. Blank lines are rejected.
  The final line may omit its trailing newline.
* Exactly the five keys above. **An unknown key is a rejection**, not
  something to ignore — a field you skip is a field the signer thought they
  were asserting.
* **A duplicate key is a rejection.** Do not take the first, and do not take
  the last: if two readers of the same bytes can disagree about what the token
  says, an attacker picks which reader to target.
* All five values must be present and non-empty. `created` and `expires` are
  decimal integers.

### 5.3 Verifying a token

In this order, and the order is the point:

1. **Establish who signed it.** Try the token's detached signature against
   each key in the keyring. If none verifies, the token is not signed by
   anyone this device trusts, and nothing further is worth doing.
2. **Check that signer is authorised.** The matching signer's `purposes` must
   include the required purpose. Being trusted to sign *something* is not
   being permitted to authorise *this* — the keyring holds a catalogue key
   too, and `signed-by-catalog-signer.token` is exactly that case.
3. **Only now parse the token.** Parsing unauthenticated input is how parsers
   become the attack surface: every rule in section 5.2 is running on bytes an
   attacker chose, so run it on bytes you have already authenticated.
4. Apply policy:
   - `purpose` equals the required purpose;
   - `device` is **not** `*`, and equals this unit's serial;
   - `expires > created`;
   - `expires - created <= max_window` (default 24 h);
   - `created <= now + max_clock_skew` (default 300 s);
   - `now < expires`.

> `device=*` is what the shipping script actually emits. A token that matches
> every unit matches every attacker's unit too, and one leaked stick is then a
> fleet-wide master key. Rejecting it is deliberate; question 2 in
> `NOTES.md` is about it.

### 5.4 Service-mode challenge/response

Away from the USB path, a technician authenticates against a per-unit shared
secret. The device sends a nonce; the tool returns a hex tag.

```
tag = HMAC-SHA256(secret,
                  "viss-service-v1" || 0x00 ||
                  device_id         || 0x00 ||
                  nonce             || 0x00 ||
                  purpose)
```

`VerifyServiceResponse` recomputes the tag and compares it with the hex string
supplied. Two requirements, and `fixtures/service/vectors.json` tests both:

* **The separators are load-bearing.** Concatenating the fields directly makes
  `("AB", "CD")` and `("ABC", "D")` the same input, so one response
  authenticates both. The vectors include that pair. (Fields are ASCII and
  contain no NUL, so NUL separation is sufficient here; length prefixes would
  be stronger and are a fair thing to say so in your notes.)
* **Compare without an early exit.** The expected tag is derived from a
  secret, and a comparison that stops at the first differing byte leaks it one
  byte per attempt. Compare the full length every time, or use
  `CRYPTO_memcmp`.

The comparison is over the lowercase hex form, so an uppercase response is not
a match.

---

## 6. Known limitations

Real properties of the system as specified, not defects in the fixtures. Some
are the subject of the write-up questions.

* An unpadded bundle's bytes after the last data block are covered by neither
  the hash tree nor anything else.
* Nothing in this exercise binds a token's `nonce` to anything. Replay is
  bounded only by the validity window.
* There is no revocation. A signing key that leaks stays trusted until an OS
  update replaces the keyring, and the keyring ships inside the rootfs image.
* Nothing binds a signer to a device population, so a maintenance key is
  trusted by every unit that shipped with the same image.
