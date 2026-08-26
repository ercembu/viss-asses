# vissapp — device-side cryptography

An implementation exercise for the VISS OS embedded team.

VISS OS is a Yocto Linux distribution for the Raspberry Pi Compute Module 5.
It refuses to act on anything it cannot authenticate: application bundles are
integrity-protected with dm-verity, everything is signed with ECDSA P-256,
every signing key it trusts is listed in a keyring baked into the image, and
maintenance access is granted by signed, time-bounded, device-bound tokens.

This exercise is that machinery, self-contained. Same formats, same trust
model, same failure modes — no hardware, no Yocto build.

You will implement the three checks the device makes before it trusts
anything:

| Part | File | Question it answers |
|---|---|---|
| 1 | `src/hashtree.cpp` | Do these bytes still hash to what was signed? |
| 2 | `src/ecdsa.cpp` | Was this signature produced by the holder of a private key? |
| 3 | `src/token.cpp` | Is that holder allowed to do *this*, *here*, *now*? |

Everything you need is in this directory. There is nothing else to fetch and
nobody to ask — where the spec is ambiguous, decide, and write down in
`NOTES.md` what you decided and why. That is a graded part of the exercise,
not a fallback.

---

## Timing

**Six hours, hard.** We agree the start time with you in advance; six hours
later, whatever is pushed is what we grade.

The clock is on wall time, not on time-at-keyboard — take breaks, but they
come out of the six. Git timestamps are the record, so commit as you go and
do not rewrite history to tidy them up. We would rather see the real shape of
the work, including the commit where you realised the tree loop was wrong.

It is scoped to fit with room to spare, but only if you spend the first half
hour reading rather than typing — `SPEC.md` is the contract, and skimming it
is the most common way to lose an hour later.

A suggested shape, if it helps:

| | |
|---|---|
| 0:00–0:30 | fork, clone, build, read `SPEC.md`, run the starter tests |
| 0:30–1:45 | Part 1 |
| 1:45–4:00 | Part 2 |
| 4:00–5:00 | Part 3 |
| 5:00–6:00 | your own tests, `NOTES.md`, tidy up, open the PR |

If you are running short, **stop implementing at 5:00 regardless** and spend
the last hour on tests and notes. A correct Part 1 and 2 with real tests and
honest notes scores better than three parts that nobody checked.

Leave yourself the last fifteen minutes for the push and the pull request. An
excellent submission that never left your laptop scores nothing.

---

## Getting the code

Work in a **fork** of this repository, on your own GitHub account.

1. Fork `https://github.com/ercembu/viss-asses` (the **Fork** button, top
   right). Keep the default name.
2. Clone your fork and set up a branch:

   ```bash
   git clone https://github.com/<your-username>/viss-asses.git
   cd viss-asses/candidate
   git checkout -b solution
   ```

3. Build once, **before your window starts**, to confirm your toolchain
   works (see below). Tell us if it does not — that is a free fix beforehand
   and an expensive one at 0:20.

Do not push to this repository directly; you will not have access. Everything
you commit goes to your fork.

---

## Building

C++17, CMake, and libcrypto. On Debian/Ubuntu:

```bash
sudo apt install build-essential cmake libssl-dev
```

All CMake commands run from this `candidate/` directory:

```bash
cd candidate
cmake -B build
cmake --build build -j
./build/tests/viss-tests          # or: ctest --test-dir build --output-on-failure
```

All four starter tests fail right now. That is the starting point.

cJSON is vendored in `vendors/cjson`, exactly as it is in `viss_gui`. Nothing
else to install — no `veritysetup`, no root, no network. The fixtures are real
keys, real OpenSSL signatures and real dm-verity trees, committed so you do
not need the tools that made them.

The CLI is wired up and works once your code does:

```bash
NOW=$(cat fixtures/now.txt)

./build/vissapp verifysig fixtures/sigs/message.bin \
    fixtures/sigs/valid.der fixtures/sigs/signer.pub

./build/vissapp token fixtures/tokens/valid.token \
    --keyring keys/keyring.json --device CM5-0001-A7F3 --now $NOW
```

---

## The task

The three files above throw `TODO:` and need implementing. Each declaration in
the matching header points at the part of `SPEC.md` that defines it.

Provided and needing no changes: `src/pubkey.cpp` (parsing a P-256 public key
out of PEM), `src/keyring.cpp` (loading the device's trusted-signer keyring —
Part 3 uses it, so read the header), `src/crypto_util.cpp` (SHA-256, HMAC,
hex, base64, file I/O), `src/json.cpp`, `src/main.cpp`, all headers, the test
harness and the build files.

**Read `SPEC.md` first, in full.** It is the contract, and in this exercise it
is also the threat model. Several of its details look like pedantry on a first
read and are the entire point — it flags them where they occur.

One hard constraint, in section 4: **you may not call `EVP_DigestVerify`,
`ECDSA_do_verify` or `ECDSA_verify`.** Those are the function you are writing.
`BIGNUM` and `EC_POINT` are not only allowed but expected — you are not being
asked to write modular arithmetic.

Keep the declared signatures; they are what the grading suite calls. You may
add anything you like alongside them — helpers, new files, new tests — but do
not change the fixtures, the keyring, the headers or the build files. We
overlay pristine copies of those before grading, so a submission that depends
on an edited fixture fails on our machine rather than yours.

---

## What to hand back

1. **The three implemented files** — `hashtree.cpp`, `ecdsa.cpp`, `token.cpp`.
   They should build clean under `-Wall -Wextra`, which the build already
   enables.
2. **Your own tests**, added to `tests/`. The starter suite has four tests —
   one per part, plus one for the service HMAC — and every one of them checks
   only that a *valid* thing is accepted. An implementation that accepts
   everything passes three of the four.

   The corpus is mostly the opposite case. `fixtures/sigs/` holds fifteen
   signature encodings; `fixtures/tokens/` holds seventeen tokens;
   `fixtures/service/vectors.json` holds eleven vectors **with their expected
   results already in the file**. Almost all must be rejected, and nothing in
   `tests/` currently looks at any of them. Every file is named after the
   condition it exercises.

   Add sources to `VISSAPP_TEST_SOURCES` in `tests/CMakeLists.txt`, or just
   extend `test_public.cpp`. `TEST(Suite, Name)` and the `EXPECT_*` /
   `ASSERT_*` macros are documented at the top of `tests/viss_test.h`;
   `tests/test_support.h` has helpers for fixture paths, the device keyring
   and the fixed "now".
3. **`NOTES.md`**, one page is plenty. A skeleton with the questions is
   already in this directory — fill it in. Anything you found ambiguous,
   wrong or dangerous in `SPEC.md` and what you did about it, plus answers to
   the two questions below. Bullet points are fine — we are reading for how
   you think, not for prose.

### Questions for `NOTES.md`

1. `fixtures/sigs/s-malleable.der` is a second valid signature over the same
   message, produced without the private key. Our app catalog identifies each
   bundle by `bundle_sig_hash` — the SHA-256 of its `.sig` file. What goes
   wrong, and what would you use as the identifier instead?

2. The token format is taken from a script we actually ship, which emits
   `device=*` and no `expires` field at all. Section 5.3 rejects both. Suppose
   you are told a fleet of units is already running with those tokens in
   circulation. What is the exploit, and how would you roll out the fix
   without bricking the technicians' access?

---

## Submitting

Inside the six hours:

```bash
cd viss-asses            # the repository root of your fork
git add -A
git commit -m "vissapp exercise: parts 1-3, tests, notes"
git push -u origin solution
```

Then open a **pull request from your fork against
`ercembu/viss-asses`**, targeting `main`:

* Title it `<Your Name> — vissapp exercise`.
* In the description, say which parts are complete, what you did not get to,
  and anything we need to know to build it. One paragraph.
* Do not merge it, and do not push after the window closes. If you spot
  something afterwards, say so in a PR comment rather than committing — an
  honest "I noticed this an hour later" costs nothing and reads well.

Sanity-check before you open it:

```bash
cd candidate
rm -rf build && cmake -B build && cmake --build build -j 2>&1 | grep -i warn
./build/tests/viss-tests
git status --short        # NOTES.md committed? build/ not committed?
```

`build/` is already in `.gitignore` — keep it that way. We build from source.

---

## How it is assessed

Roughly, in descending weight: correctness against the full corpus; how you
handle malformed and hostile input; the tests you wrote; the clarity of the
code; and the judgement in `NOTES.md`.

Rejecting valid inputs counts against you as much as accepting invalid ones. A
verifier that says no to everything is not secure, it is broken.

Judged against six hours, not against an open-ended take-home. An unfinished
Part 3 with a note saying what was left is normal and costs little; silence
about it costs more.

**On using AI tools:** use them if you want, we do. But you will walk us
through this code in a follow-up session and be asked to change it live, so
submit only what you can explain and modify. Cryptographic code you cannot
explain is worth less than none — it looks like it works.

Parts 1 and 2 are the core. Say in `NOTES.md` what you would have done next
if you ran out of time — that reads far better than silence.
