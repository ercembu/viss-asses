# NOTES

Replace this skeleton with your own. One page is plenty; bullet points are
fine. We are reading for how you think, not for prose.

---

## Status

What is finished, what is partial, what you did not start. Be specific and be
honest — an accurate "Part 3 parses but does not enforce the window" is worth
more than a vague "mostly done".

| Part | State | Notes |
|---|---|---|
| 1 — `hashtree.cpp` |complete | |
| 2 — `ecdsa.cpp` |complete |  |
| 3 — `token.cpp` |mostly complete | could not verify all cases, tbd |
| Tests | mostly compelte | could not write all unit tests for task 3 |

## What I would do next

I would first make sure that all the unit tests are working for task 3 correctly, 
since that also helps in verifying the overall functionality of the tasks 
(especially 2 and 3). I also want to take more time to refine the code and write it 
cleaner so as to make it more readable and idiomatic. I would also check for any bugs 
in the way the signature is verified since I used most of the checks from pubkey.cpp.

## Spec ambiguities, errors and dangers

Anything in `SPEC.md` you found ambiguous, wrong or dangerous, and what you
did about it. Where you had to decide something the spec did not settle, say
what you decided and why. Disagreeing with us is fine and scores as well as
agreeing, provided the argument is clear.

> It is to be assumed that the keyring is present in the read only part of rootfs. 
  Salt size is read from an unauthenticated superrblock with no bound.
  There is no mention as to why if a superblock is malformed, it has to crash or what sort of a crash.
  There are not a lot of checks for `created` and `expires` keys in task 3, which leaves it open for loopholes.

## Question 1 — signature malleability

`fixtures/sigs/s-malleable.der` is a second valid signature over the same
message, produced without the private key. Our app catalog identifies each
bundle by `bundle_sig_hash` — the SHA-256 of its `.sig` file. What goes wrong,
and what would you use as the identifier instead?

> your answer

## Question 2 — the tokens already in the field

The token format is taken from a script we actually ship, which emits
`device=*` and no `expires` field at all. Section 5.3 rejects both. A fleet of
units is already running with those tokens in circulation. What is the
exploit, and how would you roll out the fix without bricking the technicians'
access?

> This makes the signed token trustable by every device and can potentially unlock any unit. 
  Instead of the USB stick being used for a single device for authentication, it can well be used
  for all devices. With no expiration, the access never gets denied when the token is checked for validity.
  That's why the method of rejecting device=* offers a failsafe to prevent this and only works when the device
  ID is equal to the unit's serial ID.

  Roll out: 
  1. change to per device `device=` and a short `expires` window.
  2. Ship a patched OS temporarily to accept legacy tokens for a fixed short period (while also logging the legacy presence).
  3. After the short grace period, adopt stricter verifiers to reject `*` and missing expires or any such dangerous loopholes.

## Anything else

Tools you used, including AI ones, and what you used them for. This costs you
nothing — we use them too — and you will be asked to walk through and modify
this code live, so it is worth being straight about it here.


> I used OpenCode for writing boilerplate and helper functions when dealing with the tasks. 
I also used OpenCode but in ask mode to ask for more information on how some parts could be 
implemented (especially task 2 since I am not too familiar with ECDSA). Unit tests were written 
by myself while using the examples provided in `test_public.cpp`.
