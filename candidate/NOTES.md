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
| 1 — `hashtree.cpp` | | |
| 2 — `ecdsa.cpp` | | |
| 3 — `token.cpp` | | |
| Tests | | |

## What I would do next

If you ran out of time, say what the next hour would have gone on and why that
first. This reads far better than silence.

## Spec ambiguities, errors and dangers

Anything in `SPEC.md` you found ambiguous, wrong or dangerous, and what you
did about it. Where you had to decide something the spec did not settle, say
what you decided and why. Disagreeing with us is fine and scores as well as
agreeing, provided the argument is clear.

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

> your answer

## Anything else

Tools you used, including AI ones, and what you used them for. This costs you
nothing — we use them too — and you will be asked to walk through and modify
this code live, so it is worth being straight about it here.
