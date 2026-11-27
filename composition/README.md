# Composition at registration: test vectors

For any SCITT Transparency Service that wants to apply requirements C2 and C3 of
draft-dobson-scitt-statement-references:

> Refuse a Signed Statement unless every reference it carries resolves to a statement
> already registered in this service with the same iss and sub. On refusal, register nothing.

## Files

- `composition-vectors.json`: eight Signed Statements (base64, with SHA-256 and length)
  and ten registration steps, each with the outcome the service must give.
- `make_vectors.py`: rebuilds the JSON byte for byte from fixed Ed25519 test seeds.
  Test keys only.

## The reference form

Protected header, text label `"inputs"`: an array of `[iss text, sub text, digest bstr(32)]`,
where digest is SHA-256 over the referenced statement's Sig_structure
`["Signature1", protected, h'', payload]` (the ToBeSigned scheme of
draft-gruszka-scitt-statement-identification). This is the form live at sebbi.pro today.
A set for the draft's proposed form `[alg, scheme, digest]` follows once the design team
settles it.

## The steps

Start from a log holding none of these statements, register in order, compare.

| Step | Register | Expect | Why |
|---|---|---|---|
| 1 | B | refuse, Missing Reference | cites A, not yet registered; nothing is registered |
| 2 | A | accept | cites nothing |
| 3 | B | accept | A is now there with the same iss and sub |
| 4 | C | refuse, Missing Reference | cites A and A2; A2 missing |
| 5 | A2 | accept | cites nothing |
| 6 | C | accept | both references resolve |
| 7 | D | refuse, Missing Reference | right digest, wrong sub |
| 8 | E | refuse, Rejected | 31-byte digest: not well-formed |
| 9 | F | refuse, Rejected | empty inputs array |
| 10 | G | refuse, Missing Reference | digest over whole bytes, not ToBeSigned |

The problem titles are sebbi.pro's. Another service may use its own titles; what must agree
is accept or refuse at each step, and that a refused statement leaves no entry.

## Measured

The ten steps give the expected outcome through sebbi.pro's live registration policy
(modules/scitt.py with modules/scittdoor.py), run against an in-memory log, 27 November 2026.
The same steps can be run against the live service at https://sebbi.pro/entries
(statements are registered permanently there).
