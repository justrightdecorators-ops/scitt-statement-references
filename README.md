# SCITT statement references

Open design-team workspace for references between SCITT Signed Statements:
how one Signed Statement identifies another so that independent
implementations can resolve each other's references, and how a
Transparency Service can refuse a statement whose references it cannot
resolve (composition at registration).

The SCITT working group chairs asked for this work to move off the mailing
list into an open design team (27 November 2026). Anyone is welcome to
take part: open an issue or a pull request.

## Contents

| File | What it is |
|---|---|
| `draft-dobson-scitt-statement-references-00.md` | Individual Internet-Draft (kramdown-rfc source): problem statement, requirements C1 to C5, the open question (header or payload), candidate design direction |
| `check_reference.py` | Conformance checker, Python standard library only, no network, verifies no signatures |
| `sid_reader.py` | Independent reader of Section 6 of draft-gruszka-scitt-statement-identification-04, written from the text only |
| `composition/` | Ten composition-at-registration steps with expected outcomes, and the script that rebuilds them byte for byte |

## Running the checker

```
python3 check_reference.py --selftest [--b3 original_b3.cose]
python3 check_reference.py --identifiers statement.cbor [--payload FILE]
python3 check_reference.py statement.cbor reference.json [--payload FILE] [--aad HEX | --aad-named]
python3 check_reference.py --cases <proofbundle>/interop/scitt-statement-identification-04/cases
```

A reference is CBOR `[alg, scheme, digest]`, or JSON
`{"alg": -16, "scheme": "ToBeSigned", "digest": "<hex>", "iss": "...", "sub": "..."}`.

Schemes: `ToBeSigned` (alg -16 or -44), as in draft-gruszka;
`ReceivedBytes` (alg -16), defined by this draft. Anything else is
UNSUPPORTED. By default the checker uses the fixed-empty external_aad
variant; `--aad` supplies one and `--aad-named` marks one as named but not
supplied (INDETERMINATE).

Results: ref_usable, match (MATCH, NO_MATCH, INDETERMINATE, UNSUPPORTED)
and is_scitt, plus what a match shows. sig_valid is reported as not
checked.

## Known answers

| Statement | ToBeSigned (SHA-256) | Bytes (SHA-256) |
|---|---|---|
| draft-gruszka Appendix A.1, statement 01 | `c3f5f137...faa9dbc` | `9c725361...3d054c6` |
| draft-moore-scitt-ciris-ceg-04 Appendix B.3 | `7bc1a540...2d21689` | `ec5d0587...7c60dab` |

On the published Section 6 cases of draft-gruszka the checker agrees on
ref_usable, match and is_scitt in all 58 checks it runs, and
`sid_reader.py` reproduces all 63 published results (54 cases, 9
variants) under sid-ed25519-strict:

```
python3 sid_reader.py <proofbundle>/interop/scitt-statement-identification-04/cases
```

The cases are at https://github.com/b7n0de/proofbundle.

## Timeline

- Fri 4 December 2026: revised text posted for working group review

## Builds on

- draft-gruszka-scitt-statement-identification (Konrad Gruszka)
- draft-le-comparing-derived-identifiers
- Tiago Pinto's note on derivation and comparison context:
  https://mailarchive.ietf.org/arch/msg/scitt/SsHbIj2bDs9TdiAsZ37NFUqt5TM/
- draft-mih-sokolov-scitt-payload-binding, draft-nobuo-scitt-protected-object-binding
- draft-moore-scitt-ciris-ceg (Eric Moore), draft-wright-verdict-record (Darren Wright)

## Licence

Code (`*.py`) is under the BSD 3-Clause licence in `LICENSE`. Statement 01
embedded in `check_reference.py` is from draft-gruszka-scitt-statement-identification
(MIT, Copyright (c) 2026 Konrad Gruszka). The draft text is an IETF
contribution and is subject to the IETF Trust Legal Provisions once
submitted.

Maintained by Justin Dobson, Founder and Lead Systems Architect, sebbi.pro.
