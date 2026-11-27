# Composition at registration: the Registration Policy

This is the reference check the ten steps in `composition-vectors.json` exercise,
written so another Transparency Service or gatekeeper can implement it.

The live sebbi.pro policy, as JSON: https://sebbi.pro/x/scittdoor/policy

## Where references are found

Protected header, text label `"inputs"`: a non-empty array of up to 64 references.

    inputs = [ [ iss: tstr, sub: tstr, digest: bstr .size 32 ], ... ]

A statement with no `"inputs"` header is unaffected by this policy. An empty
`"inputs"` array, or more than 64 references, is refused as not well-formed.

## The check, run before anything is written to the log

    for each reference r in inputs:
        r must be an array of exactly three: text, text, 32-byte string
            otherwise: refuse (sebbi.pro uses the title "Rejected")
        find a statement S already registered in THIS service where
            SHA-256( Sig_structure(S) ) == r.digest            # ToBeSigned scheme
            where Sig_structure(S) = ["Signature1", protected(S), h'', payload(S)]
        and the CWT claims of S have iss == r.iss and sub == r.sub
        if none:  refuse ("Missing Reference"), naming the reference
    if every reference resolved: continue with the service's normal registration

On any refusal nothing is registered: no entry, no Receipt, no log update.

## What the ten steps check

| Step | Submit | Expected |
|---|---|---|
| 1 | B, which cites A (A not yet registered) | refuse |
| 2 | A | accept |
| 3 | B again | accept |
| 4 | C, citing A and A2 (A2 not registered) | refuse, whole statement |
| 5 | A2 | accept |
| 6 | C again | accept |
| 7 | D, right digest of A under the wrong sub | refuse |
| 8 | E, a 31-byte digest | refuse |
| 9 | F, an empty `inputs` array | refuse |
| 10 | G, digest over A's whole bytes instead of its Sig_structure | refuse |

Only accept or refuse at each step needs to match, plus nothing registered on a
refusal. Error titles are free.

## Notes

- The digest is over the Sig_structure with an empty external_aad, so it does not
  change when a Receipt is attached or the unprotected header changes.
- sebbi.pro currently also resolves the CEG statement id of
  draft-moore-scitt-ciris-ceg-04 for the same 32-byte slot. The draft
  (draft-dobson-scitt-statement-references) moves to references that name their
  scheme, `[alg, scheme, digest]`, so a service resolves one value under one named
  scheme. The ten steps use only the ToBeSigned scheme, so they are unaffected.
