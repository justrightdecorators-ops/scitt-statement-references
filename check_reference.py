#!/usr/bin/env python3
"""
check_reference.py v2 - conformance checker for References between SCITT Signed Statements
(draft-dobson-scitt-statement-references).

Standard library only. Never touches the network. Verifies no signatures: sig_valid is
always reported as "not checked".

A Reference has the form of draft-gruszka-scitt-statement-identification-05, A1:

    [alg, scheme, digest]        a CBOR array, or JSON {"alg", "scheme", "digest" (hex)}

optionally with "iss" and "sub" (JSON only), checked against the CWT claims of the candidate.

Given a candidate COSE_Sign1 and a Reference, it reports three of the axes of Section 6 of
that draft (ref_usable, match, is_scitt) and, for a MATCH, what the match shows (C1). The
outcomes MATCH, NO_MATCH, INDETERMINATE and UNSUPPORTED are kept apart.

Schemes:
  ToBeSigned, alg -16 or -44   digest over the COSE Sig_structure
                               ["Signature1", protected, external_aad, payload] (RFC 9052 s4.4),
                               as in Gruszka -05. Equality shows: the same signed content.
                               external_aad: by default this checker uses the FIXED EMPTY
                               external_aad variant. --aad HEX supplies one; --aad-named says
                               one is named but not supplied, which gives INDETERMINATE.
  ReceivedBytes, alg -16       SHA-256 of the candidate's bytes exactly as received (defined by
                               draft-dobson-scitt-statement-references, not by Gruszka).
                               Equality shows: the same octets.
  CEGStatementId, alg -16      the statement id of draft-moore-scitt-ciris-ceg-04, Section 5.2:
                               SHA-256 of the deterministic encoding of the three-element array
                               ["CEG-statement-id/2", protected, payload], protected and payload
                               as byte strings. The label is inside the hashed bytes, so the
                               value cannot be mistaken for a digest under another rule. It reads
                               no external_aad (that draft fixes it empty) and no signature.
                               Equality shows: the same protected header and payload. It selects
                               the same statements as ToBeSigned when external_aad is empty, and
                               gives a different value; two statements signed over different
                               external_aad share a CEGStatementId and differ under ToBeSigned.
  any other scheme             UNSUPPORTED.

A candidate is read strictly (RFC 8949): one data item and nothing after it, tag 18 or untagged,
valid UTF-8, no duplicate map keys. A candidate that fails is not a statement (is_scitt false).
A detached payload not supplied gives INDETERMINATE, never a success.

Usage:
  python3 check_reference.py CANDIDATE REFERENCE [--payload FILE] [--aad HEX | --aad-named]
  python3 check_reference.py --identifiers CANDIDATE [--payload FILE]
  python3 check_reference.py --cases CASES_DIR     # Gruszka Section 6 cases, three axes
  python3 check_reference.py --selftest [--b3 original_b3.cose]
"""
import base64, binascii, hashlib, json, os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sid_reader import Bad, Map, Tag, read_one, to_be_signed, HASH_LEN  # strict RFC 8949 reader
from sid_reader import _cbor_head

VERSION = "2.0.0"
HASHES = {-16: hashlib.sha256, -44: hashlib.sha512}
SCHEMES = {
    ("ToBeSigned", -16): "the same signed content",
    ("ToBeSigned", -44): "the same signed content",
    ("ReceivedBytes", -16): "the same octets as received",
    ("CEGStatementId", -16): "the same protected header and payload",
}
CEG_LABEL = b"CEG-statement-id/2"

def ceg_statement_id_input(protected, payload):
    """["CEG-statement-id/2", protected, payload], definite lengths, shortest form (ceg-04 Section 5.2)."""
    out = _cbor_head(4, 3) + _cbor_head(3, len(CEG_LABEL)) + CEG_LABEL
    for b in (protected, payload):
        out += _cbor_head(2, len(b)) + b
    return out

# ---------------------------------------------------------------- reading

def read_reference(ref):
    """Returns (alg, scheme, digest, context) or None if the reference is not well-formed."""
    ctx = {}
    if isinstance(ref, (bytes, bytearray)):
        try:
            v = read_one(bytes(ref))
        except Bad:
            return None
    elif isinstance(ref, dict):
        ctx = {k: ref[k] for k in ("iss", "sub") if k in ref}
        try:
            v = [ref["alg"], ref["scheme"], binascii.unhexlify(ref["digest"])]
        except (KeyError, binascii.Error, TypeError):
            return None
    else:
        return None
    if not isinstance(v, list) or len(v) != 3:
        return None
    alg, scheme, digest = v
    if isinstance(alg, bool) or not isinstance(alg, int) or alg not in HASH_LEN:
        return None
    if not isinstance(scheme, str) or not isinstance(digest, bytes) or len(digest) != HASH_LEN[alg]:
        return None
    return alg, scheme, digest, ctx

def read_candidate(raw):
    """Strict read. Returns (tagged, protected, payload, protected_map) or None if not a statement."""
    try:
        top = read_one(raw)
    except Bad:
        return None
    tagged = isinstance(top, Tag)
    if tagged:
        if top.n != 18:
            return None
        top = top.v
    if not isinstance(top, list) or len(top) != 4:
        return None
    prot, unprot, payload, sig = top
    if not isinstance(prot, bytes) or not isinstance(unprot, Map) or not isinstance(sig, bytes):
        return None
    if payload is not None and not isinstance(payload, bytes):
        return None
    pmap = None
    if prot:
        try:
            pmap = read_one(prot)
        except Bad:
            return None
        if not isinstance(pmap, Map):
            return None
    return tagged, prot, payload, pmap

def _get(m, key):
    if not isinstance(m, Map):
        return None
    for k, v in m.pairs:
        if k == key and not isinstance(k, bool):
            return v
    return None

def claims(pmap):
    cwt = _get(pmap, 15)
    return _get(cwt, 1), _get(cwt, 2)

# ---------------------------------------------------------------- check

def identifier(raw, scheme, alg, payload=None, aad=b""):
    """Returns the digest bytes, or None when an input is missing (INDETERMINATE)."""
    if scheme == "ReceivedBytes":
        return HASHES[alg](raw).digest()
    rc = read_candidate(raw)
    if rc is None:
        return None
    _, prot, pl, _ = rc
    pl = pl if pl is not None else payload
    if scheme == "CEGStatementId":
        return None if pl is None else HASHES[alg](ceg_statement_id_input(prot, pl)).digest()
    if pl is None or aad is None:
        return None
    return HASHES[alg](to_be_signed(prot, aad, pl)).digest()

def check(raw, ref, payload=None, aad=b""):
    """aad: bytes to use; b"" is the fixed-empty variant; None means named but not supplied."""
    r = read_reference(ref)
    if r is None:
        rc = read_candidate(raw)
        return {"ref_usable": False, "match": "INDETERMINATE", "is_scitt": bool(rc and rc[0]),
                "sig_valid": "not checked"}
    alg, scheme, digest, ctx = r
    if (scheme, alg) not in SCHEMES:
        return "UNSUPPORTED"
    rc = read_candidate(raw)
    if rc is None:
        return {"ref_usable": True, "match": "NO_MATCH", "is_scitt": False, "sig_valid": "not checked"}
    tagged, _, _, pmap = rc
    value = identifier(raw, scheme, alg, payload, aad)
    if value is None:
        match = "INDETERMINATE"
    else:
        match = "MATCH" if value == digest else "NO_MATCH"
    out = {"ref_usable": True, "match": match, "is_scitt": tagged, "sig_valid": "not checked"}
    if match == "MATCH" and ctx:
        iss, sub = claims(pmap)
        if ("iss" in ctx and ctx["iss"] != iss) or ("sub" in ctx and ctx["sub"] != sub):
            out["match"] = "NO_MATCH"
            out["context"] = "iss or sub differs"
    if out["match"] == "MATCH":
        out["shows"] = SCHEMES[(scheme, alg)] + " (scheme %s, alg %d)" % (scheme, alg)
    return out

# ---------------------------------------------------------------- Gruszka Section 6 cases

def _b(v):
    return base64.b64decode(v["base64"]) if isinstance(v, dict) and "base64" in v else v

def run_cases(cases_dir):
    """Compares ref_usable, match and is_scitt with each case and variant. sig_valid is skipped."""
    names = sorted((f for f in os.listdir(cases_dir) if f.endswith(".json")),
                   key=lambda f: int("".join(ch for ch in f if ch.isdigit()) or 0))
    n = bad = 0
    for f in names:
        case = json.load(open(os.path.join(cases_dir, f)))
        base = {k: _b(v) for k, v in case["inputs"].items()}
        jobs = [(case["id"], base, case["expected"])]
        for v in case.get("variants", []):
            if v.get("rules", "all") != "all":
                continue  # signature-rule variants: this checker verifies no signatures
            inp = dict(base)
            for k, val in v.get("change", {}).items():
                inp[k] = _b(val)
            jobs.append(("%s [%s]" % (case["id"], v["name"]), inp, v["expected"]))
        for label, inp, exp in jobs:
            sch = inp["scheme"]
            ref = inp["reference"]
            # a reference names its scheme; the case's scheme is what the verifier implements
            r = read_reference(ref)
            if r is not None and (r[1], r[0]) != (sch["name"], sch["alg"]):
                got = {"ref_usable": False, "match": "INDETERMINATE",
                       "is_scitt": bool(read_candidate(inp["candidate"]) and read_candidate(inp["candidate"])[0])}
                if (sch["name"], sch["alg"]) not in SCHEMES:
                    got = "UNSUPPORTED"
            elif (sch["name"], sch["alg"]) not in SCHEMES:
                got = "UNSUPPORTED"
            else:
                got = check(inp["candidate"], ref, inp.get("detached_payload"), inp.get("external_aad"))
            if isinstance(exp, dict) and isinstance(got, dict):
                keys = [k for k in ("ref_usable", "match", "is_scitt") if k in exp]
                ok = all(got.get(k) == exp[k] for k in keys)
                shown = {k: got.get(k) for k in keys}
            else:
                ok, shown = got == exp, got
            n += 1; bad += not ok
            print("%-4s %-50s %s" % ("ok" if ok else "FAIL", label[:50], shown))
    print("%d of %d match on ref_usable, match and is_scitt (sig_valid not checked)" % (n - bad, n))
    return bad == 0

# ---------------------------------------------------------------- self-test with known answers

# Statement 01 of draft-gruszka-scitt-statement-identification, Appendix A.1
# (MIT licence, Copyright (c) 2026 Konrad Gruszka, https://github.com/b7n0de/proofbundle).
STATEMENT_01 = base64.b64decode(
    "0oRYe6QBMgNwYXBwbGljYXRpb24vanNvbgRYIA5uhs0gwH306Vy0oHooYZLSn8dFZ7Qecm8cf3vSAutbD6MBdmh0dHBz"
    "Oi8vaXNzdWVyLmV4YW1wbGUCeCBwa2c6Z2VuZXJpYy9leGFtcGxlLXdpZGdldEAxLjAuMAYaaM57IKBYhnsiYXJ0aWZh"
    "Y3QiOiJleGFtcGxlLXdpZGdldC0xLjAuMC50YXIuZ3oiLCJsaWNlbnNlIjoiTUlUIiwic2hhMjU2IjoiNjA3ZTZjMWU2"
    "YzM1ZGNjOWI3NzBkZTVkYTkyYjk2OTcwNGEzNjZkNDY4OTcyYThiNTVkMWEwYzMyZGIzNGE3MiJ9WEAfsxpt80XxwYQN"
    "h4vUtKzttmEpVpFuS0VQxbZHkontNvQctgTIq3Q9wuufvaf+z7iWs9REujDlkeZjCTpO64EE")
KNOWN = {
    "01_tbs": "c3f5f13764679b9f77918bb52782480bc222be5ae4bce37f51384a6b1faa9dbc",
    "01_bytes": "9c7253617b9fe51ba25eb0f957dadea493ca03e98c4a81806237757f13d054c6",
    # draft-moore-scitt-ciris-ceg-04 Appendix B.3 (original_b3.cose in CIRISAI/CIRISConstitution,
    # ietf/scitt-companion-demo). Not embedded; pass --b3 to check it.
    "b3_tbs": "7bc1a5408ac6d6e9c8f3339c5c0e720998aa23be858da0dfda317f2e82d21689",
    "b3_bytes": "ec5d05875122c5043d18db3225737c0e977f30d80d3d9f4c13c1768aa7c60dab",
    # the statement id that Appendix B.3 of that draft states, over a 505-byte input
    "b3_ceg": "7d868e399743467fd3f01b0c92ab3e10a442ad1141f68a54261dd558c111bad4",
}

def selftest(b3_path=None):
    tbs = lambda raw: identifier(raw, "ToBeSigned", -16).hex()
    rb = lambda raw: identifier(raw, "ReceivedBytes", -16).hex()
    ref01 = {"alg": -16, "scheme": "ToBeSigned", "digest": KNOWN["01_tbs"], "iss": "https://issuer.example"}
    cases = [
        ("known answer: statement 01, ToBeSigned", tbs(STATEMENT_01) == KNOWN["01_tbs"]),
        ("known answer: statement 01, ReceivedBytes", rb(STATEMENT_01) == KNOWN["01_bytes"]),
        ("a correct reference matches", check(STATEMENT_01, ref01).get("match") == "MATCH"),
        ("a reference to the same content under ReceivedBytes does not",
         check(STATEMENT_01, dict(ref01, scheme="ReceivedBytes")).get("match") == "NO_MATCH"),
        ("an unknown scheme is UNSUPPORTED", check(STATEMENT_01, dict(ref01, scheme="WholeBytes")) == "UNSUPPORTED"),
        ("a 31-byte digest is not usable",
         check(STATEMENT_01, dict(ref01, digest=KNOWN["01_tbs"][:-2]))["ref_usable"] is False),
        ("a wrong iss does not match",
         check(STATEMENT_01, dict(ref01, iss="https://other.example"))["match"] == "NO_MATCH"),
        ("a byte after the candidate: not a statement",
         check(STATEMENT_01 + b"\x00", ref01)["is_scitt"] is False),
        ("tag 17: not a statement", check(b"\xd1" + STATEMENT_01[1:], ref01)["is_scitt"] is False),
        ("external_aad named but not supplied: INDETERMINATE",
         check(STATEMENT_01, ref01, aad=None)["match"] == "INDETERMINATE"),
        ("CEGStatementId is computable for any COSE_Sign1 with its payload",
         len(identifier(STATEMENT_01, "CEGStatementId", -16)) == 32),
        ("a different external_aad changes ToBeSigned and not CEGStatementId",
         identifier(STATEMENT_01, "ToBeSigned", -16, aad=b"x") != identifier(STATEMENT_01, "ToBeSigned", -16)
         and identifier(STATEMENT_01, "CEGStatementId", -16, aad=b"x") == identifier(STATEMENT_01, "CEGStatementId", -16)),
    ]
    if b3_path:
        b3 = open(b3_path, "rb").read()
        cases.append(("known answer: ceg-04 B.3, ToBeSigned", tbs(b3) == KNOWN["b3_tbs"]))
        cases.append(("known answer: ceg-04 B.3, ReceivedBytes", rb(b3) == KNOWN["b3_bytes"]))
        ceg = identifier(b3, "CEGStatementId", -16)
        rc = read_candidate(b3)
        cases.append(("known answer: ceg-04 B.3, CEGStatementId", ceg.hex() == KNOWN["b3_ceg"]))
        cases.append(("ceg-04 B.3: the statement id input is 505 bytes",
                      len(ceg_statement_id_input(rc[1], rc[2])) == 505))
        ref = {"alg": -16, "scheme": "CEGStatementId", "digest": KNOWN["b3_ceg"]}
        cases.append(("a CEG statement id matches under its own scheme",
                      check(b3, ref).get("match") == "MATCH"))
        cases.append(("the same value named as ToBeSigned does not match",
                      check(b3, dict(ref, scheme="ToBeSigned")).get("match") == "NO_MATCH"))
        cases.append(("CEGStatementId does not read external_aad",
                      check(b3, ref, aad=None).get("match") == "MATCH"))
        cases.append(("an unprotected header entry does not change the CEG statement id",
                      identifier(b3[:249] + bytes.fromhex("a119018a814100") + b3[250:], "CEGStatementId", -16) == ceg))
    bad = 0
    for name, ok in cases:
        print("%-4s %s" % ("ok" if ok else "FAIL", name)); bad += not ok
    print("%d/%d passed%s" % (len(cases) - bad, len(cases), "" if b3_path else " (pass --b3 for the B.3 known answer)"))
    return bad == 0

# ---------------------------------------------------------------- main

def _opt(argv, name, default=None):
    if name in argv:
        i = argv.index(name)
        return argv[i + 1] if i + 1 < len(argv) else default
    return default

def main(argv):
    if "--selftest" in argv:
        return 0 if selftest(_opt(argv, "--b3")) else 1
    if "--cases" in argv:
        return 0 if run_cases(_opt(argv, "--cases")) else 1
    payload = open(_opt(argv, "--payload"), "rb").read() if _opt(argv, "--payload") else None
    if "--identifiers" in argv:
        raw = open(_opt(argv, "--identifiers"), "rb").read()
        if read_candidate(raw) is None:
            print("not a statement (strict read failed)"); return 1
        for (scheme, alg), shows in SCHEMES.items():
            v = identifier(raw, scheme, alg, payload)
            print("%-14s alg %-4d %s  (equality shows: %s)" % (scheme, alg, v.hex() if v else "INDETERMINATE", shows))
        return 0
    pos = [a for a in argv[1:] if not a.startswith("--") and a not in (_opt(argv, "--payload"), _opt(argv, "--aad"))]
    if len(pos) == 2:
        raw = open(pos[0], "rb").read()
        refraw = open(pos[1], "rb").read()
        try:
            ref = json.loads(refraw)
        except (ValueError, UnicodeDecodeError):
            ref = refraw
        aad = None if "--aad-named" in argv else (binascii.unhexlify(_opt(argv, "--aad")) if _opt(argv, "--aad") else b"")
        out = check(raw, ref, payload, aad)
        print(json.dumps(out, indent=1))
        return 0 if isinstance(out, dict) and out.get("match") == "MATCH" else 1
    print(__doc__); return 2

if __name__ == "__main__":
    sys.exit(main(sys.argv))
