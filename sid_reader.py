#!/usr/bin/env python3
"""
sid_reader.py - an independent reader of draft-gruszka-scitt-statement-identification-04,
Section 6 (Conformance and Illustrative Test Cases).

Written from the text of Section 6 only, without reference to the draft author's own
checker. Python standard library only. Never touches the network.

For each case file it reports the four axes of Section 6 (ref_usable, match, is_scitt,
sig_valid), or UNSUPPORTED for a named scheme it does not implement, and compares them with
the expected result in the case file, including the variants.

    python3 sid_reader.py CASES_DIR

CASES_DIR is the cases/ folder of interop/scitt-statement-identification-04 in
https://github.com/b7n0de/proofbundle. Exit 0 only if every check matches.

Signature profile: sid-ed25519-strict (Section 6, rules 1 to 4). Variants that leave a rule
out are computed as the case file names them and are reported as outside the profile.

Part of the sebbi.pro statement-references work (draft-dobson-scitt-statement-references).
"""
import base64, hashlib, json, os, struct, sys

# ============================================================== strict CBOR reader (RFC 8949)

class Bad(Exception):
    """Not well-formed or not valid (RFC 8949 s5.3.1)."""

class Tag:
    __slots__ = ("n", "v")
    def __init__(self, n, v): self.n, self.v = n, v

class Simple:
    __slots__ = ("n",)
    def __init__(self, n): self.n = n

class Float:
    """Keeps the width so NaN significands can be compared as Section 6 says."""
    __slots__ = ("value", "nan_sig")
    def __init__(self, value, nan_sig=None): self.value, self.nan_sig = value, nan_sig

BREAK = object()

def _half(h):
    s, e, f = (h >> 15) & 1, (h >> 10) & 0x1F, h & 0x3FF
    if e == 31:
        return Float(float("nan") if f else (-1) ** s * float("inf"), (f << 54) if f else None)
    v = (f / 1024.0) * 2 ** -14 if e == 0 else (1 + f / 1024.0) * 2 ** (e - 15)
    return Float(-v if s else v)

def _single(b):
    u = struct.unpack(">I", b)[0]
    e, f = (u >> 23) & 0xFF, u & 0x7FFFFF
    if e == 255 and f:
        return Float(float("nan"), f << 41)
    return Float(struct.unpack(">f", b)[0])

def _double(b):
    u = struct.unpack(">Q", b)[0]
    e, f = (u >> 52) & 0x7FF, u & 0xFFFFFFFFFFFFF
    if e == 2047 and f:
        return Float(float("nan"), f << 12)
    return Float(struct.unpack(">d", b)[0])

class Reader:
    def __init__(self, b):
        self.b, self.i = b, 0

    def need(self, n):
        if self.i + n > len(self.b):
            raise Bad("truncated")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def arg(self, ai):
        if ai < 24: return ai
        if ai == 24: return self.need(1)[0]
        if ai == 25: return int.from_bytes(self.need(2), "big")
        if ai == 26: return int.from_bytes(self.need(4), "big")
        if ai == 27: return int.from_bytes(self.need(8), "big")
        raise Bad("reserved additional information")

    def item(self, depth=0, allow_break=False):
        if depth > 512:
            raise Bad("too deep")
        ib = self.need(1)[0]
        mt, ai = ib >> 5, ib & 31
        if ib == 0xFF:
            if allow_break: return BREAK
            raise Bad("unexpected break")
        if mt == 0: return self.arg(ai)
        if mt == 1: return -1 - self.arg(ai)
        if mt in (2, 3):
            if ai == 31:
                parts = []
                while True:
                    c = self.need(1)[0]
                    if c == 0xFF: break
                    if c >> 5 != mt or c & 31 == 31:
                        raise Bad("bad chunk in indefinite string")
                    self.i -= 1
                    parts.append(self._string(mt, depth))
                raw = b"".join(p if isinstance(p, bytes) else p.encode() for p in parts)
                return raw if mt == 2 else "".join(parts)
            self.i -= 1
            return self._string(mt, depth)
        if mt == 4:
            out = []
            if ai == 31:
                while True:
                    v = self.item(depth + 1, True)
                    if v is BREAK: return out
                    out.append(v)
            for _ in range(self.arg(ai)):
                out.append(self.item(depth + 1))
            return out
        if mt == 5:
            pairs = []
            if ai == 31:
                while True:
                    k = self.item(depth + 1, True)
                    if k is BREAK: break
                    pairs.append((k, self.item(depth + 1)))
            else:
                for _ in range(self.arg(ai)):
                    k = self.item(depth + 1)
                    pairs.append((k, self.item(depth + 1)))
            seen = set()
            for k, _ in pairs:
                kk = key_of(k)
                if kk in seen:
                    raise Bad("duplicate map key")
                seen.add(kk)
            return dict_of(pairs)
        if mt == 6:
            return Tag(self.arg(ai), self.item(depth + 1))
        # major type 7
        if ai < 20: return Simple(ai)
        if ai == 20: return False
        if ai == 21: return True
        if ai == 22: return None
        if ai == 23: return Simple(23)
        if ai == 24:
            n = self.need(1)[0]
            if n < 32: raise Bad("simple value in two bytes below 32")
            return Simple(n)
        if ai == 25: return _half(int.from_bytes(self.need(2), "big"))
        if ai == 26: return _single(self.need(4))
        if ai == 27: return _double(self.need(8))
        raise Bad("reserved simple")

    def _string(self, mt, depth):
        ib = self.need(1)[0]
        raw = self.need(self.arg(ib & 31))
        if mt == 2:
            return raw
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise Bad("text string is not valid UTF-8")


class Map:
    """Ordered pairs; lookup by key equivalence."""
    def __init__(self, pairs): self.pairs = pairs
    def get(self, k, default=None):
        kk = key_of(k)
        for a, b in self.pairs:
            if key_of(a) == kk: return b
        return default

def dict_of(pairs): return Map(pairs)

def key_of(x):
    """RFC 8949 s5.6.1 key equivalence, as Section 6 spells it out."""
    if isinstance(x, bool): return ("bool", x)
    if isinstance(x, int): return ("int", x)
    if isinstance(x, bytes): return ("bytes", x)
    if isinstance(x, str): return ("text", x)
    if x is None: return ("null",)
    if isinstance(x, Float):
        if x.nan_sig is not None: return ("nan", x.nan_sig)
        return ("float", 0.0 if x.value == 0 else x.value)
    if isinstance(x, Simple): return ("simple", x.n)
    if isinstance(x, list): return ("array", tuple(key_of(i) for i in x))
    if isinstance(x, Map): return ("map", frozenset((key_of(a), key_of(b)) for a, b in x.pairs))
    if isinstance(x, Tag): return ("tag", x.n, key_of(x.v))
    raise Bad("unknown item")

def read_one(b):
    r = Reader(b)
    v = r.item()
    if r.i != len(b):
        raise Bad("bytes after the data item")
    return v

# ============================================================== Ed25519, sid-ed25519-strict

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
O = (0, 1, 1, 0)

def _add(a, b):
    x1, y1, z1, t1 = a; x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % P; B = (y1 + x1) * (y2 + x2) % P
    C = 2 * t1 * t2 * D % P; Dd = 2 * z1 * z2 % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)

def _mul(n, pt):
    q = O
    while n:
        if n & 1: q = _add(q, pt)
        pt = _add(pt, pt); n >>= 1
    return q

def _eq(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0

def _decode(s, canonical=True):
    """RFC 8032 s5.1.3. canonical=False reads y modulo p (for the rule-1-left-out reading)."""
    if len(s) != 32: return None
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    sign = s[31] >> 7
    if y >= P:
        if canonical: return None
        y %= P
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P: x = x * SQRT_M1 % P
    if (x * x - x2) % P: return None
    if x == 0 and sign: return None
    if x & 1 != sign: x = P - x
    return (x, y, 1, x * y % P)

GY = 4 * pow(5, P - 2, P) % P
BASE = _decode(int.to_bytes(GY, 32, "little"))

def _order_l(pt):
    return _eq(_mul(L, pt), O) and not _eq(pt, O)

def ed25519_strict(A_bytes, sig, msg, rules="all"):
    """rules: 'all' (the profile), 'no-rule-2', 'no-rule-2-cofactored', 'no-rule-3'."""
    R_b, S_b = sig[:32], sig[32:]
    A = _decode(A_bytes)
    R = _decode(R_b)
    if A is None or R is None:                                        # rule 1
        return False
    if rules not in ("no-rule-2", "no-rule-2-cofactored"):
        if not (_order_l(A) and _order_l(R)):                         # rule 2
            return False
    S = int.from_bytes(S_b, "little")
    if rules != "no-rule-3" and S >= L:                               # rule 3
        return False
    k = int.from_bytes(hashlib.sha512(R_b + A_bytes + msg).digest(), "little") % L
    lhs, rhs = _mul(S, BASE), _add(R, _mul(k, A))                     # rule 4
    if rules == "no-rule-2-cofactored":
        return _eq(_mul(8, lhs), _mul(8, rhs))
    return _eq(lhs, rhs)

# ============================================================== Section 6

HASH_LEN = {-14: 20, -15: 8, -16: 32, -17: 32, -18: 32, -43: 48, -44: 64, -45: 64}
IMPLEMENTED = {("ToBeSigned", -16): hashlib.sha256, ("ToBeSigned", -44): hashlib.sha512}

def _cbor_head(mt, n):
    if n < 24: return bytes([mt << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size): return bytes([mt << 5 | ai]) + n.to_bytes(size, "big")

def to_be_signed(protected, aad, payload):
    """Section 5.1: ["Signature1", body_protected, external_aad, payload], definite, shortest form."""
    out = _cbor_head(4, 4) + _cbor_head(3, 10) + b"Signature1"
    for b in (protected, aad, payload):
        out += _cbor_head(2, len(b)) + b
    return out

def reference_usable(ref_bytes, scheme):
    try:
        ref = read_one(ref_bytes)
    except Bad:
        return False
    if not isinstance(ref, list) or len(ref) != 3:
        return False
    alg, name, digest = ref
    if isinstance(alg, bool) or not isinstance(alg, int) or alg not in HASH_LEN:
        return False
    if not isinstance(name, str) or not isinstance(digest, bytes) or len(digest) != HASH_LEN[alg]:
        return False
    return alg == scheme["alg"] and name == scheme["name"]

def read_candidate(c):
    """Returns (is_scitt, protected_bytes, payload) or None if the read check fails."""
    try:
        top = read_one(c)
    except Bad:
        return None
    tagged = isinstance(top, Tag)
    if tagged:
        if top.n != 18: return None
        top = top.v
    if not isinstance(top, list) or len(top) != 4:
        return None
    prot, unprot, payload, sig = top
    if not isinstance(prot, bytes) or not isinstance(unprot, Map) or not isinstance(sig, bytes):
        return None
    if payload is not None and not isinstance(payload, bytes):
        return None
    if prot:
        try:
            if not isinstance(read_one(prot), Map): return None
        except Bad:
            return None
    return tagged, prot, payload, sig

def evaluate(inp, rules="all"):
    scheme = inp["scheme"]
    h = IMPLEMENTED.get((scheme["name"], scheme["alg"]))
    if h is None:
        return "UNSUPPORTED"
    usable = reference_usable(inp["reference"], scheme)
    rc = read_candidate(inp["candidate"])
    if rc is None:
        return {"ref_usable": usable, "match": "NO_MATCH" if usable else "INDETERMINATE",
                "is_scitt": False, "sig_valid": None}
    tagged, prot, payload, sig = rc
    aad = inp["external_aad"]
    if payload is None:
        payload = inp["detached_payload"]
    missing = payload is None or aad is None
    tbs = None if missing else to_be_signed(prot, aad, payload)
    if not usable or missing:
        match = "INDETERMINATE"
    else:
        match = "MATCH" if h(tbs).digest() == read_one(inp["reference"])[2] else "NO_MATCH"
    if len(sig) != 64:
        sv = False
    elif missing:
        sv = None
    else:
        sv = ed25519_strict(inp["stated_key"]["public_key"], sig, tbs, rules)
    return {"ref_usable": usable, "match": match, "is_scitt": tagged, "sig_valid": sv}

# ============================================================== case files

def _bytes(v):
    if isinstance(v, dict) and "base64" in v:
        return base64.b64decode(v["base64"])
    return v

def _inputs(raw):
    out = {k: _bytes(v) for k, v in raw.items()}
    out["stated_key"] = {"public_key": _bytes(raw["stated_key"]["public_key"])}
    out["scheme"] = raw["scheme"]
    return out

def run(cases_dir):
    names = sorted((f for f in os.listdir(cases_dir) if f.endswith(".json")),
                   key=lambda f: int("".join(ch for ch in f if ch.isdigit()) or 0))
    checks = bad = 0
    for f in names:
        case = json.load(open(os.path.join(cases_dir, f)))
        base = _inputs(case["inputs"])
        jobs = [(case["id"], base, "all", case["expected"])]
        for v in case.get("variants", []):
            inp = dict(base)
            for k, val in v.get("change", {}).items():
                inp[k] = _bytes(val)
            jobs.append(("%s [%s]" % (case["id"], v["name"]), inp, v.get("rules", "all"), v["expected"]))
        for label, inp, rules, exp in jobs:
            got = evaluate(inp, rules)
            if isinstance(exp, dict) and isinstance(got, dict):
                ok = all(got[k] == exp[k] for k in exp)
                shown = {k: got[k] for k in exp}
            else:
                ok, shown = got == exp, got
            checks += 1; bad += not ok
            profile = "sid-ed25519-strict" if rules == "all" else "outside profile (%s)" % rules
            print("%-4s %-60s %s  %s" % ("ok" if ok else "FAIL", label[:60], shown, profile))
    print("%d of %d checks match" % (checks - bad, checks))
    return bad == 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(2)
    sys.exit(0 if run(sys.argv[1]) else 1)
