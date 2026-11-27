#!/usr/bin/env python3
"""
make_vectors.py - test vectors for composition at registration
(draft-dobson-scitt-statement-references, requirements C2 and C3).

Builds a small set of Signed Statements and a script of registration steps with the
outcome a Transparency Service applying C2/C3 must give at each step. Deterministic:
fixed Ed25519 test seeds, so every run writes the same bytes. TEST KEYS ONLY.

Reference form used here is the one live at sebbi.pro today: a protected-header array
under the text label "inputs" of [iss text, sub text, digest bstr(32)], where digest is
SHA-256 over the referenced statement's Sig_structure ["Signature1", protected, h'', payload]
(the ToBeSigned scheme of draft-gruszka-scitt-statement-identification). The draft's
proposed form [alg, scheme, digest] will get its own set once the design team settles it.

    pip install cryptography
    python3 make_vectors.py            # writes composition-vectors.json
"""
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ISS_A, ISS_B = "https://publisher.test.example", "https://agent.test.example"

def _head(mt, n):
    if n < 24: return bytes([mt << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size): return bytes([mt << 5 | ai]) + n.to_bytes(size, "big")

def cbor(x):
    if isinstance(x, bool): return b"\xf5" if x else b"\xf4"
    if isinstance(x, int): return _head(0, x) if x >= 0 else _head(1, -1 - x)
    if isinstance(x, bytes): return _head(2, len(x)) + x
    if isinstance(x, str): b = x.encode(); return _head(3, len(b)) + b
    if isinstance(x, list): return _head(4, len(x)) + b"".join(cbor(i) for i in x)
    if isinstance(x, dict):
        items = sorted(((cbor(k), cbor(v)) for k, v in x.items()), key=lambda kv: (len(kv[0]), kv[0]))
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    raise TypeError(type(x))

def key(label):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("composition test key " + label).encode()).digest())

def statement(k, iss, sub, payload, inputs=None):
    from cryptography.hazmat.primitives import serialization as ser
    pub = k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    prot = {1: -8, 15: {1: iss, 2: sub, 8: {1: {1: 1, -1: 6, -2: pub}}}}
    if inputs is not None:
        prot["inputs"] = inputs
    p = cbor(prot)
    tbs = cbor(["Signature1", p, b"", payload])
    raw = _head(6, 18) + cbor([p, {}, payload, k.sign(tbs)])
    return raw, hashlib.sha256(tbs).digest()

def b64(b): return base64.b64encode(b).decode()

def main():
    ka, kb = key("publisher"), key("agent")
    A, dA = statement(ka, ISS_A, "figure-1", b'{"figure":"4.21%"}')
    A2, dA2 = statement(ka, ISS_A, "figure-2", b'{"figure":"7.03%"}')
    B, dB = statement(kb, ISS_B, "decision-1", b'{"decision":"ALLOW"}', [[ISS_A, "figure-1", dA]])
    C, dC = statement(kb, ISS_B, "decision-2", b'{"decision":"ALLOW"}', [[ISS_A, "figure-1", dA], [ISS_A, "figure-2", dA2]])
    D, _ = statement(kb, ISS_B, "decision-3", b'{"decision":"ALLOW"}', [[ISS_A, "figure-WRONG", dA]])
    E, _ = statement(kb, ISS_B, "decision-4", b'{"decision":"ALLOW"}', [[ISS_A, "figure-1", dA[:31]]])
    F, _ = statement(kb, ISS_B, "decision-5", b'{"decision":"ALLOW"}', [])
    G, _ = statement(kb, ISS_B, "decision-6", b'{"decision":"ALLOW"}', [[ISS_A, "figure-1", hashlib.sha256(A).digest()]])

    stmts = {"A": A, "A2": A2, "B": B, "C": C, "D": D, "E": E, "F": F, "G": G}
    steps = [
        ("B", "refuse", "Missing Reference", "B cites A, which is not registered yet. Nothing is registered (C3)."),
        ("A", "accept", None, "A cites nothing."),
        ("B", "accept", None, "A is now registered with the same iss and sub, so B's reference resolves."),
        ("C", "refuse", "Missing Reference", "C cites A and A2; A2 is not registered. One unresolved reference refuses the whole statement."),
        ("A2", "accept", None, "A2 cites nothing."),
        ("C", "accept", None, "Both references now resolve."),
        ("D", "refuse", "Missing Reference", "Right digest, wrong sub: a reference resolves only with matching iss and sub."),
        ("E", "refuse", "Rejected", "Digest of 31 bytes: the reference is not well-formed."),
        ("F", "refuse", "Rejected", "An empty inputs array is not well-formed."),
        ("G", "refuse", "Missing Reference", "Digest over A's whole bytes, not its Sig_structure: under the ToBeSigned scheme it does not resolve."),
    ]
    out = {
        "title": "Composition at registration: test vectors (C2, C3)",
        "draft": "draft-dobson-scitt-statement-references-00",
        "reference_form": "protected header text label \"inputs\": [[iss text, sub text, digest bstr(32)], ...], "
                          "digest = SHA-256 over Sig_structure ['Signature1', protected, h'', payload]",
        "rule": "Refuse a Signed Statement unless every reference resolves to a statement already registered "
                "in this service with the same iss and sub. On refusal, register nothing.",
        "test_keys": "Ed25519, seed = SHA-256('composition test key ' + label), labels 'publisher' and 'agent'. "
                     "TEST KEYS ONLY: never use for real statements.",
        "statements": {n: {"base64": b64(s), "sha256": hashlib.sha256(s).hexdigest(), "length": len(s)}
                       for n, s in stmts.items()},
        "tbs_digests": {"A": dA.hex(), "A2": dA2.hex(), "B": dB.hex(), "C": dC.hex()},
        "steps": [{"step": i + 1, "register": n, "expect": e, "problem_title": t, "why": w}
                  for i, (n, e, t, w) in enumerate(steps)],
        "start_state": "an empty log, or one holding none of these statements",
    }
    with open("composition-vectors.json", "w") as f:
        json.dump(out, f, indent=1)
    print("wrote composition-vectors.json: %d statements, %d steps" % (len(stmts), len(steps)))

if __name__ == "__main__":
    main()
