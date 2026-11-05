"""Stand-alone certificate reader. Intentionally does not import protocol.py.

The caller supplies trusted context/committee pins. This checks signed finality
statements, not model quality, storage retention, operator independence or permission.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"pon-nakamoto-v1"))
from strict_signature import strict_point, verify as verify_ed25519

PREFIX = b"TRNM-RELEASE-FINALITY-V2\0"
LIMIT = 2097152

def fail(condition, message):
    if not condition:
        raise ValueError(message)

def encode(obj):
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    fail(len(data) <= LIMIT, "size")
    return data

def load(data):
    fail(type(data) is bytes and len(data) <= LIMIT, "size")
    def pairs(rows):
        d = {}
        for k, v in rows:
            fail(k not in d, "duplicate-key")
            d[k] = v
        return d
    obj = json.loads(data, object_pairs_hook=pairs,
                     parse_constant=lambda _: (_ for _ in ()).throw(ValueError("number")))
    fail(encode(obj) == data, "noncanonical")
    return obj

def shape(obj, expected):
    fail(type(obj) is dict and set(obj) == set(expected.split()), "shape")

def number(v, lo=0):
    fail(type(v) is int and lo <= v < 2**63, "integer")

def hex32(v):
    fail(type(v) is str and len(v) == 64 and all(x in "0123456789abcdef" for x in v), "hex")

def sha(obj):
    return hashlib.sha256(PREFIX + encode(obj)).hexdigest()

def verify(bundle_bytes, committee_bytes, context_bytes):
    b, m, c = map(load, (bundle_bytes, committee_bytes, context_bytes))
    shape(m, "schema genesis epoch members fault_bound quorum")
    fail(m["schema"] == "trnm-release-committee-v2", "manifest-version")
    hex32(m["genesis"]); number(m["epoch"]); number(m["fault_bound"]); number(m["quorum"], 1)
    ids = m["members"]
    fail(type(ids) is list and 1 <= len(ids) <= 32, "members")
    for key in ids:
        hex32(key)
        strict_point(bytes.fromhex(key))
    fail(ids == sorted(set(ids)), "duplicate-members")
    n, f, q = len(ids), m["fault_bound"], m["quorum"]
    fail(n >= 3*f+1 and 2*q-n > f and q <= n-f, "unsafe-quorum")
    shape(c, "profile genesis epoch committee height parent parent_model")
    fail(c["profile"] == "trnm-release-finality-v2" and c["genesis"] == m["genesis"] and
         c["epoch"] == m["epoch"] and c["committee"] == sha(m), "context")
    number(c["height"], 1); hex32(c["parent"]); hex32(c["parent_model"])
    shape(b, "context statement availability commit")
    fail(b["context"] == c, "trusted-context")
    s = b["statement"]
    shape(s, "context model evaluation availability retention_height state_root next_committee")
    fail(s["context"] == sha(c), "statement-context")
    for k in ("model", "evaluation", "availability", "state_root"):
        hex32(s[k])
    number(s["retention_height"], c["height"])
    if s["next_committee"] is not None:
        hex32(s["next_committee"])
    value = sha(s)
    for field, phase in (("availability", "availability"), ("commit", "commit")):
        cert = b[field]
        shape(cert, "body votes")
        body = cert["body"]
        shape(body, "context view phase value")
        number(body["view"], 0 if phase == "availability" else 1)
        fail(body["phase"] == phase and body["context"] == sha(c) and body["value"] == value, "certificate-binding")
        fail(phase != "availability" or body["view"] == 0, "availability-view")
        votes = cert["votes"]
        fail(type(votes) is list and q <= len(votes) <= n, "quorum")
        seen = []
        for vote in votes:
            shape(vote, "body signer signature")
            fail(vote["body"] == body and vote["signer"] in ids, "vote-binding")
            sig = vote["signature"]
            fail(type(sig) is str and len(sig) == 128 and all(x in "0123456789abcdef" for x in sig), "signature-format")
            verify_ed25519(bytes.fromhex(vote["signer"]), bytes.fromhex(sig), PREFIX + encode(body))
            seen.append(vote["signer"])
        fail(seen == sorted(set(seen)), "duplicate-or-unsorted-votes")
    return dict(value=value, finality_certificate_valid=True, model_quality_accepted=False,
                long_term_availability_accepted=False, hepta_final_use=False, production_activation=False)

def read_bounded(path):
    with Path(path).open("rb") as handle:
        data = handle.read(LIMIT+1)
    fail(len(data) <= LIMIT, "size")
    return data

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("bundle", "committee", "context"):
        parser.add_argument("--"+name, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(read_bounded(args.bundle), read_bounded(args.committee), read_bounded(args.context)), sort_keys=True))
