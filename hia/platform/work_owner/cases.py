"""Independent finite-field proofs, complete progress order, and physical controls."""
from __future__ import annotations
from functools import lru_cache
import hashlib
import json
import random
import signal
import struct

Q = 4294967291
N = 64
R = 8
PROTOCOL_ONLY = {
    "unsealed-input", "callback-output-alias",
    "gate-eof-before-replay", "gate-bad-ack-before-replay",
}

def need(ok, message):
    if not ok:
        raise ValueError(message)

def packed(values):
    return struct.pack("<" + "I" * len(values), *values)

def tagged(tag, *parts):
    wire = b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag
    wire += b"".join(struct.pack("<I", len(part)) + part for part in parts)
    return hashlib.sha256(wire).digest()

def multiply(a, b, rows, inner, columns):
    return [sum(a[i * inner + k] * b[k * columns + j] for k in range(inner)) % Q
            for i in range(rows) for j in range(columns)]

def progress_for(challenge):
    rows = []
    def add(kind, a=0, b=0, c=0):
        rows.append([kind, a, b, c, len(rows) + 1])
    add(64)
    for label in range(4):
        accepted = 0
        for counter in range(128):
            add(65, label, counter)
            data = tagged(b"noise", challenge, bytes([label]), struct.pack("<I", counter))
            for value in struct.unpack("<8I", data):
                if value < Q:
                    accepted += 1
                    if accepted == N * R:
                        break
            if accepted == N * R:
                break
        need(accepted == N * R, "Independent NoiseBudget exhausted")
    for _ in range(2):
        for row in range(N):
            add(66, row)
    for row in range(N // R):
        for column in range(N // R):
            for inner in range(N // R):
                add(67, row, column, inner)
    add(68)
    for size in (64, 64, 8, 64):
        for row in range(size):
            add(66, row)
    add(69)
    return rows

def noise(challenge, label):
    values = []
    for counter in range(128):
        data = tagged(b"noise", challenge, bytes([label]), struct.pack("<I", counter))
        for value in struct.unpack("<8I", data):
            if value < Q:
                values.append(value)
                if len(values) == N * R:
                    return values
    raise ValueError("Independent NoiseBudget exhausted")

def proof(challenge, a, b):
    need(len(challenge) == 32 and len(a) == len(b) == N * N
         and all(type(x) is int and 0 <= x < Q for x in a + b), "Independent proof input")
    e = multiply(noise(challenge, 0), noise(challenge, 1), N, R, N)
    f = multiply(noise(challenge, 2), noise(challenge, 3), N, R, N)
    ap = [(x + y) % Q for x, y in zip(a, e, strict=True)]
    bp = [(x + y) % Q for x, y in zip(b, f, strict=True)]
    cp = [0] * (N * N)
    trace = hashlib.sha256(b"TRNM-PON-TRACE1\0" + challenge)
    for bi in range(N // R):
        for bj in range(N // R):
            for bk in range(N // R):
                for i in range(bi * R, (bi + 1) * R):
                    for j in range(bj * R, (bj + 1) * R):
                        index = i * N + j
                        cp[index] = (cp[index] + sum(ap[i * N + k] * bp[k * N + j]
                                                    for k in range(bk * R, (bk + 1) * R))) % Q
                        trace.update(struct.pack("<I", cp[index]))
    product = packed(multiply(a, b, N, N, N))
    return b"PNW1" + packed(a) + packed(b) + product + trace.digest(), product

def framed(challenge, raw, task=None, target=b"\xff" * 32):
    if task is None:
        task = tagged(b"task", raw[4:16388], raw[16388:32772])
    return challenge + task + target + raw

@lru_cache(maxsize=1)
def corpus_bytes():
    rng = random.Random(0x574F524B)
    challenge = bytes(range(32))
    raw, product = proof(challenge, [rng.randrange(Q) for _ in range(4096)],
                         [rng.randrange(Q) for _ in range(4096)])
    request = framed(challenge, raw)
    expected = progress_for(challenge)
    need(len(expected) == 1099 and len(request) == 49284, "Pinned dense corpus dimensions")
    cases = []
    def add(name, request=request, domain=0, code=0, n=1099, product=product,
            progress=expected, **options):
        opts = dict(options)
        if "gate_ack" in opts:
            value = opts.pop("gate_ack")
            opts["gate_ack_hex"] = None if value is None else value.hex()
        if "signal_number" in opts:
            opts["signal_number"] = int(opts["signal_number"])
        cases.append({"name": name, "request_hex": request.hex(), "domain": domain,
                      "code": code, "progress": progress[:n],
                      "product_hex": product.hex() if domain == 0 else None, "options": opts})
    add("dense-positive")
    bad = bytearray(request); bad[-1] ^= 1
    add("transcript-mismatch", request=bytes(bad), domain=1, code=5, n=897)
    bad = bytearray(request); bad[32868 + 4095 * 4] ^= 1
    add("last-product-mismatch", request=bytes(bad), domain=1, code=6, n=1098)
    bad = bytearray(request); bad[64:96] = bytes(32)
    add("zero-target", request=bytes(bad), domain=1, code=7, n=0)
    for label, value in (("empty", request[:96]), ("short", request[:-1]),
                         ("long", request + b"x"), ("large", request + b"x" * 131072)):
        add("proof-length-" + label, request=value, domain=1, code=1, n=0)
    for name, offset, code in (("magic", 96, 2), ("task", 32, 4), ("noncanonical-C", 32868, 3),
                               ("noncanonical-A", 100, 3), ("noncanonical-B", 16484, 3)):
        bad = bytearray(request)
        if name.startswith("noncanonical"):
            bad[offset:offset + 4] = Q.to_bytes(4, "little")
        else:
            bad[offset] ^= 1
        add("cheap-" + name, request=bytes(bad), domain=1, code=code, n=0)
    add("unsealed-input", sealed=False, domain=5, code=1, n=0)
    add("callback-output-alias", gate_alias=True, domain=5, code=1, n=0)
    for seq in (1, 2, 258, 386, 897, 898, 1098, 1099):
        for stage in (3, 4, 5):
            add(f"cancel-at-{seq}-stage-{stage}", gate_sequence=seq, gate_stage=stage,
                signal_number=signal.SIGUSR1, domain=2, code=1, n=seq)
    add("stop-before-replay", gate_sequence=1, gate_stage=3,
        signal_number=signal.SIGUSR2, domain=2, code=2, n=1)
    add("gate-eof-before-replay", gate_sequence=1, gate_stage=3,
        gate_ack=None, domain=5, code=12, n=1)
    add("gate-bad-ack-before-replay", gate_sequence=1, gate_stage=3,
        gate_ack=b"\0", domain=5, code=12, n=1)
    for stage in (1, 2):
        add(f"acquisition-parent-replaced-{stage}", gate_sequence=0, gate_stage=stage,
            actions=[{"kind": "replace_parent"}], domain=3, code=4, n=0)
    add("worker-membership-not-acquirer", gate_stage=2,
        actions=[{"kind": "write", "target": "membership", "hex": b"0::/different.slice\n".hex()}],
        domain=3, code=3, n=0)
    for name, action, code in (
        ("boot", {"kind": "write", "target": "boot", "hex": b"different-boot\n".hex()}, 4),
        ("limits", {"kind": "write", "target": "pids.max", "hex": b"128\n".hex()}, 7),
        ("parent-inode", {"kind": "replace_parent"}, 4),
    ):
        add("progress-fresh-" + name, gate_sequence=386, gate_stage=4,
            actions=[action], domain=3, code=code, n=386)
    add("final-Host-overrides-cancel", gate_sequence=386, gate_stage=3,
        signal_number=signal.SIGUSR1, actions=[{"kind": "replace_parent"}],
        domain=3, code=4, n=386)
    bad = bytearray(request); bad[-1] ^= 1
    add("final-Host-overrides-transcript", request=bytes(bad), gate_sequence=897, gate_stage=6,
        actions=[{"kind": "replace_parent"}], domain=3, code=4, n=897)
    add("final-success-time-fence", gate_sequence=1099, gate_stage=7,
        gate_delay=4.05, domain=2, code=2, n=1099)
    add("post-join-counter-error", gate_sequence=1099, gate_stage=8,
        actions=[{"kind": "write", "target": "cpu.stat", "hex": b"invalid".hex()}],
        domain=3, code=13, n=1099)
    need(len(cases) == 52, "Retained physical corpus prefix changed")
    other_rng = random.Random(0x504E57316408)
    fixtures = [
        ("zero-times-max", bytes(32), [0] * 4096, [Q - 1] * 4096),
        ("identity-times-pattern", challenge, [int(i // N == i % N) for i in range(4096)],
         [other_rng.randrange(Q) for _ in range(4096)]),
        ("max-pattern", b"\xff" * 32, [Q - 1 - i % 257 for i in range(4096)],
         [(i * 65537 + 258) % Q for i in range(4096)]),
    ]
    for name, ch, a, b in fixtures:
        p, prod = proof(ch, a, b)
        add(name, request=framed(ch, p), product=prod, progress=progress_for(ch))
    ticket = tagged(b"ticket", challenge, raw[-32:])
    add("exact-ticket-equality", request=framed(challenge, raw, target=ticket))
    add("ticket-minus-one", request=framed(challenge, raw,
        target=(int.from_bytes(ticket, "big") - 1).to_bytes(32, "big")), domain=1, code=7, n=0)
    ch = bytes([challenge[0] ^ 1]) + challenge[1:]
    add("changed-challenge", request=framed(ch, raw), domain=1, code=5, n=897, progress=progress_for(ch))
    bad = bytearray(raw); bad[32772] ^= 1; bad[-1] ^= 1
    add("transcript-before-product-error", request=framed(challenge, bytes(bad)), domain=1, code=5, n=897)
    bad = bytearray(raw); bad[4:8] = Q.to_bytes(4, "little")
    add("target-before-field-error", request=framed(challenge, bytes(bad), target=bytes(32)),
        domain=1, code=7, n=0)
    bad[0] ^= 1
    add("version-before-target-error", request=framed(challenge, bytes(bad), target=bytes(32)),
        domain=1, code=2, n=0)
    need(len(cases) == 61 and len({row["name"] for row in cases}) == 61, "Complete finite corpus roster")
    return (json.dumps(cases, sort_keys=True, indent=2) + "\n").encode()

def corpus():
    return json.loads(corpus_bytes())

def native_options(case):
    options = dict(case["options"])
    if "gate_ack_hex" in options:
        value = options.pop("gate_ack_hex")
        options["gate_ack"] = None if value is None else bytes.fromhex(value)
    return options

def original_cases():
    rows = []
    for case in corpus():
        if case["name"] in PROTOCOL_ONLY:
            continue
        options = case["options"]
        rows.append({"name": case["name"], "request_hex": case["request_hex"],
                     "gate_stage": options.get("gate_stage", 0),
                     "gate_sequence": options.get("gate_sequence", 0),
                     "actions": options.get("actions", []),
                     "signal": {None: 0, int(signal.SIGUSR1): 1, int(signal.SIGUSR2): 2}[options.get("signal_number")],
                     "delay_ms": round(options.get("gate_delay", 0) * 1000)})
    need(len(rows) == 57, "Original-method corpus roster differs")
    return rows

def require_semantics(case, physical):
    need(physical.get("status") == "PHYSICAL_FRAME_PASS_SEMANTIC_EXPECTATIONS_PENDING",
         case["name"] + ": real native frame failed")
    actual = physical["decoded"]
    header = actual["header"]
    need((header["domain"], header["code"], header["progress_count"]) ==
         (case["domain"], case["code"], len(case["progress"])), case["name"] + ": terminal result differs")
    need(actual["progress"] == case["progress"], case["name"] + ": complete ordered original progress differs")
    want = hashlib.sha256(bytes.fromhex(case["product_hex"])).hexdigest() if case["product_hex"] is not None else None
    need(actual["product_sha256"] == want, case["name"] + ": independent direct A*B product differs")
    if case["domain"] == 0:
        need(header["worker_host_calls"] == len(case["progress"]) + 2
             and header["aggregate_samples"] == 2 and header["joins"] == 1
             and header["alive_clocks"] == 2 * len(case["progress"]) + 2,
             case["name"] + ": missing fresh authority, clock, sample or join boundary")
    return actual
