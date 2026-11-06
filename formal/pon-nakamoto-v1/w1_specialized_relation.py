"""Full W1 witness/constraint reference, NOT a succinct proof or admission API.

The integer constraints preserve q=2**32-5. Every dot-product reduction is
expanded into nine base-256 carry equations whose bounded residuals cannot wrap
in BabyBear. Every SHA message has an explicit complete compression chain.
No PCS, Fiat-Shamir transcript, zero knowledge, or security claim is implemented.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import time

from contract_wire import header_decode, header_encode

N, R, Q = 64, 8, 4_294_967_291
CELLS, HEADER_BYTES, PROOF_BYTES = 4096, 318, 49188
VERSION = "trnm-w1-exact-constraint-reference-v1"
TRACE_DOMAIN = b"TRNM-PON-TRACE1\0"
TRACE_WORDS = 32768
TRACE_MESSAGE_BYTES = 131120
TRACE_BLOCKS = 2049
BABY_BEAR = 2_013_265_921
CARRY_BOUND = 1 << 17
# At most 64 products, four 8-bit convolution terms per product per column,
# six signed scalar limbs, four quotient*q terms, and two bounded carries.
COLUMN_RESIDUAL_BOUND = 64 * 4 * 255**2 + 6 * 255 + 4 * 255**2 + 257 * CARRY_BOUND
MAX_WITNESS_BYTES = 16 * 1024 * 1024
GROUP_COUNTS = {
    "noise_e": 4096, "noise_f": 4096, "a_prime": 4096, "b_prime": 4096,
    "prefix": 32768, "a_fl": 512, "c1": 4096, "er_b_prime": 512,
    "c2": 4096, "recover": 4096,
}
MASK = (1 << 32) - 1
IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def integer(x, low, high):
    return type(x) is int and low <= x <= high


def canonical_words(values, count):
    require(isinstance(values, list) and len(values) == count, "FIELD_LENGTH")
    require(all(integer(x, 0, Q - 1) for x in values), "FIELD")


def words_bytes(values):
    return struct.pack("<" + "I" * len(values), *values)


def framed(tag, *parts):
    tag = tag.encode("ascii")
    return b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag + b"".join(
        struct.pack("<I", len(part)) + part for part in parts
    )


def rotate(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def compress(state, block):
    """Independent integer SHA-256 compression with all 64 schedule/round steps."""
    require(len(block) == 64 and len(state) == 8, "SHA_SHAPE")
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        x, y = w[i - 15], w[i - 2]
        s0 = rotate(x, 7) ^ rotate(x, 18) ^ (x >> 3)
        s1 = rotate(y, 17) ^ rotate(y, 19) ^ (y >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        s1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)
        t1 = (h + s1 + ((e & f) ^ ((~e & MASK) & g)) + K[i] + w[i]) & MASK
        s0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)
        t2 = (s0 + ((a & b) ^ (a & c) ^ (b & c))) & MASK
        a, b, c, d, e, f, g, h = (t1 + t2) & MASK, a, b, c, (d + t1) & MASK, e, f, g
    return [(x + y) & MASK for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def padded(message):
    require(len(message) < (1 << 61), "SHA_LENGTH")
    return message + b"\x80" + bytes((55 - len(message)) % 64) + struct.pack(">Q", 8 * len(message))


def sha_record(name, message):
    blocks = padded(message)
    state, states = list(IV), []
    for i in range(0, len(blocks), 64):
        state = compress(state, blocks[i:i + 64])
        states.append(state)
    digest = struct.pack(">8I", *state)
    # An independent standard implementation checks this reference, including
    # padding/endianness. This does not make it a cryptographic proof backend.
    require(digest == hashlib.sha256(message).digest(), "SHA_REFERENCE_MISMATCH")
    return {"name": name, "digest": digest.hex(), "states": states}


def check_sha(record, name, message):
    require(type(record) is dict and set(record) == {"name", "digest", "states"}, "SHA_RECORD")
    require(record["name"] == name, "SHA_ORDER")
    blocks, states = padded(message), record["states"]
    require(type(states) is list and len(states) == len(blocks) // 64, "SHA_BLOCK_COUNT")
    state = list(IV)
    for i, supplied in enumerate(states):
        require(type(supplied) is list and len(supplied) == 8, "SHA_STATE_SHAPE")
        require(all(integer(x, 0, MASK) for x in supplied), "SHA_WORD")
        expected = compress(state, blocks[i * 64:(i + 1) * 64])
        require(supplied == expected, "SHA_COMPRESSION")
        state = supplied
    digest = struct.pack(">8I", *state)
    require(record["digest"] == digest.hex(), "SHA_DIGEST")
    return digest


def limb_columns(products, positive, negative, quotient):
    """Columns of sum(x*y)+sum(positive)-sum(negative)-quotient*q."""
    require(len(products) <= 64 and len(positive) + len(negative) <= 6, "COLUMN_SHAPE")
    require(all(integer(x, 0, Q - 1) and integer(y, 0, Q - 1) for x, y in products), "COLUMN_FIELD")
    require(all(integer(x, 0, (1 << 34) - 1) for x in positive + negative), "COLUMN_SCALAR")
    require(integer(quotient, 0, (1 << 39) - 1), "QUOTIENT_RANGE")
    columns = [0] * 9
    for x, y in products:
        xl, yl = x.to_bytes(4, "little"), y.to_bytes(4, "little")
        for i in range(4):
            for j in range(4):
                columns[i + j] += xl[i] * yl[j]
    for sign, values in ((1, positive), (-1, negative)):
        for x in values:
            for i, limb in enumerate(x.to_bytes(9, "little")):
                columns[i] += sign * limb
    ql, kl = Q.to_bytes(4, "little"), quotient.to_bytes(5, "little")
    for i in range(4):
        for j in range(5):
            columns[i + j] -= ql[i] * kl[j]
    return columns


def reduction_row(products, positive=(), negative=()):
    positive, negative = list(positive), list(negative)
    total = sum(x * y for x, y in products) + sum(positive) - sum(negative)
    require(total >= 0, "NEGATIVE_REDUCTION")
    quotient, result = divmod(total, Q)
    carry, carries = 0, []
    for column in limb_columns(products, positive, negative + [result], quotient):
        value = carry + column
        require(value % 256 == 0, "CARRY_DIVISIBILITY")
        carry = value // 256
        require(-CARRY_BOUND <= carry <= CARRY_BOUND, "CARRY_RANGE")
        carries.append(carry)
    require(carry == 0, "CARRY_FINAL")
    return [result, quotient, *carries]


def check_reduction(row, products, positive=(), negative=()):
    require(type(row) is list and len(row) == 11, "REDUCTION_SHAPE")
    result, quotient, *carries = row
    require(integer(result, 0, Q - 1), "REDUCTION_RESULT")
    require(all(integer(c, -CARRY_BOUND, CARRY_BOUND) for c in carries), "CARRY_RANGE")
    columns = limb_columns(products, list(positive), list(negative) + [result], quotient)
    carry = 0
    for column, next_carry in zip(columns, carries):
        residual = carry + column - 256 * next_carry
        require(abs(residual) <= COLUMN_RESIDUAL_BOUND < BABY_BEAR, "COLUMN_BOUND")
        require(residual == 0, "CARRY_EQUATION")
        carry = next_carry
    require(carry == 0, "CARRY_FINAL")
    return result


def accepted_words(chunk, remaining):
    require(type(chunk) is bytes and len(chunk) == 32, "NOISE_DIGEST")
    require(integer(remaining, 1, 512), "NOISE_REMAINING")
    return [x for (x,) in struct.iter_unpack("<I", chunk) if x < Q][:remaining]


class Execution:
    def __init__(self, witness=None):
        self.build = witness is None
        self.witness = witness if witness is not None else {
            "version": VERSION, "arithmetic": {}, "hashes": [], "statement": {},
        }
        require(type(self.witness) is dict and set(self.witness) == {
            "version", "arithmetic", "hashes", "statement"
        }, "WITNESS_SCHEMA")
        require(self.witness["version"] == VERSION, "WITNESS_VERSION")
        require(type(self.witness["arithmetic"]) is dict, "ARITHMETIC_SCHEMA")
        require(type(self.witness["hashes"]) is list and len(self.witness["hashes"]) <= 520, "HASH_COUNT")
        if not self.build:
            require(set(self.witness["arithmetic"]) == set(GROUP_COUNTS), "GROUP_SET")
            for name, count in GROUP_COUNTS.items():
                group = self.witness["arithmetic"][name]
                require(type(group) is list and len(group) == count, "GROUP_LENGTH:" + name)
        self.hash_cursor = 0
        self.group_cursor = {name: 0 for name in GROUP_COUNTS}
        self.multiplications = 0

    def hash(self, name, message):
        if self.build:
            record = sha_record(name, message)
            self.witness["hashes"].append(record)
            result = bytes.fromhex(record["digest"])
        else:
            require(self.hash_cursor < len(self.witness["hashes"]), "MISSING_HASH")
            result = check_sha(self.witness["hashes"][self.hash_cursor], name, message)
        self.hash_cursor += 1
        return result

    def h(self, name, tag, *parts):
        return self.hash(name, framed(tag, *parts))

    def row(self, name, products, positive=(), negative=()):
        require(name in GROUP_COUNTS and self.group_cursor[name] < GROUP_COUNTS[name], "ROW_COUNT")
        if self.build:
            row = reduction_row(products, positive, negative)
            self.witness["arithmetic"].setdefault(name, []).append(row)
            result = row[0]
        else:
            row = self.witness["arithmetic"][name][self.group_cursor[name]]
            result = check_reduction(row, products, positive, negative)
        self.group_cursor[name] += 1
        self.multiplications += len(products)
        return result

    def matrix(self, name, a, b, n, k, m):
        return [self.row(name, [(a[i * k + t], b[t * m + j]) for t in range(k)])
                for i in range(n) for j in range(m)]

    def noise(self, challenge, label):
        result = []
        for counter in range(128):
            digest = self.h(f"noise/{label}/{counter}", "noise", challenge,
                            bytes([label]), struct.pack("<I", counter))
            result.extend(accepted_words(digest, 512 - len(result)))
            if len(result) == 512:
                return result
        raise ValueError("NOISE_BUDGET")

    def finish(self, statement):
        require(self.group_cursor == GROUP_COUNTS, "INCOMPLETE_ARITHMETIC")
        require(self.hash_cursor == len(self.witness["hashes"]), "UNUSED_HASH")
        if self.build:
            self.witness["statement"] = statement
        else:
            require(self.witness["statement"] == statement, "STATEMENT")
        return self.witness


def execute(header, proof, expected_artifacts, witness=None):
    """Check the complete mathematical relation against EXTERNAL expected bytes.

    Caller must independently obtain header and A/B commitments. Parent-state,
    target derivation, task authority and state transition remain Node duties.
    """
    require(type(header) is bytes and len(header) == HEADER_BYTES, "HEADER_LENGTH")
    h = header_decode(header)
    require(header_encode(h) == header, "HEADER_CANONICAL")
    require(type(proof) is bytes and len(proof) == PROOF_BYTES and proof[:4] == b"PNW1", "PROOF_ENCODING")
    require(type(expected_artifacts) is bytes and len(expected_artifacts) == 64, "ARTIFACT_LENGTH")
    values = list(struct.unpack("<12288I", proof[4:-32]))
    a, b, product = values[:CELLS], values[CELLS:2 * CELLS], values[2 * CELLS:]
    for matrix in (a, b, product):
        canonical_words(matrix, CELLS)
    ex = Execution(witness)
    ab, bb = proof[4:4 + CELLS * 4], proof[4 + CELLS * 4:4 + 2 * CELLS * 4]
    require(ex.h("task", "task", ab, bb) == h["work_task"], "TASK")
    model = ex.h("artifact/model", "artifact", ab)
    source_input = ex.h("artifact/input", "qualified-task-input-v1", bb)
    require(model + source_input == expected_artifacts, "ARTIFACT_BINDING")
    challenge = ex.h("challenge", "challenge", header)
    ticket = ex.h("ticket", "ticket", challenge, proof[-32:])
    require(h["target"] != bytes(32) and ticket <= h["target"], "TARGET")
    el, er, fl, fr = [ex.noise(challenge, label) for label in range(4)]
    e, f = ex.matrix("noise_e", el, er, N, R, N), ex.matrix("noise_f", fl, fr, N, R, N)
    aa = [ex.row("a_prime", [], [x, y]) for x, y in zip(a, e)]
    bp = [ex.row("b_prime", [], [x, y]) for x, y in zip(b, f)]
    cp, prefixes = [0] * CELLS, []
    for i0 in range(0, N, R):
        for j0 in range(0, N, R):
            for k0 in range(0, N, R):
                for i in range(i0, i0 + R):
                    for j in range(j0, j0 + R):
                        pos = i * N + j
                        terms = [(aa[i * N + k], bp[k * N + j]) for k in range(k0, k0 + R)]
                        cp[pos] = ex.row("prefix", terms, [cp[pos]])
                        prefixes.append(cp[pos])
    message = TRACE_DOMAIN + challenge + words_bytes(prefixes)
    require(len(prefixes) == TRACE_WORDS and len(message) == TRACE_MESSAGE_BYTES, "TRACE_COUNT")
    trace = ex.hash("trace", message)
    require(trace == proof[-32:], "TRANSCRIPT")
    a_fl = ex.matrix("a_fl", a, fl, N, N, R)
    c1 = ex.matrix("c1", a_fl, fr, N, R, N)
    er_bp = ex.matrix("er_b_prime", er, bp, R, N, N)
    c2 = ex.matrix("c2", el, er_bp, N, R, N)
    recovered = [ex.row("recover", [], [x, 2 * Q], [y, z]) for x, y, z in zip(cp, c1, c2)]
    require(recovered == product, "PRODUCT")
    work_id = ex.h("work_id", "block", header, trace)
    statement = {
        "header_sha256": hashlib.sha256(header).hexdigest(),
        "proof_sha256": hashlib.sha256(proof).hexdigest(),
        "model": model.hex(), "input": source_input.hex(),
        "challenge": challenge.hex(), "trace": trace.hex(),
        "ticket": ticket.hex(), "work_id": work_id.hex(),
        "product_sha256": hashlib.sha256(words_bytes(recovered)).hexdigest(),
    }
    result = ex.finish(statement)
    return result, {
        "schema": VERSION, "full_relation_evaluated": True,
        "complete_mathematical_witness_checked": not ex.build,
        "succinct_proof": False, "polynomial_sha_constraints_implemented": False,
        "cryptographic_backend_implemented": False, "node_admission_authorized": False,
        "production_activation": False, "quantum_security_bits": None,
        "native_field": Q, "candidate_constraint_field": BABY_BEAR,
        "carry_bound": CARRY_BOUND, "column_residual_bound": COLUMN_RESIDUAL_BOUND,
        "reduction_rows": sum(GROUP_COUNTS.values()),
        "carry_equations": 9 * sum(GROUP_COUNTS.values()),
        "field_multiplications": ex.multiplications,
        "trace_words": len(prefixes), "trace_bytes": len(message),
        "trace_sha256_blocks": len(padded(message)) // 64,
        "all_sha256_messages": ex.hash_cursor,
        "all_sha256_blocks": sum(len(row["states"]) for row in result["hashes"]),
        "work_id": work_id.hex(),
    }


def bounded_regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "INPUT_FILE")
        data = stream.read(limit + 1)
        require(len(data) <= limit, "INPUT_SIZE")
        return data


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_KEY")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("build", "check"))
    parser.add_argument("--header", required=True)
    parser.add_argument("--proof", required=True, help="Original 49,188-byte PNW1 witness")
    parser.add_argument("--expected-artifacts", required=True)
    parser.add_argument("--witness", required=True)
    args = parser.parse_args()
    header = bounded_regular(args.header, HEADER_BYTES)
    proof = bounded_regular(args.proof, PROOF_BYTES)
    artifacts = bounded_regular(args.expected_artifacts, 64)
    witness = None
    if args.mode == "check":
        witness = json.loads(bounded_regular(args.witness, MAX_WITNESS_BYTES), object_pairs_hook=unique)
    wall, cpu = time.monotonic_ns(), time.process_time_ns()
    result, report = execute(header, proof, artifacts, witness)
    report.update(wall_ns=time.monotonic_ns() - wall, process_cpu_ns=time.process_time_ns() - cpu)
    if args.mode == "build":
        data = json.dumps(result, separators=(",", ":"), sort_keys=True).encode() + b"\n"
        require(len(data) <= MAX_WITNESS_BYTES, "WITNESS_SIZE")
        with open(args.witness, "xb") as stream:
            stream.write(data)
        report["witness_bytes"] = len(data)
        report["witness_sha256"] = hashlib.sha256(data).hexdigest()
    report["mode"] = args.mode
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
