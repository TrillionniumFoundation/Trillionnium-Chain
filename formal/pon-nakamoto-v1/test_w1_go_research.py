"""Independent Python scalar W1 transcript versus research-only Go executable.

Both implementations are developed in this workstream, NOT independently
administered, and neither establishes lowest legitimate prover costs.
"""
import hashlib
import json
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
Q, N, R = 4_294_967_291, 64, 8


def H(tag, *parts):
    tag = tag.encode()
    m = hashlib.sha256(b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag)
    for part in parts:
        m.update(struct.pack("<I", len(part)))
        m.update(part)
    return m.digest()


def words(data):
    return struct.pack("<" + "I" * len(data), *data)


def matrix(shape, seed):
    a, b = [], []
    for idx in range(4096):
        b.append((29 * idx + 11 * seed + 31) % 1231)
        if shape == "dense":
            a.append((13 * idx + 3 * seed + 7) % 1009)
        elif shape == "zero":
            a.append(0)
        elif shape == "rank1":
            a.append(((1 + ((idx // 64) * 7 + seed) % 251) *
                      (1 + ((idx % 64) * 13) % 257)) % Q)
        elif shape == "sparse":
            a.append((idx + seed) % 101 if idx % 129 == 0 else 0)
        else:
            raise ValueError(shape)
    return a, b


def mul(left, right, m, inner, n):
    return [sum(left[i * inner + k] * right[k * n + j]
                for k in range(inner)) % Q for i in range(m) for j in range(n)]


def noise(challenge, label):
    result = []
    for counter in range(128):
        if len(result) >= N * R:
            break
        x = H("noise", challenge, bytes([label]), struct.pack("<I", counter))
        for (v,) in struct.iter_unpack("<I", x):
            if v < Q:
                result.append(v)
                if len(result) == N * R:
                    return result
    raise AssertionError("noise budget exhausted")


def scalar_proof(shape, seed, challenge=None):
    if challenge is None:
        challenge = hashlib.sha256(f"trnm-w1-go-research-v1/{seed}".encode()).digest()
    a, b = matrix(shape, seed)
    el, er, fl, fr = [noise(challenge, i) for i in range(4)]
    aa = [(v + w) % Q for v, w in zip(a, mul(el, er, N, R, N))]
    bb = [(v + w) % Q for v, w in zip(b, mul(fl, fr, N, R, N))]
    cells = [0] * (N * N)
    trace = hashlib.sha256(b"TRNM-PON-TRACE1\0" + challenge)
    for bi in range(0, N, R):
        for bj in range(0, N, R):
            for bk in range(0, N, R):
                for i in range(bi, bi + R):
                    for j in range(bj, bj + R):
                        ksum = sum(aa[i * N + k] * bb[k * N + j]
                                   for k in range(bk, bk + R))
                        cells[i * N + j] = (cells[i * N + j] + ksum) % Q
                        trace.update(struct.pack("<I", cells[i * N + j]))
    product = mul(a, b, N, N, N)
    proof = b"PNW1" + words(a) + words(b) + words(product) + trace.digest()
    return {
        "challenge": challenge.hex(),
        "task": H("task", words(a), words(b)).hex(),
        "decoded_product_sha256": hashlib.sha256(words(product)).hexdigest(),
        "transcript_sha256": trace.hexdigest(),
        "proof_sha256": hashlib.sha256(proof).hexdigest(),
    }


class GoW1Research(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="trnm-w1-go-")
        cls.binary = Path(cls.tmp.name) / "workprobe"
        subprocess.run(["go", "build", "-o", str(cls.binary),
                        str(HERE / "work_go_probe.go")],
                       check=True, capture_output=True, timeout=90)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_go(self, shape, seed, *args):
        proc = subprocess.run([str(self.binary), "--shape", shape,
                               "--seed", str(seed), *args],
                              capture_output=True, text=True, timeout=25)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_byte_identity_with_independent_scalar_reference(self):
        for shape in ("dense", "zero", "rank1", "sparse"):
            for seed in (0, 1, 9):
                with self.subTest(shape=shape, seed=seed):
                    go = self.run_go(shape, seed)
                    py = scalar_proof(shape, seed)
                    for field, val in py.items():
                        self.assertEqual(go[field], val, field)
                    # Winning and forged candidates have the SAME threshold,
                    # although their challenge selection strategies differ.
                    win = scalar_proof(shape, seed,
                        bytes.fromhex(go["honest_winning_challenge"]))
                    self.assertEqual(go["honest_winning_proof_sha256"], win["proof_sha256"])
                    ticket = H("ticket", bytes.fromhex(win["challenge"]),
                               bytes.fromhex(win["transcript_sha256"]))
                    self.assertLessEqual(ticket.hex(), go["same_target_hex"])
                    self.assertGreater(go["honest_winner_attempts"], 0)
                    self.assertGreater(go["honest_winner_full_search_wall_ns"], 0)
                    self.assertEqual(go["proof_bytes"], 49188)
                    self.assertEqual(go["negative_controls"], 4)
                    self.assertTrue(go["false_ticket_passed"])
                    self.assertEqual(go["false_proof_full_rejection"], "Transcript")
                    self.assertFalse(go["production_eligible"])

    def test_ticket_precheck_is_not_valid_work(self):
        for shape in ("dense", "zero", "rank1", "sparse"):
            go = self.run_go(shape, 1)
            nonce = go["false_ticket_hash_attempts"] - 1
            t = H("research-forged-trace",
                  bytes.fromhex(go["challenge"]), struct.pack("<Q", nonce))
            ticket = H("ticket", bytes.fromhex(go["challenge"]), t)
            self.assertLessEqual(int.from_bytes(ticket, "big"), (1 << 255) - 1)
            self.assertNotEqual(t.hex(), go["transcript_sha256"])

    def test_forged_ticket_exhaustion_is_not_success(self):
        proc = subprocess.run([str(self.binary), "--shape", "dense", "--seed", "1",
                               "--false-attempts", "1"],
                              text=True, capture_output=True, timeout=25)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("SearchExhausted", proc.stderr)

    def test_invalid_shape_or_bounds_are_rejected(self):
        for arguments in (("--shape", "nonexistent"),
                          ("--seed", "999999"),
                          ("--false-attempts", "0")):
            proc = subprocess.run([str(self.binary), *arguments],
                                  text=True, capture_output=True, timeout=25)
            self.assertNotEqual(proc.returncode, 0)

if __name__ == "__main__":
    unittest.main()
