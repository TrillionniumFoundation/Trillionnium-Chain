"""Native PQL5N vs real ML-DSA-65 signed public fixtures, adversarial boundaries.

These tests prove only a bounded read-only verifier can parse/signature-check PQL5.
They do not establish source authority, independent witnesses or rollback resistance.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

KEY_DOMAIN = b"TRNM/PoN/PQKey/v1\0"
SIGN_DOMAIN = b"TRNM/PQ/PQL5Witness/v1\0"
SIZE = 269 + 2 + 3309
SOURCE = Path(__file__).with_name("pq_pql5_native_verify.c")


def run(argv: list[str | Path], *, timeout: int = 15):
    return subprocess.run([str(a) for a in argv], capture_output=True, timeout=timeout, check=False)


def keypair(path: Path, name: str, algorithm="ML-DSA-65"):
    private, public = path / (name + ".private.pem"), path / (name + ".public.pem")
    assert run(["openssl", "genpkey", "-algorithm", algorithm, "-out", private]).returncode == 0
    assert run(["openssl", "pkey", "-in", private, "-pubout", "-out", public]).returncode == 0
    return private, public


def key_id(public: Path) -> bytes:
    d = run(["openssl", "pkey", "-pubin", "-in", public, "-outform", "DER"])
    if d.returncode:
        raise AssertionError(d.stderr.decode(errors="replace"))
    return hashlib.sha256(KEY_DOMAIN + d.stdout).digest()


def sign(private: Path, data: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="pql5n-sign-") as d:
        msg, sig = Path(d) / "msg", Path(d) / "sig"
        msg.write_bytes(data)
        result = run(["openssl", "pkeyutl", "-sign", "-inkey", private,
                      "-rawin", "-in", msg, "-out", sig])
        if result.returncode:
            raise AssertionError(result.stderr.decode(errors="replace"))
        signed = sig.read_bytes()
        assert len(signed) == 3309
        return signed


class NativePQL5NTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.global_tmp = tempfile.TemporaryDirectory(prefix="pql5n-global-")
        cls.addClassCleanup(cls.global_tmp.cleanup)
        cls.root = Path(cls.global_tmp.name)
        cls.binary = cls.root / "pql5n"
        compile = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                   "-O1" if os.getenv("PQL5N_SANITIZE") else "-O2"]
        if os.getenv("PQL5N_SANITIZE"):
            compile += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g"]
        compile += [SOURCE, "-lcrypto", "-o", cls.binary]
        result = run(compile, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr.decode(errors="replace"))
        cls.keys = [keypair(cls.root, "w" + str(i)) for i in range(3)]
        cls.outsider = keypair(cls.root, "outsider")
        cls.classical = keypair(cls.root, "classical", "ED25519")
        cls.ids = [key_id(pub) for _, pub in cls.keys]
        cls.network = bytes(range(1, 33))
        cls.root_id = bytes([0x22]) * 48
        cls.genesis = bytes([0x33]) * 48
        cls.challenge = bytes([0x44]) * 32
        cls.fid1 = bytes([0x55]) * 48
        cls.fid2 = bytes([0x66]) * 48
        cls.now = 1500

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="pql5n-case-")
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)
        self.replies = [self.reply(i, 2, self.fid2) for i in (0, 1)]

    def reply(self, witness: int, seq: int, fid: bytes, *, challenge: bytes | None = None,
              network: bytes | None = None, root: bytes | None = None,
              genesis: bytes | None = None, observed: int = 1495,
              expires: int | None = None, override_private: Path | None = None) -> bytes:
        kid = self.ids[witness]
        header = (b"PQL5\x01" + kid
                  + (self.network if network is None else network)
                  + (self.root_id if root is None else root)
                  + (self.genesis if genesis is None else genesis)
                  + seq.to_bytes(8, "big") + fid
                  + (self.challenge if challenge is None else challenge)
                  + observed.to_bytes(8, "big")
                  + (observed + 30 if expires is None else expires).to_bytes(8, "big"))
        self.assertEqual(len(header), 269)
        private = self.keys[witness][0] if override_private is None else override_private
        return header + (3309).to_bytes(2, "big") + sign(private, SIGN_DOMAIN + header)

    def call(self, frames: list[bytes] | None = None, *, seq: int = 2,
             fid: bytes | None = None, challenge: bytes | None = None,
             now: int = 1500, network: bytes | None = None,
             pubs: list[Path] | None = None):
        frames = self.replies if frames is None else frames
        pubs = [k[1] for k in self.keys] if pubs is None else pubs
        files = []
        for i, frame in enumerate(frames):
            p = self.work / ("reply" + str(i))
            p.write_bytes(frame)
            files.append(p)
        args = [self.binary, (self.network if network is None else network).hex(),
                self.root_id.hex(), self.genesis.hex(),
                (self.challenge if challenge is None else challenge).hex(),
                str(now), str(seq), (self.fid2 if fid is None else fid).hex(), *pubs, *files]
        return run(args)

    def accepted(self, frames=None, **kw):
        r = self.call(frames, **kw)
        self.assertEqual(r.returncode, 0, r.stderr.decode(errors="replace"))
        self.assertTrue(r.stdout.startswith(b"PQL5N_VALID_RESEARCH_OBSERVATION_ONLY"))
        self.assertNotIn(b"AUTHORIZATION", r.stdout)
        return r

    def refused(self, frames=None, **kw):
        r = self.call(frames, **kw)
        self.assertEqual(r.returncode, 2, repr(r.stdout) + repr(r.stderr))
        self.assertTrue(r.stderr.startswith(b"PQL5N_REJECT"))
        self.assertEqual(r.stdout, b"")

    def test_two_and_three_real_pq_signatures_quorum(self):
        self.accepted()
        self.accepted(self.replies + [self.reply(2, 2, self.fid2)])

    def test_wrong_external_monotone_pin_and_old_signed_quorum_refuse(self):
        self.refused(seq=3)
        self.refused(fid=self.fid1)
        self.refused([self.reply(0, 1, self.fid1), self.reply(1, 1, self.fid1)])

    def test_majority_clone_with_rewound_caller_pin_still_passes_as_negative(self):
        # This is a deliberate limitation, NOT a successful anti-rollback property.
        old = [self.reply(i, 1, self.fid1) for i in (0, 1)]
        self.refused(old, seq=2, fid=self.fid2)
        self.accepted(old, seq=1, fid=self.fid1)

    def test_singular_highest_head_cannot_override_two_older_witnesses(self):
        older = [self.reply(i, 1, self.fid1) for i in (0, 1)]
        self.refused(older + [self.reply(2, 2, self.fid2)])
        newer = [self.reply(i, 2, self.fid2) for i in (0, 1)]
        self.accepted(newer + [self.reply(2, 1, self.fid1)])

    def test_same_sequence_split_no_quorum(self):
        self.refused([self.reply(0, 2, self.fid2), self.reply(1, 2, self.fid1)])
        self.refused([self.reply(0, 2, self.fid2), self.reply(1, 2, self.fid1),
                      self.reply(2, 2, bytes([0x77])*48)])

    def test_duplicate_witness_response_and_roster_fail_closed(self):
        self.refused([self.reply(0, 2, self.fid2), self.reply(0, 2, self.fid2)])
        self.refused(pubs=[self.keys[0][1], self.keys[0][1], self.keys[2][1]])
        self.refused(pubs=[self.keys[0][1], self.outsider[1], self.keys[2][1]])

    def test_real_signature_wrong_secret_and_signed_byte_modification(self):
        self.refused([self.reply(0, 2, self.fid2, override_private=self.outsider[0]), self.replies[1]])
        b = bytearray(self.replies[0]); b[-1] ^= 1
        self.refused([bytes(b), self.replies[1]])

    def test_all_269_signed_header_byte_mutations_fail(self):
        original = self.replies[0]
        for i in range(269):
            bad = bytearray(original); bad[i] ^= 1
            with self.subTest(offset=i):
                self.refused([bytes(bad), self.replies[1]])

    def test_wrong_network_genesis_root_and_challenge(self):
        self.refused([self.reply(0, 2, self.fid2, network=bytes([0x88])*32), self.replies[1]])
        self.refused([self.reply(0, 2, self.fid2, root=bytes([0x88])*48), self.replies[1]])
        self.refused([self.reply(0, 2, self.fid2, genesis=bytes([0x88])*48), self.replies[1]])
        self.refused([self.reply(0, 2, self.fid2, challenge=bytes([0x88])*32), self.replies[1]])
        self.refused(challenge=bytes([0x77])*32)

    def test_replay_expired_future_and_expiry_overflow(self):
        self.refused([self.reply(0, 2, self.fid2, observed=1450), self.replies[1]])
        self.refused([self.reply(0, 2, self.fid2, observed=1501), self.replies[1]])
        self.refused([self.reply(0, 2, self.fid2, expires=1500), self.replies[1]])
        self.refused([self.reply(0, 2, self.fid2, expires=1499), self.replies[1]])
        self.refused([self.reply(0, 2, self.fid2, observed=(1 << 64)-20, expires=(1 << 64)-1), self.replies[1]])

    def test_empty_head_zero_frontier_and_inconsistent_identity(self):
        self.refused([self.reply(0, 0, bytes(48)), self.reply(1, 0, bytes(48))], seq=0, fid=bytes(48))
        self.refused([self.reply(0, 2, bytes(48)), self.replies[1]])
        self.refused([self.reply(0, 0, self.fid2), self.replies[1]])

    def test_frame_malleation_truncation_oversize_and_length(self):
        b = self.replies[0]
        for bad in (b[:-1], b + b"x", b"x" + b, b[:269] + bytes(2) + b[271:],
                    b"XQL5"+b[4:], b[:4] + b"\x02" + b[5:]):
            with self.subTest(length=len(bad)):
                self.refused([bad, self.replies[1]])

    def test_pem_algorithm_downgrade_trailing_or_symlink(self):
        self.refused(pubs=[self.classical[1], self.keys[1][1], self.keys[2][1]])
        bad = self.work / "badpem"
        bad.write_bytes(self.keys[0][1].read_bytes() + b"UNTRUSTED EXTRA BYTES")
        self.refused(pubs=[bad, self.keys[1][1], self.keys[2][1]])
        symlink = self.work / "symlink.pem"
        symlink.symlink_to(self.keys[0][1]); self.refused(pubs=[symlink, self.keys[1][1], self.keys[2][1]])
        link = self.work / "response-link"
        link.symlink_to(self.work / "reply0")
        args = [self.binary, self.network.hex(), self.root_id.hex(), self.genesis.hex(),
                self.challenge.hex(), "1500", "2", self.fid2.hex(),
                *(k[1] for k in self.keys), link, self.work / "reply1"]
        self.work.joinpath("reply1").write_bytes(self.replies[1])
        self.assertEqual(run(args).returncode, 2)

    def test_caller_decimal_and_boundaries(self):
        args = [self.binary, self.network.hex(), self.root_id.hex(), self.genesis.hex(),
                self.challenge.hex(), "01500", "2", self.fid2.hex(),
                *(k[1] for k in self.keys)]
        a = self.work / "a"; b = self.work / "b"
        a.write_bytes(self.replies[0]); b.write_bytes(self.replies[1])
        self.assertEqual(run([*args, a, b]).returncode, 2)
        for number in ("-1", "1.0", str(1 << 64), "xyz"):
            c = list(args); c[5] = number
            self.assertEqual(run([*c, a, b]).returncode, 2)
        self.refused(network=bytes(32))

    def test_optional_inherited_python_reference_parity(self):
        try:
            import pq_pql5_quorum as parent
        except ModuleNotFoundError:
            self.skipTest("inherited full PR #458 checkout unavailable in isolated runtime")
        roster = {self.ids[i]: self.keys[i][1].read_bytes() for i in range(3)}
        for frames, seq, fid, good in (
            (self.replies, 2, self.fid2, True),
            ([self.reply(0, 1, self.fid1), self.reply(1, 1, self.fid1)], 2, self.fid2, False),
            ([self.reply(0, 2, self.fid2), self.reply(1, 2, self.fid1)], 2, self.fid2, False),
        ):
            with self.subTest(good=good):
                native = self.call(frames, seq=seq, fid=fid).returncode == 0
                try:
                    parent.verify_quorum([(self.ids[i],v) for i,v in enumerate(frames)],
                        roster=roster,network=self.network,root=self.root_id,
                        genesis=self.genesis,challenge=self.challenge,now=self.now,
                        expected_sequence=seq,expected_frontier_id=fid)
                    python_result = True
                except parent.Reject:
                    python_result = False
                self.assertEqual(native, python_result)
                self.assertEqual(native, good)


if __name__ == "__main__":
    unittest.main()
