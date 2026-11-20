"""Live original-Rust/native-HIA differential tests, explicitly opt in.

Set TRNM_HIA_RUST_REFERENCE to the standalone executable built from
rust_reference.rs. It imports the retained Rust modules by path and calls their
public methods. Missing configuration is NOT_RUN, reported as unittest skip;
an invalid configured executable or any difference is a failure, never a skip.

The Rust fixture's SourceOk only exposes replay's pure boundary and transition
semantics. These tests do not establish source authentication, durable recovery,
network ownership, persistence, or full verified-token integration. The HIA
prior operation is compared with the original state's derived equality.
"""
from __future__ import annotations

import hashlib
import itertools
import os
from pathlib import Path
import random
import subprocess
import unittest

from hia.tests.native_support import NativeModule
from hia.tests import test_closed_round as closed
from hia.tests import test_replay as replay


DESCRIPTION = "TRNM-HIA-RUST-REFERENCE/1 original-modules SourceOk-test-only"


class OriginalRustDifferentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("TRNM_HIA_RUST_REFERENCE")
        if not configured:
            raise unittest.SkipTest(
                "NOT_RUN: TRNM_HIA_RUST_REFERENCE is not configured; "
                "the original Rust/native HIA differential has not executed"
            )
        cls.reference = Path(configured).expanduser().resolve(strict=True)
        if not cls.reference.is_file() or not os.access(cls.reference, os.X_OK):
            raise AssertionError("configured Rust reference must be an executable file")
        cls.reference_sha256 = hashlib.sha256(cls.reference.read_bytes()).hexdigest()
        described = subprocess.run(
            [str(cls.reference), "--describe"], capture_output=True, text=True,
            timeout=10, check=True,
        )
        if described.stdout.strip() != DESCRIPTION or described.stderr:
            raise AssertionError("configured executable is not the original-Rust reference protocol")
        cls.modules = {}
        for kind, source in (("C", closed.SOURCE), ("R", replay.SOURCE)):
            module = NativeModule(source, byte_exports=("f0",), backend="selfhost")
            cls.addClassCleanup(module.close)
            cls.modules[kind] = module

    def compare(self, kind, cases):
        """Compare status and the entire output; no Python policy oracle."""
        self.assertEqual(hashlib.sha256(self.reference.read_bytes()).hexdigest(),
                         self.reference_sha256, "Rust reference changed during testing")
        lines = [f"{kind} {raw.hex() or '-'} {output.hex() or '-'}\n"
                 for raw, output in cases]
        reference = subprocess.run(
            [str(self.reference)], input="".join(lines), capture_output=True,
            text=True, timeout=30, check=False,
        )
        self.assertEqual(reference.returncode, 0, reference.stderr)
        self.assertEqual(reference.stderr, "")
        observed = reference.stdout.splitlines()
        self.assertEqual(len(observed), len(cases))
        scratch = closed.SCRATCH if kind == "C" else replay.SCRATCH
        results = self.modules[kind].call_many(
            [("f0", [raw, output, scratch]) for raw, output in cases], timeout=30,
        )
        self.assertEqual(len(results), len(cases))
        for number, (result, line, (raw, initial)) in enumerate(zip(results, observed, cases)):
            with self.subTest(kind=kind, case=number,
                              input_sha256=hashlib.sha256(raw).hexdigest()):
                fields = line.split()
                self.assertEqual(len(fields), 2)
                status = int(fields[0])
                output = b"" if fields[1] == "-" else bytes.fromhex(fields[1])
                self.assertGreaterEqual(status, 0)
                self.assertLessEqual(status, (1 << 32) - 1)
                result.require_returned()
                self.assertEqual(result.abi_status, 0)
                self.assertEqual(result.value, status)
                self.assertEqual(result.arguments, [raw, output, scratch])
                if status:
                    self.assertEqual(output, initial, "reference wrote an error output")
        self.assertEqual(hashlib.sha256(self.reference.read_bytes()).hexdigest(),
                         self.reference_sha256, "Rust reference changed during testing")
        return results

    def closed_cases(self, specifications):
        return self.compare("C", [(closed.wire(eligible, votes, maximum), closed.CANARY)
                                  for eligible, votes, maximum in specifications])

    def replay_cases(self, requests):
        return self.compare("R", [(raw, replay.SENTINEL) for raw in requests])

    def test_original_closed_round_scores_authority_and_arrival_order(self):
        cases = []
        endpoints = (0, 1, 255, 65535, (1 << 32) - 1, 1 << 32,
                     (1 << 63) - 1, 1 << 63, closed.MAX_U64 - 1, closed.MAX_U64)
        for count in range(6):
            eligible = set("abcde"[:count])
            cases.extend([(eligible, {}, 0), (eligible, {"unknown": closed.MAX_U64}, 0)])
        for maximum in endpoints:
            for eligible in ({"a", "b"}, {"a", "b", "c"}):
                cases.extend([
                    (eligible, {}, maximum),
                    (eligible, {"a": 0}, maximum),
                    (eligible, {name: maximum for name in eligible}, maximum),
                    (eligible, {name: 0 for name in eligible}, maximum),
                    (eligible, {"a": 0, "b": maximum}, maximum),
                    (eligible, {"unknown": closed.MAX_U64}, maximum),
                ])
                if maximum < closed.MAX_U64:
                    cases.extend([
                        (eligible, {"a": maximum + 1}, maximum),
                        (eligible, {**dict.fromkeys(eligible, 0), "a": maximum + 1}, maximum),
                        (eligible, {"a": maximum + 1, "unknown": maximum + 1}, maximum),
                    ])
        for arrival in itertools.permutations(("a", "b", "c")):
            votes = {}
            for name in arrival:
                cases.append(({"a", "b", "c"}, votes.copy(), 1000))
                votes[name] = {"a": 10, "b": 100, "c": 0}[name]
            cases.append(({"a", "b", "c"}, votes.copy(), 1000))
        self.closed_cases(cases)
        complete = closed.wire({"a", "b"}, {"a": 0, "b": closed.MAX_U64})
        pending = closed.wire({"a", "b"}, {"a": 0})
        self.compare("C", [(raw, b"\xa5" * size)
                           for raw in (complete, pending) for size in range(17)])

    def test_original_closed_round_strings_maps_and_full_width_random_scores(self):
        names = ["", "\x00", "a", "ab", "b", "é", "e\u0301", "中", "\ud7ff", "\ue000",
                 "\uffff", "\U00010000", "\U0010ffff"]
        cases = [({left, right}, {left: 17, right: 23}, closed.MAX_U64)
                 for left, right in itertools.combinations(names, 2)]
        cases.append(({"é", "a"}, {"e\u0301": 17, "a": 23}, closed.MAX_U64))
        rng = random.Random(0x5255535443524431)
        for _ in range(512):
            eligible = set(rng.sample(names, rng.randrange(6)))
            votes = {name: rng.choice((0, 1, 17, 1 << 63, closed.MAX_U64, rng.getrandbits(64)))
                     for name in rng.sample(names, rng.randrange(6))}
            maximum = rng.choice((0, 1, 17, 1 << 63, closed.MAX_U64, rng.getrandbits(64)))
            cases.append((eligible, votes, maximum))
        first, second = "a" * 262131, "b" * 262131
        self.assertEqual(len(closed.wire({first, second}, {first: 5, second: 7})), 1 << 20)
        cases.append(({first, second}, {first: 5, second: 7}, closed.MAX_U64))
        self.closed_cases(cases)

    def test_original_replay_recovery_nonce_pending_and_ack_boundaries(self):
        current, first = replay.state(), replay.frame()
        pending = replay.state(pending=first)
        terminal = replay.state(acknowledged=replay.MAX_U64)
        final_frame = replay.frame(nonce=replay.MAX_U64)
        final_pending = replay.state(acknowledged=replay.MAX_U64 - 1, pending=final_frame)
        raws = [replay.request(0, value) for value in (current, pending, terminal, final_pending)]
        for operation in (1, 3):
            for nonce in (0, 1, 2, (1 << 63) - 1, 1 << 63, replay.MAX_U64):
                raws.append(replay.request(operation, current, replay.frame(nonce=nonce)))
            for candidate in (first, replay.frame(digest=b"\x0b" * 32),
                              replay.frame(size=129), replay.frame(nonce=2),
                              replay.frame(identity=replay.session(2))):
                raws.append(replay.request(operation, pending, candidate))
            raws.extend([
                replay.request(operation, terminal, first),
                replay.request(operation, terminal, replay.frame(identity=replay.session(2))),
                replay.request(operation, replay.state(acknowledged=replay.MAX_U64 - 1), final_frame),
                replay.request(operation, replay.state(acknowledged=replay.MAX_U64 - 1),
                               replay.frame(nonce=replay.MAX_U64 - 1)),
            ])
        for candidate in (first, replay.frame(nonce=2), replay.frame(size=129),
                          replay.frame(digest=b"\x0b" * 32), replay.frame(identity=replay.session(2))):
            raws.extend([replay.request(2, pending, candidate), replay.request(2, current, candidate)])
        raws.append(replay.request(2, final_pending, final_frame))
        for size in (0, 1, replay.MAX_FRAME, replay.MAX_FRAME + 1, replay.MAX_U64):
            raws.append(replay.request(1, current, replay.frame(size=size)))
        for value in (replay.state(pending=replay.frame(nonce=2)),
                      replay.state(pending=replay.frame(identity=replay.session(2))),
                      replay.state(acknowledged=replay.MAX_U64, pending=final_frame)):
            raws.append(replay.request(0, value))
        for left, right in ((current, current), (pending, pending), (terminal, terminal),
                            (current, pending), (pending, current),
                            (current, replay.state(acknowledged=1)),
                            (pending, replay.state(pending=replay.frame(size=129))),
                            (current, replay.state(pending=replay.frame(nonce=2)))):
            raws.append(replay.request(4, left, right))
        self.replay_cases(raws)

    def test_original_replay_all_identity_components_and_failure_precedence(self):
        raws = []
        current, first = replay.state(), replay.frame()
        pending = replay.state(pending=first)
        for offset in (0, 31, 32, 63, 64, 95, 96, 127, 128, 159, 160, 167):
            identity = replay.changed(replay.session(), offset, b"\x13")
            candidate = replay.frame(identity=identity)
            raws.extend([replay.request(1, current, candidate), replay.request(2, pending, candidate),
                         replay.request(4, current, replay.state(identity=identity))])
        for group in range(5):
            digests = [bytes([number]) * 32 for number in range(1, 6)]
            digests[group] = bytes(32)
            identity = replay.session(0, digests)
            raws.extend([replay.request(0, replay.state(identity=identity)),
                         replay.request(1, current, replay.frame(identity=identity, nonce=0))])
        for invalid in (replay.frame(digest=bytes(32), nonce=0, size=0),
                        replay.frame(identity=replay.session(0), digest=bytes(32)),
                        replay.frame(nonce=0), replay.frame(size=0)):
            raws.extend([replay.request(1, current, invalid),
                         replay.request(0, replay.state(acknowledged=replay.MAX_U64, pending=invalid))])
        for offset in (184, 399):
            raws.append(replay.request(0, replay.changed(current, offset, b"\x01")))
        for tag in (2, 1 << 63, replay.MAX_U64):
            raws.append(replay.request(0, replay.changed(current, 176, replay.u64(tag))))
        original = replay.request(0, current)
        raws.extend(original[:size] for size in (0, 1, 4, 7, 8, 160, 407))
        raws.append(original + b"\x00")
        for offset in range(8):
            raws.append(replay.changed(original, offset, b"\x05" if offset == 5 else b"\xff"))
        for operation, argument in ((1, first), (2, first), (3, first), (4, current)):
            raw = replay.request(operation, current, argument)
            raws.extend([raw[:-1], raw + b"\x00"])
        self.replay_cases(raws)
        self.compare("R", [(original, b"\xa5" * size) for size in (0, 1, 399, 401)])

    def test_original_replay_full_width_deterministic_state_matrix(self):
        rng = random.Random(0x5255535454525031)
        raws = []
        for number in range(128):
            identity = replay.session(rng.randrange(1, 1 << 64), [rng.randbytes(32) for _ in range(5)])
            acknowledged = (0, 1, (1 << 63) - 1, 1 << 63,
                            replay.MAX_U64 - 1, replay.MAX_U64, rng.getrandbits(64))[number % 7]
            current = replay.state(identity, acknowledged)
            raws.extend([replay.request(0, current), replay.request(4, current, current)])
            nonce = 1 if acknowledged == replay.MAX_U64 else acknowledged + 1
            candidate = replay.frame(identity, nonce, rng.randbytes(32), rng.randint(1, replay.MAX_FRAME))
            if acknowledged == replay.MAX_U64:
                raws.extend([replay.request(1, current, candidate), replay.request(3, current, candidate)])
                continue
            pending = replay.state(identity, acknowledged, candidate)
            conflict = replay.changed(candidate, 176, bytes([candidate[176] ^ 1]))
            raws.extend([
                replay.request(1, current, candidate), replay.request(3, current, candidate),
                replay.request(0, pending), replay.request(1, pending, candidate),
                replay.request(3, pending, candidate), replay.request(2, pending, candidate),
                replay.request(1, pending, conflict), replay.request(2, pending, conflict),
                replay.request(4, current, pending), replay.request(4, pending, pending),
            ])
            if acknowledged:
                raws.append(replay.request(1, current, replay.frame(identity, acknowledged)))
            if nonce != replay.MAX_U64:
                raws.append(replay.request(1, current, replay.frame(identity, nonce + 1)))
        self.replay_cases(raws)

    def test_original_replay_successors_recover_across_new_processes(self):
        for acknowledged in (0, replay.MAX_U64 - 2):
            current = replay.state(acknowledged=acknowledged)
            for nonce in (acknowledged + 1, acknowledged + 2):
                candidate = replay.frame(nonce=nonce)
                proposed = self.replay_cases([replay.request(3, current, candidate)])[0]
                self.assertEqual(proposed.value, 0)
                pending = proposed.arguments[1]
                recovered = self.replay_cases([replay.request(0, pending)])[0]
                self.assertEqual(recovered.value, 0)
                self.assertEqual(recovered.arguments[1], pending)
                acknowledged_result = self.replay_cases([replay.request(2, pending, candidate)])[0]
                self.assertEqual(acknowledged_result.value, 0)
                current = acknowledged_result.arguments[1]
                self.assertEqual(current, replay.state(acknowledged=nonce))


if __name__ == "__main__":
    unittest.main()
