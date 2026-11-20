"""Execute HIA replay checks and pure successor proposals as native machine code.

Expected state bytes come from the public replay contract and explicit test
vectors. Both upstream compiler implementations execute each vector. These
tests exercise no source-authority callback, network owner, or durable store.
"""
from pathlib import Path
import random
import unittest

from hia.tests.native_support import NativeModule


SOURCE = Path(__file__).resolve().parents[1] / "src/transport/replay.hepta"
MAX_U64 = (1 << 64) - 1
MAX_FRAME = 2_097_152
STATE_BYTES = 400
SENTINEL = b"\xa5" * STATE_BYTES
SCRATCH = b"untouched-replay-scratch\x00\xff"


def u64(value):
    return value.to_bytes(8, "little")


def session(generation=1, digests=None):
    if digests is None:
        digests = [bytes([number]) * 32 for number in range(1, 6)]
    return b"".join(digests) + u64(generation)


def frame(identity=None, nonce=1, digest=None, size=128):
    return ((session() if identity is None else identity) + u64(nonce)
            + (b"\x0a" * 32 if digest is None else digest) + u64(size))


def state(identity=None, acknowledged=0, pending=None):
    return ((session() if identity is None else identity) + u64(acknowledged)
            + u64(int(pending is not None)) + (bytes(216) if pending is None else pending))


def request(operation, current, argument=b""):
    return b"TRP1\x01" + bytes([operation]) + b"\x00\x00" + current + argument


def changed(data, offset, replacement):
    return data[:offset] + replacement + data[offset + len(replacement):]


class ReplayNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules = []
        for backend in ("selfhost", "direct"):
            module = NativeModule(SOURCE, byte_exports=("f0",), backend=backend)
            cls.addClassCleanup(module.close)
            cls.modules.append(module)

    def vectors(self, cases):
        """Each case has request, expected status, and expected success output."""
        calls = [("f0", [raw, SENTINEL, SCRATCH]) for raw, _, _ in cases]
        for module in self.modules:
            results = module.call_many(calls)
            self.assertEqual(len(results), len(cases))
            for number, (result, (raw, expected, next_state)) in enumerate(zip(results, cases)):
                with self.subTest(backend=module.receipt["chain_migration"]["backend"], case=number):
                    result.require_returned()
                    self.assertEqual(result.value, expected)
                    self.assertEqual(result.arguments[0], raw)
                    self.assertEqual(result.arguments[1], SENTINEL if expected else next_state)
                    self.assertEqual(result.arguments[2], SCRATCH)

    def test_recovery_round_trip_and_no_pending_maximum_nonce(self):
        states = [state(), state(pending=frame()), state(acknowledged=MAX_U64),
                  state(acknowledged=MAX_U64 - 1, pending=frame(nonce=MAX_U64))]
        self.vectors([(request(0, value), 0, value) for value in states])

    def test_complete_check_proposal_recovery_ack_sequence(self):
        empty, first = state(), frame()
        pending, acked = state(pending=first), state(acknowledged=1)
        second = frame(nonce=2, digest=b"\x0b" * 32)
        self.vectors([
            (request(1, empty, first), 0, empty),
            (request(3, empty, first), 0, pending),
            (request(0, pending), 0, pending),
            (request(1, pending, first), 0, pending),
            (request(3, pending, first), 0, pending),
            (request(2, pending, first), 0, acked),
            (request(2, empty, first), 12, None),
            (request(1, acked, first), 7, None),
            (request(3, acked, second), 0, state(acknowledged=1, pending=second)),
        ])

    def test_native_output_can_be_recovered_in_a_new_process(self):
        for module in self.modules:
            proposed = module.call("f0", [request(3, state(), frame()), SENTINEL, SCRATCH]).require_returned()
            self.assertEqual(proposed.value, 0)
            recovered = module.call("f0", [request(0, proposed.arguments[1]), SENTINEL, SCRATCH]).require_returned()
            self.assertEqual(recovered.value, 0)
            self.assertEqual(recovered.arguments[1], proposed.arguments[1])
            acked = module.call("f0", [request(2, recovered.arguments[1], frame()), SENTINEL, SCRATCH]).require_returned()
            self.assertEqual(acked.value, 0)
            self.assertEqual(acked.arguments[1], state(acknowledged=1))

    def test_pending_replay_identity_and_error_priority(self):
        pending = state(pending=frame())
        self.vectors([
            (request(1, pending, frame(digest=b"\x0b" * 32)), 10, None),
            (request(3, pending, frame(size=129)), 10, None),
            (request(1, pending, frame(nonce=2)), 9, None),
            (request(3, pending, frame(nonce=MAX_U64)), 9, None),
            (request(1, pending, frame(identity=session(2), digest=b"\x0b" * 32)), 6, None),
            (request(1, state(acknowledged=MAX_U64), frame(identity=session(2))), 6, None),
        ])

    def test_all_session_components_are_compared(self):
        cases = []
        for offset in (0, 31, 32, 63, 64, 95, 96, 127, 128, 159, 160):
            other_session = changed(session(), offset, b"\x13")
            candidate = frame(identity=other_session)
            cases.append((request(1, state(), candidate), 6, None))
            cases.append((request(2, state(pending=frame()), candidate), 12, None))
        self.vectors(cases)

    def test_ack_requires_the_complete_pending_frame(self):
        pending = state(pending=frame())
        self.vectors([
            (request(2, pending, frame(nonce=2)), 12, None),
            (request(2, pending, frame(digest=b"\x0b" * 32)), 12, None),
            (request(2, pending, frame(size=129)), 12, None),
            (request(2, state(acknowledged=1), frame()), 12, None),
        ])

    def test_unsigned_nonce_limits_stale_and_gap(self):
        terminal = state(acknowledged=MAX_U64)
        final_frame = frame(nonce=MAX_U64)
        final_pending = state(acknowledged=MAX_U64 - 1, pending=final_frame)
        self.vectors([
            (request(1, terminal, frame()), 5, None),
            (request(3, terminal, final_frame), 5, None),
            (request(0, state(acknowledged=MAX_U64, pending=final_frame)), 5, None),
            (request(2, final_pending, final_frame), 0, terminal),
            (request(1, state(acknowledged=MAX_U64 - 1), final_frame), 0, state(acknowledged=MAX_U64 - 1)),
            (request(1, state(acknowledged=MAX_U64 - 1), frame(nonce=MAX_U64 - 1)), 7, None),
            (request(1, state(), frame(nonce=2)), 8, None),
            (request(3, state(acknowledged=1), frame(nonce=3)), 8, None),
            (request(1, state(), frame(nonce=0)), 3, None),
        ])

    def test_recovery_rejects_noncanonical_or_inconsistent_state(self):
        self.vectors([
            (request(0, changed(state(), 176, u64(2))), 15, None),
            (request(0, changed(state(), 184, b"\x01")), 15, None),
            (request(0, changed(state(), 399, b"\x01")), 15, None),
            (request(0, state(pending=frame(nonce=2))), 4, None),
            (request(0, state(pending=frame(identity=session(2)))), 4, None),
            (request(0, state(acknowledged=5, pending=frame(nonce=5))), 4, None),
            (request(0, state(pending=frame(digest=bytes(32)))), 1, None),
            (request(0, state(identity=session(0))), 2, None),
            (request(0, state(identity=bytes(168))), 1, None),
        ])

    def test_digest_and_payload_bounds(self):
        cases = []
        for group in range(5):
            ids = [bytes([n]) * 32 for n in range(1, 6)]
            ids[group] = bytes(32)
            cases.append((request(0, state(identity=session(digests=ids))), 1, None))
        for size in (0, MAX_FRAME + 1, MAX_U64):
            cases.append((request(1, state(), frame(size=size)), 3, None))
        for size in (1, MAX_FRAME):
            cases.append((request(1, state(), frame(size=size)), 0, state()))
        cases.append((request(1, state(), frame(digest=bytes(32))), 1, None))
        for position in (0, 15, 31):
            digest = bytes(position) + b"\x01" + bytes(31 - position)
            identity = session(MAX_U64, [digest] * 5)
            current = state(identity=identity)
            cases.append((request(1, current, frame(identity=identity, digest=digest)), 0, current))
        self.vectors(cases)

    def test_prior_comparison_is_a_fact_and_checks_all_state_bytes(self):
        current = state()
        self.vectors([
            (request(4, current, current), 0, current),
            (request(4, current, state(acknowledged=1)), 11, None),
            (request(4, current, state(identity=session(2))), 11, None),
            (request(4, current, state(pending=frame())), 11, None),
            (request(4, state(pending=frame()), state(pending=frame(size=129))), 11, None),
            (request(4, current, state(pending=frame(nonce=2))), 4, None),
        ])

    def test_wire_header_lengths_and_no_failure_writes(self):
        original = request(0, state())
        cases = [(original[:size], 13, None) for size in (0, 1, 4, 7, 8, 160, 407)]
        cases += [(original + b"\x00", 13, None)]
        for offset in range(8):
            replacement = b"\x05" if offset == 5 else b"\xff"
            cases.append((changed(original, offset, replacement), 14, None))
        for operation in (1, 2, 3):
            cases.append((request(operation, state(), frame())[:-1], 13, None))
            cases.append((request(operation, state(), frame()) + b"\x00", 13, None))
        cases.append((request(4, state(), state())[:-1], 13, None))
        self.vectors(cases)
        for module in self.modules:
            for size in (0, 1, 399, 401):
                before = b"\xa5" * size
                result = module.call("f0", [original, before, SCRATCH]).require_returned()
                self.assertEqual(result.value, 13)
                self.assertEqual(result.arguments[1], before)
                self.assertEqual(result.arguments[2], SCRATCH)

    def test_deterministic_cross_compiler_state_matrix(self):
        rng = random.Random(0x54525031)
        cases = []
        for number in range(96):
            identity = session(rng.randrange(1, 1 << 64), [rng.randbytes(32) for _ in range(5)])
            acknowledged = [0, 1, MAX_U64 - 1, MAX_U64, rng.randrange(1 << 64)][number % 5]
            current = state(identity, acknowledged)
            cases.append((request(0, current), 0, current))
            nonce = 1 if acknowledged == MAX_U64 else acknowledged + 1
            candidate = frame(identity, nonce, rng.randbytes(32), rng.randint(1, MAX_FRAME))
            if acknowledged == MAX_U64:
                cases.append((request(3, current, candidate), 5, None))
                continue
            pending = state(identity, acknowledged, candidate)
            cases.extend([
                (request(1, current, candidate), 0, current),
                (request(3, current, candidate), 0, pending),
                (request(1, pending, candidate), 0, pending),
                (request(3, pending, candidate), 0, pending),
                (request(2, pending, candidate), 0, state(identity, nonce)),
                (request(4, current, pending), 11, None),
            ])
        self.vectors(cases)


if __name__ == "__main__":
    unittest.main()
