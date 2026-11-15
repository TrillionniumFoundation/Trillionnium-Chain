"""Real ordinary wait4 owner, synthetic charge files/clock; no cgroup/model pass."""
import sys
import unittest
from unittest.mock import Mock, patch

import llm_runtime_kernel_aggregate as aggregate
import llm_runtime_evidence_pipe as transport
import test_llm_runtime_kernel_aggregate as fixtures


@unittest.skipUnless(sys.implementation.name == 'cpython' and
    sys.version_info[:3] == (3, 12, 3), 'controlled ABI requires CPython 3.12.3')
class TerminalChargeWaitTests(unittest.TestCase):
    # Keep the original actual native owner/FD fixture and cleanup obligations.
    setUp = fixtures.AggregateTests.setUp
    cleanup = fixtures.AggregateTests.cleanup
    fixture = fixtures.AggregateTests.fixture
    owned_terminal = fixtures.AggregateTests.owned_terminal

    def terminal(self):
        cap = self.fixture()
        child = self.owned_terminal(cap)
        pipe = object.__new__(transport._EvidencePipeOwner)
        pipe.capability = cap
        pipe.deadline_ns = 8_000_000_000
        # This slice tests charge reconciliation after transport, whose actual
        # framing, EOF and native-FD tests remain separate and unchanged.
        pipe._finish_locked = Mock()
        cap.evidence_pipe = pipe
        return cap, child, pipe

    def test_actual_zero_is_required_after_transient_memory_and_swap_charge(self):
        cap, child, pipe = self.terminal()
        path = cap.operation
        (path/'memory.current').write_text('159744\n')
        (path/'memory.swap.current').write_text('4096\n')
        clock = [1_000_000_000]
        sleeps = []
        def teardown(seconds):
            sleeps.append(seconds)
            clock[0] += round(seconds * 10**9)
            (path/('memory.current' if len(sleeps) == 1 else 'memory.swap.current')).write_text('0\n')
        with patch.object(aggregate, 'monotonic_ns', side_effect=lambda: clock[0]), \
                patch.object(aggregate, 'sleep', side_effect=teardown):
            result = cap.terminal_record(child.pid, child.termination_fd)
        self.assertEqual(sleeps, [0.01, 0.01])
        self.assertEqual(pipe.deadline_ns, 8_000_000_000)
        self.assertEqual(cap.fact.counters['memory.current'], '0\n')
        self.assertEqual(cap.fact.counters['memory.swap.current'], '0\n')
        self.assertEqual((result['reservation'], result['outer_reconciliation']), ('RETAINED', 'UNKNOWN'))
        self.assertFalse(cap.failed)
        pipe._finish_locked.assert_called_once_with(child)

    def test_persistent_charge_expires_without_fact_or_deadline_reset(self):
        cap, child, pipe = self.terminal()
        (cap.operation/'memory.current').write_text('4096\n')
        clock = [pipe.deadline_ns - 1_000_000]
        def deadline(seconds):
            self.assertEqual(seconds, 0.001)
            clock[0] = pipe.deadline_ns
        with patch.object(aggregate, 'monotonic_ns', side_effect=lambda: clock[0]), \
                patch.object(aggregate, 'sleep', side_effect=deadline), \
                self.assertRaises(aggregate.AggregateCounterError) as failed:
            cap.terminal_record(child.pid, child.termination_fd)
        self.assertEqual(failed.exception.counter_diagnostic,
            aggregate._CounterDiagnostic('aggregate/memory.current', '4096\n', 'aggregate-charge-retained'))
        self.assertIsNone(cap.fact)
        self.assertTrue(cap.failed)
        self.assertIs(self.native.operation, cap)
        self.assertEqual(pipe.deadline_ns, 8_000_000_000)

    def test_malformed_counter_never_waits(self):
        cap, child, _ = self.terminal()
        (cap.operation/'memory.current').write_text('not-a-counter\n')
        with patch.object(aggregate, 'monotonic_ns', return_value=1), \
                patch.object(aggregate, 'sleep') as slept, \
                self.assertRaises(aggregate.AggregateCounterError):
            cap.terminal_record(child.pid, child.termination_fd)
        slept.assert_not_called()
        self.assertTrue(cap.failed)
        self.assertIsNone(cap.fact)

    def test_identity_drift_during_wait_fails_before_reading_zero(self):
        cap, child, _ = self.terminal()
        (cap.operation/'memory.current').write_text('4096\n')
        def replaced(seconds):
            (cap.operation/'memory.current').write_text('0\n')
            cap._verify_locked.side_effect = ValueError('changed-held-owner')
        with patch.object(aggregate, 'monotonic_ns', return_value=1), \
                patch.object(aggregate, 'sleep', side_effect=replaced), \
                self.assertRaisesRegex(ValueError, 'changed-held-owner'):
            cap.terminal_record(child.pid, child.termination_fd)
        self.assertTrue(cap.failed)
        self.assertIsNone(cap.fact)

    def test_second_snapshot_and_completion_must_still_precede_deadline(self):
        cap, child, pipe = self.terminal()
        clock = [1]
        original = aggregate._raw
        reads = []
        def read(fd):
            result = original(fd)
            reads.append(fd)
            if len(reads) == 2:
                clock[0] = pipe.deadline_ns
            return result
        with patch.object(aggregate, 'monotonic_ns', side_effect=lambda: clock[0]), \
                patch.object(aggregate, '_raw', side_effect=read), \
                self.assertRaisesRegex(ValueError, 'original-deadline'):
            cap.terminal_record(child.pid, child.termination_fd)
        self.assertEqual(len(reads), 2)
        self.assertTrue(cap.failed)
        self.assertIsNone(cap.fact)

    def test_attempted_deadline_extension_cannot_keep_waiting(self):
        cap, child, pipe = self.terminal()
        (cap.operation/'memory.current').write_text('4096\n')
        def extend(seconds):
            pipe.deadline_ns += 8_000_000_000
        with patch.object(aggregate, 'monotonic_ns', return_value=1), \
                patch.object(aggregate, 'sleep', side_effect=extend) as slept, \
                self.assertRaisesRegex(ValueError, 'original-deadline'):
            cap.terminal_record(child.pid, child.termination_fd)
        slept.assert_called_once_with(0.01)
        self.assertTrue(cap.failed)
        self.assertIsNone(cap.fact)

    def test_wait4_owner_is_rechecked_before_publishing_a_fact(self):
        for interrupted_read in (1, 2):
            with self.subTest(interrupted_read=interrupted_read):
                cap, child, _ = self.terminal()
                original = aggregate._raw
                reads = []
                def changed(fd):
                    value = original(fd)
                    reads.append(fd)
                    if len(reads) == interrupted_read:
                        child.reaped = False
                    return value
                try:
                    with patch.object(aggregate, 'monotonic_ns', return_value=1), \
                            patch.object(aggregate, '_raw', side_effect=changed), \
                            self.assertRaisesRegex(ValueError, 'exact-owned-wait4'):
                        cap.terminal_record(child.pid, child.termination_fd)
                    self.assertTrue(cap.failed)
                    self.assertIsNone(cap.fact)
                finally:
                    child.reaped = True  # Only the original real cleanup receipt.
                    child.kernel_operation = None
                    for slot in cap._fd_owners:
                        if slot[1] >= 0:
                            self.native.release_owned(slot)
                    self.native.operation = self.cap = None


if __name__ == '__main__': unittest.main()
