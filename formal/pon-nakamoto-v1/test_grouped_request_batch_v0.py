"""Adversarial local scheduling controls; these fixtures authenticate no demand."""
from dataclasses import FrozenInstanceError, replace
import unittest
from grouped_request_batch_v0 import BatchPlanner, Request, MAX_U64


def identity(n):
    return n.to_bytes(32, 'big').hex()


def request(n, arrival=0, deadline=100, **changes):
    return replace(Request(identity(n), identity(90), identity(91), identity(n + 100),
                           arrival, deadline), **changes)


def complete(planner, batch, row, now, **changes):
    values = dict(scope=row.scope, model_version=row.model_version, input_sha256=row.input_sha256)
    values.update(changes)
    return planner.complete(batch.batch_id, row.request_id, now, **values)


class GroupedRequestBatchTests(unittest.TestCase):
    def test_capacity_preserves_intake_ties_and_never_pads(self):
        planner = BatchPlanner(max_batch=4, max_wait_ns=20)
        order = [4, 2, 3, 1]
        batches = []
        for n in order:
            batches += planner.submit(request(n), 0)
        self.assertEqual(len(batches), 1)
        self.assertEqual([r.request_id for r in batches[0].requests], [identity(n) for n in order])
        self.assertEqual(batches[0].reason, 'capacity')
        self.assertIsNone(planner.next_wakeup_ns)
        self.assertEqual(planner.advance(40), [])
        self.assertEqual(planner.snapshot()['requests_seen'], 4)

    def test_partial_batch_flush_at_wait_without_synthetic_requests(self):
        planner = BatchPlanner(max_wait_ns=7)
        planner.submit(request(1, arrival=4), 4)
        planner.submit(request(2, arrival=6), 6)
        self.assertEqual(planner.next_wakeup_ns, 11)
        self.assertEqual(planner.advance(10), [])
        batch, = planner.advance(11)
        self.assertEqual(len(batch.requests), 2)
        self.assertEqual(batch.as_dict()['queue_wait_ns'], [7, 5])
        self.assertEqual(planner.advance(50), [])

    def test_earliest_original_deadline_reserve_wins(self):
        planner = BatchPlanner(max_wait_ns=50, service_reserve_ns=3)
        planner.submit(request(1, deadline=70), 0)
        planner.submit(request(2, arrival=1, deadline=8), 1)
        self.assertEqual(planner.next_wakeup_ns, 5)
        batch, = planner.advance(5)
        self.assertEqual(batch.requests[1].deadline_ns, 8)
        self.assertTrue(complete(planner, batch, batch.requests[0], 6)['accepted'])
        event = complete(planner, batch, batch.requests[1], 8)
        self.assertFalse(event['accepted'])
        self.assertEqual(event['status'], 'completed_late')
        self.assertEqual(event['original_deadline_ns'], 8)

    def test_missed_wakeup_expires_without_backdated_dispatch(self):
        planner = BatchPlanner(max_wait_ns=5, service_reserve_ns=1)
        planner.submit(request(1, deadline=7), 0)
        self.assertEqual(planner.advance(9), [])
        self.assertEqual(planner.events[-1]['status'], 'expired_before_dispatch')
        self.assertEqual(planner.events[-1]['observed_ns'], 9)
        self.assertEqual(planner.batches, ())

    def test_expired_at_intake_is_preserved(self):
        planner = BatchPlanner(max_wait_ns=3)
        self.assertEqual(planner.submit(request(1, deadline=3), 4), [])
        self.assertEqual(planner.events[-1]['status'], 'expired_on_arrival')
        self.assertIsNone(planner.next_wakeup_ns)

    def test_zero_wait_flushes_immediately(self):
        planner = BatchPlanner(max_wait_ns=0)
        batch, = planner.submit(request(1, arrival=2), 2)
        self.assertEqual(batch.as_dict()['queue_wait_ns'], [0])

    def test_zero_reserve_does_not_dispatch_at_expired_deadline(self):
        planner = BatchPlanner(max_wait_ns=100, service_reserve_ns=0)
        planner.submit(request(1, deadline=3), 0)
        self.assertEqual(planner.next_wakeup_ns, 3)
        self.assertEqual(planner.advance(3), [])
        self.assertEqual(planner.events[-1]['status'], 'expired_before_dispatch')

    def test_scope_and_model_boundaries_never_share_a_batch(self):
        for key in ('scope', 'model_version'):
            with self.subTest(key=key):
                planner = BatchPlanner(max_wait_ns=50)
                planner.submit(request(1), 0)
                emitted = planner.submit(request(2, **{key: identity(900)}), 1)
                self.assertEqual(len(emitted), 1)
                self.assertEqual(emitted[0].reason, 'scope_or_model_boundary')
                self.assertEqual(planner.pending_ids, (identity(2),))
                self.assertEqual(len(planner.advance(2, flush=True)[0].requests), 1)

    def test_duplicate_id_cannot_change_any_original_identity(self):
        planner = BatchPlanner(max_wait_ns=50)
        row = request(1)
        planner.submit(row, 0)
        for values in ({}, {'deadline_ns': 101}, {'arrival_ns': 1},
                       {'scope': identity(8)}, {'model_version': identity(7)},
                       {'input_sha256': identity(6)}):
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, 'DUPLICATE_REQUEST'):
                planner.submit(replace(row, **values), 1)
        self.assertEqual(planner.pending_ids, (row.request_id,))
        self.assertEqual(planner.snapshot()['requests_seen'], 1)

    def test_missing_future_boolean_and_rewound_clock_refuse(self):
        planner = BatchPlanner(max_wait_ns=9)
        for row in (request(1, arrival=1), request(1, deadline=None),
                    request(1, arrival=True), request(1, deadline=0)):
            with self.subTest(row=row), self.assertRaises(ValueError):
                planner.submit(row, 0)
        planner.submit(request(2), 5)
        with self.assertRaisesRegex(ValueError, 'CLOCK_REWIND'):
            planner.advance(4)
        self.assertEqual(planner.pending_ids, (identity(2),))

    def test_cancellation_stays_terminal_even_if_output_arrives(self):
        planner = BatchPlanner(max_batch=1, max_wait_ns=20)
        row = request(1)
        batch, = planner.submit(row, 0)
        event = planner.cancel(row.request_id, 1)
        event['status'] = 'forged'
        result = complete(planner, batch, row, 2)
        self.assertEqual(result['status'], 'output_after_cancellation')
        self.assertFalse(result['accepted'])
        with self.assertRaisesRegex(ValueError, 'TERMINAL_ALREADY_RECORDED'):
            complete(planner, batch, row, 3)
        self.assertEqual(planner.events[-2]['status'], 'cancelled')

    def test_cancellation_before_dispatch_has_no_executed_batch(self):
        planner = BatchPlanner(max_wait_ns=5)
        planner.submit(request(1), 0)
        self.assertFalse(planner.cancel(identity(1), 1)['after_dispatch'])
        self.assertEqual(planner.advance(10), [])
        self.assertEqual(planner.batches, ())
        with self.assertRaisesRegex(ValueError, 'NOT_DISPATCHED'):
            planner.complete(identity(9), identity(1), 11, scope=identity(90),
                             model_version=identity(91), input_sha256=identity(101))

    def test_wrong_completion_identity_unknown_batch_and_duplicate_refuse(self):
        planner = BatchPlanner(max_batch=1, max_wait_ns=20)
        row = request(1)
        batch, = planner.submit(row, 0)
        for key in ('scope', 'model_version', 'input_sha256'):
            with self.assertRaisesRegex(ValueError, 'COMPLETION_IDENTITY'):
                complete(planner, batch, row, 1, **{key: identity(999)})
        with self.assertRaisesRegex(ValueError, 'BATCH_IDENTITY'):
            planner.complete(identity(999), row.request_id, 1, scope=row.scope,
                             model_version=row.model_version, input_sha256=row.input_sha256)
        self.assertEqual(complete(planner, batch, row, 2)['status'], 'completed_on_time')
        with self.assertRaisesRegex(ValueError, 'TERMINAL_ALREADY_RECORDED'):
            complete(planner, batch, row, 3)
        with self.assertRaisesRegex(ValueError, 'UNKNOWN_REQUEST'):
            planner.cancel(identity(999), 4)

    def test_session_and_integer_bounds_no_unbounded_wait(self):
        planner = BatchPlanner(max_batch=1, max_wait_ns=MAX_U64, max_requests=1)
        row = request(1, arrival=MAX_U64 - 2, deadline=MAX_U64)
        batch, = planner.submit(row, MAX_U64 - 2)
        self.assertTrue(complete(planner, batch, row, MAX_U64 - 1)['accepted'])
        with self.assertRaisesRegex(ValueError, 'SESSION_EXHAUSTED'):
            planner.submit(request(2, arrival=MAX_U64 - 1, deadline=MAX_U64), MAX_U64 - 1)
        for args in ({'max_batch': 65, 'max_wait_ns': 0}, {'max_wait_ns': -1},
                     {'max_wait_ns': MAX_U64 + 1}, {'max_batch': True, 'max_wait_ns': 1}):
            with self.assertRaises(ValueError):
                BatchPlanner(**args)

    def test_snapshots_and_request_objects_cannot_rewrite_history(self):
        planner = BatchPlanner(max_wait_ns=10)
        row = request(1)
        planner.submit(row, 0)
        with self.assertRaises(FrozenInstanceError):
            row.deadline_ns = 10000
        view = planner.snapshot()
        view['events'][0]['original_deadline_ns'] = 10000
        planner.events[0]['status'] = 'forged'
        self.assertEqual(planner.events[0]['status'], 'queued')
        self.assertEqual(planner.events[0]['original_deadline_ns'], 100)
        self.assertFalse(view['real_demand_authenticated'])


if __name__ == '__main__':
    unittest.main()
