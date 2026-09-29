"""Real proof/signature/state replay for M13/M14; no pre-accepted history fixtures."""
from __future__ import annotations
import base64
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import client_confirmation as client
from contract_wire import H, PARAMS, canonical, header_decode, header_encode
from ledger import GENESIS, Ledger, key, public, sign


class VerifiedHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.TemporaryDirectory(prefix='pon-verified-history-')
        cls.source = Ledger(Path(cls.root.name) / 'source')
        cls.tx = sign(key(0), 1, 'transfer', {'recipient': public(key(1)), 'amount': 9})
        cls.txid = H('tx-id', cls.tx)
        cls.blocks = []
        parent = GENESIS
        for height in range(1, 8):
            packet = cls.source.make(parent, [cls.tx] if height == 1 else [])
            parent = cls.source.admit(*packet, PARAMS['genesis_timestamp'] + 1000)
            cls.source.activate(parent)
            cls.blocks.append(parent)
        cls.tip = parent
        cls.pages = list(client.history_pages(cls.source, cls.tip, blocks_per_page=2))
        cls.fork = GENESIS
        for height in range(1, 9):
            packet = cls.source.make(cls.fork, [], miner=public(key(2)))
            cls.fork = cls.source.admit(*packet, PARAMS['genesis_timestamp'] + 1000)

    @classmethod
    def tearDownClass(cls):
        cls.source.close()
        cls.root.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pon-confirm-receiver-')
        self.path = Path(self.tmp.name) / 'ledger'
        self.receiver = Ledger(self.path)
        self.now = PARAMS['genesis_timestamp'] + 1000

    def tearDown(self):
        self.receiver.close()
        self.tmp.cleanup()

    def import_all(self, tip=None, after=GENESIS):
        tip = tip or self.tip
        result = None
        for page in client.history_pages(self.source, tip, after, blocks_per_page=2):
            result = client.receive_page(self.receiver, page, expected_tip=tip,
                                         after=after, observed_now=self.now)
            after = bytes.fromhex(result['next_after'])
        return result

    def reject_before_admission(self, value, error):
        raw = value if isinstance(value, bytes) else canonical(value)
        before = self.receiver.read_active()
        with patch.object(self.receiver, 'admit', side_effect=AssertionError('expensive path reached')):
            with self.assertRaisesRegex(ValueError, error):
                client.receive_page(self.receiver, raw, expected_tip=self.tip,
                                    after=GENESIS, observed_now=self.now)
        self.assertEqual(self.receiver.read_active(), before)

    def test_full_work_state_and_transaction_confirmation(self):
        result = self.import_all()
        self.assertTrue(result['complete'])
        self.assertTrue(result['requested_tip_active'])
        self.assertEqual(self.source.read_active()[2], self.receiver.read_active()[2])
        fact = client.confirmation(self.receiver, self.txid, self.blocks[0], observed_now=self.now)
        self.assertEqual(fact['status'], 'confirmed')
        self.assertEqual(fact['depth'], 6)
        self.assertEqual(fact['cumulative_work_delta'], fact['required_work_delta'])
        self.assertFalse(fact['finalized'])
        self.assertFalse(fact['execution_authority'])

    def test_partial_page_not_requested_tip_success(self):
        result = client.receive_page(self.receiver, self.pages[0], expected_tip=self.tip,
                                     after=GENESIS, observed_now=self.now)
        self.assertFalse(result['complete'])
        self.assertEqual(self.receiver.active()[0], GENESIS)
        self.assertEqual(self.receiver.block(self.blocks[1])[1], 2)

    def test_disk_reopen_resume_uses_verified_block_cursor(self):
        first = client.receive_page(self.receiver, self.pages[0], expected_tip=self.tip,
                                    after=GENESIS, observed_now=self.now)
        self.receiver.close()
        self.receiver = Ledger(self.path)
        self.receiver.recover()
        result = self.import_all(after=bytes.fromhex(first['next_after']))
        self.assertTrue(result['complete'])
        self.assertEqual(client.confirmation(self.receiver, self.txid, self.blocks[0], observed_now=self.now)['status'], 'confirmed')

    def test_fork_replay_invalidates_old_confirmation(self):
        self.import_all()
        old = client.confirmation(self.receiver, self.txid, self.blocks[0], observed_now=self.now)
        self.import_all(self.fork)
        new = client.confirmation(self.receiver, self.txid, self.blocks[0], observed_now=self.now)
        self.assertEqual(new['status'], 'reorged')
        self.assertIsNone(new['depth'])
        self.assertIsNone(new['cumulative_work_delta'])
        self.assertNotEqual(old['active_generation'], new['active_generation'])

    def test_lighter_valid_history_cannot_replace_best_chain(self):
        self.import_all(self.fork)
        result = self.import_all()
        self.assertFalse(result['requested_tip_active'])
        self.assertEqual(self.receiver.active()[0], self.fork)

    def test_too_shallow_reports_included_not_confirmed(self):
        self.import_all(self.blocks[1])
        self.assertEqual(client.confirmation(self.receiver, self.txid, self.blocks[0], observed_now=self.now)['status'], 'included')

    def test_unknown_transaction_cannot_obtain_confirmation(self):
        self.import_all()
        with self.assertRaisesRegex(ValueError, 'NO_TRANSACTION'):
            client.confirmation(self.receiver, H('absent-transaction'), self.blocks[0], observed_now=self.now)

    def test_forged_work_total_or_confirmation_flags_reject(self):
        for field, value in [('chainwork', '99999999'), ('confirmed', True), ('observed_now', self.now)]:
            page = json.loads(self.pages[0]); page[field] = value
            self.reject_before_admission(page, 'PAGE_FIELDS')

    def test_wrong_network_parameters_and_genesis_reject(self):
        for field in ['network', 'parameters', 'genesis']:
            page = json.loads(self.pages[0]); page[field] = '00' * 32
            self.reject_before_admission(page, 'NETWORK')

    def test_swapped_target_and_cursor_reject(self):
        for field in ['tip', 'after']:
            page = json.loads(self.pages[0]); page[field] = '11' * 32
            self.reject_before_admission(page, 'PAGE_CONTEXT')

    def test_false_complete_or_next_cursor_reject(self):
        for field, value in [('complete', True), ('complete', 0), ('next_after', '11' * 32)]:
            page = json.loads(self.pages[0]); page[field] = value
            self.reject_before_admission(page, 'PAGE_COMPLETE|PAGE_CONTINUATION')

    def test_empty_nonterminal_and_reordered_blocks_reject(self):
        page = json.loads(self.pages[0]); page['blocks'] = []
        self.reject_before_admission(page, 'PAGE_NO_PROGRESS')
        page = json.loads(self.pages[0]); page['blocks'].reverse()
        self.reject_before_admission(page, 'PAGE_ORDER')

    def test_duplicate_keys_and_oversize_reject_before_json_work(self):
        self.reject_before_admission(b'{"tip":"a","tip":"b"}', 'PAGE_JSON')
        with patch.object(client.json, 'loads', side_effect=AssertionError('JSON parser reached')):
            with self.assertRaisesRegex(ValueError, 'PAGE_BYTES'):
                client.decode_page(b' ' * (client.MAX_PAGE_BYTES + 1), self.tip, GENESIS)

    def test_excessive_blocks_or_transactions_reject_early(self):
        page = json.loads(self.pages[0]); page['blocks'] *= 9
        self.reject_before_admission(page, 'PAGE_LIMIT')
        page = json.loads(self.pages[0]); page['blocks'][0]['transactions'] *= 257
        self.reject_before_admission(page, 'BODY')

    def test_noncanonical_base64_and_wrong_proof_length_reject(self):
        page = json.loads(self.pages[0]); page['blocks'][0]['header'] += '\n'
        self.reject_before_admission(page, 'BASE64|ENCODED_LIMIT')
        page = json.loads(self.pages[0]); page['blocks'][0]['proof'] = base64.b64encode(b'bad').decode()
        self.reject_before_admission(page, 'WORK_LENGTH')

    def test_invalid_proof_cannot_persist_or_activate(self):
        page = json.loads(self.pages[0])
        raw = bytearray(base64.b64decode(page['blocks'][0]['proof']))
        raw[32772] ^= 1  # change C, leave ticket/trace and block identity unchanged
        page['blocks'][0]['proof'] = base64.b64encode(raw).decode()
        with self.assertRaises(ValueError):
            client.receive_page(self.receiver, canonical(page), expected_tip=self.tip,
                                after=GENESIS, observed_now=self.now)
        self.assertEqual(self.receiver.db.execute('SELECT count(*) FROM blocks').fetchone()[0], 1)
        self.assertEqual(self.receiver.active()[0], GENESIS)

    def test_future_clock_is_local_deferral_not_remote_authority(self):
        with self.assertRaisesRegex(ValueError, 'TIME_DEFERRED'):
            client.receive_page(self.receiver, self.pages[0], expected_tip=self.tip,
                                after=GENESIS, observed_now=0)
        self.assertEqual(self.receiver.active()[0], GENESIS)
        self.assertTrue(self.import_all()['complete'])

    def test_cancel_retains_only_fully_verified_prefix_and_can_resume(self):
        def cancel(stage, count):
            if stage == 'admitted' and count == 1:
                raise InterruptedError('caller cancelled')
        with self.assertRaises(InterruptedError):
            client.receive_page(self.receiver, self.pages[0], expected_tip=self.tip,
                                after=GENESIS, observed_now=self.now, progress=cancel)
        self.assertEqual(self.receiver.active()[0], GENESIS)
        self.assertEqual(self.receiver.block(self.blocks[0])[1], 1)
        self.assertTrue(self.import_all(after=self.blocks[0])['complete'])

    def test_export_cursor_on_other_fork_rejects(self):
        with self.assertRaisesRegex(ValueError, 'CURSOR_NOT_ANCESTOR'):
            list(client.history_pages(self.source, self.tip, self.fork))

    def test_unverified_receiver_cursor_rejects(self):
        page = next(client.history_pages(self.source, self.tip, self.blocks[0]))
        with self.assertRaisesRegex(ValueError, 'UNKNOWN_PARENT'):
            client.receive_page(self.receiver, page, expected_tip=self.tip,
                                after=self.blocks[0], observed_now=self.now)

    def test_bounded_stream_incomplete_and_trailing_data_not_success(self):
        with self.assertRaisesRegex(ValueError, 'INCOMPLETE_HISTORY'):
            client.receive_stream(self.receiver, io.BytesIO(self.pages[0] + b'\n'),
                                  expected_tip=self.tip, after=GENESIS, observed_now=self.now)
        stream = b'\n'.join(self.pages) + b'\n'
        result = client.receive_stream(self.receiver, io.BytesIO(stream), expected_tip=self.tip,
                                       after=GENESIS, observed_now=self.now)
        self.assertTrue(result['complete'])
        with self.assertRaisesRegex(ValueError, 'TRAILING_PAGE'):
            client.receive_stream(self.receiver, io.BytesIO(stream + self.pages[-1] + b'\n'),
                                  expected_tip=self.tip, after=GENESIS, observed_now=self.now)

    def test_logical_import_does_not_masquerade_as_live_confirmation(self):
        self.import_all()
        with patch.object(client.time, 'time', return_value=0):
            with self.assertRaisesRegex(ValueError, 'TIME_DEFERRED'):
                client.confirmation(self.receiver, self.txid, self.blocks[0])
        result = client.confirmation(self.receiver, self.txid, self.blocks[0], observed_now=self.now)
        self.assertEqual(result['clock_scope'], 'explicit-logical-test-clock')

    def test_lost_ack_replays_verified_page_without_repeating_work(self):
        client.receive_page(self.receiver, self.pages[0], expected_tip=self.tip,
                            after=GENESIS, observed_now=self.now)
        with patch('ledger.work.verify', side_effect=AssertionError('duplicate work verification')):
            result = client.receive_page(self.receiver, self.pages[0], expected_tip=self.tip,
                                         after=GENESIS, observed_now=self.now)
        self.assertEqual(result['next_after'], self.blocks[1].hex())
        self.assertEqual(self.receiver.db.execute('SELECT count(*) FROM blocks').fetchone()[0], 3)

    def test_changed_transaction_body_rejects_before_persistence(self):
        page = json.loads(self.pages[0])
        replacement = sign(key(0), 1, 'transfer', {'recipient': public(key(2)), 'amount': 7})
        page['blocks'][0]['transactions'] = [base64.b64encode(replacement).decode()]
        with self.assertRaisesRegex(ValueError, 'ROOT'):
            client.receive_page(self.receiver, canonical(page), expected_tip=self.tip,
                                after=GENESIS, observed_now=self.now)
        self.assertEqual(self.receiver.db.execute('SELECT count(*) FROM blocks').fetchone()[0], 1)

    def test_query_rechecks_body_commitment_before_membership(self):
        self.import_all()
        original = self.receiver.block(self.blocks[0])[4]
        replacement = sign(key(0), 1, 'transfer', {'recipient': public(key(2)), 'amount': 7})
        import struct
        changed = struct.pack('<HH', 1, len(replacement)) + replacement
        self.receiver.db.execute('UPDATE blocks SET body=? WHERE id=?', (changed, self.blocks[0]))
        with self.assertRaisesRegex(ValueError, 'ROOT'):
            client.confirmation(self.receiver, H('tx-id', replacement), self.blocks[0], observed_now=self.now)
        self.receiver.db.execute('UPDATE blocks SET body=? WHERE id=?', (original, self.blocks[0]))

    def test_page_limit_rejects_boolean_or_unbounded_values(self):
        for value in [True, 0, 17, 1.5]:
            with self.assertRaisesRegex(ValueError, 'PAGE_LIMIT'):
                list(client.history_pages(self.source, self.tip, blocks_per_page=value))

    def test_exact_stored_body_decoder_rejects_bad_lengths(self):
        for value in [b'', b'\x00\x00x', b'\x01\x00', b'\x01\x00\xff\xff']:
            with self.assertRaisesRegex(ValueError, 'BODY'):
                client.unpack_body(value)

    def test_empty_already_verified_tip_is_idempotent(self):
        self.import_all()
        generation = self.receiver.active()[1]
        result = self.import_all(after=self.tip)
        self.assertEqual(result['verified_blocks'], 0)
        self.assertEqual(self.receiver.active()[1], generation)

    def test_command_line_receive_and_confirm_use_persistent_receiver(self):
        path = str(Path(self.tmp.name) / 'cli-store')
        program = str(Path(client.__file__))
        args = [sys.executable, program, 'receive', '--store', path, '--tip', self.tip.hex(),
                '--logical-now', str(self.now)]
        result = subprocess.run(args, input=b'\n'.join(self.pages) + b'\n', capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertTrue(json.loads(result.stdout)['complete'])
        result = subprocess.run([sys.executable, program, 'confirm', '--store', path,
                                 '--transaction', self.txid.hex(), '--included-block', self.blocks[0].hex(),
                                 '--logical-now', str(self.now)],
                                capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout)['status'], 'confirmed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
