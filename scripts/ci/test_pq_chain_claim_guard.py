"""Adversarial fixtures for the claim guard; deliberately no crypto pass tests."""
import json
import errno
import io
import mmap
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from copy import deepcopy
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pq_chain_claim_guard import (BOUNDARY, CONFIG, CONSENSUS, CORPUS, DEVNET, GATES,
                                  PROOF_MANIFEST, UnsafePromotion, inspect, safe_file)


class DescriptorReaderControls:
    """Shared real-filesystem attacks for both public reader wrappers.

    Hooks only choose the scheduling boundary. All opens, reads, directory
    renames, hardlinks, symlinks, writes and FIFO creation use the actual OS.
    The io.open hook also makes these controls replayable against the old
    pathname reader; no returned bytes or stat identities are fabricated.
    """

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.area = Path(temp.name)
        self.root = self.area / 'checkout-parent' / 'checkout'
        self.relative = 'nested/source.bin'
        self.source = self.root / self.relative
        self.source.parent.mkdir(parents=True)
        self.original = b'original source'
        self.replacement = b'replaced source'
        self.assertEqual(len(self.original), len(self.replacement))
        self.source.write_bytes(self.original)

    @staticmethod
    def identity(path):
        value = path.lstat()
        return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                value.st_mtime_ns, value.st_ctime_ns)

    def exercise(self, mutation, moment='open'):
        changed = False
        opened = []
        read_lengths = []
        before = self.identity(self.source)
        original_open, original_read, original_io_open = os.open, os.read, io.open

        def change():
            nonlocal changed
            changed = True
            mutation()

        def is_leaf(path):
            return (isinstance(path, (str, os.PathLike))
                    and os.fspath(path) in (str(self.source), self.source.name))

        def descriptor_open(path, flags, mode=0o777, *, dir_fd=None):
            if moment == 'open' and is_leaf(path) and not changed:
                change()
            fd = original_open(path, flags, mode, dir_fd=dir_fd)
            opened.append(fd)
            return fd

        def descriptor_read(fd, size):
            if moment == 'read' and not changed:
                change()
            data = original_read(fd, size)
            read_lengths.append(len(data))
            return data

        class WatchedFile:
            def __init__(self, handle):
                self.handle = handle

            def __enter__(self):
                self.handle.__enter__()
                return self

            def __exit__(self, *args):
                return self.handle.__exit__(*args)

            def __getattr__(self, name):
                return getattr(self.handle, name)

            def read(self, *args, **kwargs):
                if moment == 'read' and not changed:
                    change()
                data = self.handle.read(*args, **kwargs)
                read_lengths.append(len(data))
                return data

        def pathname_open(path, *args, **kwargs):
            watched = is_leaf(path)
            if watched and moment == 'open' and not changed:
                change()
            handle = original_io_open(path, *args, **kwargs)
            return WatchedFile(handle) if watched else handle

        try:
            with (patch.object(os, 'open', side_effect=descriptor_open),
                  patch.object(os, 'read', side_effect=descriptor_read),
                  patch.object(io, 'open', side_effect=pathname_open)):
                try:
                    accepted = self.reader(self.root, self.relative)
                except self.reader_error:
                    pass
                else:
                    self.fail(f'filesystem race accepted {accepted!r}; '
                              f'mutation_executed={changed}; before={before}; '
                              f'after={self.identity(self.source)}')
            self.assertTrue(changed, 'refusal occurred before the real attack ran')
            return read_lengths
        finally:
            for fd in opened:
                with self.assertRaises(OSError) as error:
                    os.fstat(fd)
                self.assertEqual(error.exception.errno, errno.EBADF,
                                 'opened source/ancestor descriptor leaked')

    def replace_leaf(self):
        other = self.area / 'replacement.bin'
        other.write_bytes(self.replacement)
        other.replace(self.source)

    def symlink_leaf(self):
        other = self.area / 'replacement.bin'
        other.write_bytes(self.replacement)
        self.source.unlink()
        self.source.symlink_to(other)

    def test_regular_file_is_returned_unchanged(self):
        self.assertEqual(self.reader(self.root, self.relative), self.original)

    def test_leaf_symlink_between_check_and_open_is_refused(self):
        self.exercise(self.symlink_leaf)

    def test_same_length_leaf_replacement_before_open_is_refused(self):
        self.exercise(self.replace_leaf)

    def test_same_length_leaf_replacement_during_read_is_refused(self):
        self.exercise(self.replace_leaf, 'read')

    def test_leaf_symlink_during_read_is_refused(self):
        self.exercise(self.symlink_leaf, 'read')

    def test_parent_replacement_with_identical_leaf_is_refused(self):
        # Create the extra link before the reader snapshots file ctime, so
        # the directory check is the only reason for refusal.
        replacement = self.area / 'replacement-directory'
        replacement.mkdir()
        os.link(self.source, replacement / self.source.name)

        def substitute():
            self.source.parent.rename(self.area / 'detached-directory')
            replacement.rename(self.source.parent)

        self.exercise(substitute)

    def test_parent_symlink_to_same_leaf_during_read_is_refused(self):
        def substitute():
            detached = self.area / 'detached-directory'
            self.source.parent.rename(detached)
            self.source.parent.symlink_to(detached, target_is_directory=True)

        self.exercise(substitute, 'read')

    def test_checkout_ancestor_symlink_during_read_is_refused(self):
        def substitute():
            detached = self.area / 'detached-checkout-parent'
            self.root.parent.rename(detached)
            self.root.parent.symlink_to(detached, target_is_directory=True)

        self.exercise(substitute, 'read')

    def test_same_length_in_place_rewrite_is_refused(self):
        def rewrite():
            original = self.source.stat()
            self.source.write_bytes(self.replacement)
            os.utime(self.source, ns=(original.st_atime_ns,
                                     original.st_mtime_ns + 1_000_000_000))

        self.exercise(rewrite, 'read')

    def test_same_length_rewrite_with_restored_mtime_is_refused(self):
        def rewrite():
            original = self.source.stat()
            self.source.write_bytes(self.replacement)
            os.utime(self.source, ns=(original.st_atime_ns, original.st_mtime_ns))
            self.assertNotEqual(self.source.stat().st_ctime_ns, original.st_ctime_ns)

        self.exercise(rewrite, 'read')

    def test_same_length_mmap_rewrite_is_refused(self):
        def rewrite():
            with self.source.open('r+b') as source:
                with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_WRITE) as mapping:
                    mapping[:] = self.replacement
                    mapping.flush()

        self.exercise(rewrite, 'read')

    def test_growth_during_read_is_bounded(self):
        lengths = self.exercise(
            lambda: self.source.write_bytes(b'x' * (self.byte_limit + 17)), 'read')
        self.assertLessEqual(sum(lengths), self.byte_limit + 1)
        self.assertTrue(lengths, 'growth must reach the actual bounded read')

    def test_fifo_substitution_cannot_block_before_fstat(self):
        def substitute():
            self.source.unlink()
            os.mkfifo(self.source)

        def blocked(signum, frame):
            raise AssertionError('reader blocked after real FIFO substitution')

        previous_handler = signal.signal(signal.SIGALRM, blocked)
        previous_timer = signal.setitimer(signal.ITIMER_REAL, 2)
        try:
            self.exercise(substitute)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
            if previous_timer[0]:
                signal.setitimer(signal.ITIMER_REAL, *previous_timer)

    def test_missing_after_check_is_wrapped_and_fds_close(self):
        self.exercise(self.source.unlink)


class ClaimReaderRaceTests(DescriptorReaderControls, unittest.TestCase):
    reader = staticmethod(safe_file)
    reader_error = UnsafePromotion
    byte_limit = 1024 * 1024


class TestClaimGuard(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.configs = {
            CONFIG: {'schema': 'trnm-pon-post-quantum-transition-v1',
                     'status': 'research-only-no-activation',
                     'changes_existing_consensus': False,
                     'production_activation': False, 'allow_classical_fallback': False,
                     'reference_signature': {'algorithm': 'ML-DSA-65', 'signature_bytes': 3309,
                                             'public_key_bytes': 1952, 'signed_envelope_bytes': 3487,
                                             'native_account_migration_integrated': False},
                     'reference_key_exchange': {'tls_authenticated_deployed': False},
                     'existing_devnet_limits': {'post_quantum_transaction_wire_compatible': False,
                                                'max_transaction_bytes': 2048,
                                                'max_block_bytes': 1048576},
                     'candidate_limits_for_analysis_only': {'evaluated_for_network_or_security': False},
                     'conformance': {'tests_are_product_activation': False,
                                     'independent_accepted': False,
                                     'native_node_integrated': False}},
            CORPUS: {'assertions': {'production_activation': False, 'independent_accepted': False,
                                   'native_pq_node_integrated': False,
                                   'quantum_pon_hardness_qualified': False,
                                   'physical_rollback_resistant': False,
                                   'hepta_final_use_integrated': False,
                                   'public_wan_accepted': False,
                                   'allow_legacy_fallback': False}},
            CONSENSUS: {'runtime_implemented': False, 'work_profile_qualified': False,
                        'production_candidate': False, 'production_consensus_activation': False,
                        'public_testnet_ready': False, 'release_ready': False,
                        'active_consensus_implementation': None},
            DEVNET: {'production_activation': False, 'max_transaction_bytes': 2048,
                     'max_block_bytes': 1048576},
            BOUNDARY: {'consensus': {'production_candidate': False,
                                    'production_consensus_activation': False,
                                    'active_implementation': None}},
        }
        for name, obj in self.configs.items():
            self.put(name, json.dumps(obj).encode())
        for paths in GATES.values():
            for path in paths:
                if path not in self.configs:
                    self.put(path, b'research source only')

    def put(self, path, data):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    def mutate(self, path, *keys, value=True):
        data = deepcopy(self.configs[path])
        item = data
        for key in keys[:-1]:
            item = item[key]
        item[keys[-1]] = value
        self.put(path, json.dumps(data).encode())

    def refused(self):
        with self.assertRaises(UnsafePromotion):
            inspect(self.root)

    def test_hold_is_not_pq_success(self):
        report = inspect(self.root)
        self.assertEqual(report['status'], 'HOLD')
        self.assertFalse(report['whole_chain_pq_qualified'])
        self.assertEqual(set(report['gates']), set(GATES))
        self.assertTrue(all(x['status'] == 'UNQUALIFIED' for x in report['gates'].values()))

    def test_classical_fallback_refused(self):
        self.mutate(CONFIG, 'allow_classical_fallback')
        self.refused()

    def test_production_activation_refused(self):
        self.mutate(BOUNDARY, 'consensus', 'production_consensus_activation')
        self.refused()

    def test_corrupt_independent_qualification_refused(self):
        self.mutate(CORPUS, 'assertions', 'independent_accepted')
        self.refused()

    def test_quantum_hardness_claim_refused(self):
        self.mutate(CORPUS, 'assertions', 'quantum_pon_hardness_qualified')
        self.refused()

    def test_rollback_claim_refused(self):
        self.mutate(CORPUS, 'assertions', 'physical_rollback_resistant')
        self.refused()

    def test_hepta_final_use_claim_refused(self):
        self.mutate(CORPUS, 'assertions', 'hepta_final_use_integrated')
        self.refused()

    def test_pq_128_guest_promotion_refused(self):
        self.put(PROOF_MANIFEST,
                 b'{"pq_128_security_qualified":true,"production_consensus_activation":false}')
        self.refused()

    def test_missing_proof_relation_refused(self):
        (self.root / GATES['proof_pq128'][0]).unlink()
        self.refused()

    def test_source_reader_helper_cannot_disappear(self):
        (self.root / 'scripts/ci/pq_source_reader.py').unlink()
        self.refused()

    def test_missing_authority_surface_inventory_refused(self):
        (self.root / 'scripts/ci/pq_authority_surface_scan.py').unlink()
        self.refused()

    def test_missing_pq_hepta_verifier_refused(self):
        (self.root / 'trillionnium/crates/trnm-research-protocol/src/hepta_handoff/pq.rs').unlink()
        self.refused()

    def test_missing_external_rollback_oracle_refused(self):
        (self.root / 'scripts/ci/pq_external_rollback_oracle.py').unlink()
        self.refused()

    def test_native_witness_and_live_admission_sources_cannot_disappear(self):
        for path in (
            'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/live_admission_tests.rs',
            'trillionnium/crates/trnm-pon-node/src/pq_rollback_witness.rs',
            'trillionnium/crates/trnm-pon-node/src/pq_rollback_witness/tests.rs',
            'trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness.rs',
            'trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness/tests.rs',
            'docs/security/PQ_NETWORK_DURABLE_WITNESS_V1.md',
        ):
            with self.subTest(path=path):
                original = (self.root / path).read_bytes()
                (self.root / path).unlink()
                self.refused()
                self.put(path, original)

    def test_missing_quantum_daa_model_refused(self):
        (self.root / 'scripts/ci/pq_quantum_daa_scenarios.py').unlink()
        self.refused()

    def test_history_storage_and_rehearsal_owner_paths_cannot_disappear(self):
        for name in (
            'trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs',
            'trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs',
            'trillionnium/crates/trnm-data-availability/src/cell/closure.rs',
            'trillionnium/crates/trnm-data-availability/src/cell/release.rs',
            'trillionnium/crates/trnm-pon-node/src/store/storage_service.rs',
            'trillionnium/crates/trnm-service-settlement/src/native_budget.rs',
            'trillionnium/crates/trnm-data-availability/src/cell/retention.rs',
            'trillionnium/crates/trnm-pon-node/src/store/authenticated_migration/growth_rehearsal.rs',
        ):
            with self.subTest(path=name):
                path = self.root / name
                data = path.read_bytes()
                path.unlink()
                self.refused()
                path.write_bytes(data)
        self.assertFalse(inspect(self.root)['whole_chain_pq_qualified'])

    def test_duplicate_json_keys_refused(self):
        self.put(DEVNET, b'{"production_activation":false,"production_activation":false}')
        self.refused()

    def test_nonfinite_and_nonstandard_json_numbers_refused(self):
        # Unused configuration fields must not launder invalid JSON into HOLD.
        # Both Python extensions (NaN/Infinity) and exponent overflow (1e999)
        # otherwise deserialize successfully and look like valid research data.
        original = json.dumps(self.configs[CONFIG]).encode()
        self.assertTrue(original.endswith(b'}'))
        for literal in (b'NaN', b'Infinity', b'-Infinity', b'1e999', b'-1e999'):
            with self.subTest(literal=literal):
                self.put(CONFIG, original[:-1] + b',"untrusted_probe":' + literal + b'}')
                self.refused()

    def test_symlinked_checkout_root_refused(self):
        # The previous leaf-only check returned HOLD for this source-tree alias.
        alias = self.root.parent / (self.root.name + '-root-alias')
        alias.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(alias.unlink)
        with self.assertRaisesRegex(UnsafePromotion, 'symlinked repository root/ancestor'):
            inspect(alias)
        # The real pinned test tree remains eligible only for the HOLD verdict.
        self.assertEqual(inspect(self.root)['status'], 'HOLD')

    def test_symlinked_checkout_ancestor_refused(self):
        # A final checkout component can be ordinary even when its parent is
        # a symlink. The leaf-only check also accepted this redirection.
        ancestor = self.root.parent / (self.root.name + '-parent-alias')
        ancestor.symlink_to(self.root.parent, target_is_directory=True)
        self.addCleanup(ancestor.unlink)
        nested_root = ancestor / self.root.name
        self.assertFalse(nested_root.is_symlink())
        with self.assertRaisesRegex(UnsafePromotion, 'symlinked repository root/ancestor'):
            inspect(nested_root)

    def test_missing_or_non_directory_checkout_root_refused(self):
        with self.assertRaisesRegex(UnsafePromotion, 'missing or unreadable repository root'):
            inspect(self.root / 'absent-checkout')
        with self.assertRaisesRegex(UnsafePromotion, 'non-directory repository root'):
            inspect(self.root / CONFIG)

    def test_symlink_source_refused(self):
        path = self.root / GATES['authorization'][0]
        path.unlink()
        path.symlink_to(self.root / CONSENSUS)
        self.refused()

    def test_unbounded_or_unaccepted_candidate_refused(self):
        self.mutate(CONFIG, 'candidate_limits_for_analysis_only',
                    'evaluated_for_network_or_security')
        self.refused()


if __name__ == '__main__':
    unittest.main()
