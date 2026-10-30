#!/usr/bin/env python3
"""Finite original-ledger handoff controls; no trusted loader or native evidence."""
import ast
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'scripts/ci'))
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1'))
import run_pon_identity_churn as collector
import run_pon_native_io_component as component


class OriginalOwnerHandoffTests(unittest.TestCase):
    def test_writer_module_has_only_standard_library_imports(self):
        origin = Path(sys.modules[collector.V2Writer.__module__].__file__)
        self.assertEqual(origin.name, 'pon_identity_outer_owner.py')
        imports = [node for node in ast.parse(origin.read_text()).body
                   if isinstance(node, (ast.Import, ast.ImportFrom))]
        names = {alias.name.split('.')[0] for node in imports if isinstance(node, ast.Import)
                 for alias in node.names}
        names |= {node.module.split('.')[0] for node in imports if isinstance(node, ast.ImportFrom)}
        self.assertLessEqual(names, sys.stdlib_module_names | {'__future__'})
        self.assertIs(component.V2Writer, collector.V2Writer)

    def test_same_live_writer_keeps_all_prior_bytes_and_reservations(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            writer = collector.V2Writer(output)
            try:
                writer.chunks('observed-input.data', [b'owned bytes'], writer.reserve('outer', 11), exact_bytes=11)
                token = writer.reserve('outer', 16384)
                before = dict(writer.used), dict(writer.held), writer.fd
                io = collector.CollectorIO(output, 'v2', writer=writer)
                self.assertIs(io.writer, writer)
                self.assertEqual((writer.used, writer.held, writer.fd), before)
                io.json(output/'observation.json', {'qualification':False})
                self.assertEqual(writer.used['outer'], 11 + (output/'observation.json').stat().st_size)
                self.assertEqual(writer.held['outer'], 16384)
                self.assertTrue(token[2])
                self.assertIsNone(writer.failure)
            finally:
                writer.close()

    def test_narrow_prior_reservation_refuses_before_any_output_or_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            writer = collector.V2Writer(output, limits=dict(outer=7, terminal=4096, binary=128, inventory=128))
            try:
                first = writer.reserve('outer', 7)
                with self.assertRaisesRegex(ValueError, 'WRITE_BUCKET_CAP'):
                    writer.reserve('outer', 1)
                self.assertEqual(writer.held['outer'], 7)
                self.assertEqual(writer.used['outer'], 0)
                self.assertTrue(first[2])
                first_error = writer.failure
                with self.assertRaisesRegex(ValueError, 'LIVE_MATCHING'):
                    collector.CollectorIO(output, 'v2', writer=writer)
                self.assertEqual(writer.failure, first_error)
                self.assertEqual(list(output.iterdir()), [])
            finally:
                writer.close()

    def test_wrong_root_closed_owner_and_wrong_version_never_fall_back(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root/'out'; other = root/'other'
            output.mkdir(); other.mkdir(); writer = collector.V2Writer(output)
            try:
                fd = writer.fd
                with self.assertRaisesRegex(ValueError, 'LIVE_MATCHING'):
                    collector.CollectorIO(other, 'v2', writer=writer)
                with self.assertRaisesRegex(ValueError, 'EXACT_V2'):
                    collector.CollectorIO(output, 'v1', writer=writer)
                self.assertEqual(writer.fd, fd)
                self.assertEqual(list(other.iterdir()), [])
                writer.close()
                with self.assertRaisesRegex(ValueError, 'LIVE_MATCHING'):
                    collector.CollectorIO(output, 'v2', writer=writer)
            finally:
                writer.close()

    def test_visible_root_replacement_refuses_same_path_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root/'out'; output.mkdir()
            writer = collector.V2Writer(output)
            try:
                output.rename(root/'original'); output.mkdir()
                with self.assertRaisesRegex(ValueError, 'DIRECTORY_CHANGED'):
                    collector.CollectorIO(output, 'v2', writer=writer)
                self.assertEqual(list(output.iterdir()), [])
                self.assertEqual(os.fstat(writer.fd).st_ino, (root/'original').stat().st_ino)
            finally:
                writer.close()

    def test_reexecuting_identical_owner_bytes_does_not_create_same_class(self):
        origin = Path(sys.modules[collector.V2Writer.__module__].__file__)
        self.assertEqual(origin.name, 'pon_identity_outer_owner.py')
        spec = importlib.util.spec_from_file_location('test_only_unapproved_owner_copy', origin)
        duplicate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(duplicate)
        self.assertIsNot(duplicate.V2Writer, collector.V2Writer)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory); writer = duplicate.V2Writer(output)
            try:
                with self.assertRaisesRegex(ValueError, 'EXACT_V2'):
                    collector.CollectorIO(output, 'v2', writer=writer)
                self.assertEqual(list(output.iterdir()), [])
            finally:
                writer.close()

    def test_public_p1_reuses_exact_io_and_keeps_unimplemented_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root/'out'; output.mkdir()
            writer = collector.V2Writer(output)
            io = collector.CollectorIO(output, 'v2', writer=writer)
            writer.chunks('observed-input.data', [b'original'], writer.reserve('outer', 8), exact_bytes=8)
            reservation = writer.reserve('outer', 16384)
            args = SimpleNamespace(profile='v2', target_dir=root/'target', expected_head='a'*40,
                                   expected_tree='b'*40, collection_seconds=6000)
            with patch.object(collector, 'environment', return_value={}), \
                 patch.object(collector.CollectorIO, '__init__', side_effect=AssertionError('second IO forbidden')), \
                 patch.object(collector, 'run_bounded') as native, \
                 patch.object(collector, 'source_snapshot') as source:
                self.assertFalse(collector.prepare(args, output, io=io))
                native.assert_not_called(); source.assert_not_called()
            self.assertIs(io.writer, writer)
            self.assertEqual((output/'observed-input.data').read_bytes(), b'original')
            self.assertTrue(reservation[2]); self.assertEqual(writer.held['outer'], 16384)
            import json
            prepared = json.loads((output/'prepared.json').read_bytes())
            self.assertIs(prepared['prepared'], False)
            self.assertIs(prepared['selector_executed'], False)
            self.assertEqual(prepared['failure'], 'V2_FULL_IO_BOUNDARY_NOT_IMPLEMENTED')
            self.assertIsNone(writer.fd)
            self.assertFalse(collector.V2_FULL_IO_BOUNDARY_IMPLEMENTED)

    def test_public_p1_rejects_other_io_before_source_or_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); output = root/'out'; other = root/'other'
            output.mkdir(); other.mkdir(); writer = collector.V2Writer(other)
            io = collector.CollectorIO(other, 'v2', writer=writer)
            args = SimpleNamespace(profile='v2', target_dir=root/'target', expected_head='a'*40,
                                   expected_tree='b'*40, collection_seconds=6000)
            try:
                with patch.object(collector, 'environment', return_value={}), \
                     patch.object(collector, 'run_bounded') as native, \
                     patch.object(collector, 'source_snapshot') as source, \
                     self.assertRaisesRegex(ValueError, 'EXACT_PREPARATION_IO'):
                    collector.prepare(args, output, io=io)
                native.assert_not_called(); source.assert_not_called()
                self.assertEqual(list(output.iterdir()), [])
                self.assertEqual(writer.used['outer'], 0)
            finally:
                writer.close()

    def test_public_p3_inherits_same_live_writer_and_refuses_invalid_target(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            writer = collector.V2Writer(output)
            try:
                writer.reserve('outer', 16384)
                io = component.ComponentIO(output, writer=writer)
                self.assertIs(io.writer, writer)
                args = SimpleNamespace(target_dir=output/'inside')
                with patch.object(component, 'environment', return_value={}), \
                     patch.object(component.ComponentIO, '__init__', side_effect=AssertionError('second IO forbidden')), \
                     patch.object(component, 'source_snapshot') as source, \
                     patch.object(component, 'run_bounded') as native, \
                     self.assertRaisesRegex(ValueError, 'ISOLATED_FRESH_TARGET'):
                    component.prepare(args, io)
                source.assert_not_called(); native.assert_not_called()
                self.assertEqual(writer.held['outer'], 16384)
                self.assertTrue(all(flag is False for flag in component.component_flags().values()))
                self.assertIs(io.writer, writer)
                self.assertEqual(list(output.iterdir()), [])
            finally:
                writer.close()


if __name__ == '__main__':
    unittest.main()
