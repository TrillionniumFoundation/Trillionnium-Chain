"""Private framing and source-binding controls, not model execution evidence."""
import hashlib
import json
import socket
import sys
import types
import unittest
from pathlib import Path

import llm_neural_read_worker as worker
import llm_python_runtime_contract as contract


class NeuralReadFramingTests(unittest.TestCase):
    def request(self, raw):
        sender, receiver = socket.socketpair()
        with sender, receiver:
            sender.sendall(raw)
            sender.shutdown(socket.SHUT_WR)
            return worker.read_request(receiver)

    def test_real_socket_binds_exact_raw_bytes_and_has_no_expected_label(self):
        value = dict(schema='hepta-smollm-inference-input-v1', request_id='next-task-1', prompt='Actual query')
        raw = json.dumps(value).encode()
        self.assertEqual(self.request(raw+b'\n'), (value, hashlib.sha256(raw).hexdigest()))
        with self.assertRaisesRegex(ValueError, 'NEURAL_READ_REQUEST'):
            self.request(json.dumps(dict(value, expected_output='answer')).encode()+b'\n')

    def test_partial_duplicate_oversized_and_multiple_frames_are_rejected(self):
        for raw in (b'', b'{}', b'{}\n{}\n', b'{}\ntrailing', b'x'*8193+b'\n',
                    b'{"schema":"bad","schema":"hepta-smollm-inference-input-v1"}\n'):
            with self.subTest(raw=raw[:40]), self.assertRaises(ValueError):
                self.request(raw)

    def test_exact_stop_is_not_a_query_or_a_coerced_number(self):
        raw = json.dumps(dict(schema=worker.SCHEMA, stop=True)).encode()
        self.assertEqual(self.request(raw+b'\n'), (None, hashlib.sha256(raw).hexdigest()))
        for value in (dict(schema=worker.SCHEMA, stop=1), dict(schema=worker.SCHEMA, stop=False),
                      dict(schema=worker.SCHEMA, stop=True, prompt='extra'), None, []):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.request(json.dumps(value).encode()+b'\n')

    def test_frozen_action_vocabulary_rejects_aliases_order_and_extra_fields(self):
        actions = [dict(action_id='action-a', completion='no'), dict(action_id='action-b', completion='yes')]
        self.assertEqual(worker.action_profile(actions), actions)
        for value in ([], actions[::-1], [actions[0], actions[0]],
                      [actions[0], dict(action_id='action-b', completion='no')],
                      [dict(actions[0], expected_for_current_query=True)],
                      [dict(action_id='action-a', completion='x'*65)]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                worker.action_profile(value)



class NeuralReadSourceSetTests(unittest.TestCase):
    """Actual file/guard consumer controls; no independently trusted model snapshot."""

    # Exact source names required by Hepta's SmolLmNeuralReadConfigV1.
    HOST_SOURCE_PATHS = (
        'formal/pon-nakamoto-v1/contract_wire.py',
        'config/pon/devnet-v1.json',
        'config/pon/ledger-v1.json',
        'formal/pon-nakamoto-v1/llm_adapter_contract.py',
        'scripts/llm_base_material.py',
        'scripts/llm_inherited_runtime.py',
        'scripts/llm_neural_read_worker.py',
        'scripts/llm_parent_material.py',
        'scripts/llm_python_runtime_contract.py',
        'scripts/llm_runtime_pilot.py',
        'config/pon/model-family-smollm2-135m-v1.json',
        'config/pon/model-family-v1.json',
        'config/pon/work-profile-v1.json',
    )

    def setUp(self):
        self.original_meta_path = list(sys.meta_path)
        self.had_runtime = hasattr(worker, 'python_runtime')
        self.original_runtime = getattr(worker, 'python_runtime', None)
        worker.python_runtime = contract
        root = Path(worker.__file__).resolve().parents[1]
        self.pins = {str(root / relative): contract.file_digest(root / relative)[0]
                     for relative in self.HOST_SOURCE_PATHS}
        self.assertEqual(len(self.pins), 13)
        # Observe this test interpreter's actual loaded files solely to exercise
        # Ready's full consistency checker, not to provision a production root.
        paths = {str(Path(module.__file__).resolve()) for module in tuple(sys.modules.values())
                 if type(getattr(module, '__file__', None)) is str}
        for line in Path('/proc/self/maps').read_text().splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) == 6 and 'x' in fields[1] and fields[5].startswith('/'):
                paths.add(str(Path(fields[5]).resolve()))
        self.value = {'files': {path: contract.file_digest(path)[0]
                               for path in paths if path not in self.pins}}
        self.args = types.SimpleNamespace(runtime_contract=self.value)

    def tearDown(self):
        sys.meta_path[:] = self.original_meta_path
        if self.had_runtime:
            worker.python_runtime = self.original_runtime
        else:
            del worker.python_runtime

    def test_ready_uses_all_thirteen_host_sources_and_the_installed_guard(self):
        expected = dict(self.pins)
        worker._install_runtime_guard(self.args, self.pins)
        self.assertEqual(self.args.runtime_source_pins, expected)
        self.assertIsNot(self.args.runtime_source_pins, self.pins)
        self.assertIn(self.args.runtime_import_guard, sys.meta_path)
        self.assertEqual(self.args.runtime_import_guard.files, dict(self.value['files'], **expected))
        self.pins.clear()
        worker._verify_runtime_ready(self.args)
        self.assertEqual(self.args.runtime_source_pins, expected)

    def test_ready_rejects_eight_python_subset_and_each_omitted_source(self):
        worker._install_runtime_guard(self.args, self.pins)
        python_only = {path: pin for path, pin in self.pins.items() if path.endswith('.py')}
        self.assertEqual(len(python_only), 8)
        cases = [python_only] + [{path: pin for path, pin in self.pins.items() if path != omitted}
                                for omitted in self.pins]
        for supplied in cases:
            with self.subTest(sources=sorted(supplied)):
                self.args.runtime_source_pins = supplied
                with self.assertRaisesRegex(ValueError, 'IMPORT_GUARD_IDENTITY'):
                    worker._verify_runtime_ready(self.args)
        self.args.runtime_source_pins = dict(self.pins)
        worker._verify_runtime_ready(self.args)

    def test_every_host_source_pin_is_validated_before_guard_installation(self):
        for path in self.pins:
            supplied = dict(self.pins)
            supplied[path] = '00' * 32
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'SOURCE_BYTE_DRIFT'):
                worker._install_runtime_guard(self.args, supplied)
            self.assertEqual(sys.meta_path, self.original_meta_path)
            self.assertFalse(hasattr(self.args, 'runtime_import_guard'))
        with self.assertRaisesRegex(ValueError, 'SOURCE_BOUND'):
            worker._install_runtime_guard(self.args, list(self.pins.items()))

    def test_ready_rejects_changed_pin_and_replacement_guard(self):
        worker._install_runtime_guard(self.args, self.pins)
        retained = dict(self.args.runtime_source_pins)
        self.args.runtime_source_pins[next(iter(retained))] = '00' * 32
        with self.assertRaisesRegex(ValueError, 'IMPORT_GUARD_IDENTITY'):
            worker._verify_runtime_ready(self.args)
        self.args.runtime_source_pins = retained
        installed = self.args.runtime_import_guard
        self.args.runtime_import_guard = contract.PinnedImports(dict(installed.files))
        with self.assertRaisesRegex(ValueError, 'IMPORT_GUARD_IDENTITY'):
            worker._verify_runtime_ready(self.args)
        self.args.runtime_import_guard = installed
        worker._verify_runtime_ready(self.args)


if __name__ == '__main__':
    unittest.main()
