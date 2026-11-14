"""Real memfd/SCM_RIGHTS/parser controls; no claim of model execution."""
import array
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import typing
import unittest
from unittest import mock

import llm_cell_sealed_worker_v1 as worker


def sealed(raw, *, immutable=True):
    fd = os.memfd_create('cell-sealed-control', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | 0x0008)
    os.write(fd, raw)
    os.fchmod(fd, 0o400)
    if immutable:
        fcntl.fcntl(fd, getattr(fcntl, 'F_ADD_SEALS', 1033), 0x0f)
    return fd


def descriptor(pins, layout='09' * 32):
    raw = b'CHB1' + bytes([1]) * 32 + struct.pack('>Q', 1)
    raw += bytes([2]) * 64 + bytes([3]) * 64 + bytes([4]) * 32 + bytes([5]) * 32
    raw += struct.pack('>QQ', 7, 2) + b'\x07fixture'
    for value in (bytes([6])*32, bytes([7])*32, bytes([8])*32, bytes.fromhex(layout),
                  bytes.fromhex(pins[worker.WORKER_PATH])):
        raw += value
    for path in (worker.WORKER_PATH, worker.SNAPSHOT_PATH):
        raw += struct.pack('>H', len(path)) + path.encode()
    return raw + bytes.fromhex(pins[worker.SNAPSHOT_PATH])


class SealedHandoffControls(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.fds = []
        self.addCleanup(self.close_fds)
        self.blobs = {('environment', p): b'bounded source/config parser fixture:' + p.encode()
                      for p in worker.ENVIRONMENT}
        self.blobs.update({('model', p): b'bounded model parser fixture:' + p.encode()
                           for p in worker.MODEL_FILES})
        pins = {p: worker.sha(raw) for (scope, p), raw in self.blobs.items() if scope == 'environment'}
        rows = []
        for (scope, path), raw in sorted(self.blobs.items()):
            role = 6
            if scope == 'model':
                if path == 'base/model.safetensors': role = 1
                elif path == 'adapter/artifact.safetensors': role = 4
                elif path.startswith('base/tokenizer') or path == 'base/special_tokens_map.json': role = 2
            rows.append(dict(scope=scope, path=path, role=role, bytes=len(raw), sha256=worker.sha(raw),
                sha512=hashlib.sha512(b'TRNM/Cell/PayloadContent/v2\0' + struct.pack('>Q', len(raw)) + raw).hexdigest()))
            self.fds.append(sealed(raw))
        wire = descriptor(pins)
        pin = hashlib.sha512(b'TRNM/Cell/HostSealedDualContext/v1\0' + wire).hexdigest()
        self.header = dict(schema=worker.HEADER_SCHEMA, descriptor=wire.hex(), descriptor_sha512=pin,
            worker=next(i for i, row in enumerate(rows) if row['path'] == worker.WORKER_PATH), files=rows,
            deadline_monotonic_ns=time.monotonic_ns() + 30 * 10**9,
            execution=dict(schema=worker.GRANT_SCHEMA, operation='01'*32, descriptor=pin,
                environment_pins=pins, max_snapshot_bytes=sum(len(x) for x in self.blobs.values()),
                runtime_rss_bytes=1024**3, python='/independently/pinned/python', python_sha256='ab'*32,
                output=self.root.name, threads=1,
                material_profile=worker.CURRENT_MATERIAL,
                parent=dict(generation=7, operation_id='original-parent', contract='09'*32,
                            adapter='10'*32, file_sha256='07'*32),
                requests=[dict(request_id='first', prompt='A real input'),
                          dict(request_id='next', prompt='A different next input')]))
        self.bootstrap = pins[worker.BOOTSTRAP_PATH]

    def replace_blob(self, scope, path, raw):
        index = next(i for i, row in enumerate(self.header['files'])
                     if (row['scope'], row['path']) == (scope, path))
        os.close(self.fds[index])
        self.fds[index] = sealed(raw)
        self.blobs[scope, path] = raw
        row = self.header['files'][index]
        row.update(bytes=len(raw), sha256=worker.sha(raw), sha512=hashlib.sha512(
            b'TRNM/Cell/PayloadContent/v2\0' + struct.pack('>Q', len(raw)) + raw).hexdigest())
        if scope == 'environment':
            self.header['execution']['environment_pins'][path] = worker.sha(raw)
        self.header['execution']['max_snapshot_bytes'] = sum(len(x) for x in self.blobs.values())
        wire = descriptor(self.header['execution']['environment_pins'], self.header['execution']['parent']['contract'])
        pin = hashlib.sha512(b'TRNM/Cell/HostSealedDualContext/v1\0' + wire).hexdigest()
        self.header.update(descriptor=wire.hex(), descriptor_sha512=pin)
        self.header['execution']['descriptor'] = pin
        self.bootstrap = self.header['execution']['environment_pins'][worker.BOOTSTRAP_PATH]

    def close_fds(self):
        for fd in self.fds:
            os.close(fd)

    def inputs(self, header=None, fds=None):
        return worker.SealedInputs(header or self.header, self.fds if fds is None else fds, self.bootstrap)

    def test_complete_pair_reads_same_sealed_bytes_without_any_model_path(self):
        inputs = self.inputs()
        for key, raw in self.blobs.items():
            self.assertEqual(inputs.raw(*key), raw)
        self.assertEqual(list(Path(self.root.name).iterdir()), [])
        with self.assertRaises(OSError):
            os.pwrite(self.fds[0], b'changed', 0)

    def test_missing_scope_or_swapped_role_refuses_the_complete_admission(self):
        for change in ('omit', 'swap', 'role'):
            header = copy.deepcopy(self.header)
            if change == 'omit': header['files'].pop()
            elif change == 'swap': header['files'][0]['scope'] = 'model'
            else: header['files'][0]['role'] = 7
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.inputs(header)

    def test_kernel_write_seals_and_cloexec_are_required(self):
        for immutable in (False, True):
            changed = sealed(self.blobs[('environment', self.header['files'][0]['path'])], immutable=immutable)
            try:
                if immutable: fcntl.fcntl(changed, fcntl.F_SETFD, 0)
                fds = list(self.fds); fds[0] = changed
                with self.subTest(immutable=immutable), self.assertRaisesRegex(ValueError, 'IMMUTABLE_FD'):
                    self.inputs(fds=fds)
            finally:
                os.close(changed)

    def test_same_length_substituted_fd_fails_actual_content_digest(self):
        row = self.header['files'][0]
        changed = sealed(b'x' * row['bytes'])
        try:
            fds = list(self.fds); fds[0] = changed
            with self.assertRaisesRegex(ValueError, 'FILE_CONTENT'):
                self.inputs(fds=fds)
        finally:
            os.close(changed)

    def test_independent_environment_pin_cannot_follow_supplied_new_bytes(self):
        header = copy.deepcopy(self.header)
        header['files'][0]['sha256'] = 'ff' * 32
        with self.assertRaisesRegex(ValueError, 'ENVIRONMENT_PIN'):
            self.inputs(header)

    def test_both_sha256_and_stronger_payload_domain_are_checked(self):
        header = copy.deepcopy(self.header)
        header['files'][0]['sha512'] = 'ff' * 64
        with self.assertRaisesRegex(ValueError, 'FILE_CONTENT'):
            self.inputs(header)

    def test_expiry_is_checked_before_input_use_and_is_not_reset(self):
        inputs = self.inputs()
        original = inputs.deadline
        inputs.deadline = time.monotonic_ns() - 1
        with self.assertRaisesRegex(ValueError, 'ORIGINAL_DEADLINE'):
            inputs.raw('model', 'base/model.safetensors')
        self.assertEqual(self.header['deadline_monotonic_ns'], original)
        header = copy.deepcopy(self.header)
        header['deadline_monotonic_ns'] = time.monotonic_ns() - 1
        with self.assertRaisesRegex(ValueError, 'ORIGINAL_DEADLINE'):
            self.inputs(header)

    def test_complete_snapshot_ram_and_original_generation_refuse_before_read(self):
        for change in ('bytes', 'generation', 'request', 'extra'):
            header = copy.deepcopy(self.header)
            if change == 'bytes': header['execution']['max_snapshot_bytes'] -= 1
            elif change == 'generation': header['execution']['parent']['generation'] += 1
            elif change == 'request': header['execution']['requests'][1]['request_id'] = 'first'
            else: header['execution']['requests'][0]['expected_output'] = 'not admitted'
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.inputs(header)

    def test_descriptor_bootstrap_and_owner_pin_cannot_be_replaced(self):
        for key in ('descriptor', 'descriptor_sha512'):
            header = copy.deepcopy(self.header)
            header[key] = '00' + header[key][2:]
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.inputs(header)
        with self.assertRaisesRegex(ValueError, 'WORKER_PROFILE_PIN'):
            worker.SealedInputs(self.header, self.fds, '00' * 32)

    def test_actual_scm_rights_keeps_seals_bytes_and_original_deadline(self):
        inputs = self.inputs()
        parent, child = socket.socketpair()
        errors = []
        def sender():
            try: worker.send_descriptors(parent, inputs)
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=sender)
        received = []
        try:
            thread.start()
            def exact(n):
                raw = bytearray()
                while len(raw) < n:
                    value = child.recv(n - len(raw))
                    self.assertTrue(value); raw.extend(value)
                return raw
            length = struct.unpack('>I', exact(4))[0]
            header = worker.decode(exact(length))
            for _ in self.fds:
                marker, ancillary, flags, _ = child.recvmsg(1, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
                self.assertEqual(len(ancillary), 1)
                level, kind, raw = ancillary[0]
                self.assertEqual((level, kind), (socket.SOL_SOCKET, socket.SCM_RIGHTS))
                values = array.array('i'); values.frombytes(raw); self.assertEqual(len(values), 1)
                received.extend(values)
                self.assertEqual(marker, b'F')
                self.assertEqual(flags & ~socket.MSG_CMSG_CLOEXEC, 0)
            actual = worker.SealedInputs(header, received, self.bootstrap)
            self.assertEqual(actual.deadline, inputs.deadline)
            self.assertEqual(actual.raw('model', 'base/model.safetensors'), self.blobs['model', 'base/model.safetensors'])
            thread.join(2)
            self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
        finally:
            parent.close(); child.close()
            for fd in received: os.close(fd)

    def test_unknown_file_and_metadata_role_never_open_ambient_payload(self):
        inputs = self.inputs()
        with self.assertRaisesRegex(ValueError, 'UNDECLARED_FILE'):
            inputs.raw('model', '/etc/passwd')
        with self.assertRaisesRegex(ValueError, 'FILE_READ_BOUND'):
            inputs.raw('model', 'base/model.safetensors', maximum=1)

    def test_original_modules_and_configurations_execute_only_same_admitted_fd_bytes(self):
        project = Path(os.environ.get('CELL_SEALED_TEST_PROJECT_ROOT',
                       str(Path(__file__).resolve().parents[1]))).resolve(strict=True)
        for path in (*worker.MODULES.values(), *worker.CONFIGS):
            self.replace_blob('environment', path, (project / path).read_bytes())
        inputs = self.inputs()
        virtual = Path(self.root.name) / 'sealed-source-names'
        for relative in (*worker.MODULES.values(), *worker.CONFIGS):
            path = virtual / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'raise RuntimeError("ambient substitution must not execute")')
        sources = worker.ProjectSources(inputs, virtual)
        self.assertTrue(all(name not in sys.modules for name in worker.MODULES))
        prior_path = list(sys.path)
        sys.meta_path.insert(0, sources)
        try:
            with mock.patch.dict(os.environ, {'TRNM_PON_EVALUATION_POLICY': 'legacy-first-two-v3'}):
                runtime = __import__('llm_runtime_pilot')
                contract = runtime.contract_module()
                parent = __import__('llm_parent_material')
                inherited = __import__('llm_inherited_runtime')
                original = __import__('llm_neural_read_worker')
                reference_spec = importlib.util.spec_from_file_location('_ordinary_contract_control',
                    project / 'formal/pon-nakamoto-v1/contract_wire.py')
                reference = importlib.util.module_from_spec(reference_spec)
                reference_spec.loader.exec_module(reference)
            self.assertEqual(sys.modules['contract_wire'].PARAMETER_HASH, reference.PARAMETER_HASH)
            self.assertEqual(runtime.file_sha(runtime.__file__),
                inputs.grant['environment_pins'][worker.MODULES['llm_runtime_pilot']])
            self.assertEqual(runtime.read_json(runtime.FAMILY_PATH),
                worker.decode((project / 'config/pon/model-family-smollm2-135m-v1.json').read_bytes()))
            self.assertTrue(callable(contract.verify_target_contract))
            self.assertTrue(callable(parent.factor_bytes))
            self.assertTrue(callable(inherited.load_factors))
            self.assertEqual(original.action_profile([{'action_id':'no','completion':'no'}]),
                             [{'action_id':'no','completion':'no'}])
            self.assertIs(runtime.__loader__, sources)
            with self.assertRaisesRegex(ValueError, 'UNDECLARED_SOURCE_OR_CONFIG_PATH'):
                runtime.file_sha('/undeclared/source.py')
            with self.assertRaisesRegex(ValueError, 'UNDECLARED_PROJECT_MODULE'):
                sources.find_spec('llm_not_in_original_closure')
            with self.assertRaisesRegex(ValueError, 'CONTRACT_CONFIG_SCOPE'):
                sys.modules['contract_wire'].read_config('config/pon/evaluation-round-v1.json')
        finally:
            sys.meta_path.remove(sources)
            sys.path[:] = prior_path
            for name in worker.MODULES:
                sys.modules.pop(name, None)

    def test_project_source_compiler_preserves_original_annotation_semantics(self):
        project = Path(os.environ.get('CELL_SEALED_TEST_PROJECT_ROOT',
                       str(Path(__file__).resolve().parents[1]))).resolve(strict=True)
        relative = worker.MODULES['llm_python_runtime_contract']
        original = (project / relative).read_bytes()
        self.replace_blob('environment', relative, original)
        inputs = self.inputs()
        sources = worker.ProjectSources(inputs, Path(self.root.name) / 'original-sources')
        helper = types.ModuleType('llm_python_runtime_contract')
        sources.exec_module(helper)
        self.assertEqual(sources.file_sha(helper.__file__), worker.sha(original))
        # Use the actual original helper's second compilation boundary. No
        # Torch substitute is imported or represented as a model execution.
        for explicit_future in (False, True):
            with self.subTest(explicit_future=explicit_future):
                raw = b'from typing import Optional\nvalue: Optional[str] = None\n'
                if explicit_future:
                    raw = b'from __future__ import annotations\n' + raw
                path = Path(self.root.name) / ('dependency-' + str(explicit_future) + '.py')
                path.write_bytes(raw)
                dependency = types.ModuleType('_cell_original_annotations_' + str(explicit_future))
                loader = helper.PinnedPythonSource(dependency.__name__, str(path), worker.sha(raw))
                loader.exec_module(dependency)
                expected = 'Optional[str]' if explicit_future else typing.Optional[str]
                self.assertEqual(dependency.__annotations__['value'], expected)

    def _failed_original_supervisor(self, after_handoff):
        project = Path(os.environ.get('CELL_SEALED_TEST_PROJECT_ROOT',
                       str(Path(__file__).resolve().parents[1]))).resolve(strict=True)
        if after_handoff:
            bootstrap = Path(__file__).with_name('cell_sealed_bootstrap_v1.py').read_bytes()
            failing_entry = b'def entry(header, fds, mode, bootstrap_sha256):\n    raise SystemExit(7)\n'
            self.replace_blob('environment', worker.WORKER_PATH, failing_entry)
        else:
            bootstrap = b'raise SystemExit(7)\n'
        self.replace_blob('environment', worker.BOOTSTRAP_PATH, bootstrap)
        self.header['execution']['python'] = str(Path(sys.executable).resolve(strict=True))
        self.header['execution']['python_sha256'] = worker.sha(Path(sys.executable).read_bytes())
        self.header['deadline_monotonic_ns'] = time.monotonic_ns() + 6 * 10**9
        inputs = self.inputs()
        deadline = inputs.deadline
        prior_path = list(sys.path)
        prior_modules = {name: sys.modules.get(name) for name in worker.MODULES}
        directory_fd = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        spec = importlib.util.spec_from_file_location('_cell_original_supervisor_control',
            project / 'scripts/llm_runtime_pilot.py')
        original_runtime = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = original_runtime
        sys.path.insert(0, str(project / 'scripts'))
        try:
            spec.loader.exec_module(original_runtime)
            state = types.SimpleNamespace(runtime=original_runtime,
                original_worker=types.SimpleNamespace(SCHEMA='hepta-smollm-neural-read-worker-v2'))
            started = time.monotonic()
            with self.assertRaisesRegex(ValueError, 'ORIGINAL_WAIT4_AND_NEXT_USE'):
                worker.supervisor(inputs, state)
            elapsed = time.monotonic() - started
            result = worker.read_observation(Path(self.root.name) / 'next-use-result.json')
            self.assertTrue(result['connector_complete'])
            self.assertEqual(result['observations'], 0)
            self.assertTrue(result['failures'])
            self.assertEqual(result['supervisor']['outcome'], 'failed')
            self.assertEqual(result['supervisor']['exit_code'], 7)
            self.assertTrue(result['supervisor']['waited_child_reaped'])
            self.assertTrue(result['supervisor']['owned_child_reap_resolved'])
            self.assertEqual(worker.read_observation(Path(self.root.name) / 'next-use-observations.json'), [])
            self.assertFalse((Path(self.root.name) / 'fd.sock').exists())
            self.assertFalse(any(t.name == 'sealed-research-original-requests' and t.is_alive()
                                 for t in threading.enumerate()))
            self.assertEqual(inputs.deadline, deadline)
            self.assertLess(elapsed, 3.0, 'connector kept waiting after the original failed child was reaped')
            self.assertLess(time.monotonic_ns(), deadline)
        finally:
            os.fchdir(directory_fd)
            os.close(directory_fd)
            sys.path[:] = prior_path
            sys.modules.pop(spec.name, None)
            for name, original in prior_modules.items():
                if original is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = original

    def test_failed_supervisor_cancels_connector_before_handshake(self):
        self._failed_original_supervisor(False)

    def test_failed_supervisor_cancels_ready_wait_after_sealed_handoff(self):
        self._failed_original_supervisor(True)

    def _virtual_runtime_fixture(self):
        # Small namespace fixtures exercise identity rejection, not Torch or a
        # model. Their source uses the actual original pinned Python loader.
        project = Path(os.environ.get('CELL_SEALED_TEST_PROJECT_ROOT',
                       str(Path(__file__).resolve().parents[1]))).resolve(strict=True)
        spec = importlib.util.spec_from_file_location('_cell_virtual_origin_helper',
            project / 'scripts/llm_python_runtime_contract.py')
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        root = Path(self.root.name) / 'virtual-runtime-fixture/torch'
        root.mkdir(parents=True)
        sources = {'torch': ('__init__.py', b'# independent pinned namespace fixture\n')}
        for child, cls, export in (('_ops', '_Ops', 'ops'), ('_classes', '_Classes', 'classes')):
            raw = ('import types\nclass ' + cls + '(types.ModuleType):\n'
                '    __file__ = "' + child + '.py"\n'
                '    def __init__(self):\n'
                '        super().__init__("torch.' + export + '")\n'
                + export + ' = ' + cls + '()\n').encode()
            sources['torch.' + child] = (child + '.py', raw)
        modules, pins = {}, {}
        for name, (filename, raw) in sources.items():
            path = root / filename
            path.write_bytes(raw)
            pins[str(path)] = worker.sha(raw)
            loader = helper.PinnedPythonSource(name, str(path), worker.sha(raw))
            spec = importlib.util.spec_from_loader(name, loader)
            module = importlib.util.module_from_spec(spec)
            loader.exec_module(module)
            modules[name] = module
        for child, export in (('_ops', 'ops'), ('_classes', 'classes')):
            owner = modules['torch.' + child]
            namespace = vars(owner)[export]
            vars(modules['torch'])[child] = owner
            vars(modules['torch'])[export] = namespace
            modules['torch.' + export] = namespace
        state = types.SimpleNamespace(helper=helper, snapshot={'files':pins},
                                      guard=types.SimpleNamespace(files=dict(pins)))
        return state, modules

    def test_runtime_virtual_namespace_requires_exact_pinned_singleton(self):
        state, modules = self._virtual_runtime_fixture()
        with mock.patch.dict(sys.modules, modules):
            for alias, owner in (('torch.ops', 'torch._ops'), ('torch.classes', 'torch._classes')):
                with self.subTest(alias=alias):
                    namespace = modules[alias]
                    self.assertEqual(worker.runtime_module_origin(state, alias, namespace),
                                     modules[owner].__file__)
                    clone = type(namespace)()
                    with mock.patch.dict(sys.modules, {alias:clone}):
                        with self.assertRaisesRegex(ValueError, 'VIRTUAL_MODULE_SINGLETON'):
                            worker.runtime_module_origin(state, alias, clone)
                    spoof = types.ModuleType(alias)
                    spoof.__file__ = type(namespace).__file__
                    subclass = type('SubstituteNamespace', (type(namespace),), {})
                    for changed in (spoof, subclass()):
                        with self.assertRaisesRegex(ValueError, 'VIRTUAL_MODULE_CLASS'):
                            worker.runtime_module_origin(state, alias, changed)
                    with mock.patch.object(namespace, '__file__', '/unrelated/physical.py'):
                        with self.assertRaisesRegex(ValueError, 'VIRTUAL_MODULE_SINGLETON'):
                            worker.runtime_module_origin(state, alias, namespace)
                    with mock.patch.dict(vars(modules['torch']), {alias.split('.')[1]:clone}):
                        with self.assertRaisesRegex(ValueError, 'VIRTUAL_MODULE_SINGLETON'):
                            worker.runtime_module_origin(state, alias, namespace)

    def test_runtime_virtual_namespace_refuses_source_or_loader_drift(self):
        state, modules = self._virtual_runtime_fixture()
        namespace, owner = modules['torch.ops'], modules['torch._ops']
        with mock.patch.dict(sys.modules, modules):
            path = Path(owner.__file__)
            raw = path.read_bytes()
            path.write_bytes(b'#' + raw[1:])
            try:
                with self.assertRaisesRegex(ValueError, 'VIRTUAL_MODULE_SOURCE_BYTES'):
                    worker.runtime_module_origin(state, 'torch.ops', namespace)
            finally:
                path.write_bytes(raw)
            for obj, field, value in ((owner.__loader__, 'expected', '00' * 32),
                    (owner.__loader__, 'name', 'torch.other'),
                    (owner.__spec__, 'name', 'torch.other'),
                    (owner.__spec__, 'origin', '/unrelated/source.py'),
                    (owner, '__loader__', object())):
                with self.subTest(field=field), mock.patch.object(obj, field, value):
                    with self.assertRaisesRegex(ValueError, 'VIRTUAL_MODULE_PINNED_LOADER'):
                        worker.runtime_module_origin(state, 'torch.ops', namespace)
            with mock.patch.dict(state.guard.files, {str(path):'00' * 32}):
                with self.assertRaisesRegex(ValueError, 'VIRTUAL_MODULE_PINNED_LOADER'):
                    worker.runtime_module_origin(state, 'torch.ops', namespace)
            cls = type(namespace)
            transplanted = types.FunctionType(cls.__init__.__code__, dict(vars(owner)),
                                             closure=cls.__init__.__closure__)
            with mock.patch.object(cls, '__init__', transplanted):
                with self.assertRaisesRegex(ValueError, 'VIRTUAL_MODULE_CLASS'):
                    worker.runtime_module_origin(state, 'torch.ops', namespace)

    def test_runtime_module_origin_refuses_other_relative_paths(self):
        state, modules = self._virtual_runtime_fixture()
        ordinary = types.ModuleType('ordinary')
        ordinary.__file__ = 'unknown.py'
        with self.assertRaisesRegex(ValueError, 'MODULE_ORIGIN'):
            worker.runtime_module_origin(state, 'ordinary', ordinary)
        with mock.patch.dict(sys.modules, modules):
            with self.assertRaisesRegex(ValueError, 'MODULE_ORIGIN'):
                worker.runtime_module_origin(state, 'torch.unapproved_alias', modules['torch.ops'])
            self.assertEqual(worker.runtime_module_origin(state, 'torch._ops', modules['torch._ops']),
                             modules['torch._ops'].__file__)

    def test_observation_publish_is_complete_before_visibility_and_cannot_replace(self):
        path = Path(self.root.name) / 'ready.json'
        payload = {'schema':worker.SCHEMA, 'actual':list(range(40))}
        link = os.link
        observed = []
        def inspect_before_link(source, destination, **kwargs):
            self.assertFalse(path.exists())
            observed.append(worker.read_observation(source))
            return link(source, destination, **kwargs)
        with mock.patch.object(worker.os, 'link', side_effect=inspect_before_link):
            worker.publish(path, payload)
        self.assertEqual(observed, [payload])
        self.assertEqual(worker.read_observation(path), payload)
        with self.assertRaises(FileExistsError):
            worker.publish(path, {'changed':True})
        self.assertEqual(worker.read_observation(path), payload)
        self.assertTrue(path.with_name('ready.json.pending').is_file())

    def test_unfinished_publication_remains_pending_without_successful_ready(self):
        path = Path(self.root.name) / 'ready.json'
        with mock.patch.object(worker.os, 'fsync', side_effect=OSError('injected durable write failure')):
            with self.assertRaisesRegex(OSError, 'durable write failure'):
                worker.publish(path, {'partial':True})
        self.assertFalse(path.exists())
        self.assertTrue(path.with_name('ready.json.pending').is_file())

    def test_explicit_material_bridge_uses_sealed_original_pair_and_complete_loaded_contract(self):
        project = Path(os.environ.get('CELL_SEALED_TEST_PROJECT_ROOT',
                       str(Path(__file__).resolve().parents[1]))).resolve(strict=True)
        fixtures = project / 'tests/fixtures/llm_material_runtime_bridge_v1'
        plan, target = (fixtures / 'historical_plan.json').read_bytes(), (fixtures / 'historical_target.json').read_bytes()
        self.header['execution']['material_profile'] = worker.BRIDGED_MATERIAL
        self.header['execution']['parent']['contract'] = 'c9b06f9a029a3257801844f89acb59b5f59f6a39087335af323f274e9152992f'
        self.header['files'].append(dict(scope='environment', path=worker.MATERIAL_PLAN_PATH, role=6))
        self.fds.append(sealed(plan))
        self.replace_blob('environment', worker.MATERIAL_PLAN_PATH, plan)
        for name in ('llm_runtime_pilot', 'llm_neural_read_worker'):
            self.replace_blob('environment', worker.MODULES[name], (project / worker.MODULES[name]).read_bytes())
        self.replace_blob('model', 'adapter/target-contract.json', target)
        inputs = self.inputs()
        sources = worker.ProjectSources(inputs, Path(self.root.name) / 'virtual')
        original = importlib.util.module_from_spec(sources.find_spec('llm_neural_read_worker'))
        sources.exec_module(original)
        state = types.SimpleNamespace(original_worker=original)
        pilot = dict(worker.decode(plan), runtime_source=original._EXECUTION_RUNTIME_SHA256)
        actual = worker.decode(target)
        actual['tokenizer']['behavior_contract'] = '5bd0bfea568f544a784a11cc9f162cb401d1c23b44e5951ff38388ef9fca441a'
        actual['numeric']['operator_contract'] = '42707d81b3af6343388afe865307522c13e56edebf8ce4e6c7ec25ac4dbd73c8'
        actual['registration']['target_admission'] = '5293fb3ad4d607c34089b6c2a1f14f6fa902db48df4501830bc36fc27630b6e8'
        result = worker.verify_loaded_material(inputs, state, pilot, actual, worker.decode(target))
        self.assertEqual(result['historical_runtime_source'], worker.decode(plan)['runtime_source'])
        self.assertEqual(result['execution_runtime_source'], original._EXECUTION_RUNTIME_SHA256)
        changed = copy.deepcopy(actual); changed['registration']['target_admission'] = '00' * 32
        with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_LOADED_CONTRACT'):
            worker.verify_loaded_material(inputs, state, pilot, changed, worker.decode(target))
        with self.assertRaisesRegex(ValueError, 'NEURAL_BRIDGE_CURRENT_PLAN'):
            worker.verify_loaded_material(inputs, state, dict(pilot, threads=1), actual, worker.decode(target))
        header = copy.deepcopy(self.header); header['execution']['material_profile'] = worker.CURRENT_MATERIAL
        with self.assertRaisesRegex(ValueError, 'COMPLETE_ENVIRONMENT_PINS'):
            self.inputs(header)
        inputs.grant['material_profile'] = worker.CURRENT_MATERIAL
        with self.assertRaisesRegex(ValueError, 'ORIGINAL_RUNTIME_BINDING'):
            worker.verify_loaded_material(inputs, state, pilot, actual, worker.decode(target))

    def bootstrap_control(self, fault):
        raw = b'def entry(header, fds, mode, pin):\n print("BOOTSTRAP_EXACT_SEALED_CONTROL", len(fds))\n'
        self.replace_blob('environment', worker.WORKER_PATH, raw)
        inputs = self.inputs()
        index = self.header['worker']
        replacement = None
        if fault is not None:
            replacement = sealed(b'x' * len(raw) if fault == 'bytes' else raw, immutable=fault != 'unsealed')
            values = list(inputs.fds); values[index] = replacement; inputs.fds = tuple(values)
        parent, child = socket.socketpair()
        process = None
        try:
            bootstrap = (Path(__file__).with_name('cell_sealed_bootstrap_v1.py')).read_bytes()
            command = [sys.executable, '-I', '-S', '-B', '-c', bootstrap.decode(),
                self.header['descriptor_sha512'], worker.sha(raw), 'supervisor', 'stdin', self.bootstrap]
            process = subprocess.Popen(command, stdin=child, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       env={'LANG':'C.UTF-8','LC_ALL':'C.UTF-8'})
            child.close()
            worker.send_descriptors(parent, inputs)
            parent.close()
            stdout, stderr = process.communicate(timeout=5)
            return process.returncode, stdout, stderr
        finally:
            parent.close(); child.close()
            if replacement is not None: os.close(replacement)
            if process is not None and process.poll() is None:
                process.kill(); process.communicate()

    def test_fixed_bootstrap_executes_actual_independently_pinned_sealed_worker_bytes(self):
        code, stdout, stderr = self.bootstrap_control(None)
        self.assertEqual((code, stdout, stderr),
            (0, ('BOOTSTRAP_EXACT_SEALED_CONTROL %d\n' % len(self.fds)).encode(), b''))

    def test_fixed_bootstrap_refuses_substituted_worker_before_any_entry(self):
        code, stdout, stderr = self.bootstrap_control('bytes')
        self.assertNotEqual(code, 0); self.assertEqual(stdout, b'')
        self.assertIn(b'SEALED_BOOTSTRAP_WORKER_BYTES', stderr)

    def test_fixed_bootstrap_refuses_unsealed_worker_before_any_entry(self):
        code, stdout, stderr = self.bootstrap_control('unsealed')
        self.assertNotEqual(code, 0); self.assertEqual(stdout, b'')
        self.assertIn(b'SEALED_BOOTSTRAP_IMMUTABLE_WORKER', stderr)


if __name__ == '__main__':
    unittest.main()
