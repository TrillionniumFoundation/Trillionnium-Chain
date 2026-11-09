"""Actual SmolLM research forwards from a complete CHB1 sealed descriptor pair.

This fresh entry has no directory-model fallback, CURRENT, selector, signer or
FinalUse issuer. Original host Python/native dependencies keep the existing
independently pinned runtime-snapshot boundary; they are not transported memfds.
"""
from __future__ import annotations

import array
import builtins
import fcntl
import hashlib
import importlib.abc
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import resource
import socket
import stat
import struct
import sys
import threading
import time
import types

SCHEMA = 'trnm.cell-sealed-research-next-use.v1'
HEADER_SCHEMA = 'trnm.cell-sealed-research-fds.v1'
GRANT_SCHEMA = 'trnm.cell-sealed-research-execution.v1'
WORKER_PATH = 'scripts/llm_cell_sealed_worker_v1.py'
BOOTSTRAP_PATH = 'scripts/cell_sealed_bootstrap_v1.py'
SNAPSHOT_PATH = 'runtime/runtime-snapshot.json'
MATERIAL_PLAN_PATH = 'runtime/material-plan.json'
CURRENT_MATERIAL = 'current-contract-v1'
BRIDGED_MATERIAL = 'smollm2-public-v2-material-runtime-bridge-v1'
MODULES = {
    'contract_wire': 'formal/pon-nakamoto-v1/contract_wire.py',
    'llm_adapter_contract': 'formal/pon-nakamoto-v1/llm_adapter_contract.py',
    **{name: 'scripts/' + name + '.py' for name in (
        'llm_runtime_pilot', 'llm_base_material', 'llm_parent_material',
        'llm_inherited_runtime', 'llm_neural_read_worker', 'llm_python_runtime_contract',
        'llm_runtime_rss_diagnostics', 'llm_runtime_exit_observation')},
}
CONFIGS = tuple('config/pon/' + name for name in (
    'devnet-v1.json', 'ledger-v1.json', 'work-profile-v1.json',
    'model-family-v1.json', 'model-family-smollm2-135m-v1.json'))
ENVIRONMENT = frozenset((*MODULES.values(), *CONFIGS, WORKER_PATH, BOOTSTRAP_PATH, SNAPSHOT_PATH))
MODEL_FILES = frozenset((
    'base/README.md', 'base/config.json', 'base/generation_config.json',
    'base/material-manifest.json', 'base/model.safetensors', 'base/special_tokens_map.json',
    'base/tokenizer.json', 'base/tokenizer_config.json', 'adapter/artifact.safetensors',
    'adapter/target-contract.json', 'adapter/wrapped-adapter.json'))
NO_AUTHORITY = dict(installation_authorized=False, selection_authorized=False,
                    independent_accepted=False, prospective_accepted=False,
                    public_reward_eligible=False, hepta_final_use=False)


def require(condition, reason):
    if not condition:
        raise ValueError('CELL_SEALED_' + reason)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'DUPLICATE_FIELD')
        result[key] = value
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: require(False, 'JSON_NUMBER'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value, length=64):
    return type(value) is str and len(value) == length and all(c in '0123456789abcdef' for c in value)


def descriptor_fields(raw):
    require(type(raw) is bytes and len(raw) <= 2048 and raw[:4] == b'CHB1', 'DESCRIPTOR')
    offset = 4
    def take(n):
        nonlocal offset
        require(0 <= n <= len(raw) - offset, 'DESCRIPTOR_LENGTH')
        value = raw[offset:offset+n]
        offset += n
        return value
    value = {'operation': take(32).hex(), 'owner_generation': int.from_bytes(take(8), 'big'),
             'content': take(64).hex(), 'version': take(64).hex(),
             'model_closure': take(32).hex(), 'environment_closure': take(32).hex(),
             'model_generation': int.from_bytes(take(8), 'big'),
             'environment_generation': int.from_bytes(take(8), 'big')}
    length = int.from_bytes(take(1), 'big')
    require(1 <= length <= 64, 'DESCRIPTOR_FAMILY')
    value['family'] = take(length).decode('ascii')
    for key in ('base', 'parent', 'tokenizer', 'layout', 'runtime'):
        value[key] = take(32).hex()
    for key in ('worker_path', 'runtime_snapshot_path'):
        length = int.from_bytes(take(2), 'big')
        require(1 <= length <= 255, 'DESCRIPTOR_PATH')
        value[key] = take(length).decode('ascii')
    value['runtime_snapshot_sha256'] = take(32).hex()
    require(offset == len(raw) and value['owner_generation'] > 0, 'DESCRIPTOR_TRAILING')
    return value


class SealedInputs:
    """Only already-received kernel descriptors; there is no path reader."""
    def __init__(self, header, fds, bootstrap_sha256):
        require(type(header) is dict and set(header) == {'schema', 'descriptor',
            'descriptor_sha512', 'worker', 'files', 'execution', 'deadline_monotonic_ns'}
            and header['schema'] == HEADER_SCHEMA, 'HEADER')
        self.header, self.fds = header, tuple(fds)
        self.deadline = header['deadline_monotonic_ns']
        require(type(self.deadline) is int and 0 < self.deadline - time.monotonic_ns() <= 601 * 10**9,
                'ORIGINAL_DEADLINE')
        self.check()
        wire = bytes.fromhex(header['descriptor'])
        require(hashlib.sha512(b'TRNM/Cell/HostSealedDualContext/v1\0' + wire).hexdigest()
                == header['descriptor_sha512'], 'DESCRIPTOR_PIN')
        self.descriptor = descriptor_fields(wire)
        grant = header['execution']
        require(type(grant) is dict and set(grant) == {'schema', 'operation', 'descriptor',
            'environment_pins', 'max_snapshot_bytes', 'runtime_rss_bytes', 'python',
            'python_sha256', 'output', 'threads', 'parent', 'requests', 'material_profile'}
            and grant['schema'] == GRANT_SCHEMA and grant['operation'] == self.descriptor['operation']
            and grant['descriptor'] == header['descriptor_sha512'], 'EXECUTION_PIN')
        for name, low, high in (('max_snapshot_bytes', 1, 1024**3),
                              ('runtime_rss_bytes', 1, 8 * 1024**3), ('threads', 1, 4)):
            require(type(grant[name]) is int and low <= grant[name] <= high, 'FINITE_ALLOWANCE')
        require(grant['material_profile'] in (CURRENT_MATERIAL, BRIDGED_MATERIAL), 'MATERIAL_PROFILE')
        environment = ENVIRONMENT | ({MATERIAL_PLAN_PATH} if grant['material_profile'] == BRIDGED_MATERIAL else set())
        require(type(grant['environment_pins']) is dict and
                set(grant['environment_pins']) == environment and
                all(digest(x) for x in grant['environment_pins'].values()), 'COMPLETE_ENVIRONMENT_PINS')
        require(type(header['files']) is list and len(header['files']) == len(fds)
                and 1 <= len(fds) <= 64 and len(set(fds)) == len(fds), 'COMPLETE_FDS')
        self.entries, self.cached = {}, {}
        total = 0
        for index, row in enumerate(header['files']):
            require(type(row) is dict and set(row) == {'scope', 'path', 'role', 'bytes', 'sha256', 'sha512'}
                and row['scope'] in ('model', 'environment') and type(row['path']) is str
                and type(row['role']) is int and 1 <= row['role'] <= 6
                and type(row['bytes']) is int and 0 < row['bytes'] <= 512 * 1024**2
                and digest(row['sha256']) and digest(row['sha512'], 128), 'FILE_DECLARATION')
            key = row['scope'], row['path']
            require(key not in self.entries, 'FILE_ALIAS')
            self.entries[key] = index, row
            total += row['bytes']
            self._sealed(index, row)
            if row['scope'] == 'environment':
                require(row['role'] == 6 and grant['environment_pins'].get(row['path']) == row['sha256'], 'ENVIRONMENT_PIN')
            elif row['path'] == 'base/model.safetensors':
                require(row['role'] == 1, 'BASE_FILE_ROLE')
            elif row['path'] == 'adapter/artifact.safetensors':
                require(row['role'] == 4, 'ADAPTER_FILE_ROLE')
            elif row['path'].startswith('base/tokenizer') or row['path'] == 'base/special_tokens_map.json':
                require(row['role'] == 2, 'TOKENIZER_FILE_ROLE')
            else:
                require(row['role'] == 6, 'CONFIGURATION_FILE_ROLE')
        require(total <= grant['max_snapshot_bytes'] and
                {p for s, p in self.entries if s == 'model'} == MODEL_FILES and
                {p for s, p in self.entries if s == 'environment'} == environment,
                'COMPLETE_SNAPSHOT_ALLOWANCE')
        require(type(header['worker']) is int and 0 <= header['worker'] < len(fds)
                and header['files'][header['worker']]['path'] == WORKER_PATH
                and self.descriptor['worker_path'] == WORKER_PATH
                and self.descriptor['runtime_snapshot_path'] == SNAPSHOT_PATH
                and self.descriptor['runtime'] == grant['environment_pins'][WORKER_PATH]
                and self.descriptor['runtime_snapshot_sha256'] == grant['environment_pins'][SNAPSHOT_PATH]
                and bootstrap_sha256 == grant['environment_pins'][BOOTSTRAP_PATH], 'WORKER_PROFILE_PIN')
        self.grant = grant
        self.bootstrap_sha256 = bootstrap_sha256
        self._requests()
        # All environment contents are bounded and verified before importing any
        # project/third-party code. Their same immutable bytes are retained.
        for path in sorted(environment):
            self.raw('environment', path, maximum=16 * 1024**2, retain=True)

    def check(self):
        require(time.monotonic_ns() < self.deadline, 'ORIGINAL_DEADLINE')

    def remaining(self, ceiling=10):
        self.check()
        return min(ceiling, (self.deadline - time.monotonic_ns()) / 1e9)

    def _sealed(self, index, row):
        self.check()
        fd = self.fds[index]
        info = os.fstat(fd)
        seals = fcntl.fcntl(fd, getattr(fcntl, 'F_GET_SEALS', 1034))
        require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o111
                and info.st_size == row['bytes'] and seals & 0x2f == 0x2f
                and fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC, 'IMMUTABLE_FD')
        return info

    def raw(self, scope, path, maximum=512 * 1024**2, retain=False):
        self.check()
        key = scope, path
        require(key in self.entries, 'UNDECLARED_FILE')
        index, row = self.entries[key]
        require(row['bytes'] <= maximum, 'FILE_READ_BOUND')
        self._sealed(index, row)
        if key in self.cached:
            return self.cached[key]
        raw = bytearray()
        while len(raw) < row['bytes']:
            self.check()
            block = os.pread(self.fds[index], min(65536, row['bytes'] - len(raw)), len(raw))
            require(bool(block), 'FILE_EOF')
            raw.extend(block)
        raw = bytes(raw)
        require(sha(raw) == row['sha256'] and hashlib.sha512(
            b'TRNM/Cell/PayloadContent/v2\0' + struct.pack('>Q', len(raw)) + raw).hexdigest()
            == row['sha512'], 'FILE_CONTENT')
        self._sealed(index, row)
        if retain:
            self.cached[key] = raw
        return raw

    def _requests(self):
        requests = self.grant['requests']
        require(type(requests) is list and len(requests) == 2, 'TWO_DISTINCT_TASKS')
        ids = set()
        for query in requests:
            require(type(query) is dict and set(query) == {'request_id', 'prompt'}
                and type(query['request_id']) is str and 1 <= len(query['request_id'].encode()) <= 128
                and type(query['prompt']) is str and 1 <= len(query['prompt'].encode()) <= 2048
                and query['request_id'] not in ids, 'TASK_SCOPE')
            ids.add(query['request_id'])
        parent = self.grant['parent']
        require(type(parent) is dict and set(parent) == {'generation', 'operation_id',
            'contract', 'adapter', 'file_sha256'} and type(parent['generation']) is int
            and 1 <= parent['generation'] < 2**63 and type(parent['operation_id']) is str
            and 1 <= len(parent['operation_id'].encode()) <= 128 and
            all(digest(parent[key]) for key in ('contract', 'adapter', 'file_sha256')),
            'ORIGINAL_PARENT')
        require(parent['generation'] == self.descriptor['model_generation']
            and parent['file_sha256'] == self.descriptor['parent']
            and parent['contract'] == self.descriptor['layout'], 'ORIGINAL_PARENT_CONTEXT')


class ProjectSources(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Execute original project modules from the admitted source bytes only.

    The original contract_wire module receives a read-only configuration-path
    capability. The original pilot's two input-reader dependencies are bound to
    this same exact source/config map. No source is transformed, and no unknown
    path is delegated to an ambient filesystem reader.
    """
    def __init__(self, inputs, root):
        self.inputs, self.root, self.loaded = inputs, root, {}
        self.paths = {str(root / relative): relative for relative in ENVIRONMENT}

    def find_spec(self, fullname, path=None, target=None):
        if fullname in MODULES:
            return importlib.util.spec_from_loader(fullname, self, origin=str(self.root / MODULES[fullname]))
        require(not fullname.startswith('llm_'), 'UNDECLARED_PROJECT_MODULE')
        return None

    def create_module(self, spec):
        return None

    def read(self, path):
        path = str(path)
        require(path in self.paths, 'UNDECLARED_SOURCE_OR_CONFIG_PATH')
        return self.inputs.raw('environment', self.paths[path], maximum=16 * 1024**2, retain=True)

    def file_sha(self, path):
        return sha(self.read(path))

    def read_json(self, path):
        require(self.paths.get(str(path)) in CONFIGS, 'UNDECLARED_CONFIGURATION')
        return decode(self.read(path))

    def exec_module(self, module):
        name = module.__name__
        require(name in MODULES and name not in self.loaded, 'PROJECT_MODULE_ALIAS')
        path = str(self.root / MODULES[name])
        raw = self.read(path)
        module.__file__, module.__loader__ = path, self
        if name == 'contract_wire':
            owner = self
            class ConfigPath:
                def __init__(self, value):
                    self.value = PurePosixPath(value)
                def resolve(self):
                    return self
                @property
                def parents(self):
                    return tuple(ConfigPath(str(x)) for x in self.value.parents)
                def __truediv__(self, value):
                    return ConfigPath(str(self.value / value))
                def read_text(self):
                    require(owner.paths.get(str(self.value)) in CONFIGS, 'CONTRACT_CONFIG_SCOPE')
                    return owner.read(str(self.value)).decode('utf-8')
            original_import = builtins.__import__
            shim = types.ModuleType('pathlib')
            shim.Path = ConfigPath
            def admitted_import(fullname, globals=None, locals=None, fromlist=(), level=0):
                if fullname == 'pathlib' and level == 0:
                    require(tuple(fromlist) == ('Path',), 'CONTRACT_PATH_CAPABILITY')
                    return shim
                return original_import(fullname, globals, locals, fromlist, level)
            module.__dict__['__builtins__'] = dict(builtins.__dict__, __import__=admitted_import)
        exec(compile(raw, path, 'exec'), module.__dict__)
        if name == 'llm_runtime_pilot':
            module.file_sha = self.file_sha
            module.read_json = self.read_json
        self.loaded[name] = module


def decode_runtime_snapshot(inputs, helper):
    raw = inputs.raw('environment', SNAPSHOT_PATH, maximum=16 * 1024**2, retain=True)
    value = decode(raw)
    require(type(value) is dict and value.get('schema') == helper.SCHEMA, 'RUNTIME_SNAPSHOT_SCHEMA')
    files, inventory = value.get('files'), value.get('managed_inventory')
    require(type(files) is dict and 0 < len(files) <= helper.MAX_FILES and
        all(type(p) is str and Path(p).is_absolute() and digest(d) for p, d in files.items()),
        'RUNTIME_SNAPSHOT_FILES')
    require(type(inventory) is list and 0 < len(inventory) <= helper.MAX_FILES and
        all(type(p) is str and p in files for p in inventory) and inventory == sorted(set(inventory)),
        'RUNTIME_SNAPSHOT_INVENTORY')
    for key in ('prefix', 'stdlib_root'):
        root = Path(value.get(key, ''))
        require(root.is_absolute() and root != Path('/') and root.is_dir()
                and root.resolve(strict=True) == root, 'RUNTIME_SNAPSHOT_ROOT')
    python = value.get('python')
    require(type(python) is dict and python.get('executable') in files
        and type(python.get('version')) is str, 'RUNTIME_SNAPSHOT_PYTHON')
    require(Path(inputs.grant['python']).is_absolute() and
        str(Path(inputs.grant['python']).resolve(strict=True)) == python['executable']
        and helper.file_digest(inputs.grant['python'])[0] == inputs.grant['python_sha256'],
        'INDEPENDENT_INTERPRETER_PIN')
    return value


def prepare_runtime(inputs):
    require(sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode,
            'ISOLATED_ENTRY')
    require(not any(k.startswith('LD_') or k == 'GLIBC_TUNABLES' for k in os.environ),
            'NATIVE_LOADER_ENVIRONMENT')
    output = Path(inputs.grant['output'])
    require(output.is_absolute() and output.resolve(strict=True) == output, 'OUTPUT_PATH')
    info = output.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_OWNER_DIRECTORY')
    root = output / 'sealed-source-names'
    # These empty directories preserve original __file__/relative-name semantics
    # only. No source, config or model input is materialized into them.
    for path in (root, root / 'scripts', root / 'formal', root / 'formal/pon-nakamoto-v1',
                 root / 'config', root / 'config/pon'):
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            require(path.is_dir() and not path.is_symlink() and
                    stat.S_IMODE(path.stat().st_mode) == 0o700, 'SOURCE_NAME_DIRECTORY')
    sources = ProjectSources(inputs, root)
    require(not any(name in sys.modules for name in MODULES), 'PREIMPORTED_PROJECT_SOURCE')
    sys.meta_path.insert(0, sources)
    helper = __import__('llm_python_runtime_contract')
    snapshot = decode_runtime_snapshot(inputs, helper)
    helper.configure(snapshot)
    inputs.check()
    helper.verify_files(snapshot)
    inputs.check()
    guard = helper.PinnedImports(dict(snapshot['files']), helper._generated_source_profile(snapshot))
    sys.meta_path[sys.meta_path.index(importlib.machinery.PathFinder)] = guard
    runtime = __import__('llm_runtime_pilot')
    inherited = __import__('llm_inherited_runtime')
    parent_material = __import__('llm_parent_material')
    base = __import__('llm_base_material')
    original_worker = __import__('llm_neural_read_worker')
    return types.SimpleNamespace(inputs=inputs, sources=sources, helper=helper, snapshot=snapshot,
        guard=guard, runtime=runtime, inherited=inherited, parent_material=parent_material,
        base=base, original_worker=original_worker)


def verify_runtime_ready(state):
    state.inputs.check()
    require(state.sources in sys.meta_path and state.guard in sys.meta_path
            and state.guard.files == state.snapshot['files'], 'IMPORT_GUARDS_CHANGED')
    generated = state.guard.generated.verify_loaded() if state.guard.generated is not None else None
    origins = set()
    for name, module in tuple(sys.modules.items()):
        if name in state.sources.loaded:
            require(module is state.sources.loaded[name] and module.__loader__ is state.sources
                and module.__file__ == str(state.sources.root / MODULES[name]), 'SEALED_MODULE_CHANGED')
            continue
        path = getattr(module, '__file__', None)
        if path is not None:
            require(type(path) is str, 'MODULE_ORIGIN')
            origins.add(str(Path(path).resolve(strict=True)))
    with Path('/proc/self/maps').open() as stream:
        raw = stream.read(8 * 1024**2 + 1)
    require(len(raw) <= 8 * 1024**2, 'NATIVE_MAPS_BOUND')
    for row in raw.splitlines():
        parts = row.split(maxsplit=5)
        if len(parts) == 6 and 'x' in parts[1] and parts[5].startswith('/'):
            require(not parts[5].endswith(' (deleted)'), 'DELETED_NATIVE_MAPPING')
            origins.add(str(Path(parts[5]).resolve(strict=True)))
    require(len(origins) <= state.helper.MAX_FILES, 'LOADED_FILE_BOUND')
    for path in sorted(origins):
        state.inputs.check()
        if path == generated:
            continue
        require(path in state.snapshot['files'] and
                state.helper.file_digest(path)[0] == state.snapshot['files'][path], 'RUNTIME_BYTE_DRIFT')
    state.inputs.check()


def capture_base(inputs, state):
    runtime, base = state.runtime, state.base
    manifest_raw = inputs.raw('model', 'base/material-manifest.json', maximum=base.MAX_MANIFEST_BYTES)
    manifest = base.decode(manifest_raw)
    require(type(manifest) is dict and manifest.get('model') == runtime.MODEL
        and manifest.get('revision') == runtime.REVISION, 'BASE_SNAPSHOT_CONTEXT')
    members = manifest.get('files')
    require(type(members) is dict and set(members) == set(runtime.PUBLIC_FILES), 'BASE_COMPLETE_ROSTER')
    files = []
    for name, pin in runtime.PUBLIC_FILES.items():
        item = members[name]
        require(type(item) is dict and type(item.get('size')) is int
            and (item['size'], item.get('sha256')) == pin
            and item.get('revision') == runtime.REVISION, 'BASE_INDEPENDENT_PIN')
        raw = inputs.raw('model', 'base/' + name, maximum=pin[0])
        require(len(raw) == pin[0] and sha(raw) == pin[1], 'BASE_ACTUAL_BYTES')
        files.append((name, raw))
    return base.BaseMaterial(manifest_raw, tuple(sorted(files)))


def capture_parent(inputs, state):
    parent, runtime = inputs.grant['parent'], state.runtime
    c = runtime.contract_module()
    family = runtime.verify_family(runtime.read_json(runtime.FAMILY_PATH))
    raw = inputs.raw('model', 'adapter/target-contract.json', maximum=c.MAX_MANIFEST_BYTES)
    contract = c.verify_target_contract(raw, parent['contract'],
        expected_backbone_root=family['material_pins']['fp32_backbone_index_root'],
        expected_tokenizer_root=family['material_pins']['tokenizer_files_root'])
    targets = sorted((dict(module=f'model.layers.{layer}.self_attn.{projection}',
        in_features=576, out_features=576 if projection == 'q_proj' else 192,
        rank=4, alpha=[8, 1]) for layer in range(30) for projection in ('q_proj', 'v_proj')),
        key=lambda x: x['module'])
    require(contract['architecture'] == family['architecture'] and
        contract['reference'] == runtime.MODEL + '@' + runtime.REVISION + ':derived-cpu-float32'
        and contract['numeric']['storage_dtype'] == 'float32'
        and contract['numeric']['accumulation_dtype'] == 'float32'
        and contract['numeric']['quantization'] == 'none' and contract['targets'] == targets
        and contract['ports']['batch_max'] == 1 and contract['ports']['input_tokens_max'] == 128
        and contract['ports']['output_tokens_max'] == 16, 'ORIGINAL_PARENT_PROFILE')
    artifact = inputs.raw('model', 'adapter/artifact.safetensors', maximum=family['artifact_max_bytes'])
    require(sha(artifact) == parent['file_sha256'], 'ORIGINAL_ADAPTER_BYTES')
    factors = state.parent_material.factor_bytes(artifact, contract)
    wrapped = inputs.raw('model', 'adapter/wrapped-adapter.json', maximum=c.MAX_MANIFEST_BYTES)
    c.verify_wrapped_adapter(wrapped, parent['adapter'], contract, parent['contract'], factors)
    return contract, factors


def verify_loaded_material(inputs, state, pilot, actual, contract):
    if inputs.grant['material_profile'] == CURRENT_MATERIAL:
        require({k: v for k, v in actual.items() if k != 'registration'} ==
                {k: v for k, v in contract.items() if k != 'registration'}, 'ORIGINAL_RUNTIME_BINDING')
        return None
    # The existing bridge accepts one exact historical/current source pair and
    # compares the complete projected loaded contract. It is provenance only.
    original = state.original_worker
    require(inputs.grant['material_profile'] == original.MATERIAL_BRIDGE_PROFILE_V1
        and inputs.grant['environment_pins'][MODULES['llm_runtime_pilot']]
            == original._EXECUTION_RUNTIME_SHA256, 'ORIGINAL_BRIDGE_EXECUTION_SOURCE')
    bridge = original._MaterialRuntimeBridgeV1(inputs.grant['material_profile'],
        inputs.raw('environment', MATERIAL_PLAN_PATH, maximum=64 * 1024, retain=True), pilot,
        inputs.raw('model', 'adapter/target-contract.json', maximum=1024 * 1024),
        inputs.grant['parent']['contract'])
    return bridge.verify_loaded_contract(actual)


def publish(path, value):
    raw = canonical(value) + b'\n'
    pending = path.with_name(path.name + '.pending')
    with os.fdopen(os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as out:
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())
    # link is atomic and fails if a previous result exists. A reader can only
    # observe the complete fsynced object; partial work remains visibly pending.
    os.link(pending, path, follow_symlinks=False)
    pending.unlink()
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read_observation(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 131072, 'OBSERVATION_BOUND')
        raw = source.read(131073)
    require(len(raw) == info.st_size, 'OBSERVATION_LENGTH')
    return decode(raw)


def read_original_request(inputs, original, connection):
    # Preserve the original parser while giving every underlying recv the same
    # caller-owned absolute deadline, including a partially received frame.
    class DeadlineReader:
        def recv(self, maximum):
            connection.settimeout(inputs.remaining())
            raw = connection.recv(maximum)
            inputs.check()
            return raw
    return original.read_request(DeadlineReader())


def worker(inputs, state):
    runtime, base = state.runtime, state.base
    directory = Path(inputs.grant['output']) / 'worker'
    observer = runtime.Observer(directory, 'cpu')
    material = observer.stage('sealed-base-capture', lambda: capture_base(inputs, state))
    manifest = material.manifest()
    pilot = runtime.experiment_plan(manifest, threads=inputs.grant['threads'], steps=10)
    runtime.validate_plan(pilot)
    contract, factors = observer.stage('sealed-parent-verification', lambda: capture_parent(inputs, state))
    imports = observer.stage('runtime-import', lambda: runtime.runtime_import(pilot))
    torch, device, *_ = imports
    shapes = runtime.contract_module().architecture_shapes(runtime.architecture(material.document('config.json')))
    tokenizer = observer.stage('sealed-tokenizer-load', lambda: base.tokenizer_from_material(material))
    model, _ = observer.stage('sealed-base-load', lambda: base.model_from_material(material, shapes, torch))
    model.to(device)
    model.eval()
    require(sum(p.numel() for p in model.parameters()) == 134515008 and
        all(p.dtype == torch.float32 and p.device.type == 'cpu' for p in model.parameters()),
        'ORIGINAL_LOADED_PARAMETERS')
    require(tokenizer.bos_token_id == 1 and tokenizer.eos_token_id == tokenizer.pad_token_id == 2
        and len(tokenizer) == 49152, 'ORIGINAL_TOKENIZER_PROFILE')
    base.bind_loaded(material, model, tokenizer)
    del material
    actual, _, _ = observer.stage('actual-backbone-tokenizer-verification',
        lambda: runtime.make_contract(model, tokenizer, shapes, None, manifest, pilot))
    bridge_record = verify_loaded_material(inputs, state, pilot, actual, contract)
    model = runtime.insert_lora(model, pilot, 'candidate', torch)
    parent = inputs.grant['parent']
    loaded = observer.stage('actual-sealed-parent-load', lambda: state.inherited.load_factors(
        model, contract, parent['contract'], factors, parent['adapter'], torch, device))
    del factors
    actions = state.original_worker.action_profile([
        {'action_id': 'no', 'completion': 'no'}, {'action_id': 'yes', 'completion': 'yes'}])
    action_tokens = [tokenizer.encode(item['completion'], add_special_tokens=False) for item in actions]
    require(all(len(tokens) == 1 for tokens in action_tokens) and
        len({tokens[0] for tokens in action_tokens}) == len(actions), 'ORIGINAL_ACTION_PROFILE')
    model.eval()
    verify_runtime_ready(state)
    ready = dict(schema=SCHEMA, descriptor=inputs.header['descriptor_sha512'],
        content=inputs.descriptor['content'], version=inputs.descriptor['version'],
        actual_loaded_parent=loaded, file_sha256=parent['file_sha256'], contract=parent['contract'],
        generation=parent['generation'], backbone=contract['backbone']['index_root'],
        tokenizer=contract['tokenizer']['files_root'], worker_sha256=inputs.descriptor['runtime'],
        environment_pins=inputs.grant['environment_pins'],
        runtime_snapshot_sha256=inputs.descriptor['runtime_snapshot_sha256'],
        material_profile=inputs.grant['material_profile'], material_runtime_bridge=bridge_record,
        deadline_monotonic_ns=inputs.deadline, authority=NO_AUTHORITY,
        interpreter_and_native_dependencies='original independently pinned host snapshot; not sealed transport')
    os.chdir(directory)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind('model.sock')
        os.chmod('model.sock', 0o600)
        server.listen(1)
        publish(directory / 'ready.json', ready)
        for expected in inputs.grant['requests']:
            server.settimeout(inputs.remaining())
            connection, _ = server.accept()
            with connection:
                connection.settimeout(inputs.remaining())
                request, input_sha256 = read_original_request(inputs, state.original_worker, connection)
                require(request == dict(schema='hepta-smollm-inference-input-v1', **expected),
                        'ORIGINAL_TASK_ORDER_AND_BYTES')
                inputs.check()
                started = time.monotonic_ns()
                tokens = runtime.prompt_tokens(tokenizer, request, pilot['input_tokens_max'])
                ids = torch.tensor([tokens], dtype=torch.int64, device=device)
                with torch.inference_mode():
                    mask = torch.ones_like(ids, dtype=torch.bool)
                    positions = mask.to(torch.int64).cumsum(-1) - 1
                    result = model(input_ids=ids, attention_mask=mask, position_ids=positions, use_cache=False)
                    logits = result.logits[:, -1, :]
                    require(logits.dtype == torch.float32 and logits.device.type == 'cpu'
                        and torch.isfinite(logits).all().item(), 'ORIGINAL_ACTUAL_LOGITS')
                    scores = [round(float(logits[0, token[0]].item()) * (1 << 32)) for token in action_tokens]
                    require(all(-(1 << 63) <= score < (1 << 63) for score in scores), 'ORIGINAL_SCORE_RANGE')
                inputs.check()
                response = dict(schema=SCHEMA, request_id=request['request_id'], input_sha256=input_sha256,
                    descriptor=inputs.header['descriptor_sha512'], content=inputs.descriptor['content'],
                    artifact=loaded, file_sha256=parent['file_sha256'], contract=parent['contract'],
                    profile='hepta-smollm-single-token-action-score-v1', action_ids=['no', 'yes'],
                    scores_q32=scores, input_tokens=len(tokens),
                    logits_sha256=sha(runtime.tensor_bytes(logits)),
                    execution_ns=time.monotonic_ns() - started,
                    observed_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024,
                    authority=NO_AUTHORITY)
                connection.settimeout(inputs.remaining())
                connection.sendall(canonical(response) + b'\n')
                inputs.check()
        server.settimeout(inputs.remaining())
        connection, _ = server.accept()
        with connection:
            connection.settimeout(inputs.remaining())
            stop, _ = read_original_request(inputs, state.original_worker, connection)
            require(stop is None, 'EXACT_STOP_AFTER_TWO_TASKS')
    (directory / 'model.sock').unlink()
    inputs.check()


def send_descriptors(connection, inputs):
    raw = canonical(inputs.header)
    require(len(raw) <= 131072, 'HEADER_BOUND')
    connection.settimeout(inputs.remaining())
    connection.sendall(struct.pack('>I', len(raw)) + raw)
    for fd in inputs.fds:
        connection.settimeout(inputs.remaining())
        require(connection.sendmsg([b'F'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
            array.array('i', [fd]))]) == 1, 'DESCRIPTOR_TRANSFER')
    inputs.check()


def query_worker(inputs, directory, value, stop=False):
    raw = canonical(value)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(inputs.remaining())
        # A held directory descriptor avoids sun_path length and fixes this
        # query to the original private worker directory.
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            stream.connect(f'/proc/self/fd/{fd}/model.sock')
            stream.settimeout(inputs.remaining())
            stream.sendall(raw + b'\n')
            inputs.check()
            if stop:
                return None
            result = bytearray()
            while len(result) <= 131072:
                stream.settimeout(inputs.remaining())
                block = stream.recv(min(8192, 131073 - len(result)))
                if not block:
                    break
                result.extend(block)
                if b'\n' in block:
                    break
            require(0 < len(result) <= 131072 and result.endswith(b'\n')
                    and result.count(b'\n') == 1, 'RESPONSE_FRAME')
            return decode(result)
        finally:
            os.close(fd)


def supervisor(inputs, state):
    root, observations, failures = Path(inputs.grant['output']), [], []
    # Original supervision creates worker/ itself. The connector socket carries
    # only sealed descriptors; no FD inheritance or CLOEXEC change is needed.
    channel = root / 'fd.sock'
    bootstrap = inputs.raw('environment', BOOTSTRAP_PATH, maximum=2 * 1024**2, retain=True)
    require(sha(bootstrap) == inputs.bootstrap_sha256, 'BOOTSTRAP_EXACT_BYTES')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        os.chdir(root)
        listener.bind('fd.sock')
        os.chmod(channel, 0o600)
        listener.listen(1)
        def client():
            try:
                listener.settimeout(inputs.remaining())
                connection, _ = listener.accept()
                with connection:
                    send_descriptors(connection, inputs)
                ready_path = root / 'worker/ready.json'
                while not ready_path.exists():
                    inputs.check()
                    time.sleep(min(0.05, inputs.remaining()))
                # Observation is not authority. Exact request/content/parent
                # binding is checked against the independently retained grant.
                ready = read_observation(ready_path)
                require(ready.get('schema') == SCHEMA and
                    ready.get('descriptor') == inputs.header['descriptor_sha512']
                    and ready.get('actual_loaded_parent') == inputs.grant['parent']['adapter']
                    and ready.get('material_profile') == inputs.grant['material_profile']
                    and ((ready.get('material_runtime_bridge') is None) ==
                         (inputs.grant['material_profile'] == CURRENT_MATERIAL))
                    and ready.get('authority') == NO_AUTHORITY, 'READY_BINDING')
                for original in inputs.grant['requests']:
                    request = dict(schema='hepta-smollm-inference-input-v1', **original)
                    observed = query_worker(inputs, root / 'worker', request)
                    require(observed.get('schema') == SCHEMA and
                        observed.get('request_id') == request['request_id']
                        and observed.get('input_sha256') == sha(canonical(request))
                        and observed.get('descriptor') == inputs.header['descriptor_sha512']
                        and observed.get('content') == inputs.descriptor['content']
                        and observed.get('artifact') == inputs.grant['parent']['adapter']
                        and observed.get('contract') == inputs.grant['parent']['contract']
                        and observed.get('file_sha256') == inputs.grant['parent']['file_sha256']
                        and observed.get('action_ids') == ['no', 'yes']
                        and type(observed.get('scores_q32')) is list
                        and len(observed['scores_q32']) == 2
                        and all(type(score) is int for score in observed['scores_q32'])
                        and observed.get('authority') == NO_AUTHORITY, 'NEXT_TASK_READBACK')
                    observations.append(observed)
                query_worker(inputs, root / 'worker',
                    dict(schema=state.original_worker.SCHEMA, stop=True), stop=True)
            except BaseException as error:
                failures.append(type(error).__name__ + ': ' + str(error))
        thread = threading.Thread(target=client, name='sealed-research-original-requests')
        thread.start()
        result = None
        try:
            inputs.check()
            # Floor the remaining original allowance. This deliberately cannot
            # refresh a full 600-second window after bootstrap/import work.
            remaining_seconds = (inputs.deadline - time.monotonic_ns()) // 1_000_000_000
            require(remaining_seconds >= 1, 'ORIGINAL_SUPERVISION_DEADLINE')
            command = [inputs.grant['python'], '-I', '-S', '-B', '-X',
                'pycache_prefix=' + str(root / 'unused-child-bytecode'), '-c', bootstrap.decode('utf-8'),
                inputs.header['descriptor_sha512'], inputs.descriptor['runtime'], 'worker',
                'fd.sock', inputs.bootstrap_sha256]
            with state.runtime.cooperative_supervisor_stop() as stop_request:
                result = state.runtime.supervise(command, root / 'worker',
                    dict(wall_seconds=remaining_seconds, rss_bytes=inputs.grant['runtime_rss_bytes']),
                    stop_request=stop_request)
        finally:
            # Socket timeouts and the same original absolute deadline bound the
            # connector. A still-live thread is recorded as unresolved failure.
            thread.join(timeout=max(0, (inputs.deadline - time.monotonic_ns()) / 1e9) + 1)
            publish(root / 'next-use-observations.json', observations)
            publish(root / 'next-use-result.json', dict(schema=SCHEMA,
                descriptor=inputs.header['descriptor_sha512'], content=inputs.descriptor['content'],
                observations=len(observations), failures=failures, supervisor=result,
                connector_complete=not thread.is_alive(), authority=NO_AUTHORITY,
                interpreter_and_native_dependencies='original independently pinned host snapshot; not sealed transport'))
            channel.unlink()
        require(not thread.is_alive() and not failures and len(observations) == 2
            and result is not None and result.get('outcome') == 'success'
            and result.get('waited_child_reaped') is True
            and not (root / 'worker/model.sock').exists(), 'ORIGINAL_WAIT4_AND_NEXT_USE')
        inputs.check()


def entry(header, fds, mode, bootstrap_sha256):
    os.umask(0o077)
    inputs = SealedInputs(header, fds, bootstrap_sha256)
    state = prepare_runtime(inputs)
    if mode == 'supervisor':
        supervisor(inputs, state)
    else:
        require(mode == 'worker', 'ENTRY_MODE')
        worker(inputs, state)


if __name__ == '__main__':
    raise SystemExit('CELL_SEALED_TYPED_FD_ENTRY_REQUIRED')

