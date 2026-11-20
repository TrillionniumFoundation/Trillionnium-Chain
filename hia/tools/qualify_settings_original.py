"""Compare native Settings with the unchanged original public constructor.

All production sources are copied intact. Only a cfg(test) child declaration
and its new observation file are added to the isolated Node library. No Rust
implementation function or visibility is edited. Cargo's actual JSON artifact
event selects the test executable; no target-directory glob or cached guess is
accepted. This tool is test infrastructure, not a native runtime dependency.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import sys
import time
import traceback

HIA = Path(__file__).resolve().parents[1]
ROOT = HIA.parent
LIB = 'trillionnium/crates/trnm-pon-node/src/lib.rs'
TEST = 'hia_settings_reference::evaluate'
MARKER = 'HIA_SETTINGS_ORACLE:'
DECLARATION = (b'\n#[cfg(test)]\n#[path = "hia_settings_reference.rs"]\n'
               b'mod hia_settings_reference;\n')
SOURCE_PINS = HIA / 'tests/oracles/settings_original_sources.json'
HOOK = HIA / 'tests/oracles/settings_original.rs'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, data):
    path.write_text(json.dumps(data, sort_keys=True, indent=2) + '\n')


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON event key: ' + key)
        result[key] = value
    return result


def verify_original(repository):
    expected = json.loads(SOURCE_PINS.read_text(), object_pairs_hook=unique_keys)
    if expected['schema'] != 'trnm.hia.settings-original-sources.v1':
        raise ValueError('Unknown original Settings source pin schema')
    for row in expected['files']:
        path = repository / row['path']
        if path.is_symlink():
            raise ValueError('Symlinked original Settings input: ' + row['path'])
        raw = path.read_bytes()
        if len(raw) != row['bytes'] or digest(raw) != row['sha256']:
            raise ValueError('Original Settings input changed: ' + row['path'])
    return expected


def select_original_executable(raw, target, manifest, source):
    """Validate a complete successful Cargo JSON event stream, not a glob."""
    target, manifest, source = map(lambda p: Path(p).absolute(), (target, manifest, source))
    events = []
    for line in raw.splitlines():
        if line.strip():
            item = json.loads(line, object_pairs_hook=unique_keys)
            if not isinstance(item, dict):
                raise ValueError('Cargo event is not an object')
            events.append(item)
    finished = [item for item in events if item.get('reason') == 'build-finished']
    if len(finished) != 1 or finished[0].get('success') is not True:
        raise ValueError('Cargo did not report one successful completed build')
    candidates = []
    for event in events:
        if event.get('reason') != 'compiler-artifact':
            continue
        info = event.get('target', {})
        if info.get('name') != 'trnm_pon_node' or event.get('profile', {}).get('test') is not True:
            continue
        if info.get('kind') != ['lib']:
            continue
        if (event.get('manifest_path') != str(manifest)
                or info.get('src_path') != str(source)):
            raise ValueError('Original Node artifact source identity differs')
        value = event.get('executable')
        if not isinstance(value, str):
            raise ValueError('Original Node test artifact has no executable')
        path = Path(value)
        if (not path.is_absolute() or '..' in path.parts or path.as_posix() != value
                or not path.is_relative_to(target) or path == target):
            raise ValueError('Original Node test artifact escapes its fresh target directory')
        candidates.append(path)
    if len(candidates) != 1:
        raise ValueError('Cargo original Node test artifact is missing or ambiguous')
    return candidates[0]


def corpus():
    times = [None, 0, 1, 2, 9, 10, 99, 100, 999, 1000, 1799999999, 1800000000,
             1800000001, (1 << 32) - 1, 1 << 32, (1 << 53) - 1, 1 << 53,
             (1 << 53) + 1, 10**18, (1 << 63) - 1, 1 << 63, (1 << 64) - 1]
    rng = random.Random(0x53445631)
    times += [rng.randrange(1, 1 << 63) for _ in range(8)]
    return [{'name': f'settings-{index:03}',
             'timestamp': None if timestamp is None else str(timestamp)}
            for index, timestamp in enumerate(times)]


class RustOracle:
    def __init__(self, repository, output):
        self.repository = Path(repository).resolve()
        self.output = Path(output)
        self.output.mkdir(mode=0o700)
        self.isolated = self.output / 'isolated-source'
        self.isolated.mkdir(mode=0o700)
        sys.path.insert(0, str(self.repository))
        from hia.platform.transport_request.rust_oracle import command
        self.command = command
        self.command_source = self.repository / 'hia/platform/transport_request/rust_oracle.py'
        self.command_bytes = self.command_source.read_bytes()
        self.sources = {}
        for directory in ('trillionnium', 'config', 'formal'):
            for path in sorted((self.repository / directory).rglob('*')):
                relative = path.relative_to(self.repository)
                if any(part in {'target', '__pycache__', '.pytest_cache'} for part in relative.parts):
                    continue
                if path.is_symlink():
                    raise ValueError('Symlinked original source: ' + str(relative))
                if not path.is_file():
                    continue
                raw = path.read_bytes()
                destination = self.isolated / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(raw)
                self.sources[relative.as_posix()] = {'bytes': len(raw), 'sha256': digest(raw)}
        original_lib = self.isolated / LIB
        self.original_lib = original_lib.read_bytes()
        if b'mod hia_settings_reference' in self.original_lib:
            raise ValueError('Original library already contains the observation hook')
        self.hook = HOOK.read_bytes()
        self.hook_path = original_lib.parent / 'hia_settings_reference.rs'
        if self.hook_path.exists():
            raise FileExistsError('Refusing to replace an original source path')
        self.hook_path.write_bytes(self.hook)
        original_lib.write_bytes(self.original_lib + DECLARATION)
        self.stages = []
        version, stage = self.command(['rustc', '-Vv'], self.isolated, self.output,
                                     'rustc-version', timeout=10)
        self.stages.append(stage)
        self.compiler = version.decode()
        target = self.output / 'cargo-target'
        manifest = self.isolated / 'trillionnium/crates/trnm-pon-node/Cargo.toml'
        command = ['cargo', 'test', '--locked', '--manifest-path',
                   str(self.isolated / 'trillionnium/Cargo.toml'), '-p', 'trnm-pon-node',
                   '--lib', '--no-run', '--message-format=json', '--target-dir', str(target)]
        raw, stage = self.command(command, self.isolated, self.output,
                                  'cargo-original-test-build', timeout=600)
        self.stages.append(stage)
        self.binary = select_original_executable(raw, target, manifest, original_lib)
        if self.binary.is_symlink() or not self.binary.is_file():
            raise ValueError('Original executable is not a regular artifact')
        self.binary_digest = digest(self.binary.read_bytes())
        available, stage = self.command([str(self.binary), '--list'], self.isolated,
            self.output, 'list-original-tests', timeout=20)
        self.stages.append(stage)
        tests = {line.removesuffix(': test') for line in available.decode().splitlines()
                 if line.endswith(': test')}
        if TEST not in tests:
            raise ValueError('Actual original executable does not contain the requested test')
        self.check_sources()

    def check_sources(self):
        verify_original(self.repository)
        for relative, expected in self.sources.items():
            raw = (self.repository / relative).read_bytes()
            if len(raw) != expected['bytes'] or digest(raw) != expected['sha256']:
                raise ValueError('Original source changed: ' + relative)
            isolated = raw + (DECLARATION if relative == LIB else b'')
            if (self.isolated / relative).read_bytes() != isolated:
                raise ValueError('Isolated original source changed: ' + relative)
        if self.hook_path.read_bytes() != self.hook or HOOK.read_bytes() != self.hook:
            raise ValueError('Original observation hook changed')
        if self.command_source.read_bytes() != self.command_bytes:
            raise ValueError('Process receipt helper changed')
        if digest(self.binary.read_bytes()) != self.binary_digest:
            raise ValueError('Original test executable changed')

    def compare(self, corpus_path, native):
        self.check_sources()
        env = dict(os.environ, TRNM_HIA_SETTINGS_ORACLE_CORPUS=str(corpus_path))
        raw, stage = self.command([str(self.binary), '--exact', TEST, '--nocapture',
            '--test-threads=1'], self.isolated, self.output, 'original-settings-corpus',
            env=env, timeout=60)
        self.stages.append(stage)
        self.check_sources()
        original = [json.loads(line.split(MARKER, 1)[1], object_pairs_hook=unique_keys)
                    for line in raw.decode().splitlines() if MARKER in line]
        if [row['name'] for row in original] != [row['name'] for row in native]:
            raise ValueError('Original output cases are missing, extra or reordered')
        controls = [{'name': got['name'], 'status': 'PASS' if got == expected else 'FAIL',
                     'native': expected, 'original': got} for got, expected in zip(original, native)]
        write_json(self.output / 'comparison.json', {'controls': controls})
        if not all(row['status'] == 'PASS' for row in controls):
            raise ValueError('Real original Settings constructor differs from native output')
        return {'status': 'PASS', 'compared': len(controls), 'failed': 0,
                'executable_sha256': self.binary_digest, 'compiler': self.compiler,
                'sources': self.sources, 'stages': self.stages,
                'original_production_function_bytes_preserved': True,
                'original_lib_sha256': digest(self.original_lib),
                'hook_sha256': digest(self.hook), 'declaration_hex': DECLARATION.hex(),
                'process_receipt_helper_sha256': digest(self.command_bytes),
                'runtime_dependency': False}


def qualify(repository, output, rows):
    sys.path.insert(0, str(ROOT))
    from hia.tests.native_support import NativeModule
    from hia.tests.test_node_settings import (SOURCE, OUT_MIN, WORK_MIN, GENESIS_TIME,
                                               request, expected_snapshot)
    production = verify_original(repository)
    checked_tools = (Path(__file__), HOOK, SOURCE_PINS,
                     HIA / 'tests/test_node_settings.py', HIA / 'tests/test_ed25519.py',
                     HIA / 'tests/test_state_root.py', HIA / 'tests/native_support.py',
                     HIA / 'tools/toolchain.py')
    initial_inputs = {path: path.read_bytes() for path in checked_tools}
    corpus_path = output / 'corpus.jsonl'
    corpus_bytes = ''.join(json.dumps(row, sort_keys=True) + '\n' for row in rows).encode()
    corpus_path.write_bytes(corpus_bytes)
    oracle = RustOracle(repository, output / 'original')
    native = []
    with NativeModule(SOURCE, byte_exports=('f0',)) as module:
        write_json(output / 'native-build.json', module.receipt)
        for row in rows:
            timestamp = None if row['timestamp'] is None else int(row['timestamp'])
            raw = request(timestamp)
            before = b'\xa5' * (OUT_MIN + 29)
            scratch = b'\x6b' * (WORK_MIN + 37)
            returned = module.call('f0', [raw, before, scratch], timeout=60).require_returned()
            if returned.arguments[0] != raw or returned.arguments[2][WORK_MIN:] != scratch[WORK_MIN:]:
                raise ValueError('Native constructor changed immutable input or scratch tail')
            if timestamp is not None and not 0 < timestamp < 1 << 63:
                if returned.value != GENESIS_TIME or returned.arguments[1] != before:
                    raise ValueError('Native GENESIS_TIME result differs')
                got = {'name': row['name'], 'status': 'ERROR', 'error': 'GENESIS_TIME',
                       'kind': 'Unclassified', 'code': None,
                       'requires_owner_stop': False, 'has_source': False}
            else:
                expected = expected_snapshot(timestamp)
                if (returned.value != len(expected) or returned.arguments[1][:len(expected)] != expected
                        or returned.arguments[1][len(expected):] != before[len(expected):]):
                    raise ValueError('Native result differs from complete independent byte oracle')
                got = {'name': row['name'], 'status': 'OK',
                       'snapshot_hex': returned.arguments[1][:returned.value].hex()}
            native.append(got)
        write_json(output / 'native-results.json', {'controls': native})
        result = oracle.compare(corpus_path, native)
        if corpus_path.read_bytes() != corpus_bytes:
            raise ValueError('Original corpus changed during qualification')
        if any(path.read_bytes() != raw for path, raw in initial_inputs.items()):
            raise ValueError('Qualification source changed during execution')
        verify_original(repository)
        return {'status': 'PASS', 'native': 'PASS', 'original_rust': result,
                'native_build': module.receipt, 'source_inputs_stable': True,
                'qualification_inputs': {str(path): {'bytes': len(raw), 'sha256': digest(raw)}
                                         for path, raw in initial_inputs.items()},
                'original_pins': production, 'corpus_sha256': digest(corpus_bytes),
                'controls': len(native), 'production_activation': False,
                'four_second_service_budget_qualified': False,
                'file_or_cli_owner_qualified': False, 'whole_node_qualified': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-rust', action='store_true')
    options = parser.parse_args(argv)
    repository = options.repository.resolve(strict=True)
    output = options.output.absolute()
    output.mkdir(mode=0o700)
    started = time.monotonic()
    rows = corpus()
    base = {'schema': 'trnm.hia.settings-original-differential.v1',
            'scope': 'Settings::development(Option<u64>)', 'cases': len(rows),
            'source': {'qualifier_sha256': digest(Path(__file__).read_bytes()),
                       'hook_sha256': digest(HOOK.read_bytes()),
                       'pins_sha256': digest(SOURCE_PINS.read_bytes())},
            'production_runtime_dependency': False, 'required': options.require_rust}
    try:
        base['original_pins'] = verify_original(repository)
        missing = [name for name in ('cargo', 'rustc') if shutil.which(name) is None]
        if missing:
            report = dict(base, status='NOT_RUN', native='NOT_RUN', original_rust='NOT_RUN',
                          missing_tools=missing, elapsed_seconds=time.monotonic()-started)
            write_json(output / 'report.json', report)
            print(json.dumps({'status': 'NOT_RUN', 'missing_tools': missing,
                              'report': str(output / 'report.json')}))
            return 2 if options.require_rust else 0
        result = qualify(repository, output, rows)
        report = dict(base, **result, elapsed_seconds=time.monotonic()-started)
        write_json(output / 'report.json', report)
        print(json.dumps({'status': report['status'], 'controls': len(rows),
                          'report': str(output / 'report.json')}))
        return 0
    except Exception as error:
        report = dict(base, status='FAIL', error=repr(error),
                      original_rust='FAIL_OR_NOT_REACHED; inspect retained process receipts',
                      elapsed_seconds=time.monotonic()-started)
        write_json(output / 'report.json', report)
        (output / 'failure.txt').write_text(traceback.format_exc())
        raise


if __name__ == '__main__':
    raise SystemExit(main())
