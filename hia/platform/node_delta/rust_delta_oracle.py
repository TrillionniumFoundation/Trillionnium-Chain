"""Test-only original Node/SQLite differential; never a production adapter.

The original production sources are copied intact and only a cfg(test) child is
appended to store.rs. The real private original method is called by that child.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]
STORE = 'trillionnium/crates/trnm-pon-node/src/store.rs'
DECLARATION = (b'\n#[cfg(test)]\n#[path = "hia_delta_reference.rs"]\n'
               b'mod hia_delta_reference;\n')
TEST = 'store::hia_delta_reference::evaluate'
MARKER = 'HIA_DELTA_ORACLE:'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def selected_cases():
    from test_delta import MAX, cases
    # Both directions of every 32nd exhaustive state pair, plus every named
    # boundary/random/cancel/changed-row case. A synthetic read error has no
    # corresponding SQLite fault injection and is deliberately not compared.
    return [(index, case) for index, case in enumerate(cases())
            if (index >= 8192 or (index // 2) % 32 == 0)
            and int.from_bytes(case[0][16:24], 'little') == MAX]


class RustOracle:
    def __init__(self, repository, output):
        self.repository, self.output = Path(repository).resolve(), Path(output)
        self.output.mkdir(mode=0o700)
        self.isolated = self.output / 'isolated-source'
        self.isolated.mkdir(mode=0o700)
        sys.path.insert(0, str(self.repository))
        # Reuse the qualified process/timeout receipt helper, including its
        # already-exited cleanup race handling. No original grammar is reused.
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
        store = self.isolated / STORE
        self.original_store = store.read_bytes()
        if b'mod hia_delta_reference' in self.original_store:
            raise ValueError('Original source already contains the test oracle hook')
        self.hook = (HERE / 'rust_delta_reference.rs').read_bytes()
        self.hook_path = store.parent / 'hia_delta_reference.rs'
        if self.hook_path.exists():
            raise FileExistsError('Refusing to replace an original source file')
        self.hook_path.write_bytes(self.hook)
        store.write_bytes(self.original_store + DECLARATION)
        self.stages = []
        version, row = self.command(['rustc', '-Vv'], self.isolated, self.output,
                                   'rustc-version', timeout=10)
        self.stages.append(row)
        self.compiler = version.decode()
        argv = ['cargo', 'test', '--locked', '--manifest-path',
                str(self.isolated / 'trillionnium/Cargo.toml'), '-p', 'trnm-pon-node',
                '--lib', '--no-run', '--message-format=json', '--target-dir',
                str(self.output / 'cargo-target')]
        raw, row = self.command(argv, self.isolated, self.output,
                                'cargo-original-test-build', timeout=600)
        self.stages.append(row)
        events = [json.loads(line) for line in raw.splitlines() if line.startswith(b'{')]
        candidates = [item for item in events if item.get('reason') == 'compiler-artifact'
                      and item['target']['name'] == 'trnm_pon_node'
                      and item.get('executable') and item['profile'].get('test')]
        if len(candidates) != 1:
            raise ValueError('Expected one original Node lib-test executable')
        self.binary = Path(candidates[0]['executable'])
        self.binary_digest = digest(self.binary.read_bytes())
        self.binary_profile = candidates[0]['profile']
        available, row = self.command([str(self.binary), '--list'], self.isolated,
            self.output, 'list-original-tests', timeout=20)
        self.stages.append(row)
        tests = {line.removesuffix(': test') for line in available.decode().splitlines()
                 if line.endswith(': test')}
        if TEST not in tests:
            raise ValueError('Original test oracle was not actually linked')
        self.check_sources()

    def check_sources(self):
        for relative, expected in self.sources.items():
            raw = (self.repository / relative).read_bytes()
            if len(raw) != expected['bytes'] or digest(raw) != expected['sha256']:
                raise ValueError('Original source changed: ' + relative)
            expected_copy = raw + (DECLARATION if relative == STORE else b'')
            if (self.isolated / relative).read_bytes() != expected_copy:
                raise ValueError('Isolated original source changed: ' + relative)
        if self.hook_path.read_bytes() != self.hook or (HERE / 'rust_delta_reference.rs').read_bytes() != self.hook:
            raise ValueError('Original test fixture changed')
        if self.command_source.read_bytes() != self.command_bytes:
            raise ValueError('Process receipt helper changed')
        if digest(self.binary.read_bytes()) != self.binary_digest:
            raise ValueError('Original reference executable changed')

    def verify(self, corpus, native):
        self.check_sources()
        environment = dict(os.environ, TRNM_HIA_DELTA_ORACLE_CORPUS=str(corpus))
        raw, stage = self.command([str(self.binary), '--exact', TEST, '--nocapture',
            '--test-threads=1'], self.isolated, self.output, 'original-delta-corpus',
            env=environment, timeout=180)
        self.stages.append(stage)
        self.check_sources()
        original = [json.loads(line.split(MARKER, 1)[1]) for line in raw.decode().splitlines()
                    if MARKER in line]
        if [row['name'] for row in original] != [row['name'] for row in native]:
            raise ValueError('Original oracle returned a missing, extra or reordered case')
        controls = []
        for expected, row in zip(native, original):
            same = all(row[key] == expected[key]
                       for key in ('status', 'origin', 'token', 'kind', 'progresses', 'kv_hex'))
            controls.append({'name': row['name'], 'status': 'PASS' if same else 'FAIL',
                             'native': expected, 'original': row})
        write_json(self.output / 'comparison.json', {'controls': controls})
        if not all(row['status'] == 'PASS' for row in controls):
            raise ValueError('Original private Node Delta differential failed')
        return {'status': 'PASS', 'compared': len(controls), 'failed': 0,
            'controls': controls, 'compiler': self.compiler,
            'executable_sha256': self.binary_digest, 'cargo_profile': self.binary_profile,
            'sources': self.sources, 'original_production_function_bytes_preserved': True,
            'original_store_sha256': digest(self.original_store),
            'test_hook_sha256': digest(self.hook), 'appended_declaration_hex': DECLARATION.hex(),
            'process_receipt_helper_sha256': digest(self.command_bytes), 'stages': self.stages,
            'runtime_dependency': False, 'outer_reorg_or_native_durability_qualified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', type=Path, default=REPOSITORY)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--require-rust', action='store_true')
    options = parser.parse_args()
    output = options.output.resolve()
    output.mkdir(mode=0o700)
    selected = selected_cases()
    local_sources = {path: path.read_bytes() for path in
        (Path(__file__), HERE / 'rust_delta_reference.rs', HERE / 'test_delta.py', HERE / 'native_support.py')}
    base = {'schema': 'trnm.hia.original-delta-differential.v1',
        'selected_corpus_cases': len(selected),
        'selection': 'Both directions of every 32nd exhaustive pair plus all later cases; synthetic read errors excluded',
        'production_runtime_dependency': False,
        'source_inputs': {str(path): {'bytes': len(raw), 'sha256': digest(raw)}
                         for path, raw in local_sources.items()},
        'original_store_sha256': digest((options.repository / STORE).read_bytes())}
    missing = [name for name in ('cargo', 'rustc') if shutil.which(name) is None]
    if missing:
        report = dict(base, status='NOT_RUN', native='NOT_RUN', original_rust='NOT_RUN',
                      missing_tools=missing, required=options.require_rust)
        write_json(output / 'report.json', report)
        print(json.dumps({'status': 'NOT_RUN', 'missing_tools': missing,
                          'report': str(output / 'report.json')}))
        return 1 if options.require_rust else 0
    try:
        from native_support import Module
        module = Module(HERE / 'delta_fixture.hepta', output / 'native-build')
        native, corpus_rows = [], []
        inputs = output / 'inputs'
        inputs.mkdir(mode=0o700)
        for begin in range(0, len(selected), 100):
            batch = selected[begin:begin + 100]
            sent = [[raw, b'\xa5' * (len(raw) + 256), bytes(used) + b'\x6b' * 37]
                    for _, (raw, used, _, _, _) in batch]
            returned = module.call_many(sent, timeout=60)
            for (index, (raw, used, want, body, _)), answer, arguments in zip(batch, returned, sent):
                data = answer['arguments'][1]
                assert data[:8] == b'NDFOUT01'
                header = struct.unpack('<9Q', data[8:80])
                assert answer['value'] == want[0] and header[:7] == want
                assert header[7] == len(body) and header[8] == 0
                actual = data[80:80 + header[7]]
                assert actual == body
                assert answer['arguments'][2][used:] == arguments[2][used:]
                name = f'case-{index:05}'
                path = inputs / (name + '.raw')
                path.write_bytes(raw)
                corpus_rows.append({'name': name, 'input_path': str(path), 'input_sha256': digest(raw)})
                native.append({'name': name, 'status': header[0], 'origin': header[1],
                    'token': header[2], 'kind': header[3], 'progresses': header[4],
                    'kv_hex': actual.hex()})
        corpus = output / 'corpus.jsonl'
        corpus.write_text(''.join(json.dumps(row, sort_keys=True) + '\n' for row in corpus_rows))
        write_json(output / 'native-results.json', {'build': module.receipt, 'controls': native})
        module.check_pin()
        oracle = RustOracle(options.repository, output / 'original')
        observed = oracle.verify(corpus, native)
        module.check_pin()
        assert all(path.read_bytes() == raw for path, raw in local_sources.items())
        report = dict(base, status='PASS', native='PASS', original_rust=observed,
                      native_build=module.receipt, source_inputs_stable=True)
        write_json(output / 'report.json', report)
        print(json.dumps({'status': 'PASS', 'compared': len(native),
                          'report': str(output / 'report.json')}))
        return 0
    except Exception as error:
        write_json(output / 'report.json', dict(base, status='FAIL', error=repr(error),
            original_rust='FAIL_OR_NOT_REACHED; inspect retained stage receipts'))
        raise


if __name__ == '__main__':
    raise SystemExit(main())
