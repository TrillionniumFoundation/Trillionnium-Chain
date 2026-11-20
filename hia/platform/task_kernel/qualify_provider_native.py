"""Fresh original-C/native-HIA provider differential and resource qualification.

The original comparison image has a different, qualification-only build fence.
Every observation process owns exactly one SQLite image. C interception code is
linked only into isolated fault observers, never into the production provider.
"""
from __future__ import annotations

import argparse
import ctypes
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
Q = HERE / 'qualification'
sys.path.insert(0, str(ROOT))
from hia.platform.task_kernel.build_provider import FENCE, ORACLE_FENCE, identity, need, write_json

FAULT_SCENARIOS = ('new-calloc', 'new-mutex', 'open', 'prepare', 'column',
                   'invalid-path-flags', 'close-eintr', 'close-eio')
FAULT_WRAPS = ('malloc', 'calloc', 'realloc', 'free', 'close', 'pthread_mutex_init',
               'pthread_mutex_destroy', 'sqlite3_finalize', 'sqlite3_close_v2')
FD_WRAPS = ('malloc', 'calloc', 'open', 'close', 'read', 'sqlite3_finalize', 'sqlite3_close_v2')


class Qualification:
    def __init__(self, provider, output):
        self.provider = Path(provider).resolve(strict=True)
        self.output = Path(output).absolute()
        need(self.output.resolve() == self.output and not self.output.exists() and ROOT not in self.output.parents,
             'Fresh canonical evidence outside checkout required')
        self.output.mkdir(parents=True, mode=0o700)
        self.report = {'schema': 'trnm.hia.task-provider.native-qualification.v1', 'status': 'FAIL',
                       'finalized': False, 'stages': [], 'pairs': [], 'allocation_cases': [],
                       'observer_artifacts': {},
                       'scope': 'Complete 6-entry provider lifecycle and 29-op mechanical ABI; external SQLite remains C',
                       'whole_chain_native': False, 'original_c_in_production_runtime': False}
        self.sources = {}
        self.save()

    def save(self):
        write_json(self.output / 'report.json', self.report)

    def capture(self, path, expected=None):
        path = Path(path).resolve(strict=True)
        observed = identity(path)
        need(expected is None or observed == expected, 'Source/artifact changed: ' + str(path))
        need(str(path) not in self.sources or self.sources[str(path)] == observed, 'Recaptured input changed')
        self.sources[str(path)] = observed

    def stage(self, name, argv, timeout=60):
        row = {'name': name, 'argv': list(map(str, argv)), 'cwd': str(ROOT),
               'started': True, 'completed': False, 'timeout_seconds': timeout}
        self.report['stages'].append(row); self.save()
        (self.output / (name + '.stdin.raw')).write_bytes(b'')
        started = time.monotonic_ns()
        try:
            result = subprocess.run(row['argv'], input=b'', capture_output=True, cwd=ROOT, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            (self.output / (name + '.stdout.raw')).write_bytes(error.stdout or b'')
            (self.output / (name + '.stderr.raw')).write_bytes(error.stderr or b'')
            row.update(error='TimeoutExpired', elapsed_ns=time.monotonic_ns() - started)
            self.save(); raise
        (self.output / (name + '.stdout.raw')).write_bytes(result.stdout)
        (self.output / (name + '.stderr.raw')).write_bytes(result.stderr)
        row.update(completed=True, exit_code=result.returncode, elapsed_ns=time.monotonic_ns() - started)
        self.save(); result.check_returncode()
        return result.stdout

    def run(self):
        try:
            production = json.loads((self.provider / 'build.json').read_text())
            need(production['status'] == 'PASS' and production['finalized'] and production['fence'] == FENCE and
                 production['qualification_only_original_oracle'] is False and
                 production['source_before'] == production['source_after'], 'Production provider is not qualified')
            for path, value in production['source_before'].items(): self.capture(path, value)
            for name, value in production['artifacts'].items(): self.capture(self.provider / name, value)
            self.capture(production['compiler']['path'],
                         {key: production['compiler'][key] for key in ('bytes', 'sha256')})
            for path in (Path(__file__), Q / 'native_provider_observer.py', Q / 'provider_fault_observer.c',
                         Q / 'fd_observer.c', Q / 'read_observer.c', Q / 'native_witness_observer.py',
                         Q / 'provider_controls.py', HERE / 'provider.c'):
                self.capture(path)
            self.capture(self.provider / 'build.json')
            self.report['source_before'] = self.sources.copy()
            original_source = self.stage('original-source-git', ['git', 'show', 'HEAD:hia/platform/task_kernel/provider.c'])
            need(original_source == (HERE / 'provider.c').read_bytes(), 'Original C oracle differs from retained Git source')
            dependency = next(Path(path).parent for path in production['source_before']
                              if path.endswith('/libsqlite3-sys-0.39.1/Cargo.toml'))
            original = self.output / 'original'
            self.stage('build-original-oracle', [sys.executable, HERE / 'build_provider.py', '--dependency', dependency,
                       '--output', original, '--original-oracle'], 600)
            oracle = json.loads((original / 'build.json').read_text())
            need(oracle['status'] == 'PASS' and oracle['fence'] == ORACLE_FENCE and
                 oracle['qualification_only_original_oracle'] is True, 'Original comparison fence differs')
            need(identity(original / 'sqlite.o') == identity(self.provider / 'sqlite.o'),
                 'Comparisons do not use identical actual external SQLite code')
            self.report['original_build'] = str(original / 'build.json')
            self.report['native_build'] = str(self.provider / 'build.json')
            self.report['original_source'] = identity(HERE / 'provider.c')
            observations = {}
            for label, directory in (('original', original), ('native', self.provider)):
                destination = self.output / (label + '-observations')
                self.stage(label + '-29-operations', [sys.executable, Q / 'native_provider_observer.py',
                           '--library', directory / 'provider.so', '--output', destination], 120)
                observations[label] = json.loads((destination / 'observation.json').read_text())
                need(observations[label]['status'] == 'PASS' and observations[label]['finalized'], 'Incomplete provider observations')
            old, new = observations['original'], observations['native']
            need(len(old['calls']) == len(new['calls']), 'Provider differential roster differs')
            for left, right in zip(old['calls'], new['calls']):
                keys = ('name', 'op', 'capacity', 'normalized')
                equal = all(left[key] == right[key] for key in keys)
                self.report['pairs'].append({'name': left['name'], 'op': left['op'], 'equal': equal})
                need(equal, 'Original/native provider mismatch: ' + left['name'])
            for key in ('resource_checks', 'concurrent', 'operation_coverage'):
                need(old[key] == new[key], 'Original/native resource/concurrency mismatch: ' + key)
            need(old['operation_coverage'] == list(range(1, 30)) and len(old['calls']) == 1182 and
                 len(old['concurrent']) == 64, 'Required complete operation/concurrency roster differs')
            self.report.update(actual_original_native_pairs=len(old['calls']),
                               concurrent_transactions=64, concurrent_provider_calls=256,
                               public_abi_entries=6, operation_coverage=list(range(1, 30)))
            self.emitter_controls()
            self.foreign_faults(original, production, dependency)
            self.stage('native-witness-controls', [sys.executable, Q / 'native_witness_observer.py',
                       '--build', self.provider / 'native-witness', '--output', self.output / 'witness-controls'], 120)
            witness = json.loads((self.output / 'witness-controls/report.json').read_text())
            need(witness['status'] == 'PASS' and witness['finalized'], 'Independent native witness controls failed')
            self.stage('provider-negative-controls', [sys.executable, Q / 'provider_controls.py', self.provider,
                       self.output / 'provider-controls'], 180)
            negatives = json.loads((self.output / 'provider-controls/report.json').read_text())
            need(negatives['status'] == 'PASS' and negatives['finalized'] and negatives['negative_controls'] == 8,
                 'Provider build rejection controls differ')
            self.report['source_after'] = {path: identity(path) for path in self.sources}
            need(self.report['source_after'] == self.report['source_before'], 'Qualification input changed')
            need(all(identity(self.output / name) == value for name, value in self.report['observer_artifacts'].items()),
                 'A qualification observer changed during execution')
            self.report.update(status='PASS', finalized=True,
                               exact_c_comparison=True, native_witness_controls=True,
                               build_negative_controls=8, oracle_runtime_fallback=False)
            self.save()
            return self.report
        except BaseException as error:
            self.report.update(status='FAIL', finalized=False, failure=repr(error));self.save();raise

    def emitter_controls(self):
        emitter = ctypes.CDLL(str(self.provider / 'provider-emitter.so'))
        function = emitter.f0
        function.argtypes = [ctypes.c_void_p, ctypes.c_uint64] * 3
        function.restype = ctypes.c_uint32
        expected = (self.provider / 'provider.o').read_bytes()
        cases = []
        vectors = [(raw, len(expected) + 8, 100) for raw in (b'', b'TKPROV0', b'TKPROV00', b'TKPROV01x', bytes(8))]
        vectors += [(b'TKPROV01', cap, 101) for cap in (0, 1, 7, 8, len(expected) + 7)]
        vectors += [(b'TKPROV01', cap, 0) for cap in (len(expected) + 8, len(expected) + 72)]
        for index, (raw, cap, wanted) in enumerate(vectors):
            source = ctypes.create_string_buffer(raw)
            target = ctypes.create_string_buffer(bytes([0xA5]) * (cap + 64), cap + 64)
            scratch = ctypes.create_string_buffer(1)
            status = function(source, len(raw), target, cap, scratch, 0)
            need(status == wanted and source.raw[:-1] == raw, 'Native provider emitter input/refusal differs')
            if status:
                need(target.raw == bytes([0xA5]) * (cap + 64), 'Refused emitter wrote output')
            else:
                need(target.raw[:len(expected) + 8] == struct.pack('<Q', len(expected)) + expected and
                     target.raw[len(expected) + 8:] == bytes([0xA5]) * (cap + 56 - len(expected)),
                     'Actual emitted ELF or output guard differs')
            cases.append({'index': index, 'input': raw.hex(), 'capacity': cap, 'actual_status': status})
        self.report['emitter_controls'] = cases; self.save()

    def foreign_faults(self, original, production, dependency):
        cc = production['compiler']['path']
        self.capture(cc)
        baseline = {}
        for label, directory in (('original', original), ('native', self.provider)):
            work = self.output / (label + '-faults'); work.mkdir()
            objects = [directory / (name + '.o') for name in ('provider', 'sqlite', 'witness')]
            common = [cc, '-std=c11', '-O0', '-fPIC', '-Wall', '-Wextra', '-Werror']
            self.stage(label + '-compile-fault-observer', [*common, '-I', dependency / 'sqlite3',
                       Q / 'provider_fault_observer.c', *objects, *['-Wl,--wrap=' + name for name in FAULT_WRAPS],
                       '-ldl', '-lm', '-lpthread', '-o', work / 'fault-observer'])
            baseline[label] = {}
            for scenario in FAULT_SCENARIOS:
                raw = self.stage(label + '-fault-' + scenario + '-baseline',
                                 [work / 'fault-observer', scenario, '-1', work / 'target'], 30)
                row = json.loads(raw); need(row['status'] == 'PASS', 'Fault baseline failed')
                baseline[label][scenario] = row
            fd_wrap = ['-Wl,--wrap=' + name for name in FD_WRAPS]
            self.stage(label + '-compile-fd-observer', [*common, Q / 'fd_observer.c', *objects,
                       *fd_wrap, '-ldl', '-lm', '-lpthread', '-o', work / 'fd-observer'])
            self.stage(label + '-compile-fd-wrapper', [*common, '-DTRNM_OBSERVER_NO_MAIN', '-c',
                       Q / 'fd_observer.c', '-o', work / 'fd-wrapper.o'])
            self.stage(label + '-compile-read-observer', [*common, Q / 'read_observer.c', work / 'fd-wrapper.o',
                       *objects, *fd_wrap, '-ldl', '-lm', '-lpthread', '-o', work / 'read-observer'])
            for name in ('fault-observer', 'fd-observer', 'fd-wrapper.o', 'read-observer'):
                self.report['observer_artifacts'][str((work / name).relative_to(self.output))] = identity(work / name)
            self.save()
            descriptor = self.stage(label + '-real-descriptor-controls', [work / 'fd-observer', work / 'fd-target'], 30)
            reads = self.stage(label + '-real-read-controls', [work / 'read-observer', work], 30)
            need(json.loads(descriptor.splitlines()[-1]) == {'status': 'PASS', 'cases': 8}, 'Real descriptor controls differ')
            need(json.loads(reads.splitlines()[-1]) == {'status': 'PASS', 'cases': 13, 'real_signal_interruptions': 1},
                 'Real short-read/EOF/EINTR controls differ')
        need(baseline['original'] == baseline['native'], 'Allocation/error baseline differs')
        need(baseline['original']['column']['allocation_calls'] > 0, 'Missing actual SQLite column allocation case')
        count = 0
        for scenario in ('open', 'prepare', 'column', 'invalid-path-flags'):
            calls = baseline['original'][scenario]['allocation_calls']
            need(0 < calls < 8192, 'Unexpected observed allocation fixture roster')
            for index in range(calls):
                values = {}
                for label in ('original', 'native'):
                    work = self.output / (label + '-faults')
                    raw = self.stage(label + '-allocation-' + scenario + '-' + str(index),
                                     [work / 'fault-observer', scenario, str(index), work / 'target'], 30)
                    values[label] = json.loads(raw)
                    need(values[label]['status'] == 'PASS' and values[label]['actual_failure_hit'] is True and
                         values[label]['live_allocations'] == values[label]['sqlite_memory'] == 0,
                         'Allocation failure was not actually exercised and cleaned')
                equal = values['original'] == values['native']
                self.report['allocation_cases'].append({'scenario': scenario, 'index': index,
                                                        'equal': equal, 'actual': values['native']})
                self.save();need(equal, 'Original/native allocation failure differs: ' + scenario + '/' + str(index))
                count += 1
        self.report.update(actual_allocation_failure_pairs=count, actual_constructor_failure_pairs=2,
                           actual_close_error_pairs=2, direct_descriptor_cases_per_image=8,
                           direct_read_cases_per_image=13, real_signal_interruptions_per_image=1)
        self.report['allocation_baselines'] = baseline['native']; self.save()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--provider', required=True)
    parser.add_argument('--output', required=True)
    options = parser.parse_args()
    result = Qualification(options.provider, options.output).run()
    print(json.dumps({key: result[key] for key in ('status', 'actual_original_native_pairs',
          'actual_allocation_failure_pairs', 'actual_constructor_failure_pairs',
          'actual_close_error_pairs', 'concurrent_provider_calls')}))


if __name__ == '__main__':
    main()
