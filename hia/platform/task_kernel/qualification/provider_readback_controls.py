"""Negative controls for the canonical independent provider reader.

Semantic controls supply isolated, retained byte overlays through the reader's
explicit input callback. They do not modify positive evidence. Artifact hashes
and enclosing manifests are recomputed before checking structural/semantic
refusals. Filesystem/reader-identity controls execute the real reader separately.
No compiler, provider operation, or qualification result is simulated here.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[4]
READER = ROOT / 'hia/platform/task_kernel/readback_provider.py'
CASE_NAMES = (
    'oracle-fence', 'runtime-c-claim', 'production-artifact-omission',
    'provider-source-omission', 'provider-abi-source-omission', 'witness-source-omission',
    'probe-source-omission', 'reader-source-substitution', 'foreign-source-extra',
    'original-c-as-production-image', 'linked-call-retargeting',
    'provider-instruction-rehashed', 'provider-export-rehashed', 'provider-import-rehashed',
    'production-link-probe', 'compiler-input-rehashed', 'compiler-output-foreign-abi',
    'witness-source-closure-omission', 'witness-artifact-omission',
    'witness-layout-rehashed', 'witness-option-string-rehashed', 'witness-pointer-table-rehashed',
    'witness-code-count-rehashed', 'witness-function-instruction-rehashed',
    'witness-input-layout-rehashed', 'abi-probe-rehashed',
    'original-provider-source-omission', 'original-provider-object-substitution',
    'original-compile-graph', 'qualification-source-omission', 'qualification-stage-argv',
    'fault-ordinal-omission', 'fault-ordinal-duplicate', 'failure-not-hit', 'failure-leak',
    'masked-column-nomem', 'actual-return-normalized-away', 'missing-observation',
    'observed-image-substitution', 'caller-pair-claim', 'fd-case-omission',
    'actual-eintr-not-observed', 'foreign-reader-identical-copy',
    'symlinked-provider-directory', 'symlinked-qualification-directory', 'symlinked-artifact',
)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


class Controls:
    def __init__(self, provider, qualification, output):
        self.provider, self.qualification = Path(provider).absolute(), Path(qualification).absolute()
        self.output = Path(output).absolute()
        if not __debug__ or self.output.exists() or self.output.resolve() != self.output or any(
                root == self.output or root in self.output.parents for root in (ROOT, self.provider, self.qualification)):
            raise ValueError('Fresh canonical controls output outside inputs required')
        self.output.mkdir(parents=True, mode=0o700)
        spec = importlib.util.spec_from_file_location('canonical_provider_readback', READER)
        self.reader = importlib.util.module_from_spec(spec);spec.loader.exec_module(self.reader)
        self.positive = self.reader.Reader()
        self.cache = {}
        self.report = {'schema': 'trnm.hia.task-provider.reader-negative-controls.v1',
            'status': 'FAIL', 'finalized': False, 'cases': [],
            'provider_build': str(self.provider / 'build.json'),
            'qualification_report': str(self.qualification / 'report.json'),
            'scope': 'Canonical reader semantic input refusals plus real reader/path refusals',
            'positive_files_modified': False}
        self.save()

    def save(self):
        (self.output / 'report.json').write_bytes(encoded(self.report))

    def original(self, path):
        path = Path(path).absolute()
        if self.output in path.parents:
            self.reader.require(path.resolve() == path and path.is_file(), 'Invalid isolated negative input')
            return path.read_bytes()
        if path not in self.cache:self.cache[path] = self.positive.read(path)
        return self.cache[path]

    def case(self, name, mutate, expected, qualification=False):
        changes = {}
        def get(path):
            path = Path(path).absolute()
            return changes[path] if path in changes else self.original(path)
        def load(path):return json.loads(get(path))
        def put(path, raw):changes[Path(path).absolute()] = raw
        def edit(path, change):
            value = load(path);change(value);put(path, encoded(value))
        mutate(get, load, put, edit)
        # Bind every changed artifact to its enclosing retained build manifest.
        witness = self.provider / 'native-witness'
        if any(path == witness / 'build.json' or witness in path.parents for path in changes):
            value = load(witness / 'build.json')
            for artifact in value['artifacts']:
                path = witness / artifact
                if path in changes:value['artifacts'][artifact] = identity(get(path))
            for artifact, key in (('emitter-input.bin', 'input'), ('emitter-output.bin', 'output')):
                if witness / artifact in changes:
                    value['native_emission'][key] = identity(get(witness / artifact))
                    if key == 'input':value['emitter_input'] = identity(get(witness / artifact))
            put(witness / 'build.json', encoded(value))
        value = load(self.provider / 'build.json')
        for artifact in value['artifacts']:
            path = self.provider / artifact
            if path in changes:value['artifacts'][artifact] = identity(get(path))
        for artifact, key in (('provider-emitter-input.bin', 'input'),
                              ('provider-emitter-output.bin', 'output'), ('provider.o', 'object')):
            if self.provider / artifact in changes:value['native_provider'][key] = identity(get(self.provider / artifact))
        put(self.provider / 'build.json', encoded(value))
        oracle = self.qualification / 'original'
        if any(path == oracle / 'build.json' or oracle in path.parents for path in changes):
            value = load(oracle / 'build.json')
            for artifact in value['artifacts']:
                path = oracle / artifact
                if path in changes:value['artifacts'][artifact] = identity(get(path))
            put(oracle / 'build.json', encoded(value))
        if qualification:
            value = load(self.qualification / 'report.json')
            for namespace in ('source_before', 'source_after'):
                for path in value[namespace]:
                    if Path(path) in changes:value[namespace][path] = identity(get(path))
            put(self.qualification / 'report.json', encoded(value))
        directory = self.output / name;directory.mkdir()
        mapping = []
        for index, (path, raw) in enumerate(sorted(changes.items())):
            destination = directory / ('input-' + str(index) + '.bin');destination.write_bytes(raw)
            mapping.append({'requested_path': str(path), 'isolated_input': str(destination),
                            'original': identity(self.original(path)), 'negative': identity(raw)})
        (directory / 'overlays.json').write_bytes(encoded(mapping))
        visited = set()
        def read(path, expected_identity=None):
            path = Path(path).absolute();raw = get(path);visited.add(str(path))
            if expected_identity is not None:
                self.reader.require(identity(raw) == {key: expected_identity[key] for key in ('bytes', 'sha256')},
                                    'Negative input artifact hash mismatch: ' + str(path))
            return raw
        started = time.monotonic_ns()
        try:
            self.reader.check_provider(read, self.provider, ROOT)
            if qualification:self.reader.check_qualification(read, self.qualification, self.provider)
        except ValueError as error:
            self.reader.require(expected in str(error), 'Wrong refusal for ' + name + ': ' + str(error))
            row = {'name': name, 'kind': 'isolated-semantic-input', 'status': 'PASS',
                   'actual_refusal': str(error), 'expected_refusal': expected,
                   'manifest_hashes_recomputed': True, 'input_overlay': str(directory / 'overlays.json'),
                   'checked_inputs': len(visited), 'elapsed_ns': time.monotonic_ns() - started}
        else:
            raise ValueError('Reader admitted invalid semantic input: ' + name)
        self.report['cases'].append(row);self.save()

    def process_case(self, name, argv, expected):
        started = time.monotonic_ns()
        result = subprocess.run(list(map(str, argv)), input=b'', capture_output=True, cwd=ROOT, timeout=45)
        for stream, raw in (('stdin', b''), ('stdout', result.stdout), ('stderr', result.stderr)):
            (self.output / (name + '.' + stream + '.raw')).write_bytes(raw)
        self.reader.require(result.returncode != 0 and expected.encode() in result.stderr,
                            'Missing actual subprocess reader refusal: ' + name)
        self.report['cases'].append({'name': name, 'kind': 'actual-reader-subprocess', 'status': 'PASS',
            'argv': list(map(str, argv)), 'cwd': str(ROOT), 'exit_code': result.returncode,
            'expected_refusal': expected, 'elapsed_ns': time.monotonic_ns() - started})
        self.save()

    def run(self):
        try:
            self.original(READER);self.original(Path(__file__).resolve())
            self.reader.check_provider(self.positive.read, self.provider, ROOT)
            self.reader.check_qualification(self.positive.read, self.qualification, self.provider)
            for path in list(self.positive.checked):self.original(path)
            self.report['positive_checked_files'] = len(self.positive.checked)
            self.report['source_before'] = copy.deepcopy(self.positive.checked)
            self.report['reader'] = identity(self.original(READER))
            self.report['harness'] = identity(self.original(Path(__file__).resolve()))
            self.save()
            p, q = self.provider, self.qualification
            w, ob = p / 'native-witness', q / 'original'
            b, qb, wb = p / 'build.json', q / 'report.json', w / 'build.json'
            task = ROOT / 'hia/platform/task_kernel'
            def changed(path, change):return lambda get, load, put, edit: edit(path, change)
            self.case('oracle-fence', changed(b, lambda value: value.update(fence=self.reader.ORACLE_FENCE)),
                      'Legacy C oracle cannot be a production provider')
            self.case('runtime-c-claim', changed(b, lambda value: value['claims'].update(original_project_c_linked=True)),
                      'Provider runtime boundary claim differs')
            self.case('production-artifact-omission', changed(b, lambda value: value['artifacts'].pop('sqlite.o')),
                      'Production provider artifact roster differs')
            def omit_source(path, name):
                def mutate(get, load, put, edit):
                    value = load(path)
                    for namespace in ('source_before', 'source_after'):value[namespace].pop(str(name))
                    put(path, encoded(value))
                return mutate
            for label, source in (('provider', 'provider_native.hepta'), ('provider-abi', 'provider_abi.json'),
                                  ('witness', 'witness_emitter.hepta'), ('probe', 'qualification/provider_abi_probe.c')):
                self.case(label + '-source-omission', omit_source(b, task / source),
                          'Provider canonical source namespace is missing or substituted')
            foreign_source = self.output / 'foreign-reader-source.py';foreign_source.write_bytes(self.original(READER))
            def substitute_source(get, load, put, edit):
                value = load(b)
                for namespace in ('source_before', 'source_after'):
                    value[namespace][str(foreign_source)] = value[namespace].pop(str(READER))
                put(b, encoded(value))
            self.case('reader-source-substitution', substitute_source,
                      'Provider canonical source namespace is missing or substituted')
            def extra_source(get, load, put, edit):
                value = load(b)
                for namespace in ('source_before', 'source_after'):
                    value[namespace][str(foreign_source)] = identity(foreign_source.read_bytes())
                put(b, encoded(value))
            self.case('foreign-source-extra', extra_source, 'Provider canonical source namespace is missing or substituted')
            self.case('original-c-as-production-image', lambda get, load, put, edit: put(p / 'provider.so', get(ob / 'provider.so')),
                      'Final provider image is missing native lifecycle/helper functions')
            def retarget(get, load, put, edit):
                obj = self.reader.elf_object(get(p / 'provider.o'))
                offset = obj['relocations'][0][0]
                name, (start, size) = next((name, bounds) for name, bounds in obj['functions'].items()
                                          if bounds[0] <= offset < sum(bounds))
                raw = bytearray(get(p / 'provider.so'));header = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
                sections = [struct.unpack_from('<IIQQQQIIQQ', raw, header[6] + 64 * i) for i in range(header[12])]
                position = None
                for section in sections:
                    if section[1] != 2:continue
                    strings = sections[section[6]];names = raw[strings[4]:strings[4] + strings[5]]
                    for pos in range(section[4], section[4] + section[5], 24):
                        index, info, other, shndx, address, extent = struct.unpack_from('<IBBHQQ', raw, pos)
                        symbol = names[index:names.index(0, index)].decode('ascii')
                        if symbol == name:
                            code = sections[shndx];position = code[4] + address - code[3] + offset - start
                self.reader.require(position is not None, 'Missing linked call fixture')
                struct.pack_into('<i', raw, position, struct.unpack_from('<i', raw, position)[0] + 1)
                put(p / 'provider.so', bytes(raw))
            self.case('linked-call-retargeting', retarget, 'Native foreign call does not target an admitted PLT slot')
            def provider_object(change):
                def mutate(get, load, put, edit):
                    raw = bytearray(get(p / 'provider.o'));change(raw)
                    put(p / 'provider.o', bytes(raw))
                    put(p / 'provider-emitter-output.bin', struct.pack('<Q', len(raw)) + raw)
                return mutate
            self.case('provider-instruction-rehashed', provider_object(lambda raw: raw.__setitem__(64, raw[64] ^ 1)),
                      'Provider ELF differs from canonical HIA literal emission despite rehashed manifests')
            def replace_once(raw, before, after):
                index = raw.index(before);raw[index:index + len(before)] = after
            self.case('provider-export-rehashed', provider_object(lambda raw: replace_once(raw,
                b'trnm_task_provider_free\0', b'trnm_task_provider_frex\0')),
                'Provider ELF differs from canonical HIA literal emission despite rehashed manifests')
            self.case('provider-import-rehashed', provider_object(lambda raw: replace_once(raw,
                b'sqlite3_step\0', b'sqlite3_stap\0')),
                'Provider ELF differs from canonical HIA literal emission despite rehashed manifests')
            def link_probe(get, load, put, edit):
                value = load(b);next(row for row in value['stages'] if row['name'] == 'link')['argv'].insert(3, str(w / 'probe.o'))
                put(b, encoded(value))
            self.case('production-link-probe', link_probe, 'Production provider link includes a C provider or probe')
            def compiler_change(output=False):
                def mutate(get, load, put, edit):
                    value = load(b);receipt = value['native_provider']['compiler_stages'][0]
                    stage = p / 'pinned-native/compile-provider-emitter'
                    if output:
                        raw = get(p / 'provider.o');put(p / 'provider-emitter.o', raw);put(stage / 'stdout.raw', raw)
                        receipt.update(output_bytes=len(raw), output_sha256=identity(raw)['sha256'])
                    else:
                        raw = get(p / 'provider-emitter.hepta') + b'\n'
                        put(p / 'provider-emitter.hepta', raw);put(stage / 'stdin.raw', raw)
                        receipt.update(input_bytes=len(raw), input_sha256=identity(raw)['sha256'])
                    put(stage / 'receipt.json', encoded(receipt));put(b, encoded(value))
                return mutate
            self.case('compiler-input-rehashed', compiler_change(), 'Native provider compiler source bytes differ')
            self.case('compiler-output-foreign-abi', compiler_change(True), 'Native HIA emitter object has a substituted foreign ABI')
            self.case('witness-source-closure-omission', omit_source(wb, task / 'witness_emitter.hepta'),
                      'Native witness canonical source namespace is missing or substituted')
            self.case('witness-artifact-omission', changed(wb, lambda value: value['artifacts'].pop('probe.so')),
                      'Native witness artifact roster differs')
            def witness_object(change):
                def mutate(get, load, put, edit):
                    raw = bytearray(get(w / 'witness.o'));change(raw, get(w / 'emitter-input.bin'))
                    put(w / 'witness.o', bytes(raw));put(p / 'witness.o', bytes(raw))
                    put(w / 'emitter-output.bin', struct.pack('<Q', len(raw)) + raw)
                return mutate
            self.case('witness-layout-rehashed', witness_object(lambda raw, request: struct.pack_into('<Q', raw, 64 + 96, 16)),
                      'Native witness readonly data layout differs')
            def string_change(raw, request):
                count = struct.unpack_from('<Q', request, 16)[0];index = 64 + 248 + 8 * count;raw[index] ^= 1
            self.case('witness-option-string-rehashed', witness_object(string_change),
                      'Witness readonly strings differ from actual probe input')
            self.case('witness-pointer-table-rehashed', witness_object(lambda raw, request:
                struct.pack_into('<Q', raw, 64 + 248, 1)), 'Witness option pointer table differs')
            self.case('witness-code-count-rehashed', witness_object(lambda raw, request:
                struct.pack_into('<I', raw, 64 + 34, 0)), 'Witness dynamic code operands differ')
            self.case('witness-function-instruction-rehashed', witness_object(lambda raw, request:
                raw.__setitem__(64, raw[64] ^ 1)), 'Native witness function instruction sequence differs')
            def witness_input(get, load, put, edit):
                raw = bytearray(get(w / 'emitter-input.bin'));struct.pack_into('<Q', raw, 40, 16)
                put(w / 'emitter-input.bin', bytes(raw))
            self.case('witness-input-layout-rehashed', witness_input, 'Witness input layout or complete extent differs')
            def probe(get, load, put, edit):
                value = load(p / 'provider-abi.json');value['mutex_bytes'] = 48
                put(p / 'provider-abi.json', encoded(value));put(p / 'observe-provider-abi.stdout.raw', encoded(value))
                edit(b, lambda report: report.update(native_provider_abi=value))
            self.case('abi-probe-rehashed', probe, 'Actual platform ABI probe differs from native owner layout')
            self.case('original-provider-source-omission', omit_source(ob / 'build.json', task / 'provider.c'),
                      'Original C oracle canonical source namespace differs', True)
            self.case('original-provider-object-substitution', lambda get, load, put, edit:
                      put(ob / 'provider.o', get(p / 'provider.o')),
                      'Original comparison provider object is not the complete C translation unit', True)
            def original_compile(get, load, put, edit):
                value = load(ob / 'build.json')
                next(row for row in value['stages'] if row['name'] == 'compile-provider')['argv'][-3] = str(task / 'provider_native.hepta')
                put(ob / 'build.json', encoded(value))
            self.case('original-compile-graph', original_compile, 'Original C provider actual compile/link graph differs', True)
            self.case('qualification-source-omission', omit_source(qb, task / 'qualification/provider_fault_observer.c'),
                      'Provider qualification canonical source namespace is missing or substituted', True)
            self.case('qualification-stage-argv', changed(qb, lambda value: value['stages'][3]['argv'].append('--substituted')),
                      'Actual provider qualification stage/argv graph differs', True)
            self.case('fault-ordinal-omission', changed(qb, lambda value: value['allocation_cases'].pop()),
                      'Allocation failure ordinal roster differs', True)
            self.case('fault-ordinal-duplicate', changed(qb, lambda value:
                      value['allocation_cases'].__setitem__(1, copy.deepcopy(value['allocation_cases'][0]))),
                      'Allocation failure ordinal roster differs', True)
            def fault_both(suffix, change):
                def mutate(get, load, put, edit):
                    for label in ('original', 'native'):edit(q / (label + suffix), change)
                return mutate
            self.case('failure-not-hit', fault_both('-allocation-open-0.stdout.raw', lambda value:
                      value.update(actual_failure_hit=False)), 'Actual allocation failure/cleanup differs', True)
            self.case('failure-leak', fault_both('-allocation-open-0.stdout.raw', lambda value:
                      value.update(live_allocations=1)), 'Actual allocation failure/cleanup differs', True)
            self.case('masked-column-nomem', fault_both('-allocation-column-0.stdout.raw', lambda value:
                      value.update(code=0)), 'Actual SQLite NOMEM was lost', True)
            def masked_response(get, load, put, edit):
                value = load(q / 'native-observations/observation.json')
                row = next(row for row in value['calls'] if row['op'] == 1 and len(row['actual_response_hex']) >= 48)
                raw = bytearray.fromhex(row['actual_response_hex']);raw[0] ^= 1;row['actual_response_hex'] = raw.hex()
                put(q / 'native-observations/observation.json', encoded(value))
            self.case('actual-return-normalized-away', masked_response,
                      'Provider normalization concealed an actual return value', True)
            self.case('missing-observation', changed(q / 'native-observations/observation.json', lambda value:
                      value['calls'].pop()), 'Complete original/native call roster differs', True)
            self.case('observed-image-substitution', changed(q / 'native-observations/observation.json', lambda value:
                      value.update(library=str(ob / 'provider.so'), library_sha256=identity(self.original(ob / 'provider.so'))['sha256'])),
                      'Observed original/native library identity differs', True)
            self.case('caller-pair-claim', changed(qb, lambda value: value['pairs'][0].update(equal=False)),
                      'Native emitter refusal or exact pair roster differs', True)
            def missing_fd(get, load, put, edit):
                raw = get(q / 'original-real-descriptor-controls.stdout.raw').splitlines()
                put(q / 'original-real-descriptor-controls.stdout.raw', b'\n'.join(raw[1:]) + b'\n')
            self.case('fd-case-omission', missing_fd, 'Missing actual descriptor lifecycle observation', True)
            def missing_eintr(get, load, put, edit):
                for label in ('original', 'native'):
                    path = q / (label + '-real-read-controls.stdout.raw')
                    rows = [json.loads(line) for line in get(path).splitlines()]
                    row = next(row for row in rows if row.get('case') == 'actual-fifo-eintr')
                    raw = bytearray.fromhex(row['actual_output']);struct.pack_into('<Q', raw, 0, 0);row['actual_output'] = raw.hex()
                    put(path, b''.join((json.dumps(row) + '\n').encode() for row in rows))
            self.case('actual-eintr-not-observed', missing_eintr, 'Actual EINTR errno differs', True)
            def command(reader, provider, qualification, name):
                return [sys.executable, reader, '--provider', provider, '--qualification', qualification,
                        '--repo', ROOT, '--output', self.output / (name + '-result')]
            identical = self.output / 'identical-reader.py';shutil.copyfile(READER, identical)
            self.process_case('foreign-reader-identical-copy', command(identical, p, q, 'foreign-reader'),
                              'Reader must be the canonical current provider reader')
            provider_alias = self.output / 'provider-alias';provider_alias.symlink_to(p, target_is_directory=True)
            self.process_case('symlinked-provider-directory', command(READER, provider_alias, q, 'provider-alias'),
                              'Symlinked or noncanonical provider evidence path')
            qualification_alias = self.output / 'qualification-alias';qualification_alias.symlink_to(q, target_is_directory=True)
            self.process_case('symlinked-qualification-directory', command(READER, p, qualification_alias, 'qualification-alias'),
                              'Symlinked or noncanonical provider evidence path')
            artifact_alias = self.output / 'provider-artifact-alias.o';artifact_alias.symlink_to(p / 'provider.o')
            try:self.reader.Reader().read(artifact_alias)
            except ValueError as error:
                self.reader.require('Symlinked or noncanonical provider evidence path' in str(error), 'Wrong artifact symlink refusal')
                self.report['cases'].append({'name': 'symlinked-artifact', 'kind': 'actual-filesystem-input',
                    'status': 'PASS', 'actual_refusal': str(error), 'path': str(artifact_alias)})
            else:raise ValueError('Symlinked artifact was admitted')
            self.reader.require(tuple(row['name'] for row in self.report['cases']) == CASE_NAMES,
                                'Reader negative control roster differs')
            for path, expected in list(self.positive.checked.items()):self.positive.read(path, expected)
            self.report.update(status='PASS', finalized=True, negative_controls=len(CASE_NAMES),
                positive_source_unchanged=True, source_after=copy.deepcopy(self.positive.checked))
            self.reader.require(self.report['source_after'] == self.report['source_before'],
                                'Positive evidence changed during negative controls')
            self.save()
        except BaseException as error:
            self.report.update(status='FAIL', finalized=False, failure=repr(error));self.save();raise
        print(json.dumps({'status': 'PASS', 'negative_controls': len(CASE_NAMES), 'positive_source_unchanged': True}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--provider', type=Path, required=True)
    parser.add_argument('--qualification', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    Controls(args.provider, args.qualification, args.output).run()


if __name__ == '__main__':main()
