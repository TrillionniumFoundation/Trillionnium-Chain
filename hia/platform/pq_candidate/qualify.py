"""Run complete original, native Candidate, ownership and readback qualification."""
from __future__ import annotations
from pathlib import Path
import argparse
import json
import lzma
import os
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from hia.platform.pq_candidate.qualification.contract import (
    COMPILER, LIMITS, METHODS, PREFIX, ROOT, SCHEMA, canonical, check_platform_environment,
    document, identity, input_map, inventory, jsonl, need, normalize, read, regular, sha,
)
from hia.platform.pq_candidate.qualification import cases
from hia.platform.pq_auth.qualification.supervision import run as supervise
from hia.tools import ml_dsa_original, qualify_ml_dsa


class Qualification:
    def __init__(self, args):
        guard = ml_dsa_original.check_environment(ROOT, os.environ)
        platform_guard = check_platform_environment(os.environ)
        need(os.environ.get('HIA_NATIVE_COMPILER_SHA256') == COMPILER, 'different native compiler pin')
        self.args, self.output = args, args.output.absolute()
        need(not self.output.exists() and not self.output.is_symlink(), 'qualification output must be fresh')
        regular(self.output.parent, directory=True)
        self.provider = document(regular(args.provider_receipt).read_bytes())
        qualify_ml_dsa.validate_provider(self.provider)
        self.sources = input_map(ROOT)
        self.output.mkdir(mode=0o700)
        self.started = time.monotonic()
        self.report = {'schema': SCHEMA, 'status': 'FAIL', 'limits': LIMITS,
            'environment_guard': guard, 'platform_environment_guard': platform_guard,
            'source_inputs': self.sources, 'source_set_sha256': sha(canonical(self.sources)),
            'repository': str(ROOT), 'output': str(self.output),
            'python': str(Path(sys.executable).resolve(strict=True)), 'rust_bin': str(args.rust_bin.absolute()),
            'stages': [], 'tools': {}, 'original_method_roster': list(METHODS),
            'full_host_dependency_closure_claimed': False}
        for name, expected in self.sources.items():
            raw = read(ROOT, name)
            need(sha(raw) == expected, 'source changed before capture')
            target = self.output / 'inputs' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        (self.output / 'provider.json').write_bytes(regular(args.provider_receipt).read_bytes())
        (self.output / 'provider.env').write_bytes(regular(args.provider_environment).read_bytes())
        for index, row in enumerate(self.provider['native_backend_inputs']):
            target = self.output / 'provider' / (f'{index:02d}-' + Path(row['path']).name)
            target.parent.mkdir(exist_ok=True)
            raw = regular(row['path']).read_bytes()
            need({'bytes': len(raw), 'sha256': sha(raw)} == {key: row[key] for key in ('bytes', 'sha256')},
                 'live provider changed before capture')
            target.write_bytes(raw)
        (self.output / 'tools').mkdir()
        for name in ('cc', 'ld', 'nm', 'objcopy', 'objdump', 'python'):
            path = Path(self.report['python']) if name == 'python' else Path('/usr/bin', name).resolve(strict=True)
            raw = regular(path).read_bytes()
            target = self.output / 'tools' / name
            target.write_bytes(raw)
            self.report['tools'][name] = {'path': str(path), 'retained': 'tools/' + name, **identity(target)}
        self.save()

    def save(self):
        self.report['seconds'] = time.monotonic() - self.started
        (self.output / 'report.json').write_text(json.dumps(self.report, sort_keys=True, indent=2) + '\n')

    def stage(self, name, argv, *, data=b'', limit=180, environment=None):
        argv = list(map(str, argv))
        before = time.monotonic()
        row = {'name': name, 'argv': argv, 'cwd': str(ROOT), 'wall_limit_seconds': limit,
               'input_bytes': len(data), 'input_sha256': sha(data)}
        (self.output / (name + '.stdin.raw')).write_bytes(data)
        stdout, stderr = b'', b''
        try:
            result = supervise(argv, cwd=ROOT, environment=environment, data=data, execution_seconds=limit)
            stdout, stderr, supervision = result['stdout'], result['stderr'], result['receipt']
            row.update(exit_code=supervision['exit_code'], timed_out=supervision['timed_out'], supervision=supervision)
        except OSError:
            row.update(exit_code=None, timed_out=False, launch_error=traceback.format_exc())
            raise
        finally:
            for label, raw in (('stdout', stdout), ('stderr', stderr)):
                path = self.output / (name + '.' + label + '.raw')
                path.write_bytes(raw)
                row[label] = {'path': path.name, **identity(path)}
            row['seconds'] = time.monotonic() - before
            self.report['stages'].append(row)
            (self.output / (name + '.receipt.json')).write_text(json.dumps(row, sort_keys=True, indent=2) + '\n')
            self.save()
        print(json.dumps({'stage': name, 'exit_code': row['exit_code'], 'seconds': row['seconds']}, sort_keys=True), flush=True)
        need(row['exit_code'] == 0 and row['timed_out'] is False
             and row['supervision']['outcome'] == 'success' and row['supervision']['cleanup_complete'] is True,
             'failed qualification stage: ' + name)
        return stdout

    def original(self):
        self.stage('original-complete', [self.report['python'], '-I', '-S', '-B', ROOT / 'hia/tools/ml_dsa_original.py',
            '--repository', ROOT, '--output', self.output / 'original', '--rust-bin', self.args.rust_bin,
            '--provider-environment', self.output / 'provider.env'], limit=1200)
        original = document(read(self.output, 'original/report.json'))
        qualify_ml_dsa.validate_original(original, self.output / 'original', self.sources)
        qualify_ml_dsa.provider_environment(self.provider, original['environment'])
        qualify_ml_dsa.validate_provider(self.provider)
        self.report.update(provider_inputs_unchanged_after_original=True,
            original_report_sha256=sha(read(self.output, 'original/report.json')),
            original_reference=original['reference'])
        self.save()

    def original_rows(self, name, requests):
        reference = self.report['original_reference']
        before = identity(Path(reference['path']))
        need(before == {key: reference[key] for key in ('bytes', 'sha256')}, 'changed original reference')
        raw = self.stage(name, [reference['path']], data=jsonl(requests), limit=240)
        rows = [document(line) for line in raw.splitlines()]
        need(len(rows) == len(requests), 'original reference returned a partial roster')
        need(identity(Path(reference['path'])) == before, 'original reference changed during execution')
        return rows

    def native(self):
        python = self.report['python']
        self.stage('native-build', [python, '-I', '-S', '-B', HERE / 'build_owned.py',
            '--output', self.output / 'native'], limit=240)
        build = document(read(self.output, 'native/build.json'))
        need(build['status'] == 'PASS', 'native build failed')
        image = self.output / 'native/candidate-owned.so'
        self.report['production_image'] = {'path': str(image), 'retained': 'native/candidate-owned.so', **identity(image)}
        initial = cases.fixture_requests()
        first_values = self.original_rows('fixtures-original', [row['request'] for row in initial])
        first = cases.fixture_map(initial, first_values)
        modes = cases.mode_requests(first)
        second_values = self.original_rows('modes-original', [row['request'] for row in modes])
        second = cases.fixture_map(modes, second_values)
        validation = self.original_rows('mode-validity-original', cases.mode_validation_requests(first, modes, second))
        need(all(row['code'] == 0 for row in validation), 'a mode-separation fixture was not valid in its own mode')
        rows = cases.corpus(first_values, second_values)
        encoded = canonical(rows)
        (self.output / 'cases.json.xz').write_bytes(lzma.compress(encoded))
        self.report.update(case_roster_sha256=sha(encoded), case_count=len(rows),
                           original_mode_signatures_accepted_under_their_own_modes=len(validation))
        originals = self.original_rows('comparison-original', [row['original'] for row in rows])
        original_map = {row['label']: observed for row, observed in zip(rows, originals)}
        calls = 0
        import gzip
        for partition in cases.PARTITIONS:
            self.stage('native-' + partition, [python, '-I', '-S', '-B', HERE / 'qualification/native_cases.py',
                '--image', image, '--image-sha256', identity(image)['sha256'], '--cases', self.output / 'cases.json.xz',
                '--partition', partition, '--output', self.output / partition], limit=240)
            report = document(read(self.output, partition + '/report.json'))
            calls += report['native_calls']
            observed = [document(line) for line in gzip.decompress(read(self.output,
                partition + '/native-values.jsonl.gz')).splitlines()]
            wanted = cases.selected(rows, partition)
            need([item['label'] for item in observed] == [item['label'] for item in wanted], 'native case roster differs')
            for row, value in zip(wanted, observed):
                expected = normalize(row['original'], original_map[row['label']])
                if value['result'] != expected:
                    (self.output / 'difference.json').write_text(json.dumps({'case': row['label'],
                        'native': value['result'], 'original': expected}, sort_keys=True, indent=2) + '\n')
                    raise ValueError('actual native/original mismatch: ' + row['label'])
        self.report.update(native_cases=len(rows), native_abi_calls=calls)
        self.save()

    def ownership(self):
        python = self.report['python']
        tools = {name: row['path'] for name, row in self.report['tools'].items()}
        observer = self.output / 'observer'
        observer.mkdir()
        version = read(ROOT, PREFIX + 'owned.map').decode().replace('  global:\n',
            '  global:\n    trnm_pq_test_stat;\n    trnm_pq_test_fail_after;\n    trnm_pq_test_probe;\n')
        (observer / 'observer.map').write_text(version)
        self.stage('observer-compile', [tools['cc'], '-std=c11', '-O2', '-fPIC', '-Wall', '-Wextra', '-Werror',
            '-c', ROOT / 'hia/platform/pq_auth/qualification/allocator_observer.c', '-o', observer / 'observer.o'])
        objects = [self.output / 'native' / name for name in ('owned.o', 'candidate-private.o', 'gate-private.o')]
        self.report['observer_production_objects'] = {path.name: identity(path) for path in objects}
        self.stage('observer-link', [tools['ld'], '-m', 'elf_x86_64', '-shared', '-z', 'defs', '-z', 'noexecstack',
            '-z', 'relro', '-z', 'now', '--build-id=none', '--hash-style=both', '--wrap=calloc', '--wrap=free',
            '--version-script=' + str(observer / 'observer.map'), observer / 'observer.o', *objects, '-lc', '-lpthread',
            '-o', observer / 'candidate-observed.so'])
        observed = observer / 'candidate-observed.so'
        self.report['observer_image'] = {'retained': observed.relative_to(self.output).as_posix(), **identity(observed)}
        self.stage('observer-symbols', [tools['nm'], '-D', '--defined-only', observed])
        self.stage('allocations', [python, '-I', '-S', '-B', HERE / 'qualification/allocations.py',
            '--image', observed, '--image-sha256', identity(observed)['sha256'],
            '--fixtures', self.output / 'fixtures-original.stdout.raw', '--output', self.output / 'allocations'])
        image = self.output / 'native/candidate-owned.so'
        self.stage('lifetimes', [python, '-I', '-S', '-B', HERE / 'qualification/lifetimes.py',
            '--image', image, '--image-sha256', identity(image)['sha256'],
            '--fixtures', self.output / 'fixtures-original.stdout.raw', '--output', self.output / 'lifetimes'])
        aliases = [document(read(self.output, f'lifetimes/alias-original-{parameter}.json')) for parameter in (65, 87)]
        actual = self.original_rows('alias-original', [row['original'] for row in aliases])
        need(actual == [row['native'] for row in aliases], 'const-owner-alias original/native mismatch')
        self.report.update(alias_original_pairs=len(aliases), native_original_pairs=self.report['native_cases'] + len(aliases))
        self.stage('header-compile', [tools['cc'], '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-I', HERE,
            HERE / 'qualification/abi_client.c', image, '-Wl,-rpath,' + str(image.parent), '-o', self.output / 'header-client'])
        self.stage('header-client', [self.output / 'header-client'])

    def run(self):
        try:
            raw = self.stage('git-head', ['git', 'rev-parse', 'HEAD', 'HEAD^{tree}'])
            head, tree = raw.decode().splitlines()
            self.report.update(source_commit_observed=head, source_tree_observed=tree)
            self.report['source_dirty_observed'] = self.stage('git-status', ['git', 'status', '--porcelain=v1', '--untracked-files=all']).decode()
            self.stage('preflight', ml_dsa_original.PREFLIGHT_COMMAND)
            self.stage('supervision-controls', [self.report['python'], '-I', '-S', '-B',
                ROOT / 'hia/platform/pq_auth/qualification/supervision_controls.py',
                '--output', self.output / 'supervision-controls'], limit=30)
            self.original()
            self.native()
            self.ownership()
            need(input_map(ROOT) == self.sources, 'source changed during qualification')
            need(ml_dsa_original.check_environment(ROOT, os.environ) == self.report['environment_guard'], 'environment changed')
            need(check_platform_environment(os.environ) == self.report['platform_environment_guard'], 'platform environment changed')
            need(all(identity(Path(row['path'])) == {key: row[key] for key in ('bytes', 'sha256')}
                     for row in self.report['tools'].values()), 'platform executable changed')
            qualify_ml_dsa.validate_provider(self.provider)
            self.report.update(status='EXECUTED', source_unchanged_during_tests=True,
                provider_inputs_unchanged_after_all_execution=True, files=inventory(self.output))
            self.save()
            from hia.platform.pq_candidate.readback import validate_evidence, validate
            from hia.platform.pq_candidate.qualification.integrity import controls
            validate_evidence(self.output, ROOT)
            result = controls(self.output, ROOT)
            (self.output / 'executed-report.json').write_bytes(read(self.output, 'report.json'))
            (self.output / 'integrity.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
            self.report.update(status='PASS', files=inventory(self.output))
            self.save()
            result = validate(self.output, ROOT)
            print(json.dumps(result, sort_keys=True), flush=True)
            return self.report
        except BaseException:
            self.report.update(status='FAIL', traceback=traceback.format_exc())
            self.save()
            raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rust-bin', type=Path, required=True)
    parser.add_argument('--provider-receipt', type=Path, required=True)
    parser.add_argument('--provider-environment', type=Path, required=True)
    Qualification(parser.parse_args()).run()
