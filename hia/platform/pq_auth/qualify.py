"""Execute all public PQ-owner native, unchanged-original and integrity gates."""
from __future__ import annotations
from pathlib import Path
import argparse
import json
import lzma
import os
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from hia.platform.pq_auth.qualification.contract import (ADAPTERS, COMPILER, LIBRARIES, LIMITS, PARTITIONS,
    PREFIX, ROOT, SCHEMA, adapter_command, canonical, check_platform_environment, document, identity, input_map, inventory,
    need, normalize, read, regular, sha)
from hia.tools import ml_dsa_original, qualify_ml_dsa
from hia.platform.pq_auth.qualification.supervision import run as supervise


class Qualification:
    def __init__(self, args):
        guard = ml_dsa_original.check_environment(ROOT, os.environ)
        platform_guard = check_platform_environment(os.environ)
        need(os.environ.get('HIA_NATIVE_COMPILER_SHA256') == COMPILER, 'different native compiler pin')
        self.args = args
        self.output = args.output.absolute()
        need(not self.output.exists() and not self.output.is_symlink(), 'qualification output must be fresh')
        regular(self.output.parent, directory=True)
        provider = document(regular(args.provider_receipt).read_bytes())
        qualify_ml_dsa.validate_provider(provider)
        self.provider = provider
        self.sources = input_map(ROOT)
        self.output.mkdir(mode=0o700)
        self.started = time.monotonic()
        self.report = {'schema': SCHEMA, 'status': 'FAIL', 'limits': LIMITS,
                       'environment_guard': guard, 'stages': [], 'source_inputs': self.sources,
                       'platform_environment_guard': platform_guard,
                       'source_set_sha256': sha(canonical(self.sources)), 'repository': str(ROOT),
                       'output': str(self.output), 'python': str(Path(sys.executable).resolve()),
                       'rust_bin': str(args.rust_bin.absolute()), 'tools': {}, 'original_adapters': {}}
        for name, expected in self.sources.items():
            raw = read(ROOT, name)
            need(sha(raw) == expected, 'source changed before capture')
            target = self.output / 'inputs' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        (self.output / 'provider.json').write_bytes(regular(args.provider_receipt).read_bytes())
        environment = regular(args.provider_environment).read_bytes()
        (self.output / 'provider.env').write_bytes(environment)
        for index, row in enumerate(provider['native_backend_inputs']):
            target = self.output / 'provider' / (f'{index:02d}-' + Path(row['path']).name)
            target.parent.mkdir(exist_ok=True)
            raw = regular(row['path']).read_bytes()
            need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'live provider changed before capture')
            target.write_bytes(raw)
        for name in ('cc', 'ld', 'nm'):
            path = Path('/usr/bin', name).resolve(strict=True)
            self.report['tools'][name] = {'path': str(path), **identity(path)}
        self.save()

    def save(self):
        self.report['seconds'] = time.monotonic() - self.started
        (self.output / 'report.json').write_text(json.dumps(self.report, sort_keys=True, indent=2) + '\n')

    def stage(self, name, argv, *, data=b'', limit=180, environment=None):
        argv = list(map(str, argv))
        row = {'name': name, 'argv': argv, 'cwd': str(ROOT), 'wall_limit_seconds': limit,
               'input_bytes': len(data), 'input_sha256': sha(data)}
        before = time.monotonic()
        (self.output / (name + '.stdin.raw')).write_bytes(data)
        stdout, stderr = b'', b''
        try:
            result = supervise(argv, cwd=ROOT, environment=environment, data=data, execution_seconds=limit)
            stdout, stderr = result['stdout'], result['stderr']
            supervision = result['receipt']
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
        args = self.args
        self.stage('original-complete', [self.report['python'], '-I', '-S', '-B', ROOT / 'hia/tools/ml_dsa_original.py',
            '--repository', ROOT, '--output', self.output / 'original', '--rust-bin', args.rust_bin,
            '--provider-environment', self.output / 'provider.env'], limit=1200)
        original = document(read(self.output, 'original/report.json'))
        qualify_ml_dsa.validate_original(original, self.output / 'original', self.sources)
        qualify_ml_dsa.provider_environment(self.provider, original['environment'])
        qualify_ml_dsa.validate_provider(self.provider)
        self.report['provider_inputs_unchanged_after_original'] = True
        self.report['original_report_sha256'] = sha(read(self.output, 'original/report.json'))
        artifacts = document(read(self.output, 'original/artifacts.json'))
        graph = {}
        for name in LIBRARIES:
            rows = [(event, path) for event in artifacts if event['target']['name'] == name
                    for path in event['filenames'] if Path(path).suffix == '.rlib']
            need(len(rows) == 1, 'ambiguous original dependency ' + name)
            event, path = rows[0]
            target = self.output / 'adapters/dependencies' / Path(path).name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(regular(path).read_bytes())
            graph[name] = {'path': path, 'retained': target.relative_to(self.output).as_posix(),
                           'package_id': event['package_id'], 'features': event['features'], **identity(target)}
        self.report['adapter_graph'] = graph
        environment = dict(os.environ)
        environment.update(original['environment'])
        environment['PATH'] = str(args.rust_bin) + ':' + environment['PATH']
        for family, source in ADAPTERS.items():
            self.stage('format-' + family, [args.rust_bin / 'rustfmt', '--edition', '2021', '--check', ROOT / source],
                       environment=environment)
            target = self.output / 'adapters' / (family + '-reference')
            argv = adapter_command(args.rust_bin, ROOT, self.output / 'original', self.provider['install_prefix'], graph, family, target)
            self.stage('build-' + family, argv, environment=environment)
            self.report['original_adapters'][family] = {'path': str(target), 'retained': target.relative_to(self.output).as_posix(),
                'source': source, 'source_sha256': self.sources[source], **identity(target)}
            need(all(identity(Path(row['path'])) == {key: row[key] for key in ('bytes', 'sha256')}
                     for row in graph.values()), 'original library changed during adapter build')
        qualify_ml_dsa.validate_provider(self.provider)
        self.report['provider_inputs_unchanged_after_adapter_links'] = True
        self.save()

    def native(self):
        python = self.report['python']
        self.stage('native-build', [python, '-I', '-S', '-B', HERE / 'build_owned.py', '--output', self.output / 'native'], limit=240)
        build = document(read(self.output, 'native/build.json'))
        need(build['status'] == 'PASS', 'native build failed')
        image = self.output / 'native/pq-owned.so'
        image_sha = identity(image)['sha256']
        self.report['production_image'] = {'path': str(image), 'retained': 'native/pq-owned.so', **identity(image)}
        for partition, _, _, _ in PARTITIONS:
            self.stage('native-' + partition, [python, '-I', '-S', '-B', HERE / 'qualification/native_cases.py',
                '--image', image, '--image-sha256', image_sha, '--partition', partition,
                '--output', self.output / partition], limit=240)
        rows = []
        for partition, _, _, _ in PARTITIONS:
            rows += document(lzma.decompress(read(self.output, partition + '/cases.json.xz')))
        need(len(rows) == 1609, 'incomplete native case roster')
        for family in ADAPTERS:
            cases = [row for row in rows if row['family'] == family]
            adapter = self.report['original_adapters'][family]
            raw = b''.join((json.dumps(row['original'], sort_keys=True) + '\n').encode() for row in cases)
            stdout = self.stage('compare-' + family, [adapter['path']], data=raw, limit=240)
            original = [document(line) for line in stdout.splitlines()]
            need(len(original) == len(cases), 'original adapter returned a partial roster')
            for case, observation in zip(cases, original):
                if normalize(family, observation) != case['native']:
                    (self.output / 'difference.json').write_text(json.dumps({'case': case['label'], 'native': case['native'],
                        'original': observation}, sort_keys=True, indent=2) + '\n')
                    raise ValueError('actual native/original mismatch: ' + case['label'])
            need(identity(Path(adapter['path'])) == {key: adapter[key] for key in ('bytes', 'sha256')}, 'adapter changed during comparison')
        self.report['native_original_pairs'] = len(rows)

    def ownership(self):
        python = self.report['python']
        tools = {name: row['path'] for name, row in self.report['tools'].items()}
        observer = self.output / 'observer'
        observer.mkdir()
        version = read(ROOT, PREFIX + 'owned.map').decode().replace('  global:\n',
            '  global:\n    trnm_pq_test_stat;\n    trnm_pq_test_fail_after;\n    trnm_pq_test_probe;\n')
        (observer / 'observer.map').write_text(version)
        self.stage('observer-compile', [tools['cc'], '-std=c11', '-O2', '-fPIC', '-Wall', '-Wextra', '-Werror',
            '-c', HERE / 'qualification/allocator_observer.c', '-o', observer / 'observer.o'])
        objects = [self.output / 'native' / name for name in ('owned.o', 'auth-private.o', 'verify-private.o', 'profile-private.o')]
        self.report['observer_production_objects'] = {path.name: identity(path) for path in objects}
        self.stage('observer-link', [tools['ld'], '-m', 'elf_x86_64', '-shared', '-z', 'defs', '-z', 'noexecstack',
            '-z', 'relro', '-z', 'now', '--build-id=none', '--hash-style=both', '--wrap=calloc', '--wrap=free',
            '--version-script=' + str(observer / 'observer.map'), observer / 'observer.o', *objects, '-lc', '-lpthread',
            '-o', observer / 'pq-owned-observed.so'])
        observed = observer / 'pq-owned-observed.so'
        self.report['observer_image'] = {'retained': observed.relative_to(self.output).as_posix(), **identity(observed)}
        self.stage('observer-symbols', [tools['nm'], '-D', '--defined-only', observed])
        self.stage('allocations', [python, '-I', '-S', '-B', HERE / 'qualification/allocations.py', '--image', observed,
            '--image-sha256', identity(observed)['sha256'], '--output', self.output / 'allocations'])
        image = self.output / 'native/pq-owned.so'
        self.stage('lifetimes', [python, '-I', '-S', '-B', HERE / 'qualification/lifetimes.py', '--image', image,
            '--image-sha256', identity(image)['sha256'], '--output', self.output / 'lifetimes'])
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
                HERE / 'qualification/supervision_controls.py', '--output', self.output / 'supervision-controls'], limit=30)
            self.original()
            self.native()
            self.ownership()
            need(input_map(ROOT) == self.sources, 'source changed during qualification')
            need(ml_dsa_original.check_environment(ROOT, os.environ) == self.report['environment_guard'], 'environment changed')
            need(check_platform_environment(os.environ) == self.report['platform_environment_guard'], 'platform environment changed')
            need(all(identity(Path(row['path'])) == {key: row[key] for key in ('bytes', 'sha256')}
                     for row in self.report['tools'].values()), 'platform executable changed')
            self.report.update(status='EXECUTED', source_unchanged_during_tests=True,
                               files=inventory(self.output))
            self.save()
            from hia.platform.pq_auth.readback import validate_evidence, validate
            from hia.platform.pq_auth.qualification.integrity import controls
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
            raise
        finally:
            if self.report['status'] != 'PASS':
                self.save()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rust-bin', type=Path, required=True)
    parser.add_argument('--provider-receipt', type=Path, required=True)
    parser.add_argument('--provider-environment', type=Path, required=True)
    Qualification(parser.parse_args()).run()
