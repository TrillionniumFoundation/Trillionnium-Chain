"""Build the HIA-owned PQ interface; no hosted PQ business implementation."""
from __future__ import annotations
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import traceback
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from hia.tools.toolchain import build_native, checked_source
from hia.tools import ml_dsa_original
from hia.platform.pq_auth.qualification.contract import check_platform_environment


def identity(path):
    assert path.is_file() and not any(parent.is_symlink() for parent in (path, *path.parents))
    raw = path.read_bytes()
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


class Build:
    def __init__(self, output):
        guard = ml_dsa_original.check_environment(ROOT, os.environ)
        platform_guard = check_platform_environment(os.environ)
        self.output = output.absolute()
        assert not self.output.exists() and not self.output.is_symlink()
        self.output.mkdir(parents=True, mode=0o700)
        self.sources = {}
        self.report = {'status': 'FAIL', 'stages': [], 'builds': [], 'source_before': self.sources,
                       'native_invocations': [],
                       'environment_guard': guard, 'platform_tools': {},
                       'platform_environment_guard': platform_guard,
                       'whole_chain_native': False, 'constant_time_qualified': False,
                       'openssl_owned_provider_ported': False, 'complete_pq_crate_ported': False}
        self.started = time.monotonic()

    def save(self):
        self.report['seconds'] = time.monotonic() - self.started
        (self.output / 'build.json').write_text(json.dumps(self.report, sort_keys=True, indent=2) + '\n')

    def capture(self, path):
        name = path.relative_to(ROOT).as_posix()
        value = identity(path)
        if name in self.sources:
            assert self.sources[name] == value
        else:
            self.sources[name] = value
            target = self.output / 'inputs' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
            assert identity(target) == value

    def stage(self, name, argv, data=b'', limit=60):
        argv = list(map(str, argv))
        before = time.monotonic()
        row = {'name': name, 'argv': argv, 'cwd': str(ROOT), 'wall_limit_seconds': limit,
               'input_bytes': len(data), 'input_sha256': hashlib.sha256(data).hexdigest()}
        (self.output / (name + '.stdin.raw')).write_bytes(data)
        try:
            result = subprocess.run(argv, input=data, capture_output=True, cwd=ROOT, timeout=limit, check=False)
            stdout, stderr = result.stdout, result.stderr
            row.update(exit_code=result.returncode, timed_out=False)
        except subprocess.TimeoutExpired as error:
            stdout, stderr = error.stdout or b'', error.stderr or b''
            row.update(exit_code=None, timed_out=True)
        for label, raw in [('stdout', stdout), ('stderr', stderr)]:
            target = self.output / (name + '.' + label + '.raw')
            target.write_bytes(raw)
            row[label] = {'path': target.name, **identity(target)}
        row['seconds'] = time.monotonic() - before
        self.report['stages'].append(row)
        (self.output / (name + '.receipt.json')).write_text(json.dumps(row, sort_keys=True, indent=2) + '\n')
        self.save()
        assert row['exit_code'] == 0 and not row['timed_out'], name
        return stdout

    def run(self):
        try:
            for name in ('scripts/project-preflight.sh', 'trillionnium/Cargo.toml',
                         *ml_dsa_original.boundary_inputs(ROOT)):
                self.capture(ROOT / name)
            self.stage('preflight', ml_dsa_original.PREFLIGHT_COMMAND)
            for path in [Path(__file__), HERE / 'emit_owned.py', HERE / 'owned.map', HERE / 'owned_exports.json',
                         HERE / 'pq_auth.h', HERE / 'README.md', ROOT / 'hia/tools/ml_dsa_original.py',
                         HERE / 'qualification/contract.py',
                         ROOT / 'hia/tools/toolchain.py', ROOT / 'hia/toolchain.lock.json',
                         ROOT / 'hia/qualification/compiler-binding.json']:
                self.capture(path)
            platform = {}
            for name in ('ld', 'objcopy', 'objdump', 'nm'):
                path = Path('/usr/bin', name).resolve(strict=True)
                platform[name] = str(path)
                self.report['platform_tools'][name] = {'path': str(path), **identity(path)}
            units = [('auth', ROOT / 'hia/src/crypto/pq_auth_owner.hepta', 'trnm_pq_auth_private'),
                     ('verify', ROOT / 'hia/src/crypto/pq_auth_verify.hepta', 'trnm_pq_verify_private'),
                     ('profile', ROOT / 'hia/src/crypto/pq_profile_auth.hepta', 'trnm_pq_profile_private'),
                     ('owned-emitter', HERE / 'owned_emitter.hepta', None)]
            for name, source, symbol in units:
                _, composed, _, _, inputs = checked_source(source)
                for path, raw in inputs:
                    self.capture(path)
                    assert (self.output / 'inputs' / path.relative_to(ROOT)).read_bytes() == raw
                (self.output / (name + '.hepta')).write_bytes(composed)
                target = self.output / (name + ('.o' if symbol else '.so'))
                # Observe the real subprocess calls made by the unchanged pinned
                # build driver. In particular retain the actual sealed-compiler
                # request and stdout object, including unsuccessful invocations.
                actual_run = subprocess.run
                invocations = []

                def observed_run(argv, **kwargs):
                    args = list(map(str, argv))
                    label = f'native-{name}-{len(invocations):02d}'
                    data = kwargs.get('input', b'')
                    assert isinstance(data, bytes)
                    row = {'name': label, 'unit': name, 'argv': args,
                           'cwd': str(kwargs.get('cwd', Path.cwd())),
                           'wall_limit_seconds': kwargs.get('timeout'),
                           'environment': kwargs.get('env'),
                           'pass_fds': list(kwargs.get('pass_fds', ())),
                           'input_bytes': len(data), 'input_sha256': hashlib.sha256(data).hexdigest()}
                    (self.output / (label + '.stdin.raw')).write_bytes(data)
                    if args[0].startswith('/proc/self/fd/'):
                        compiler = Path(args[0]).read_bytes()
                        row['executable_sha256'] = hashlib.sha256(compiler).hexdigest()
                    before = time.monotonic()
                    stdout, stderr = b'', b''
                    try:
                        result = actual_run(argv, **kwargs)
                        stdout, stderr = result.stdout or b'', result.stderr or b''
                        row.update(exit_code=result.returncode, timed_out=False)
                        return result
                    except subprocess.TimeoutExpired as error:
                        stdout, stderr = error.stdout or b'', error.stderr or b''
                        row.update(exit_code=None, timed_out=True)
                        raise
                    except subprocess.CalledProcessError as error:
                        stdout, stderr = error.stdout or b'', error.stderr or b''
                        row.update(exit_code=error.returncode, timed_out=False)
                        raise
                    finally:
                        for stream, raw in [('stdout', stdout), ('stderr', stderr)]:
                            if isinstance(raw, str):
                                raw = raw.encode()
                            path = self.output / (label + '.' + stream + '.raw')
                            path.write_bytes(raw)
                            row[stream] = {'path': path.name, **identity(path)}
                        row['seconds'] = time.monotonic() - before
                        invocations.append(row)
                        self.report['native_invocations'].append(row)
                        (self.output / (label + '.receipt.json')).write_text(json.dumps(row, sort_keys=True, indent=2) + '\n')
                        self.save()

                with patch.object(subprocess, 'run', observed_run):
                    receipt, document = build_native(source, target, byte_exports=('f0',),
                        kind='object' if symbol else 'shared', backend='selfhost',
                        compiler=os.environ['HIA_NATIVE_COMPILER'], compiler_sha256=os.environ['HIA_NATIVE_COMPILER_SHA256'])
                (self.output / (name + '.core.json')).write_text(json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n')
                assert receipt['claims']['fallback_used'] is False and receipt['claims']['python_emitter_used'] is False
                self.report['builds'].append({'name': name, 'receipt': receipt,
                    'functions': len(document['functions']), 'ops': sum(len(b['ops']) for fn in document['functions'] for b in fn['blocks'])})
                self.save()
                if symbol:
                    self.stage('rename-' + name, [platform['objcopy'], '--redefine-sym', 'f0=' + symbol, target, self.output / (name + '-private.o')])
            emitted = self.output / 'owned.o'
            request = {'image': str(self.output / 'owned-emitter.so'), 'sha256': identity(self.output / 'owned-emitter.so')['sha256'],
                       'output': str(emitted)}
            observed = json.loads(self.stage('emit-owned', [sys.executable, '-I', '-S', '-B', HERE / 'emit_owned.py'], json.dumps(request).encode()))
            assert observed['status'] == 'PASS' and observed['host_compiler_modules_loaded'] == []
            assert identity(emitted) == {'bytes': observed['object_bytes'], 'sha256': observed['object_sha256']}
            self.stage('inspect-owned', [platform['objdump'], '-dr', emitted])
            final = self.output / 'pq-owned.so'
            self.stage('link-owned', [platform['ld'], '-m', 'elf_x86_64', '-shared', '-z', 'defs', '-z', 'noexecstack', '-z', 'relro',
                '-z', 'now', '--build-id=none', '--hash-style=both', '--version-script=' + str(HERE / 'owned.map'), emitted,
                *[self.output / (name + '-private.o') for name, _, symbol in units if symbol], '-lc', '-o', final])
            symbols = self.stage('public-symbols', [platform['nm'], '-D', '--defined-only', final]).decode().splitlines()
            actual = sorted(row.split()[-1] for row in symbols if row.strip())
            expected = sorted(json.loads((HERE / 'owned_exports.json').read_text())['exports'])
            assert actual == expected and len(actual) == len(set(actual))
            after = {name: identity(ROOT / name) for name in self.sources}
            assert after == self.sources
            assert all(identity(Path(row['path'])) == {key: row[key] for key in ('bytes', 'sha256')}
                       for row in self.report['platform_tools'].values())
            self.report.update(status='PASS', source_after=after, exports=actual,
                emitted_object=identity(emitted), final_image=identity(final),
                artifacts={path.name: identity(path) for path in self.output.iterdir() if path.is_file()
                           and path.suffix in ('.o', '.so', '.hepta')})
            return self.report
        except BaseException:
            self.report['traceback'] = traceback.format_exc()
            raise
        finally:
            self.save()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = Build(args.output).run()
    print(json.dumps({'status': value['status'], 'image': value['final_image'], 'exports': len(value['exports']),
                      'seconds': value['seconds']}, sort_keys=True))
