"""Hosted test driver for the Delta HIA actor; never a Node runtime adapter.

The unchanged official repository composer/native compiler builds each source.
The private test worker has a 256 MiB process address-space limit. This fixture's
explicit 8 MiB per-buffer extent permits the 131,072-row Delta-union control; it
does not qualify the original complete State maximum byte extent.
"""
from pathlib import Path
import base64
import hashlib
import json
import os
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[3]
HIA = REPO / 'hia'
MAX_EXTENT = 8 << 20
MAX_BATCH_BYTES = 32 << 20
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Module:
    def __init__(self, source, output):
        from hia.tools.toolchain import build_native
        self.source, self.output = Path(source).resolve(), Path(output).resolve()
        if self.output == HIA or HIA in self.output.parents:
            raise ValueError('Native test artifacts must be outside HIA sources')
        self.output.mkdir(mode=0o700)
        self.library = self.output / 'program.so'
        compiler = os.environ.get('HIA_NATIVE_COMPILER')
        compiler_sha = os.environ.get('HIA_NATIVE_COMPILER_SHA256')
        if not compiler or not compiler_sha:
            raise RuntimeError('Set explicit HIA_NATIVE_COMPILER and HIA_NATIVE_COMPILER_SHA256')
        self.compiler_path = Path(compiler).resolve(strict=True)
        self.compiler = self.compiler_path.read_bytes()
        binding = json.loads((HIA / 'qualification/compiler-binding.json').read_bytes())
        if sha(self.compiler) != compiler_sha or compiler_sha != binding['compiler_sha256']:
            raise ValueError('Native compiler differs from explicit and qualification pins')
        self.inputs = {path: path.read_bytes() for path in
            (Path(__file__), HIA/'tools/toolchain.py', HIA/'tests/native_support.py',
             HIA/'qualification/compiler-binding.json', HIA/'toolchain.lock.json')}
        built, self.document = build_native(self.source, self.library, byte_exports=('f0',),
            backend='selfhost', compiler=self.compiler_path, compiler_sha256=compiler_sha)
        for row in built['chain_migration']['inputs']:
            path = HIA / row['path']
            raw = path.read_bytes()
            if sha(raw) != row['sha256']:
                raise ValueError('Captured source changed after official build')
            self.inputs[path] = raw
        self.digest = sha(self.library.read_bytes())
        self.calls = []
        self.receipt = {'schema': 'trnm.hia.native-delta-build.v1', 'status': 'PASS',
            'source_sha256': sha(self.source.read_bytes()), 'library_sha256': self.digest,
            'source_inputs': {str(path.relative_to(REPO)): {'bytes': len(raw), 'sha256': sha(raw)}
                              for path, raw in self.inputs.items()},
            'official_composer_and_builder': True, 'source_root_guard_redefined': False,
            'native_compiler_only': True, 'hosted_build_and_test_driver': True,
            'borrowed_test_extent_bytes': MAX_EXTENT,
            'maximum_complete_state_extent_qualified': False,
            'build': built}
        self.check_pin()
        (self.output / 'build.json').write_text(json.dumps(self.receipt, sort_keys=True, indent=2) + '\n')

    def check_pin(self):
        from hia.tools.toolchain import pinned_toolchain
        pinned_toolchain()
        for path, raw in self.inputs.items():
            if path.is_symlink() or path.read_bytes() != raw:
                raise ValueError('Native qualification source changed: ' + str(path))
        if self.compiler_path.read_bytes() != self.compiler:
            raise ValueError('Native compiler changed')
        if sha(self.library.read_bytes()) != self.digest:
            raise ValueError('Native artifact changed')

    def call_many(self, cases, timeout=30):
        if not 0 < timeout <= 60:
            raise ValueError('Native test process wall limit must be in (0,60] seconds')
        rows, extent = [], 0
        for arguments in cases:
            if len(arguments) != 3 or any(type(value) not in (bytes, bytearray) or len(value) > MAX_EXTENT
                                         for value in arguments):
                raise ValueError('Delta fixture requires three private byte extents of at most 8 MiB')
            extent += sum(map(len, arguments))
            rows.append({'function':'f0', 'returns':['u32'], 'byte_abi':True,
                'arguments':[{'type':kind, 'bytes':base64.b64encode(value).decode()}
                             for kind, value in zip(('readbuf','mutbuf','mutbuf'), arguments)]})
        if not rows or extent > MAX_BATCH_BYTES:
            raise ValueError('Delta fixture batch exceeds its explicit 32 MiB input extent')
        request = json.dumps({'library':str(self.library), 'sha256':self.digest,
                             'cases':rows, 'cpu_seconds':max(1,int(timeout))}).encode()
        started = time.monotonic_ns()
        label = f'call-{len(self.calls):04}'
        try:
            process = subprocess.run([sys.executable,'-I','-S','-B',str(HIA/'tests/native_support.py'),'--worker'],
                input=request, capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            receipt = {'status':'TIMEOUT','elapsed_ns':time.monotonic_ns()-started,
                       'wall_limit_seconds':timeout,'request_sha256':sha(request),
                       'cleanup':'subprocess.run killed and reaped the direct worker'}
            self._retain(label, receipt, error.stdout or b'', error.stderr or b'')
            raise RuntimeError('Native Delta worker timed out; observation retained') from error
        receipt = {'status':'RETURNED' if process.returncode == 0 else 'FAIL',
            'returncode':process.returncode,'elapsed_ns':time.monotonic_ns()-started,
            'wall_limit_seconds':timeout,'request_sha256':sha(request),
            'stdout_sha256':sha(process.stdout),'stdout_bytes':len(process.stdout),
            'stderr_sha256':sha(process.stderr),'stderr_bytes':len(process.stderr),
            'cases':len(rows),'library_sha256':self.digest}
        self._retain(label, receipt, process.stdout if process.returncode else None,
                     process.stderr if process.returncode else None)
        if process.returncode != 0:
            raise RuntimeError('Native Delta worker failed; observation retained: ' + label)
        result = json.loads(process.stdout)
        if result['artifact_sha256'] != self.digest or result['host_compiler_modules_loaded'] != [] or len(result['cases']) != len(cases):
            raise ValueError('Native worker result identity differs')
        answers = []
        for case, row in zip(cases, result['cases']):
            if row['function'] != 'f0' or row['abi_status'] != 0:
                raise ValueError('Native borrowed ABI did not return normally')
            arguments = [base64.b64decode(item['bytes'],validate=True) for item in row['arguments']]
            if [len(value) for value in arguments] != [len(value) for value in case] or arguments[0] != case[0]:
                raise ValueError('Native invocation changed read-only bytes or extents')
            answers.append({'value':row['value'], 'arguments':arguments})
        return answers

    def _retain(self, label, receipt, stdout, stderr):
        self.calls.append(receipt)
        (self.output/(label+'.json')).write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
        if stdout is not None:
            (self.output/(label+'.stdout.raw')).write_bytes(stdout)
        if stderr is not None:
            (self.output/(label+'.stderr.raw')).write_bytes(stderr)
