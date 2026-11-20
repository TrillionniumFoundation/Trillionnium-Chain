"""Test-only real libc allocation failures, relinking exact production objects."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import os
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('--build', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
BUILD = args.build.resolve()
OUT = args.output.resolve()
REPO = ROOT.parents[3]
OUT.mkdir(mode=0o700)
REPORT = {'status': 'INCOMPLETE', 'production_image_changed': False,
          'test_only_allocator_interposer': True, 'stages': []}


def ident(data): return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def save(path, value): path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def stage(name, argv):
    from hia.platform.service_settlement.process import run
    environment={'PATH':'/usr/bin:/bin','HOME':os.environ['HOME'],'PYTHONDONTWRITEBYTECODE':'1'}
    receipt=run(OUT/name,list(map(str,argv)),cwd=REPO,environment=environment,seconds=30)
    REPORT['stages'].append({'name':name,**receipt})
    save(OUT/'build.json',REPORT)
    assert receipt['status']=='PASS',receipt
    return (OUT/name/'stdout.raw').read_bytes()


try:
    original_report = (BUILD / 'build.json').read_bytes()
    original = json.loads(original_report)
    assert original['status'] == 'PUBLIC_NATIVE_LINKED_NOT_QUALIFIED'
    assert ident((BUILD / 'settlement-engine.so').read_bytes()) == original['artifact']
    REPORT['production_build'] = ident(original_report)
    REPORT['production_image'] = original['artifact']
    (OUT / 'production-build.json').write_bytes(original_report)
    (OUT / 'executed-builder.py').write_bytes(Path(__file__).read_bytes())
    tools = {}
    for label,p in [('allocator_cc',Path('/usr/bin/gcc').resolve(strict=True)),('python',Path(sys.executable).resolve(strict=True))]:
        tools[label]={'path':str(p),**ident(p.read_bytes())}
    REPORT['tools']=tools
    observer = (ROOT / 'allocator_observer.c').read_bytes()
    (OUT / 'observer.c').write_bytes(observer)
    REPORT['observer'] = ident(observer)
    objects = []
    inventory = {}
    for name in ['engine-owned', 'control', 'trust', 'receipt', 'rollup', 'settle', 'values']:
        raw = (BUILD / (name + '.o')).read_bytes()
        expected = original['emitter_execution']['object'] if name == 'engine-owned' else original['modules'][name]['renamed']
        assert ident(raw) == expected
        path = OUT / (name + '.o'); path.write_bytes(raw); objects.append(path)
        inventory[name] = ident(raw)
    REPORT['unchanged_production_objects'] = inventory
    stage('preflight', ['bash', REPO / 'scripts/project-preflight.sh', '--audit'])
    stage('compile-observer', ['/usr/bin/gcc', '-std=c11', '-O2', '-fPIC', '-Wall', '-Wextra', '-Werror',
                               '-c', OUT / 'observer.c', '-o', OUT / 'observer.o'])
    exports = sorted(original['exports'] + ['trnm_settlement_test_alloc_' + name
                     for name in ['calls', 'frees', 'live', 'bytes', 'failures', 'bad_frees', 'fail_after']])
    (OUT / 'observer.map').write_text('{\n global:\n' + ''.join('  '+name+';\n' for name in exports) + ' local: *;\n};\n')
    image = OUT / 'engine-observed.so'
    stage('link-observed', ['/usr/bin/gcc', '-shared', '-Wl,-z,defs,-z,noexecstack,-z,relro,-z,now,--build-id=none,--wrap=calloc,--wrap=free',
          *objects, OUT / 'observer.o', '-Wl,--version-script=' + str(OUT / 'observer.map'), '-pthread', '-o', image])
    defined = stage('defined-symbols', ['/usr/bin/nm', '-D', '--defined-only', image]).decode().splitlines()
    assert sorted(row.split()[-1] for row in defined) == exports
    undefined = stage('undefined-symbols', ['/usr/bin/nm', '-D', '--undefined-only', image]).decode().splitlines()
    names = {row.split()[-1].split('@')[0] for row in undefined}
    assert names <= {'calloc', 'free', 'memcpy', 'abort', 'pthread_mutex_lock', 'pthread_mutex_unlock',
                     '__cxa_finalize', '_ITM_registerTMCloneTable', '_ITM_deregisterTMCloneTable', '__gmon_start__'}
    for name, expected in inventory.items(): assert ident((BUILD / (name + '.o')).read_bytes()) == expected
    assert (BUILD / 'build.json').read_bytes() == original_report
    for v in tools.values(): assert ident(Path(v['path']).read_bytes())=={k:v[k] for k in ['bytes','sha256']}
    REPORT.update(status='TEST_OBSERVER_LINKED_NOT_EXECUTED', image=ident(image.read_bytes()),
                  symbols=exports, undefined_symbols=sorted(names), exact_production_objects_relinked=True)
except BaseException:
    REPORT.update(status='FAIL', exception=traceback.format_exc()); raise
finally:
    save(OUT / 'build.json', REPORT)
    print(json.dumps({k: REPORT.get(k) for k in ('status', 'image', 'exception')}), flush=True)
