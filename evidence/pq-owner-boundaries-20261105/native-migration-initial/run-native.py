import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

base = Path(__file__).resolve().parent
root = base / 'repo'
out = base / 'receipts'
out.mkdir(exist_ok=True)
env = os.environ.copy()
env.update(json.loads((base / 'native-env.json').read_text()))
env['PATH'] = '/root/.cargo/bin:' + env['PATH']
label, *cmd = sys.argv[1:]

def source():
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=root)
    diff = git('diff', '--binary', '--no-ext-diff')
    paths = git('diff', '--name-only').decode().splitlines()
    return {
        'head': git('rev-parse', 'HEAD').decode().strip(),
        'diff_sha256': hashlib.sha256(diff).hexdigest(),
        'status': git('status', '--porcelain').decode(),
        'changed_file_sha256': {
            path: hashlib.sha256((root / path).read_bytes()).hexdigest()
            for path in paths
        },
    }

pre = subprocess.run(['bash', 'scripts/project-preflight.sh'], cwd=root, env=env,
                     capture_output=True, text=True)
print(pre.stdout + pre.stderr, flush=True)
if pre.returncode:
    raise SystemExit(pre.returncode)
before = source()
started = time.time()
with (out / (label + '.log')).open('w') as log:
    result = subprocess.run(cmd, cwd=root, env=env, stdout=log,
                            stderr=subprocess.STDOUT, text=True)
after = source()
record = {
    'command': cmd,
    'source_before': before,
    'source_after': after,
    'source_unchanged': before == after,
    'exit_code': result.returncode,
    'elapsed_seconds': time.time() - started,
    'environment': json.loads((base / 'native-env.json').read_text()),
    'output_sha256': hashlib.sha256((out / (label + '.log')).read_bytes()).hexdigest(),
}
(out / (label + '.json')).write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps({k: record[k] for k in ['command', 'source_unchanged', 'exit_code', 'elapsed_seconds']}), flush=True)
print('\n'.join((out / (label + '.log')).read_text().splitlines()[-80:]), flush=True)
raise SystemExit(result.returncode if before == after else 200)
