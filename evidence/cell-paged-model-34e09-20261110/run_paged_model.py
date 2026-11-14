import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time

ROOT = Path('/home/qq/work/chain-cell-paged-model-34e09-20261110')
VALIDATION = Path(str(ROOT) + '-validation')
TARGET = Path(str(ROOT) + '-target')
COMMIT = 'c57a384abe3edf88e79ca7ecbd0de645df4934c6'
TREE = 'a3e6a456d9dd6ae1c6242413611ea1648f66fe46'
INPUT_SHA = '42b7580309ed1b664114116f82c434cedea34958cb6d893cf22bb665a2bb01f5'

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while block := f.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()

def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()

def identity():
    value = dict(commit=git('rev-parse', 'HEAD'), tree=git('rev-parse', 'HEAD^{tree}'), status=git('status', '--porcelain', '--untracked-files=all'))
    assert value == dict(commit=COMMIT, tree=TREE, status=''), value
    return value

def write(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write('\n')

qualification = json.loads((VALIDATION / 'c4-rowkeys-full/observation.json').read_text())
assert qualification['passed'] and qualification['sources_unchanged']
assert qualification['identity'] == identity()
guard = Path(str(TARGET) + '.owner.lock').open('a')
fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
own_ancestors = {os.getpid()}
pid = os.getppid()
while pid > 1 and pid not in own_ancestors:
    own_ancestors.add(pid)
    pid = int(Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[1])
active = []
probe_root = '/home/qq/work/chain-rs-cost-probe-34e09-20261110'
for entry in Path('/proc').iterdir():
    if not entry.name.isdecimal() or int(entry.name) in own_ancestors:
        continue
    try:
        if entry.stat().st_uid != os.getuid():
            continue
        argv = [os.fsdecode(a) for a in (entry / 'cmdline').read_bytes().split(b'\0') if a]
        cwd = os.readlink(entry / 'cwd')
        if cwd.startswith(probe_root) or any(a.startswith(probe_root) for a in argv):
            active.append(dict(pid=int(entry.name), cwd=cwd, argv=argv))
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        continue
assert not active, active
source = VALIDATION / 'paged-source-inputs.v1.json'
assert sha(source) == INPUT_SHA
spec = json.loads(source.read_text())
assert spec['source']['seconds'] == 300 and spec['source']['max_snapshot_bytes'] == 512 << 20
assert spec['source']['runtime_rss_bytes'] == 8 << 30 and spec['source']['threads'] == 4
assert spec['custody']['available_slots'] == [0, 2, 4, 5]
operation_output = Path(spec['source']['output'])
assert operation_output == Path(str(ROOT) + '-operation-01') and not operation_output.exists()
materials = []
for group in ['environment', 'model']:
    for name, item in spec['source'][group].items():
        path = Path(item['path'])
        observed = sha(path)
        assert observed == item['sha256'], (group, name)
        materials.append(dict(group=group, name=name, path=str(path), sha256=observed, bytes=path.stat().st_size))
python = spec['source']['python']
assert sha(Path(python['path'])) == python['sha256']
assert len(materials) + 1 == 31
receipt = VALIDATION / 'real-paged-operation-01'
receipt.mkdir(mode=0o700)
write(receipt / 'admission.json', dict(identity=identity(), input_sha256=INPUT_SHA, owned_probe_absent=True, materials=materials, original_seconds=300, scope='Input verification and compilation only; no RS precomputation. Model operation retains its own original absolute 300 second deadline.'))
start = json.loads((VALIDATION / 'c4-rowkeys-full/start.json').read_text())
env = os.environ.copy()
env.update(start['environment'])
rust = '/home/qq/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin'
env['PATH'] = rust + ':' + env.get('PATH', '')
env['CARGO_TERM_COLOR'] = 'never'
with (receipt / 'build.log').open('x') as log:
    build_started = time.monotonic()
    build = subprocess.run([rust + '/cargo', 'build', '--locked', '--offline', '--jobs', '2', '-p', 'trnm-data-availability', '--example', 'cell_sealed_research_paged_next_use_v1'], cwd=ROOT / 'trillionnium', env=env, stdout=log, stderr=subprocess.STDOUT)
write(receipt / 'build.json', dict(exit_code=build.returncode, elapsed_seconds=time.monotonic() - build_started, log_sha256=sha(receipt / 'build.log')))
assert build.returncode == 0
identity()
binary = TARGET / 'debug/examples/cell_sealed_research_paged_next_use_v1'
write(receipt / 'execution-start.json', dict(identity=identity(), binary=str(binary), binary_sha256=sha(binary), source_sha256=INPUT_SHA, started_unix_ns=time.time_ns(), output=str(operation_output), external_cleanup_watchdog_seconds=360, internal_original_seconds=300))
out = (receipt / 'native.stdout').open('xb')
err = (receipt / 'native.stderr').open('xb')
started = time.monotonic()
pid = os.fork()
if pid == 0:
    os.setsid()
    os.chdir(ROOT / 'trillionnium')
    os.dup2(out.fileno(), 1)
    os.dup2(err.fileno(), 2)
    os.execve(binary, [str(binary), str(source), INPUT_SHA], env)
watchdog = False
while True:
    done, status, usage = os.wait4(pid, os.WNOHANG)
    if done:
        break
    if time.monotonic() - started > 360:
        watchdog = True
        os.killpg(pid, signal.SIGTERM)
        for _ in range(40):
            done, status, usage = os.wait4(pid, os.WNOHANG)
            if done:
                break
            time.sleep(0.25)
        if not done:
            os.killpg(pid, signal.SIGKILL)
            done, status, usage = os.wait4(pid, 0)
        break
    time.sleep(0.25)
out.close()
err.close()
observed = dict(identity=identity(), elapsed_seconds=time.monotonic() - started, wait_status=status, exit_code=os.waitstatus_to_exitcode(status), watchdog_terminated=watchdog, child_user_cpu_seconds=usage.ru_utime, child_system_cpu_seconds=usage.ru_stime, child_max_rss_kib=usage.ru_maxrss, stdout_sha256=sha(receipt / 'native.stdout'), stderr_sha256=sha(receipt / 'native.stderr'), scope='Original native process wait4 with joined descendants; compilation retained separately; no deadline credit or refund.')
native = operation_output / 'native-result.json'
if native.is_file():
    result = json.loads(native.read_text())
    observed.update(native_result_sha256=sha(native), native_passed=result.get('passed'), native_stage=result.get('stage'), native_error=result.get('error'), paged_custody=result.get('paged_custody'))
write(receipt / 'execution-result.json', observed)
print(json.dumps(observed), flush=True)
raise SystemExit(0 if observed.get('native_passed') and observed['exit_code'] == 0 and not watchdog else 1)
