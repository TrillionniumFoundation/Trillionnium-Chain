import datetime, hashlib, json, os, subprocess, sys, time
from pathlib import Path
ROOT = Path('/workspace/scratch/ab60bfa410b1/root-cleanup')
OUT = Path('/workspace/scratch/ab60bfa410b1/root-cleanup-validation/exact-commit')
COMMIT = '0f6598454b0d743259579e7e193b1158e5c9353d'
TREE = 'b3cab76d5cf4321d94a6b8c64f578717d749c83e'
BASE = '44330b91eb552fd20ef6f2e69bf5e6f1e8f5c0b0'
COMMANDS = {
 'preflight': ['bash', 'scripts/project-preflight.sh'],
 'materialize': ['git', 'sparse-checkout', 'disable'],
 'source-before': ['python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head', '--expected-head', COMMIT, '--output', str(OUT / 'source-before-identity.json')],
 'cleanup': ['python3', 'formal/pon-nakamoto-v1/test_pq_root_journal_cleanup.py', '-v'],
 'dependency-controls': ['python3', 'scripts/ci/test_pq_root_dependency_register.py'],
 'source-controls': ['python3', 'scripts/ci/test_ci_source_integrity.py'],
 'ci-contract-controls': ['python3', 'scripts/ci/test_ci_contract.py'],
 'corpus-controls': ['python3', 'scripts/ci/test_pq_research_integration.py'],
 'dependency-register': ['python3', 'scripts/ci/pq_root_dependency_register.py'],
 'ci-contract': ['python3', 'scripts/ci/check_ci_contract.py'],
 'corpus': ['python3', 'scripts/ci/check_pq_research_integration.py'],
 'diff-check': ['git', 'diff', '--check', BASE, COMMIT],
 'source-after': ['python3', 'scripts/ci/verify_ci_source.py', '--kind', 'head', '--expected-head', COMMIT, '--output', str(OUT / 'source-after-identity.json')],
}
name = sys.argv[1]
assert name in COMMANDS
for suffix in ['.json', '.log']:
 if (OUT / (name + suffix)).exists():
  raise SystemExit('refusing to overwrite an earlier observation: '+ name)
def git(*args):
 return subprocess.check_output(['git', '--no-replace-objects', *args], cwd=ROOT, text=True).strip()
assert git('rev-parse', 'HEAD') == COMMIT
assert git('rev-parse', 'HEAD^{tree}') == TREE
record = {'name': name, 'argv': COMMANDS[name], 'cwd': str(ROOT), 'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'tested_commit': COMMIT, 'tested_tree': TREE, 'environment': {'PYTHONDONTWRITEBYTECODE': '1'}}
start = time.monotonic()
with (OUT / (name + '.log')).open('wb') as log:
 result = subprocess.run(COMMANDS[name], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), check=False)
data = (OUT / (name + '.log')).read_bytes()
record.update({'elapsed_seconds': time.monotonic()-start, 'returncode': result.returncode, 'log': str(OUT / (name + '.log')), 'log_sha256': hashlib.sha256(data).hexdigest(), 'head_after': git('rev-parse', 'HEAD'), 'tree_after': git('rev-parse', 'HEAD^{tree}'), 'finished_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()})
(OUT / (name + '.json')).write_text(json.dumps(record, indent=2)+'\n')
print(json.dumps(record))
print(data.decode('utf-8','replace')[-1800:])
sys.exit(result.returncode)
