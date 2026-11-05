import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import time
import unittest

root = pathlib.Path('/workspace/scratch/aea25ba345a8/research-agent').resolve()
out = pathlib.Path('/workspace/scratch/aea25ba345a8/research-run')
out.mkdir(exist_ok=True)
sys.dont_write_bytecode = True
sys.path[:0] = [str(root / 'formal/pon-nakamoto-v1'), str(root / 'scripts/ci')]
opened = set()

def audit(event, args):
    if event != 'open' or not isinstance(args[0], (str, bytes)):
        return
    name = args[0].decode() if isinstance(args[0], bytes) else args[0]
    path = pathlib.Path(name)
    if not path.is_absolute():
        path = pathlib.Path.cwd() / path
    try:
        rel = path.resolve().relative_to(root)
    except (OSError, ValueError):
        return
    if '.git' not in rel.parts and '__pycache__' not in rel.parts:
        opened.add(str(rel))

sys.addaudithook(audit)
names = [
    'test_reversible_components', 'test_w1_quantum_oracle',
    'test_quantum_oracle_resources', 'test_quantum_resource_clock',
    'test_quantum_candidate_check_clock', 'test_quantum_network_sim',
    'test_quantum_adversarial_search', 'test_quantum_daa_model',
    'test_parallel_variable_ohie', 'test_w1_quantum_restricted_oracle',
    'test_fast_daa_reference_component',
]
paths = [root / 'formal/pon-nakamoto-v1' / (name + '.py') for name in names]
paths += [root / 'scripts/ci/test_pq_quantum_daa_scenarios.py',
          root / 'scripts/ci/test_w1_security_budget.py']
suite = unittest.TestSuite()
for path in paths:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
start = time.monotonic()
with (out / 'tests.log').open('w') as stream:
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
duration = time.monotonic() - start
inputs = []
for rel in sorted(opened):
    path = root / rel
    if not path.is_file():
        continue
    raw = path.read_bytes()
    git_blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    inputs.append({'path': rel, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                   'git_blob': git_blob})
report = {
    'checkout_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
    'target_research_source': 'ef1fa4d48ab9894f3d7a4b1c797ca9e7e490b155',
    'scope': '13 research and component-budget suites; no native, WAN, QROM theorem or independent deployment acceptance',
    'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
    'skipped': len(result.skipped), 'seconds': duration,
    'failed_ids': [test.id() for test, _ in result.failures],
    'error_ids': [test.id() for test, _ in result.errors],
    'inputs': inputs,
    'production_qualified': False, 'security_theorem': False,
}
(out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({key: value for key, value in report.items() if key != 'inputs'}))
raise SystemExit(not result.wasSuccessful())
