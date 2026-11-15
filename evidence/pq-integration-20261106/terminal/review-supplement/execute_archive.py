#!/usr/bin/env python3
"""Execute the authorized frozen scan and archive, retaining each original result."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path('/workspace/scratch/8a6ecb667c1e')
REVIEW = ROOT / 'terminal-evidence-review-supplement-final-20261106-v1'
PLAN = ROOT / 'terminal-evidence-preparation-v1/frozen-selection-ready-v5.json'
OUTPUT = ROOT / 'terminal-evidence-curated-final-20261106-v1'
PLAN_SHA = 'a13a654264d6409f40d642c8f04976fb6ed1f146403b45ed42f4217778b047fa'
METHODS = {
    'scan_terminal_sensitive_patterns_v1.py': '79424d0b5e0ba3da7496263f057e717acab5c8027087414ef3a32f3b2a3119a7',
    'collect_terminal_increment_v2.py': '5320a3097a0757dc1b92d460026e3409ebb113e0eb64837e9a27b0317fee2649',
    'verify_curated_evidence.py': 'ad84ee5ccec29a339a54a20a863e964ced941821321c87f10e188de9979174c4',
}

def identity(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

def save(path, data):
    with path.open('x') as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write('\n')

def available():
    value = os.statvfs(ROOT)
    return value.f_bavail * value.f_frsize

assert identity(PLAN)['sha256'] == PLAN_SHA
assert not OUTPUT.exists(), 'fresh collection output is required'
plan = json.loads(PLAN.read_text())
assert plan['state'] == 'FROZEN_INPUT_SELECTION_READY'
assert available() > 4 * plan['bytes'] + 64 * 1024 * 1024
method_ids = []
for filename, expected in METHODS.items():
    row = identity(ROOT / 'integration-review' / filename)
    assert row['sha256'] == expected
    method_ids.append(row)
commands = [
    ('limited-sensitive-pattern-scan', [
        'python', str(ROOT / 'integration-review/scan_terminal_sensitive_patterns_v1.py'),
        '--plan', str(PLAN), '--report', str(REVIEW / 'sensitive-pattern-review.json')]),
    ('frozen-input-collection-and-package', [
        'python', str(ROOT / 'integration-review/collect_terminal_increment_v2.py'),
        '--plan', str(PLAN), '--output', str(OUTPUT), '--package']),
]
save(REVIEW / 'execution-configuration.json', {
    'schema': 'trnm-terminal-frozen-archive-controller-v1', 'plan': identity(PLAN),
    'candidate': plan['candidate'], 'tree': plan['tree'], 'methods': method_ids,
    'controller': identity(Path(__file__)), 'python': sys.version, 'python_executable': sys.executable,
    'working_directory': str(ROOT), 'commands': [{'label': l, 'argv': a} for l, a in commands],
    'available_bytes_before': available(), 'native_tests_executed': 0,
    'external_review_not_in_its_own_archive': True,
})

def interrupted(signum, frame):
    raise KeyboardInterrupt('controller signal ' + str(signum))

signal.signal(signal.SIGTERM, interrupted)
receipts = []
for label, argv in commands:
    assert identity(PLAN)['sha256'] == PLAN_SHA
    stdout = REVIEW / (label + '.stdout.log')
    stderr = REVIEW / (label + '.stderr.log')
    before = available()
    started = time.time_ns()
    monotonic = time.monotonic_ns()
    interrupted_note = None
    with stdout.open('xb') as out, stderr.open('xb') as err:
        child = subprocess.Popen(argv, cwd=ROOT, stdout=out, stderr=err, start_new_session=True)
        try:
            code = child.wait()
        except BaseException as exc:
            interrupted_note = type(exc).__name__ + ': ' + str(exc)
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
            code = child.returncode
    receipt = {'schema': 'trnm-terminal-archive-command-receipt-v1', 'label': label,
               'argv': argv, 'cwd': str(ROOT), 'exit_code': code,
               'started_epoch_ns': started, 'elapsed_ns': time.monotonic_ns() - monotonic,
               'stdout': identity(stdout), 'stderr': identity(stderr),
               'plan': identity(PLAN), 'interrupted': interrupted_note,
               'available_bytes_before': before, 'available_bytes_after': available(),
               'native_tests_executed': 0, 'raw_observations_modified': False}
    assert receipt['plan']['sha256'] == PLAN_SHA
    dest = REVIEW / (label + '.receipt.json')
    save(dest, receipt)
    receipts.append(identity(dest))
    print(json.dumps({'label': label, 'exit_code': code, 'receipt': identity(dest)}, sort_keys=True), flush=True)
    if code != 0 or interrupted_note is not None:
        save(REVIEW / 'execution-terminal.json', {'state': 'STOPPED_WITH_ORIGINAL_FAILURE',
             'failed_label': label, 'receipts': receipts, 'native_tests_executed': 0,
             'evidence_rewritten': False})
        raise SystemExit(code if code > 0 else 1)
    if label == 'limited-sensitive-pattern-scan':
        result = json.loads((REVIEW / 'sensitive-pattern-review.json').read_text())
        assert result['result'] == 'NO_MATCH_FOR_THESE_LIMITED_PATTERNS' and not result['findings']

index = OUTPUT / 'publication/archive-index.json'
verification = OUTPUT / 'publication/archive-verification.json'
assert json.loads(verification.read_text())['result'] == 'PASS_ARCHIVE_CONTENT_ONLY'
save(REVIEW / 'execution-terminal.json', {
    'state': 'SCAN_AND_COLLECTION_COMPLETE_ARCHIVE_INTEGRITY_ONLY', 'receipts': receipts,
    'index': identity(index), 'verification': identity(verification), 'plan': identity(PLAN),
    'available_bytes_after': available(), 'native_tests_executed': 0,
    'whole_chain_pq_qualified': False, 'original_native_failures_reclassified': False,
    'independent_roundtrip_may_start_now': True,
})
print(json.dumps({'state': 'COMPLETE_ARCHIVE_INTEGRITY_ONLY', 'index': identity(index),
                  'available_bytes_after': available()}, sort_keys=True), flush=True)
