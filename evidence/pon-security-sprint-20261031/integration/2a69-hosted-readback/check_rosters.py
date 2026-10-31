#!/usr/bin/env python3
"""Exercise the actual workflow roster predicates; never execute native code."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile


def workflow_fragment(text: str, count: int) -> str:
    start = text.index(f'test "$(grep -Ec \'^test result: ok\\. {count} passed;')
    end_marker = f'")" = {count}'
    end = text.index(end_marker, start) + len(end_marker)
    fragment = text[start:end]
    assert len(re.findall(r'^\s+store::native_authenticated', fragment, re.M)) == count
    return fragment


def check(fragment: str, text: str, relative: str) -> int:
    with tempfile.TemporaryDirectory(prefix='pon-roster-reader-') as tmp:
        Path(tmp, relative).write_text(text)
        env = dict(os.environ, OUT=tmp, name='store__native_authenticated__')
        run = subprocess.run(['bash', '-c', 'set -euo pipefail\n'+fragment], env=env,
                             text=True, capture_output=True, timeout=10)
        return run.returncode


def cases(text: str, count: int, old_count: int, prefix: str):
    names = [line for line in text.splitlines(keepends=True)
             if line.startswith('test '+prefix) and line.rstrip().endswith(' ... ok')]
    assert len(names) == count
    summary = next(line for line in text.splitlines(keepends=True)
                   if line.startswith('test result:'))
    return [
        ('complete-roster', text, 0),
        ('missing-name', text.replace(names[0], '', 1), 1),
        ('duplicate-name', text.replace(names[0], names[0]+names[0], 1), 1),
        ('renamed-name', text.replace(names[-1], names[-1].replace(' ... ok', '_other ... ok'), 1), 1),
        ('ignored-name', text.replace(names[-1], names[-1].replace(' ... ok', ' ... ignored'), 1), 1),
        ('failed-name', text.replace(names[-1], names[-1].replace(' ... ok', ' ... FAILED'), 1), 1),
        ('old-summary', text.replace(f'{count} passed;', f'{old_count} passed;', 1), 1),
        ('duplicate-summary', text.replace(summary, summary+summary, 1), 1),
        ('failed-summary', text.replace('0 failed;', '1 failed;', 1), 1),
        ('empty', '', 1),
    ]


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--workflow', type=Path, required=True)
    p.add_argument('--artifact', type=Path, required=True)
    p.add_argument('--inventory', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    workflow = args.workflow.read_text()
    with zipfile.ZipFile(args.artifact) as archive:
        native = archive.read('native-snapshots.log').decode()
    inv = json.loads(args.inventory.read_text())
    names = [row['name'] for row in inv['tests']]
    assert len(names) == len(set(names)) == 60
    # This second transcript is explicitly synthetic; the failed job never ran this suite.
    synthetic = ('running 60 tests\n' + ''.join(f'test {n} ... ok\n' for n in names)
                 + 'test result: ok. 60 passed; 0 failed; 0 ignored; 0 measured; '
                 + '0 filtered out; finished in 0.00s\n')
    observations = []
    for count, old_count, text, prefix, filename, scope in [
        (22, 20, native, 'store::native_authenticated_tests::', 'native-snapshots.log',
         'actual ARM prospective-merge native transcript, then explicit mutations'),
        (60, 56, synthetic, 'store::native_authenticated::', 'store__native_authenticated__.log',
         'synthetic reader fixture from source inventory; no native execution'),
    ]:
        fragment = workflow_fragment(workflow, count)
        for case, mutated, expected in cases(text, count, old_count, prefix):
            rc = check(fragment, mutated, filename)
            passed = rc == 0
            if passed != (expected == 0):
                raise ValueError(f'unexpected predicate outcome: {count}/{case}: {rc}')
            observations.append({'count': count, 'case': case, 'scope': scope,
                                 'exit_code': rc, 'accepted': passed})
    result = {'schema': 'pon-recent-roster-readback-controls-v1', 'result': 'PASS',
              'scope': 'actual workflow log predicates only; not native test execution',
              'workflow_sha256': hashlib.sha256(args.workflow.read_bytes()).hexdigest(),
              'artifact_sha256': hashlib.sha256(args.artifact.read_bytes()).hexdigest(),
              'inventory_sha256': hashlib.sha256(args.inventory.read_bytes()).hexdigest(),
              'controls': len(observations), 'observations': observations}
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='observations'}))


if __name__ == '__main__':
    main()
