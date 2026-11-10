#!/usr/bin/env python3
"""Replay changed log gates on retained, timestamp-stripped hosted test spans.

This does not launch Rust tests or qualify the changed native source. Original
GitHub logs remain separate; derived spans retain their original line ranges.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import textwrap

REPO = Path('/workspace/scratch/23345083847a/Trillionnium-Chain')
OUT = Path(__file__).resolve().parent
OBSERVATIONS = OUT.parent / 'observations'
SUITES = ('factorial-kernel-tests', 'factorial-example-tests',
          'header-binding-tests', 'history-w1-tests', 'history-import-tests',
          'cpu-completion-tests')


def extract(job, names):
    path = OBSERVATIONS / f'gh-job-{job}.log'
    raw = path.read_bytes()
    lines = raw.decode().splitlines()
    stripped = [re.sub(r'^\d{4}-\d\d-\d\dT\S+Z ', '', line) for line in lines]
    spans = []
    for start, line in enumerate(stripped):
        if re.fullmatch(r'running [0-9]+ tests?', line):
            end = next(index for index in range(start + 1, len(stripped))
                       if stripped[index].startswith('test result:'))
            spans.append((start, end))
    if len(spans) != len(names):
        raise ValueError(('HOSTED_SUITE_COUNT', job, len(spans), len(names)))
    result = []
    for name, (start, end) in zip(names, spans):
        data = ('\n'.join(stripped[start:end + 1]) + '\n').encode()
        target = OUT / 'extracted-hosted' / (name + '.log')
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(data)
        result.append(dict(suite=name, original_first_line=start + 1,
                           original_last_line=end + 1, output=str(target),
                           bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
    return dict(job_id=job, original=str(path), original_bytes=len(raw),
                original_sha256=hashlib.sha256(raw).hexdigest(), spans=result)


def main(label):
    original = [extract(129678540672, ('legal-native-controls',)),
                extract(129678540829, SUITES)]
    workflow = (REPO / '.github/workflows/pon-w1-work-security.yml').read_text()
    legal_marker = 'python3 - "$OUT/legal-native-controls.log" <<\'PY\'\n'
    legal = textwrap.dedent(workflow.split(legal_marker, 1)[1].split('          PY', 1)[0])
    factorial = textwrap.dedent(workflow.split("<<'PYTEST'\n", 1)[1].split('          PYTEST', 1)[0])
    results = []
    for name, code, argument in (
        ('legal', legal, OUT / 'extracted-hosted/legal-native-controls.log'),
        ('factorial', factorial, OUT / 'extracted-hosted'),
    ):
        result = subprocess.run([sys.executable, '-c', code, str(argument)],
                                capture_output=True)
        for stream, data in (('stdout', result.stdout), ('stderr', result.stderr)):
            (OUT / f'{label}-hosted-{name}.{stream}.log').write_bytes(data)
        results.append(dict(gate=name, exit_code=result.returncode,
                            stdout=result.stdout.decode(), stderr=result.stderr.decode(),
                            code_sha256=hashlib.sha256(code.encode()).hexdigest()))
    report = dict(scope='gate replay only on historical hosted logs; no new Rust execution',
                  workflow_sha256=hashlib.sha256(workflow.encode()).hexdigest(),
                  original_logs=original, results=results)
    (OUT / f'{label}-hosted-gates.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main(sys.argv[1])
