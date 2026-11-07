#!/usr/bin/env python3
"""Retain one actual Cargo test artifact and every native result."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

p = argparse.ArgumentParser()
p.add_argument('--build-log', type=Path, required=True)
p.add_argument('--target', required=True)
p.add_argument('--selector', default='')
p.add_argument('--exact', action='store_true')
p.add_argument('--include-ignored', action='store_true')
p.add_argument('--expected-count', type=int)
p.add_argument('--output', type=Path, required=True)
args = p.parse_args()
artifacts = {}
for line in args.build_log.read_text().splitlines():
    item = json.loads(line)
    if item.get('reason') == 'compiler-artifact' and item.get('executable') and item.get('profile', {}).get('test'):
        artifacts[item['target']['name']] = item
artifact = artifacts[args.target]
binary = Path(artifact['executable'])
binary_hash = hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest()
args.output.mkdir(parents=True, exist_ok=False)
source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], text=True).strip()
status_before = subprocess.check_output(['git', 'status', '--porcelain=v1'], text=True)
command = [str(binary)]
if args.selector:
    command.append(args.selector)
if args.exact:
    command.append('--exact')
if args.include_ignored:
    command.append('--include-ignored')
command += ['--nocapture', '--test-threads=1']
started = time.monotonic_ns()
with (args.output/'stdout.log').open('wb') as stdout, (args.output/'stderr.log').open('wb') as stderr:
    child = subprocess.Popen(command, stdout=stdout, stderr=stderr)
    _, status, usage = os.wait4(child.pid, 0)
    child.returncode = os.waitstatus_to_exitcode(status)
elapsed = time.monotonic_ns() - started
stdout = (args.output/'stdout.log').read_text()
counts = re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out', stdout)
executed = sum(int(row[1]) + int(row[2]) for row in counts)
harness_accepted = (child.returncode == 0 and len(counts) == 1 and executed > 0
                    and (args.expected_count is None or executed == args.expected_count))
status_after = subprocess.check_output(['git', 'status', '--porcelain=v1'], text=True)
result = {
    'schema': 'native-test-execution-v1',
    'source_commit': source, 'source_tree': tree, 'cwd': str(Path.cwd()),
    'worktree_clean_before': not status_before, 'worktree_clean_after': not status_after,
    'test_artifact': artifact, 'binary_sha256': binary_hash,
    'binary_unchanged': hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest() == binary_hash,
    'command': command, 'exit_code': child.returncode, 'elapsed_ns': elapsed,
    'user_cpu_s': usage.ru_utime, 'system_cpu_s': usage.ru_stime, 'max_rss_kib': usage.ru_maxrss,
    'native_summaries': counts, 'physical_host_qualification': False,
    'expected_count': args.expected_count, 'executed_count': executed,
    'harness_accepted': harness_accepted,
    'performance_or_throughput_claim': False,
}
for name in ['stdout.log', 'stderr.log']:
    result[name+'_sha256'] = hashlib.sha256((args.output/name).read_bytes()).hexdigest()
(args.output/'execution.json').write_text(json.dumps(result, indent=2)+'\n')
print(json.dumps({key: result[key] for key in ['source_commit', 'binary_sha256', 'exit_code', 'elapsed_ns', 'native_summaries']}))
raise SystemExit(0 if harness_accepted else child.returncode or 3)
