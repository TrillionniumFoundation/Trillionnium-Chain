#!/usr/bin/env python3
"""Synthetic finite-timeout mechanism; never a model or campaign execution.

The old pilot caller passed a finite 14,400-second timeout to command(). This
control invokes that same generic helper with a short timeout and disposable
Python descendants. It also records whether the CURRENT pilot caller has been
changed to timeout=None. The first independent observation is preserved in the
record; that initial ad-hoc run did not capture the complete source hash.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    repo = Path(args.repository).resolve()
    source_path = repo / 'scripts/ci/llm_hosted_once.py'
    raw = source_path.read_bytes()
    parsed = ast.parse(raw, str(source_path))
    helper = next(node for node in parsed.body
                  if isinstance(node, ast.FunctionDef) and node.name == 'command')
    caller = [node for node in ast.walk(parsed)
              if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
              and node.func.id == 'command' and len(node.args) >= 2
              and isinstance(node.args[1], ast.Constant)
              and node.args[1].value == 'original-pilot']
    assert len(caller) == 1, 'one fixed original-pilot call is required'
    current_timeout = ast.literal_eval(caller[0].args[-1])
    module = types.ModuleType('hosted_timeout_fixture')
    module.__file__ = str(source_path)
    # Compile exactly the source bytes whose SHA is recorded. Only command()
    # is invoked; no registration, authority, download or model entry is used.
    exec(compile(raw, str(source_path), 'exec'), module.__dict__)
    with tempfile.TemporaryDirectory(prefix='hosted-timeout-independent-') as temporary:
        root = Path(temporary)
        marker = root / 'descendant-after-timeout.txt'
        child = ('import pathlib,time; time.sleep(0.5); pathlib.Path('
                 + repr(str(marker)) + ').write_text("continued")')
        outer = ('import subprocess,sys,time; subprocess.Popen([sys.executable,'
                 '"-I","-S","-B","-c",' + repr(child) + ']); time.sleep(5)')
        timed_out = False
        started = time.monotonic_ns()
        try:
            module.command(root, 'synthetic-timeout',
                [sys.executable, '-I', '-S', '-B', '-c', outer], repo, 0.2)
        except subprocess.TimeoutExpired:
            timed_out = True
        # The disposable descendant exits immediately after writing its marker.
        time.sleep(0.8)
        observation = dict(outer_timeout_observed=timed_out,
            descendant_completed_after_timeout=marker.exists(),
            terminal_record_created=(root / 'synthetic-timeout-exit.json').exists(),
            elapsed_ns=time.monotonic_ns() - started)
    record = dict(schema='hosted-timeout-descendant-control-v1',
        scope='synthetic-former-finite-timeout-mechanism-and-current-call-site-only',
        model_executed=False, trial_created=False, source_path=str(source_path),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        command_source_sha256=hashlib.sha256(
            ast.get_source_segment(raw.decode(), helper).encode()).hexdigest(),
        python=sys.version, executable=sys.executable,
        former_pilot_timeout_seconds=14400, synthetic_timeout_seconds='0.2',
        current_pilot_timeout=current_timeout,
        current_pilot_has_no_independent_timeout=current_timeout is None,
        first_independent_observation=dict(
            source_sha256_captured=False, outer_timeout_observed=True,
            descendant_completed_after_timeout=True, terminal_record_created=False,
            note='Preserved ad-hoc control observed before the original-pilot call was fixed.'),
        bounded_reproduction=observation)
    with Path(args.output).open('x') as handle:
        json.dump(record, handle, sort_keys=True, indent=2)
        handle.write('\n')
    print(json.dumps(record, sort_keys=True))
    if not (observation['outer_timeout_observed']
            and observation['descendant_completed_after_timeout']
            and not observation['terminal_record_created']):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
