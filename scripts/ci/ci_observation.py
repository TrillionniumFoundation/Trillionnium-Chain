#!/usr/bin/env python3
"""Small bounded command/receipt owner for CI; failures remain nonzero observations."""
from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def tool_versions() -> dict[str, str]:
    return dict(line.split('=', 1) for line in
                (ROOT / 'scripts/ci/tool-versions.env').read_text().splitlines()
                if line and not line.startswith('#'))


def tool_root() -> Path:
    return Path(os.environ.get('TRNM_CI_TOOL_ROOT',
                str(Path(os.environ.get('RUNNER_TEMP', '/tmp')) / 'trnm-ci-tools')))


def receipt_root(kind: str) -> Path:
    base = Path(os.environ.get('TRNM_CI_RECEIPT_DIR',
                str(Path(os.environ.get('RUNNER_TEMP', '/tmp')) / 'trnm-ci-evidence')))
    result = base / kind
    # Reusing a result directory could relabel a prior failure or corpus as this run.
    result.mkdir(parents=True, exist_ok=False)
    return result


def run(command: list[str], log: Path, *, timeout: int = 900,
        env: dict[str, str] | None = None, cwd: Path = ROOT) -> dict:
    started = time.monotonic_ns()
    timed_out = False
    with log.open('xb') as stream:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            code = 124
    return {'command': command, 'cwd': str(cwd), 'exit_code': code,
            'timed_out': timed_out, 'elapsed_ns': time.monotonic_ns() - started,
            'log': log.name}


def checked(command: list[str], log: Path, observations: list[dict], **kwargs) -> dict:
    result = run(command, log, **kwargs)
    observations.append(result)
    if result['exit_code'] != 0:
        raise RuntimeError(f"command exited {result['exit_code']}; retained {log}")
    return result


def source() -> dict:
    # Reuse the exact worktree predicate used by the head/merge guards. Git's
    # cached status alone can hide changed source; a receipt must not relabel it.
    from verify_ci_source import verify
    git = lambda *args: subprocess.check_output(
        ['git', '--no-replace-objects', *args], cwd=ROOT, text=True).strip()
    commit = git('rev-parse', 'HEAD')
    result = {'commit': commit, 'tree': git('rev-parse', commit + '^{tree}'),
              'source_state': 'dirty-candidate', 'tracked_worktree_verified': False}
    try:
        verified = verify('head', commit, root=ROOT)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        result['source_verification_error'] = str(error)
    else:
        result.update(source_state='committed-clean', tracked_worktree_verified=True,
                      tracked_entries=verified['tracked_entries'],
                      tracked_bytes=verified['tracked_bytes'])
    return result


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def finish(output: Path, report: dict, inputs: list[str]) -> None:
    report['source'] = source()
    report['input_sha256'] = {name: digest(ROOT / name) for name in inputs}
    report['artifact_sha256'] = {str(p.relative_to(output)): digest(p)
                                for p in sorted(output.rglob('*')) if p.is_file()}
    (output / 'manifest.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'result': report['result'], 'receipt': str(output)}, sort_keys=True))
