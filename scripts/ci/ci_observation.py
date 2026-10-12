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


def _source_error(expected_commit: str) -> str | None:
    """Reuse the existing raw-byte verifier; no cached verdict grants execution."""
    from verify_ci_source import verify
    if type(expected_commit) is not str:
        return 'noncanonical expected source'
    try:
        verify('head', expected_commit, root=ROOT)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        return str(error)
    return None


def run(command: list[str], log: Path, *, timeout: int = 900,
        env: dict[str, str] | None = None, cwd: Path = ROOT,
        expected_source: str | None = None) -> dict:
    started = time.monotonic_ns()
    timed_out = False
    executed = False
    process_code = None
    source_error = None
    source_phase = None
    code = 125
    with log.open('xb') as stream:
        if expected_source is not None:
            source_error = _source_error(expected_source)
            if source_error is not None:
                source_phase = 'before'
        if source_error is None:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            executed = True
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        pass
                finally:
                    # Waiting for the leader does not wait for its process group.
                    # Even a TERM handler that exits zero can leave descendants
                    # holding this log open. Always signal the timed-out group;
                    # never turn the leader's graceful exit into a successful run.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                code = 124
            process_code = process.returncode
    if executed and expected_source is not None:
        source_error = _source_error(expected_source)
        if source_error is not None:
            source_phase = 'after'
            # Keep the original nonzero process/timeout outcome. Only an
            # otherwise successful command needs a distinct source refusal.
            if code == 0:
                code = 125
    result = {'command': command, 'cwd': str(cwd), 'exit_code': code,
              'timed_out': timed_out, 'elapsed_ns': time.monotonic_ns() - started,
              'log': log.name, 'executed': executed,
              'process_exit_code': process_code}
    if expected_source is not None:
        result.update(expected_source=expected_source,
                      source_before_verified=source_phase != 'before',
                      source_after_verified=executed and source_error is None,
                      source_verified=executed and source_error is None)
        if source_error is not None:
            result.update(source_error=source_error, source_failure_phase=source_phase)
    return result


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


def pin_source() -> str:
    """Pin the actual tested commit once, including a prospective-merge commit.

    Workflow guards still own candidate/base/ordered-merge policy. This pin only
    prevents commands within one report from silently changing tested source.
    """
    observed = source()
    if observed['source_state'] != 'committed-clean':
        raise ValueError('CI_SOURCE_NOT_COMMITTED_CLEAN')
    return observed['commit']


def finish(output: Path, report: dict, inputs: list[str]) -> None:
    report['source'] = source()
    expected = report.get('source_expected')
    current = report['source']
    consistent = (type(expected) is str and current['commit'] == expected and
                  current['source_state'] == 'committed-clean' and
                  current['tracked_worktree_verified'] is True)
    report['source_consistent'] = consistent
    if not consistent:
        # A clean different commit is just as unsuitable as dirty source. Do
        # not overwrite a primary failure, or hash untrusted changed inputs.
        report['result'] = 'FAIL'
        report['source_error'] = 'CI_SOURCE_EXPECTATION_MISSING_OR_CHANGED'
    report['input_sha256'] = ({name: digest(ROOT / name) for name in inputs}
                              if consistent else {})
    report['artifact_sha256'] = {str(p.relative_to(output)): digest(p)
                                for p in sorted(output.rglob('*')) if p.is_file()}
    (output / 'manifest.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'result': report['result'], 'receipt': str(output)}, sort_keys=True))
