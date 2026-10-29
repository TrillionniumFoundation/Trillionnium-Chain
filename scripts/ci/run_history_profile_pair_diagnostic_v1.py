#!/usr/bin/env python3
"""Execute exact original step bodies sequentially, retaining both verdicts.

This file has not been executed on a real hosted runner. It must not be treated
as a completed comparison or a replacement for either original campaign gate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

WORKFLOW = '.github/workflows/pon-native-campaign-qualification.yml'
WORKFLOW_SHA = '66a2b12994764f30d69b882001e38fe9921bcef40034dd90de6c033541354d84'
PROFILE = {'strict': 'strict-every-native-checkpoint-v1',
           'n8': 'history-account-graph-resource-fence-v1'}
ORDERS = {'strict-then-n8': ('strict', 'n8'), 'n8-then-strict': ('n8', 'strict')}
ARM_SECONDS = 80 * 60
CLEANUP_NAME = 'Close only parents bound to this run by a root-owned exclusive lease'
NATIVE_NAME = 'Run three original campaigns under verified actual limits'
CLEANUP_SECONDS = 220
INTERRUPTED_SIGNAL = None


def interrupt(signum, _frame):
    # Do not raise asynchronously inside Popen's fork/exec/handle publication.
    # Once the owned child handle is available, invoke observes this flag and
    # signals only that still-unreaped process group. Repeated signals cannot
    # interrupt the finite safety cleanup itself.
    global INTERRUPTED_SIGNAL
    if INTERRUPTED_SIGNAL is None:
        INTERRUPTED_SIGNAL = signum


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def write(path, value):
    pending = path.with_suffix('.pending')
    pending.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    pending.replace(path)


def extract_original_steps(path):
    require(digest(path) == WORKFLOW_SHA, 'original workflow bytes changed; review and repin explicitly')
    chunks = re.split(r'^      - name: ', path.read_text(), flags=re.M)[1:]
    result = []
    for chunk in chunks:
        name = chunk.splitlines()[0]
        if '\n        run: |\n' not in chunk:
            continue
        body = chunk.split('\n        run: |\n', 1)[1]
        lines = []
        for line in body.splitlines(keepends=True):
            if line.strip() and not line.startswith('          '):
                break
            lines.append(line[10:] if line.startswith('          ') else line)
        if name == 'Reserve new output and isolated Cargo directories':
            continue  # Only artifact-directory plumbing is supplied per arm.
        timeout = re.search(r'^        timeout-minutes: ([1-9][0-9]*)$', chunk, re.M)
        result.append({'name': name, 'always': '\n        if: always()\n' in chunk,
                       'code': ''.join(lines),
                       'timeout_seconds': int(timeout.group(1)) * 60 if timeout else None})
    require(len(result) == 12 and len({r['name'] for r in result}) == 12,
            'exact original twelve native/readback/cleanup step bodies required')
    require([r['name'] for r in result if r['always']] == [
        'Require actual controller-death closure with the same release binary', CLEANUP_NAME,
        'Preserve final source verification and all partial artifact hashes'],
        'original unconditional lifeline, owned cleanup and source retention required')
    return result


def host_observation():
    models = sorted({line.partition(':')[2].strip() for line in Path('/proc/cpuinfo').read_text().splitlines()
                     if line.startswith('model name')})
    return {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'cpu_models': models, 'affinity': sorted(os.sched_getaffinity(0)),
            'hostname': os.uname().nodename, 'kernel': os.uname().release,
            'observation_is_authority': False}


def stop_owned_group(child, grace_seconds=20):
    # Keep the direct child unreaped until the last group signal. Its PID cannot
    # then be reused for a foreign process group. A leader exiting on TERM does
    # not prove that a grandchild has stopped; always send the final KILL before
    # wait(), including when the leader has already become a zombie.
    if child.returncode is not None:
        # A signal may arrive just after a successful wait has already reaped
        # the child. Never use that now-reusable PID as signalling authority.
        return child.returncode
    for signum, delay in ((signal.SIGTERM, grace_seconds), (signal.SIGKILL, 0)):
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            pass
        if delay:
            time.sleep(delay)
    return child.wait(timeout=5)


def invoke(script, log, root, env, deadline, *, grace_seconds=20, accept_interrupt=True):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'returncode': None, 'timed_out': True, 'executed': False}
    if accept_interrupt and INTERRUPTED_SIGNAL is not None:
        return {'returncode': None, 'timed_out': False, 'executed': False,
                'interrupted_signal': INTERRUPTED_SIGNAL}
    with log.open('xb') as output:
        child = subprocess.Popen(['/usr/bin/bash', '--noprofile', '--norc', '-e', '-o', 'pipefail', str(script)],
                                 cwd=root, env=env, stdout=output, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        started = time.monotonic()
        interrupted_signal = None
        timed_out = False
        try:
            while True:
                remaining = deadline - time.monotonic()
                if accept_interrupt and INTERRUPTED_SIGNAL is not None:
                    interrupted_signal = INTERRUPTED_SIGNAL
                    status = stop_owned_group(child, grace_seconds)
                    break
                if remaining <= 0:
                    status = stop_owned_group(child, grace_seconds)
                    timed_out = True
                    break
                try:
                    status = child.wait(timeout=min(remaining, 0.1))
                    interrupted_signal = INTERRUPTED_SIGNAL if accept_interrupt else None
                    break
                except subprocess.TimeoutExpired:
                    pass
        except BaseException:
            stop_owned_group(child, grace_seconds)
            raise
    return {'returncode': status, 'timed_out': timed_out, 'executed': True,
            'interrupted_signal': interrupted_signal,
            'elapsed_seconds': time.monotonic() - started, 'log_sha256': digest(log),
            'owned_group_signal_is_not_descendant_quiescence_proof': True}


def cleanup_only(root, output, environment):
    """Run the unchanged root-lease cleanup, never a native/lifeline step.

    This entry point is deliberately independent of pair-results.json and of the
    interrupted controller's writable receipts. The original root-only lease is
    still the sole authority to remove either fixed parent. Repeated cleanup
    retains separate attempts and uses the original absent-lease no-op behavior.
    """
    root = root.resolve(strict=True)
    output = output.absolute()
    require(not output.is_symlink(), 'cleanup output cannot be a symlink')
    output = output.resolve()
    require(not output.is_relative_to(root), 'cleanup output outside original source required')
    require(re.fullmatch(r'[1-9][0-9]{0,19}', environment.get('GITHUB_RUN_ID', ''))
            and re.fullmatch(r'[1-9][0-9]{0,9}', environment.get('GITHUB_RUN_ATTEMPT', '')),
            'original numeric run/attempt owner required')
    steps = extract_original_steps(root / WORKFLOW)
    cleanup = next(step for step in steps if step['name'] == CLEANUP_NAME)
    output.mkdir(parents=True, exist_ok=True)
    attempt = Path(tempfile.mkdtemp(prefix='owned-cleanup-', dir=output))
    script = attempt / 'original-cleanup.sh'
    script.write_text(cleanup['code'])
    result = {'schema': 'history-pair-owned-cleanup-v1', 'original_workflow_sha256': WORKFLOW_SHA,
              'exact_original_step_sha256': digest(script), 'run_id': environment['GITHUB_RUN_ID'],
              'run_attempt': environment['GITHUB_RUN_ATTEMPT'], 'complete_success': False,
              'cleanup_is_not_native_completion': True}
    try:
        env = dict(environment, OUT=str(attempt))
        status = invoke(script, attempt / 'cleanup.log', root, env,
                        time.monotonic() + CLEANUP_SECONDS, accept_interrupt=False)
        result.update(status)
        result['complete_success'] = (status['returncode'] == 0 and not status['timed_out']
                                      and status.get('interrupted_signal') is None)
    except BaseException as error:
        result['failure'] = f'{type(error).__name__}: {error}'
    finally:
        write(attempt / 'cleanup-results.json', result)
    return result


def record_arm(output, expected_head):
    campaign = json.loads((output / 'results.json').read_text())
    before = json.loads((output / 'source-before.json').read_text())
    after = json.loads((output / 'source-after.json').read_text())
    require(before == after and before['tested_commit'] == expected_head
            and before['tracked_worktree_verified'] is True, 'same complete immutable source before and after arm')
    binary = campaign['binary']
    require(binary['sha256_before'] == binary['sha256_after'] == digest(output / binary['retained']),
            'actual retained ELF must match all native run receipts')
    require(len(campaign['attempts']) == 3 and all(row['actual_verifier_boundary_readback'] is True
            and row['report_validation_failure'] is None and row['step']['error'] is None
            and row['step']['outer_stage_timeout_seconds'] == 600 for row in campaign['attempts']),
            'all three unchanged original campaigns must complete and retain actual verifier evidence')
    return {'source': before, 'binary_sha256': binary['sha256_after'], 'binary_bytes': binary['bytes'],
            'original_inputs': campaign['original_inputs'], 'expected_resources': campaign['expected_resources'],
            'separate_verifier_limits': campaign['separate_verifier_limits'],
            'history_resource_profile': campaign['history_resource_profile'],
            'campaign_complete_success': campaign['complete_success'],
            'original_attempt_outcomes': [row['original_criteria_met'] for row in campaign['attempts']],
            'lifeline_complete_success': json.loads((output / 'verifier-lifeline/results.json').read_text())['complete_success']}


def run(args):
    root = args.root.resolve(strict=True)
    output = args.output.resolve()
    require(not output.exists() and not output.is_relative_to(root), 'fresh output outside original source required')
    output.mkdir(parents=True)
    steps = extract_original_steps(root / WORKFLOW)
    scripts = output / 'original-step-bodies'; scripts.mkdir()
    for index, step in enumerate(steps):
        path = scripts / f'{index:02}.sh'; path.write_text(step['code'])
        step['script'] = str(path); step['sha256'] = digest(path)
    environment = os.environ.copy()
    # Build/download caches are shared by the two arms, but must not be swept
    # into the evidence artifact. Each arm retains its actual executed ELF.
    cargo_home = output.parent / (output.name + '-cargo-home')
    cargo_target = output.parent / (output.name + '-cargo-target')
    require(not cargo_home.exists() and not cargo_target.exists(), 'fresh shared build directories required')
    environment.update(CARGO_HOME=str(cargo_home), CARGO_TARGET_DIR=str(cargo_target))
    expected_head = environment['EXPECTED_HEAD']
    require(re.fullmatch('[0-9a-f]{40}', expected_head), 'one immutable expected head required')
    result = {'schema': 'history-same-runner-profile-pair-diagnostic-draft-v1',
              'order': list(ORDERS[args.order]), 'arm_budget_seconds': ARM_SECONDS,
              'original_workflow_sha256': WORKFLOW_SHA, 'original_gates_changed': False,
              'pair_binding_valid': False, 'all_original_campaigns_passed': False,
              'all_required_steps_passed': False, 'controller_interrupted_signal': None,
              'production_qualified': False, 'arms': [], 'failure': None,
              'safety_cleanup': None}
    try:
        for label in ORDERS[args.order]:
            arm = output / label; arm.mkdir()
            controller = output / ('controller-' + label); controller.mkdir()
            env_file = controller / 'github-env'; env_file.touch()
            env = dict(environment, OUT=str(arm), GITHUB_ENV=str(env_file), HISTORY_RESOURCE_PROFILE=PROFILE[label])
            arm_record = {'profile': label, 'host_before': host_observation(), 'steps': [],
                          'complete': False, 'required_steps_passed': False}
            result['arms'].append(arm_record)
            write(output / 'pair-results.json', result)
            deadline = time.monotonic() + ARM_SECONDS
            successful = True
            for index, step in enumerate(steps):
                if not successful and not step['always']:
                    arm_record['steps'].append({'name': step['name'], 'skipped_after_failure': True})
                    continue
                # Safety cleanup is outside the elapsed-work budget; no native
                # campaign or lifeline gains more time or earns a late PASS.
                step_deadline = (time.monotonic() + CLEANUP_SECONDS
                                 if step['name'] == CLEANUP_NAME else deadline)
                if step['timeout_seconds'] is not None:
                    step_deadline = min(step_deadline, time.monotonic() + step['timeout_seconds'])
                status = invoke(Path(step['script']), controller / f'{index:02}.log', root, env, step_deadline)
                status.update(name=step['name'], exact_original_step_sha256=step['sha256'])
                arm_record['steps'].append(status)
                successful = successful and status['returncode'] == 0 and not status['timed_out']
                write(output / 'pair-results.json', result)
                require(status.get('interrupted_signal') is None, 'controller interrupted; no next profile')
                for line in env_file.read_text().splitlines():
                    require(re.fullmatch(r'EXPECTED_TREE=[0-9a-f]{40}', line), 'only original expected-tree export permitted')
                    env['EXPECTED_TREE'] = line.partition('=')[2]
                write(output / 'pair-results.json', result)
            arm_record['required_steps_passed'] = (
                len(arm_record['steps']) == len(steps)
                and [row['name'] for row in arm_record['steps']] == [step['name'] for step in steps]
                and all(row.get('executed') is True and row.get('returncode') == 0
                        and row.get('timed_out') is False
                        and row.get('interrupted_signal') is None
                        and not row.get('skipped_after_failure', False)
                        for row in arm_record['steps']))
            arm_record['host_after'] = host_observation()
            cleanup = next(row for row in arm_record['steps'] if row['name'] == CLEANUP_NAME)
            require(cleanup.get('returncode') == 0 and not cleanup.get('timed_out', True),
                    'exact owned cleanup must finish before the next profile can start')
            try:
                arm_record.update(record_arm(arm, expected_head), complete=True)
                require(arm_record['history_resource_profile'] == PROFILE[label], 'one exact requested profile per arm')
            except (OSError, ValueError, KeyError, TypeError) as error:
                # A retained first-arm reader failure is useful paired evidence,
                # not permission to skip the separately declared second arm.
                # Only successful original owned cleanup permits continuation.
                arm_record['complete'] = False
                arm_record['readback_failure'] = f'{type(error).__name__}: {error}'
            write(output / 'pair-results.json', result)
        left, right = result['arms']
        result['all_required_steps_passed'] = all(row['required_steps_passed'] for row in result['arms'])
        require(left['complete'] and right['complete'], 'both original arm readbacks required')
        require(left['host_before'] == left['host_after'] == right['host_before'] == right['host_after'],
                'same runner boot, CPU model, affinity, hostname and kernel required')
        for key in ('source', 'binary_sha256', 'binary_bytes', 'original_inputs',
                    'expected_resources', 'separate_verifier_limits'):
            require(left[key] == right[key], 'paired source/binary/workload/resources differ: ' + key)
        result['all_original_campaigns_passed'] = all(row['campaign_complete_success'] for row in result['arms'])
        result['both_independent_lifelines_passed'] = all(row['lifeline_complete_success'] for row in result['arms'])
        require(result['all_required_steps_passed'], 'one or more required original steps failed or did not execute')
        result['pair_binding_valid'] = True
    except BaseException as error:
        result['failure'] = f'{type(error).__name__}: {error}'
    finally:
        # Also used after extraction/readback/host-observation failures. This
        # cannot replace a mandatory original cleanup or campaign success.
        try:
            result['safety_cleanup'] = cleanup_only(root, output, environment)
        except BaseException as error:
            result['safety_cleanup'] = {'complete_success': False,
                                        'failure': f'{type(error).__name__}: {error}'}
        result['controller_interrupted_signal'] = INTERRUPTED_SIGNAL
        if INTERRUPTED_SIGNAL is not None and result['failure'] is None:
            result['failure'] = f'controller received signal {INTERRUPTED_SIGNAL}'
        write(output / 'pair-results.json', result)
    # A useful paired FAIL observation is retained; it never makes an original
    # failing strict profile into a green qualification gate.
    return 0 if (result['pair_binding_valid'] and result['all_original_campaigns_passed']
                 and result.get('both_independent_lifelines_passed') is True
                 and result['all_required_steps_passed'] is True
                 and result['safety_cleanup']['complete_success'] is True
                 and result['controller_interrupted_signal'] is None
                 and INTERRUPTED_SIGNAL is None
                 and result['failure'] is None) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--order', choices=ORDERS)
    parser.add_argument('--cleanup-only', action='store_true')
    args = parser.parse_args()
    if args.cleanup_only and args.order is not None:
        parser.error('--cleanup-only cannot select or run a profile')
    if not args.cleanup_only and args.order is None:
        parser.error('--order is required for native execution')
    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    if args.cleanup_only:
        raise SystemExit(0 if cleanup_only(args.root, args.output, os.environ)['complete_success'] else 1)
    raise SystemExit(run(args))
