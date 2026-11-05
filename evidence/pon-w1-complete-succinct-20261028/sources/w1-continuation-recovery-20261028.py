#!/usr/bin/env python3
"""Observe the existing orphaned W1 process, preserving the original deadline.

Never restart the prover or synthesize the interrupted supervisor's result.
Fresh verification stages are separately owned, measured, and bounded inside
the original continuation window. The original experiment remains interrupted.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path('/workspace/scratch/56818e4fba76/chain-w1-next')
CHECKPOINT = Path('/tmp/w1-staged-full-20261028-r3')
ORIGINAL = Path('/tmp/w1-full-90min-20261028')
CONTINUATION = Path('/tmp/w1-full-continuation-60min-20261028')
OUT = Path('/tmp/w1-continuation-recovery-20261028')
HOST = Path('/tmp/trnm-w1-r2-target/release')
PID, BIRTH = 823124, 6650831
ARGV = [str(HOST / 'w1-staged-prover'), '--r0vm', '/tmp/pure-pon-risc0-3.0.3/r0vm', 'compress', str(CHECKPOINT)]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_new(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def proc(pid):
    p = Path('/proc') / str(pid)
    raw = (p / 'stat').read_text()
    a = raw[raw.rfind(')') + 2:].split()
    return {'pid': pid, 'state': a[0], 'ppid': int(a[1]), 'pgrp': int(a[2]),
            'user_ticks': int(a[11]), 'system_ticks': int(a[12]),
            'reaped_child_user_ticks': int(a[13]), 'reaped_child_system_ticks': int(a[14]),
            'birth_ticks': int(a[19]), 'rss_pages': int(a[21]),
            'argv': [b.decode() for b in (p / 'cmdline').read_bytes().split(b'\0') if b]}


def matching_runner():
    try:
        row = proc(PID)
    except FileNotFoundError:
        return None
    if row['birth_ticks'] != BIRTH:
        raise RuntimeError('Owned PID was reused; no signal or adoption is permitted')
    if row['state'] != 'Z' and row['argv'] != ARGV:
        raise RuntimeError('Owned process argv changed; refuse process control')
    if row['pgrp'] != PID:
        raise RuntimeError('Owned group changed')
    return row


def main():
    entered_ns, entered_mono = time.time_ns(), time.monotonic()
    declaration = json.loads((CONTINUATION / 'declaration.json').read_text())
    assert declaration['maximum_new_total_wall_seconds'] == 3600
    deadline_ns = declaration['started_unix_ns'] + 3600 * 10**9
    deadline_mono = entered_mono + (deadline_ns - entered_ns) / 1e9
    compression_declaration = json.loads((CONTINUATION / 'proof-run/complete-recursive-compression/declaration.json').read_text())
    compression_deadline_ns = compression_declaration['started_unix_ns'] + int(compression_declaration['wall_limit_seconds'] * 1e9)
    compression_deadline_mono = entered_mono + (compression_deadline_ns - entered_ns) / 1e9
    last_old_sample = json.loads(Path('/tmp/w1-proc-observer-continuation-20261028/samples.jsonl').read_text().splitlines()[-1])
    assert time.monotonic() < deadline_mono
    expected = ['64be7c4ad51d432e7736ad135476262e23e968f5', '4157fb5cec32f74dc0d0fe50a4ad93ee11eafbca']
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], cwd=ROOT, text=True).splitlines() == expected
    assert subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT) == b''
    assert sha(ORIGINAL / 'result.json') == declaration['original_result_sha256']
    for path, expected_hash in declaration['binaries'].items():
        assert sha(Path(path)) == expected_hash
    first = matching_runner()
    assert first is not None or (CHECKPOINT / 'succinct.bin').is_file()
    OUT.mkdir(exist_ok=False)
    originals = {}
    for base, paths in [(ORIGINAL, ['result.json']), (CONTINUATION, ['declaration.json', 'original-90min-result.json', 'frozen-prefix-before-continuation.json', 'proof-run/declaration.json', 'proof-run/reverify-existing-prefix/result.json']), (Path('/tmp/w1-proc-observer-continuation-20261028'), ['declaration.json', 'samples.jsonl', 'observed-maxima.json'])]:
        for path in paths:
            f = base / path
            originals[str(f)] = {'bytes': f.stat().st_size, 'sha256': sha(f)}
    pre = {'schema': 'TRNM-W1-INTERRUPTED-CONTINUATION-OBSERVATION1',
           'entered_unix_ns': entered_ns, 'original_continuation_started_unix_ns': declaration['started_unix_ns'],
           'original_total_deadline_unix_ns': deadline_ns, 'new_wall_budget_granted_seconds': 0,
           'original_compression_deadline_unix_ns': compression_deadline_ns,
           'original_compression_termination_grace_seconds': compression_declaration['termination_grace_seconds'],
           'original_controller_outcome': 'UNKNOWN_INTERRUPTED_NO_TERMINAL_RECORD',
           'new_prover_started': False, 'original_prover_identity': first,
           'last_old_observer_sample_unix_ns': last_old_sample['unix_ns'],
           'observation_gap_seconds': (entered_ns - last_old_sample['unix_ns']) / 1e9,
           'original_records_before': originals, 'source_commit': expected[0], 'source_tree': expected[1],
           'observer_source_sha256': sha(Path(__file__)),
           'fresh_stage_plan': ['fresh-original-full-gate', 'original-verifier-100', 'native-verifier-1000', 'fresh-hardened-full-gate', 'hardened-verifier-100', 'hardened-controls-1-positive-23-negative'],
           'complete_proof_claim': False, 'benefit_gate_passed': False,
           'cpu_scope': 'sampled lower bound: root own CPU plus already reaped child CPU and live same-parent r0vm CPU. It overlaps per-PID maxima; take max, never sum both.',
           'interrupted_supervisor_wait4_result_fabricated': False, 'production_qualification': False}
    write_new(OUT / 'declaration.json', pre)
    hz = os.sysconf('SC_CLK_TCK')
    page = os.sysconf('SC_PAGE_SIZE')
    cpu_lower = 0.0
    rss_peak = 0
    proof_wait_outcome = None
    stages = []
    error = None
    gates = {'original': False, 'hardened': False}
    with (OUT / 'samples.jsonl').open('x', buffering=1) as log:
        while True:
            row = matching_runner()
            if row is None or row['state'] == 'Z':
                if row is not None:
                    ticks = sum(row[k] for k in ['user_ticks', 'system_ticks', 'reaped_child_user_ticks', 'reaped_child_system_ticks'])
                    cpu_lower = max(cpu_lower, ticks / hz)
                    log.write(json.dumps({'unix_ns': time.time_ns(), 'root': row, 'children': [], 'root_including_reaped_cpu_lower_bound_seconds': ticks / hz}) + '\n')
                proof_wait_outcome = 'ORIGINAL_PROCESS_EXIT_OBSERVED_EXIT_CODE_UNKNOWN'
                break
            children = []
            # Read root first, then still-live children, to avoid adding a
            # child sampled before its CPU was included in root cutime.
            for p in Path('/proc').iterdir():
                if not p.name.isdigit():
                    continue
                try:
                    child = proc(int(p.name))
                except (FileNotFoundError, ProcessLookupError, PermissionError, UnicodeDecodeError):
                    continue
                if child['ppid'] == PID and child['pgrp'] == PID and child['state'] != 'Z' and child['argv'][:1] == ['/tmp/pure-pon-risc0-3.0.3/r0vm']:
                    children.append(child)
            ticks = sum(row[k] for k in ['user_ticks', 'system_ticks', 'reaped_child_user_ticks', 'reaped_child_system_ticks'])
            ticks += sum(c['user_ticks'] + c['system_ticks'] for c in children)
            cpu_lower = max(cpu_lower, ticks / hz)
            rss = (row['rss_pages'] + sum(c['rss_pages'] for c in children)) * page
            rss_peak = max(rss_peak, rss)
            log.write(json.dumps({'unix_ns': time.time_ns(), 'root': row, 'children': children, 'root_including_reaped_cpu_lower_bound_seconds': ticks / hz, 'sampled_aggregate_rss_bytes': rss}) + '\n')
            if time.monotonic() >= compression_deadline_mono:
                # Root authorization covers this exact owned process group;
                # re-check PID birth, executable argv and group immediately.
                current = matching_runner()
                if current is not None and current['state'] != 'Z':
                    os.killpg(PID, signal.SIGTERM)
                    time.sleep(1)
                    current = matching_runner()
                    if current is not None and current['state'] != 'Z':
                        os.killpg(PID, signal.SIGKILL)
                proof_wait_outcome = 'ORIGINAL_COMPRESSION_DEADLINE_TERMINATION_REQUESTED'
                error = 'Original compression stage budget reached; no fresh budget granted'
                break
            time.sleep(0.25)
        log.flush()
        os.fsync(log.fileno())

    def measured(label, command):
        remaining = deadline_mono - time.monotonic()
        if remaining <= 8:
            raise RuntimeError('Original total deadline reached before next gate')
        invocation = [sys.executable, str(ROOT / 'formal/pon-nakamoto-v1/experiments/w1_stage_measure.py'), '--wall-seconds', str(min(30, remaining - 7)), '--out', str(OUT / label), '--', *map(str, command)]
        with (OUT / (label + '.supervisor.stdout')).open('xb') as stdout, (OUT / (label + '.supervisor.stderr')).open('xb') as stderr:
            result = subprocess.run(invocation, cwd=ROOT, stdout=stdout, stderr=stderr)
        record = json.loads((OUT / label / 'result.json').read_text())
        stages.append({'stage': label, 'result': record})
        if result.returncode:
            raise RuntimeError(f'{label} failed: {result.returncode}')

    try:
        if error is not None:
            raise RuntimeError(error)
        if not (CHECKPOINT / 'succinct.bin').is_file():
            raise RuntimeError('Original process exited without final Succinct bytes')
        pair = [CHECKPOINT / 'header.bin', CHECKPOINT / 'succinct.bin']
        measured('fresh-original-full-gate', [HOST / 'trnm-w1-zk-host', 'verify', *pair])
        gates['original'] = True
        measured('original-verifier-100', [HOST / 'trnm-w1-zk-host', 'verify-many', *pair])
        measured('native-verifier-1000', [HOST / 'w1-native-cost', CHECKPOINT / 'input.bin'])
        measured('fresh-hardened-full-gate', [HOST / 'trnm-w1-hardened-verifier', 'verify', *pair])
        gates['hardened'] = True
        measured('hardened-verifier-100', [HOST / 'trnm-w1-hardened-verifier', 'benchmark', *pair])
        measured('hardened-controls-1-positive-23-negative', [HOST / 'trnm-w1-hardened-verifier', 'controls', *pair, OUT / 'full-negative-control-assets'])
    except (OSError, RuntimeError, ValueError) as failure:
        error = str(failure)
    unchanged = all(Path(path).stat().st_size == record['bytes'] and sha(Path(path)) == record['sha256'] for path, record in originals.items())
    if not unchanged and error is None:
        error = 'Original frozen observation changed'
    if time.monotonic() > deadline_mono and error is None:
        error = 'Original continuation total deadline exceeded'
    report = {**pre, 'finished_unix_ns': time.time_ns(), 'proof_wait_outcome': proof_wait_outcome,
              'observed_orphan_cpu_lower_bound_seconds': cpu_lower, 'sampled_orphan_aggregate_peak_rss_bytes': rss_peak,
              'stages': stages, 'fresh_gates': gates, 'complete_proof_claim': all(gates.values()),
              'all_declared_fresh_stages_completed': error is None, 'error': error,
              'original_observations_unchanged': unchanged,
              'prover_exit_code': None, 'original_continuation_controller_result': None,
              'prover_exact_cpu_cost_known': False, 'prover_p99_established': False,
              'new_total_elapsed_from_original_start_seconds': (time.time_ns() - declaration['started_unix_ns']) / 1e9,
              'additional_observer_elapsed_seconds': time.monotonic() - entered_mono}
    write_new(OUT / 'result.json', report)
    print(json.dumps({k: report[k] for k in ['complete_proof_claim', 'all_declared_fresh_stages_completed', 'error', 'observed_orphan_cpu_lower_bound_seconds', 'new_total_elapsed_from_original_start_seconds']}), flush=True)
    return 0 if error is None and all(gates.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
