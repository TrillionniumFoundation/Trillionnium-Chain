"""Precommitted 1/2/4-process propagation and local-budget amplification control.

One producer creates two fixed-nonce packets. Independent receiver processes
recheck the actual Node capsule, full grouped arithmetic and seal over localhost
TCP. Each keeps the old local journal; this experiment intentionally does NOT
use the new shared authority. Public fixture keys and historical inputs do not
establish external demand, independent organizations or WAN/TLS performance.
"""
from __future__ import annotations

import argparse
import concurrent.futures
from dataclasses import asdict
import json
import os
from pathlib import Path
import resource
import signal
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract_wire import ROOT, canonical, unique
import grouped_fresh_work_v0 as fresh
import grouped_work_lottery_v0 as old
from grouped_fresh_admission_wire_v0 import inspect_freeze
from grouped_fresh_deployment_cost_v0 import (
    CASES, DEMAND_COMPONENTS, LOCAL_CAP, demand_bridge_audit, material_identity,
    topology_accounting, produced_work_ids,
)
from grouped_legal_strategy_v0 import prepare, execute, REPRESENTATION
from experiments.grouped_cell_operator_v0 import make_commands, model_commitment
from experiments.grouped_fresh_work_v0 import (
    NativeSession, Receiver, SOURCES as BASE_SOURCES, context, durable_bytes,
    elapsed, require, result, sha, stamp,
)
from experiments.grouped_legal_strategy_v0 import source_identity, source_gate_failures
from experiments.shared_cell_operator_v1 import DEFAULT_MATERIAL, DEFAULT_BUNDLE, load_inputs

OWNED = (
    'formal/pon-nakamoto-v1/grouped_fresh_deployment_cost_v0.py',
    'formal/pon-nakamoto-v1/test_grouped_fresh_deployment_cost_v0.py',
    'formal/pon-nakamoto-v1/experiments/grouped_fresh_fanout_v0.py',
)
SOURCES = tuple(dict.fromkeys(BASE_SOURCES + OWNED + tuple(c['path'] for c in DEMAND_COMPONENTS)))
TOPOLOGIES = (1, 2, 4)
NONCES = (1, 2)


def save_json(path, value):
    # Observational CPU seconds may be finite floats. Protocol messages still
    # use contract_wire.canonical, whose integer-only grammar is unchanged.
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True, allow_nan=False).encode('ascii') + b'\n'
    return durable_bytes(path, raw)


def read_json(path):
    return json.loads(Path(path).read_bytes(), object_pairs_hook=unique)


def storage_observation(directory):
    path = Path(directory).resolve()
    stat = os.statvfs(path)
    matching = []
    for line in Path('/proc/mounts').read_text().splitlines():
        fields = line.split()
        mount = fields[1].replace('\\040', ' ')
        if str(path) == mount or str(path).startswith(mount.rstrip('/') + '/'):
            matching.append((len(mount), fields[2]))
    return {'resolved_directory': str(path),
            'filesystem_type': max(matching)[1] if matching else 'unknown',
            'free_bytes': stat.f_bfree * stat.f_frsize,
            'available_bytes': stat.f_bavail * stat.f_frsize,
            'power_loss_durability_tested': False}


def close_native_with_cleanup(session):
    """A log-write failure must not bypass termination/reaping of our child."""
    try:
        return session.close()
    finally:
        if session.child.poll() is None:
            os.killpg(session.child.pid, signal.SIGKILL)
        session.child.wait(timeout=5)


def pinned_sources(pins):
    observed = {}
    for relative, expected in pins.items():
        path = Path(relative)
        require(not path.is_absolute() and '..' not in path.parts, 'SOURCE_PATH')
        digest = sha((ROOT / path).read_bytes())
        require(digest == expected, 'SOURCE_PIN_' + relative)
        observed[relative] = digest
    return observed


def procfs_identity(procfs_pid):
    directory = Path('/proc') / str(procfs_pid)
    raw = (directory / 'stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    outer_pid = int(raw.split(' ', 1)[0])
    outer_parent = int(fields[1])
    def namespace_pid(status, fallback):
        line = next((s for s in status.splitlines() if s.startswith('NSpid:')), None)
        return int(line.split()[-1]) if line else fallback
    pid = namespace_pid((directory / 'status').read_text(), outer_pid)
    parent = namespace_pid(Path(f'/proc/{outer_parent}/status').read_text(), outer_parent)
    return {'pid': pid, 'parent_pid': parent, 'procfs_pid': outer_pid,
            'procfs_parent_pid': outer_parent, 'start_ticks': int(fields[19])}


def process_identity(pid):
    # The managed executor can expose an outer /proc mount while Popen/getpid
    # use an inner PID namespace. Resolve only self or self's direct children;
    # never assume /proc/<namespace pid> identifies the owned process.
    own = procfs_identity('self')
    if pid == os.getpid():
        require(own['pid'] == pid, 'SELF_NAMESPACE_PID')
        return own
    children_path = Path(f"/proc/{own['procfs_pid']}/task/{own['procfs_pid']}/children")
    if children_path.is_file():
        children = children_path.read_text().split()
    else:
        # Some managed procfs projections omit the children file. Inspect only
        # bounded PID/PPID metadata, then read namespace metadata exclusively
        # for self's actual children. No command lines or environments are read.
        children = []
        entries = [p for p in Path('/proc').iterdir() if p.name.isdigit()]
        require(len(entries) <= 16384, 'PROCFS_IDENTITY_SCAN_LIMIT')
        for path in entries:
            try:
                raw = (path / 'stat').read_text()
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            fields = raw[raw.rfind(')') + 2:].split()
            if int(fields[1]) == own['procfs_pid']:
                children.append(path.name)
    for outer in children:
        try:
            observed = procfs_identity(int(outer))
        except FileNotFoundError:
            continue
        if observed['pid'] == pid and observed['parent_pid'] == os.getpid():
            return observed
    raise ValueError('OWNED_CHILD_NAMESPACE_ID_UNAVAILABLE')


def append_record(handle, value):
    handle.write(canonical(value) + b'\n')
    handle.flush()
    os.fsync(handle.fileno())


def campaign_plan():
    return {
        'schema': 'pon-grouped-fresh-fanout-plan-v0',
        'topology_sizes': list(TOPOLOGIES), 'primary_nonces': list(NONCES),
        'no_stop_on_hit': True, 'same_two_packets_across_all_topologies': True,
        'receiver_cases': list(CASES), 'case_order_fixed_before_any_ticket': True,
        'truncated_payload_bytes': 17, 'carrier_suffix_bytes': 3,
        'local_verification_cap': LOCAL_CAP,
        'exhaust_each_local_budget_before_last_case': True,
        'reopen_each_local_journal_after_exhaustion': True,
        'expected_receivers': sum(TOPOLOGIES),
        'expected_transport_attempts': len(CASES) * sum(TOPOLOGIES),
        'independently_administered_receivers': False,
        'topology': 'Separate Python/native processes and SQLite journals on one host; actual localhost TCP.',
        'target_hit_does_not_change_plan': True,
        'chainwork_awarded': 0,
    }


def receive_into(connection, count, captured):
    start = len(captured)
    while len(captured) - start < count:
        part = connection.recv(count - (len(captured) - start))
        if not part:
            raise ValueError('TCP_TRUNCATED_FRAME')
        captured.extend(part)
    return bytes(captured[start:])


def serve_case(listener, receiver, directory, case, ordinal):
    started = stamp()
    record = {'case': case, 'ordinal': ordinal, 'status': 'started',
              'complete_verifier_called': False, 'received_frame_bytes': 0,
              'ack_kernel_accepted_bytes': 0, 'peer_application_read_proved': False}
    incoming, ack = bytearray(), b''
    try:
        with listener.accept()[0] as connection:
            connection.settimeout(receiver.timeout)
            try:
                prefix = receive_into(connection, 4, incoming)
                length, = struct.unpack('!I', prefix)
                require(length <= fresh.MAX_PACKAGE_BYTES, 'TCP_RECEIVE_LIMIT')
                raw = receive_into(connection, length, incoming)
                record['complete_verifier_called'] = True
                record['verification'] = receiver.verify(raw, 'untrusted')
            except Exception as error:
                record.update(transport_error=str(error), transport_error_type=type(error).__name__)
            ack = canonical({'case': case, 'verification': record.get('verification'),
                             'transport_error': record.get('transport_error')})
            require(len(ack) <= fresh.MAX_PACKAGE_BYTES, 'TCP_ACK_LIMIT')
            framed = struct.pack('!I', len(ack)) + ack
            # A successful send only means the local kernel accepted bytes.
            # The deliberately discarded case is never counted as a client ACK.
            try:
                while record['ack_kernel_accepted_bytes'] < len(framed):
                    n = connection.send(framed[record['ack_kernel_accepted_bytes']:])
                    require(n > 0, 'TCP_SEND_ZERO')
                    record['ack_kernel_accepted_bytes'] += n
            except OSError as error:
                record.update(ack_send_error=str(error), ack_send_error_type=type(error).__name__)
    except Exception as error:
        record.update(transport_error=str(error), transport_error_type=type(error).__name__)
    record['received_frame_bytes'] = len(incoming)
    record['incoming_file'] = f'tcp-{ordinal:02d}-incoming.bin'
    record['incoming_sha256'] = durable_bytes(directory / record['incoming_file'], bytes(incoming))
    record['ack_file'] = f'tcp-{ordinal:02d}-ack.bin'
    record['ack_sha256'] = durable_bytes(directory / record['ack_file'], ack)
    record['status'] = 'observed'
    record['receive_verify_ack_and_capture'] = elapsed(started)
    return record


def worker(config_path, expected_hash):
    """One receiver owner; its only child during NativeSession is the native node."""
    raw = Path(config_path).read_bytes()
    require(sha(raw) == expected_hash, 'WORKER_CONFIGURATION_PIN')
    cfg = json.loads(raw, object_pairs_hook=unique)
    directory = Path(cfg['directory'])
    started = stamp()
    session, listener, source_before, source_after, native_exit = None, None, None, None, None
    records = [dict(case=case, ordinal=i, status='not_started') for i, case in enumerate(CASES)]
    failures, ledger, pins, binding, budget_fill = [], None, None, None, None
    final_path = directory / 'worker-report.json'

    def terminate(_signum, _frame):
        raise InterruptedError('CONTROLLER_REQUESTED_WORKER_STOP')

    signal.signal(signal.SIGTERM, terminate)
    with (directory / 'server-attempts.ndjson').open('xb') as journal:
        try:
            source_before = pinned_sources(cfg['source_pins'])
            require(sha(Path(cfg['runner']).read_bytes()) == cfg['runner_sha256'], 'WORKER_RUNNER_PIN')
            session = NativeSession(Path(cfg['runner']), directory / 'native-session', directory, cfg['timeout'])
            frozen = result(session.call(cfg['freeze_request']))
            native_directory = directory / 'native-session'
            pins = {'expected_body_sha256': sha((native_directory / 'expected-body.bin').read_bytes()),
                    'expected_capsule_sha256': sha((native_directory / 'capsule.bin').read_bytes()),
                    'expected_policy_file_sha256': sha((native_directory / 'expected-policy.json').read_bytes()),
                    'branch': frozen['branch']}
            require(pins == cfg['native_pins'], 'RECEIVER_NOT_SAME_NATIVE_POLICY')
            binding = inspect_freeze(frozen,
                {k: v for k, v in cfg['freeze_request'].items() if k != 'op'},
                cfg['init'], cfg['requests'], expected_native=pins)
            receiver = Receiver(session, frozen, binding['candidates_by_nonce'], cfg['init'],
                                cfg['requests'], directory, cfg['timeout'])
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.settimeout(cfg['timeout'])
            listener.bind(('127.0.0.1', 0))
            listener.listen(len(CASES))
            ready = {'receiver_id': cfg['receiver_id'], 'port': listener.getsockname()[1],
                     'process': process_identity(os.getpid()),
                     'native_process': process_identity(session.child.pid),
                     'native_policy_pins': pins, 'configuration_sha256': expected_hash}
            save_json(directory / 'ready.tmp', ready)
            os.replace(directory / 'ready.tmp', directory / 'ready.json')
            for ordinal, case in enumerate(CASES):
                if case == 'after_local_cap':
                    fill_started = stamp()
                    before = result(session.call({'op': 'status'}))['ledger']['verification_budget']
                    sequences = []
                    value = fresh.parse_package(bytes.fromhex(cfg['original_packet_hex']))
                    for _ in range(LOCAL_CAP - before['reserved']):
                        reserved = receiver.reserve(value, 'untrusted')
                        sequences.append(reserved['permit']['sequence'])
                    reopened = result(session.call({'op': 'reopen', 'now_ns': receiver.now()}))
                    ledger = reopened['ledger']
                    budget_fill = {'before': before, 'reservation_sequences': sequences,
                                   'new_reservations': len(sequences), 'after_reopen': ledger,
                                   'fill_and_reopen': elapsed(fill_started)}
                    save_json(directory / 'budget-fill.json', budget_fill)
                records[ordinal] = serve_case(listener, receiver, directory, case, ordinal)
                append_record(journal, records[ordinal])
            ledger = result(session.call({'op': 'status'}))['ledger']
        except Exception as error:
            failures.append({'stage': 'worker', 'error_type': type(error).__name__, 'error': str(error)})
        finally:
            if listener is not None:
                listener.close()
            if session is not None:
                try:
                    native_exit = close_native_with_cleanup(session)
                except Exception as error:
                    failures.append({'stage': 'native_close', 'error_type': type(error).__name__, 'error': str(error)})
    try:
        source_after = pinned_sources(cfg['source_pins'])
        runner_stable = sha(Path(cfg['runner']).read_bytes()) == cfg['runner_sha256']
    except Exception as error:
        runner_stable = False
        failures.append({'stage': 'worker_source_after', 'error_type': type(error).__name__, 'error': str(error)})
    native_path = directory / 'native-session' / 'research-ledger.sqlite'
    file_identity = None
    if native_path.is_file():
        st = native_path.stat()
        file_identity = {'device': st.st_dev, 'inode': st.st_ino, 'bytes': st.st_size,
                         'sha256': sha(native_path.read_bytes())}
    report = {
        'schema': 'pon-grouped-fresh-fanout-receiver-v0',
        'status': 'PASS' if not failures and all(r['status'] == 'observed' for r in records) else 'FAIL',
        'receiver_id': cfg['receiver_id'], 'configuration_sha256': expected_hash,
        'source_before': source_before, 'source_after': source_after,
        'source_bytes_stable': source_before is not None and source_before == source_after,
        'runner_bytes_stable': runner_stable, 'runner_sha256': cfg['runner_sha256'],
        'native_pins': pins, 'independent_wire_check': binding,
        'transport_records': records, 'native_exit': native_exit,
        'native_exchange_count': len(session.records) if session is not None else 0,
        'final_ledger': ledger, 'budget_fill': budget_fill,
        'journal_file_identity': file_identity,
        'material_content_id': cfg['material_content_id'],
        'whole_worker_before_report': elapsed(started),
        'python_self_cpu_through_report_construction_seconds': resource.getrusage(resource.RUSAGE_SELF).ru_utime + resource.getrusage(resource.RUSAGE_SELF).ru_stime,
        'python_self_cpu_excludes_native_child': True,
        'failures': failures, 'external_demand_authenticated': False,
        'independent_operators': False, 'chainwork_awarded': 0, 'production_activation': False,
    }
    save_json(final_path, report)
    return 0 if report['status'] == 'PASS' else 1


def client_attempt(directory, identity, port, case, packets, timeout):
    started = stamp()
    raw = packets[2] if case == 'discarded_response' else packets[1]
    if case == 'carrier_replay':
        raw += b' ' * 3
    elif case == 'forged_endpoint':
        value = fresh.parse_package(raw)
        proof = bytearray.fromhex(value['proof_hex'])
        proof[-1] ^= 1  # Always different; no outcome-dependent search.
        value['proof_hex'] = proof.hex()
        raw = canonical(value)
    frame = struct.pack('!I', len(raw)) + (raw[:17] if case == 'truncated_cancel' else raw)
    record = {'receiver_id': identity, 'case': case, 'status': 'started',
              'sent_bytes': 0, 'received_bytes': 0, 'response_observed': False}
    sent_path = directory / f'{identity}-{case}-sent.bin'
    record['planned_sent_sha256'] = durable_bytes(sent_path, frame)
    record['planned_sent_file'] = sent_path.name
    captured = bytearray()
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            while record['sent_bytes'] < len(frame):
                n = connection.send(frame[record['sent_bytes']:])
                require(n > 0, 'TCP_SEND_ZERO')
                record['sent_bytes'] += n
            connection.shutdown(socket.SHUT_WR)
            if case == 'discarded_response':
                record['status'] = 'response_intentionally_discarded'
            else:
                prefix = receive_into(connection, 4, captured)
                length, = struct.unpack('!I', prefix)
                require(length <= fresh.MAX_PACKAGE_BYTES, 'TCP_CLIENT_ACK_LIMIT')
                ack = receive_into(connection, length, captured)
                record.update(status='response_observed', response_observed=True,
                              response=json.loads(ack, object_pairs_hook=unique),
                              ack_sha256=sha(ack))
    except Exception as error:
        record.update(status='failed', error_type=type(error).__name__, error=str(error),
                      partial_stage_costs=None)
    record['received_bytes'] = len(captured)
    reply_path = directory / f'{identity}-{case}-received.bin'
    record['received_file'] = reply_path.name
    record['received_sha256'] = durable_bytes(reply_path, bytes(captured))
    record['client_whole_attempt'] = elapsed(started)
    return record


def observe_unreaped_exit(pid):
    return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def wait_receiver(process, ready, timeout):
    """Retain wait4, including failed exits; never call Popen.poll first."""
    deadline = time.monotonic() + timeout
    signals = []
    while True:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid:
            process.returncode = os.waitstatus_to_exitcode(status)
            return {'exit_code': process.returncode, 'raw_wait_status': status,
                    'user_seconds': usage.ru_utime, 'system_seconds': usage.ru_stime,
                    'peak_rss_kib': usage.ru_maxrss, 'signals': signals,
                    'scope': 'Linux wait4 for this receiver and native children it waited; includes Python start/import/exit.'}
        if time.monotonic() >= deadline:
            if not signals:
                os.killpg(process.pid, signal.SIGTERM)
                signals.append('SIGTERM')
                # A native close command itself has the configured bounded
                # timeout plus a five-second kill/wait cleanup allowance.
                deadline = time.monotonic() + timeout + 10
            else:
                # NativeSession owns a separate group. Pin its recorded start
                # identity before cleanup; never signal an arbitrary reused PID.
                native = (ready or {}).get('native_process')
                if native is not None:
                    try:
                        actual = procfs_identity(native['procfs_pid'])
                        if actual['pid'] == native['pid'] and actual['start_ticks'] == native['start_ticks']:
                            os.killpg(native['pid'], signal.SIGKILL)
                            signals.append('SIGKILL_OWNED_NATIVE')
                    except ProcessLookupError:
                        pass
                    except FileNotFoundError:
                        pass
                os.killpg(process.pid, signal.SIGKILL)
                signals.append('SIGKILL')
                pid, status, usage = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
                return {'exit_code': process.returncode, 'raw_wait_status': status,
                        'user_seconds': usage.ru_utime, 'system_seconds': usage.ru_stime,
                        'peak_rss_kib': usage.ru_maxrss, 'signals': signals,
                        'scope': 'Killed receiver; any unwaited native CPU is unknown, no complete CPU claim.'}
        time.sleep(0.01)


def readback_receiver(directory, report, clients):
    """Compare client/server raw bytes after both processes have exited."""
    checks = []
    for row in report['transport_records']:
        case = row['case']
        if row['status'] != 'observed':
            checks.append({'case': case, 'status': 'FAIL', 'reason': 'NOT_OBSERVED'})
            continue
        client = clients.get(case)
        if client is None:
            checks.append({'case': case, 'status': 'FAIL', 'reason': 'CLIENT_UNAVAILABLE'})
            continue
        incoming = (directory / row['incoming_file']).read_bytes()
        ack = (directory / row['ack_file']).read_bytes()
        planned = (directory.parent / client['planned_sent_file']).read_bytes()
        received = (directory.parent / client['received_file']).read_bytes()
        require(sha(incoming) == row['incoming_sha256'] and len(incoming) == row['received_frame_bytes'],
                'SERVER_INCOMING_READBACK')
        require(sha(ack) == row['ack_sha256'], 'SERVER_ACK_READBACK')
        require(sha(planned) == client['planned_sent_sha256'], 'CLIENT_SENT_READBACK')
        require(sha(received) == client['received_sha256'] and len(received) == client['received_bytes'],
                'CLIENT_RECEIVED_READBACK')
        require(incoming == planned[:client['sent_bytes']], 'TCP_EXACT_SENT_RECEIVED')
        if client['response_observed']:
            require(received == struct.pack('!I', len(ack)) + ack, 'TCP_EXACT_ACK_READBACK')
            require(json.loads(ack, object_pairs_hook=unique) == client['response'], 'ACK_JSON_READBACK')
        else:
            require(case == 'discarded_response' and received == b'', 'UNEXPECTED_MISSING_RESPONSE')
        verification = row.get('verification')
        if verification:
            packet = (directory / verification['packet_file']).read_bytes()
            require(sha(packet) == verification['packet_sha256'] == verification['persisted_packet_sha256'],
                    'VERIFIER_PACKET_READBACK')
            require(incoming[4:] == packet, 'TRANSPORT_VERIFIER_PACKET_IDENTITY')
            receipt_name = verification['packet_file'].replace('packet-', 'receipt-').replace('.bin', '.json')
            receipt_raw = (directory / receipt_name).read_bytes()
            require(sha(receipt_raw) == verification['receipt_sha256'], 'VERIFIER_RECEIPT_READBACK')
            expected = {k: v for k, v in verification.items() if k not in
                        ('receipt_sha256', 'receipt_persistence_and_readback', 'receiver_total_before_ack_encoding')}
            require(read_json(directory / receipt_name) == expected, 'VERIFIER_RECEIPT_IDENTITY')
        row['client'] = client
        checks.append({'case': case, 'status': 'PASS', 'incoming_bytes': len(incoming),
                       'ack_bytes': len(ack), 'client_received_bytes': len(received)})
    return checks


def run_topology(size, cfg, packets, out, timeout):
    started = stamp()
    directory = out / f'fanout-{size}'
    directory.mkdir()
    processes, clients, ready, orchestration_failures = {}, {}, {}, []
    observations = [dict(receiver_id=f'receiver-{index}', status='not_started') for index in range(size)]
    try:
        for observed in observations:
            identity = observed['receiver_id']
            clients[identity] = {}
            target = directory / identity
            target.mkdir()
            configuration = dict(cfg, directory=str(target), receiver_id=identity)
            config_hash = save_json(target / 'configuration.json', configuration)
            with (target / 'stdout.log').open('xb') as stdout, (target / 'stderr.log').open('xb') as stderr:
                process = subprocess.Popen(
                    [sys.executable, str(Path(__file__).resolve()), '--worker', str(target / 'configuration.json'),
                     '--worker-config-sha256', config_hash],
                    stdout=stdout, stderr=stderr, start_new_session=True)
            processes[identity] = process
            observed.update(pid=process.pid, configuration_sha256=config_hash, status='started')
        deadline = time.monotonic() + timeout
        pending = set(processes)
        while pending and time.monotonic() < deadline:
            for identity in tuple(pending):
                path = directory / identity / 'ready.json'
                if path.is_file():
                    record = read_json(path)
                    require(record['receiver_id'] == identity and record['process']['pid'] == processes[identity].pid,
                            'RECEIVER_PROCESS_PIN')
                    require(record['native_process']['parent_pid'] == processes[identity].pid,
                            'NATIVE_PARENT_PIN')
                    ready[identity] = record
                    pending.remove(identity)
                elif observe_unreaped_exit(processes[identity].pid):
                    pending.remove(identity)
            if pending:
                time.sleep(0.01)
        with (directory / 'client-attempts.ndjson').open('xb') as journal:
            for case in CASES:
                # Each stage has one independent client per ready receiver.
                # Attempt scheduling never changes after observing a hit or failure.
                with concurrent.futures.ThreadPoolExecutor(max_workers=size) as pool:
                    jobs = {identity: pool.submit(client_attempt, directory, identity,
                            ready[identity]['port'], case, packets, timeout)
                            for identity in processes if identity in ready}
                    for identity in processes:
                        if identity in jobs:
                            observed = jobs[identity].result()
                        else:
                            observed = {'receiver_id': identity, 'case': case, 'status': 'not_started',
                                        'reason': 'RECEIVER_NOT_READY', 'cost': None}
                        clients[identity][case] = observed
                        append_record(journal, observed)
    except Exception as error:
        orchestration_failures.append({'stage': 'start_or_transport', 'error_type': type(error).__name__, 'error': str(error)})
    finally:
        for observed in observations:
            identity = observed['receiver_id']
            observed['raw_readback_passed'] = False
            observed['worker_report'] = None
            if identity not in processes:
                observed['wait4'] = None
                continue
            try:
                observed['wait4'] = wait_receiver(processes[identity], ready.get(identity), timeout)
            except Exception as error:
                observed['wait4'] = None
                observed.update(wait_error=str(error), wait_error_type=type(error).__name__)
                orchestration_failures.append({'stage': 'wait_receiver', 'receiver_id': identity,
                                               'error_type': type(error).__name__, 'error': str(error)})
            path = directory / identity / 'worker-report.json'
            observed['ready'] = ready.get(identity)
            try:
                observed['worker_report'] = read_json(path) if path.is_file() else None
                if observed['worker_report'] is not None:
                    observed['raw_readback_checks'] = readback_receiver(
                        directory / identity, observed['worker_report'], clients[identity])
                    observed['raw_readback_passed'] = all(r['status'] == 'PASS' for r in observed['raw_readback_checks'])
            except Exception as error:
                observed.update(raw_readback_passed=False, readback_error=str(error),
                                readback_error_type=type(error).__name__)
                # Continue to reap every other launched receiver even if this
                # report is missing, truncated or cannot be read after ENOSPC.
                orchestration_failures.append({'stage': 'readback_receiver', 'receiver_id': identity,
                                               'error_type': type(error).__name__, 'error': str(error)})
    inodes = []
    for observed in observations:
        path = directory / observed['receiver_id'] / 'native-session' / 'research-ledger.sqlite'
        if path.is_file() and not path.is_symlink():
            st = path.stat()
            inodes.append((st.st_dev, st.st_ino))
    accounting = topology_accounting(size, observations,
                                     expected_work_ids=cfg['expected_work_ids'])
    if len(inodes) != size or len(set(inodes)) != size:
        accounting['issues'].append('RECEIVERS_DID_NOT_HAVE_DISTINCT_JOURNAL_FILES')
    if not all(row['raw_readback_passed'] for row in observations):
        accounting['issues'].append('RAW_READBACK_FAILED')
    if orchestration_failures:
        accounting['issues'].append('ORCHESTRATION_FAILURES')
    accounting['status'] = 'FAIL' if accounting['issues'] else 'PASS'
    value = {'planned_receivers': size, 'accounting': accounting, 'workers': observations,
             'whole_topology': elapsed(started),
             'orchestration_failures': orchestration_failures,
             'unstarted_clients': [v for rows in clients.values() for v in rows.values() if v['status'] == 'not_started']}
    save_json(directory / 'report.json', value)
    return value


def run(args):
    started, cpu_before = stamp(), time.process_time_ns()
    children_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    storage_before = storage_observation(out)
    prereg = campaign_plan()
    plan_hash = save_json(out / 'plan.json', prereg)
    save_json(out / 'request.json', {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()})
    before = source_identity(sources=SOURCES)
    runner_before = sha(args.runner.read_bytes()) if args.runner.is_file() else None
    failures = [dict(v, stage='source_before') for v in source_gate_failures(before, args.source_sha)]
    topologies, produced, material, preparation, producer_exit = [], [], None, None, None
    session, native_pins, freeze_request = None, None, None
    try:
        require(not failures, 'SOURCE_GATE')
        require(args.source_sha is None or args.replay_source, 'SOURCE_REPLAY_REQUIRED')
        require(args.runner_sha256 is None or args.runner_sha256 == runner_before, 'RUNNER_PIN')
        step = stamp()
        model, rows, provenance = load_inputs(args.model, args.tasks, args.evaluation_bundle,
            args.bundle_hash, 'consumer', 0, 16, replay_source=args.replay_source)
        init, commands = make_commands(model, rows, provenance, [16], 1, 0)
        requests = commands[0]['requests']
        material = {'provenance': provenance, 'load_and_source_replay': elapsed(step),
                    'historical_corpus_not_new_demand': True,
                    'model_sha256': sha(args.model.read_bytes()), 'tasks_sha256': sha(args.tasks.read_bytes())}
        step = stamp()
        prepared = prepare(init, 'sparse_cached_merged')
        strategy_requests = [dict(r, generation=init['model_version'], representation=REPRESENTATION) for r in requests]
        product, costs = execute(prepared, strategy_requests)
        identity = material_identity(init, requests, product)
        material.update(identity)
        preparation = {'measured': elapsed(step), 'model_preparation_counts': prepared.preparation_cost,
                       'product_execution_counts': asdict(costs), 'fresh_neural_contractions_after_preparation': 0}
        producer_dir = out / 'producer'
        producer_dir.mkdir()
        session = NativeSession(args.runner.resolve(), producer_dir / 'native-session', producer_dir, args.timeout)
        freeze_request = dict(op='freeze', model_commitment=model_commitment(init),
            request_precommitment=old.request_precommitment(init, requests),
            batch_id=commands[0]['context']['batch_id'], authorization_scope=requests[0]['scope'],
            demand_id=sha(b'controlled-historical-consumer-not-current-demand'),
            source_record=sha(canonical(provenance)), withdrawal_head=sha(b'controlled-withdrawal-head'),
            payee=sha(b'controlled-public-test-payee'), model_generation=1,
            timestamp_ms=1_700_000_000_000, not_before_ns=1, expires_ns=3_600_000_000_000,
            available_until_ns=3_600_000_000_000, nonce_first=NONCES[0], nonce_count=len(NONCES), now_ns=1)
        frozen = result(session.call(freeze_request))
        native_dir = producer_dir / 'native-session'
        native_pins = {'expected_body_sha256': sha((native_dir / 'expected-body.bin').read_bytes()),
                       'expected_capsule_sha256': sha((native_dir / 'capsule.bin').read_bytes()),
                       'expected_policy_file_sha256': sha((native_dir / 'expected-policy.json').read_bytes()),
                       'branch': frozen['branch']}
        binding = inspect_freeze(frozen, {k: v for k, v in freeze_request.items() if k != 'op'},
                                 init, requests, expected_native=native_pins)
        packets = {}
        for nonce in NONCES:
            step = stamp()
            candidate = binding['candidates_by_nonce'][nonce]
            ctx = context(frozen, candidate)
            statement = fresh.grouped_binding(init, requests, ctx, product)['statement_commitment']
            proof = result(session.call({'op': 'prove', 'nonce': nonce, 'statement': statement, 'now_ns': 1}))
            independent = fresh.prove(ctx['challenge'], statement)
            require(independent.hex() == proof['proof_hex'], 'PRODUCER_CROSSCHECK')
            packet = fresh.package(init, requests, ctx, product, nonce=nonce,
                                   capsule_hex=frozen['capsule_hex'], proof=independent)
            packet_hash = durable_bytes(producer_dir / f'packet-{nonce}.bin', packet)
            packets[nonce] = packet
            produced.append({'nonce': nonce, 'challenge': ctx['challenge'], 'work_id': candidate['work_id'],
                             'statement': statement, 'packet_sha256': packet_hash, 'packet_bytes': len(packet),
                             'native': proof, 'generation_crosscheck_capture': elapsed(step)})
        # Close before starting receiver children: the producer's RUSAGE_CHILDREN
        # interval really contains only this native process.
        producer_exit = close_native_with_cleanup(session)
        save_json(producer_dir / 'report.json', {'freeze': frozen, 'binding': binding,
                                               'native_exit': producer_exit, 'produced': produced})
        cfg = {'runner': str(args.runner.resolve()), 'runner_sha256': runner_before,
               'timeout': args.timeout, 'source_pins': before['relevant_sources_sha256'],
               'init': init, 'requests': requests, 'freeze_request': freeze_request,
               'native_pins': native_pins, 'original_packet_hex': packets[1].hex(),
               'material_content_id': identity['material_content_id'],
               'expected_work_ids': produced_work_ids(produced)}
        for size in TOPOLOGIES:
            topology = run_topology(size, cfg, packets, out, args.timeout)
            topologies.append(topology)
            if topology['accounting']['status'] != 'PASS':
                failures.append({'stage': 'topology', 'size': size, 'reasons': topology['accounting']['issues']})
    except Exception as error:
        failures.append({'stage': 'campaign', 'error_type': type(error).__name__, 'error': str(error)})
    finally:
        if session is not None and not session.closed:
            try:
                producer_exit = close_native_with_cleanup(session)
            except Exception as error:
                failures.append({'stage': 'producer_close', 'error_type': type(error).__name__, 'error': str(error)})
    after = source_identity(sources=SOURCES)
    runner_after = sha(args.runner.read_bytes()) if args.runner.is_file() else None
    failures.extend(dict(v, stage='source_after') for v in source_gate_failures(after, args.source_sha))
    if before['relevant_sources_sha256'] != after['relevant_sources_sha256']:
        failures.append({'stage': 'source_after', 'reason': 'SOURCE_BYTES_CHANGED'})
    if runner_before != runner_after:
        failures.append({'stage': 'runner_after', 'reason': 'RUNNER_BYTES_CHANGED'})
    missing = [size for size in TOPOLOGIES if size not in [r['planned_receivers'] for r in topologies]]
    if missing:
        failures.append({'stage': 'campaign', 'reason': 'TOPOLOGIES_NOT_STARTED', 'sizes': missing})
    audit = demand_bridge_audit(ROOT)
    save_json(out / 'demand-bridge-audit.json', audit)
    children_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    report = {
        'schema': 'pon-grouped-fresh-fanout-campaign-v0',
        'status': 'PASS' if not failures else 'FAIL', 'preregistered_plan_sha256': plan_hash,
        'expected_source_sha': args.source_sha, 'source_before': before, 'source_after': after,
        'exact_committed_source_verified': args.source_sha is not None and
            not source_gate_failures(before, args.source_sha) and not source_gate_failures(after, args.source_sha),
        'runner_sha256': runner_before, 'runner_bytes_stable': runner_before == runner_after,
        'output_storage_before': storage_before, 'output_storage_after': storage_observation(out),
        'measurement_mode': 'exact-source' if args.source_sha else 'development-not-exact-committed-source',
        'material': material, 'preparation': preparation, 'produced': produced, 'producer_native_exit': producer_exit,
        'topologies': topologies, 'not_started_topologies': missing,
        'primary_packets_generated': len(produced),
        'primary_hits': sum(bool(r['native']['target_hit']) for r in produced),
        'all_receptions_are_not_independent_tickets': True,
        'whole_campaign_before_report': elapsed(started),
        'parent_process_cpu_ns': time.process_time_ns() - cpu_before,
        'all_waited_children_user_seconds': children_after.ru_utime - children_before.ru_utime,
        'all_waited_children_system_seconds': children_after.ru_stime - children_before.ru_stime,
        'cost_scope': [
            'Whole campaign includes source/input replay, producer, native startup/exit, independent Python workers, actual TCP, failures/cancellation/discard controls, budget exhaustion, persistence and readback.',
            'Parent CPU includes its client threads; child wait4 covers each receiver and the native descendants it waited on Linux. Native-only and stage costs are subsets, never extra terms.',
            'Receiver wait4 includes Python process start/import/exit; outer controller startup/import/exit and final report encoding remain outside the named campaign interval.',
            'A sender discard records bytes accepted by its local kernel and zero received bytes. Server ACK send success never proves application consumption.',
            'This is shared-host localhost, not WAN/TLS, public gossip, availability, succinct-proof benefit or independent operator qualification.',
            'The named output filesystem is recorded. If tmpfs is used, journal fsync/reopen measures memory-backed persistence only, not durable disk or power loss.',
            'Forced-kill partial stages or unwaited descendants remain unknown; no crash-complete accounting claim.',
        ],
        'external_demand_authenticated': False, 'actual_consumer_uses_observed': 0,
        'native_payment_for_grouped_output_observed': False, 'independent_operators': False,
        'global_verification_cap_enforced': False, 'hidden_verifier_side_channel_model_verified': False,
        'minimum_fresh_neural_cost_proved': False, 'physical_resource_lower_bound_proved': False,
        'quantum_security_proved': False, 'pow_qualified': False,
        'production_activation': False, 'chainwork_awarded': 0, 'failures': failures,
    }
    save_json(out / 'report.json', report)
    return report


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--worker', type=Path)
    p.add_argument('--worker-config-sha256')
    p.add_argument('--out', type=Path)
    p.add_argument('--runner', type=Path)
    p.add_argument('--runner-sha256')
    p.add_argument('--timeout', type=float, default=30)
    p.add_argument('--source-sha')
    p.add_argument('--replay-source', action='store_true')
    p.add_argument('--model', type=Path, default=DEFAULT_MATERIAL / 'model.json')
    p.add_argument('--tasks', type=Path, default=DEFAULT_MATERIAL / 'consumer.json')
    p.add_argument('--evaluation-bundle', type=Path, default=DEFAULT_MATERIAL / 'evaluation-bundle.json')
    p.add_argument('--bundle-hash', default=DEFAULT_BUNDLE)
    return p


if __name__ == '__main__':
    args = parser().parse_args()
    if args.worker is not None:
        require(args.worker_config_sha256 is not None, 'WORKER_CONFIGURATION_PIN_REQUIRED')
        raise SystemExit(worker(args.worker, args.worker_config_sha256))
    require(args.out is not None and args.runner is not None, 'OUT_AND_RUNNER_REQUIRED')
    require(1 <= args.timeout <= 60, 'BOUNDED_TIMEOUT')
    observed = run(args)
    print(json.dumps({'status': observed['status'], 'out': str(args.out),
                      'topologies': [r['accounting']['status'] for r in observed['topologies']],
                      'failures': observed['failures']}, sort_keys=True))
    raise SystemExit(0 if observed['status'] == 'PASS' else 1)
