"""Bounded local end-to-end campaign for explicitly added security work.

The retained consumer corpus is historical. Public test signatures, localhost
TCP and local SQLite are measured, not promoted to real demand, WAN propagation,
independent operators, physical durability or a useful-computation lower bound.
Every output directory is create-only; fixed attempts include misses and failures.
"""
from __future__ import annotations

import argparse
import copy
from collections import Counter
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contract_wire import ROOT, canonical, unique
import grouped_fresh_work_v0 as fresh
import grouped_work_lottery_v0 as old
from grouped_fresh_admission_wire_v0 import inspect_freeze
from grouped_legal_strategy_v0 import prepare, execute, REPRESENTATION
from experiments.grouped_cell_operator_v0 import make_commands, model_commitment
from experiments.grouped_legal_strategy_v0 import (
    RELEVANT_SOURCES, source_identity, source_gate_failures, write_json)
from experiments.shared_cell_operator_v1 import DEFAULT_MATERIAL, DEFAULT_BUNDLE, load_inputs

OWNED = tuple('formal/pon-nakamoto-v1/' + path for path in (
    'experiments/grouped_fresh_work_v0.py', 'grouped_fresh_work_v0.py',
    'test_grouped_fresh_work_v0.py', 'grouped_fresh_admission_wire_v0.py',
    'test_grouped_fresh_admission_wire_v0.py', 'grouped_work_lottery_v0.py',
    'experiments/grouped_cell_operator_v0.py', 'fresh_work_query_floor_v0.py',
    'test_fresh_work_query_floor_v0.py')) + (
    'trillionnium/Cargo.toml', 'trillionnium/Cargo.lock',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_grouped_fresh_seal_v0.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/lib.rs',
    'trillionnium/crates/trnm-pon-node/src/grouped_fresh_admission_v0.rs',
    'trillionnium/crates/trnm-pon-node/src/lib.rs',
    'trillionnium/crates/trnm-pon-node/examples/grouped_fresh_admission_v0.rs',
    'trillionnium/crates/trnm-pon-node/tests/grouped_fresh_admission_v0.rs')
SOURCES = tuple(dict.fromkeys(RELEVANT_SOURCES + OWNED))
MAX_NATIVE_FRAME = 4 * 1024 * 1024
MAX_STDERR = 64 * 1024
K = 256


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp():
    return time.perf_counter_ns(), time.thread_time_ns()


def elapsed(start):
    return {'wall_ns': time.perf_counter_ns() - start[0],
            'thread_cpu_ns': time.thread_time_ns() - start[1]}


def durable_bytes(path, raw):
    with Path(path).open('xb') as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    actual = Path(path).read_bytes()
    require(actual == raw, 'PERSISTENCE_READBACK')
    return sha(actual)


class NativeSession:
    """One persistent child, bounded commands/replies/time, exact retained I/O."""
    def __init__(self, binary, directory, out, timeout):
        self.timeout, self.ordinal, self.buffer, self.stderr_bytes = timeout, -1, b'', 0
        self.records = []
        self.start = stamp()
        self.children_before = resource.getrusage(resource.RUSAGE_CHILDREN)
        self.logs = [(out / name).open('xb') for name in
                     ('native.stdin.ndjson', 'native.stdout.ndjson', 'native.stderr.bin')]
        self.child = subprocess.Popen([str(binary), '--directory', str(directory)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0, start_new_session=True)
        self.selector = selectors.DefaultSelector()
        for pipe in (self.child.stdin, self.child.stdout, self.child.stderr):
            os.set_blocking(pipe.fileno(), False)
        self.selector.register(self.child.stdout, selectors.EVENT_READ, 'stdout')
        self.selector.register(self.child.stderr, selectors.EVENT_READ, 'stderr')
        self.closed = False

    def _fail(self, reason):
        if self.child.poll() is None:
            os.killpg(self.child.pid, signal.SIGKILL)
        self.child.wait(timeout=5)
        raise RuntimeError(reason)

    def call(self, value):
        require(not self.closed, 'CHILD_CLOSED')
        raw = canonical(value) + b'\n'
        require(len(raw) <= 8192, 'NATIVE_COMMAND_LIMIT')
        self.ordinal += 1
        record = {'ordinal': self.ordinal, 'operation': value['op'],
                  'request_bytes': len(raw), 'request_sha256': sha(raw), 'status': 'started'}
        self.records.append(record)
        start = stamp()
        deadline = time.monotonic() + self.timeout
        self.logs[0].write(raw)
        self.logs[0].flush()
        self.selector.register(self.child.stdin, selectors.EVENT_WRITE, 'stdin')
        sent = 0
        response = None
        try:
            while response is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._fail('NATIVE_RESPONSE_TIMEOUT')
                for key, _ in self.selector.select(remaining):
                    if key.data == 'stdin':
                        try:
                            sent += os.write(key.fd, raw[sent:])
                        except BlockingIOError:
                            continue
                        if sent == len(raw):
                            self.selector.unregister(key.fileobj)
                        continue
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        self.selector.unregister(key.fileobj)
                        if key.data == 'stdout' and b'\n' not in self.buffer:
                            self._fail('NATIVE_EOF_BEFORE_REPLY')
                        continue
                    if key.data == 'stderr':
                        self.stderr_bytes += len(chunk)
                        self.logs[2].write(chunk[:max(0, MAX_STDERR - self.logs[2].tell())])
                        if self.stderr_bytes > MAX_STDERR:
                            self._fail('NATIVE_STDERR_LIMIT')
                    else:
                        self.logs[1].write(chunk)
                        self.buffer += chunk
                        if len(self.buffer) > MAX_NATIVE_FRAME:
                            self._fail('NATIVE_RESPONSE_LIMIT')
                        if b'\n' in self.buffer:
                            line, self.buffer = self.buffer.split(b'\n', 1)
                            require(not self.buffer, 'UNSOLICITED_NATIVE_REPLY')
                            response = json.loads(line, object_pairs_hook=unique)
                            record['response_bytes'] = len(line) + 1
                            record['response_sha256'] = sha(line + b'\n')
                if response is None and self.child.poll() is not None and not self.selector.get_map():
                    self._fail('NATIVE_CHILD_EXIT')
            require(response['ordinal'] == self.ordinal, 'NATIVE_RESPONSE_ORDINAL')
            # Native bounded_line retains the newline; request identity is exact.
            require(response['request_sha256'] == sha(raw), 'NATIVE_REQUEST_BINDING')
            require(response['request_bytes'] == len(raw), 'NATIVE_REQUEST_BYTES')
            record.update(status='complete', native_ok=response['ok'],
                          native_error=response.get('error'),
                          command_before_response_encoding=response['command_before_response_encoding'])
            return response
        except Exception as error:
            record.update(status='failed', error_type=type(error).__name__, error=str(error),
                          partial_stage_costs=None)
            # A framing/identity failure closes this child, preventing a stale
            # response from being consumed as the next authorized result.
            if self.child.poll() is None:
                os.killpg(self.child.pid, signal.SIGKILL)
                self.child.wait(timeout=5)
            raise
        finally:
            record.update(local_exchange=elapsed(start))
            for log in self.logs:
                log.flush()

    def close(self):
        if self.closed:
            return self.exit_observation
        try:
            if self.child.poll() is None:
                self.call({'op': 'close'})
                self.child.stdin.close()
                try:
                    self.child.wait(timeout=self.timeout)
                except subprocess.TimeoutExpired:
                    self._fail('NATIVE_EXIT_TIMEOUT')
            # Final buffered bytes, if any, must also be retained and bounded.
            for pipe, log, limit in ((self.child.stdout, self.logs[1], MAX_NATIVE_FRAME),
                                     (self.child.stderr, self.logs[2], MAX_STDERR)):
                while not pipe.closed:
                    try:
                        chunk = os.read(pipe.fileno(), 65536)
                    except BlockingIOError:
                        break
                    if not chunk:
                        break
                    require(log.tell() + len(chunk) <= 64 * MAX_NATIVE_FRAME
                            if log is self.logs[1] else log.tell() + len(chunk) <= limit,
                            'NATIVE_FINAL_IO_LIMIT')
                    log.write(chunk)
            observed = elapsed(self.start)
            children_after = resource.getrusage(resource.RUSAGE_CHILDREN)
            self.exit_observation = {
                'exit_code': self.child.returncode,
                'observed_child_lifetime_wall_ns': observed['wall_ns'],
                'observer_main_thread_cpu_ns': observed['thread_cpu_ns'],
                'native_child_user_seconds': children_after.ru_utime - self.children_before.ru_utime,
                'native_child_system_seconds': children_after.ru_stime - self.children_before.ru_stime,
                'child_cpu_scope': 'RUSAGE_CHILDREN delta; native child is the only subprocess in this interval',
                'lifetime_includes_idle_fixture_orchestration': True}
            return self.exit_observation
        finally:
            self.closed = True
            self.selector.close()
            for pipe in (self.child.stdin, self.child.stdout, self.child.stderr):
                if not pipe.closed:
                    pipe.close()
            for log in self.logs:
                log.close()


def result(response):
    require(response['ok'], 'NATIVE_' + str(response.get('error')))
    return response['result']


def context(frozen, candidate):
    return {'chain': frozen['branch']['network'], 'parent': frozen['branch']['parent'],
            'challenge': candidate['challenge'], 'batch_id': candidate['context']['batch_id']}


def recv_exact(connection, count):
    value = bytearray()
    while len(value) < count:
        chunk = connection.recv(count - len(value))
        if not chunk:
            raise ValueError('TCP_TRUNCATED_FRAME')
        value.extend(chunk)
    return bytes(value)


class Receiver:
    def __init__(self, session, frozen, candidates, init, requests, out, timeout):
        self.session, self.frozen, self.candidates = session, frozen, candidates
        self.init, self.requests, self.out, self.timeout = init, requests, out, timeout
        self.start_ns = time.monotonic_ns()
        self.receipts = []

    def now(self):
        return 1 + time.monotonic_ns() - self.start_ns

    def reserve(self, value, mode):
        return result(self.session.call({
            'op': 'reserve_verification', 'nonce': value['nonce'],
            'statement': value['statement_commitment'],
            'proof_sha256': sha(bytes.fromhex(value['proof_hex'])),
            'capsule_sha256': sha(bytes.fromhex(value['capsule_hex'])),
            'mode': mode, 'now_ns': self.now()}))

    def verify(self, raw, mode):
        record = {'status': 'started', 'packet_bytes': len(raw), 'packet_sha256': sha(raw),
                  'stages': {}, 'chainwork_awarded': 0}
        started = stamp()
        try:
            step = stamp()
            packet_path = self.out / f'packet-{len(self.receipts):04d}.bin'
            record['persisted_packet_sha256'] = durable_bytes(packet_path, raw)
            record['packet_file'] = packet_path.name
            record['stages']['exact_packet_persistence_and_readback'] = elapsed(step)
            step = stamp()
            value = fresh.parse_package(raw)
            candidate = self.candidates[value['nonce']]
            expected_context = context(self.frozen, candidate)
            record['stages']['bounded_decode_and_candidate_lookup'] = elapsed(step)
            step = stamp()
            permit = self.reserve(value, mode)
            record['stages']['durable_verification_budget_reservation'] = elapsed(step)
            record['budget_reservation'] = permit
            # The expensive arithmetic is AFTER the persistent, non-refundable cap.
            step = stamp()
            checked = fresh.verify_grouped_package(raw, init=self.init, requests=self.requests,
                expected_context=expected_context, now_ns=self.now())
            record['stages']['independent_full_cell'] = elapsed(step)
            record['reference_macs'] = checked['reference_macs']
            record['reference_additions'] = checked['reference_additions']
            step = stamp()
            verified = result(self.session.call({
                'op': 'verify' if mode == 'record' else 'verify_untrusted',
                'nonce': value['nonce'], 'statement': value['statement_commitment'],
                'proof_hex': value['proof_hex'], 'capsule_hex': value['capsule_hex'],
                'verification_permit': permit['permit']['verification_permit'],
                'now_ns': self.now()}))
            record['stages']['native_authorization_seal_and_journal'] = elapsed(step)
            record.update(status='verified', native_verification=verified,
                          nonce=value['nonce'], work_id=candidate['work_id'],
                          target_hit=verified['observation']['target_hit'],
                          full_grouped_relation_verified=True,
                          canonical_statement_verified=True)
        except Exception as error:
            record.update(status='rejected', error_type=type(error).__name__, error=str(error),
                          unknown_partial_stage_costs=None)
        record['receiver_before_receipt_persistence'] = elapsed(started)
        path = self.out / f'receipt-{len(self.receipts):04d}.json'
        step = stamp()
        record['receipt_sha256'] = durable_bytes(path, canonical(record) + b'\n')
        record['receipt_persistence_and_readback'] = elapsed(step)
        record['receiver_total_before_ack_encoding'] = elapsed(started)
        self.receipts.append(record)
        return record

    def send(self, raw, *, mode='record'):
        require(type(raw) is bytes and len(raw) <= fresh.MAX_PACKAGE_BYTES, 'TCP_PACKET_LIMIT')
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.settimeout(self.timeout)
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        address = listener.getsockname()
        capture = {}
        def serve():
            try:
                with listener, listener.accept()[0] as connection:
                    connection.settimeout(self.timeout)
                    n, = struct.unpack('!I', recv_exact(connection, 4))
                    require(n <= fresh.MAX_PACKAGE_BYTES, 'TCP_RECEIVE_LIMIT')
                    data = recv_exact(connection, n)
                    record = self.verify(data, mode)
                    ack = canonical(record)
                    require(len(ack) <= fresh.MAX_PACKAGE_BYTES, 'TCP_ACK_LIMIT')
                    connection.sendall(struct.pack('!I', len(ack)) + ack)
                    capture['record'] = record
                    capture['ack_bytes'] = len(ack)
            except Exception as error:
                capture.update(error_type=type(error).__name__, error=str(error))
        started = stamp()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with socket.create_connection(address, timeout=self.timeout) as client:
                client.settimeout(self.timeout)
                client.sendall(struct.pack('!I', len(raw)) + raw)
                n, = struct.unpack('!I', recv_exact(client, 4))
                require(n <= fresh.MAX_PACKAGE_BYTES, 'TCP_CLIENT_ACK_LIMIT')
                reply = json.loads(recv_exact(client, n), object_pairs_hook=unique)
            thread.join(timeout=self.timeout)
            require(not thread.is_alive(), 'TCP_RECEIVER_EXIT_TIMEOUT')
            require('error' not in capture, 'TCP_RECEIVER_' + str(capture.get('error')))
            require(reply == capture['record'], 'TCP_ACK_IDENTITY')
            return {'response': reply, 'client_round_trip': elapsed(started),
                    'tcp_application_sent_bytes': len(raw) + 4,
                    'tcp_application_received_bytes': capture['ack_bytes'] + 4,
                    'network_scope': 'actual localhost TCP only; no WAN or TLS measurement'}
        finally:
            listener.close()
            thread.join(timeout=self.timeout)


def plan(rounds):
    return {'schema': 'pon-grouped-fresh-work-plan-v0', 'profile': fresh.PROFILE,
            'primary_nonces': list(range(1, rounds + 1)), 'no_stop_on_hit': True,
            'carrier_nonce': 1, 'carrier_encodings': 64,
            'untrusted_nonce': rounds + 1, 'cancel_after_17_nonce': rounds + 2,
            'reserved_unknown_nonce': rounds + 3, 'nonce_count': rounds + 3,
            'negative_packets': ['forged_zero_endpoint', 'wrong_output', 'wrong_context',
                                 'wrong_capsule', 'trailing_non_json'],
            'authority_controls': ['outside_authorized_nonce', 'expired_authority'],
            'verification_budget': K, 'exhaust_remaining_budget': True,
            'remaining_verification_reservations': K - rounds - 69,
            'same_process_reopen_controls': True,
            'source_replay_required_for_final': True, 'chainwork_awarded': 0}


def expected_controls(prereg):
    counts = {name: 1 for name in prereg['negative_packets'] + prereg['authority_controls']}
    counts.update(carrier_replay=64, valid_without_native_producer_journal=1,
                  cancel_after_17=1, reserved_without_execution=1,
                  same_process_sqlite_reopen=1, reopened_nonce_cannot_restart=3,
                  consume_remaining_verification_reservation=prereg['remaining_verification_reservations'],
                  budget_survives_reopen=1, **{'257th_verification_rejected_before_cell': 1})
    return counts


def run(args):
    whole = stamp()
    cpu = time.process_time_ns()
    child_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    before = source_identity(sources=SOURCES)
    runner_before = sha(args.runner.read_bytes()) if args.runner.is_file() else None
    prereg = plan(args.rounds)
    write_json(out / 'request.json', {k: str(v) if isinstance(v, Path) else v
                                    for k, v in vars(args).items()})
    write_json(out / 'plan.json', prereg)
    plan_sha = sha((out / 'plan.json').read_bytes())
    failures = [dict(f, stage='source_before') for f in source_gate_failures(before, args.source_sha)]
    if args.source_sha and not args.replay_source:
        failures.append({'stage': 'source_before', 'reason': 'SOURCE_REPLAY_REQUIRED'})
    attempts, controls, trace, session, receiver = [], [], [], None, None
    material, frozen, binding_check, preparation, exit_state = None, None, None, None, None
    try:
        require(not failures, 'SOURCE_GATE')
        step = stamp()
        model, rows, provenance = load_inputs(args.model, args.tasks, args.evaluation_bundle,
            args.bundle_hash, 'consumer', 0, 16, replay_source=args.replay_source)
        init, commands = make_commands(model, rows, provenance, [16], 1, 0)
        requests = commands[0]['requests']
        material = {'provenance': provenance, 'load_and_source_replay': elapsed(step),
                    'historical_corpus_not_new_demand': True,
                    'model_file_sha256': sha(args.model.read_bytes()),
                    'tasks_file_sha256': sha(args.tasks.read_bytes()),
                    'model_commitment': model_commitment(init),
                    'request_precommitment': old.request_precommitment(init, requests)}
        # A legal sparse merged producer computes the fixed useful product once.
        step = stamp()
        prepared = prepare(init, 'sparse_cached_merged')
        strategy_requests = [dict(r, generation=init['model_version'],
                                  representation=REPRESENTATION) for r in requests]
        product, product_cost = execute(prepared, strategy_requests)
        preparation = {'scope': 'one legal sparse merged product, then exact memo reuse',
                       'measured': elapsed(step), 'model_preparation_counts': dict(prepared.preparation_cost),
                       'product_execution_counts': asdict(product_cost),
                       'product_sha256': sha(canonical(product)),
                       'new_neural_contractions_per_primary_nonce': 0}
        native_dir = out / 'native-session'
        session = NativeSession(args.runner.resolve(), native_dir, out, args.timeout)
        freeze_request = dict(op='freeze', model_commitment=material['model_commitment'],
            request_precommitment=material['request_precommitment'],
            batch_id=commands[0]['context']['batch_id'], authorization_scope=requests[0]['scope'],
            demand_id=sha(b'controlled-historical-consumer-not-current-demand'),
            source_record=sha(canonical(provenance)), withdrawal_head=sha(b'controlled-withdrawal-head'),
            payee=sha(b'controlled-public-test-payee'), model_generation=1,
            timestamp_ms=1_700_000_000_000, not_before_ns=1, expires_ns=3_600_000_000_000,
            available_until_ns=3_600_000_000_000, nonce_first=prereg['carrier_nonce'],
            nonce_count=prereg['nonce_count'], now_ns=1)
        frozen = result(session.call(freeze_request))
        pins = {'expected_body_sha256': sha((native_dir / 'expected-body.bin').read_bytes()),
                'expected_capsule_sha256': sha((native_dir / 'capsule.bin').read_bytes()),
                'expected_policy_file_sha256': sha((native_dir / 'expected-policy.json').read_bytes()),
                'branch': frozen['branch']}
        binding_check = inspect_freeze(frozen, {k: v for k, v in freeze_request.items() if k != 'op'},
                                      init, requests, expected_native=pins)
        require(binding_check['pins_checked'] and binding_check['branch_pin_checked'],
                'COMPLETE_LOCAL_PINS_REQUIRED')
        candidates = binding_check['candidates_by_nonce']
        receiver = Receiver(session, frozen, candidates, init, requests, out, args.timeout)
        first_packet = None
        for nonce in prereg['primary_nonces']:
            attempt = {'nonce': nonce, 'status': 'started', 'stage': 'binding',
                       'new_neural_contractions': 0, 'chainwork_awarded': 0}
            attempts.append(attempt)
            started = stamp()
            try:
                ctx = context(frozen, candidates[nonce])
                step = stamp()
                statement = fresh.grouped_binding(init, requests, ctx, product)['statement_commitment']
                attempt['statement_binding'] = elapsed(step)
                attempt.update(statement=statement, challenge=ctx['challenge'], stage='native_producer')
                produced = result(session.call({'op': 'prove', 'nonce': nonce,
                                               'statement': statement, 'now_ns': receiver.now()}))
                attempt['native_producer'] = produced
                attempt['stage'] = 'independent_python_hash_transcript'
                step = stamp()
                local_trace = []
                independent = fresh.prove(ctx['challenge'], statement, on_step=local_trace.append)
                require(independent.hex() == produced['proof_hex'], 'NATIVE_PYTHON_SEAL_MISMATCH')
                trace.extend(dict(row, nonce=nonce, owner='independent_python_crosscheck')
                             for row in local_trace)
                attempt['independent_python_seal_and_trace'] = elapsed(step)
                attempt['independent_trace_steps'] = len(local_trace)
                attempt['stage'] = 'serialization_and_tcp'
                step = stamp()
                packet = fresh.package(init, requests, ctx, product, nonce=nonce,
                                       capsule_hex=frozen['capsule_hex'], proof=independent)
                attempt['package_serialization'] = elapsed(step)
                attempt['packet_bytes'] = len(packet)
                observed = receiver.send(packet)
                attempt['transport_and_full_verification'] = observed
                require(observed['response']['status'] == 'verified', 'PRIMARY_FULL_VERIFICATION')
                require(observed['response']['native_verification']['observation']['first_record'],
                        'PRIMARY_DUPLICATE')
                require(observed['response']['target_hit'] == produced['target_hit'], 'TARGET_DISAGREEMENT')
                attempt.update(status='verified', stage='complete', target_hit=produced['target_hit'])
                if nonce == prereg['carrier_nonce']:
                    first_packet = packet
            except Exception as error:
                attempt.update(status='failed', error_type=type(error).__name__, error=str(error),
                               unknown_partial_counts=None)
                failures.append({'stage': 'primary', 'nonce': nonce, 'reason': str(error)})
            attempt['whole_attempt'] = elapsed(started)
        require(first_packet is not None, 'FIRST_PACKET_UNAVAILABLE')

        # Sixty-four distinct JSON carriers for exactly the same ticket/work ID.
        for i in range(prereg['carrier_encodings']):
            observed = receiver.send(first_packet + b' ' * i)
            entry = {'control': 'carrier_replay', 'encoding': i, **observed}
            controls.append(entry)
            require(observed['response']['status'] == 'verified' and
                    not observed['response']['native_verification']['observation']['first_record'],
                    'CARRIER_REPLAY_REISSUED_IDENTITY')
        original = fresh.parse_package(first_packet)
        for name in prereg['negative_packets']:
            changed = copy.deepcopy(original)
            if name == 'forged_zero_endpoint':
                changed['proof_hex'] = changed['proof_hex'][:204] + '00' * 32
            elif name == 'wrong_output':
                changed['product']['logits'][0][0] += 1
            elif name == 'wrong_context':
                changed['context']['parent'] = '00' * 32
            elif name == 'wrong_capsule':
                blob = bytearray.fromhex(changed['capsule_hex'])
                blob[-1] ^= 1
                changed['capsule_hex'] = blob.hex()
            packet = canonical(changed) + (b'garbage' if name == 'trailing_non_json' else b'')
            observed = receiver.send(packet)
            controls.append({'control': name, **observed})
            require(observed['response']['status'] == 'rejected', 'NEGATIVE_PACKET_ACCEPTED_' + name)

        # This valid endpoint was never placed in the native producer journal.
        nonce = prereg['untrusted_nonce']
        independent_started = stamp()
        ctx = context(frozen, candidates[nonce])
        statement = fresh.grouped_binding(init, requests, ctx, product)['statement_commitment']
        untrusted_trace = []
        independent = fresh.prove(ctx['challenge'], statement, on_step=untrusted_trace.append)
        trace.extend(dict(row, nonce=nonce, owner='independent_untrusted_producer')
                     for row in untrusted_trace)
        packet = fresh.package(init, requests, ctx, product, nonce=nonce,
                               capsule_hex=frozen['capsule_hex'], proof=independent)
        independent_production = elapsed(independent_started)
        observed = receiver.send(packet, mode='untrusted')
        controls.append({'control': 'valid_without_native_producer_journal',
                         'binding_python_production_and_encoding': independent_production,
                         'python_chain_steps': len(untrusted_trace), **observed})
        require(observed['response']['status'] == 'verified', 'UNTRUSTED_VALID_ENDPOINT')
        for name, control_nonce, control_time in (
                ('outside_authorized_nonce', prereg['reserved_unknown_nonce'] + 1, receiver.now()),
                ('expired_authority', prereg['carrier_nonce'], freeze_request['expires_ns'])):
            refused = session.call({'op': 'reserve_verification', 'nonce': control_nonce,
                'statement': statement, 'proof_sha256': sha(independent),
                'capsule_sha256': frozen['capsule_sha256'], 'mode': 'untrusted',
                'now_ns': control_time})
            controls.append({'control': name, 'native_response': refused})
            require(not refused['ok'], 'AUTHORITY_CONTROL_ACCEPTED_' + name)
        cancelled_nonce = prereg['cancel_after_17_nonce']
        ctx_cancel = context(frozen, candidates[cancelled_nonce])
        cancel_statement = fresh.grouped_binding(init, requests, ctx_cancel, product)['statement_commitment']
        cancelled = session.call({'op': 'prove', 'nonce': cancelled_nonce,
            'statement': cancel_statement, 'now_ns': receiver.now(), 'cancel_after': 17})
        controls.append({'control': 'cancel_after_17', 'native_response': cancelled})
        require(result(cancelled)['completed_steps'] == 17 and
                not result(cancelled)['final_query_evaluated'] and result(cancelled)['proof_hex'] is None,
                'CANCELLED_PREFIX_PROMOTED')
        unknown = session.call({'op': 'reserve_only', 'nonce': prereg['reserved_unknown_nonce'],
                                'now_ns': receiver.now()})
        controls.append({'control': 'reserved_without_execution', 'native_response': unknown})
        result(unknown)
        reopened = session.call({'op': 'reopen', 'now_ns': receiver.now()})
        controls.append({'control': 'same_process_sqlite_reopen', 'native_response': reopened})
        result(reopened)
        for nonce in (prereg['carrier_nonce'], cancelled_nonce, prereg['reserved_unknown_nonce']):
            refused = session.call({'op': 'prove', 'nonce': nonce, 'statement': statement,
                                    'now_ns': receiver.now()})
            controls.append({'control': 'reopened_nonce_cannot_restart', 'nonce': nonce,
                             'native_response': refused})
            require(not refused['ok'], 'REOPENED_RESERVATION_REISSUED')

        status = result(session.call({'op': 'status'}))
        remaining = status['ledger']['verification_budget']['remaining']
        require(remaining == prereg['remaining_verification_reservations'], 'PRECOMMITTED_BUDGET_DISPOSITION')
        # Fixed cap; unused reservations consume budget without inventing hashes.
        for index in range(remaining):
            reserved = receiver.reserve(original, 'record')
            controls.append({'control': 'consume_remaining_verification_reservation',
                             'index': index, 'native_response': reserved,
                             'full_replay_performed': False})
        status = result(session.call({'op': 'reopen', 'now_ns': receiver.now()}))
        controls.append({'control': 'budget_survives_reopen', 'native_response': status})
        require(status['ledger']['verification_budget']['remaining'] == 0, 'BUDGET_RESET')
        rejected = receiver.send(first_packet)
        controls.append({'control': '257th_verification_rejected_before_cell', **rejected})
        require(rejected['response']['status'] == 'rejected' and
                'independent_full_cell' not in rejected['response']['stages'], 'BUDGET_BYPASS')
    except Exception as error:
        failures.append({'stage': 'campaign', 'error_type': type(error).__name__, 'reason': str(error)})
    finally:
        if session is not None:
            try:
                exit_state = session.close()
                if exit_state['exit_code'] != 0:
                    failures.append({'stage': 'native_exit', 'reason': exit_state})
            except Exception as error:
                failures.append({'stage': 'native_close', 'reason': str(error)})
    after = source_identity(sources=SOURCES)
    runner_after = sha(args.runner.read_bytes()) if args.runner.is_file() else None
    if runner_before is None or runner_before != runner_after:
        failures.append({'stage': 'runner', 'reason': 'BINARY_MISSING_OR_CHANGED'})
    failures.extend(dict(f, stage='source_after') for f in source_gate_failures(after, args.source_sha))
    stable = before['commit'] == after['commit'] and before['relevant_sources_sha256'] == after['relevant_sources_sha256']
    if not stable:
        failures.append({'stage': 'source', 'reason': 'SOURCE_CHANGED'})
    if sha((out / 'plan.json').read_bytes()) != plan_sha:
        failures.append({'stage': 'plan', 'reason': 'PLAN_CHANGED'})
    not_started = [dict(nonce=n, status='not_started', cost=None) for n in prereg['primary_nonces']
                   if n not in {a['nonce'] for a in attempts}]
    control_counts = Counter(c['control'] for c in controls)
    control_plan = expected_controls(prereg)
    missing_controls = [{'control': key, 'not_started': max(0, count - control_counts[key]),
                         'cost': None} for key, count in control_plan.items() if count > control_counts[key]]
    controls_complete = dict(control_counts) == control_plan
    if not controls_complete:
        failures.append({'stage': 'control_accounting', 'reason': 'PLANNED_CONTROL_DISPOSITION_INCOMPLETE'})
    for name, values in (('attempts', attempts), ('controls', controls), ('hash-transcript', trace),
                         ('native-exchanges', session.records if session else [])):
        durable_bytes(out / (name + '.ndjson'), b''.join(canonical(v) + b'\n' for v in values))
    child_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    report = {'schema': 'pon-grouped-fresh-work-campaign-v0', 'profile': fresh.PROFILE,
        'status': 'complete_research_hold' if not failures else 'failed_research_hold',
        'measurement_mode': 'final_exact_source' if args.source_sha else 'development_unqualified',
        'expected_source_sha': args.source_sha, 'source_before': before, 'source_after': after,
        'exact_committed_source_verified': bool(args.source_sha) and stable and
            not source_gate_failures(before, args.source_sha) and not source_gate_failures(after, args.source_sha),
        'runner_before_sha256': runner_before, 'runner_sha256': runner_after,
        'runner_bytes_stable': runner_before is not None and runner_before == runner_after,
        'preregistered_plan_sha256': plan_sha, 'material': material, 'freeze': frozen,
        'independent_wire_binding_check': binding_check, 'legal_preparation': preparation,
        'attempts': attempts, 'not_started': not_started, 'controls': controls,
        'expected_control_counts': control_plan, 'actual_control_counts': dict(control_counts),
        'not_started_controls': missing_controls, 'control_accounting_complete': controls_complete,
        'planned_primary_attempts': args.rounds, 'actual_primary_attempts': len(attempts),
        'verified_primary_attempts': sum(a['status'] == 'verified' for a in attempts),
        'primary_target_hits': sum(a.get('target_hit', False) for a in attempts),
        'distinct_primary_challenges': len({a.get('challenge') for a in attempts if 'challenge' in a}),
        'independent_python_step_hashes': len(trace),
        'primary_independent_python_step_hashes': sum(t['owner'] == 'independent_python_crosscheck' for t in trace),
        'untrusted_python_producer_step_hashes': sum(t['owner'] == 'independent_untrusted_producer' for t in trace),
        'distinct_independent_python_step_preimages': len({t['input_hex'] for t in trace}),
        'trace_scope': 'actual extra Python crosscheck; native producer/verifier counters are separate; not complete global oracle attestation',
        'primary_round_accounting_complete': sorted([a['nonce'] for a in attempts] +
            [a['nonce'] for a in not_started]) == prereg['primary_nonces'],
        'native_exit': exit_state, 'native_exchanges': session.records if session else [],
        'receipt_count': len(receiver.receipts) if receiver else 0,
        'whole_campaign_before_report': elapsed(whole),
        'parent_process_cpu_ns': time.process_time_ns() - cpu,
        'child_user_seconds': child_after.ru_utime - child_before.ru_utime,
        'child_system_seconds': child_after.ru_stime - child_before.ru_stime,
        'children_peak_rss_kib_high_water_not_delta': child_after.ru_maxrss,
        'cost_scope': ['Parent process CPU includes receiver thread; do not add it again.',
            'Children CPU includes source replay, git identity commands and native service; nested phases are not additive.',
            'Wall includes reads, source replay, preparation, signatures, proofs, full verification, persistence and localhost transport.',
            'Seed/binding/signature hashes and SHA256 compression operations are not equated to the64 chain-oracle queries.',
            'Final report encoding, Python parent startup/import/exit, WAN, TLS, production proofs, consensus propagation and real availability service remain outside this measurement.'],
        'crash_accounting_scope': 'Native request/response journals and completed receiver receipts persist incrementally; a whole-Python-process kill can leave remaining attempt stage counts unknown. No crash-complete accounting claim.',
        'failures': failures, 'external_demand_authenticated': False, 'independent_operators': False,
        'global_verification_cap_enforced': False, 'hidden_verifier_side_channel_model_verified': False,
        'minimum_fresh_neural_cost_proved': False, 'physical_resource_lower_bound_proved': False,
        'quantum_security_proved': False, 'pow_qualified': False, 'production_activation': False,
        'chainwork_awarded': 0}
    write_json(out / 'report.json', report)
    return report


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--runner', type=Path, required=True)
    p.add_argument('--rounds', type=int, default=16)
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
    require(1 <= args.rounds <= 64 and 0 < args.timeout <= 60, 'CAMPAIGN_LIMIT')
    report = run(args)
    print(json.dumps({'status': report['status'], 'verified': report['verified_primary_attempts'],
                      'planned': report['planned_primary_attempts'], 'failures': report['failures'],
                      'chainwork_awarded': 0}, sort_keys=True))
    raise SystemExit(0 if not report['failures'] else 2)
