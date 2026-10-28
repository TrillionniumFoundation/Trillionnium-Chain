#!/usr/bin/env python3
"""Two real host verifications around a bounded, local TCP byte observation.

This research CLI never generates proofs, accepts supplied success records, or
offers a skip-verification mode. The host must be the reviewed original Rust
build; recording its bytes is provenance, not executable attestation.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

BACKEND = Path(__file__).resolve().parent
REPOSITORY = BACKEND.parents[4]
sys.path.insert(0, str(REPOSITORY/'scripts'))
from llm_runtime_pilot import _OwnedChildCleanupRequired, supervise
from _loopback_tcp import (FRAME, MAX_BYTES, file_identity, read_json, remaining,
                           require, write_json)
from observations import read_single_result

TRANSFER_SECONDS = 30
VERIFY_SECONDS = 900
VERIFY_RSS_BYTES = 8*1024**3
INPUT_BYTES = 49640
WORKER_COMMAND = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                  'from _loopback_tcp import worker;worker()')


def _closed_success(result, rss_cap):
    require(result.get('outcome') == 'success' and result.get('exit_code') == 0
            and result.get('stop_reason') is None and result.get('waited_child_reaped') is True
            and result.get('owned_child_reap_resolved') is True
            and result.get('cleanup_method') == 'wait4'
            and result.get('waited_child_observation_error') is None,
            'loopback-owned-process-not-successfully-closed')
    for key in ('sampled_peak_rss_bytes','waited_child_peak_rss_bytes'):
        require(type(result.get(key)) is int and 0 <= result[key] <= rss_cap,
                'loopback-measured-rss-cap')
    require(type(result.get('child_cpu_ns')) is int and result['child_cpu_ns'] >= 0,
            'loopback-wait4-cpu-unavailable')


def _source_snapshot():
    paths = [BACKEND/p for p in ('measure_loopback.py','_loopback_tcp.py','observations.py',
             'backend-manifest.json','Cargo.toml','Cargo.lock','host/Cargo.toml')]
    paths += list((BACKEND/'host/src').rglob('*.rs'))
    paths += [REPOSITORY/'scripts'/p for p in ('llm_runtime_pilot.py',
              'llm_runtime_exit_observation.py','llm_runtime_rss_diagnostics.py')]
    manifest = read_json(BACKEND/'backend-manifest.json')
    for relative, expected in manifest['guest_source_sha256'].items():
        path = (BACKEND/relative).resolve()
        require(path.is_relative_to(REPOSITORY), 'loopback-source-scope')
        require(file_identity(path)['sha256'] == expected, 'loopback-guest-source-binding')
        paths.append(path)
    return {str(path.relative_to(REPOSITORY)):file_identity(path)
            for path in sorted(set(paths))}


def _verify(host, elf, input_path, receipt, directory, expected, manifest, record):
    command = [str(host),'verify',str(elf),str(input_path),str(receipt)]
    record.update(command=command, outcome='failed', result=None)
    try:
        process = supervise(command,directory,dict(wall_seconds=VERIFY_SECONDS,rss_bytes=VERIFY_RSS_BYTES))
    except _OwnedChildCleanupRequired as error:
        record['process'] = error.receipt
        raise
    record['process'] = process
    _closed_success(process,VERIFY_RSS_BYTES)
    record['raw_log'] = file_identity(directory/'process.log',1024**2,allow_empty=True)
    value = read_single_result(directory/'process.log','pon-w1-risc0-research-v1','verify')
    record['result'] = value
    require(value.get('real_composite_stark_verified') is True
            and value.get('consensus_authority') is False
            and value.get('native_w1_recomputed') is False
            and value.get('image_id') == manifest['guest_image_id']
            and value.get('receipt_bytes') == expected['bytes']
            and re.fullmatch('[0-9a-f]{64}',str(value.get('statement_id')))
            and type(value.get('verified_segment_profile')) is list
            and value['verified_segment_profile'], 'loopback-native-verification-result')
    for key in ('verify_wall_ns','verify_process_cpu_ns'):
        require(type(value.get(key)) is int and value[key] >= 0,
                'loopback-native-verification-cost')
    record['outcome'] = 'verified'
    return value


def _transfer(source, expected, directory, record):
    """Private byte component; successful execution alone verifies no proof."""
    directory.mkdir(mode=0o700)
    start, parent_cpu = time.monotonic_ns(), time.process_time_ns()
    deadline = start+TRANSFER_SECONDS*10**9
    nonce = secrets.token_bytes(32)
    nonce_hash = hashlib.sha256(nonce).hexdigest()
    record.update(schema='pon-w1-loopback-transport-v1',outcome='failed',roles={},
        deadline_ns=deadline,wall_cap_seconds=TRANSFER_SECONDS,rss_cap_per_role_bytes=MAX_BYTES,
        cryptographic_proof_verified=False,tcp_ip_bytes_measured=False,wan_measured=False,
        public_ingress_qualified=False,resource_qualification=False,consensus_authority=False,
        application_payload_bytes=None,application_framing_bytes=None,
        parent_observer_cpu_scope='one parent process CPU interval; per-role observer intervals overlap')
    futures = {}
    error = None

    def launch(pool,role,port):
        config = directory/(role+'-config.json')
        write_json(config,dict(schema='pon-w1-loopback-worker-v1',role=role,directory=str(directory),
            source=str(source),expected=expected,nonce=nonce.hex(),deadline_ns=deadline,port=port))
        command = [sys.executable,'-I','-c',WORKER_COMMAND,str(BACKEND),str(config)]
        record['roles'][role] = dict(command=command,process=None,worker=None)
        # A single absolute protocol deadline; late launches receive only its remaining time.
        budget = dict(wall_seconds=remaining(deadline),rss_bytes=MAX_BYTES)
        futures[role] = pool.submit(supervise,command,directory/role,budget)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            try:
                launch(pool,'receiver',None)
                while not (directory/'ready.json').exists():
                    require(not futures['receiver'].done(),'loopback-receiver-exited-before-ready')
                    time.sleep(min(0.005,remaining(deadline)))
                ready = read_json(directory/'ready.json')
                require(ready.get('schema') == 'pon-w1-loopback-ready-v1'
                        and ready.get('nonce_sha256') == nonce_hash
                        and type(ready.get('address')) is list and len(ready['address']) == 2
                        and ready['address'][0] == '127.0.0.1'
                        and type(ready['address'][1]) is int and 0 < ready['address'][1] < 65536,
                        'loopback-listener-identity')
                record['ready'] = ready
                launch(pool,'sender',ready['address'][1])
            except BaseException as caught:
                error = caught
            finally:
                # Never cancel or forget a live owner. Each independently settles its exact child.
                for role,future in futures.items():
                    try:
                        record['roles'][role]['process'] = future.result()
                    except BaseException as caught:
                        if isinstance(caught,_OwnedChildCleanupRequired):
                            record['roles'][role]['process'] = caught.receipt
                        record['roles'][role]['owner_error'] = dict(type=type(caught).__name__,
                                                                   message=str(caught)[:200])
                        if error is None: error = caught
                    path = directory/role/'worker.json'
                    if path.exists():
                        try: record['roles'][role]['worker'] = read_json(path)
                        except BaseException as caught:
                            record['roles'][role]['worker_read_error'] = str(caught)[:200]
                            if error is None: error = caught
        if error is not None: raise error
        require(set(record['roles']) == {'sender','receiver'},'loopback-two-roles-required')
        for role,item in record['roles'].items():
            _closed_success(item['process'],MAX_BYTES)
            worker = item['worker']
            require(type(worker) is dict and worker.get('schema') == 'pon-w1-loopback-worker-observation-v1'
                    and worker.get('role') == role and worker.get('outcome') == 'complete'
                    and worker.get('nonce_sha256') == nonce_hash
                    and worker.get('address_space_limit_bytes') == MAX_BYTES
                    and worker.get('cryptographic_proof_verified') is False,
                    'loopback-worker-observation')
        sender,receiver = (record['roles'][role]['worker'] for role in ('sender','receiver'))
        require(sender['pid'] != receiver['pid'] and receiver['pid'] == ready['pid']
                and sender['local'] == receiver['peer'] and sender['peer'] == receiver['local']
                and receiver['local'] == ready['address'], 'loopback-connected-process-pair')
        require(sender['payload_bytes_sendall_completed'] == receiver['payload_bytes_received'] == expected['bytes']
                and receiver['payload_sha256'] == expected['sha256']
                and sender['partial_send_unknown'] is False
                and sender['header_bytes_sent'] == receiver['header_bytes_received'] == FRAME.size
                and sender['ack_bytes_received'] == receiver['ack_bytes_sent'] == FRAME.size
                and receiver['file_fsync_completed'] is True and receiver['directory_fsync_completed'] is True,
                'loopback-complete-byte-fsync-observation')
        received = file_identity(directory/'received.bin')
        record['received'] = received
        require({key:received[key] for key in ('bytes','sha256')} == expected,
                'loopback-received-file-binding')
        remaining(deadline)
        record.update(outcome='complete',application_payload_bytes=expected['bytes'],
                      application_framing_bytes=2*FRAME.size)
        return directory/'received.bin'
    except BaseException as caught:
        record['error'] = dict(type=type(caught).__name__,message=str(caught)[:200])
        raise
    finally:
        record.update(observed_wall_ns=time.monotonic_ns()-start,
                      parent_observer_cpu_ns=time.process_time_ns()-parent_cpu)
        write_json(directory/'transport.json',record)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('host','elf','input','receipt','out'):
        parser.add_argument('--'+name,required=True,type=Path)
    args = parser.parse_args(argv)
    out = args.out.absolute()
    out.mkdir(mode=0o700)
    report = dict(schema='pon-w1-loopback-cost-v1',outcome='failed',
        scope='two controlled processes over IPv4 127.0.0.1 only; same-administrator host',
        cryptographic_receipt_verified_before=False,cryptographic_receipt_verified_after=False,
        real_proof_transfer_observed=False,public_ingress_qualified=False,
        resource_qualification=False,consensus_authority=False,pq_128_security_qualified=False,
        work_hardness_qualified=False,wan_measured=False,tcp_ip_bytes_measured=False,
        verification={'before':None,'after':None},transport=None,
        binary_build_attested=False,source_snapshot_before=None,source_snapshot_after=None,
        material_before=None,material_after=None,
        cost_scope='transport phases exclude two native verification phases; application bytes are not TCP/IP bytes')
    paths = {name:getattr(args,name).absolute() for name in ('host','elf','input','receipt')}
    paths['python'] = Path(sys.executable).resolve()
    started = time.monotonic_ns()
    try:
        require(sys.platform == 'linux' and 'RISC0_DEV_MODE' not in os.environ,
                'loopback-linux-and-no-development-mode-required')
        report['source_commit'] = subprocess.check_output(
            ['git','-C',str(REPOSITORY),'rev-parse','HEAD'],text=True).strip()
        report['source_snapshot_before'] = _source_snapshot()
        before = {key:file_identity(path) for key,path in paths.items()}
        report['material_before'] = before
        manifest = read_json(BACKEND/'backend-manifest.json')
        require(before['elf']['bytes'] <= 16*1024**2
                and before['elf']['sha256'] == manifest['guest_program_sha256']
                and before['input']['bytes'] == INPUT_BYTES
                and os.access(paths['host'],os.X_OK),'loopback-native-material-binding')
        expected = {key:before['receipt'][key] for key in ('bytes','sha256')}
        report['verification']['before'] = {}
        first = _verify(paths['host'],paths['elf'],paths['input'],paths['receipt'],out/'verify-before',
                        expected,manifest,report['verification']['before'])
        report['cryptographic_receipt_verified_before'] = True
        report['transport'] = {}
        received = _transfer(paths['receipt'],expected,out/'transport',report['transport'])
        report['verification']['after'] = {}
        second = _verify(paths['host'],paths['elf'],paths['input'],received,out/'verify-after',
                         expected,manifest,report['verification']['after'])
        require(first['image_id'] == second['image_id'] and first['statement_id'] == second['statement_id']
                and first['verified_segment_profile'] == second['verified_segment_profile'],
                'loopback-same-native-verification-identity')
        require(file_identity(received) == report['transport']['received'],
                'loopback-materialized-receipt-changed')
        report['cryptographic_receipt_verified_after'] = True
        report['material_after'] = {key:file_identity(path) for key,path in paths.items()}
        report['source_snapshot_after'] = _source_snapshot()
        require(before == report['material_after']
                and report['source_snapshot_before'] == report['source_snapshot_after'],
                'loopback-source-or-input-changed')
        report.update(outcome='complete',real_proof_transfer_observed=True)
    except BaseException as error:
        report['error'] = dict(type=type(error).__name__,message=str(error)[:300])
    finally:
        # Attempt final source/material retention even when a phase refused; never fill missing costs with zero.
        for key,operation in (
            ('material_after',lambda:{key:file_identity(path) for key,path in paths.items()}),
            ('source_snapshot_after',_source_snapshot)):
            if report[key] is None:
                try: report[key] = operation()
                except BaseException as error: report[key+'_error'] = str(error)[:200]
        report['observed_total_wall_ns'] = time.monotonic_ns()-started
        write_json(out/'loopback-cost.json',report)
    print(json.dumps(dict(schema=report['schema'],outcome=report['outcome'],
                         real_proof_transfer_observed=report['real_proof_transfer_observed'],
                         consensus_authority=False)))
    return 0 if report['outcome'] == 'complete' else 1


if __name__ == '__main__':
    raise SystemExit(main())
