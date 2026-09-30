#!/usr/bin/env python3
"""Verify source-bound engineering observations; never confer public-network authority."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import re
import sqlite3
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
FLAGS = ('public_network_ready', 'production_activation', 'independent_accepted',
         'future_window_accepted', 'work_profile_qualified', 'physical_power_loss')
CASES = (('hot', 'legacy'), ('hot', 'protected'), ('disjoint4', 'protected'), ('growth', 'protected'))
TESTS = ('test_model_attribution', 'test_work_utility', 'test_public_evaluation_lifecycle', 'test_llm_adapter_contract')
SOCKET_RUN = 'transport-sustained-paid-unpaid'
NEGATIVE_RUN = 'public-readiness-evidence-negative-tests'
SOURCE_NEGATIVE_RUN = 'evidence-source-negative-tests'
SOURCE_PREPARATION_RUN = 'evidence-source-preparation'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def load(path):
    def constant(value):
        raise ValueError('noncanonical JSON constant '+value)
    return json.loads(path.read_text(), object_pairs_hook=unique, parse_constant=constant)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def integer(value, minimum=0, maximum=None):
    require(type(value) is int and value >= minimum and (maximum is None or value <= maximum), 'invalid integer')
    return value


def digest(value, length=64):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{'+str(length)+'}', value), 'digest shape')
    return value


def scope_flags(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FLAGS:
                require(item is False, 'artifact unsupported authority '+key)
            scope_flags(item)
    elif isinstance(value, list):
        for item in value: scope_flags(item)


def safe(folder, relative):
    """No symlink component, normalization alias, traversal or implicit file substitution."""
    require(isinstance(relative, str) and relative and all(c not in relative for c in ('\\','\x00','\n','\r','\t')), 'unsafe artifact path')
    item = Path(relative)
    require(not item.is_absolute() and item.as_posix() == relative and all(p not in ('.', '..') for p in item.parts), 'unsafe artifact path')
    path = Path(folder)
    require(all(not ancestor.is_symlink() for ancestor in (path,*path.parents)), 'symlink evidence root/ancestor')
    for part in item.parts:
        path = path / part
        require(not path.is_symlink(), 'symlink artifact')
    require(path.is_file(), 'missing artifact '+relative)
    return path


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root, text=True).strip()


def relevant(path):
    return ((path.startswith(('trillionnium/', 'formal/pon-nakamoto-v1/', 'scripts/'))
             and not path.endswith('.md')) or path.startswith(('config/pon/', '.github/workflows/')))


def source_inventory(root, commit):
    inventory = {}
    for row in git(root, 'ls-tree', '-r', commit).splitlines():
        metadata, path = row.split('\t', 1)
        if relevant(path):
            mode, kind, oid = metadata.split()
            require(mode in ('100644', '100755') and kind == 'blob', 'source symlink or non-file')
            raw = subprocess.check_output(['git', 'cat-file', 'blob', oid], cwd=root)
            inventory[path] = sha(raw)
    return inventory


def validate_source(root, report, manifest, *, current=True):
    commit, tree = digest(report['source_commit'], 40), digest(report['source_tree'], 40)
    require(commit == manifest['implementation_commit'] and tree == manifest['implementation_tree'], 'source identity')
    require(git(root, 'rev-parse', commit+'^{tree}') == tree, 'source tree')
    expected = source_inventory(root, commit)
    require(report['source_files_sha256'] == expected and expected, 'source inventory/hash mismatch')
    if current:
        paths = set(git(root, 'ls-files').splitlines()) | set(git(root, 'ls-files', '--others', '--exclude-standard').splitlines())
        require({p for p in paths if relevant(p)} == set(expected), 'current source inventory changed')
        for name, fingerprint in expected.items():
            require(sha(safe(root, name).read_bytes()) == fingerprint, 'current source bytes changed '+name)
    return commit


def validate_artifacts(root, folder, manifest, *, tracked=True):
    files = manifest['files']
    require(isinstance(files, dict) and 'qualification.json' in files, 'artifact inventory')
    observed = set()
    for path in folder.rglob('*'):
        require(not path.is_symlink(), 'symlink artifact')
        if path.is_file() and path != folder/'manifest.json':
            observed.add(path.relative_to(folder).as_posix())
    require(set(files) == observed, 'artifact inventory mismatch')
    for name, fingerprint in files.items():
        require(sha(safe(folder, name).read_bytes()) == digest(fingerprint), 'artifact bytes changed '+name)
        if name.endswith('.json'):
            scope_flags(load(safe(folder,name)))
    if tracked and folder.is_relative_to(root):
        index = set(git(root, 'ls-files').splitlines())
        prefix = folder.relative_to(root)
        required = {(prefix/'manifest.json').as_posix()} | {(prefix/p).as_posix() for p in files}
        require(required <= index, 'untracked published evidence')


def quantiles(values):
    ordered = sorted(values)
    def rank(percent):
        return ordered[max(0, math.ceil(len(ordered)*percent/100)-1)]
    return {'count':len(ordered), 'p50_ns':rank(50) if ordered else None,
            'p95_ns':rank(95) if len(ordered) >= 20 else None,
            'p99_ns':rank(99) if len(ordered) >= 100 else None,
            'tail_rule':'empirical block sample quantiles only;20 samples for p95 resolution,100 for p99; correlation and confidence are not established'}


def validate_tails(summary):
    records = summary['records'][:integer(summary['requested_blocks'], 20, 4096)]
    for field, metric in [('intake_to_inclusion_ns','inclusion_latency_block_samples'),
                          ('intake_to_confirmation_ns','confirmation_latency_block_samples')]:
        values = [integer(row[field], 1) for row in records]
        require(summary[metric] == quantiles(values), 'unobserved/miscomputed latency tails')


def decode_packet(raw):
    require(len(raw) >= 318+2+49188 and len(raw) <= 1048576, 'packet length')
    require(raw[:6] == b'PNH1\x01\x00', 'header version')
    count = int.from_bytes(raw[318:320], 'little')
    require(count <= 256, 'packet transaction limit')
    pos, txs = 320, []
    for _ in range(count):
        require(pos+2 <= len(raw), 'transaction framing')
        size = int.from_bytes(raw[pos:pos+2], 'little'); pos += 2
        require(159 <= size <= 2048 and pos+size <= len(raw), 'transaction framing')
        txs.append(raw[pos:pos+size]); pos += size
    require(len(raw)-pos == 49188, 'work length/trailing bytes')
    return raw[:318], txs, raw[pos:]


def validate_durable_store(root, folder, summary, packets, roots, cumulative, state, canonical, H):
    source = safe(root,'trillionnium/crates/trnm-pon-node/src/store.rs').read_text()
    ddl = re.search(r'const DDL:&str="(.*?)";',source,re.S)
    require(ddl is not None, 'durable schema source')
    ddl = ddl[1]
    schema_names = set(re.findall(r'CREATE (?:TABLE|INDEX) (\w+)',ddl))
    expected_sql = {match[1]:' '.join(match[0][:-1].split())
                    for match in re.finditer(r'CREATE (?:TABLE|INDEX) (\w+).*?;',ddl,re.S)}
    actual_ledger_bytes = sum(path.stat().st_size for owner in ('producer','validator')
                              for path in (folder/owner).rglob('*') if path.is_file())
    require(integer(summary['ledger_disk_bytes'],1) == actual_ledger_bytes, 'actual ledger disk denominator')
    for owner in ('producer','validator'):
        path = safe(folder,owner+'/native.sqlite')
        require(not path.with_name(path.name+'-wal').exists(), 'uncheckpointed durable evidence')
        with sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True) as database:
            database.execute('PRAGMA trusted_schema=OFF')
            require(database.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'durable SQLite integrity')
            schema = dict(database.execute("SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
            require(set(schema) == schema_names and {name:' '.join(sql.split()) for name,sql in schema.items()} == expected_sql, 'durable schema additions/omissions/changes')
            metadata = dict(database.execute('SELECT key,value FROM metadata'))
            require(metadata == {'schema':H('native-branch-schema-v1',ddl.encode()),
                                  'parameters':bytes.fromhex(summary['parameters']),
                                  'genesis':bytes.fromhex(summary['genesis'])}, 'durable metadata/context')
            tip,generation,slot = database.execute('SELECT tip,generation,state_slot FROM active WHERE singleton=1').fetchone()
            require(tip.hex() == summary['producer_final_state']['tip'] and generation == len(packets) and slot in (0,1), 'durable active state')
            values = {key:json.loads(bytes(raw),object_pairs_hook=unique) for key,raw in database.execute('SELECT key,value FROM kv WHERE slot=?',(slot,))}
            require(canonical(values) == canonical(state), 'durable published state differs from replay')
            require(database.execute('SELECT count(*) FROM blocks').fetchone()[0] == len(packets)+1, 'durable block denominator')
            rows = list(database.execute('SELECT id,parent,height,chainwork,packet,state_root FROM blocks ORDER BY height'))
            genesis = rows[0]
            require(genesis == (bytes.fromhex(summary['genesis']),None,0,bytes(64),None,roots[0]), 'durable genesis state')
            for index,(actual,raw) in enumerate(zip(rows[1:],packets),1):
                block,parent,height,work,packet,root = actual
                previous = bytes.fromhex(summary['genesis']) if index == 1 else rows[index-1][0]
                require(block.hex() == summary['records'][index-1]['block'] and parent == previous
                        and height == index and work == cumulative[index].to_bytes(64,'big')
                        and packet == raw and root == roots[index], 'durable packet/state/work differs from replay')


def validate_observations(batch, row, tx_ids, summary, headers, cumulative, *, confirmed):
    observations = batch['observations']
    require(isinstance(observations, list) and len(observations) == len(tx_ids), 'confirmation count')
    require([o['transaction'] for o in observations] == tx_ids, 'confirmation membership')
    for fact in observations:
        for key in ('network', 'parameters', 'genesis'):
            require(fact[key] == summary[key], 'confirmation context')
        require(fact['included_block'] == row['block'] and fact['included_height'] == row['height'], 'confirmation inclusion')
        observed = integer(fact['observed_height'], row['height'], len(headers))
        if not confirmed:
            require(observed == row['height'], 'initial membership observation height')
        require(fact['observed_tip'] == headers[observed-1]['id'], 'confirmation observed tip')
        depth = observed-row['height']
        require(fact['depth'] == depth and fact['active_generation'] == observed, 'confirmation depth/generation')
        require(fact['reorged'] is False and fact['finalized'] is False and fact['execution_authority'] is False, 'confirmation authority')
        require(fact['policy'] == 'installed-depth-and-required-work', 'confirmation policy')
        work = cumulative[observed]-cumulative[row['height']]
        threshold = (2**256//(headers[row['height']-1]['target']+1))*6
        require(fact['work_delta'] == work.to_bytes(64,'big').hex()
                and fact['required_work_delta'] == threshold.to_bytes(64,'big').hex(), 'confirmation work')
        expected = depth >= 6 and work >= threshold
        require(fact['confirmed'] is expected and expected is confirmed, 'confirmation truth')
        require(integer(fact['observed_now'], 1)+120 >= headers[observed-1]['timestamp'], 'future observation')


def validate_pipeline(root, folder, pattern, profile, command):
    sys.path.insert(0, str(root/'formal/pon-nakamoto-v1'))
    import contract_wire as wire
    import ledger
    import work_oracle
    from reference import retarget
    summary = load(safe(folder, 'summary.json'))
    require(summary['schema'] == 'trnm-continuous-native-pipeline-v1' and summary['pattern'] == pattern, 'pipeline schema/case')
    require(summary['campaign_passed'] is True and summary['producer_validator_heads_agree'] is True
            and summary['campaign_error'] is None and summary['final_head_error'] is None, 'failed pipeline campaign')
    require(summary['logical_pacing'] is False and summary['admission_profile'] == ('connection-work-v1' if profile == 'protected' else 'legacy-development'), 'live pipeline profile')
    blocks = integer(summary['requested_blocks'], 20, 4096)
    batch = integer(summary['transactions_per_block'], 1, 256)
    pace = integer(summary['pace_ms'], 1000, 60000)
    require(command[-5:] == [str(blocks),str(batch),str(pace),pattern,profile], 'pipeline command parameters')
    require(summary['transaction_type'] == 'signed PNX1 transfer tag1 only', 'pipeline transaction class')
    require(summary['funded_senders'] == (1 if pattern == 'hot' else 4), 'pipeline sender denominator')
    require(summary['accepted_transactions'] == summary['confirmed_transactions'] == blocks*batch and summary['pending_confirmation_blocks'] == 0, 'pipeline actual totals')
    require(summary['gpu_used'] is False and summary['gpu_device'] is None and summary['vram_bytes'] is None and summary['mempool_latency'] is None, 'pipeline unmeasured claim')
    params = wire.development_parameters('closed-round-all-eligible-min-v1')
    genesis_time = integer(summary['genesis_timestamp'], 1)
    params['genesis_timestamp'] = genesis_time
    params['chain_label'] = 'trnm-pon-native-wall-devnet-4-closed-round-all-eligible-min-v1-'+str(genesis_time)
    network = wire.H('network',params['chain_label'].encode())
    parameters = wire.H('parameters',wire.canonical(params),wire.canonical(wire.SCHEMA),wire.canonical(wire.WORK_PROFILE),wire.canonical(wire.MODEL_FAMILY))
    require(summary['network'] == network.hex() and summary['parameters'] == parameters.hex(), 'pipeline parameter/source binding')
    with patch.multiple(wire, PARAMS=params, NETWORK=network, PARAMETER_HASH=parameters), patch.multiple(ledger, PARAMS=params, NETWORK=network, PARAMETER_HASH=parameters):
        state = ledger.genesis_state()
        genesis = wire.H('genesis',network,parameters,wire.state_root(state),wire.u64(genesis_time)).hex()
        require(summary['genesis'] == genesis, 'pipeline genesis')
        records = summary['records']
        require(len(records) == blocks+6, 'pipeline confirmation drain blocks')
        headers, tx_sets, cumulative, parent = [], [], [0], genesis
        packets, roots = [], [wire.state_root(state)]
        history = [{'timestamp':genesis_time,'target':int(params['initial_target_hex'],16)}]
        for index, row in enumerate(records):
            raw = safe(folder, f'block-{index:04}.bin').read_bytes()
            packets.append(raw)
            hb, txs, proof = decode_packet(raw)
            header = wire.header_decode(hb)
            require(header['miner'] == ledger.public(ledger.key(3)), 'pipeline actual miner')
            require(header['parent'].hex() == parent and header['network'] == network and header['parameters'] == parameters and header['height'] == index+1, 'packet parent/context/height')
            require(row['height'] == index+1 and row['packet_bytes'] == len(raw) and row['transaction_count'] == len(txs) == (batch if index < blocks else 0), 'packet/transfer denominator')
            require(header['timestamp'] == row['timestamp'] and header['timestamp'] > history[-1]['timestamp'], 'packet live timestamp')
            target = history[-1]['target']
            if (index+1)%params['retarget_interval'] == 0:
                target = retarget(target,history[-params['retarget_interval']]['timestamp'],history[-1]['timestamp'],params['retarget_interval'],params['target_spacing_seconds'],int(params['pow_limit_hex'],16))
            require(int.from_bytes(header['target'],'big') == target and row['attempts'] == header['nonce']+1 <= 4096, 'packet target/attempts')
            require(header['transactions'] == wire.sequence_root('transactions',txs), 'packet body commitment')
            ids = []
            for offset, tx in enumerate(txs):
                decoded = wire.tx_decode(tx)
                require(decoded['tag'] == 1 and decoded['network'] == network and decoded['fields']['amount'] == 1, 'actual signed transfer')
                sender_index = 0 if pattern == 'hot' else offset%4
                require(decoded['sender'] == ledger.public(ledger.key(sender_index)), 'actual funded sender')
                receiver = wire.H('pipeline-growth-receiver-v1',wire.u64(index),wire.u64(offset)) if pattern == 'growth' else wire.H('pipeline-receiver-v1',wire.u64(sender_index))
                require(decoded['fields']['recipient'] == receiver, 'actual conflict/growth pattern')
                ids.append(wire.H('tx-id',tx).hex())
            work_oracle.verify(wire.H('challenge',hb),header['work_task'],header['target'],proof)
            require(header['work_task'] == ledger.MAINTENANCE, 'pipeline work task')
            state, receipts = ledger.execute_reference(state,txs,index+1,header['miner'],header['parent'])
            roots.append(wire.state_root(state))
            require(header['state'] == wire.state_root(state) and header['receipts'] == wire.sequence_root('receipts',receipts), 'pipeline state/receipt replay')
            require(integer(row['producer_state_keys'],1) == len(state), 'pipeline actual state growth')
            for metric in ('scheduled_lateness_ns','construct_sign_ns','execute_and_mine_ns',
                           'producer_full_verify_and_store_ns','producer_activate_ns',
                           'socket_admission_verify_store_activate_ns','membership_query_ns',
                           'intake_to_inclusion_ns','disk_bytes_before','disk_bytes_after',
                           'ledger_disk_bytes_before','ledger_disk_bytes_after'):
                integer(row[metric])
            require(row['ledger_disk_bytes_before'] <= row['disk_bytes_before']
                    and row['ledger_disk_bytes_after'] <= row['disk_bytes_after'], 'ledger bytes include packet/log artifacts')
            block_id = wire.H('block',hb,proof[-32:]).hex()
            require(row['block'] == block_id, 'actual block identity')
            parent = block_id
            headers.append({'id':block_id,'target':target,'timestamp':header['timestamp']})
            tx_sets.append(ids)
            cumulative.append(cumulative[-1]+2**256//(target+1))
            history.append(headers[-1])
        for row, ids in zip(records[:blocks],tx_sets[:blocks]):
            validate_observations(row['initial_membership'],row,ids,summary,headers,cumulative,confirmed=False)
            validate_observations(row['confirmation'],row,ids,summary,headers,cumulative,confirmed=True)
            require(integer(row['intake_to_confirmation_ns'],1) >= integer(row['intake_to_inclusion_ns'],1), 'confirmation timing')
        final = summary['producer_final_state']
        require(final['tip'] == parent and final['height'] == blocks+6 and final['state_root'] == wire.state_root(state).hex(), 'pipeline final state')
        require(final['chainwork_hex'] == cumulative[-1].to_bytes(64,'big').hex(), 'pipeline final chainwork')
        for field in ('tip','height','state_root','chainwork_hex'):
            require(summary['validator_final_head'][field] == final[field], 'validator/producer divergence')
        validate_durable_store(root,folder,summary,packets,roots,cumulative,state,wire.canonical,wire.H)
    validate_tails(summary)
    seconds = summary['inclusion_window_seconds']
    require(type(seconds) in (int,float) and math.isfinite(seconds) and seconds >= (blocks-1)*pace/1000, 'live pacing denominator')
    require(math.isclose(summary['measured_inclusion_transactions_per_second'],blocks*batch/seconds,rel_tol=1e-12), 'pipeline rate denominator')
    whole = summary['whole_campaign_seconds']
    integer(summary['producer_close_ns'])
    require(type(whole) in (int,float) and math.isfinite(whole) and whole >= seconds, 'pipeline campaign denominator')
    require(math.isclose(summary['whole_campaign_confirmed_transactions_per_second'],blocks*batch/whole,rel_tol=1e-12), 'pipeline confirmed rate denominator')
    return blocks*batch


def validate_socket_log(text):
    rows = []
    for line in text.splitlines():
        start = line.find('{')
        if start >= 0:
            value = json.loads(line[start:], object_pairs_hook=unique)
            if value.get('schema') == 'transport-admission-sustained-cost-v2':
                rows.append(value)
    require([r['phase'] for r in rows] == ['baseline','unpaid_false_transcript','paid_false_transcript','slow_hello_occupancy'], 'socket phase coverage')
    require(re.search(r'\btest sustained_protected_socket_cost_campaign \.\.\.',text)
            and re.search(r'test result: ok\. 1 passed; 0 failed;',text)
            and 'panicked at' not in text and 'test result: FAILED' not in text, 'socket actual test outcome')
    for row in rows:
        for field in ['attack_connections','paid_full_work_rejections','cheap_rejections','busy_rejections',
                      'slow_preface_connections','slow_partial_hello_connections','slow_body_hello_connections',
                      'request_template_bytes','attacker_body_bytes_successfully_written',
                      'attacker_body_write_success_count','attacker_body_write_outcome_unknown_count',
                      'attacker_body_not_started_count','attack_transport_error_count','forged_ticket_hash_trials',
                      'admission_hash_trials','attacker_admission_solve_ns']:
            integer(row[field])
        # The harness records the serialized first-request template size in every
        # phase, including baseline; this is not total attacker-submitted bytes.
        require('submitted_wire_bytes' not in row
                and integer(row['request_template_bytes'],1) == rows[0]['request_template_bytes'], 'socket request template size')
        require(row['bits'] == 16 and row['ttl_ms'] == 2000 and row['requested_attack_duration_ns'] == 10_000_000_000, 'socket cost context')
        integer(row['observed_wall_ns'],1)
        require(row['attack_connections'] == row['paid_full_work_rejections']+row['cheap_rejections']+row['busy_rejections']+row['slow_preface_connections']+row['attack_transport_error_count'], 'socket attack denominator')
        require(row['slow_preface_connections'] == row['slow_partial_hello_connections']+row['slow_body_hello_connections'], 'slow initial/body occupancy denominator')
        require(len(row['attack_transport_errors']) == row['attack_transport_error_count']
                and all(isinstance(error,str) and error for error in row['attack_transport_errors']), 'socket transport failure denominator')
        for prefix in ('honest_submit','honest_head'):
            attempts = integer(row[prefix+'_attempts'],1)
            samples, errors = row[prefix+'_ns'], row[prefix+'_errors']
            require(attempts == len(samples)+len(errors), 'honest outcome denominator')
            for sample in samples: integer(sample,1)
            for error in errors:
                integer(error['elapsed_ns'],1); require(isinstance(error['error'],str) and error['error'], 'honest error outcome')
        require(row['honest_valid_blocks'] == len(row['honest_submit_ns']), 'honest acceptance count')
        metrics = row['metrics']
        for value in metrics.values(): integer(value)
        require(row['paid_full_work_rejections']+row['honest_valid_blocks'] <= metrics['work_verifications'] <= row['paid_full_work_rejections']+row['honest_submit_attempts'], 'socket verifier denominator')
        require(metrics['admission_rejected_before_work'] == row['cheap_rejections'] and metrics['admission_accepted'] >= row['paid_full_work_rejections']+row['busy_rejections']+row['honest_valid_blocks'], 'socket cost accounting')
        baseline = row['phase'] == 'baseline'
        slow = row['phase'] == 'slow_hello_occupancy'
        body_fields = ('attacker_body_bytes_successfully_written','attacker_body_write_success_count',
                       'attacker_body_write_outcome_unknown_count','attacker_body_not_started_count')
        if baseline or slow:
            require(all(row[field] == 0 for field in body_fields), 'unexpected attacker body write')
        else:
            # A failed opaque write helper can fail before or during the body.
            # It contributes an unknown outcome, never invented partial bytes.
            success, unknown, not_started = (row[field] for field in body_fields[1:])
            require(success+unknown+not_started == row['attack_connections'], 'attacker body outcome denominator')
            require(row['attacker_body_bytes_successfully_written'] == success*row['request_template_bytes'], 'attacker body byte denominator')
            require(success >= row['paid_full_work_rejections']+row['cheap_rejections']+row['busy_rejections']
                    and unknown+not_started <= row['attack_transport_error_count'], 'attacker body outcome accounting')
        if not slow:
            require(row['slow_preface_connections'] == row['slow_partial_hello_connections']
                    == row['slow_body_hello_connections'] == 0, 'unexpected slow-Hello phase')
        require(row['attacker_streams'] == (0 if baseline else (3 if slow else 2)) and len(row['attacker_observed_ns']) == row['attacker_streams'], 'attacker identity denominator')
        for elapsed in row['attacker_observed_ns']: integer(elapsed,9_000_000_000)
        if baseline:
            require(all(row[field] == 0 for field in
                ('attack_connections','paid_full_work_rejections','cheap_rejections','busy_rejections',
                 'slow_preface_connections','slow_partial_hello_connections','slow_body_hello_connections',
                 'attack_transport_error_count','forged_ticket_hash_trials','admission_hash_trials',
                 'attacker_admission_solve_ns')), 'baseline attack contamination')
        elif row['phase'] == 'unpaid_false_transcript':
            require(row['attack_connections'] > 0 and row['paid_full_work_rejections'] == row['admission_hash_trials'] == row['attacker_admission_solve_ns'] == 0, 'unpaid work reached verifier')
        elif slow:
            require(row['slow_partial_hello_connections'] > 0 and row['slow_body_hello_connections'] > 0
                and row['request_template_bytes'] > 0 and all(row[field] == 0 for field in
                ('forged_ticket_hash_trials','admission_hash_trials','attacker_admission_solve_ns','paid_full_work_rejections','cheap_rejections','busy_rejections')), 'slow-preface cost/outcome class')
        else:
            require(row['paid_full_work_rejections'] > 0 and row['admission_hash_trials'] >= row['paid_full_work_rejections']+row['busy_rejections'] and row['attacker_admission_solve_ns'] > 0, 'paid attack cost absent')
    return rows


def validate_attribution(root, folder, command, commit):
    sys.path.insert(0,str(root/'formal/pon-nakamoto-v1'))
    from contract_wire import H, canonical
    from evaluation_bundle import artifact_id, verify_bundle
    from model_attribution import verify_attribution_result
    report = load(safe(folder,'report.json'))
    require(report['schema'] == 'pon-bounded-model-attribution-campaign-v1'
            and report['source_commit'] == commit and report['source_clean'] is True, 'attribution source')
    for flag in ('prospective_accepted','independent_accepted','ordinary_hepta_entry','llm_runtime_executed','public_reward_eligible'):
        require(report[flag] is False, 'attribution authority '+flag)
    require(command[0].endswith('python3') and command[1] == 'formal/pon-nakamoto-v1/experiments/model_attribution_campaign.py', 'attribution invocation')
    require(command[command.index('--bundle-hash')+1] == report['bundle'], 'attribution owner bundle')
    inputs = root/'evidence/pon-native-node-v1/model-current/model'
    for name,fingerprint in report['input_files_sha256'].items():
        require(name in {'evaluation-bundle.json','train.json','evaluation_a.json','evaluation_b.json'}, 'attribution input inventory')
        raw = safe(inputs,name).read_bytes()
        original = subprocess.check_output(['git','show',commit+':'+(inputs.relative_to(root)/name).as_posix()],cwd=root)
        require(raw == original and sha(raw) == digest(fingerprint), 'attribution actual input bytes')
    require(set(report['input_files_sha256']) == {'evaluation-bundle.json','train.json','evaluation_a.json','evaluation_b.json'}, 'attribution complete inputs')
    for name,fingerprint in report['source_files_sha256'].items():
        require(relevant(name) and sha(safe(root,name).read_bytes()) == digest(fingerprint), 'attribution source bytes')
    bundle = verify_bundle(safe(inputs,'evaluation-bundle.json').read_bytes(),report['bundle'])
    parent = bundle['controls']['current']
    cases = [('evaluation_a','evaluation_a','evaluation_a'),('evaluation_b','evaluation_b','evaluation_b'),
             ('evaluation_b_repeated_A_content','evaluation_a','evaluation_a'),('stale_retry_A','evaluation_a','evaluation_a'),
             ('reexecuted_A','evaluation_a','evaluation_a')]
    for result_name,plan_name,partition in cases:
        raw = safe(folder,plan_name+'-plan.json').read_bytes()
        verify_attribution_result(raw,H('bounded-model-attribution-plan-v1',raw).hex(),
            load(safe(inputs,partition+'.json')),load(safe(folder,result_name+'-result.json')),
            expected_parent=artifact_id(parent),expected_bundle=report['bundle'])
    synthetic = copy.deepcopy(parent)
    synthetic['source'] = 'controlled-complementarity-attack-fixture'
    synthetic['base'] = [[0]*257 for _ in range(3)]; synthetic['base'][0][-1] = 1
    synthetic['router'] = [[0]*257 for _ in range(3)]
    synthetic['deltas'] = [[[0]*257 for _ in range(3)] for _ in range(3)]
    identity = lambda value: H('attribution-campaign-identity-v1',value.encode()).hex()
    tasks = [dict(id=identity('controlled-task-'+str(i)),file='controlled-attack/'+str(i)+'.rs',label=1,
                  source_content_sha256=identity('controlled-content-'+str(i)),x=[1,1]+[0]*254+[8]) for i in range(24)]
    raw = safe(folder,'complementarity-plan.json').read_bytes()
    require(canonical(load(safe(folder,'controlled_complementarity-consumer-tasks.json'))) == canonical(tasks), 'synthetic attack tasks')
    verified = verify_attribution_result(raw,H('bounded-model-attribution-plan-v1',raw).hex(),tasks,
        load(safe(folder,'controlled_complementarity-result.json')),
        expected_parent=artifact_id(synthetic),expected_bundle=identity('controlled-attack-bundle'))
    require(report['controlled_complementarity'] == load(folder/'controlled_complementarity-result.json')['complementarity'], 'controlled attack outcome')
    return verified


def validate(root=ROOT, evidence=None, *, tracked=True):
    root = Path(root).resolve()
    folder = Path(evidence or root/'evidence/pon-public-readiness-v1').absolute()
    require(not folder.is_symlink(), 'symlink evidence root')
    manifest = load(safe(folder,'manifest.json'))
    require(manifest['schema'] == 'trnm-public-readiness-evidence-v1', 'manifest schema')
    validate_artifacts(root,folder,manifest,tracked=tracked)
    report = load(safe(folder,'qualification.json'))
    require(report['schema'] == 'trnm-public-readiness-engineering-v1', 'qualification schema')
    for value in (manifest,report):
        require(value['source_clean'] is True and value['all_commands_passed'] is True, 'failed/dirty engineering run')
        for flag in FLAGS: require(value[flag] is False, 'unsupported authority '+flag)
    require(report['source_clean_after'] is True and 'error' not in report, 'incomplete run')
    commit = validate_source(root,report,manifest)
    records = report['results']
    required = {'full-native-reference-regression','pipeline-build','bounded-model-attribution',SOCKET_RUN,NEGATIVE_RUN,SOURCE_NEGATIVE_RUN,SOURCE_PREPARATION_RUN,*TESTS} | {'pipeline-'+p+'-'+a for p,a in CASES}
    require(len(records) == len(required) and {r['name'] for r in records} == required, 'command matrix')
    by_name = {r['name']:r for r in records}
    for row in records:
        require(type(row['returncode']) is int and row['returncode'] == 0 and row['timed_out'] is False, 'failed command')
        integer(row['elapsed_ns'],1)
        require(row['vram_bytes'] is None and row['log'] in manifest['files'] and isinstance(row['command'],list) and row['command'], 'command evidence')
        if row['peak_rss_kib'] is not None: integer(row['peak_rss_kib'],1)
        text = safe(folder,row['log']).read_text()
        if row['name'] in TESTS:
            require(row['command'][0].endswith('python3') and row['command'][1:] == ['formal/pon-nakamoto-v1/'+row['name']+'.py'], 'Python invocation')
            require(re.search(r'(?m)^Ran [1-9]\d* tests?\b',text) and re.search(r'(?m)^OK\s*$',text), 'Python actual outcome')
        if row['name'] in (NEGATIVE_RUN,SOURCE_NEGATIVE_RUN):
            target = 'scripts/ci/test_public_readiness_evidence.py' if row['name'] == NEGATIVE_RUN else 'scripts/ci/test_evidence_sources.py'
            require(row['command'][0].endswith('python3') and row['command'][1:] == [target], 'negative-test invocation')
            require(re.search(r'(?m)^Ran [1-9]\d* tests?\b',text) and re.search(r'(?m)^OK\s*$',text), 'negative-test actual outcome')
        if row['name'] == SOURCE_PREPARATION_RUN:
            require(row['command'][0].endswith('python3') and row['command'][1:] == ['scripts/ci/prepare_evidence_sources.py'], 'source-preparation invocation')
            prepared = json.loads(text.splitlines()[-1],object_pairs_hook=unique)
            from prepare_evidence_sources import declarations
            require(prepared['verified_object_trees'] == declarations(root)
                    and prepared['branch_refs_changed'] is False
                    and prepared['acceptance_granted'] is False, 'source-preparation scope')
    baseline_command = by_name['full-native-reference-regression']['command']
    require(baseline_command[0].endswith('python3') and baseline_command[1] == 'scripts/run_evaluation_qualification.py' and '--native-node' in baseline_command and baseline_command[baseline_command.index('--source')+1] == commit, 'baseline command/source')
    from check_client_confirmation_evidence import validate as baseline_validate
    baseline = baseline_validate(root=root,evidence=folder/'baseline')
    require(baseline['measured_commit'] == commit and baseline['runtime_matches'] is True and baseline['native_development_entry'] is True, 'baseline execution scope')
    build = by_name['pipeline-build']['command']
    require(build == ['cargo','build','--offline','--locked','--release','--manifest-path','trillionnium/Cargo.toml','-p','trnm-pon-node','--examples','--bins'], 'pipeline actual build')
    digest(report['pipeline_binary_sha256'])
    transfers = 0
    for pattern, profile in CASES:
        name = 'pipeline-'+pattern+'-'+profile
        command = by_name[name]['command']
        require(len(command) == 7 and Path(command[0]).name == 'continuous_pipeline' and Path(command[1]).name == name, 'pipeline invocation')
        transfers += validate_pipeline(root,folder/name,pattern,profile,command)
        output = json.loads(safe(folder,by_name[name]['log']).read_text().splitlines()[-1],object_pairs_hook=unique)
        summary = load(folder/name/'summary.json')
        require(output['accepted_transactions'] == output['confirmed_transactions'] == summary['accepted_transactions'] and output['public_qualified'] is False, 'pipeline execution output')
    socket = by_name[SOCKET_RUN]
    require(socket['command'] == ['cargo','test','--offline','--locked','--release','--manifest-path','trillionnium/Cargo.toml',
            '-p','trnm-pon-node','--test','protected_ingress','sustained_protected_socket_cost_campaign',
            '--','--exact','--ignored','--nocapture','--test-threads=1'], 'socket exact invocation')
    validate_socket_log(safe(folder,socket['log']).read_text())
    validate_attribution(root,folder/'attribution',by_name['bounded-model-attribution']['command'],commit)
    require(report['environment']['cargo_jobs'] == 2 and report['environment']['test_threads'] == 1 and report['environment']['gpu_used'] is False and report['environment']['vram_bytes'] is None, 'environment scope')
    return {'measured_commit':commit,'current_source_qualified_by_this_check':True,'runtime_matches':True,
            'engineering_observations_verified':True,'pipeline_cases':4,'actual_confirmed_transfers':transfers,
            **{flag:False for flag in FLAGS}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT)
    parser.add_argument('--evidence',type=Path)
    parser.add_argument('--historical',action='store_true')
    args = parser.parse_args()
    folder = args.evidence or args.root/'evidence/pon-public-readiness-v1'
    if args.historical:
        from historical_evidence import measured_checkout
        validate_artifacts(args.root.resolve(),folder.absolute(),load(safe(folder,'manifest.json')))
        with measured_checkout(args.root,folder) as source:
            child = subprocess.run([sys.executable,__file__,'--root',str(source),'--evidence',str(folder.absolute())],check=True,capture_output=True,text=True)
            original = json.loads(child.stdout.splitlines()[-1])
        result = dict(original,current_source_qualified_by_this_check=False,runtime_matches=False,historical_semantics_verified=True)
    else:
        result = validate(args.root,folder)
    print(json.dumps(result,sort_keys=True))
