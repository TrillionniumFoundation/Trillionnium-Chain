#!/usr/bin/env python3
"""Replay the 36-block native DAA legality vector and all retained W1 proofs.

This verifies transcript bytes, parent/target/timestamp arithmetic and reported
work identities. Node State execution and the system clock are source-bound
observations, not independently authenticated by Python. Hidden search misses
are not retained and this result is not a full mining-cost campaign.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'formal/pon-nakamoto-v1/experiments'))
import w1_parent_reuse_reader as p
import w1_native_daa_resource_v2 as m
from read_w1_cost_research import exact, require, uint64
from w1_lossless_raw import bounded_raw_lines

SCHEMA = 'pon-w1-native-daa-resource-v2'

def equal(a, b, label):
    require(json.dumps(a, sort_keys=True, allow_nan=False) == json.dumps(b, sort_keys=True, allow_nan=False), label)

def read(path):
    raw_hash, size, rows = hashlib.sha256(), 0, []
    for line in bounded_raw_lines(path, 16 * 1024 * 1024, 256 * 1024):
        require(line.endswith(b'\n'), 'LINE_TERMINATOR')
        raw_hash.update(line); size += len(line)
        value = json.loads(line, object_pairs_hook=p.unique)
        require(type(value) is dict and value.get('schema') == SCHEMA, 'ROW_SCHEMA')
        rows.append(value)
    require(len(rows) == 72, 'EXACT_VECTOR_ROW_COUNT')
    controls, start, end = rows[0], rows[1], rows[-1]
    equal(controls['kind'], 'native-time-controls', 'TIME_CONTROL')
    exact(controls, ('schema', 'kind', 'controls'), 'TIME_CONTROL_FIELDS')
    c = exact(controls['controls'], 'native_arithmetic_only observed_now median_rejection future_rejection inclusive_future_timestamp rejected_future_timestamp backdated_candidate parent_timestamp'.split(), 'TIME_FIELDS')
    now = uint64(c['observed_now'], 'OBSERVED_NOW', 1200)
    equal(c, dict(native_arithmetic_only=True, observed_now=now, median_rejection='TIME', future_rejection='TIME_DEFERRED',
                  inclusive_future_timestamp=now + 120, rejected_future_timestamp=now + 121, backdated_candidate=12, parent_timestamp=600), 'TIME_CONTROL_BINDING')
    exact(start, 'schema kind source_scope started_at genesis_time genesis network parameters retarget_interval spacing_seconds median_width future_skew_seconds max_attempts_per_block planned_non_genesis_blocks new_valueless_development_namespace production_activation complete_failure_proofs_retained performance_claim'.split(), 'START_FIELDS')
    require(start['kind'] == 'start' and start['source_scope'] == 'bounded-native-rule-legality-not-production-qualification', 'START_SCOPE')
    equal((start['started_at'], start['genesis_time'], start['retarget_interval'], start['spacing_seconds'], start['median_width'], start['future_skew_seconds'], start['planned_non_genesis_blocks'], start['new_valueless_development_namespace'], start['production_activation'], start['complete_failure_proofs_retained'], start['performance_claim']),
          (now, now - 1200, 16, 10, 11, 120, 36, True, False, False, False), 'START_PARAMETERS')
    cap = uint64(start['max_attempts_per_block'], 'SEARCH_CAP', 1, 4096)
    genesis = p.hx(start['genesis'], 32, 'GENESIS')
    network, parameters = (p.hx(start[k], 32, k) for k in ('network', 'parameters'))
    parents = {genesis: m.Parent(0, m.target_limit(), (start['genesis_time'],))}
    names, packets = {}, {}
    ordinal = attempts = total_work = 0
    active, active_work = genesis, 0
    expected_events = [(kind, 'common') for _ in range(30) for kind in ('admitted-block', 'activation')]
    expected_events += [('admitted-block', label) for label in ('tighten', 'unchanged', 'ease') for _ in range(2)]
    expected_events += [('activation', label) for label in ('ease', 'unchanged', 'tighten')]
    require(len(rows[2:-1]) == len(expected_events), 'EVENT_COUNT')
    for row, (kind, label) in zip(rows[2:-1], expected_events):
        equal((row.get('kind'), row.get('label')), (kind, label), 'EVENT_ORDER')
        if kind == 'activation':
            exact(row, ('schema', 'kind', 'label', 'observed_now', 'stats', 'production_activation'), 'ACTIVATION_FIELDS')
            uint64(row['observed_now'], 'ACTIVATION_NOW', now)
            require(row['production_activation'] is False, 'ACTIVATION_AUTHORITY')
            selected = names[label]
            require(parents[selected].extension_work > active_work, 'GREATER_WORK_ACTIVATION')
            active, active_work = selected, parents[selected].extension_work
            stats = row['stats']
            equal((stats['tip'], stats['height'], stats['chainwork_hex'], stats['production_activation']),
                  (active.hex(), parents[active].height, active_work.to_bytes(64, 'big').hex(), False), 'ACTIVATION_READBACK')
            continue
        exact(row, 'schema kind ordinal label block parent height timestamp observed_now target work chainwork_hex native_search_attempts nonce unsuccessful_proof_bytes_retained packet_hex observation performance_claim production_activation'.split(), 'BLOCK_FIELDS')
        ordinal += 1; equal(row['ordinal'], ordinal, 'BLOCK_ORDINAL')
        data = p.hx(row['packet_hex'], 318 + 2 + p.PROOF_BYTES, 'PACKET')
        require(data[318:320] == b'\0\0', 'EMPTY_TRANSACTIONS')
        header, proof = p.header_decode(data[:318]), data[320:]
        require(p.header_encode(header) == data[:318] and header['parent'] in parents, 'HEADER_PARENT')
        require(header['network'] == network and header['parameters'] == parameters and header['miner'] == p.public(3), 'HEADER_CONTEXT')
        parent = parents[header['parent']]
        if label == 'common':
            require(header['parent'] == active and header['height'] == ordinal, 'COMMON_PATH')
            offset = 11 if ordinal == 16 else ordinal
        else:
            height = 31 if label not in names else 32
            expected_parent = names['common'] if height == 31 else names[label]
            require(header['parent'] == expected_parent and header['height'] == height, 'SIBLING_PATH')
            offset = dict(tighten=31, unchanged=161, ease=611)[label] if height == 31 else 32
        require(header['timestamp'] == start['genesis_time'] + offset, 'REGISTERED_TIMESTAMP')
        observed = uint64(row['observed_now'], 'BLOCK_NOW', now)
        child = m.append_header_rule(parent, header['timestamp'], observed)
        target = int.from_bytes(header['target'], 'big')
        require(target == child.target, 'ORIGINAL_DAA_TARGET')
        challenge = p.H('challenge', data[:318])
        ticket, _ = p.work_oracle.verify(challenge, header['work_task'], header['target'], proof)
        block = p.H('block', data[:318], proof[-32:])
        require(block not in parents, 'DUPLICATE_NATIVE_IDENTITY')
        weight = m.work(target)
        count = header['nonce'] + 1
        require(count <= cap, 'SEARCH_CAP_EXCEEDED')
        equal(tuple(row[k] for k in ('block', 'parent', 'height', 'timestamp', 'target', 'work', 'chainwork_hex', 'native_search_attempts', 'nonce', 'unsuccessful_proof_bytes_retained', 'performance_claim', 'production_activation')),
              (block.hex(), header['parent'].hex(), child.height, header['timestamp'], header['target'].hex(), weight, child.extension_work.to_bytes(64, 'big').hex(), count, header['nonce'], False, False, False), 'BLOCK_BINDING')
        observation = row['observation']
        require(observation['stored_exact'] is True and observation['block_chainwork_hex'] == row['chainwork_hex'], 'NATIVE_STORAGE_OBSERVATION')
        parents[block] = child; names[label] = block; packets[block] = data
        attempts += count; total_work += weight
        require(ticket <= header['target'], 'WINNING_PROOF')
    exact(end, 'schema kind admitted_non_genesis_blocks native_search_attempts common_chainwork forest_work active_chainwork branch_work32 branch_chainwork32 replay_changed_state weaker_branch_replaced_tip retained_packet_count stats node_admission_and_activation_executed native_clock_parameter_relaxed proof_cost_campaign common_prefix_established O03_closed production_activation'.split(), 'END_FIELDS')
    equal({k: end[k] for k in ('kind', 'admitted_non_genesis_blocks', 'native_search_attempts', 'common_chainwork', 'forest_work', 'active_chainwork', 'branch_work32', 'branch_chainwork32', 'replay_changed_state', 'weaker_branch_replaced_tip', 'retained_packet_count', 'node_admission_and_activation_executed', 'native_clock_parameter_relaxed', 'proof_cost_campaign', 'common_prefix_established', 'O03_closed', 'production_activation')},
          dict(kind='complete', admitted_non_genesis_blocks=36, native_search_attempts=attempts, common_chainwork=135, forest_work=196, active_chainwork=173,
               branch_work32=dict(tighten=31, unchanged=7, ease=2), branch_chainwork32=dict(tighten=173, unchanged=149, ease=144),
               replay_changed_state=False, weaker_branch_replaced_tip=False, retained_packet_count=36, node_admission_and_activation_executed=True,
               native_clock_parameter_relaxed=False, proof_cost_campaign=False, common_prefix_established=False, O03_closed=False, production_activation=False), 'END_BINDING')
    require(total_work == 196 and active_work == 173 and active == names['tighten'], 'FOREST_NOT_ADDITIVE_BRANCH')
    equal((end['stats']['tip'], end['stats']['chainwork_hex'], end['stats']['height']), (active.hex(), (173).to_bytes(64, 'big').hex(), 32), 'FINAL_NATIVE_STATE')
    return dict(schema='pon-w1-native-daa-resource-readback-v2', raw_sha256=raw_hash.hexdigest(), raw_bytes=size, original_rows=len(rows),
                full_proofs_replayed=36, native_search_attempts=attempts, hidden_miss_proofs_not_retained=attempts - 36,
                total_forest_work=total_work, greatest_branch_work=active_work, branch_work32=end['branch_work32'],
                original_node_execution_is_source_bound_observation=True, native_execution_attested_by_reader=False,
                independent_clock_attestation=False, physical_cost_bound=False, common_prefix_established=False, O03_closed=False)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--raw', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = read(args.raw)
    with args.out.open('x') as out:
        json.dump(result, out, indent=2, sort_keys=True); out.write('\n')
    print(json.dumps(result))
