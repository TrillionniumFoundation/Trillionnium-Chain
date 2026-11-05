"""Durable, strictly replayed diagnostics for a complete reference Cell search.

This records legal W1 proof search, including misses and unknown outcomes. It
does not authenticate clocks, establish a cheapest implementation, measure
invalid-input rejection or authorize work. Hash chaining detects alterations
relative to a retained endpoint; it is not external rollback custody.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct

from contract_wire import H, canonical, u64, unique
import work_oracle as work

SCHEMA = 'useful-cell-reference-search-journal-v1'
MAX_BYTES = 64 * 1024 * 1024
MAX_LINE = 16384
ZERO = '00' * 32


def require(ok, code):
    if not ok:
        raise ValueError(code)


def integer(value, code, maximum=(1 << 64) - 1):
    require(type(value) is int and 0 <= value <= maximum, code)
    return value


def hex32(value):
    require(type(value) is str and len(value) == 64 and
            all(c in '0123456789abcdef' for c in value), 'SEARCH_HEX')
    return bytes.fromhex(value)


def reject_number(_):
    raise ValueError('SEARCH_NONINTEGER_JSON')


def validate_plan(plan):
    require(type(plan) is dict and set(plan) == {
        'schema', 'kind', 'relation', 'contract_id', 'before_state_sha256', 'target',
        'batch_size', 'max_attempts_per_tile', 'tiles'}, 'SEARCH_PLAN_FIELDS')
    require(plan['schema'] == 'useful-cell-reference-search-plan-v1' and
            plan['kind'] == 'plan' and plan['relation'] == 'pon-useful-cell-int257-v1',
            'SEARCH_RELATION')
    for field in ('contract_id', 'before_state_sha256', 'target'):
        hex32(plan[field])
    require(plan['target'] != ZERO, 'SEARCH_ZERO_TARGET')
    require(1 <= integer(plan['batch_size'], 'SEARCH_BATCH', 64), 'SEARCH_BATCH')
    require(1 <= integer(plan['max_attempts_per_tile'], 'SEARCH_LIMIT', 4096), 'SEARCH_LIMIT')
    require(type(plan['tiles']) is list and len(plan['tiles']) == 5, 'SEARCH_TILE_DENOMINATOR')
    for index, tile in enumerate(plan['tiles']):
        require(type(tile) is dict and set(tile) == {'index', 'task', 'material_sha256'} and
                type(tile['index']) is int and tile['index'] == index, 'SEARCH_TILE_ORDER')
        hex32(tile['task'])
        hex32(tile['material_sha256'])


class AttemptJournal:
    """Create a new file and durably append before returning from each sink call.

    A write, flush or fsync failure poisons the sink and propagates to proving.
    The start record is durable before arithmetic begins. A crash can therefore
    leave an explicit unknown attempt; it cannot turn it into an unspent nonce.
    """

    def __init__(self, path):
        self.path = Path(path)
        self.file = self.path.open('xb')
        self.sequence = 0
        self.head = ZERO
        self.size = 0
        self.poisoned = False
        try:
            self.file.flush()
            os.fsync(self.file.fileno())
            directory = os.open(self.path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            self.poisoned = True
            self.file.close()
            raise

    def append(self, event):
        require(not self.poisoned and not self.file.closed, 'SEARCH_SINK_UNAVAILABLE')
        try:
            body = {'schema': SCHEMA, 'sequence': self.sequence,
                    'previous_sha256': self.head, 'event': event}
            body_raw = canonical(body)
            digest = H(SCHEMA, body_raw).hex()
            raw = canonical(dict(body, entry_sha256=digest)) + b'\n'
            require(len(raw) <= MAX_LINE and self.size + len(raw) <= MAX_BYTES,
                    'SEARCH_JOURNAL_LIMIT')
            require(self.file.write(raw) == len(raw), 'SEARCH_SHORT_WRITE')
            self.file.flush()
            os.fsync(self.file.fileno())
            self.sequence += 1
            self.size += len(raw)
            self.head = digest
        except BaseException:
            self.poisoned = True
            raise

    def close(self):
        self.file.close()

    def acknowledgement(self):
        """Last prefix for which write, flush and fsync actually returned."""
        return {'schema': SCHEMA + '/acknowledgement', 'bytes': self.size,
                'entries': self.sequence, 'head': self.head, 'sink_failed': self.poisoned}

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def decode_prefix(raw):
    """Keep a crash tail visible; a partial last line never produces success."""
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, 'SEARCH_JOURNAL_SIZE')
    boundary = raw.rfind(b'\n') + 1
    complete, tail = raw[:boundary], raw[boundary:]
    require(len(tail) <= MAX_LINE, 'SEARCH_LINE_SIZE')
    previous, events = ZERO, []
    for sequence, line in enumerate(complete.splitlines()):
        require(0 < len(line) <= MAX_LINE, 'SEARCH_LINE_SIZE')
        entry = json.loads(line, object_pairs_hook=unique, parse_float=reject_number,
                           parse_constant=reject_number)
        require(type(entry) is dict and set(entry) == {
            'schema', 'sequence', 'previous_sha256', 'event', 'entry_sha256'}, 'SEARCH_ENTRY_FIELDS')
        require(canonical(entry) == line and entry['schema'] == SCHEMA and
                type(entry['sequence']) is int and entry['sequence'] == sequence and
                entry['previous_sha256'] == previous, 'SEARCH_SEQUENCE')
        claimed = entry.pop('entry_sha256')
        require(hex32(claimed).hex() == H(SCHEMA, canonical(entry)).hex(), 'SEARCH_ENTRY_HASH')
        previous = claimed
        require(type(entry['event']) is dict, 'SEARCH_EVENT')
        events.append(entry['event'])
    return events, previous, tail


def inspect_journal(raw, *, expected_plan, materials=None, expected_final_sha256=None):
    """Reconstruct every denominator from a separately retained complete plan.

    If materials are supplied, rerun every completed W1 calculation, including
    misses, from those bytes. Without them the result is explicitly only a
    structural record check. Caller-supplied plan/materials alone are not a
    complete Cell relation check; the driver also invokes the actual verifier.
    """
    validate_plan(expected_plan)
    plan = json.loads(canonical(expected_plan))
    events, head, tail = decode_prefix(raw)
    if expected_final_sha256 is not None:
        require(head == hex32(expected_final_sha256).hex() and not tail, 'SEARCH_RETAINED_ENDPOINT')
    if events:
        require(canonical(events[0]) == canonical(plan), 'SEARCH_EXPECTED_PLAN')
    words = {}
    if materials is not None:
        require(type(materials) is dict and set(materials) == set(range(5)), 'SEARCH_MATERIAL_SET')
        for tile in plan['tiles']:
            material = materials[tile['index']]
            require(type(material) is bytes and len(material) == 2 * work.CELLS * 4 and
                    hashlib.sha256(material).hexdigest() == tile['material_sha256'], 'SEARCH_MATERIAL_BYTES')
            values = struct.unpack('<' + 'I' * (2 * work.CELLS), material)
            a, b = list(values[:work.CELLS]), list(values[work.CELLS:])
            require(work.task_id(a, b).hex() == tile['task'], 'SEARCH_MATERIAL_TASK')
            words[tile['index']] = (a, b)
    tiles = [{'index': i, 'status': 'not-run', 'started_attempts': 0,
              'completed_attempts': 0, 'hits': 0, 'misses': 0,
              'failed_attempts': 0, 'unknown_attempts': 0,
              'recorded_wall_ns': 0, 'recorded_process_cpu_ns': 0} for i in range(5)]
    index, nonce, pending, terminal, ended, replayed = 0, 0, None, False, None, 0
    winners = []
    for event in events[1:]:
        require(ended is None, 'SEARCH_AFTER_END')
        kind = event.get('kind')
        if kind == 'end':
            status = event.get('status')
            if status == 'complete':
                require(set(event) == {'kind', 'status', 'witness_sha256', 'output_sha256',
                                      'after_state_sha256'} and
                        index == 5 and pending is None and not terminal, 'SEARCH_INCOMPLETE_SUCCESS')
                for field in ('witness_sha256', 'output_sha256', 'after_state_sha256'):
                    hex32(event[field])
                require(event['after_state_sha256'] == plan['before_state_sha256'], 'SEARCH_STATE_TRANSITION')
            else:
                require(status == 'failed' and set(event) == {'kind', 'status', 'error_type', 'error'},
                        'SEARCH_END_FIELDS')
                _error_fields(event)
            ended = event
            continue
        require(not terminal and index < 5, 'SEARCH_AFTER_TERMINAL_ATTEMPT')
        tile = tiles[index]
        context_fields = {'kind', 'tile', 'nonce', 'challenge'}
        require(type(event.get('tile')) is int and event['tile'] == index and
                type(event.get('nonce')) is int and event['nonce'] == nonce, 'SEARCH_NONCE_ORDER')
        challenge = H('useful-cell-int257-v1/challenge', hex32(plan['contract_id']),
                      hex32(plan['before_state_sha256']), hex32(plan['tiles'][index]['task']),
                      u64(index), u64(nonce))
        require(event.get('challenge') == challenge.hex(), 'SEARCH_CHALLENGE')
        if kind == 'attempt-start':
            require(set(event) == context_fields and pending is None and
                    nonce < plan['max_attempts_per_tile'], 'SEARCH_START')
            tile['status'] = 'outcome-unknown'
            tile['started_attempts'] += 1
            pending = dict(event)
            continue
        require(pending is not None, 'SEARCH_COMPLETION_WITHOUT_START')
        timing_fields = {'wall_ns', 'process_cpu_ns'}
        for field in timing_fields:
            integer(event.get(field), 'SEARCH_TIMING')
        tile['recorded_wall_ns'] += event['wall_ns']
        tile['recorded_process_cpu_ns'] += event['process_cpu_ns']
        integer(tile['recorded_wall_ns'], 'SEARCH_TIMING_SUM')
        integer(tile['recorded_process_cpu_ns'], 'SEARCH_TIMING_SUM')
        if kind == 'attempt-error':
            require(set(event) == context_fields | timing_fields | {'error_type', 'error'}, 'SEARCH_ERROR_FIELDS')
            _error_fields(event)
            tile['failed_attempts'] += 1
            tile['status'] = 'failed'
            terminal = True
        else:
            require(kind == 'attempt-complete' and set(event) == context_fields | timing_fields |
                    {'trace', 'proof_sha256', 'ticket', 'hit'}, 'SEARCH_COMPLETE_FIELDS')
            trace, ticket = hex32(event['trace']), hex32(event['ticket'])
            hex32(event['proof_sha256'])
            require(type(event['hit']) is bool and ticket == H('ticket', challenge, trace) and
                    event['hit'] == (ticket <= hex32(plan['target'])), 'SEARCH_TICKET')
            if materials is not None:
                proof = work.prove(challenge, *words[index])
                require(proof[-32:] == trace and hashlib.sha256(proof).hexdigest() == event['proof_sha256'],
                        'SEARCH_FULL_ARITHMETIC_REPLAY')
                replayed += 1
            tile['completed_attempts'] += 1
            tile['hits' if event['hit'] else 'misses'] += 1
            if event['hit']:
                winners.append({key: event[key] for key in
                                ('tile', 'nonce', 'challenge', 'trace', 'proof_sha256', 'ticket')})
                tile['status'] = 'complete'
                index, nonce = index + 1, 0
            else:
                nonce += 1
                tile['status'] = 'search-exhausted' if nonce == plan['max_attempts_per_tile'] else 'incomplete'
                terminal = nonce == plan['max_attempts_per_tile']
        pending = None
    if pending is not None:
        tiles[index]['unknown_attempts'] = 1
    # A suffix cut during the next append can hide an attempt start. State that
    # uncertainty explicitly; never supply a zero-cost/zero-attempt conclusion.
    completed = ended is not None and ended['status'] == 'complete' and not tail
    counts = {key: sum(tile[key] for tile in tiles) for key in (
        'started_attempts', 'completed_attempts', 'hits', 'misses', 'failed_attempts',
        'unknown_attempts', 'recorded_wall_ns', 'recorded_process_cpu_ns')}
    return {
        'schema': SCHEMA + '/inspection',
        'status': 'complete' if completed else 'failed' if ended is not None else
                  'not-started' if not events and not tail else 'incomplete',
        'expected_plan_sha256': hashlib.sha256(canonical(plan)).hexdigest(),
        'raw_sha256': hashlib.sha256(raw).hexdigest(), 'raw_bytes': len(raw), 'last_entry_sha256': head,
        'truncated_tail_bytes': len(tail), 'truncated_tail_sha256': hashlib.sha256(tail).hexdigest(),
        'planned_tiles': 5, 'planned_application_requests': plan['batch_size'],
        'completed_producer_batches': int(completed),
        'producer_reported_complete_outputs': plan['batch_size'] if completed else 0,
        'verified_complete_cell_outputs': 0,
        'not_run_tiles': sum(t['status'] == 'not-run' for t in tiles),
        'counts': counts, 'tiles': tiles, 'ending': ended,
        'winning_attempts': winners, 'delivered_witness_matches_first_hits': False,
        'full_arithmetic_replay': materials is not None, 'mathematical_attempts_replayed': replayed,
        'unrecorded_partial_work_possible': bool(tail or pending is not None or ended is None),
        'cost_scope': 'recorded local Python attempt arithmetic only; excludes journal I/O, source replay, setup, verification and delivery',
        'adversary_class': 'legal-proof-search', 'invalid_input_rejection_measured': False,
        'clock_authenticity_verified': False, 'native_execution_verified': False,
        'complete_cell_relation_verified': False, 'ordinary_hepta_verified': False,
        'global_cheapest_legal_bound': None, 'work_security_qualified': False,
        'production_qualified': False,
    }


def _error_fields(event):
    require(type(event.get('error_type')) is str and 1 <= len(event['error_type']) <= 256 and
            type(event.get('error')) is str and len(event['error']) <= 1024, 'SEARCH_ERROR_TEXT')


def inspect_acknowledged_journal(raw, *, expected_plan, acknowledgement, materials=None):
    """Inspect only the caller-retained acknowledged prefix, retaining any suffix.

    A final line can be readable even if fsync failed. Such bytes do not advance
    the prefix and cannot supply a successful producer count. This is an OS
    acknowledgement record, not proof of media survival or external custody.
    """
    require(type(acknowledgement) is dict and set(acknowledgement) ==
            {'schema', 'bytes', 'entries', 'head', 'sink_failed'} and
            acknowledgement['schema'] == SCHEMA + '/acknowledgement' and
            type(acknowledgement['sink_failed']) is bool, 'SEARCH_ACKNOWLEDGEMENT')
    size = integer(acknowledgement['bytes'], 'SEARCH_ACK_BYTES', MAX_BYTES)
    count = integer(acknowledgement['entries'], 'SEARCH_ACK_ENTRIES', 40962)
    require(type(raw) is bytes and size <= len(raw) <= MAX_BYTES, 'SEARCH_ACK_PREFIX')
    prefix, suffix = raw[:size], raw[size:]
    events, _, tail = decode_prefix(prefix)
    require(len(events) == count and not tail, 'SEARCH_ACK_ENTRY_COUNT')
    report = inspect_journal(prefix, expected_plan=expected_plan, materials=materials,
                             expected_final_sha256=acknowledgement['head'])
    report.update({
        'acknowledgement': dict(acknowledgement),
        'original_journal_bytes': len(raw), 'original_journal_sha256': hashlib.sha256(raw).hexdigest(),
        'unacknowledged_suffix_bytes': len(suffix),
        'unacknowledged_suffix_sha256': hashlib.sha256(suffix).hexdigest(),
        'durability_scope': 'caller-retained process observation of file fsync; OS/filesystem trusted; no external rollback or power-loss attestation',
    })
    if suffix or acknowledgement['sink_failed']:
        report['status'] = 'incomplete'
        report['completed_producer_batches'] = 0
        report['producer_reported_complete_outputs'] = 0
        report['unrecorded_partial_work_possible'] = True
    return report


def bind_delivered_witness(report, witness_raw):
    """Bind the delivered five proofs to these exact first-hit search attempts.

    A different valid nonce for the same contract is still not the work whose
    cost this journal measured. The complete relation is verified separately.
    """
    require(report.get('status') == 'complete' and report.get('full_arithmetic_replay') is True,
            'SEARCH_DELIVERY_REQUIRES_COMPLETE_REPLAY')
    require(type(witness_raw) is bytes and len(witness_raw) <= 1024 * 1024, 'SEARCH_WITNESS_LIMIT')
    witness = json.loads(witness_raw, object_pairs_hook=unique, parse_float=reject_number,
                         parse_constant=reject_number)
    require(type(witness) is dict and set(witness) == {'schema', 'model', 'rows', 'tiles'} and
            witness['schema'] == 'pon-useful-cell-int257-v1/witness' and
            canonical(witness) == witness_raw and type(witness['tiles']) is list and
            len(witness['tiles']) == len(report['winning_attempts']) == 5, 'SEARCH_WITNESS_FIELDS')
    require(hashlib.sha256(witness_raw).hexdigest() == report['ending']['witness_sha256'],
            'SEARCH_WITNESS_END_HASH')
    for index, (entry, winner) in enumerate(zip(witness['tiles'], report['winning_attempts'])):
        require(type(entry) is dict and set(entry) == {'index', 'nonce', 'proof_hex'} and
                type(entry['index']) is int and entry['index'] == winner['tile'] == index and
                type(entry['nonce']) is int and entry['nonce'] == winner['nonce'], 'SEARCH_DELIVERED_FIRST_HIT')
        encoded = entry['proof_hex']
        require(type(encoded) is str and len(encoded) == 2 * work.PROOF_BYTES and
                all(c in '0123456789abcdef' for c in encoded), 'SEARCH_WITNESS_PROOF_BYTES')
        proof = bytes.fromhex(encoded)
        require(hashlib.sha256(proof).hexdigest() == winner['proof_sha256'] and
                proof[-32:].hex() == winner['trace'], 'SEARCH_DELIVERED_FIRST_HIT')
    report['delivered_witness_matches_first_hits'] = True
    return report
