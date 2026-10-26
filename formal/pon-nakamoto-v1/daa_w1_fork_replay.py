"""Actual W1 transcript/replay over a deliberately synthetic fork/lease schedule.

The real fixed-size PNH1/PNW1 wire and independent scalar W1 work oracle execute.
This is NOT an M06 State transition, native consensus, source-signed Q4 task,
network proof of independent operators, protocol activation or measured security.
The state/transactions/receipts digests are explicit deterministic research
placeholders. A simulated source outage never manufactures a new source lease:
only the explicitly selected revision12 public Genesis Maintenance task is used.

All accepted branch work comes from complete verified transcripts, never a
claimed target hit or model quality score. Public relay/confirmation/reorg is
not inferred from this deterministic offline workload.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
from typing import Any

from contract_wire import H, header_decode, header_encode
from daa_research_oracle import legacy_retarget, asert_target, mtp11, valid_time
from work_oracle import PROOF_BYTES, field_bytes, precheck, prove, task_id, verify

SCHEMA = 'trnm-research-actual-w1-fork-outage-v1'
NETWORK = H('w1-fork-research-network-v1', b'nonactivated')
PARAMETERS = H('w1-fork-research-parameters-v1', b'nonactivated')
GENESIS = H('w1-fork-research-genesis-v1', b'nonactivated')
START = 1_000_000
SPACING = 10
POW_LIMIT = (1 << 255) - 1
INITIAL_TARGET = POW_LIMIT // 2
TARGET_BYTES = INITIAL_TARGET.to_bytes(32, 'big')
# These exact formulas are Genesis Maintenance revision12. No third-party lease
# or remote task material is required for these public deterministic matrices.
A = tuple((13 * i + 17) % 257 for i in range(4096))
B = tuple((29 * i + 31) % 263 for i in range(4096))
MATERIAL = task_id(A, B)
ROOT_TX = H('research-empty-transactions', b'not-M06')
ROOT_RECEIPT = H('research-empty-receipts', b'not-M06')


def _state_root(parent: bytes, height: int) -> bytes:
    return H('research-state-not-M06', parent, height.to_bytes(8, 'little'))


def _required_work(target: int) -> int:
    if type(target) is not int or not 1 <= target <= POW_LIMIT:
        raise ValueError('TARGET')
    return (1 << 256) // (target + 1)


def _strict_decode(encoded: bytes) -> dict:
    h = header_decode(encoded)
    if header_encode(h) != encoded:
        raise ValueError('HEADER_NOT_CANONICAL')
    return h


@dataclass(frozen=True)
class Block:
    block_id: bytes
    parent: bytes | None
    height: int
    timestamp: int
    target: int
    chainwork: int
    # No model utility credit for Genesis Maintenance.
    useful_output_credit: int = 0


class WorkReplay:
    """Two partitioned local views of verified W1 proof bytes; no network I/O."""

    def __init__(self) -> None:
        self.blocks = {GENESIS: Block(GENESIS, None, 0, START, INITIAL_TARGET, 0)}
        self.tip_a = GENESIS
        self.tip_b = GENESIS
        self.events: list[dict[str, Any]] = []
        self.attempts = 0

    def ancestors(self, parent: bytes) -> list[Block]:
        if parent not in self.blocks:
            raise ValueError('UNKNOWN_PARENT')
        rows = []
        while True:
            h = self.blocks[parent]
            rows.append(h)
            if h.parent is None:
                return rows
            parent = h.parent

    def expected_target(self, parent: bytes) -> int:
        history = self.ancestors(parent)
        h = history[0].height + 1
        if h % 16:
            return history[0].target
        if len(history) < 16:
            raise ValueError('ANCESTRY')
        return legacy_retarget(history[0].target, history[15].timestamp,
                               history[0].timestamp, 16, SPACING, POW_LIMIT)

    def _guard(self, head: dict, now: int) -> None:
        if head['network'] != NETWORK or head['parameters'] != PARAMETERS:
            raise ValueError('CONTEXT')
        if head['work_task'] != MATERIAL:
            raise ValueError('TASK')
        if head['transactions'] != ROOT_TX or head['receipts'] != ROOT_RECEIPT:
            raise ValueError('UNEXECUTED_ROOT')
        if head['state'] != _state_root(head['parent'], head['height']):
            raise ValueError('UNEXECUTED_STATE_ROOT')
        parent = self.blocks.get(head['parent'])
        if parent is None or head['height'] != parent.height + 1:
            raise ValueError('PARENT')
        if int.from_bytes(head['target'], 'big') != self.expected_target(head['parent']):
            raise ValueError('TARGET')
        if not valid_time(head['timestamp'],
                          [r.timestamp for r in self.ancestors(head['parent'])[:11]], now, 120):
            raise ValueError('TIME')

    def admit(self, raw_header: bytes, raw_proof: bytes, now: int) -> bytes:
        """Recheck every W1 product and transcript before allocating new state."""
        head = _strict_decode(raw_header)
        self._guard(head, now)
        if len(raw_proof) != PROOF_BYTES:
            raise ValueError('PROOF_LENGTH')
        challenge = H('challenge', raw_header)
        # This is the actual expensive verifier, not the cheap ticket precheck.
        verify(challenge, MATERIAL, head['target'], raw_proof)
        identifier = H('block', raw_header, raw_proof[-32:])
        if identifier in self.blocks:
            raise ValueError('DUPLICATE_BLOCK')
        parent = self.blocks[head['parent']]
        target = int.from_bytes(head['target'], 'big')
        self.blocks[identifier] = Block(identifier, head['parent'], head['height'],
                                        head['timestamp'], target,
                                        parent.chainwork + _required_work(target))
        return identifier

    def mine(self, phase: str, timestamp: int, now: int, *, attempts: int = 64) -> bytes:
        if phase not in ('shared', 'A', 'B'):
            raise ValueError('WORK_SELECTION')
        if type(attempts) is not int or not 1 <= attempts <= 128:
            raise ValueError('ATTEMPT_LIMIT')
        parent = self.tip_a if phase in ('shared', 'A') else self.tip_b
        height = self.blocks[parent].height + 1
        target = self.expected_target(parent)
        miner = H('research-miner', b'B' if phase == 'B' else b'A')
        for nonce in range(attempts):
            head = {'network': NETWORK, 'parameters': PARAMETERS,
                    'parent': parent, 'height': height, 'timestamp': timestamp,
                    'target': target.to_bytes(32, 'big'), 'miner': miner,
                    'transactions': ROOT_TX, 'state': _state_root(parent, height),
                    'receipts': ROOT_RECEIPT, 'work_task': MATERIAL, 'nonce': nonce}
            raw = header_encode(head)
            challenge = H('challenge', raw)
            proof = prove(challenge, A, B)
            self.attempts += 1
            # A cheap filter only tells the producer whether a full proof might win.
            if H('ticket', challenge, proof[-32:]) > head['target']:
                continue
            bid = self.admit(raw, proof, now)
            if phase == 'shared':
                self.tip_a = self.tip_b = bid
            elif phase == 'A':
                self.tip_a = bid
            else:
                self.tip_b = bid
            self.events.append({
                'phase': phase, 'now': now, 'header': raw.hex(),
                'proof': base64.b64encode(proof).decode('ascii'),
                'block_id': bid.hex(), 'attempts': nonce + 1,
                # No source signature: the explicitly selected work is Maintenance.
                'selection': 'genesis-maintenance',
                'optional_source_available': phase == 'shared',
            })
            return bid
        raise ValueError('SEARCH_EXHAUSTED')

    def heal(self) -> bytes:
        a, b = self.blocks[self.tip_a], self.blocks[self.tip_b]
        # Equal work keeps existing A view; this is a local tie preference.
        selected = self.tip_b if b.chainwork > a.chainwork else self.tip_a
        self.tip_a = self.tip_b = selected
        return selected

    def shadow(self, tip: bytes, clock: str) -> int:
        """Research ASERT number, NEVER current difficulty or fork choice."""
        history = self.ancestors(tip)
        parent = history[0]
        anchor = next((r for r in history if r.height == 16), None)
        prior = next((r for r in history if r.height == 15), None)
        if anchor is None or prior is None:
            raise ValueError('ANCHOR_ABSENT')
        if clock == 'raw':
            parent_time, anchor_parent_time = parent.timestamp, prior.timestamp
        elif clock == 'mtp11':
            p_at = history.index(prior)
            parent_time = mtp11([r.timestamp for r in history[:11]])
            anchor_parent_time = mtp11([r.timestamp for r in history[p_at:p_at + 11]])
        else:
            raise ValueError('CLOCK')
        return asert_target(anchor.target, anchor_parent_time, parent_time,
                            anchor.height, parent.height + 1, SPACING, 7200, POW_LIMIT)


def campaign(common: int = 18, on_a: int = 16, on_b: int = 18) -> dict:
    """Actual W1 certificates on divergent branches, no Poisson ticket simulation."""
    if not (16 <= common <= 64 and 1 <= on_a <= 64 and 1 <= on_b <= 64):
        raise ValueError('CAMPAIGN_LIMIT')
    state = WorkReplay()
    for height in range(1, common + 1):
        state.mine('shared', START + height * SPACING, START + height * SPACING)
    for turn in range(max(on_a, on_b)):
        if turn < on_a:
            h = state.blocks[state.tip_a].height + 1
            state.mine('A', START + h * SPACING, START + h * SPACING)
        if turn < on_b:
            h = state.blocks[state.tip_b].height + 1
            # A different, still legal timestamp policy can affect future DAA.
            state.mine('B', START + h * (SPACING + 1), START + h * SPACING)
    losing_a, losing_b = state.tip_a, state.tip_b
    final = state.heal()
    return {
        'schema': SCHEMA,
        'context': {'network': NETWORK.hex(), 'parameters': PARAMETERS.hex(),
                    'genesis': GENESIS.hex(), 'task': MATERIAL.hex(),
                    'work_profile': 'pon-matmul-transcript-64-v1',
                    'legacy_daa': '16-block-endpoint',
                    'genesis_maintenance_revision': 12},
        'events': state.events,
        'summary': {'real_w1_winning_proofs': len(state.events),
                    'real_w1_prover_attempts': state.attempts,
                    'independent_network_operators': 0,
                    'native_w1_proofs': 0,
                    'native_consensus_activation': False,
                    'real_lease_signatures': 0,
                    'partitions': 1, 'healed_tip': final.hex(),
                    'before_heal_a': losing_a.hex(),
                    'before_heal_b': losing_b.hex(),
                    'reorg_removed_on_a': count_removed(state, losing_a, final),
                    'reorg_removed_on_b': count_removed(state, losing_b, final),
                    'shadow_raw_a': str(state.shadow(losing_a, 'raw')),
                    'shadow_raw_b': str(state.shadow(losing_b, 'raw')),
                    'shadow_mtp_a': str(state.shadow(losing_a, 'mtp11')),
                    'shadow_mtp_b': str(state.shadow(losing_b, 'mtp11')),
                    'source_outage_at_event': common},
    }


def count_removed(store: WorkReplay, old: bytes, selected: bytes) -> int:
    winning = {r.block_id for r in store.ancestors(selected)}
    return sum(r.block_id not in winning for r in store.ancestors(old))


def verify_campaign(report: dict, *, audit_search: bool = False) -> WorkReplay:
    """Cold rebuild of both local branch views and every complete W1 proof."""
    if type(report) is not dict or report.get('schema') != SCHEMA:
        raise ValueError('SCHEMA')
    exact = {'network': NETWORK.hex(), 'parameters': PARAMETERS.hex(),
             'genesis': GENESIS.hex(), 'task': MATERIAL.hex(),
             'work_profile': 'pon-matmul-transcript-64-v1',
             'legacy_daa': '16-block-endpoint',
             'genesis_maintenance_revision': 12}
    if report.get('context') != exact:
        raise ValueError('CONTEXT')
    if (type(report.get('events')) is not list
            or not 1 <= len(report['events']) <= 192):
        raise ValueError('EVENTS')
    state = WorkReplay()
    outage_started = False
    for event in report['events']:
        if type(event) is not dict or set(event) != {
            'phase', 'now', 'header', 'proof', 'block_id', 'attempts',
            'selection', 'optional_source_available'}:
            raise ValueError('EVENT_WIRE')
        phase = event['phase']
        if phase not in ('shared', 'A', 'B') or event['selection'] != 'genesis-maintenance':
            raise ValueError('WORK_SELECTION')
        if phase != 'shared':
            outage_started = True
        elif outage_started:
            raise ValueError('OUTAGE_ROLLBACK')
        if type(event['optional_source_available']) is not bool or (
            event['optional_source_available'] is not (phase == 'shared')
        ):
            raise ValueError('SOURCE_CLAIM')
        if type(event['now']) is not int or not 0 <= event['now'] < 1 << 64:
            raise ValueError('NOW')
        if type(event['attempts']) is not int or not 1 <= event['attempts'] <= 128:
            raise ValueError('ATTEMPTS')
        try:
            raw_header = bytes.fromhex(event['header'])
            raw_proof = base64.b64decode(event['proof'], validate=True)
        except (ValueError, TypeError) as error:
            raise ValueError('PROOF_WIRE') from error
        parsed = _strict_decode(raw_header)
        expected_miner = H('research-miner', b'B' if phase == 'B' else b'A')
        if parsed['miner'] != expected_miner:
            raise ValueError('MINER_ID')
        if parsed['nonce'] != event['attempts'] - 1:
            raise ValueError('ATTEMPT_NONCE')
        if audit_search:
            for nonce in range(event['attempts']):
                candidate = dict(parsed, nonce=nonce)
                raw_candidate = header_encode(candidate)
                challenge = H('challenge', raw_candidate)
                candidate_proof = prove(challenge, A, B)
                winner = H('ticket', challenge, candidate_proof[-32:]) <= candidate['target']
                if nonce + 1 == event['attempts']:
                    if not winner or candidate_proof != raw_proof:
                        raise ValueError('SEARCH_RESULT')
                elif winner:
                    raise ValueError('SEARCH_EARLY_WIN')
        expected_parent = state.tip_a if phase in ('shared', 'A') else state.tip_b
        if parsed['parent'] != expected_parent:
            raise ValueError('FORK_PARENT')
        bid = state.admit(raw_header, raw_proof, event['now'])
        if event['block_id'] != bid.hex():
            raise ValueError('BLOCK_ID')
        if phase == 'shared':
            state.tip_a = state.tip_b = bid
        elif phase == 'A':
            state.tip_a = bid
        else:
            state.tip_b = bid
        state.attempts += event['attempts']
        state.events.append(event)
    a, b = state.tip_a, state.tip_b
    head = state.heal()
    expected_summary = {
        'real_w1_winning_proofs': len(state.events),
        'real_w1_prover_attempts': state.attempts,
        'independent_network_operators': 0,
        'native_w1_proofs': 0,
        'native_consensus_activation': False,
        'real_lease_signatures': 0,
        'partitions': 1, 'healed_tip': head.hex(),
        'before_heal_a': a.hex(), 'before_heal_b': b.hex(),
        'reorg_removed_on_a': count_removed(state, a, head),
        'reorg_removed_on_b': count_removed(state, b, head),
        'shadow_raw_a': str(state.shadow(a, 'raw')),
        'shadow_raw_b': str(state.shadow(b, 'raw')),
        'shadow_mtp_a': str(state.shadow(a, 'mtp11')),
        'shadow_mtp_b': str(state.shadow(b, 'mtp11')),
        'source_outage_at_event': sum(e['phase']=='shared' for e in state.events),
    }
    if report.get('summary') != expected_summary:
        raise ValueError('SUMMARY')
    return state


def main() -> None:
    import argparse
    from pathlib import Path
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify', type=Path)
    parser.add_argument('--verify-search', action='store_true')
    args = parser.parse_args()
    if args.verify_search and args.verify is None:
        parser.error('--verify-search requires --verify')
    if (args.output is None) == (args.verify is None):
        parser.error('select exactly one of --output or --verify')
    if args.output is not None:
        if args.output.exists():
            raise ValueError('CREATE_ONLY')
        report = campaign()
        verify_campaign(report)
        # No overwriting an earlier source/evidence file.
        with args.output.open('x', encoding='utf8') as file:
            json.dump(report, file, sort_keys=True, separators=(',', ':'))
            file.write('\n')
        print(json.dumps({'w1_winners': report['summary']['real_w1_winning_proofs'],
                          'proof_attempts': report['summary']['real_w1_prover_attempts'],
                          'artifact_sha256': hashlib.sha256(args.output.read_bytes()).hexdigest()},
                         sort_keys=True))
    else:
        if args.verify.stat().st_size > 24_000_000:
            raise ValueError('REPORT_LIMIT')
        text = args.verify.read_text(encoding='utf8')
        if len(text) > 24_000_000:
            raise ValueError('REPORT_LIMIT')
        report = json.loads(text)
        verify_campaign(report, audit_search=args.verify_search)
        print(json.dumps({'verified_w1_winners': len(report['events']),
                          'sha256': hashlib.sha256(text.encode()).hexdigest()}, sort_keys=True))


if __name__ == '__main__':
    main()
