"""Replay Cell V2 validity controls without promoting them to a cost theorem.

Two fixed nonces use the unchanged complete reference prover and verifier.  No
nonce search or optimized mining strategy is implemented here.  Equal useful
outputs demonstrate which values are reusable; they do not price the remaining
nonce-dependent transcript or establish a profitable strategy.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import struct

from contract_wire import canonical
from evaluation_bundle import artifact_id
from experiments import shared_cell_operator_v1 as cell
import useful_cell_execution_v2 as execution
import useful_cell_relation_v2 as relation
import work_oracle as work


SCHEMA = 'pon-cell-lottery-cost-audit-v1'
SOURCE_PATHS = (
    'formal/pon-nakamoto-v1/cell_lottery_cost_audit_v1.py',
    'formal/pon-nakamoto-v1/work_oracle.py',
    'formal/pon-nakamoto-v1/useful_cell_relation_v2.py',
    'formal/pon-nakamoto-v1/useful_cell_execution_v2.py',
    'formal/pon-nakamoto-v1/experiments/shared_cell_operator_v1.py',
)


def require(condition, code):
    if not condition:
        raise ValueError(code)


def _refusal(call, expected):
    try:
        call()
    except ValueError as error:
        require(str(error) == expected, 'UNEXPECTED_REFUSAL:' + str(error))
        return expected
    raise ValueError('MISSING_REFUSAL:' + expected)


def run_audit():
    """Run on the retained public-source model, with independently pinned input.

    This fixture is neither a new Hepta training run nor a customer request.  Its
    all-ones target deliberately avoids search and has no difficulty claim.
    Every submitted witness reaches full original W1 and V2 verification.
    """
    model, rows, _ = cell.load_inputs(
        cell.DEFAULT_MATERIAL / 'model.json', cell.DEFAULT_MATERIAL / 'consumer.json',
        cell.DEFAULT_MATERIAL / 'evaluation-bundle.json', cell.DEFAULT_BUNDLE,
        'consumer', 0, 2)
    before = execution.initial_state(
        model, cell_id='61' * 32, generation=7, scope='lifecycle-cost-audit/fixture',
        rng_seed='62' * 32, remaining_steps=len(rows))
    policy = execution.default_policy(len(rows))
    options = {
        'policy': policy, 'consumer': 'lifecycle-cost-audit-consumer',
        'allowed_use': 'reference-conformance-only', 'request_id': '63' * 32,
        'issued_at_ms': 1000, 'deadline_ms': 2000,
        'parent_context': {'network': '64' * 32, 'parent_id': '65' * 32,
                           'parent_state_root': '66' * 32, 'block_height': 12,
                           'consensus_time_ms': 1500}, 'target': 'ff' * 32}
    identity = relation.current_identity()
    raw = relation.freeze_contract(model, rows, before, **options)
    # The consumer constructs expected before any witness, from its own request.
    expected = {
        'contract_id': relation.contract_id(raw),
        'program_sha256': identity['program_sha256'],
        'parameters_sha256': identity['parameters_sha256'],
        'before_state': copy.deepcopy(before), 'consumer': options['consumer'],
        'allowed_use': options['allowed_use'], 'candidate_artifact': artifact_id(model),
        'parent_context': copy.deepcopy(options['parent_context'])}
    original = relation.prove_reference(raw, model, rows, before, max_attempts=1)
    donor = json.loads(original['witness'])
    tiles, _ = cell.build_tiles(model, execution.prepare_rows(rows, policy))

    def verify(witness, retained=expected):
        return relation.verify_historical_relation(
            raw, before, original['output'], original['after_state'], witness,
            expected=retained)

    first_report = verify(original['witness'])
    second = copy.deepcopy(donor)
    products = []
    for tile, old, new in zip(tiles, donor['tiles'], second['tiles']):
        require(old['nonce'] == 0, 'FIXTURE_NONCE')
        words = struct.unpack('<' + 'I' * (2 * work.CELLS), tile['material'])
        challenge = relation._challenge(raw, before, tile, 1)
        proof = work.prove(challenge, list(words[:work.CELLS]), list(words[work.CELLS:]))
        old_proof = bytes.fromhex(old['proof_hex'])
        product_slice = slice(4 + 2 * work.CELLS * 4, -32)
        require(old_proof[product_slice] == proof[product_slice], 'USEFUL_PRODUCT_CHANGED')
        require(old_proof[-32:] != proof[-32:], 'NONCE_TRACE_DID_NOT_CHANGE')
        new.update(nonce=1, proof_hex=proof.hex())
        products.append({
            'index': tile['index'], 'feature_count': tile['feature_count'],
            'active_output_rows': tile['active_output_rows'],
            'active_requests': tile['active_requests'],
            'complete_product_sha256': hashlib.sha256(proof[product_slice]).hexdigest(),
            'useful_product_equal': True, 'transcript_changed': True,
        })
    second_report = verify(canonical(second))
    # The pure verifier intentionally does not consume owner operations.  A
    # repeated accepted computation is not another paid service or work credit.
    replay_report = verify(original['witness'])
    for report in (first_report, second_report, replay_report):
        require(report['relation_valid'] is True and
                report['complete_w1_transcripts_verified'] == 5, 'INCOMPLETE_RELATION')
        for key in ('request_consumed', 'checkpoint_committed', 'native_node_admission',
                    'work_security_qualified', 'public_reward_eligible',
                    'ordinary_hepta_encoder_verified', 'model_quality_qualified'):
            require(report[key] is False, 'UNSUPPORTED_PROMOTION:' + key)

    stale_nonce = copy.deepcopy(donor)
    stale_nonce['tiles'][0]['nonce'] = 1
    wrong_parent = copy.deepcopy(expected)
    wrong_parent['parent_context']['parent_id'] = '67' * 32
    refusals = {
        'nonce_change_without_reexecution': _refusal(
            lambda: verify(canonical(stale_nonce)), 'TRANSCRIPT'),
        'noncanonical_witness_whitespace': _refusal(
            lambda: verify(b' ' + original['witness']), 'V2_WITNESS_CANONICAL'),
        'independent_parent_mismatch': _refusal(
            lambda: verify(original['witness'], wrong_parent), 'EXPECTED_PARENT_CONTEXT'),
    }
    widths = [tile['feature_count'] for tile in tiles]
    require(widths == [64, 64, 64, 64, 1], 'FEATURE_COVERAGE')
    root = Path(__file__).resolve().parents[2]
    source = {path: hashlib.sha256((root / path).read_bytes()).hexdigest()
              for path in SOURCE_PATHS}
    return {
        'schema': SCHEMA, 'relation': relation.RELATION_ID,
        'scope': 'retained-public-source-model-reference-conformance',
        'contract_id': expected['contract_id'], 'program_sha256': identity['program_sha256'],
        'parameters_sha256': identity['parameters_sha256'], 'source_sha256': source,
        'model_artifact': artifact_id(model), 'model_source': model['source'],
        'rows': len(rows), 'target': options['target'], 'searched_nonces': False,
        'fixed_nonces': [0, 1], 'accepted_complete_witnesses': 2,
        'additional_same_witness_replays': 1,
        'complete_w1_verifications_in_accepted_paths': 15,
        'products': products, 'refusals': refusals,
        'useful_dense_positions': sum(
            tile['active_output_rows'] * tile['active_requests'] * tile['feature_count']
            for tile in tiles),
        'padded_dense_product_positions': len(tiles) * work.N ** 3,
        'position_counts_are_physical_cost_bounds': False,
        'ordinary_hepta_encoder_verified': False, 'model_quality_qualified': False,
        'native_node_admission': False, 'work_profile_qualified': False,
        'qualification': 'HOLD', 'physical_cost_lower_bound': None,
        'additional_chainwork': 0,
        'open_cost_obligations': [
            'fresh-randomness-enters-a-proven-paid-work-part',
            'all-legal-sharing-preprocessing-and-partial-recomputation',
            'joint-equivalent-encoding-proof-randomness-and-ticket-bound',
            'joint-execution-soundness-and-late-witness-search',
            'durable-cross-parent-profile-version-credit-deduplication',
            'all-admitted-model-input-parameter-choices',
        ],
    }


if __name__ == '__main__':
    print(json.dumps(run_audit(), sort_keys=True, indent=2))
