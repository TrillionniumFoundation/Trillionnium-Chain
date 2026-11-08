"""Independent Python reference for the fixed grouped security-seal research.

This is deliberately extra security work. It preserves lawful cached/factored
Cell arithmetic and makes no neural-MAC, physical-cost or production claim.
Native admission must independently establish the candidate and actual target;
these helpers do not authenticate caller-supplied hashes or grant authority.
"""
from __future__ import annotations

import copy
import hashlib
import json

from contract_wire import canonical, unique
import grouped_work_lottery_v0 as cell
from experiments.grouped_cell_operator_v0 import (
    digest, input_commitment, model_commitment, statement_commitment,
)
from grouped_legal_strategy_v0 import REPRESENTATION, independent_reference

PROFILE = 'pon-grouped-int257-sealed-research-v0'
OPERATOR_PROFILE = 'pon-routed-int257-grouped-research-v0'
NUMERIC = 'signed-i32-coeff-i64-accum-bias8-lowest-argmax'
STEPS = 64
BATCH_SIZE = 16
MAGIC = b'PGSF\x00\x00'
PROOF_BYTES = 134
DOMAIN = b'TRNM-GROUPED-FRESH-SEAL0\x00'
PACKAGE_SCHEMA = 'pon-grouped-fresh-seal-package-v0'
PACKAGE_FIELDS = frozenset((
    'schema', 'profile', 'nonce', 'capsule_hex', 'context', 'model_commitment',
    'input_commitment', 'statement_commitment', 'product', 'proof_hex',
))
MAX_PACKAGE_BYTES = 128 * 1024


def require(condition, code):
    if not condition:
        raise ValueError(code)


def hash_preimage(tag, *parts):
    require(type(tag) is bytes and len(tag) <= 65535, 'HASH_TAG')
    require(all(type(p) is bytes and len(p) < 1 << 32 for p in parts), 'HASH_PART')
    return DOMAIN + len(tag).to_bytes(2, 'big') + tag + b''.join(
        len(p).to_bytes(4, 'big') + p for p in parts)


def profile_hash():
    raw = hash_preimage(b'profile', PROFILE.encode(), OPERATOR_PROFILE.encode(),
                        NUMERIC.encode(), STEPS.to_bytes(2, 'big'),
                        BATCH_SIZE.to_bytes(2, 'big'))
    return hashlib.sha256(raw).digest()


def seed(challenge, statement):
    return hashlib.sha256(hash_preimage(
        b'seed', profile_hash(), digest(challenge), digest(statement))).digest()


def step_preimage(challenge, index, previous):
    require(type(index) is int and 1 <= index <= STEPS, 'STEP_INDEX')
    require(type(previous) is bytes and len(previous) == 32, 'PREVIOUS_STATE')
    return hash_preimage(b'step', profile_hash(), digest(challenge),
                         index.to_bytes(2, 'big'), previous)


def prove(challenge, statement, *, on_step=None):
    """Callback fires after each actual hash; raising leaves no full witness."""
    state = seed(challenge, statement)
    for index in range(1, STEPS + 1):
        raw = step_preimage(challenge, index, state)
        state = hashlib.sha256(raw).digest()
        if on_step is not None:
            on_step({'index': index, 'input_hex': raw.hex(), 'output_hex': state.hex()})
    return MAGIC + profile_hash() + digest(challenge) + digest(statement) + state


def precheck(challenge, statement, target, proof):
    require(type(proof) is bytes and len(proof) == PROOF_BYTES, 'SEAL_LENGTH')
    require(proof[:6] == MAGIC, 'SEAL_VERSION')
    require(proof[6:38] == profile_hash(), 'SEAL_PROFILE')
    require(proof[38:70] == digest(challenge), 'SEAL_CHALLENGE')
    require(proof[70:102] == digest(statement), 'SEAL_STATEMENT')
    bound = digest(target)
    require(bound != bytes(32), 'SEAL_TARGET')
    return {'ticket': proof[102:].hex(), 'target_hit': proof[102:] <= bound}


def verify(challenge, statement, target, proof, *, require_hit=False):
    """Full mathematical replay; target result is explicit, never promoted.

    A miss can be checked as a correctly generated research ticket. It is not
    eligible even for nominal hit credit, and all actual chainwork is zero.
    """
    verdict = precheck(challenge, statement, target, proof)
    require(prove(challenge, statement) == proof, 'SEAL_ENDPOINT')
    if require_hit:
        require(verdict['target_hit'], 'SEAL_TARGET_MISS')
    return dict(verdict, replayed_steps=STEPS, seed_hashes=1,
                chainwork_awarded=0, pow_qualified=False,
                physical_resource_lower_bound_proved=False,
                neural_mac_lower_bound_proved=False)


def grouped_binding(init, requests, context, product):
    cell.validate_init(init)
    cell.validate_requests(requests)
    cell._validate_product(product)
    require(type(context) is dict and set(context) ==
            {'chain', 'parent', 'challenge', 'batch_id'}, 'CONTEXT_FIELDS')
    for value in context.values():
        digest(value)
    model = model_commitment(init)
    inputs = input_commitment(model, {'context': context, 'requests': requests})
    statement = statement_commitment(model, inputs, context, product)
    return {'model_commitment': model, 'input_commitment': inputs,
            'statement_commitment': statement}


def package(init, requests, context, product, *, nonce, capsule_hex, proof):
    require(type(nonce) is int and 0 <= nonce < 1 << 64, 'NONCE')
    require(type(capsule_hex) is str and len(capsule_hex) <= MAX_PACKAGE_BYTES and
            len(capsule_hex) % 2 == 0 and
            all(c in '0123456789abcdef' for c in capsule_hex), 'CAPSULE_HEX')
    require(type(proof) is bytes and len(proof) == PROOF_BYTES, 'SEAL_LENGTH')
    binding = grouped_binding(init, requests, context, product)
    value = dict(schema=PACKAGE_SCHEMA, profile=PROFILE, nonce=nonce,
                 capsule_hex=capsule_hex, context=copy.deepcopy(context),
                 product=copy.deepcopy(product), proof_hex=proof.hex(), **binding)
    raw = canonical(value)
    require(len(raw) <= MAX_PACKAGE_BYTES, 'PACKAGE_LIMIT')
    return raw


def parse_package(raw):
    require(type(raw) is bytes and len(raw) <= MAX_PACKAGE_BYTES, 'PACKAGE_LIMIT')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    require(type(value) is dict and set(value) == PACKAGE_FIELDS, 'PACKAGE_FIELDS')
    require(value['schema'] == PACKAGE_SCHEMA and value['profile'] == PROFILE,
            'PACKAGE_PROFILE')
    require(type(value['nonce']) is int and 0 <= value['nonce'] < 1 << 64, 'NONCE')
    for key in ('capsule_hex', 'proof_hex'):
        text = value[key]
        require(type(text) is str and len(text) % 2 == 0 and
                all(c in '0123456789abcdef' for c in text), 'PACKAGE_HEX')
    require(len(value['proof_hex']) == PROOF_BYTES * 2, 'SEAL_LENGTH')
    return value


def verify_grouped_package(raw, *, init, requests, expected_context, now_ns):
    """Independent original-coefficient full Cell replay, before seal admission.

    This intentionally does not replace the native signature/branch verifier.
    Its exact expected context must be established outside the received bytes.
    """
    require(type(now_ns) is int and 0 <= now_ns < 1 << 64, 'CLOCK_REQUIRED')
    value = parse_package(raw)
    require(value['context'] == expected_context, 'EXPECTED_CONTEXT')
    cell.validate_init(init)
    cell.validate_requests(requests, now_ns=now_ns)
    cell._validate_product(value['product'])
    # This reference really performs separate base and delta contractions.
    # The older scalar_product control merges coefficients inside each term;
    # calling that control while charging 9*d*n MACs would overcount its work.
    reference_requests = [dict(row, generation=init['model_version'],
                               representation=REPRESENTATION) for row in requests]
    actual, reference_cost = independent_reference(init, reference_requests)
    require(value['product'] == actual, 'FULL_GROUPED_RELATION')
    binding = grouped_binding(init, requests, expected_context, actual)
    for key, expected in binding.items():
        require(value[key] == expected, 'BINDING_' + key.upper())
    return dict(value, reference_macs=reference_cost.reference_macs,
                reference_additions=reference_cost.reference_additions, chainwork_awarded=0,
                native_authority_not_checked_by_this_helper=True)
