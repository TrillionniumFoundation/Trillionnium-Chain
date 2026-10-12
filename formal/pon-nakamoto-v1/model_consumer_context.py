"""Explicit context-bound supplement to the existing offline consumer V2 owner.

This is not a trainer, journal, adoption capability or independent-use receipt.
Historical V1/V2 bytes and callers are unchanged. The ordinary evaluator/consumer
must opt in and obtain both existing keys' signatures after each completed window.
A signature covers only that completed window, never a not-yet-known final history.
"""
from __future__ import annotations

import hashlib
import json
import re

SCHEMA = 'pon-model-consumer-context-v1'
DOMAIN = b'TRNM-MODEL-CONSUMER-CONTEXT-V1\0'
FIELDS = {'schema', 'ordinal', 'window', 'run_plan', 'assessment', 'receipt'}


def context_signing_message(statement):
    """Return the exact bounded message, not an assertion that its fields are true.

    Encoding: DOMAIN || LE32(length) || ASCII JSON, sorted keys, no spaces,
    ensure_ascii=True. Only the closed schema, integer ordinal 1..3 and four
    lowercase 32-byte hex digests are admitted. Signatures use a distinct domain
    from every historical receipt; hash equality cannot supply authorization.
    """
    if type(statement) is not dict or set(statement) != FIELDS:
        raise ValueError('CONSUMER_CONTEXT_FIELDS')
    if statement['schema'] != SCHEMA:
        raise ValueError('CONSUMER_CONTEXT_SCHEMA')
    if type(statement['ordinal']) is not int or not 1 <= statement['ordinal'] <= 3:
        raise ValueError('CONSUMER_CONTEXT_ORDINAL')
    for field in ('window', 'run_plan', 'assessment', 'receipt'):
        value = statement[field]
        if type(value) is not str or re.fullmatch(r'[0-9a-f]{64}', value) is None:
            raise ValueError('CONSUMER_CONTEXT_DIGEST')
    raw = json.dumps(statement, sort_keys=True, separators=(',', ':'),
                     ensure_ascii=True, allow_nan=False).encode('ascii')
    return hashlib.sha256(DOMAIN + len(raw).to_bytes(4, 'little') + raw).digest()


def _verify_context_rows(rows, generations, receipts, attestations, contexts, verify):
    """Additional relation only; public entry below first verifies the full V2 chain."""
    for values in (rows, generations, receipts, attestations, contexts):
        if type(values) is not list or len(values) != 3:
            raise ValueError('CONSUMER_CONTEXT_COUNT')
    retained = []
    for index, (row, generation, receipt, attestation, context) in enumerate(
            zip(rows, generations, receipts, attestations, contexts)):
        if type(context) is not dict or set(context) != {
                'statement', 'consumer_signature', 'controller_signature'}:
            raise ValueError('CONSUMER_CONTEXT_ENVELOPE')
        expected = dict(schema=SCHEMA, ordinal=index + 1,
                        window=generation['window'], run_plan=row['window']['run_plan'],
                        assessment=row['receipt'], receipt=generation['consumer_receipt'])
        message = context_signing_message(context['statement'])
        if context['statement'] != expected:
            raise ValueError('CONSUMER_CONTEXT_BINDING')
        # A delayed post-window benefit can be valid V2 evidence, but does not
        # prove this stronger declared use-before-next-generation relation.
        if index < 2 and receipt['used_at'] >= rows[index + 1]['registered_at']:
            raise ValueError('CONSUMER_CONTEXT_CAUSAL_ORDER')
        for role in ('consumer', 'controller'):
            signature = context[role + '_signature']
            if type(signature) is not str or re.fullmatch(r'[0-9a-f]{128}', signature) is None:
                raise ValueError('CONSUMER_CONTEXT_SIGNATURE_ENCODING')
            # The complete V2 verifier has already checked key encoding, strict
            # key validity, all six keys' distinctness and receipt/key binding.
            try:
                verify(bytes.fromhex(attestation[role + '_public_key']),
                       bytes.fromhex(signature), message)
            except ValueError as failure:
                raise ValueError('CONSUMER_CONTEXT_' + role.upper() + '_SIGNATURE') from failure
        retained.append(dict(statement=dict(expected), message_sha256=message.hex()))
    return retained


def verify_context_bound_prospective_decisions(
        history_raw, expected_history, generations, receipts, attestations, contexts):
    """Verify old V2 semantics AND window-bound signatures and declared causal order.

    No result is emitted until all three rows pass. A rehashed lineage or replaced
    window cannot transplant old signatures, even when model identities agree.
    This verifies supplied chronology; clocks, actual installation, genuine tasks,
    current owner grants and independently controlled operators remain external.
    """
    if type(contexts) is not list or len(contexts) != 3:
        raise ValueError('CONSUMER_CONTEXT_COUNT')
    import model_window_history as owner

    base = owner.verify_signed_prospective_consumer_decisions_v2(
        history_raw, expected_history, generations, receipts, attestations)
    history = owner._decode_exposure_history(history_raw, expected_history)
    bound = _verify_context_rows(history['entries'][-3:], generations, receipts,
                                 attestations, contexts, owner.verify_signature)
    value = dict(schema='pon-model-context-bound-decision-chain-v1',
                 scope='reported-causal-context-not-installation-or-independence',
                 history=expected_history, consumer_decisions=base['id'], contexts=bound,
                 context_signatures_verified=True, declared_causal_use_order_verified=True,
                 actual_model_installation_verified=False, independent_controller_verified=False,
                 new_consumer_benefit_verified=False, hidden_windows_excluded=False,
                 prospective_accepted=False, independent_accepted=False,
                 public_reward_eligible=False, production_activation=False)
    return dict(value, id=owner.H('model-context-bound-decision-chain-v1',
                                  owner.canonical(value)).hex())
