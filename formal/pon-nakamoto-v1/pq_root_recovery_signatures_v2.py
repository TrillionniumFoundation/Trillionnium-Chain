#!/usr/bin/env python3
"""Real dual-family verification of complete root research intents.

This is a cryptographic bridge, not a production root owner. The caller supplies
current policy, public keys and state independently of an untrusted request.
Only that caller can durably consume the nonce and apply a research transition.
Every successful return remains HOLD and grants no production authority.

Public-key maps are exact ``{signer_id: canonical_SPKI_DER_bytes}`` mappings.
Signature rows are exactly ``{suite, signer_id, signature_hex}``. A current
approval quorum has two ML-DSA-87 and two SLH-DSA-SHA2-256s signatures. Successor
transitions additionally require all six successor keys to prove possession of
that specific complete transition, in a separate role-specific domain.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import time

import pq_openssl_backend as backend
from pq_operation_budget import OperationBudget
import pq_root_recovery_policy_v1 as model

SCHEMA = "trnm.pq-root-recovery-signatures.v2"
KEY_DOMAIN = b"TRNM/RootRecoveryNativeKey/v2\x00"
APPROVAL_DOMAIN = b"TRNM/RootRecoveryNativeApproval/v2\x00"
POSSESSION_DOMAIN = b"TRNM/RootRecoveryNativePossession/v2\x00"
OPERATION_DOMAIN = b"TRNM/RootRecoveryNativeOperation/v2\x00"
SUITES = model.SUITES
# Bound the *complete* message, not a substituted hash of the message. All legal
# v1 payloads, including 4096-byte payloads plus a complete successor policy, fit.
MAX_MESSAGE = 32 * 1024
MAX_JSON = model.MAX_INPUT
MAX_JSON_NODES = 4096
DEFAULT_OPERATION_SECONDS = 60.0
SIGNATURE_BYTES = {"ML-DSA-87": 4627, "SLH-DSA-SHA2-256s": 29792}
PUBLIC_KEY_BYTES = {"ML-DSA-87": 2592, "SLH-DSA-SHA2-256s": 64}
# Exact canonical NIST algorithm SPKI: AlgorithmIdentifier has OID only, no
# NULL/other parameters; the BIT STRING has zero unused bits and exact length.
# SLH SHAKE-256s has the same lengths as SHA2-256s but a different OID (.30).
SPKI_PREFIX = {
    "ML-DSA-87": bytes.fromhex("30820a32300b060960864801650304031303820a2100"),
    "SLH-DSA-SHA2-256s": bytes.fromhex("3050300b0609608648016503040318034100"),
}
Reject = model.Reject


def _require(ok, code):
    model.require(ok, code)


def _budget(budget):
    if budget is None:
        budget = OperationBudget(time.monotonic() + DEFAULT_OPERATION_SECONDS)
    _require(isinstance(budget, OperationBudget), "budget:type")
    budget.check()
    return budget


def _frame(domain, *parts):
    return domain + b"".join(len(part).to_bytes(8, "big") + part for part in parts)


def _snapshot_json(value, where):
    """Bound Python-API inputs before serialization, then detach mutable inputs.

    Network callers must also bound their outer transport before decoding. This
    helper covers policy/context/statement objects, never the larger signature
    hex transport. It prevents mutable caller dictionaries changing mid-verify.
    """
    pending, nodes, characters = [(value, 0)], 0, 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        _require(nodes <= MAX_JSON_NODES and depth <= model.MAX_DEPTH,
                 where + ":structure-limit")
        if type(item) is dict:
            _require(len(item) <= MAX_JSON_NODES, where + ":structure-limit")
            for key, child in item.items():
                _require(type(key) is str and len(key) <= 128, where + ":key")
                characters += len(key)
                pending.append((child, depth + 1))
        elif type(item) is list:
            _require(len(item) <= MAX_JSON_NODES, where + ":structure-limit")
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            characters += len(item)
        elif type(item) is int:
            _require(0 <= item < (1 << 64), where + ":integer")
        else:
            _require(item is None, where + ":json-type")
        _require(characters <= MAX_JSON, where + ":size")
    try:
        raw = model.canonical(value)
        _require(len(raw) <= MAX_JSON, where + ":size")
        return model.strict_json(raw)
    except (UnicodeError, RecursionError, TypeError) as error:
        raise Reject(where + ":json") from error


def key_id(suite, public_der):
    """SHA512 identity over framed suite and exact canonical public-key bytes.

    Exact OIDs prevent OpenSSL autodetection from substituting an equally sized
    algorithm, such as SLH-DSA-SHAKE-256s for SLH-DSA-SHA2-256s.
    """
    _require(type(suite) is str and suite in SUITES, "key:suite")
    _require(type(public_der) is bytes, "key:der-type")
    prefix = SPKI_PREFIX[suite]
    _require(len(public_der) == len(prefix) + PUBLIC_KEY_BYTES[suite], "key:der-length")
    _require(public_der.startswith(prefix), "key:der-algorithm-or-encoding")
    return hashlib.sha512(_frame(KEY_DOMAIN, suite.encode("ascii"), public_der)).hexdigest()


def validate_roster(policy, public_keys):
    """Validate the whole AND policy and every key, including unused members.

    The mapping must be sourced from the caller's trusted owner/roster store.
    Passing a self-declared policy and keys proves only internal consistency.
    """
    policy = model.validate_policy(_snapshot_json(policy, "policy"))
    _require(type(public_keys) is dict and len(public_keys) == 6, "roster:public-key-count")
    expected = set(key for suite in SUITES for key in policy["rosters"][suite])
    _require(set(public_keys) == expected, "roster:public-key-set")
    snapshot = {}
    for suite in SUITES:
        for signer_id in policy["rosters"][suite]:
            public_der = public_keys[signer_id]
            _require(key_id(suite, public_der) == signer_id, "roster:key-id-mismatch")
            snapshot[signer_id] = public_der
    return snapshot


def _statement_snapshot(statement):
    snapshot = _snapshot_json(statement, "statement")
    model.statement_bytes(snapshot)
    return snapshot


def approval_message(statement):
    """Fresh approval domain followed by the framed, complete v1 statement."""
    statement = _statement_snapshot(statement)
    return _message(_frame(APPROVAL_DOMAIN, model.statement_bytes(statement)))


def statement_id(statement):
    return hashlib.sha512(approval_message(statement)).hexdigest()


def operation_id(statement):
    """Semantic intent ID; selected quorums and signature bytes are excluded."""
    statement = _statement_snapshot(statement)
    return hashlib.sha512(_frame(OPERATION_DOMAIN, model.statement_bytes(statement))).hexdigest()


def possession_message(statement, suite, signer_id):
    """A successor key proves possession for its exact role and transition.

    The signed bytes include the complete old-authorized intent, complete new
    policy, network/genesis, generations, sequence, nonce, validity and payload.
    Possession in one transition or role cannot be transferred to another.
    """
    statement = _statement_snapshot(statement)
    _require(statement["action"] in model.SUCCESSOR_ACTIONS, "possession:unexpected-action")
    _require(type(suite) is str and suite in SUITES, "possession:suite")
    key = model.hex_bytes(signer_id, 64, "possession:signer")
    _require(signer_id in statement["next_policy"]["rosters"][suite], "possession:successor-roster")
    return _message(_frame(POSSESSION_DOMAIN, model.statement_bytes(statement),
                           suite.encode("ascii"), key))


def _message(message):
    _require(type(message) is bytes and 0 < len(message) <= MAX_MESSAGE, "message:type-or-size")
    return message


def _signatures(policy, rows, per_family, where):
    _require(type(rows) is list and len(rows) == per_family * 2, where + ":count")
    prepared, selected = [], {suite: set() for suite in SUITES}
    for row in rows:
        model.fields(row, ("suite", "signer_id", "signature_hex"), where)
        suite, signer_id = row["suite"], row["signer_id"]
        _require(type(suite) is str and suite in SUITES, where + ":suite")
        model.hex_bytes(signer_id, 64, where + ":signer")
        _require(signer_id in policy["rosters"][suite], where + ":roster")
        _require(signer_id not in selected[suite], where + ":duplicate")
        selected[suite].add(signer_id)
        signature = model.hex_bytes(row["signature_hex"], SIGNATURE_BYTES[suite],
                                    where + ":signature")
        prepared.append((suite, signer_id, signature))
    _require(all(len(selected[suite]) == per_family for suite in SUITES), where + ":family-quorum")
    return tuple(sorted(prepared, key=lambda item: (SUITES.index(item[0]), item[1])))


def _verify_records(public_keys, records, messages, budget):
    """No provider injection; each real verification uses the original budget."""
    budget.check()
    _require(len(records) == len(messages), "verify:message-count")
    with tempfile.TemporaryDirectory(prefix="trnm-root-native-v2-") as temporary:
        directory = Path(temporary)
        for index, ((suite, signer_id, signature), message) in enumerate(zip(records, messages)):
            budget.check()
            public_path = directory / (str(index) + ".der")
            signature_path = directory / (str(index) + ".sig")
            message_path = directory / (str(index) + ".message")
            public_path.write_bytes(public_keys[signer_id])
            signature_path.write_bytes(signature)
            message_path.write_bytes(_message(message))
            backend.run(["pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER",
                         "-inkey", str(public_path), "-in", str(message_path),
                         "-sigfile", str(signature_path)], budget=budget)
            budget.check()
    budget.check()


def no_authority():
    return {"schema": SCHEMA, "status": "HOLD", "research_only": True,
            "authorization_granted": False, "root_effect_executed": False,
            "signatures_verified": False,
            "activation_performed": False, "production_qualified": False,
            "custody_verified": False, "currentness_verified": False,
            "anchor_independence_verified": False, "external_effects_reconciled": False,
            "history_persisted": False, "whole_chain_pq_qualified": False,
            "composition_coverage_proved": False, "actual_lifetime_failure_bound": None}


def verify_quorum(policy, public_keys, message, approvals, budget=None):
    """Verify exactly 2-of-3 AND 2-of-3 over caller-constructed bytes.

    Internal callers must construct and validate their own fixed domain and
    expected complete receipt before calling this generic cryptographic helper.
    It does not check currentness, revocation, nonce consumption or authority.
    Use ``verified_statement`` for a root intent and its trusted state checks.
    """
    budget = _budget(budget)
    policy = model.validate_policy(_snapshot_json(policy, "policy"))
    keys = validate_roster(policy, public_keys)
    message = _message(message)
    records = _signatures(policy, approvals, 2, "approvals")
    budget.check()
    _verify_records(keys, records, (message,) * len(records), budget)
    return {**no_authority(), "signatures_verified": True,
            "verified_signatures": len(records), "message_sha512": hashlib.sha512(message).hexdigest(),
            "policy_sha512": model.policy_id(policy), "policy_paths_checked": list(model.ACTIONS)}


def verified_statement(policy, trusted_context, statement, current_public_keys,
                       approvals, successor_public_keys=None,
                       successor_possessions=None, budget=None):
    """Check trusted state, real current quorum and complete successor PoP.

    ``trusted_context`` must come from the separate durable owner, not from the
    request envelope. This function returns evidence and never mutates it. A
    caller must atomically compare that same state and consume the nonce before
    any effect, and must treat an uncertain commit as uncertain, never replay it.
    """
    budget = _budget(budget)
    policy = model.validate_policy(_snapshot_json(policy, "policy"))
    context = _snapshot_json(trusted_context, "context")
    statement = _statement_snapshot(statement)
    keys = validate_roster(policy, current_public_keys)
    records = _signatures(policy, approvals, 2, "approvals")
    # These derived claims are only the existing structural predicate input.
    # No claim from the request is treated as evidence of a valid signature.
    claims = [{"suite": suite, "signer_id": signer_id,
               "statement_sha512": model.statement_id(statement)}
              for suite, signer_id, _ in records]
    structure = model.inspect({"schema": model.SCHEMA, "policy": policy,
                               "context": context, "statement": statement,
                               "approval_claims": claims})
    _require(structure["model_checks_satisfied"], structure.get("reason", "context:rejected"))
    oid = operation_id(statement)
    _require(oid not in {entry["operation_id"] for entry in context["history"]},
             "history:operation-replay")
    required = statement["action"] in model.SUCCESSOR_ACTIONS
    next_keys, possessions, possession_messages = {}, (), ()
    if required:
        next_keys = validate_roster(statement["next_policy"], successor_public_keys)
        possessions = _signatures(statement["next_policy"], successor_possessions, 3, "possessions")
        possession_messages = tuple(possession_message(statement, suite, signer_id)
                                    for suite, signer_id, _ in possessions)
    else:
        _require(successor_public_keys is None and successor_possessions is None,
                 "possession:unexpected-input")
    # All inexpensive structural/length/OID checks finish before real processes.
    # Both stages share the one original absolute deadline and cancellation.
    budget.check()
    message = approval_message(statement)
    _verify_records(keys, records, (message,) * len(records), budget)
    if required:
        _verify_records(next_keys, possessions, possession_messages, budget)
    budget.check()
    return {**no_authority(), "signatures_verified": True, "current_quorum_verified": True,
            "successor_possession_required": required, "successor_possession_verified": required,
            "verified_signatures": len(records) + len(possessions),
            "statement_sha512": hashlib.sha512(message).hexdigest(), "operation_id": oid,
            "model_statement_sha512": model.statement_id(statement),
            "policy_sha512": model.policy_id(policy), "action": statement["action"],
            "policy_paths_checked": list(model.ACTIONS),
            "unknown_scenario_observations": structure["unknown_scenario_observations"],
            "unresolved_real_obligations": list(model.OBSERVATIONS) +
            ["atomic-durable-operation-owner", "complete-runtime-path-coverage"]}
