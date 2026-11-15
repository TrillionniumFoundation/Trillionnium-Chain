#!/usr/bin/env python3
"""Bounded, pure root/recovery policy refusal model; every result remains HOLD.

No signature is verified, key is loaded, nonce is consumed, journal is written,
root is changed, or runtime authorization is granted. Inputs are hypothetical
scenario declarations. In particular, a JSON claim about custody or currentness
is never evidence of either. This module extends the *path coverage* of the
separate root-signature experiment; it does not replace its cryptography.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SCHEMA = "trnm.pq-root-recovery-policy.v1"
POLICY_DOMAIN = b"TRNM/RootRecoveryResearchPolicy/v1\x00"
STATEMENT_DOMAIN = b"TRNM/RootRecoveryResearchStatement/v1\x00"
OPERATION_DOMAIN = b"TRNM/RootRecoveryResearchOperation/v1\x00"
ACTIONS = ("normal", "rotate", "revoke", "recover", "policy-change")
SUITES = ("ML-DSA-87", "SLH-DSA-SHA2-256s")
SUCCESSOR_ACTIONS = frozenset({"rotate", "recover", "policy-change"})
OBSERVATIONS = ("current-authority", "independent-custody",
                "independent-anti-rollback-anchor", "external-effect-reconciliation")
REAL_OBLIGATIONS = ("native-signature-verification", *OBSERVATIONS,
                    "atomic-durable-operation-owner", "complete-runtime-path-coverage")
MAX_INPUT = 64 * 1024
MAX_PAYLOAD = 4096
MAX_HISTORY = 128
MAX_DEPTH = 16


class Reject(ValueError):
    """A policy or scenario violates the closed research contract."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def require(ok, code):
    if not ok:
        raise Reject(code)


def fields(value, expected, where):
    require(type(value) is dict and set(value) == set(expected), where + ":fields")


def uint(value, where):
    # Decimal strings avoid cross-language JSON integer precision ambiguity.
    require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value)
            is not None and int(value) < (1 << 64), where + ":u64")
    return int(value)


def hex_bytes(value, size, where):
    require(type(value) is str and len(value) == size * 2
            and re.fullmatch(r"[0-9a-f]+", value) is not None,
            where + ":hex")
    return bytes.fromhex(value)


def bounded_list(value, maximum, where):
    require(type(value) is list and len(value) <= maximum, where + ":list")
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def sha512(domain, data):
    return hashlib.sha512(domain + len(data).to_bytes(8, "big") + data).hexdigest()


def strict_json(raw):
    require(type(raw) in (str, bytes), "json:type")
    try:
        encoded = raw.encode("utf-8") if type(raw) is str else raw
        require(len(encoded) <= MAX_INPUT, "json:size")
        text = encoded.decode("utf-8")
    except UnicodeError as error:
        raise Reject("json:utf8") from error

    def pairs(rows):
        out = {}
        for key, value in rows:
            require(key not in out, "json:duplicate-field")
            out[key] = value
        return out

    def integer(text):
        require(len(text) <= 20, "json:integer-size")
        return int(text)

    def not_float(_text):
        raise Reject("json:noninteger")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_int=integer,
                           parse_float=not_float, parse_constant=not_float)
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            require(depth <= MAX_DEPTH, "json:depth")
            if type(item) is dict:
                pending.extend((x, depth + 1) for x in item.values())
            elif type(item) is list:
                pending.extend((x, depth + 1) for x in item)
            elif type(item) is str:
                item.encode("utf-8")
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, Reject):
            raise
        raise Reject("json:invalid") from error


def validate_policy(policy):
    """Validate every accepted action, including inactive recovery alternatives."""
    fields(policy, ("schema", "rules", "rosters"), "policy")
    require(policy["schema"] == SCHEMA, "policy:schema")
    fields(policy["rules"], ACTIONS, "policy:actions")
    fields(policy["rosters"], SUITES, "policy:suites")
    all_keys = []
    for suite in SUITES:
        keys = bounded_list(policy["rosters"][suite], 3, "roster")
        require(len(keys) == 3, "roster:size")
        for key in keys:
            hex_bytes(key, 64, "roster:key")
        require(keys == sorted(set(keys)), "roster:duplicate-or-order")
        all_keys.extend(keys)
    require(len(set(all_keys)) == 6, "roster:cross-family-alias")
    for action in ACTIONS:
        rule = policy["rules"][action]
        fields(rule, ("operator", "requirements"), "rule")
        require(rule["operator"] == "AND", "rule:operator")
        requirements = bounded_list(rule["requirements"], 2, "rule:requirements")
        require(len(requirements) == 2, "rule:family-count")
        for row, suite in zip(requirements, SUITES):
            fields(row, ("suite", "quorum"), "requirement")
            require(row["suite"] == suite, "rule:suite")
            require(type(row["quorum"]) is int and row["quorum"] == 2,
                    "rule:quorum")
    return policy


def policy_id(policy):
    return sha512(POLICY_DOMAIN, canonical(validate_policy(policy)))


SCOPE_FIELDS = ("network", "genesis", "owner_generation", "key_epoch", "previous_state")
STATEMENT_FIELDS = ("schema", "action", *SCOPE_FIELDS, "policy_sha512", "sequence",
                    "nonce", "valid_from", "valid_until", "payload_hex", "next_policy")
CONTEXT_FIELDS = (*SCOPE_FIELDS, "last_sequence", "now_height", "anchor", "history",
                  "revoked_signers", "observations")
ANCHOR_FIELDS = (*SCOPE_FIELDS, "last_sequence", "policy_sha512")


def validate_scope(value):
    for name in ("network", "genesis"):
        hex_bytes(value[name], 32, name)
    hex_bytes(value["previous_state"], 64, "previous-state")
    for name in ("owner_generation", "key_epoch"):
        uint(value[name], name)


def statement_bytes(statement):
    """Complete research statement bytes, never a signature-byte identity."""
    fields(statement, STATEMENT_FIELDS, "statement")
    require(statement["schema"] == SCHEMA, "statement:schema")
    require(statement["action"] in ACTIONS, "statement:action")
    validate_scope(statement)
    hex_bytes(statement["policy_sha512"], 64, "policy-id")
    hex_bytes(statement["nonce"], 32, "nonce")
    for name in ("sequence", "valid_from", "valid_until"):
        uint(statement[name], name)
    require(uint(statement["valid_from"], "valid-from") <=
            uint(statement["valid_until"], "valid-until"), "statement:validity-order")
    payload = statement["payload_hex"]
    require(type(payload) is str and len(payload) <= MAX_PAYLOAD * 2 and
            len(payload) % 2 == 0 and re.fullmatch(r"[0-9a-f]*", payload) is not None,
            "statement:payload")
    if statement["action"] in SUCCESSOR_ACTIONS:
        validate_policy(statement["next_policy"])
    else:
        require(statement["next_policy"] is None, "statement:unexpected-successor")
    # Fresh domain, fixed fields, complete payload and complete successor policy.
    return STATEMENT_DOMAIN + canonical(statement)


def statement_id(statement):
    return hashlib.sha512(statement_bytes(statement)).hexdigest()


def operation_id(statement):
    """Semantic operation identity excludes signatures and selected witnesses.

    Nonce history is checked separately: changing even one signed intent field
    must not allow reuse of an already observed nonce under another digest.
    """
    return sha512(OPERATION_DOMAIN, statement_bytes(statement))


def _inspect(scenario):
    fields(scenario, ("schema", "policy", "context", "statement", "approval_claims"), "scenario")
    require(scenario["schema"] == SCHEMA, "scenario:schema")
    policy = validate_policy(scenario["policy"])
    context, statement = scenario["context"], scenario["statement"]
    fields(context, CONTEXT_FIELDS, "context")
    validate_scope(context)
    uint(context["last_sequence"], "last-sequence")
    now = uint(context["now_height"], "now-height")
    current_policy_id = policy_id(policy)
    sid, oid = statement_id(statement), operation_id(statement)
    for name in SCOPE_FIELDS:
        require(statement[name] == context[name], "context-mismatch:" + name)
    require(statement["policy_sha512"] == current_policy_id, "context-mismatch:policy")
    require(uint(statement["sequence"], "sequence") ==
            uint(context["last_sequence"], "last-sequence") + 1, "context-mismatch:sequence")
    require(uint(statement["valid_from"], "valid-from") <= now <=
            uint(statement["valid_until"], "valid-until"), "statement:expired-or-future")

    anchor = context["anchor"]
    fields(anchor, ANCHOR_FIELDS, "anchor")
    validate_scope(anchor)
    uint(anchor["last_sequence"], "anchor-sequence")
    hex_bytes(anchor["policy_sha512"], 64, "anchor-policy")
    for name in SCOPE_FIELDS + ("last_sequence",):
        require(anchor[name] == context[name], "anchor-mismatch:" + name)
    require(anchor["policy_sha512"] == current_policy_id, "anchor-mismatch:policy")

    history = bounded_list(context["history"], MAX_HISTORY, "history")
    nonces, operations = [], []
    for item in history:
        fields(item, ("nonce", "operation_id"), "history-item")
        hex_bytes(item["nonce"], 32, "history-nonce")
        hex_bytes(item["operation_id"], 64, "history-operation")
        nonces.append(item["nonce"])
        operations.append(item["operation_id"])
    require(nonces == sorted(set(nonces)) and len(set(operations)) == len(operations),
            "history:duplicate-or-order")
    require(statement["nonce"] not in nonces, "history:nonce-reuse")
    require(oid not in operations, "history:operation-replay")

    revoked = bounded_list(context["revoked_signers"], MAX_HISTORY, "revoked-signers")
    for key in revoked:
        hex_bytes(key, 64, "revoked-signer")
    require(revoked == sorted(set(revoked)), "revoked-signers:duplicate-or-order")
    claims = bounded_list(scenario["approval_claims"], 4, "approval-claims")
    require(len(claims) == 4, "approval-claims:quorum")
    selected = {suite: [] for suite in SUITES}
    for row in claims:
        fields(row, ("suite", "signer_id", "statement_sha512"), "approval-claim")
        require(row["suite"] in SUITES, "approval-claim:suite")
        key = row["signer_id"]
        hex_bytes(key, 64, "claim-signer")
        hex_bytes(row["statement_sha512"], 64, "claim-statement")
        require(key in policy["rosters"][row["suite"]], "approval-claim:current-roster")
        require(key not in revoked, "approval-claim:revoked")
        require(row["statement_sha512"] == sid, "approval-claim:cross-statement")
        selected[row["suite"]].append(key)
    for suite in SUITES:
        require(len(selected[suite]) == 2 and len(set(selected[suite])) == 2,
                "approval-claims:distinct-family-quorum")

    observations = context["observations"]
    fields(observations, OBSERVATIONS, "observations")
    for observation in observations.values():
        require(observation in ("unknown", "scenario-assumed") and type(observation) is str,
                "observations:unsupported-evidence-claim")
    unknown = sorted(key for key, value in observations.items() if value == "unknown")
    return {"model_checks_satisfied": True,
            "model_decision": "HOLD_UNRESOLVED_SCENARIO" if unknown else "SCENARIO_CONSTRAINTS_SATISFIED",
            "action": statement["action"], "statement_sha512": sid, "operation_id": oid,
            "policy_paths_checked": list(ACTIONS), "approval_claims_checked": len(claims),
            "unknown_scenario_observations": unknown,
            "unresolved_real_obligations": list(REAL_OBLIGATIONS) +
            (["successor-key-possession-and-handoff"] if statement["next_policy"] else [])}


def no_authority():
    """The same fixed no-effect boundary accompanies every diagnostic."""
    return {"schema": SCHEMA, "status": "HOLD", "research_only": True,
            "authorization_granted": False, "root_effect_executed": False,
            "activation_performed": False, "production_qualified": False,
            "signatures_verified": False, "custody_verified": False,
            "currentness_verified": False, "anchor_independence_verified": False,
            "external_effects_reconciled": False, "history_persisted": False}


def inspect(scenario):
    """Return a diagnostic. Even a completely declared scenario cannot authorize."""
    try:
        return {**_inspect(scenario), **no_authority()}
    except Reject as error:
        return {"model_checks_satisfied": False, "model_decision": "REJECTED_SCENARIO",
                "reason": error.code, "unresolved_real_obligations": list(REAL_OBLIGATIONS),
                **no_authority()}


def example(action="recover", pairs=((0, 1), (0, 1))):
    """Fabricated public IDs, never key material, cryptography or live evidence."""
    require(action in ACTIONS, "example:action")
    policy = {"schema": SCHEMA,
              "rules": {a: {"operator": "AND", "requirements":
                                [{"suite": s, "quorum": 2} for s in SUITES]} for a in ACTIONS},
              "rosters": {s: [bytes([10 * i + j + 1]).hex() * 64 for j in range(3)]
                          for i, s in enumerate(SUITES)}}
    scope = {"network": "11" * 32, "genesis": "22" * 32, "owner_generation": "7",
             "key_epoch": "3", "previous_state": "33" * 64}
    context = {**scope, "last_sequence": "40", "now_height": "150",
               "anchor": {**scope, "last_sequence": "40", "policy_sha512": policy_id(policy)},
               "history": [], "revoked_signers": [],
               "observations": {name: "unknown" for name in OBSERVATIONS}}
    statement = {"schema": SCHEMA, "action": action, **scope,
                 "policy_sha512": policy_id(policy), "sequence": "41", "nonce": "44" * 32,
                 "valid_from": "100", "valid_until": "200",
                 "payload_hex": b"public research fixture; no root effect".hex(),
                 "next_policy": json.loads(json.dumps(policy)) if action in SUCCESSOR_ACTIONS else None}
    digest = statement_id(statement)
    claims = [{"suite": s, "signer_id": policy["rosters"][s][index], "statement_sha512": digest}
              for s, pair in zip(SUITES, pairs) for index in pair]
    return {"schema": SCHEMA, "policy": policy, "context": context,
            "statement": statement, "approval_claims": claims}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path, help="bounded scenario JSON file")
    source.add_argument("--example", action="store_true", help="inspect an unknown-evidence public scenario")
    args = parser.parse_args(argv)
    try:
        if args.example:
            scenario = example()
        else:
            with args.input.open("rb") as stream:
                scenario = strict_json(stream.read(MAX_INPUT + 1))
        result = inspect(scenario)
    except (OSError, Reject) as error:
        result = {"model_checks_satisfied": False, "model_decision": "REJECTED_INPUT",
                  "reason": str(error), "unresolved_real_obligations": list(REAL_OBLIGATIONS),
                  **no_authority()}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    # Zero means only that the hypothetical structure passed; status is HOLD.
    return 0 if result["model_checks_satisfied"] else 1


if __name__ == "__main__":
    sys.exit(main())
