#!/usr/bin/env python3
"""Candidate settlement risk model; caller identity labels are NOT attestations."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass, replace
from typing import Iterable, TypeVar

U128_MAX = (1 << 128) - 1
MAX_ACTORS = 4096
MAX_FACTS = 1024
ROLES = frozenset({"payer", "provider", "verifier", "challenger"})
T = TypeVar("T")


class Reject(ValueError):
    pass


def uint(value: int, label: str, maximum: int = U128_MAX) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise Reject(label)
    return value


def checked_add(left: int, right: int) -> int:
    return uint(uint(left, "amount-shape") + uint(right, "amount-shape"), "arithmetic-overflow")


def checked_mul(left: int, right: int) -> int:
    return uint(uint(left, "amount-shape") * uint(right, "amount-shape"), "arithmetic-overflow")


def bounded(values: Iterable[T], maximum: int, label: str) -> list[T]:
    result: list[T] = []
    for value in values:
        if len(result) == maximum:
            raise Reject(label)
        result.append(value)
    return result


def identifier(value: str, label: str) -> None:
    if (not isinstance(value, str) or not 1 <= len(value) <= 128
            or any(not 33 <= ord(character) <= 126 for character in value)):
        raise Reject(label)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False, default=asdict).encode("utf-8")


def commitment(label: str, value: object) -> str:
    raw = canonical(value)
    return hashlib.sha256(label.encode("ascii") + b"\x00"
                          + len(raw).to_bytes(8, "big") + raw).hexdigest()


@dataclass(frozen=True)
class ActorV2:
    actor_id: str
    beneficial_owner: str
    roles: frozenset[str]


@dataclass(frozen=True)
class RiskPolicyV2:
    policy_id: str
    min_provider_bond_bps: int
    min_challenge_bond_bps: int
    max_provider_exposure_bps: int
    max_owner_exposure_bps: int
    allow_related_party: bool = False
    allow_provider_verifier_overlap: bool = False

    def validate(self) -> None:
        identifier(self.policy_id, "policy-id")
        for name, value in (("min-provider-bond", self.min_provider_bond_bps),
                            ("min-challenge-bond", self.min_challenge_bond_bps),
                            ("max-provider-exposure", self.max_provider_exposure_bps),
                            ("max-owner-exposure", self.max_owner_exposure_bps)):
            uint(value, name, 10_000)
        if self.max_provider_exposure_bps == 0 or self.max_owner_exposure_bps == 0:
            raise Reject("zero-exposure-cap")
        if type(self.allow_related_party) is not bool or type(self.allow_provider_verifier_overlap) is not bool:
            raise Reject("policy-boolean")


@dataclass(frozen=True)
class SettlementRiskFactV2:
    task_id: str
    payer: str
    provider: str
    verifier: str
    challenger: str | None
    funding_owner: str
    escrow_amount: int
    provider_bond: int
    challenge_bond: int
    result_status: str
    policy_id: str


def _required_role(actor: ActorV2, role: str) -> None:
    if role not in actor.roles:
        raise Reject(f"role:{role}")


def _bps(amount: int, total: int) -> int:
    """Display only. Admission compares exact products, never this rounded value."""
    uint(amount, "bps-input")
    uint(total, "bps-input")
    if total == 0:
        raise Reject("bps-input")
    return checked_mul(amount, 10_000) // total


def validate_batch(policy: RiskPolicyV2, actors: Iterable[ActorV2],
                   facts: Iterable[SettlementRiskFactV2]) -> dict[str, object]:
    policy.validate()
    actor_map: dict[str, ActorV2] = {}
    for actor in bounded(actors, MAX_ACTORS, "actors-limit"):
        if not isinstance(actor, ActorV2):
            raise Reject("actor-shape")
        identifier(actor.actor_id, "actor-shape")
        identifier(actor.beneficial_owner, "actor-shape")
        if not isinstance(actor.roles, frozenset) or not actor.roles or not actor.roles <= ROLES:
            raise Reject("actor-shape")
        if actor.actor_id in actor_map:
            raise Reject("duplicate-actor")
        actor_map[actor.actor_id] = actor
    if not actor_map:
        raise Reject("actors-empty")

    rows = bounded(facts, MAX_FACTS, "facts-limit")
    if not rows:
        raise Reject("facts-empty")
    task_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, SettlementRiskFactV2):
            raise Reject("fact-shape")
        identifier(row.task_id, "duplicate-or-empty-task")
        if row.task_id in task_ids:
            raise Reject("duplicate-or-empty-task")
        task_ids.add(row.task_id)
        for value in (row.payer, row.provider, row.verifier, row.funding_owner, row.policy_id):
            identifier(value, "fact-identity")
        if row.challenger is not None:
            identifier(row.challenger, "fact-identity")
        for amount in (row.escrow_amount, row.provider_bond, row.challenge_bond):
            uint(amount, "amount-shape")
        if row.escrow_amount == 0:
            raise Reject("amount-shape")
    rows.sort(key=lambda item: item.task_id)
    total_escrow = 0
    provider_exposure: dict[str, int] = {}
    owner_exposure: dict[str, int] = {}
    canonical_rows: list[dict[str, object]] = []
    for row in rows:
        if row.policy_id != policy.policy_id:
            raise Reject("policy-mismatch")
        if not isinstance(row.result_status, str) or row.result_status not in {"ResultFinal", "ResultRejected", "Cancelled", "Expired"}:
            raise Reject("result-status")
        try:
            payer, provider, verifier = (actor_map[key] for key in (row.payer, row.provider, row.verifier))
        except KeyError as exc:
            raise Reject("unknown-actor") from exc
        for actor, role in ((payer, "payer"), (provider, "provider"), (verifier, "verifier")):
            _required_role(actor, role)
        if row.funding_owner != payer.beneficial_owner:
            raise Reject("wash-funding-source")
        if not policy.allow_related_party and payer.beneficial_owner == provider.beneficial_owner:
            raise Reject("payer-provider-related")
        if not policy.allow_provider_verifier_overlap and provider.beneficial_owner == verifier.beneficial_owner:
            raise Reject("provider-verifier-related")
        if checked_mul(row.provider_bond, 10_000) < checked_mul(row.escrow_amount, policy.min_provider_bond_bps):
            raise Reject("provider-bond-under-collateralized")
        challenger_owner = None
        if row.result_status == "ResultRejected":
            if not row.challenger:
                raise Reject("challenger-required")
            try:
                challenger = actor_map[row.challenger]
            except KeyError as exc:
                raise Reject("unknown-actor") from exc
            _required_role(challenger, "challenger")
            challenger_owner = challenger.beneficial_owner
            if challenger_owner in {provider.beneficial_owner, verifier.beneficial_owner}:
                raise Reject("challenger-conflict-of-interest")
            if checked_mul(row.challenge_bond, 10_000) < checked_mul(row.escrow_amount, policy.min_challenge_bond_bps):
                raise Reject("challenge-bond-under-collateralized")
        elif row.challenger is not None or row.challenge_bond != 0:
            raise Reject("unexpected-challenge-facts")
        total_escrow = checked_add(total_escrow, row.escrow_amount)
        provider_exposure[row.provider] = checked_add(provider_exposure.get(row.provider, 0), row.escrow_amount)
        owner = provider.beneficial_owner
        owner_exposure[owner] = checked_add(owner_exposure.get(owner, 0), row.escrow_amount)
        canonical_rows.append({**asdict(row), "payer_owner": payer.beneficial_owner,
                               "provider_owner": owner, "verifier_owner": verifier.beneficial_owner,
                               "challenger_owner": challenger_owner})
    for exposure, cap, reason in ((provider_exposure, policy.max_provider_exposure_bps, "provider-concentration"),
                                  (owner_exposure, policy.max_owner_exposure_bps, "beneficial-owner-sybil-concentration")):
        for amount in exposure.values():
            if checked_mul(amount, 10_000) > checked_mul(total_escrow, cap):
                raise Reject(reason)
    risk_view = {"policy": asdict(policy), "tasks": canonical_rows,
                 "provider_exposure": dict(sorted(provider_exposure.items())),
                 "owner_exposure": dict(sorted(owner_exposure.items())), "total_escrow": total_escrow}
    return {"risk_root": commitment("trnm.settlement-risk.v2", risk_view), "tasks": len(rows),
            "total_escrow": total_escrow, "provider_exposure": risk_view["provider_exposure"],
            "owner_exposure": risk_view["owner_exposure"],
            "identity_claims_authenticated": False,
            "identity_provenance": "caller-asserted-model-labels-not-economic-independence",
            "settlement_authority": False, "governance_authority": False,
            "poco_weight_eligible": False, "production_activation": False}


def fixtures() -> tuple[RiskPolicyV2, list[ActorV2], list[SettlementRiskFactV2]]:
    policy = RiskPolicyV2("risk-policy-v2", 1000, 100, 4000, 4000)
    actors = [ActorV2(f"{role}-{i}", f"owner-{role}-{i}", frozenset({role}))
              for role in ("payer", "provider", "verifier") for i in range(1, 4)]
    actors += [ActorV2("provider-1-sybil", "owner-provider-1", frozenset({"provider"})),
               ActorV2("challenger-1", "owner-challenger-1", frozenset({"challenger"})),
               ActorV2("wrong-role", "owner-wrong-role", frozenset({"payer"}))]
    facts = [SettlementRiskFactV2("task-1", "payer-1", "provider-1", "verifier-1", None,
                                  "owner-payer-1", 1000, 150, 0, "ResultFinal", policy.policy_id),
             SettlementRiskFactV2("task-2", "payer-2", "provider-2", "verifier-2", "challenger-1",
                                  "owner-payer-2", 1000, 150, 20, "ResultRejected", policy.policy_id),
             SettlementRiskFactV2("task-3", "payer-3", "provider-3", "verifier-3", None,
                                  "owner-payer-3", 1000, 150, 0, "Cancelled", policy.policy_id)]
    return policy, actors, facts


def self_test() -> dict[str, object]:
    policy, actors, facts = fixtures()
    # Four *executed* positives, not a hard-coded claim for two executions.
    positives = [validate_batch(policy, a, f) for a, f in
                 ((actors, facts), (actors, reversed(facts)),
                  (reversed(actors), facts), (reversed(actors), reversed(facts)))]
    if len({item["risk_root"] for item in positives}) != 1:
        raise Reject("ordering-mev-root-drift")
    negatives: list[dict[str, str]] = []

    def reject(name: str, a: list[ActorV2], f: list[SettlementRiskFactV2]) -> None:
        try:
            validate_batch(policy, a, f)
        except Reject as exc:
            negatives.append({"case": name, "error": str(exc)})
        else:
            raise AssertionError(f"accepted:{name}")

    def relabel(actor_id: str, owner: str) -> list[ActorV2]:
        return [replace(a, beneficial_owner=owner) if a.actor_id == actor_id else a for a in actors]

    reject("payer-provider-related", relabel("payer-1", "owner-provider-1"),
           [replace(facts[0], funding_owner="owner-provider-1"), *facts[1:]])
    reject("provider-verifier-related", relabel("verifier-1", "owner-provider-1"), facts)
    reject("challenger-conflict", relabel("challenger-1", "owner-provider-2"), facts)
    reject("provider-bond-under-collateralized", actors, [replace(facts[0], provider_bond=1), *facts[1:]])
    reject("challenge-bond-under-collateralized", actors, [facts[0], replace(facts[1], challenge_bond=0), facts[2]])
    reject("provider-concentration", actors, [replace(f, provider="provider-1") for f in facts])
    reject("beneficial-owner-sybil-concentration", actors,
           [facts[0], replace(facts[1], provider="provider-1-sybil"), facts[2]])
    reject("duplicate-task", actors, [facts[0], facts[0], facts[2]])
    reject("unknown-actor", actors, [replace(facts[0], provider="missing"), *facts[1:]])
    reject("wrong-role", actors, [replace(facts[0], provider="wrong-role"), *facts[1:]])
    reject("wash-funding-source", actors, [replace(facts[0], funding_owner="owner-provider-1"), *facts[1:]])
    return {"schema": "trnm-settlement-risk-evidence-v2", "positive": len(positives),
            "negative": negatives, "risk_root": positives[0]["risk_root"], "ordering_invariant": True,
            "candidate_only": True, "identity_claims_authenticated": False,
            "settlement_authority": False, "governance_authority": False,
            "poco_weight_eligible": False, "production_activation": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    if not parser.parse_args().self_test:
        raise SystemExit("use --self-test")
    print(json.dumps(self_test(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
