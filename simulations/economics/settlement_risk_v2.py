#!/usr/bin/env python3
"""Candidate-only economic attack and concentration model for G2E."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Iterable


class Reject(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=asdict,
    ).encode("utf-8")


def commitment(label: str, value: object) -> str:
    h = hashlib.sha256()
    h.update(label.encode("ascii"))
    h.update(b"\x00")
    raw = canonical(value)
    h.update(len(raw).to_bytes(8, "big"))
    h.update(raw)
    return h.hexdigest()


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
        if not self.policy_id:
            raise Reject("policy-id")
        for name, value in (
            ("min-provider-bond", self.min_provider_bond_bps),
            ("min-challenge-bond", self.min_challenge_bond_bps),
            ("max-provider-exposure", self.max_provider_exposure_bps),
            ("max-owner-exposure", self.max_owner_exposure_bps),
        ):
            if not isinstance(value, int) or value < 0 or value > 10_000:
                raise Reject(name)
        if self.max_provider_exposure_bps == 0 or self.max_owner_exposure_bps == 0:
            raise Reject("zero-exposure-cap")


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
    if amount < 0 or total <= 0:
        raise Reject("bps-input")
    return amount * 10_000 // total


def validate_batch(
    policy: RiskPolicyV2,
    actors: Iterable[ActorV2],
    facts: Iterable[SettlementRiskFactV2],
) -> dict[str, object]:
    policy.validate()
    actor_rows = list(actors)
    if not actor_rows:
        raise Reject("actors-empty")
    actor_map: dict[str, ActorV2] = {}
    for actor in actor_rows:
        if not actor.actor_id or not actor.beneficial_owner or not actor.roles:
            raise Reject("actor-shape")
        if actor.actor_id in actor_map:
            raise Reject("duplicate-actor")
        actor_map[actor.actor_id] = actor

    rows = sorted(list(facts), key=lambda item: item.task_id)
    if not rows:
        raise Reject("facts-empty")
    task_ids = [row.task_id for row in rows]
    if any(not task_id for task_id in task_ids) or len(task_ids) != len(set(task_ids)):
        raise Reject("duplicate-or-empty-task")

    total_escrow = 0
    provider_exposure: dict[str, int] = {}
    owner_exposure: dict[str, int] = {}
    canonical_rows: list[dict[str, object]] = []

    for row in rows:
        if row.policy_id != policy.policy_id:
            raise Reject("policy-mismatch")
        if row.escrow_amount <= 0 or row.provider_bond < 0 or row.challenge_bond < 0:
            raise Reject("amount-shape")
        if row.result_status not in {"ResultFinal", "ResultRejected", "Cancelled", "Expired"}:
            raise Reject("result-status")
        try:
            payer = actor_map[row.payer]
            provider = actor_map[row.provider]
            verifier = actor_map[row.verifier]
        except KeyError as exc:
            raise Reject("unknown-actor") from exc
        _required_role(payer, "payer")
        _required_role(provider, "provider")
        _required_role(verifier, "verifier")
        if row.funding_owner != payer.beneficial_owner:
            raise Reject("wash-funding-source")
        if not policy.allow_related_party and payer.beneficial_owner == provider.beneficial_owner:
            raise Reject("payer-provider-related")
        if (
            not policy.allow_provider_verifier_overlap
            and provider.beneficial_owner == verifier.beneficial_owner
        ):
            raise Reject("provider-verifier-related")
        if row.provider_bond * 10_000 < row.escrow_amount * policy.min_provider_bond_bps:
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
            if row.challenge_bond * 10_000 < row.escrow_amount * policy.min_challenge_bond_bps:
                raise Reject("challenge-bond-under-collateralized")
        elif row.challenger is not None or row.challenge_bond != 0:
            raise Reject("unexpected-challenge-facts")

        total_escrow += row.escrow_amount
        provider_exposure[row.provider] = provider_exposure.get(row.provider, 0) + row.escrow_amount
        owner_exposure[provider.beneficial_owner] = (
            owner_exposure.get(provider.beneficial_owner, 0) + row.escrow_amount
        )
        canonical_rows.append(
            {
                **asdict(row),
                "payer_owner": payer.beneficial_owner,
                "provider_owner": provider.beneficial_owner,
                "verifier_owner": verifier.beneficial_owner,
                "challenger_owner": challenger_owner,
            }
        )

    for amount in provider_exposure.values():
        if _bps(amount, total_escrow) > policy.max_provider_exposure_bps:
            raise Reject("provider-concentration")
    for amount in owner_exposure.values():
        if _bps(amount, total_escrow) > policy.max_owner_exposure_bps:
            raise Reject("beneficial-owner-sybil-concentration")

    risk_view = {
        "policy": asdict(policy),
        "tasks": canonical_rows,
        "provider_exposure": dict(sorted(provider_exposure.items())),
        "owner_exposure": dict(sorted(owner_exposure.items())),
        "total_escrow": total_escrow,
    }
    return {
        "risk_root": commitment("trnm.settlement-risk.v2", risk_view),
        "tasks": len(rows),
        "total_escrow": total_escrow,
        "provider_exposure": risk_view["provider_exposure"],
        "owner_exposure": risk_view["owner_exposure"],
        "settlement_authority": False,
        "governance_authority": False,
        "poco_weight_eligible": False,
        "production_activation": False,
    }


def fixtures() -> tuple[RiskPolicyV2, list[ActorV2], list[SettlementRiskFactV2]]:
    policy = RiskPolicyV2(
        policy_id="risk-policy-v2",
        min_provider_bond_bps=1_000,
        min_challenge_bond_bps=100,
        max_provider_exposure_bps=4_000,
        max_owner_exposure_bps=4_000,
    )
    actors = [
        ActorV2("payer-1", "owner-payer-1", frozenset({"payer"})),
        ActorV2("payer-2", "owner-payer-2", frozenset({"payer"})),
        ActorV2("payer-3", "owner-payer-3", frozenset({"payer"})),
        ActorV2("provider-1", "owner-provider-1", frozenset({"provider"})),
        ActorV2("provider-2", "owner-provider-2", frozenset({"provider"})),
        ActorV2("provider-3", "owner-provider-3", frozenset({"provider"})),
        ActorV2("provider-1-sybil", "owner-provider-1", frozenset({"provider"})),
        ActorV2("verifier-1", "owner-verifier-1", frozenset({"verifier"})),
        ActorV2("verifier-2", "owner-verifier-2", frozenset({"verifier"})),
        ActorV2("verifier-3", "owner-verifier-3", frozenset({"verifier"})),
        ActorV2("challenger-1", "owner-challenger-1", frozenset({"challenger"})),
        ActorV2("wrong-role", "owner-wrong-role", frozenset({"payer"})),
    ]
    facts = [
        SettlementRiskFactV2(
            "task-1", "payer-1", "provider-1", "verifier-1", None,
            "owner-payer-1", 1_000, 150, 0, "ResultFinal", policy.policy_id
        ),
        SettlementRiskFactV2(
            "task-2", "payer-2", "provider-2", "verifier-2", "challenger-1",
            "owner-payer-2", 1_000, 150, 20, "ResultRejected", policy.policy_id
        ),
        SettlementRiskFactV2(
            "task-3", "payer-3", "provider-3", "verifier-3", None,
            "owner-payer-3", 1_000, 150, 0, "Cancelled", policy.policy_id
        ),
    ]
    return policy, actors, facts


def self_test() -> dict[str, object]:
    policy, actors, facts = fixtures()
    forward = validate_batch(policy, actors, facts)
    reverse = validate_batch(policy, actors, reversed(facts))
    if forward["risk_root"] != reverse["risk_root"]:
        raise Reject("ordering-mev-root-drift")

    negatives: list[dict[str, str]] = []

    def reject(name: str, fn) -> None:
        try:
            fn()
        except Reject as exc:
            negatives.append({"case": name, "error": str(exc)})
        else:
            raise AssertionError(f"accepted:{name}")

    actor_map = {actor.actor_id: actor for actor in actors}

    related_actors = [
        actor if actor.actor_id != "payer-1"
        else ActorV2("payer-1", actor_map["provider-1"].beneficial_owner, actor.roles)
        for actor in actors
    ]
    related_facts = [
        SettlementRiskFactV2(**{**asdict(facts[0]), "funding_owner": actor_map["provider-1"].beneficial_owner}),
        *facts[1:],
    ]
    reject("payer-provider-related", lambda: validate_batch(policy, related_actors, related_facts))

    colluding_actors = [
        actor if actor.actor_id != "verifier-1"
        else ActorV2("verifier-1", actor_map["provider-1"].beneficial_owner, actor.roles)
        for actor in actors
    ]
    reject("provider-verifier-related", lambda: validate_batch(policy, colluding_actors, facts))

    challenger_conflict = [
        actor if actor.actor_id != "challenger-1"
        else ActorV2("challenger-1", actor_map["provider-2"].beneficial_owner, actor.roles)
        for actor in actors
    ]
    reject("challenger-conflict", lambda: validate_batch(policy, challenger_conflict, facts))

    low_provider_bond = [
        SettlementRiskFactV2(**{**asdict(facts[0]), "provider_bond": 1}),
        *facts[1:],
    ]
    reject("provider-bond-under-collateralized", lambda: validate_batch(policy, actors, low_provider_bond))

    low_challenge_bond = [
        facts[0],
        SettlementRiskFactV2(**{**asdict(facts[1]), "challenge_bond": 0}),
        facts[2],
    ]
    reject("challenge-bond-under-collateralized", lambda: validate_batch(policy, actors, low_challenge_bond))

    concentrated = [
        facts[0],
        SettlementRiskFactV2(**{**asdict(facts[1]), "provider": "provider-1", "verifier": "verifier-2"}),
        SettlementRiskFactV2(**{**asdict(facts[2]), "provider": "provider-1", "verifier": "verifier-3"}),
    ]
    reject("provider-concentration", lambda: validate_batch(policy, actors, concentrated))

    sybil = [
        facts[0],
        SettlementRiskFactV2(**{**asdict(facts[1]), "provider": "provider-1-sybil", "verifier": "verifier-2"}),
        facts[2],
    ]
    reject("beneficial-owner-sybil-concentration", lambda: validate_batch(policy, actors, sybil))

    reject("duplicate-task", lambda: validate_batch(policy, actors, [facts[0], facts[0], facts[2]]))

    unknown = [SettlementRiskFactV2(**{**asdict(facts[0]), "provider": "missing"}), *facts[1:]]
    reject("unknown-actor", lambda: validate_batch(policy, actors, unknown))

    wrong_role = [SettlementRiskFactV2(**{**asdict(facts[0]), "provider": "wrong-role"}), *facts[1:]]
    reject("wrong-role", lambda: validate_batch(policy, actors, wrong_role))

    wash = [
        SettlementRiskFactV2(**{**asdict(facts[0]), "funding_owner": "owner-provider-1"}),
        *facts[1:],
    ]
    reject("wash-funding-source", lambda: validate_batch(policy, actors, wash))

    return {
        "schema": "trnm-settlement-risk-evidence-v2",
        "positive": 4,
        "negative": negatives,
        "risk_root": forward["risk_root"],
        "ordering_invariant": True,
        "candidate_only": True,
        "settlement_authority": False,
        "governance_authority": False,
        "poco_weight_eligible": False,
        "production_activation": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if not args.self_test:
        raise SystemExit("use --self-test")
    print(json.dumps(self_test(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
