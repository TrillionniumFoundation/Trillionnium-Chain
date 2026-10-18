"""Independent fixed-roster oracle for native evaluation quorum development v2.

It derives frozen-plan/reveal/closure/row bytes and genuine Ed25519 conflict
envelopes without invoking Rust. These are bounded protocol fixtures, not signed
model admission histories, independently governed identities, or BFT finality.
The native PNW1/SQLite lifecycle regression covers the actual model owner.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from contract_wire import H, canonical, u64

PROFILE = "native-public-evaluation-quorum-dev-v2"
LEGACY = "native-public-evaluation-dev-v1"
REVIEW = "native-replay-quorum-and-record-only-appeals-v2"
VECTOR = Path(__file__).parent / "vectors/evaluation-quorum-v2.json"
CONTEXT = {name: bytes([number]).hex() * 32 for number, name in enumerate(
    ("network", "parameters", "family", "plan", "dataset", "candidate", "artifact", "components_root", "parent"), 1)}


def private(who):
    return Ed25519PrivateKey.from_private_bytes(H("DEV-ONLY-KEY", u64(who)))


def public(who):
    return private(who).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def signed(who, tag, payload, nonce=1):
    unsigned = (b"PNX1" + bytes.fromhex(CONTEXT["network"]) + bytes.fromhex(public(who))
                + u64(nonce) + u64(2000) + u64(1_000_000)
                + bytes([tag]) + struct.pack("<H", len(payload)) + payload)
    return (unsigned + private(who).sign(H("tx-sign", unsigned))).hex()


def frozen(profile, generation, excluded):
    quorum = profile == PROFILE
    roster = sorted(public(i) for i in range(3) if quorum or i not in excluded)
    start = generation * 128
    plan = dict(schema="pon-native-frozen-evaluation-v1", network=CONTEXT["network"],
                parameters=CONTEXT["parameters"], candidate=CONTEXT["candidate"],
                artifact=CONTEXT["artifact"], components_root=CONTEXT["components_root"],
                parent=CONTEXT["parent"], family=CONTEXT["family"],
                model_and_task_contract=CONTEXT["plan"], roster=roster, start=start,
                candidate_end=start + 15, commit_end=start + 31,
                reveal_end=start + 47, adoption_start=start + 56,
                max_score=1_000_000, independent_governance_accepted=False, objective_model_quality=False)
    if quorum:
        plan.update(schema="pon-native-frozen-evaluation-v2", profile=PROFILE, author=public(3),
                    quorum=(2 * len(roster) + 2) // 3,
                    disqualified_at_freeze=sorted(public(i) for i in excluded),
                    generation=generation, dataset=CONTEXT["dataset"], review_policy=REVIEW,
                    identity_scope="controlled-development-keys; common administration possible")
        plan["generation_context"] = H("native-public-evaluation-generation-v2", *(
            bytes.fromhex(plan[name]) for name in ("network", "parameters", "family",
                "model_and_task_contract", "dataset", "parent")), u64(generation)).hex()
    round_id = H("native-public-evaluation-round-v2" if quorum else "native-public-evaluation-round-v1", canonical(plan)).hex()
    return dict(storage_revision=3 if quorum else 2, plan=plan, round=round_id,
                record_counts=dict(commits=0, reveals=0, conflicts=0, appeals=0), closed=None)


def disqualified(evaluation, external):
    return (set(evaluation["plan"].get("disqualified_at_freeze", []))
            | {row["signer"] for row in evaluation["conflicts"].values()}
            | {public(i) for i in external}) & set(evaluation["plan"]["roster"])


def counted(evaluation, external):
    excluded = disqualified(evaluation, external)
    groups = {}
    for signer, row in evaluation["reveals"].items():
        if signer not in excluded:
            pair = row["score"], row["evidence"]
            groups[pair] = groups.get(pair, 0) + 1
    accepted = [(pair, count) for pair, count in groups.items() if count >= evaluation["plan"]["quorum"]]
    assert len(accepted) <= 1
    pair, count = accepted[0] if accepted else ((None, None), 0)
    return pair, count, sum(groups.values()), len(excluded)


def close(evaluation, external):
    quorum = evaluation["storage_revision"] == 3
    missing = len(set(evaluation["plan"]["roster"]) - evaluation["reveals"].keys())
    if quorum:
        (score, evidence), matching, revealed, excluded = counted(evaluation, external)
    else:
        score = min((row["score"] for row in evaluation["reveals"].values()), default=None)
        if missing or evaluation["conflicts"]:
            score = None
    snapshot = {name: evaluation[name] for name in ("commits", "reveals", "conflicts")}
    closed = dict(schema="pon-native-closed-evaluation-v3" if quorum else "pon-native-closed-evaluation-v2",
                  round=evaluation["round"], candidate=evaluation["plan"]["candidate"],
                  status="aborted" if score is None else "complete-scored", score=score,
                  missing_reveal_count=missing, conflict_count_before_close=len(evaluation["conflicts"]),
                  records_digest=H("native-public-evaluation-closure-records-v3" if quorum else
                                   "native-public-evaluation-closure-records-v2", canonical(snapshot)).hex(),
                  closed_height=evaluation["plan"]["reveal_end"] + 1,
                  objective_model_quality=False, independent_governance_accepted=False)
    if quorum:
        closed.update(generation_context=evaluation["plan"]["generation_context"], evidence=evidence,
                      quorum=evaluation["plan"]["quorum"], eligible_reveal_count=revealed,
                      matching_reveal_count=matching, disqualified_count_before_close=excluded,
                      execution_authority=False, consensus_finality=False)
    evaluation["closed"] = closed
    return closed


def adoption(evaluation, external, allow_zero=False):
    closed = evaluation["closed"]
    if closed["status"] != "complete-scored" or (not allow_zero and closed["score"] <= 0):
        return False
    if evaluation["storage_revision"] == 2:
        return not evaluation["conflicts"]
    return counted(evaluation, external)[0] == (closed["score"], closed["evidence"])


def conflict(evaluation, who):
    prefix = bytes.fromhex(CONTEXT["candidate"] + evaluation["round"])
    records = sorted(signed(who, 14, prefix + bytes([value]) * 32, value) for value in (41, 42))
    effect = ("signer excluded from current and future counts; frozen quorum and historical closure unchanged"
              if evaluation["storage_revision"] == 3 else
              "current adoption blocked; next-round identity excluded; historical closure unchanged")
    evaluation["conflicts"][public(who) + ":14"] = dict(records=records, signer=public(who), effect=effect)
    return records


def case(name, *, profile=PROFILE, revealed=(0, 2), scores=None, excluded=(), before=(), after=(),
         global_before=(), global_after=(), generation=0, appeal=False):
    initial = frozen(profile, generation, excluded)
    evaluation = copy.deepcopy(initial)
    evaluation.update(commits={}, reveals={}, conflicts={}, appeals={})
    commits, reveals = [], []
    for who in revealed:
        score = 17 if scores is None else scores[str(who)]
        evidence, salt = bytes([14]) * 32, bytes([who + 1]) * 32
        prefix = bytes.fromhex(CONTEXT["candidate"] + evaluation["round"])
        reveal = prefix + bytes.fromhex(CONTEXT["plan"]) + evidence + u64(score) + salt
        commitment = H("native-public-evaluation-reveal-v2" if profile == PROFILE else
                       "native-public-evaluation-reveal-v1", bytes.fromhex(evaluation["round"]),
                       bytes.fromhex(CONTEXT["candidate"]), bytes.fromhex(public(who)),
                       bytes.fromhex(CONTEXT["plan"]), evidence, u64(score), salt)
        evaluation["commits"][public(who)] = commitment.hex()
        evaluation["reveals"][public(who)] = dict(score=score, evidence=evidence.hex(), salt=salt.hex())
        commits.append(signed(who, 14, prefix + commitment))
        reveals.append(signed(who, 15, reveal, 2))
    prior = [conflict(evaluation, who) for who in before]
    closure = copy.deepcopy(close(evaluation, global_before))
    closed_digest = H("native-public-evaluation-closed-v3" if profile == PROFILE else
                      "native-public-evaluation-closed-v2", canonical(closure)).hex()
    later = [conflict(evaluation, who) for who in after]
    if appeal:
        signer = public(3)
        claim, evidence = bytes([1]) * 32, bytes([2]) * 32
        identifier = H("native-public-evaluation-appeal-v2" if profile == PROFILE else
                       "native-public-evaluation-appeal-v1", signer.encode(), bytes.fromhex(closed_digest), claim, evidence).hex()
        evaluation["appeals"][identifier] = dict(signer=signer, result=closed_digest, claim=claim.hex(),
            evidence=evidence.hex(), height=generation * 128 + 49,
            effect="record-only; closed score and past reward unchanged")
    revision = evaluation["storage_revision"]
    rows = {}
    for kind, field in (("c", "commits"), ("r", "reveals"), ("f", "conflicts"), ("a", "appeals")):
        for identifier, value in evaluation[field].items():
            key = f"evaluation-record-v{revision}:{CONTEXT['candidate']}:{kind}:{identifier}"
            rows[key] = dict(schema=f"pon-native-evaluation-record-v{revision}", candidate=CONTEXT["candidate"],
                             kind=kind, id=identifier, value=value)
    external = sorted(set(global_before) | set(global_after))
    return dict(name=name, profile=profile, generation=generation, excluded=list(excluded),
                frozen=initial, commits=commits, reveals=reveals, conflicts_before=prior, conflicts_after=later,
                global_before=list(global_before), global_after=external, appeal=appeal,
                expected_closed=closure, expected_closed_digest=closed_digest,
                expected_adoption=adoption(evaluation, external),
                expected_component_adoption=adoption(evaluation, external, True),
                expected_rows_digest=H("native-evaluation-test-rows-v2", canonical(rows)).hex())


def vectors():
    rows = [case("legacy-all-reveal", profile=LEGACY, revealed=(0, 1, 2)),
            case("legacy-one-absent-aborts", profile=LEGACY),
            case("all-reveal", revealed=(0, 1, 2)), case("one-absent-completes"),
            case("two-absent-aborts", revealed=(0,)), case("no-synthetic-timeout-votes", revealed=()),
            case("zero-score-component-only", scores={"0": 0, "2": 0}),
            case("mixed-real-values-without-matching-threshold", scores={"0": 17, "2": 18}),
            case("known-disqualified-denominator-frozen", excluded=(1,)),
            case("early-conflict-absent-key", before=(1,)),
            case("early-conflict-needed-voter", before=(2,)),
            case("late-conflict-absent-key", after=(1,)),
            case("late-conflict-needed-voter", after=(2,)),
            case("other-candidate-conflict-before-close", global_before=(2,)),
            case("other-candidate-conflict-after-close", global_after=(2,)),
            case("hash-only-appeal-cannot-veto", appeal=True),
            case("next-generation-binds-frozen-disqualification", excluded=(1,), generation=1)]
    return dict(schema="native-evaluation-quorum-reference-v2", context=CONTEXT,
                scope="artificial bounded protocol inputs; native model execution and independent identities not asserted", cases=rows)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    expected = vectors()
    if args.write:
        VECTOR.write_bytes(canonical(expected) + b"\n")
    else:
        assert json.loads(VECTOR.read_bytes()) == expected, "reference vectors drifted"
        print(json.dumps({"result": "PASS", "cases": len(expected["cases"]), "native_execution": False}))
