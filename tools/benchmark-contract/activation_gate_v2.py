#!/usr/bin/env python3
"""Candidate-only strict claim and activation evidence gate.

Synthetic complete evidence is used only to test the decision function. The
checked-in repository carries no real benchmark, public-testnet or production
claim authorization.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass, replace


class Reject(ValueError):
    pass


REQUIRED_GATES = (
    "G0", "G1", "G1.5", "G2.0", "G2A", "G2B", "G2D", "G2C",
    "G2E", "G2F", "G3", "G4", "G5",
)


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def commitment(domain: str, value: object) -> str:
    digest = hashlib.sha256()
    digest.update(domain.encode("ascii"))
    digest.update(b"\x00")
    raw = canonical(value)
    digest.update(len(raw).to_bytes(8, "big"))
    digest.update(raw)
    return digest.hexdigest()


def is_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and all(
        character in "0123456789abcdef" for character in value
    )


@dataclass(frozen=True)
class GateEvidenceV2:
    gate: str
    accepted: bool
    source_commit: str
    source_tree: str
    evidence_root: str
    independent_replays: int


@dataclass(frozen=True)
class TopologyV2:
    processes: int
    hosts: int
    operators: int
    regions: int
    custody_domains: int


@dataclass(frozen=True)
class BenchmarkEvidenceV2:
    artifact_root: str
    workload_root: str
    raw_trace_root: str
    comparator_root: str
    same_hardware: bool
    same_workload: bool
    committed_goodput: float
    order_p99_ms: int
    result_p99_ms: int
    settlement_p99_ms: int
    soak_hours: int
    topology: TopologyV2


@dataclass(frozen=True)
class SecurityEvidenceV2:
    open_critical: int
    open_high: int
    independent_consensus_audit: bool
    independent_crypto_audit: bool
    economic_review: bool
    redteam_complete: bool


@dataclass(frozen=True)
class OperationsEvidenceV2:
    slo_bound: bool
    incident_drill: bool
    restore_drill: bool
    key_rotation_drill: bool
    state_sync_drill: bool
    observability_bound: bool


@dataclass(frozen=True)
class ClaimRequestV2:
    kind: str
    workload_scope: str
    exact_release_root: str
    exact_comparator_root: str


def evaluate(
    gates: list[GateEvidenceV2],
    benchmark: BenchmarkEvidenceV2,
    security: SecurityEvidenceV2,
    operations: OperationsEvidenceV2,
    request: ClaimRequestV2,
) -> dict[str, object]:
    if request.kind not in {"surpass-workload", "public-testnet", "production"}:
        raise Reject("claim-kind")
    if not request.workload_scope or request.workload_scope in {"all", "universal"}:
        raise Reject("claim-scope")
    if not is_hex(request.exact_release_root, 64) or not is_hex(request.exact_comparator_root, 64):
        raise Reject("claim-root")

    gate_map: dict[str, GateEvidenceV2] = {}
    for gate in gates:
        if gate.gate in gate_map:
            raise Reject("duplicate-gate")
        gate_map[gate.gate] = gate
    if set(gate_map) != set(REQUIRED_GATES):
        raise Reject("gate-set")
    for gate in gates:
        if gate.accepted is not True:
            raise Reject(f"gate-not-accepted:{gate.gate}")
        if not is_hex(gate.source_commit, 40) or not is_hex(gate.source_tree, 40):
            raise Reject("gate-identity")
        if not is_hex(gate.evidence_root, 64):
            raise Reject("gate-evidence-root")
        if gate.independent_replays < 2:
            raise Reject("independent-replay")

    roots = (
        benchmark.artifact_root,
        benchmark.workload_root,
        benchmark.raw_trace_root,
        benchmark.comparator_root,
    )
    if not all(is_hex(root, 64) for root in roots):
        raise Reject("benchmark-root")
    if request.exact_release_root != benchmark.artifact_root:
        raise Reject("release-artifact-mismatch")
    if request.exact_comparator_root != benchmark.comparator_root:
        raise Reject("comparator-mismatch")
    if not benchmark.same_hardware or not benchmark.same_workload:
        raise Reject("comparison-not-like-for-like")
    if benchmark.committed_goodput <= 0:
        raise Reject("committed-goodput")
    if min(benchmark.order_p99_ms, benchmark.result_p99_ms, benchmark.settlement_p99_ms) <= 0:
        raise Reject("finality-metric")

    topology = benchmark.topology
    if (
        topology.processes < 100
        or topology.hosts < 7
        or topology.operators < 5
        or topology.regions < 3
        or topology.custody_domains < 3
    ):
        raise Reject("topology-insufficient")
    if (
        topology.hosts > topology.processes
        or topology.operators > topology.processes
        or topology.regions > topology.hosts
        or topology.custody_domains > topology.operators
    ):
        raise Reject("topology-overclaim")

    minimum_soak = {
        "surpass-workload": 168,
        "public-testnet": 168,
        "production": 720,
    }[request.kind]
    if benchmark.soak_hours < minimum_soak:
        raise Reject("soak-insufficient")

    if security.open_critical or security.open_high:
        raise Reject("open-critical-high")
    if not (
        security.independent_consensus_audit
        and security.independent_crypto_audit
        and security.economic_review
        and security.redteam_complete
    ):
        raise Reject("security-review-incomplete")
    if not all(asdict(operations).values()):
        raise Reject("operations-drill-incomplete")

    decision = {
        "kind": request.kind,
        "scope": request.workload_scope,
        "release": request.exact_release_root,
        "comparator": request.exact_comparator_root,
        "gate_roots": {
            gate.gate: gate.evidence_root for gate in sorted(gates, key=lambda row: row.gate)
        },
        "benchmark": asdict(benchmark),
        "security": asdict(security),
        "operations": asdict(operations),
    }
    return {
        "authorized": True,
        "decision_root": commitment("trnm.claim-decision.v2", decision),
        "scope": request.workload_scope,
        "kind": request.kind,
    }


def fixtures() -> tuple[
    list[GateEvidenceV2], BenchmarkEvidenceV2, SecurityEvidenceV2,
    OperationsEvidenceV2, ClaimRequestV2,
]:
    gates = [
        GateEvidenceV2(
            gate=gate,
            accepted=True,
            source_commit=hashlib.sha1(("commit-" + gate).encode()).hexdigest(),
            source_tree=hashlib.sha1(("tree-" + gate).encode()).hexdigest(),
            evidence_root=hashlib.sha256(("evidence-" + gate).encode()).hexdigest(),
            independent_replays=2,
        )
        for gate in REQUIRED_GATES
    ]
    benchmark = BenchmarkEvidenceV2(
        artifact_root=commitment("artifact", "release"),
        workload_root=commitment("workload", "deterministic-reexecution-v1"),
        raw_trace_root=commitment("trace", "synthetic"),
        comparator_root=commitment("comparator", "exact"),
        same_hardware=True,
        same_workload=True,
        committed_goodput=100.0,
        order_p99_ms=500,
        result_p99_ms=5_000,
        settlement_p99_ms=10_000,
        soak_hours=720,
        topology=TopologyV2(100, 20, 10, 5, 5),
    )
    security = SecurityEvidenceV2(0, 0, True, True, True, True)
    operations = OperationsEvidenceV2(True, True, True, True, True, True)
    request = ClaimRequestV2(
        "surpass-workload",
        "deterministic-reexecution-v1",
        benchmark.artifact_root,
        benchmark.comparator_root,
    )
    return gates, benchmark, security, operations, request


def self_test() -> dict[str, object]:
    gates, benchmark, security, operations, request = fixtures()
    decision = evaluate(gates, benchmark, security, operations, request)
    expected_root = "ad1ae325fac3762af64ed01a444f807fb0b0ef5c00418fe8387d6635009b7028"
    if decision["decision_root"] != expected_root:
        raise AssertionError("decision-root-drift")

    negatives: list[dict[str, str]] = []

    def reject(name: str, operation) -> None:
        try:
            operation()
        except Reject as error:
            negatives.append({"case": name, "error": str(error)})
        else:
            raise AssertionError(f"accepted:{name}")

    reject("missing-gate", lambda: evaluate(gates[:-1], benchmark, security, operations, request))
    changed = list(gates)
    changed[1] = replace(changed[1], accepted=False)
    reject("unaccepted-gate", lambda: evaluate(changed, benchmark, security, operations, request))
    changed = list(gates)
    changed[1] = replace(changed[1], independent_replays=1)
    reject("single-replay", lambda: evaluate(changed, benchmark, security, operations, request))
    reject(
        "release-mismatch",
        lambda: evaluate(gates, benchmark, security, operations, replace(request, exact_release_root=commitment("x", "x"))),
    )
    reject(
        "comparator-mismatch",
        lambda: evaluate(gates, benchmark, security, operations, replace(request, exact_comparator_root=commitment("x", "x"))),
    )
    reject("hardware-mismatch", lambda: evaluate(gates, replace(benchmark, same_hardware=False), security, operations, request))
    reject("workload-mismatch", lambda: evaluate(gates, replace(benchmark, same_workload=False), security, operations, request))
    reject(
        "topology-insufficient",
        lambda: evaluate(gates, replace(benchmark, topology=TopologyV2(31, 4, 3, 2, 2)), security, operations, request),
    )
    reject(
        "topology-overclaim",
        lambda: evaluate(gates, replace(benchmark, topology=TopologyV2(100, 20, 10, 21, 5)), security, operations, request),
    )
    reject("soak-insufficient", lambda: evaluate(gates, replace(benchmark, soak_hours=100), security, operations, request))
    reject("open-critical", lambda: evaluate(gates, benchmark, replace(security, open_critical=1), operations, request))
    reject("open-high", lambda: evaluate(gates, benchmark, replace(security, open_high=1), operations, request))
    reject("audit-incomplete", lambda: evaluate(gates, benchmark, replace(security, economic_review=False), operations, request))
    reject("operations-drill-incomplete", lambda: evaluate(gates, benchmark, security, replace(operations, restore_drill=False), request))
    reject("universal-claim", lambda: evaluate(gates, benchmark, security, operations, replace(request, workload_scope="all")))

    return {
        "schema": "trnm-claim-activation-gate-evidence-v2",
        "positive": 3,
        "negative": negatives,
        "synthetic_authorized_decision_root": decision["decision_root"],
        "real_claim_authorized": False,
        "benchmark_results_present": False,
        "public_testnet_ready": False,
        "production_candidate": False,
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
