"""Finite REAL PNW1 proof/verification experiment for two DAA timestamp branches.

Research ONLY. This uses the repository's unchanged scalar W1 oracle, 318-byte
PNH1 header grammar and genesis-committed Revision12 maintenance matrix. It
constructs *valid mathematical work proofs*, NOT valid signed native Node
blocks: synthetic roots, reward accounting, M06 transactions, SQLite, a P2P
network and actual independent operators are absent. No target/fork rule is
installed or modified by this experiment. All timestamps use a declared logical
clock and do NOT show how many wall-clock seconds an adversary needs to mine.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import time
from dataclasses import dataclass

from contract_wire import H, header_encode
from daa_research_oracle import legacy_retarget, mtp11, valid_time
from work_oracle import field_bytes, precheck, prove, task_id, verify, PROOF_BYTES

SPACING = 10
INTERVAL = 16
POW_LIMIT = (1 << 256) - 1
INITIAL_TARGET = POW_LIMIT // 4
OBSERVED_NOW = 10_000
MAX_ATTEMPTS = 256
ZERO = bytes(32)


def maintenance_material() -> tuple[list[int], list[int]]:
    """Exactly the public deterministic Revision12 maintenance matrix recipe."""
    return ([(13 * i + 17) % 257 for i in range(4096)],
            [(29 * i + 31) % 263 for i in range(4096)])


def required_work(target: int) -> int:
    if type(target) is not int or not 1 <= target <= POW_LIMIT:
        raise ValueError("target")
    return (1 << 256) // (target + 1)


@dataclass(frozen=True)
class ProofBlock:
    height: int
    timestamp: int
    target: int
    block_id: bytes
    parent_id: bytes
    ticket: bytes
    complete_proof_sha256: bytes
    attempts: int
    chainwork: int
    producer_cpu_ns: int
    verifier_cpu_ns: int

    def public(self) -> dict:
        return {
            "height": self.height, "timestamp": self.timestamp,
            "target": f"{self.target:064x}", "block_id": self.block_id.hex(),
            "parent_id": self.parent_id.hex(), "winning_ticket": self.ticket.hex(),
            "proof_sha256": self.complete_proof_sha256.hex(),
            "proof_bytes": PROOF_BYTES, "full_verifier_pass": True,
            "attempts_including_misses": self.attempts,
            "work_cumulative": str(self.chainwork),
            "producer_cpu_ns": self.producer_cpu_ns,
            "verifier_cpu_ns": self.verifier_cpu_ns,
        }


def genesis() -> ProofBlock:
    return ProofBlock(0, 0, INITIAL_TARGET, H("genesis-maintenance-w1-daa-research-v1"),
                      ZERO, ZERO, ZERO, 0, 0, 0, 0)


def next_target(branch: list[ProofBlock]) -> int:
    height = len(branch)
    previous = branch[-1].target
    if height % INTERVAL:
        return previous
    assert height >= INTERVAL
    return legacy_retarget(previous, branch[height - INTERVAL].timestamp,
                           branch[height - 1].timestamp, INTERVAL, SPACING, POW_LIMIT)


def timestamp_for(branch: list[ProofBlock], policy: str) -> int:
    height = len(branch)
    if policy == "honest":
        return 10 * height
    if policy != "endpoint_push":
        raise ValueError("policy")
    # Deliberately legal but adversarially chosen logical time (NOT elapsed time).
    if height == 15:
        return 600
    if height >= 16:
        return 600 + height - 15
    return mtp11([p.timestamp for p in branch[-11:][::-1]]) + 1


def candidate_header(parent: ProofBlock, height: int, timestamp: int, target: int,
                     task: bytes, nonce: int) -> bytes:
    """Real fixed 318-byte PNH1 grammar; synthetic non-executed application roots."""
    return header_encode({
        "network": H("research-network", b"maintenance-v12"),
        "parameters": H("research-parameters", b"proof-cost-no-activation"),
        "parent": parent.block_id,
        "height": height,
        "timestamp": timestamp,
        "target": target.to_bytes(32, "big"),
        "miner": H("research-miner", b"operator0"),
        "transactions": H("research-nonexecuted-txs"),
        "state": H("research-nonexecuted-state", height.to_bytes(8, "little")),
        "receipts": H("research-nonexecuted-receipts"),
        "work_task": task,
        "nonce": nonce,
    })


def mine_one(branch: list[ProofBlock], policy: str, a: list[int], b: list[int],
             artifacts: dict[str, tuple[bytes, bytes]] | None = None) -> ProofBlock:
    parent = branch[-1]
    height = parent.height + 1
    assert height == len(branch)
    target = next_target(branch)
    timestamp = timestamp_for(branch, policy)
    times = [row.timestamp for row in reversed(branch[-11:])]
    if not valid_time(timestamp, times, OBSERVED_NOW, 120):
        raise AssertionError("supplied timestamp is not legal in original rule")
    task = task_id(a, b)
    start_producer_cpu = time.process_time_ns()
    proof = None
    used_nonce = None
    header = None
    for nonce in range(MAX_ATTEMPTS):
        header = candidate_header(parent, height, timestamp, target, task, nonce)
        challenge = H("challenge", header)
        attempted = prove(challenge, a, b)
        assert len(attempted) == PROOF_BYTES
        if H("ticket", challenge, attempted[-32:]) <= target.to_bytes(32, "big"):
            proof = attempted
            used_nonce = nonce
            break
    if proof is None:
        raise RuntimeError(f"finite search exhausted: {policy} height={height}")
    cpu_produced = time.process_time_ns() - start_producer_cpu
    t0 = time.process_time_ns()
    ticket, product = verify(H("challenge", header), task, target.to_bytes(32, "big"), proof)
    verified_ns = time.process_time_ns() - t0
    if not product or len(product) != 4096:
        raise AssertionError("full W1 proof verification incomplete")
    block_id = H("block", header, proof[-32:])
    if artifacts is not None:
        artifacts[block_id.hex()] = (header, proof)
    return ProofBlock(height, timestamp, target, block_id, parent.block_id,
                      ticket, hashlib.sha256(proof).digest(), used_nonce + 1,
                      parent.chainwork + required_work(target), cpu_produced, verified_ns)


def forged_false_trace(a: list[int], b: list[int], block: ProofBlock,
                       artifacts: dict[str, tuple[bytes, bytes]] | None = None) -> dict:
    """Fresh forged claimed trace with ZERO useful matrix product; invalid W1 work.

    This probes the cheap-ticket versus expensive-rejection asymmetry but the
    attacker is given the public A/B inputs and an already selected challenge.
    It is NOT a measured globally optimal from-zero attacking implementation.
    """
    start_forgery_cpu = time.process_time_ns()
    task = task_id(a, b)
    target = block.target.to_bytes(32, "big")
    # Reconstruct matching winning challenge using the stored winning nonce.
    # No valid transcript is used to generate the false candidate.
    parent = ProofBlock(block.height - 1, 0, block.target, block.parent_id,
                        ZERO, ZERO, ZERO, 0, 0, 0, 0)
    original_header = candidate_header(
        parent, block.height, block.timestamp, block.target, task, block.attempts - 1)
    challenge = H("challenge", original_header)
    base = b"PNW1" + field_bytes(a) + field_bytes(b) + field_bytes([0] * 4096)
    bad_proof = None
    trials = 0
    for attempt in range(512):
        trace = H("research-false-transcript", challenge, attempt.to_bytes(4, "little"))
        trials += 1
        if H("ticket", challenge, trace) <= target:
            bad_proof = base + trace
            break
    forged_cpu = time.process_time_ns() - start_forgery_cpu
    if bad_proof is None:
        raise AssertionError("finite forged-ticket budget unexpectedly exhausted")
    # Critical: a ticket can pass while no VerifiedWork exists.
    precheck(challenge, task, target, bad_proof)
    t0 = time.process_time_ns()
    error = None
    try:
        verify(challenge, task, target, bad_proof)
    except ValueError as exc:
        error = str(exc)
    verifier_cpu = time.process_time_ns() - t0
    if error != "TRANSCRIPT":
        raise AssertionError(f"forged trace unexpectedly accepted / wrong rejection: {error}")
    if artifacts is not None:
        artifacts["invalid-claimed-transcript"] = (original_header, bad_proof)
    return {"ticket_precheck_pass": True, "full_relation_rejected": "TRANSCRIPT",
            "valid_chainwork_added": "0", "claimed_product_is_zero": True,
            "claimed_trace_hash_trials": trials, "forgery_cpu_ns": forged_cpu,
            "full_rejection_cpu_ns": verifier_cpu,
            "unauthenticated_research_header": True}


def run(artifacts: dict[str, tuple[bytes, bytes]] | None = None) -> dict:
    a, b = maintenance_material()
    root = genesis()
    # Both branches share the same real-PNW1 first work packet.
    common = mine_one([root], "honest", a, b, artifacts)
    honest = [root, common]
    adversarial = [root, common]
    for _ in range(2, 17):
        honest.append(mine_one(honest, "honest", a, b, artifacts))
        adversarial.append(mine_one(adversarial, "endpoint_push", a, b, artifacts))
    assert len(honest) == len(adversarial) == 17
    assert honest[15].timestamp == 150 and adversarial[15].timestamp == 600
    assert honest[16].target == INITIAL_TARGET
    assert adversarial[16].target == 4 * INITIAL_TARGET  # exact legacy floor arithmetic, under pow_limit
    assert honest[16].chainwork > adversarial[16].chainwork
    original = honest[16]
    bad = forged_false_trace(a, b, original, artifacts)
    all_blocks = [common] + honest[2:] + adversarial[2:]
    frozen = [{k: v for k, v in b.public().items()
               if not k.endswith("_cpu_ns")} for b in all_blocks]
    stable_digest = hashlib.sha256(json.dumps(frozen, sort_keys=True,
                                              separators=(",", ":")).encode()).hexdigest()
    return {"schema":"trnm-w1-maintenance-daa-real-proof-research-v1",
            "qualification": {"native_Node_execution":False,"real_W1_full_proofs":True,
                              "real_W1_challenges":True,"real_WAN":False,
                              "independent_operators":False,"work_hardness_qualified":False,
                              "new_daa_activated":False,"consensus_security_qualified":False},
            "logical_now":OBSERVED_NOW,"proof_count":len(all_blocks),
            "proof_bytes_per_packet":PROOF_BYTES,"task_id":task_id(a,b).hex(),
            "research_network_not_installed":True,
            "timestamp_bounds_checked":len(all_blocks),
            "honest_tip":honest[-1].public(),"endpoint_push_tip":adversarial[-1].public(),
            "heavier_branch":"honest","branch_choice_by":"validated_cumulative_required_work",
            "forged_false_trace":bad,"deterministic_proof_inventory_sha256":stable_digest,
            "proof_inventory": [p.public() for p in all_blocks]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path,
                        help="New directory for all complete PNH1/PNW1 bytes (create only)")
    args = parser.parse_args()
    if args.output.exists() or (args.artifact_dir is not None and args.artifact_dir.exists()):
        parser.error("output paths must not exist")
    artifacts = {} if args.artifact_dir is not None else None
    result = run(artifacts)
    if artifacts is not None:
        args.artifact_dir.mkdir(parents=True, exist_ok=False)
        for name, (header, proof) in sorted(artifacts.items()):
            if len(header) != 318 or len(proof) != PROOF_BYTES:
                raise AssertionError("artifact length")
            with (args.artifact_dir / f"{name}.pnh1").open("xb") as h:
                h.write(header)
            with (args.artifact_dir / f"{name}.pnw1").open("xb") as f:
                f.write(proof)
    with args.output.open("x", encoding="utf8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({k:result[k] for k in ("schema","proof_count",
                                               "deterministic_proof_inventory_sha256")},
                     sort_keys=True))


if __name__ == "__main__":
    main()
