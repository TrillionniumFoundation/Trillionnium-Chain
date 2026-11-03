"""Read-only, bounded exact-PNH1/PNW1 replay of the synthetic W1/DAA experiment.

Never trusts a report's `full_verifier_pass` fields or claimed cumulative work.
Reconstructs both branches from original raw 318-byte headers and 49,188-byte
full work proofs, redoes the current W1 verification, time validity and legacy
16-block target calculation. Replaying the original numerical relation does
NOT verify native M06 roots, legal source/lease authority, actual P2P or WAN.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import stat

from contract_wire import H, header_decode
from daa_research_oracle import legacy_retarget, valid_time
from work_oracle import PROOF_BYTES, precheck, task_id, verify
from w1_maintenance_daa_proof_research import (
    INITIAL_TARGET, POW_LIMIT, OBSERVED_NOW, INTERVAL, SPACING,
    genesis, maintenance_material, required_work,
)

MAX_REPORT_BYTES = 100_000
EXPECTED_PROOFS = 31


def _lower_hex(value: object, name: str) -> bytes:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(name)
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(name) from exc
    if value != raw.hex():
        raise ValueError(name)
    return raw


def _strict_read(path: Path, length: int) -> bytes:
    if path.is_symlink():
        raise ValueError("symlink forbidden")
    entry = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(entry.st_mode) or entry.st_size != length:
        raise ValueError("artifact size/type")
    with path.open("rb") as handle:
        raw = handle.read(length + 1)
    if len(raw) != length:
        raise ValueError("artifact read/size")
    return raw


def replay(report: dict, get_pair) -> dict:
    if not isinstance(report, dict) or report.get("schema") != "trnm-w1-maintenance-daa-real-proof-research-v1":
        raise ValueError("report schema")
    cases = report.get("proof_inventory")
    if type(report.get("proof_count")) is not int or report["proof_count"] != EXPECTED_PROOFS:
        raise ValueError("proof count")
    if not isinstance(cases, list) or len(cases) != EXPECTED_PROOFS:
        raise ValueError("proof inventory")
    if report.get("logical_now") != OBSERVED_NOW or report.get("proof_bytes_per_packet") != PROOF_BYTES:
        raise ValueError("observation context")
    a, b = maintenance_material()
    task = task_id(a, b)
    if _lower_hex(report.get("task_id"), "task id") != task:
        raise ValueError("task binding")
    if report.get("research_network_not_installed") is not True:
        raise ValueError("research identity")
    q = report.get("qualification")
    if not isinstance(q, dict) or any(q.get(key) is not False for key in (
        "native_Node_execution", "real_WAN", "independent_operators",
        "work_hardness_qualified", "new_daa_activated", "consensus_security_qualified")):
        raise ValueError("false authority")
    root = genesis()
    # An entry includes its strict parent link, not trusted database order.
    known = {root.block_id: (root, [root])}
    stable = []
    for entry in cases:
        if not isinstance(entry, dict):
            raise ValueError("case shape")
        for metric in ("producer_cpu_ns", "verifier_cpu_ns"):
            if type(entry.get(metric)) is not int or entry[metric] < 0:
                raise ValueError("untrusted resource metric")
        block_id = _lower_hex(entry.get("block_id"), "block id")
        if block_id in known:
            raise ValueError("duplicate block")
        header_raw, proof = get_pair(block_id.hex())
        if len(header_raw) != 318 or len(proof) != PROOF_BYTES:
            raise ValueError("wire length")
        h = header_decode(header_raw)
        parent_id = h["parent"]
        if parent_id not in known:
            raise ValueError("unavailable parent")
        parent, chain = known[parent_id]
        if h["height"] != parent.height + 1:
            raise ValueError("height")
        expected_target = parent.target
        if h["height"] % INTERVAL == 0:
            expected_target = legacy_retarget(parent.target,
                chain[h["height"] - INTERVAL].timestamp, parent.timestamp,
                INTERVAL, SPACING, POW_LIMIT)
        if h["target"] != expected_target.to_bytes(32, "big"):
            raise ValueError("expected target")
        if not valid_time(h["timestamp"], [x.timestamp for x in reversed(chain[-11:])],
                          OBSERVED_NOW, 120):
            raise ValueError("time")
        if (h["network"] != H("research-network", b"maintenance-v12")
                or h["parameters"] != H("research-parameters", b"proof-cost-no-activation")
                or h["miner"] != H("research-miner", b"operator0")
                or h["transactions"] != H("research-nonexecuted-txs")
                or h["state"] != H("research-nonexecuted-state", h["height"].to_bytes(8, "little"))
                or h["receipts"] != H("research-nonexecuted-receipts")
                or h["work_task"] != task):
            raise ValueError("research header context")
        trace = proof[-32:]
        if H("block", header_raw, trace) != block_id:
            raise ValueError("block identity")
        ticket, product = verify(H("challenge", header_raw), task, h["target"], proof)
        if len(product) != 4096:
            raise ValueError("full verifier")
        complete_hash = hashlib.sha256(proof).digest()
        if _lower_hex(entry.get("proof_sha256"), "proof digest") != complete_hash:
            raise ValueError("proof digest")
        work = parent.chainwork + required_work(expected_target)
        if (entry.get("height") != h["height"]
                or entry.get("timestamp") != h["timestamp"]
                or entry.get("target") != h["target"].hex()
                or entry.get("parent_id") != parent_id.hex()
                or entry.get("winning_ticket") != ticket.hex()
                or entry.get("work_cumulative") != str(work)
                or entry.get("full_verifier_pass") is not True
                or entry.get("proof_bytes") != PROOF_BYTES
                or type(entry.get("attempts_including_misses")) is not int
                or entry["attempts_including_misses"] != h["nonce"] + 1):
            raise ValueError("report contradicts verified source")
        from w1_maintenance_daa_proof_research import ProofBlock
        checked = ProofBlock(h["height"], h["timestamp"], expected_target,
                             block_id, parent_id, ticket, complete_hash, 0, work, 0, 0)
        known[block_id] = (checked, chain + [checked])
        stable.append({k: v for k, v in entry.items() if not k.endswith("_cpu_ns")})
    digest = hashlib.sha256(json.dumps(stable, sort_keys=True,
                                       separators=(",", ":")).encode()).hexdigest()
    if report.get("deterministic_proof_inventory_sha256") != digest:
        raise ValueError("inventory digest")
    tips = [v[0] for v in known.values() if v[0].height == 16]
    if len(tips) != 2:
        raise ValueError("fork tips")
    honest = next((x for x in tips if x.timestamp == 160), None)
    adversary = next((x for x in tips if x.timestamp == 601), None)
    if honest is None or adversary is None:
        raise ValueError("expected fork schedule")
    if honest.target != INITIAL_TARGET or adversary.target != 4 * INITIAL_TARGET:
        raise ValueError("DAA result")
    if honest.chainwork <= adversary.chainwork:
        raise ValueError("chainwork order")
    for name, obj in (("honest_tip", honest), ("endpoint_push_tip", adversary)):
        claimed = report.get(name)
        if (not isinstance(claimed, dict)
                or claimed.get("block_id") != obj.block_id.hex()
                or claimed.get("work_cumulative") != str(obj.chainwork)):
            raise ValueError("reported tip")
    if report.get("heavier_branch") != "honest" or report.get("timestamp_bounds_checked") != EXPECTED_PROOFS:
        raise ValueError("fork outcome")
    # A cheap passing ticket for forged bytes is never promoted to valid work.
    header, false_proof = get_pair("invalid-claimed-transcript")
    if len(header) != 318 or len(false_proof) != PROOF_BYTES:
        raise ValueError("invalid proof length")
    # The invalid transcript must attack EXACTLY the original honest winning
    # statement, not an attacker-chosen alternate research header.
    honest_header, _ = get_pair(honest.block_id.hex())
    if header != honest_header:
        raise ValueError("invalid statement context")
    decoded = header_decode(header)
    if decoded["target"] != honest.target.to_bytes(32, "big") or decoded["height"] != 16:
        raise ValueError("invalid-proof context")
    challenge = H("challenge", header)
    precheck(challenge, task, decoded["target"], false_proof)
    try:
        verify(challenge, task, decoded["target"], false_proof)
    except ValueError as exc:
        if str(exc) != "TRANSCRIPT":
            raise ValueError("unexpected invalid-work verdict") from exc
    else:
        raise ValueError("invalid transcript was accepted")
    forged = report.get("forged_false_trace")
    if (not isinstance(forged, dict)
            or forged.get("valid_chainwork_added") != "0"
            or forged.get("ticket_precheck_pass") is not True
            or forged.get("full_relation_rejected") != "TRANSCRIPT"):
        raise ValueError("invalid-work chainwork claim")
    if report.get("branch_choice_by") != "validated_cumulative_required_work":
        raise ValueError("fork choice claim")
    return {"schema":"trnm-w1-daa-archive-readback-v1", "complete_w1_valid":EXPECTED_PROOFS,
            "invalid_transcript_rejected":1, "inventory_sha256":digest,
            "heavier_tip":honest.block_id.hex(), "native_Node_acceptance":False,
            "independent_operators_accepted":False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report",type=Path,required=True)
    parser.add_argument("--artifact-dir",type=Path,required=True)
    args = parser.parse_args()
    if args.report.is_symlink():
        parser.error("report symlinks forbidden")
    meta = args.report.stat(follow_symlinks=False)
    if not stat.S_ISREG(meta.st_mode) or meta.st_size > MAX_REPORT_BYTES:
        parser.error("report exceeds configured size/type")
    raw = _strict_read(args.report, meta.st_size)
    report = json.loads(raw, object_pairs_hook=_unique)
    def get_pair(name):
        if name != "invalid-claimed-transcript":
            _lower_hex(name, "lookup block id")
        return (_strict_read(args.artifact_dir / (name + ".pnh1"), 318),
                _strict_read(args.artifact_dir / (name + ".pnw1"), PROOF_BYTES))
    print(json.dumps(replay(report, get_pair), sort_keys=True))


def _unique(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate report key")
        out[k] = v
    return out


if __name__ == "__main__":
    main()
