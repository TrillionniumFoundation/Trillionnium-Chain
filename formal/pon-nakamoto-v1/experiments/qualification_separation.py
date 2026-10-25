"""Bounded qualification research against the retained W1 and ledger oracles.

This script executes real PNH1/PNW1 codecs, strict Ed25519 verification and SQLite
admission. It does not implement a new consensus rule or invent an installation
authority. Historical Hepta observations are read as historical observations;
they are not rerun, promoted, or combined with the maintenance vector as one job.
"""
from __future__ import annotations

import argparse
import copy
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

FORMAL = Path(__file__).resolve().parents[1]
ROOT = FORMAL.parents[1]
if str(FORMAL) not in sys.path:
    sys.path.insert(0, str(FORMAL))

import contract_wire as wire
import ledger
import reference
import strict_signature
import work_oracle as work

MAX_TARGET = bytes([255]) * 32
HISTORY = Path("evidence/pon-upgrade-implementation-20261018/native-rounds/"
               "real-model-owner-controlled-20261025")
SOURCE_FILES = (
    "formal/pon-nakamoto-v1/contract_wire.py",
    "formal/pon-nakamoto-v1/strict_signature.py",
    "formal/pon-nakamoto-v1/work_oracle.py",
    "formal/pon-nakamoto-v1/ledger.py",
    "formal/pon-nakamoto-v1/reference.py",
    "config/pon/work-profile-v1.json",
    "config/pon/ledger-v1.json",
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load_json(path):
    return json.loads(Path(path).read_text(), object_pairs_hook=wire.unique)


def source_record():
    paths = list(SOURCE_FILES) + [str(Path(__file__).relative_to(ROOT))]
    return {path: sha((ROOT / path).read_bytes()) for path in paths}


def fixture():
    directory = FORMAL / "vectors/accepted-block"
    expected = load_json(directory / "expected.json")
    header = (directory / "header.bin").read_bytes()
    transaction = (directory / "transaction.bin").read_bytes()
    proof = (directory / "work.bin").read_bytes()
    require(expected["genesis"] == ledger.GENESIS.hex(), "fixture genesis differs")
    require(wire.header_encode(wire.header_decode(header)) == header, "header round trip")
    require(wire.H("challenge", header).hex() == expected["header_challenge"], "fixture challenge")
    require(wire.H("tx-id", transaction).hex() == expected["tx_id"], "fixture transaction")
    h = wire.header_decode(header)
    ticket, product = work.verify(wire.H("challenge", header), h["work_task"], h["target"], proof)
    require(ticket.hex() == expected["ticket"], "fixture ticket")
    return header, transaction, proof, expected, product


def rejected(operation):
    try:
        operation()
    except ValueError as error:
        return str(error)
    raise AssertionError("negative control unexpectedly accepted")


def rows_snapshot(node):
    return [(bytes(bid).hex(), bytes(cw).hex()) for bid, cw in
            node.db.execute("SELECT id,chainwork FROM blocks ORDER BY id")]


def _native_case(binary, challenge, task, target, proof, accepted):
    payload = challenge + task + target + proof
    result = subprocess.run([str(binary), "verify"], input=payload,
                            capture_output=True, timeout=30, check=False)
    require((result.returncode == 0) is accepted, "native/oracle acceptance mismatch")
    if accepted:
        require(result.stdout == wire.H("native-work-verification", payload),
                "native verification acknowledgment differs")
    return {"exit_code": result.returncode, "stdout_hex": result.stdout.hex(),
            "stderr": result.stderr.decode("utf-8", errors="replace"),
            "input_sha256": sha(payload)}


def work_boundaries(native_work=None):
    header, tx, proof, expected, product = fixture()
    h = wire.header_decode(header)
    challenge = wire.H("challenge", header)
    cases = []

    def check_case(name, c, task, target, raw, expected_error=None):
        if expected_error is None:
            work.verify(c, task, target, raw)
            error = None
        else:
            error = rejected(lambda: work.verify(c, task, target, raw))
            require(error == expected_error, name + ": unexpected rejection " + error)
        row = {"name": name, "accepted": error is None, "error": error,
               "proof_sha256": sha(raw), "challenge": c.hex(),
               "task": task.hex(), "target": target.hex()}
        if native_work is not None:
            row["native"] = _native_case(native_work, c, task, target, raw, error is None)
        cases.append(row)

    check_case("committed-accepted-block", challenge, h["work_task"], h["target"], proof)
    check_case("exact-ticket-threshold", challenge, h["work_task"],
               bytes.fromhex(expected["ticket"]), proof)
    threshold = (int(expected["ticket"], 16) - 1).to_bytes(32, "big")
    check_case("one-below-ticket-threshold", challenge, h["work_task"], threshold, proof, "TARGET")

    variants = [("trailing-byte", proof + b"\0", "LENGTH"),
                ("short-proof", proof[:-1], "LENGTH"),
                ("different-profile", b"PNW2" + proof[4:], "VERSION")]
    for matrix_index, name in enumerate(("A", "B", "product")):
        offset = 4 + matrix_index * work.CELLS * 4
        bad = bytearray(proof)
        bad[offset:offset + 4] = struct.pack("<I", work.Q)
        variants.append((name + "-noncanonical-field", bytes(bad), "FIELD"))
        bad = bytearray(proof)
        value = (int.from_bytes(bad[offset:offset + 4], "little") + 1) % work.Q
        bad[offset:offset + 4] = struct.pack("<I", value)
        variants.append((name + "-canonical-wrong-value", bytes(bad),
                         "PRODUCT" if name == "product" else "TASK"))
    # Freeze a bounded search for a fabricated trace that passes the real target.
    forged = None
    for attempt in range(256):
        trace = wire.H("qualification-research-forged-trace-v1", wire.u64(attempt))
        if wire.H("ticket", challenge, trace) <= h["target"]:
            forged = proof[:-32] + trace
            break
    require(forged is not None, "bounded forged-ticket search exhausted")
    work.precheck(challenge, h["work_task"], h["target"], forged)
    variants.append(("passing-ticket-false-transcript", forged, "TRANSCRIPT"))
    for name, raw, error in variants:
        check_case(name, challenge, h["work_task"], h["target"], raw, error)

    header_cases = []
    # MAX_TARGET isolates relation binding from an early random target rejection.
    # The real SQLite admission below still uses each mutated header's own target.
    with tempfile.TemporaryDirectory(prefix="w1-separation-ledger-") as directory:
        node = ledger.Ledger(directory)
        try:
            bid = node.admit(header, [tx], proof, expected["observed_logical_time"])
            require(bid.hex() == expected["block_id"], "fixture block id")
            before = rows_snapshot(node)
            for field in wire.SCHEMA["header"]:
                name = field["name"]
                changed = copy.deepcopy(h)
                if field["type"] == "hash32":
                    changed[name] = changed[name][:-1] + bytes([changed[name][-1] ^ 1])
                else:
                    changed[name] += 1
                raw_header = wire.header_encode(changed)
                c = wire.H("challenge", raw_header)
                require(c != challenge, "header field absent from challenge: " + name)
                relation_error = "TASK" if name == "work_task" else "TRANSCRIPT"
                check_case("changed-header-" + name, c, changed["work_task"], MAX_TARGET,
                           proof, relation_error)
                admission_error = rejected(lambda: node.admit(
                    raw_header, [tx], proof, expected["observed_logical_time"]))
                require(rows_snapshot(node) == before, "rejected header changed chainwork")
                header_cases.append({"field": name, "admission_error": admission_error,
                                     "new_challenge": c.hex()})
            rejection = rejected(lambda: node.admit(
                header, [tx], forged, expected["observed_logical_time"]))
            require(rejection == "TRANSCRIPT", "forged ticket did not reach full rejection")
            for _ in range(3):
                require(node.admit(header, [tx], proof, expected["observed_logical_time"]) == bid,
                        "exact duplicate id differs")
            require(rows_snapshot(node) == before, "duplicate block added chainwork")
            parent_cw = int.from_bytes(node.block(ledger.GENESIS)[2], "big")
            credited = int.from_bytes(node.block(bid)[2], "big") - parent_cw
            require(credited == reference.work(int.from_bytes(h["target"], "big")),
                    "chainwork did not follow required target")
            block_count = len(before)
        finally:
            node.close()
    return {"fixture_scope": expected["scope"], "cases": cases,
            "header_admission_cases": header_cases,
            "passing_forgery_search_attempts": attempt + 1,
            "full_forgery_rejection": rejection,
            "duplicate_admissions": 3, "retained_blocks_including_genesis": block_count,
            "credited_chainwork": credited, "decoded_product_sha256": sha(work.field_bytes(product)),
            "native_status": "executed" if native_work is not None else "not-requested-not-executed"}


def _point_add(a, b):
    # Test-only public development key signing. Not a production signing primitive.
    p, d = strict_signature.P, strict_signature.D
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % p
    bb = (y1 + x1) * (y2 + x2) % p
    cc = 2 * d * t1 * t2 % p
    dd = 2 * z1 * z2 % p
    e, f, g, hh = bb - aa, dd - cc, dd + cc, bb + aa
    return e * f % p, g * hh % p, f * g % p, e * hh % p


def _base_multiple(scalar):
    p = strict_signature.P
    y = 4 * pow(5, p - 2, p) % p
    xx = (y * y - 1) * pow(strict_signature.D * y * y + 1, p - 2, p) % p
    x = pow(xx, (p + 3) // 8, p)
    if x * x % p != xx:
        x = x * strict_signature.SQRT_M1 % p
    if x & 1:
        x = p - x
    point, total = (x, y, 1, x * y % p), (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            total = _point_add(total, point)
        point = _point_add(point, point)
        scalar >>= 1
    x, y, z, _ = total
    iz = pow(z, p - 2, p)
    return ((y * iz % p) | ((x * iz % p & 1) << 255)).to_bytes(32, "little")


def development_alternate_signature(message, variant=1):
    """Produce another valid signature using ONLY the public development seed 0.

    This requires the signer key. It is not third-party Ed25519 rerandomization.
    Acceptance is checked by the existing strict_signature/OpenSSL verifier.
    """
    require(type(variant) is int and 1 <= variant <= 8, "bounded signing fixture")
    seed = wire.H("DEV-ONLY-KEY", wire.u64(0))
    digest = bytearray(hashlib.sha512(seed).digest())
    digest[0] &= 248
    digest[31] &= 63
    digest[31] |= 64
    scalar = int.from_bytes(digest[:32], "little")
    public = ledger.public(ledger.key(0))
    require(_base_multiple(scalar) == public, "test signer public key mismatch")
    nonce = int.from_bytes(hashlib.sha512(
        b"TRNM-RESEARCH-DEV-KEY-NONCE\0" + seed + message + bytes([variant])).digest(), "little") % strict_signature.L
    r = _base_multiple(nonce)
    k = int.from_bytes(hashlib.sha512(r + public + message).digest(), "little") % strict_signature.L
    signature = r + ((nonce + k * scalar) % strict_signature.L).to_bytes(32, "little")
    strict_signature.verify(public, signature, message)
    return signature


def signature_boundaries():
    header, transaction, proof, expected, _ = fixture()
    original = wire.tx_decode(transaction)
    message = wire.H("tx-sign", original["unsigned"])
    signature = development_alternate_signature(message)
    other = original["unsigned"] + signature
    require(other != transaction, "alternate signature must differ")
    strict_signature.verify(original["sender"], original["signature"], message)
    decoded = wire.tx_decode(other)
    require(decoded["unsigned"] == original["unsigned"], "transaction semantics changed")
    h = wire.header_decode(header)
    parent = ledger.genesis_state()
    first_state, first_receipts = ledger.execute_reference(parent, [transaction], h["height"], h["miner"], h["parent"])
    second_state, second_receipts = ledger.execute_reference(parent, [other], h["height"], h["miner"], h["parent"])
    require(first_state == second_state, "same signed command changed application state")
    require(first_receipts != second_receipts, "receipt must retain actual tx id")
    changed = copy.deepcopy(h)
    changed["transactions"] = wire.sequence_root("transactions", [other])
    changed["receipts"] = wire.sequence_root("receipts", second_receipts)
    changed["state"] = wire.state_root(second_state)
    c = wire.H("challenge", wire.header_encode(changed))
    require(c != wire.H("challenge", header), "signature bytes absent from W1 statement")
    old_proof_error = rejected(lambda: work.verify(c, h["work_task"], MAX_TARGET, proof))
    require(old_proof_error == "TRANSCRIPT", "old work survived a new signed body")
    replay_error = rejected(lambda: ledger.execute_reference(
        first_state, [other], h["height"] + 1, h["miner"], bytes.fromhex(expected["block_id"])))
    require(replay_error == "NONCE", "signature re-encoding replayed transaction effects")
    together_error = rejected(lambda: ledger.execute_reference(
        parent, [transaction, other], h["height"], h["miner"], h["parent"]))
    require(together_error == "NONCE", "same nonce paid twice in one block")
    noncanonical = signature[:32] + (int.from_bytes(signature[32:], "little") + strict_signature.L).to_bytes(32, "little")
    scalar_error = rejected(lambda: strict_signature.verify(original["sender"], noncanonical, message))
    wrong_message = rejected(lambda: strict_signature.verify(original["sender"], signature, message + b"!"))
    return {"scope": "key-holder-chosen-valid-signatures; not public Ed25519 rerandomization",
            "valid_signature_count": 2,
            "raw_tx_id_count": len({wire.H("tx-id", raw) for raw in (transaction, other)}),
            "canonical_unsigned_command_count": len({wire.tx_decode(raw)["unsigned"] for raw in (transaction, other)}),
            "same_application_state": first_state == second_state,
            "different_transaction_and_receipt_roots": changed["transactions"] != h["transactions"] and changed["receipts"] != h["receipts"],
            "old_work_for_new_body_error": old_proof_error,
            "second_command_effect_error": replay_error, "same_block_replay_error": together_error,
            "S_plus_L_error": scalar_error, "wrong_message_error": wrong_message,
            "signature_sha256": [sha(original["signature"]), sha(signature)],
            "hypothetical_envelope_hash_identity_count": 2,
            "hypothetical_semantic_identity_count": 1,
            "hypothetical_warning": "A randomized future proof envelope must not create extra full-cost tickets. No Groth16 implementation is executed here."}


def settled_contract_boundary():
    """Actual development ledger contract, explicitly not ordinary Hepta training."""
    owner, provider = ledger.public(ledger.key(0)), ledger.public(ledger.key(1))
    budget, deadline = 10000, 50
    task = ledger.task_identity(owner, 1, provider, budget, deadline)
    _, _, _, _, product = fixture()
    output = wire.H("qualification-research-maintenance-output-v1", work.field_bytes(product))
    txs = [ledger.sign(ledger.key(0), 1, "reserve_task", dict(task=task, provider=provider, budget=budget, deadline=deadline)),
           ledger.sign(ledger.key(1), 1, "record_receipt", dict(task=task, output=output)),
           ledger.sign(ledger.key(0), 2, "accept_task", dict(task=task, output=output))]
    with tempfile.TemporaryDirectory(prefix="w1-service-contract-") as directory:
        node = ledger.Ledger(directory)
        try:
            header, actual_txs, proof = node.make(ledger.GENESIS, txs, max_attempts=64)
            bid = node.admit(header, actual_txs, proof, ledger.PARAMS["genesis_timestamp"] + 10000)
            state = node.state_at(bid)
            task_state = state["task:" + task.hex()]
            require(task_state["status"] == "settled" and task_state["remaining"] == 0, "service contract not settled")
            require(state["model:current"] == ledger.genesis_state()["model:current"], "settlement installed model")
            delta = int.from_bytes(node.block(bid)[2], "big") - int.from_bytes(node.block(ledger.GENESIS)[2], "big")
            h = wire.header_decode(header)
            require(delta == reference.work(int.from_bytes(h["target"], "big")), "service changed chainwork formula")
            require(not any(name.startswith(("contribution:", "release:")) for name in state),
                    "service invented quality/release records")
            return {"scope": "actual-development-contract-on-maintenance-output; no neural-training claim",
                    "task": task.hex(), "status": task_state["status"], "remaining": task_state["remaining"],
                    "transaction_tags": [wire.tx_decode(tx)["tag"] for tx in txs],
                    "model_current": state["model:current"], "model_evaluation_records": 0,
                    "chainwork_increment_from_required_target": delta,
                    "header_sha256": sha(header), "proof_sha256": sha(proof),
                    "search_attempts": h["nonce"] + 1}
        finally:
            node.close()


def historical_hepta_boundary():
    controls_path = ROOT / HISTORY / "five-controls.json"
    owner_path = ROOT / HISTORY / "original-native-owner-results.json"
    controls, owner = load_json(controls_path), load_json(owner_path)
    require(controls["schema"] == "trnm.controlled-neural-five-controls-observation.v1", "historical control schema")
    scores = {name: Fraction(*row["evaluation"]) for name, row in controls["scores"].items()}
    candidate = scores["candidate"]
    strongest = max(value for name, value in scores.items() if name != "candidate")
    gain = candidate - strongest
    require(gain == Fraction(*controls["gain_vs_strongest_evaluation_control"]), "stored gain differs from score arithmetic")
    require(gain == 0, "frozen history no longer represents zero gain")
    phases = controls["phases"]
    successes = sum(row["outcome"] == "success" and row["exit_code"] == 0 for row in phases)
    return {"scope": "readback-of-committed-historical-observations; not reexecuted or linked to this W1 job",
            "files": {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in (controls_path, owner_path)},
            "successful_controlled_phases": successes, "total_controlled_phases": len(phases),
            "candidate_evaluation": [candidate.numerator, candidate.denominator],
            "strongest_control_evaluation": [strongest.numerator, strongest.denominator],
            "recomputed_gain": [gain.numerator, gain.denominator],
            "reported_installed": controls["installed"],
            "original_owner_peer_weight_read": owner["p2p_loaded_original_case"],
            "reported_CURRENT_updated": owner["CURRENT_updated"],
            "reported_three_round_closed": owner["three_round_closed"],
            "reported_public_reward_eligible": owner["public_reward_eligible"],
            "source_receipts_not_authority_for_current_run": True}


def run(native_work=None):
    for name in ("TRNM_NATIVE_WORK", "TRNM_NATIVE_EXECUTOR", "TRNM_PON_EVALUATION_POLICY"):
        require(not os.environ.get(name), "unset research-incompatible override: " + name)
    if native_work is not None:
        native_work = Path(native_work)
        require(native_work.is_absolute() and native_work.is_file(), "explicit absolute native binary required")
    profile = load_json(ROOT / "config/pon/work-profile-v1.json")
    require(profile["production_eligible"] is False and profile["external_hardness_acceptance"] is False,
            "research must not inherit a production qualification")
    report = {"schema": "pon-w1-qualification-separation-research-v1",
              "source_sha256": source_record(), "profile": profile["id"],
              "profile_production_eligible": profile["production_eligible"],
              "profile_external_hardness_acceptance": profile["external_hardness_acceptance"],
              "work": work_boundaries(native_work), "signatures": signature_boundaries(),
              "service_contract": settled_contract_boundary(), "historical_hepta": historical_hepta_boundary(),
              "new_model_training_executed": False, "ordinary_hepta_install_executed": False,
              "global_cost_lower_bound_proved": False, "timing_or_throughput_claim": False}
    if native_work is not None:
        report["native_binary"] = {"path": str(native_work), "sha256": sha(native_work.read_bytes())}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new JSON file; existing files are never overwritten")
    parser.add_argument("--native-work", type=Path, help="optional exact-source pon_work_io binary, absolute path")
    args = parser.parse_args()
    require(not args.output.exists(), "output already exists")
    report = run(args.native_work)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"report": str(args.output), "work_cases": len(report["work"]["cases"]),
                      "native_status": report["work"]["native_status"],
                      "global_cost_lower_bound_proved": False}, sort_keys=True))


if __name__ == "__main__":
    main()
