#!/usr/bin/env python3
"""Actual native transactions in the existing fleet process lifetime (M05/M17).

This is a bounded candidate measurement, not an A-tier or production gate.
The existing runner still requires every signed terminal/archive artifact.
"""
from __future__ import annotations
import hashlib
import json
import os
import pathlib
import shlex
import stat
import subprocess
import tempfile
import time
from typing import Any
import run_network_smoke_fleet as base

PROFILE = "trnm.native-client-campaign.v1"
ARTIFACT = "native-client-campaign.json"
MAX_TRANSFERS = 16


def application_selection(manifest: dict, key_root: pathlib.Path | None, transfers: int) -> bool:
    from check_run_material import application_public_paths_v1
    native = application_public_paths_v1(manifest) == ("public/native-client-profile.json",)
    if native != (key_root is not None):
        raise RuntimeError("native profile requires explicit isolated client keys; legacy profile forbids them")
    if not 1 <= transfers <= MAX_TRANSFERS:
        raise RuntimeError("native transfer count must be 1..16")
    return native


def key_namespace(root: pathlib.Path, coordinator: pathlib.Path, deployments: pathlib.Path, profile: bytes) -> pathlib.Path:
    root = base.require_private_directory(root, "native campaign key root")
    metadata = root.stat()
    if metadata.st_mode & 0o777 != 0o700 or metadata.st_uid != os.geteuid():
        raise RuntimeError("campaign key root must be owner-private")
    for other in (coordinator, deployments):
        if root == other or root.is_relative_to(other) or other.is_relative_to(root):
            raise RuntimeError("campaign private keys overlap deployment/coordinator material")
    if set(p.name for p in root.iterdir()) != {"operator.key", "client.key", "native-client-profile.json"}:
        raise RuntimeError("campaign key inventory differs")
    for name in ("operator.key", "client.key", "native-client-profile.json"):
        path = root / name
        m = path.lstat()
        if not stat.S_ISREG(m.st_mode) or m.st_uid != os.geteuid() or m.st_nlink != 1 or m.st_mode & 0o777 != 0o600:
            raise RuntimeError("campaign key/profile identity differs")
    if (root / "native-client-profile.json").read_bytes() != profile:
        raise RuntimeError("campaign profile differs from deployed manifest")
    if any((root / name).stat().st_size != 64 for name in ("operator.key", "client.key")):
        raise RuntimeError("campaign key size differs")
    return root


def ssh(stage: base.HostStage, arguments: list[str], *, timeout: int = 30, input_bytes: bytes | None = None) -> bytes:
    return base.run_checked(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", stage.management,
                             shlex.join(arguments)], timeout=timeout, input_bytes=input_bytes).stdout


def remote_new(stage: base.HostStage, path: str, content: bytes) -> None:
    # The fresh run-specific scratch directory is 0700; O_EXCL prohibits replacement.
    program = "import os,sys; p=sys.argv[1]; b=sys.stdin.buffer.read(9000000); fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); f=os.fdopen(fd,'wb'); f.write(b); f.flush(); os.fsync(f.fileno()); f.close()"
    ssh(stage, ["python3", "-c", program, path], input_bytes=content)


def strict_json(raw: bytes, field: str) -> dict:
    value = base.strict_json_bytes(raw, field)
    if not isinstance(value, dict):
        raise RuntimeError(f"{field} is not an object")
    return value


def validate_document(document: dict, *, run_id: str, anchor: str, validator_ids: set[str]) -> None:
    keys = {"schema", "run_id", "coordinator_manifest_sha256", "profile_sha256", "submit_validator_id", "signing_host", "verification_host", "transport", "started_monotonic_ns", "completed_monotonic_ns", "business_transfer_count", "business_window_ns", "business_goodput_per_second", "records", "candidate_only", "m05_intent_binding", "fault_matrix_completed", "performance_acceptance", "host_attestation", "production_activation"}
    if set(document) != keys or document["schema"] != PROFILE or document["run_id"] != run_id or document["coordinator_manifest_sha256"] != anchor:
        raise RuntimeError("native campaign identity differs")
    if document["submit_validator_id"] not in validator_ids or document["signing_host"] != "mac" or document["verification_host"] != "mac" or document["transport"] != "ssh-private-unix-ipc":
        raise RuntimeError("native campaign physical roles differ")
    if document["candidate_only"] is not True or any(document[k] is not False for k in ("m05_intent_binding", "fault_matrix_completed", "performance_acceptance", "host_attestation", "production_activation")):
        raise RuntimeError("native campaign exceeds candidate authority")
    n = document["business_transfer_count"]
    if type(n) is not int or not 1 <= n <= MAX_TRANSFERS or len(document["records"]) != n + 1:
        raise RuntimeError("native campaign counts differ")
    for key in ("started_monotonic_ns", "completed_monotonic_ns", "business_window_ns"):
        if type(document[key]) is not int or document[key] <= 0:
            raise RuntimeError("native campaign timing is invalid")
    if document["completed_monotonic_ns"] <= document["started_monotonic_ns"]:
        raise RuntimeError("native campaign timing reversed")
    hashes: set[str] = set()
    previous = document["started_monotonic_ns"]
    for index, record in enumerate(document["records"]):
        if set(record) != {"kind", "native_tx_hash", "outer_hex", "outer_sha256", "submitted_monotonic_ns", "ack_monotonic_ns", "verified_monotonic_ns", "ack", "retry_ack", "proof_response", "mac_verification"}:
            raise RuntimeError("native record fields differ")
        if record["kind"] != ("funding" if index == 0 else "transfer"):
            raise RuntimeError("native business classification differs")
        native_hash = record["native_tx_hash"]
        if not isinstance(native_hash, str) or len(native_hash) != 64 or native_hash in hashes:
            raise RuntimeError("native transaction identity repeated or invalid")
        hashes.add(native_hash)
        outer = bytes.fromhex(record["outer_hex"])
        if not 0 < len(outer) <= 256 * 1024 or hashlib.sha256(outer).hexdigest() != record["outer_sha256"]:
            raise RuntimeError("native signed bytes differ")
        a, b, c = (record[k] for k in ("submitted_monotonic_ns", "ack_monotonic_ns", "verified_monotonic_ns"))
        if any(type(v) is not int for v in (a, b, c)) or not previous <= a <= b < c <= document["completed_monotonic_ns"]:
            raise RuntimeError("native causal timings differ")
        previous = c
        ack, retry = record["ack"], record["retry_ack"]
        for response in (ack, retry, record["proof_response"]):
            if response.get("ok") is not True or response.get("profile_sha256") != document["profile_sha256"] or response.get("candidate_only") is not True or response.get("data", {}).get("native_tx_hash") != native_hash:
                raise RuntimeError("native response identity differs")
        if ack["data"]["receive_sequence"] != retry["data"]["receive_sequence"] or ack["data"]["status"] not in ("pending", "in_flight", "committed"):
            raise RuntimeError("native durable idempotency differs")
        expected_verification = {"candidate_only": True, "m05_intent_binding": False, "native_tx_hash": native_hash, "proof_verified_by_client": True, "height": record["mac_verification"].get("height"), "index": record["mac_verification"].get("index")}
        if record["mac_verification"] != expected_verification:
            raise RuntimeError("native independent verification summary differs")
    window = document["records"][-1]["verified_monotonic_ns"] - document["records"][1]["submitted_monotonic_ns"]
    if document["business_window_ns"] != window or document["business_goodput_per_second"] != n * 1_000_000_000 / window:
        raise RuntimeError("native actual goodput denominator differs")


def run_campaign(*, coordinator: pathlib.Path, deployments: pathlib.Path, manifest: dict,
                 processes: list[base.ValidatorProcess], stages: dict[str, base.HostStage],
                 linux_binary: pathlib.Path, mac_binary: str, observer_root: str,
                 key_root: pathlib.Path, anchor: str, transfers: int, output: pathlib.Path,
                 duration_seconds: int, running_children: list | None = None) -> dict:
    profile_bytes = (coordinator / "public/native-client-profile.json").read_bytes()
    profile = strict_json(profile_bytes, "native profile")
    digest = hashlib.sha256(profile_bytes).hexdigest()
    keys = key_namespace(key_root, coordinator, deployments, profile_bytes)
    process = next((p for p in processes if p.management == "local"), None)
    if process is None:
        raise RuntimeError("candidate client bridge requires an actual local validator")
    stage = stages[process.host_id]
    node_root = pathlib.Path(base.validator_stage_root(process, stage))
    socket = node_root / "native-client-v1" / profile["socket_basename"]
    config = strict_json((coordinator / process.config_relative).read_bytes(), "native config")
    genesis = strict_json((coordinator / "public/validator-set.json").read_bytes(), "validator set")["genesis_hash"]
    mac = stages["mac"]
    remote = f"{mac.root}/reports/native-client-campaign"
    ssh(mac, ["mkdir", "-m", "700", remote])
    # Only the explicitly isolated application keys enter this private namespace;
    # observer public material and validator deployments remain key-free.
    for name in ("operator.key", "client.key"):
        remote_new(mac, f"{remote}/{name}", (keys / name).read_bytes())
    remote_new(mac, f"{remote}/profile.json", profile_bytes)
    started = time.monotonic_ns()
    deadline = time.monotonic() + min(duration_seconds + 330, 600)
    records = []
    sequence = 0
    with tempfile.TemporaryDirectory(prefix="trnm-native-client-") as scratch_name:
        scratch = pathlib.Path(scratch_name)
        def request(op: str, data: dict) -> dict:
            nonlocal sequence
            if running_children is not None and any(child.poll() is not None for child in running_children):
                raise RuntimeError("validator exited before native campaign completed; inspect preserved process stderr")
            if time.monotonic() >= deadline:
                raise RuntimeError("native campaign absolute deadline exceeded")
            sequence += 1
            request_path = scratch / f"q{sequence}.json"
            response_path = scratch / f"r{sequence}.json"
            base.write_new(request_path, base.canonical_json({"schema": "trnm.native-client.request.v1", "request_id": f"campaign-{sequence}", "op": op, "data": data}))
            base.run_checked([str(linux_binary), "native-client", "request", str(socket), str(request_path), str(response_path), digest, genesis], timeout=12)
            return strict_json(response_path.read_bytes(), "native actual response")
        while True:
            if time.monotonic() >= deadline:
                raise RuntimeError("native endpoint never became ready")
            try:
                status = request("status", {})
                if status.get("ok") and status.get("data", {}).get("accepting"):
                    break
            except (subprocess.SubprocessError, OSError):
                pass
            time.sleep(0.25)
        operator = next(s for s in profile["signers"] if s["signer_role"] == "operator")["signer_id"]
        client = next(s for s in profile["signers"] if s["signer_role"] == "hepta")["signer_id"]
        for index in range(transfers + 1):
            funding = index == 0
            command = {"type": "credit_account", "account": client, "amount": "1000000"} if funding else {"type": "transfer", "to": operator, "amount": "1"}
            command_path = f"{remote}/command-{index}.json"
            outer_path = f"{remote}/outer-{index}.json"
            remote_new(mac, command_path, base.canonical_json(command))
            signed = strict_json(ssh(mac, [mac_binary, "native-client", "sign", f"{remote}/profile.json", digest, profile["chain_id"], operator if funding else client, f"{remote}/{'operator' if funding else 'client'}.key", "1" if funding else str(index), "300000", "1000000", "1000000", command_path, outer_path]), "Mac actual signer")
            native_hash = signed["native_tx_hash"]
            outer = ssh(mac, ["cat", outer_path])
            submitted = time.monotonic_ns()
            ack = request("submit", {"signed_outer_hex": outer.hex()})
            while ack.get("ok") is not True and ack.get("error", {}).get("code") == "time_unready":
                time.sleep(0.25)
                ack = request("submit", {"signed_outer_hex": outer.hex()})
            ack_at = time.monotonic_ns()
            if not ack.get("ok"):
                raise RuntimeError(f"native admission rejected actual request: {ack.get('error')}")
            retry = request("submit", {"signed_outer_hex": outer.hex()})
            while True:
                proof = request("proof", {"native_tx_hash": native_hash})
                if proof.get("ok"):
                    break
                if proof.get("error", {}).get("code") not in ("unknown_transaction", "proof_unavailable", "backpressure", "not_finalized"):
                    raise RuntimeError(f"native proof query failed: {proof.get('error')}")
                time.sleep(0.15)
            proof_path = f"{remote}/proof-{index}.json"
            remote_new(mac, proof_path, base.canonical_json(proof))
            verified = strict_json(ssh(mac, [mac_binary, "native-client", "verify", observer_root, str(process.config_relative), anchor, proof_path, native_hash, outer_path, digest]), "Mac independent native proof verification")
            records.append({"kind": "funding" if funding else "transfer", "native_tx_hash": native_hash, "outer_hex": outer.hex(), "outer_sha256": hashlib.sha256(outer).hexdigest(), "submitted_monotonic_ns": submitted, "ack_monotonic_ns": ack_at, "verified_monotonic_ns": time.monotonic_ns(), "ack": ack, "retry_ack": retry, "proof_response": proof, "mac_verification": verified})
    completed = time.monotonic_ns()
    window = records[-1]["verified_monotonic_ns"] - records[1]["submitted_monotonic_ns"]
    document = {"schema": PROFILE, "run_id": manifest["run_id"], "coordinator_manifest_sha256": anchor, "profile_sha256": digest, "submit_validator_id": process.validator_id, "signing_host": "mac", "verification_host": "mac", "transport": "ssh-private-unix-ipc", "started_monotonic_ns": started, "completed_monotonic_ns": completed, "business_transfer_count": transfers, "business_window_ns": window, "business_goodput_per_second": transfers * 1_000_000_000 / window, "records": records, "candidate_only": True, "m05_intent_binding": False, "fault_matrix_completed": False, "performance_acceptance": False, "host_attestation": False, "production_activation": False}
    validate_document(document, run_id=manifest["run_id"], anchor=anchor, validator_ids={p.validator_id for p in processes})
    base.write_new(output / ARTIFACT, base.canonical_json(document))
    return document
