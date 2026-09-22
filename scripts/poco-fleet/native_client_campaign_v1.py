#!/usr/bin/env python3
"""Actual native transactions in the existing fleet process lifetime (M05/M17).

This is a bounded candidate measurement, not an A-tier or production gate.
The existing runner still requires every signed terminal/archive artifact.
"""
from __future__ import annotations
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import selectors
import signal
import shlex
import stat
import subprocess
import sys
import time
from typing import Any
import run_network_smoke_fleet as base

PROFILE = "trnm.native-client-campaign.v1"
ARTIFACT = "native-client-campaign.json"
MAX_TRANSFERS = 16


# Native CLI framing ceilings; these are transport bounds, not proof authority.
REQUEST_LIMIT = 528_384
RESPONSE_LIMIT = 8 * 1024 * 1024 + 16 * 1024
STDERR_LIMIT = 64 * 1024
MAX_REQUESTS = 4096
MAX_REQUEST_BYTES = 64 * 1024 * 1024
MAX_RESPONSE_BYTES = 256 * 1024 * 1024


class NativeEndpointNotReady(RuntimeError):
    pass


class NativeRequestFailureV1(subprocess.CalledProcessError):
    def __init__(self, returncode, cmd, output, stderr, *, operation, sequence):
        super().__init__(returncode, cmd, output, stderr)
        self.operation, self.sequence = operation, sequence

    def __str__(self) -> str:
        return f"native request {self.sequence} ({self.operation}) exit {self.returncode}: {(self.stderr or b'').decode('utf-8', errors='replace')}"


def request_process_v1(processes: list[base.ValidatorProcess]) -> base.ValidatorProcess:
    if not 1 <= len(processes) <= 100 or len({p.validator_id for p in processes}) != len(processes):
        raise RuntimeError("native request requires unique actual Linux validators")
    for process in processes:
        if (process.host_id not in {"local", "desktop", "rog", "x230", "j3160"}
                or base.VALIDATOR_ID.fullmatch(process.validator_id) is None
                or process.management != ("local" if process.host_id == "local" else f"p4-{process.host_id}")):
            raise RuntimeError("native request process is not an actual Linux placement")
    local = [p for p in processes if p.management == "local"]
    return min(local or processes, key=lambda p: p.validator_id)


@dataclasses.dataclass(frozen=True)
class NativeRequestTargetV1:
    process: base.ValidatorProcess
    stage: base.HostStage
    binary: str
    node_root: str
    socket: str


def request_target_v1(processes: list[base.ValidatorProcess], stages: dict[str, base.HostStage],
                      linux_paths: dict[str, str], socket_basename: str) -> NativeRequestTargetV1:
    process = request_process_v1(processes)
    stage = stages.get(process.host_id)
    if (stage is None or stage.host_id != process.host_id or stage.management != process.management
            or (stage.local_path is None) != stage.remote
            or (not stage.remote and str(stage.local_path) != stage.root)):
        raise RuntimeError("native request stage differs from selected process")
    base.shell_path(stage.root)
    if re.fullmatch(r"/tmp/tp3-[0-9a-f]{20}", stage.root) is None:
        raise RuntimeError("native request stage is not the owned run namespace")
    binary = linux_paths.get(process.host_id)
    if binary != f"{stage.root}/bin/trnm-poco-lab-validator":
        raise RuntimeError("native request binary differs from deployed host binary")
    node_root = base.validator_stage_root(process, stage)
    if not isinstance(socket_basename, str) or re.fullmatch(r"[a-z0-9.-]{1,43}\.sock", socket_basename) is None:
        raise RuntimeError("native socket basename is not canonical")
    socket = f"{node_root}/native-client-v1/{socket_basename}"
    if len(socket.encode()) >= 104:
        raise RuntimeError("native socket exceeds portable Unix bound")
    return NativeRequestTargetV1(process, stage, binary, node_root, socket)


def remaining_timeout_v1(deadline: float, cap: float = 12) -> float:
    remaining = min(cap, deadline - time.monotonic())
    if remaining <= 0:
        raise TimeoutError("native campaign absolute deadline exceeded")
    return remaining


def bounded_command_v1(arguments: list[str], *, timeout: float, input_bytes: bytes = b"",
                       output_limit: int = RESPONSE_LIMIT) -> bytes:
    """Drain all pipes concurrently with fixed byte caps and a single deadline."""
    deadline = time.monotonic() + timeout
    child = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
    output, errors = bytearray(), bytearray()
    try:
        with selectors.DefaultSelector() as selector:
            for stream, label in ((child.stdout, "out"), (child.stderr, "err")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            if input_bytes:
                os.set_blocking(child.stdin.fileno(), False)
                selector.register(child.stdin, selectors.EVENT_WRITE, "in")
            else:
                child.stdin.close()
            sent = 0
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(arguments, timeout, bytes(output), bytes(errors))
                for key, _ in selector.select(remaining):
                    if key.data == "in":
                        try:
                            sent += os.write(key.fd, input_bytes[sent:sent + 65536])
                        except BrokenPipeError:
                            sent = len(input_bytes)
                        if sent == len(input_bytes):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        target, limit = (output, output_limit) if key.data == "out" else (errors, STDERR_LIMIT)
                        if len(target) + len(chunk) > limit:
                            raise RuntimeError(f"native transport {key.data} exceeded bounded output")
                        target.extend(chunk)
            code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
            if code:
                raise subprocess.CalledProcessError(code, arguments, bytes(output), bytes(errors))
            return bytes(output)
    finally:
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
        for stream in (child.stdin, child.stdout, child.stderr):
            stream.close()


# Executed on the selected Linux validator host, with no imported project code.
# The same program serves the local path. Nothing here signs or verifies proofs.
ON_HOST_REQUEST_V1 = r'''
import os, pathlib, re, stat, subprocess, sys
def require(condition, message):
    if not condition:
        raise RuntimeError(message)
root, node, binary, socket, sequence, digest, genesis, timeout = sys.argv[1:]
sequence = int(sequence)
require(re.fullmatch(r"/tmp/tp3-[0-9a-f]{20}", root), "owned stage namespace")
require(re.fullmatch(re.escape(root) + r"/v/v[0-9]{3}", node), "owned validator namespace")
require(binary == root + "/bin/trnm-poco-lab-validator", "deployed binary path")
require(str(pathlib.PurePosixPath(socket).parent) == node + "/native-client-v1", "socket namespace")
require(re.fullmatch(r"[a-z0-9.-]{1,43}\.sock", pathlib.PurePosixPath(socket).name), "socket basename")
require(len(socket.encode()) < 104 and 1 <= sequence <= 4096, "bounded locator/sequence")
require(re.fullmatch(r"[0-9a-f]{64}", digest) and re.fullmatch(r"[0-9a-f]{64}", genesis), "identity pins")
require(0 < float(timeout) <= 12, "request deadline")
def owned(path, kind, mode):
    info = os.lstat(path)
    require(kind(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == mode, "owned path type/mode: " + path)
    if kind == stat.S_ISREG:
        require(info.st_nlink == 1, "linked request artifact")
    return info
for path in (root, root + "/bin", root + "/v", node):
    owned(path, stat.S_ISDIR, 0o700)
owned(binary, stat.S_ISREG, 0o500)
missing = False
try:
    owned(node + "/native-client-v1", stat.S_ISDIR, 0o700)
    owned(socket, stat.S_ISSOCK, 0o600)
except FileNotFoundError:
    missing = True
scratch = node + "/native-client-campaign-requests"
if sequence == 1:
    os.mkdir(scratch, 0o700)
owned(scratch, stat.S_ISDIR, 0o700)
if missing:
    sys.stderr.write("native endpoint not ready\n")
    sys.exit(75)
request = sys.stdin.buffer.read(528385)
require(0 < len(request) <= 528384, "request byte bound")
q = scratch + "/q%04d.json" % sequence
r = scratch + "/r%04d.json" % sequence
require(not os.path.lexists(r), "response already exists")
fd = os.open(q, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "wb") as stream:
    stream.write(request); stream.flush(); os.fsync(stream.fileno())
result = subprocess.run([binary, "native-client", "request", socket, q, r, digest, genesis],
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, timeout=float(timeout))
if result.returncode:
    sys.exit(result.returncode if result.returncode > 0 else 128 - result.returncode)
info = owned(r, stat.S_ISREG, 0o600)
require(0 < info.st_size <= 8404992, "response byte bound")
fd = os.open(r, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(fd, "rb") as stream:
    actual = os.fstat(stream.fileno())
    require((actual.st_dev, actual.st_ino) == (info.st_dev, info.st_ino), "response identity changed")
    response = stream.read(8404993)
require(len(response) == info.st_size, "response changed or exceeded bound")
sys.stdout.buffer.write(response)
'''


def request_bytes_v1(op: str, data: dict, sequence: int) -> bytes:
    """M15 socket bytes: sorted compact JSON, unlike pretty fleet artifacts."""
    return json.dumps({"schema": "trnm.native-client.request.v1",
                       "request_id": f"campaign-{sequence}", "op": op, "data": data},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


class NativeRequestAdapterV1:
    def __init__(self, target: NativeRequestTargetV1, digest: str, genesis: str, deadline: float):
        if any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in (digest, genesis)):
            raise RuntimeError("native request identity pins are not canonical")
        self.target, self.digest, self.genesis, self.deadline = target, digest, genesis, deadline
        self.sequence = self.request_bytes = self.response_bytes = 0

    def request(self, op: str, data: dict) -> dict:
        timeout = remaining_timeout_v1(self.deadline)
        sequence = self.sequence + 1
        raw = request_bytes_v1(op, data, sequence)
        if (sequence > MAX_REQUESTS or len(raw) > REQUEST_LIMIT
                or self.request_bytes + len(raw) > MAX_REQUEST_BYTES
                or self.response_bytes >= MAX_RESPONSE_BYTES):
            raise RuntimeError("native request campaign byte/count limit exceeded")
        target = self.target
        arguments = ["python3", "-I", "-c", ON_HOST_REQUEST_V1, target.stage.root, target.node_root,
                     target.binary, target.socket, str(sequence), self.digest, self.genesis, str(timeout)]
        if target.stage.remote:
            arguments = ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "ConnectionAttempts=1",
                         target.stage.management, shlex.join(arguments)]
        else:
            arguments[0] = sys.executable
        self.sequence, self.request_bytes = sequence, self.request_bytes + len(raw)
        try:
            response = bounded_command_v1(arguments, timeout=remaining_timeout_v1(self.deadline), input_bytes=raw,
                                          output_limit=min(RESPONSE_LIMIT, MAX_RESPONSE_BYTES - self.response_bytes))
        except subprocess.CalledProcessError as error:
            if error.returncode == 75 and error.stderr == b"native endpoint not ready\n":
                raise NativeEndpointNotReady("native endpoint not ready") from error
            # CalledProcessError keeps exact exit/output; make the original
            # Linux/SSH diagnostic visible in the controller's failure summary.
            raise NativeRequestFailureV1(error.returncode, error.cmd, error.output, error.stderr, operation=op, sequence=sequence) from error
        self.response_bytes += len(response)
        decoded = strict_json(response, "native actual response")
        if decoded.get("request_id") != f"campaign-{sequence}":
            raise RuntimeError("native response request identity differs")
        return decoded


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


def ssh(stage: base.HostStage, arguments: list[str], *, timeout: float = 30, input_bytes: bytes | None = None) -> bytes:
    return bounded_command_v1(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", stage.management,
                               shlex.join(arguments)], timeout=timeout, input_bytes=input_bytes or b"")


def remote_new(stage: base.HostStage, path: str, content: bytes, *, deadline: float | None = None) -> None:
    # The fresh run-specific scratch directory is 0700; O_EXCL prohibits replacement.
    program = "import os,sys; p=sys.argv[1]; b=sys.stdin.buffer.read(9000000); fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); f=os.fdopen(fd,'wb'); f.write(b); f.flush(); os.fsync(f.fileno()); f.close()"
    ssh(stage, ["python3", "-c", program, path], input_bytes=content,
        timeout=30 if deadline is None else remaining_timeout_v1(deadline, 30))


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
                 linux_paths: dict[str, str], mac_binary: str, observer_root: str,
                 key_root: pathlib.Path, anchor: str, transfers: int, output: pathlib.Path,
                 duration_seconds: int, running_children: list | None = None) -> dict:
    profile_bytes = (coordinator / "public/native-client-profile.json").read_bytes()
    profile = strict_json(profile_bytes, "native profile")
    digest = hashlib.sha256(profile_bytes).hexdigest()
    keys = key_namespace(key_root, coordinator, deployments, profile_bytes)
    target = request_target_v1(processes, stages, linux_paths, profile["socket_basename"])
    process = target.process
    genesis = strict_json((coordinator / "public/validator-set.json").read_bytes(), "validator set")["genesis_hash"]
    mac = stages["mac"]
    remote = f"{mac.root}/reports/native-client-campaign"
    deadline = time.monotonic() + min(duration_seconds + 330, 600)
    ssh(mac, ["mkdir", "-m", "700", remote], timeout=remaining_timeout_v1(deadline, 30))
    # Only the explicitly isolated application keys enter this private namespace;
    # observer public material and validator deployments remain key-free.
    for name in ("operator.key", "client.key"):
        remote_new(mac, f"{remote}/{name}", (keys / name).read_bytes(), deadline=deadline)
    remote_new(mac, f"{remote}/profile.json", profile_bytes, deadline=deadline)
    started = time.monotonic_ns()
    records = []
    adapter = NativeRequestAdapterV1(target, digest, genesis, deadline)
    def request(op: str, data: dict) -> dict:
        if running_children is not None and any(child.poll() is not None for child in running_children):
            raise RuntimeError("validator exited before native campaign completed; inspect preserved process stderr")
        return adapter.request(op, data)
    while True:
        if time.monotonic() >= deadline:
            raise RuntimeError("native endpoint never became ready")
        try:
            status = request("status", {})
            if status.get("ok") is not True:
                raise RuntimeError(f"native status request failed: {status.get('error')}")
            if status.get("data", {}).get("accepting"):
                break
        except NativeEndpointNotReady:
            pass
        time.sleep(0.25)
    operator = next(s for s in profile["signers"] if s["signer_role"] == "operator")["signer_id"]
    client = next(s for s in profile["signers"] if s["signer_role"] == "hepta")["signer_id"]
    for index in range(transfers + 1):
        funding = index == 0
        command = {"type": "credit_account", "account": client, "amount": "1000000"} if funding else {"type": "transfer", "to": operator, "amount": "1"}
        command_path = f"{remote}/command-{index}.json"
        outer_path = f"{remote}/outer-{index}.json"
        remote_new(mac, command_path, base.canonical_json(command), deadline=deadline)
        signed = strict_json(ssh(mac, [mac_binary, "native-client", "sign", f"{remote}/profile.json", digest, profile["chain_id"], operator if funding else client, f"{remote}/{'operator' if funding else 'client'}.key", "1" if funding else str(index), "300000", "1000000", "1000000", command_path, outer_path], timeout=remaining_timeout_v1(deadline, 30)), "Mac actual signer")
        native_hash = signed["native_tx_hash"]
        outer = ssh(mac, ["cat", outer_path], timeout=remaining_timeout_v1(deadline, 30))
        submitted = time.monotonic_ns()
        ack = request("submit", {"signed_outer_hex": outer.hex()})
        while (ack.get("ok") is False and ack.get("error", {}).get("retryable") is True
               and ack["error"].get("code") in ("time_unready", "backpressure")):
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
        remote_new(mac, proof_path, base.canonical_json(proof), deadline=deadline)
        verified = strict_json(ssh(mac, [mac_binary, "native-client", "verify", observer_root, str(process.config_relative), anchor, proof_path, native_hash, outer_path, digest], timeout=remaining_timeout_v1(deadline, 30)), "Mac independent native proof verification")
        records.append({"kind": "funding" if funding else "transfer", "native_tx_hash": native_hash, "outer_hex": outer.hex(), "outer_sha256": hashlib.sha256(outer).hexdigest(), "submitted_monotonic_ns": submitted, "ack_monotonic_ns": ack_at, "verified_monotonic_ns": time.monotonic_ns(), "ack": ack, "retry_ack": retry, "proof_response": proof, "mac_verification": verified})
    completed = time.monotonic_ns()
    window = records[-1]["verified_monotonic_ns"] - records[1]["submitted_monotonic_ns"]
    document = {"schema": PROFILE, "run_id": manifest["run_id"], "coordinator_manifest_sha256": anchor, "profile_sha256": digest, "submit_validator_id": process.validator_id, "signing_host": "mac", "verification_host": "mac", "transport": "ssh-private-unix-ipc", "started_monotonic_ns": started, "completed_monotonic_ns": completed, "business_transfer_count": transfers, "business_window_ns": window, "business_goodput_per_second": transfers * 1_000_000_000 / window, "records": records, "candidate_only": True, "m05_intent_binding": False, "fault_matrix_completed": False, "performance_acceptance": False, "host_attestation": False, "production_activation": False}
    validate_document(document, run_id=manifest["run_id"], anchor=anchor, validator_ids={p.validator_id for p in processes})
    base.write_new(output / ARTIFACT, base.canonical_json(document))
    return document
