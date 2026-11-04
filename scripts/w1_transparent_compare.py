#!/usr/bin/env python3
"""Re-run the frozen full-W1 native/transparent verifier comparison.

This is a Linux, saved-proof measurement tool. It does not run a prover, certify
an ELF build, measure confirmation, choose a consensus backend, or authorize work.
It snapshots the public assets, checks their bindings independently, invokes two
explicit hash-pinned local executables, and preserves every failed observation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import statistics
import subprocess
import time

SCHEMA = "trnm-w1-saved-proof-comparison-v1"
PROFILE_ID = "trnm-w1-risc0-3.0.6-poseidon2-join-v1"
HEADER_BYTES = 318
WITNESS_BYTES = 49188
INPUT_BYTES = HEADER_BYTES + WITNESS_BYTES
DOMAIN = b"TRNM-W1-ZK-JOURNAL1\0"
JOURNAL_BYTES = 16818
MODULUS = 4294967291
MAX_RECEIPT_BYTES = 16 * 1024 * 1024
MAX_LOG_BYTES = 4 * 1024 * 1024
IMAGE_ID = [4203990569, 1706128024, 889896351, 2751765305,
            3434005897, 1411617246, 870515685, 3215144349]
FROZEN_GUEST_SHA256 = "6b58409420f2bd3f7a733de531ce20144580b259fde8ca9362b43d9728a8772c"
FROZEN_SOURCE = "64be7c4ad51d432e7736ad135476262e23e968f5"
CONTROL_ID = "7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e"
VERIFIER_PARAMETERS = "ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013"
ASSETS = {"header.bin": HEADER_BYTES, "input.bin": INPUT_BYTES,
          "expected-journal.bin": JOURNAL_BYTES,
          "succinct.bin": MAX_RECEIPT_BYTES, "guest.bin": 8 * 1024 * 1024,
          "manifest.json": 1024 * 1024}
FORBIDDEN_ENV = ("RISC0_DEV_MODE", "BONSAI_API_URL", "BONSAI_API_KEY", "RISC0_PROVER")


class InvalidObservation(ValueError):
    """A required observation or binding is absent or invalid."""


def require(condition, message):
    if not condition:
        raise InvalidObservation(message)


def strict_json(data):
    def pairs(values):
        out = {}
        for key, value in values:
            require(key not in out, f"duplicate JSON key: {key}")
            out[key] = value
        return out

    def reject(value):
        raise InvalidObservation(f"nonfinite JSON constant: {value}")

    def finite(value):
        number = float(value)
        require(math.isfinite(number), "nonfinite JSON number")
        return number

    try:
        return json.loads(data, object_pairs_hook=pairs, parse_constant=reject, parse_float=finite)
    except (ValueError, UnicodeError, RecursionError, OverflowError) as error:
        raise InvalidObservation(str(error)) from error


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def bounded_read(path, maximum):
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    require(len(data) <= maximum, f"oversized input: {path.name}")
    return data


def write_new(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def exact_keys(row, keys, label):
    require(type(row) is dict and set(row) == set(keys), f"{label} fields differ")


def scalar(row, key, expected):
    require(key in row and type(row[key]) is type(expected) and row[key] == expected,
            f"invalid {key}")


def positive_integer(value, label):
    require(type(value) is int and 0 < value <= (1 << 63) - 1, f"invalid {label}")
    return value


def samples(row, key, count):
    values = row.get(key)
    require(type(values) is list and len(values) == count, f"invalid {key} count")
    for value in values:
        positive_integer(value, key)
    return values


def statistics_ns(values):
    require(type(values) is list and bool(values), "no samples")
    for value in values:
        positive_integer(value, "sample")
    ordered = sorted(values)
    n = len(ordered)
    return {"n": n, "min_ns": ordered[0], "median_ns": statistics.median(ordered),
            "sample_p95_ns": ordered[math.ceil(n * .95) - 1],
            "sample_p99_ns": ordered[math.ceil(n * .99) - 1], "max_ns": ordered[-1],
            "quantile_scope": "nearest rank within this one saved-work run; no population tail"}


def pon_hash(tag, *parts):
    value = hashlib.sha256(b"TRNM-PON1\0" + len(tag).to_bytes(2, "little") + tag)
    for part in parts:
        value.update(len(part).to_bytes(4, "little"))
        value.update(part)
    return value.digest()


def validate_assets(assets):
    """Byte binding only; actual full W1 and proof verification run separately."""
    header, data = assets["header.bin"], assets["input.bin"]
    journal, receipt = assets["expected-journal.bin"], assets["succinct.bin"]
    require(len(header) == HEADER_BYTES and header[:6] == b"PNH1\x01\x00", "PNH1 header")
    require(len(data) == INPUT_BYTES and data[:HEADER_BYTES] == header, "full input/header")
    witness = data[HEADER_BYTES:]
    require(witness[:4] == b"PNW1", "PNW1 witness")
    require(len(journal) == JOURNAL_BYTES and journal.startswith(DOMAIN + header), "journal/header")
    require(receipt[:4] == b"\x01\x00\x00\x00", "only Succinct receipt wire accepted")
    for start in range(4, WITNESS_BYTES - 32, 4):
        require(int.from_bytes(witness[start:start + 4], "little") < MODULUS,
                "noncanonical W1 matrix word")
    trace = witness[-32:]
    ticket = pon_hash(b"ticket", pon_hash(b"challenge", header), trace)
    work = pon_hash(b"block", header, trace)
    require(header[118:150] != bytes(32) and ticket <= header[118:150], "ticket target")
    offset = len(DOMAIN) + HEADER_BYTES
    require(journal[offset:offset + 96] == trace + ticket + work, "trace/ticket/work binding")
    require(journal[offset + 96:] == witness[4 + 2 * 4096 * 4:-32], "complete product binding")
    manifest = strict_json(assets["manifest.json"])
    exact_keys(manifest, ["schema", "source_commit", "runner_sha256", "guest_sha256",
                         "image_id", "r0vm_sha256", "input_sha256", "journal_sha256",
                         "full_claim_digest", "segment_limit_po2", "segments"], "frozen manifest")
    scalar(manifest, "schema", "TRNM-W1-STAGED-PROOF1")
    scalar(manifest, "source_commit", FROZEN_SOURCE)
    scalar(manifest, "guest_sha256", FROZEN_GUEST_SHA256)
    require(manifest["image_id"] == IMAGE_ID and all(type(x) is int for x in manifest["image_id"]),
            "frozen image ID")
    scalar(manifest, "input_sha256", digest(data))
    scalar(manifest, "journal_sha256", digest(journal))
    require(digest(assets["guest.bin"]) == FROZEN_GUEST_SHA256, "frozen guest ELF hash")
    for key in ["runner_sha256", "r0vm_sha256", "full_claim_digest"]:
        value = manifest[key]
        require(type(value) is str and len(value) == 64
                and all(c in "0123456789abcdef" for c in value), f"manifest {key}")
    scalar(manifest, "segment_limit_po2", 18)
    require(type(manifest["segments"]) is list and len(manifest["segments"]) == 59,
            "frozen segment manifest count")
    for index, segment in enumerate(manifest["segments"]):
        exact_keys(segment, ["index", "po2", "cycles", "bytes", "sha256"], "segment manifest")
        scalar(segment, "index", index)
        scalar(segment, "po2", 18)
        positive_integer(segment["cycles"], "manifest segment cycles")
        positive_integer(segment["bytes"], "manifest segment bytes")
        value = segment["sha256"]
        require(type(value) is str and len(value) == 64
                and all(c in "0123456789abcdef" for c in value), "manifest segment digest")
    return {"work_id": work.hex(), "ticket": ticket.hex(), "image_id": IMAGE_ID,
            "frozen_guest_source": FROZEN_SOURCE,
            "assets": {name: {"bytes": len(value), "sha256": digest(value)}
                       for name, value in assets.items()}}


def validate_native(row, identity, *, historical=False):
    base_keys = ["schema", "input_sha256", "input_bytes", "completed_native_full_verifications",
                 "native_full_verifier_ns", "scope", "cryptographic_proof_generated",
                 "mining_cost_distribution_established", "production_tail_established",
                 "consensus_admission"]
    if historical:
        exact_keys(row, base_keys, "historical native report")
        scalar(row, "schema", "trnm-w1-independent-native-cost-v1")
    else:
        exact_keys(row, base_keys + ["work_id_hex", "header_sha256", "journal_sha256"], "native report")
        scalar(row, "schema", "trnm-w1-independent-native-cost-v2")
        scalar(row, "work_id_hex", identity["work_id"])
        scalar(row, "header_sha256", identity["assets"]["header.bin"]["sha256"])
        scalar(row, "journal_sha256", identity["assets"]["expected-journal.bin"]["sha256"])
    scalar(row, "input_sha256", identity["assets"]["input.bin"]["sha256"])
    scalar(row, "input_bytes", INPUT_BYTES)
    scalar(row, "completed_native_full_verifications", 1000)
    for key in ["cryptographic_proof_generated", "mining_cost_distribution_established",
                "production_tail_established", "consensus_admission"]:
        scalar(row, key, False)
    require(type(row["scope"]) is str and bool(row["scope"]), "native measurement scope")
    return statistics_ns(samples(row, "native_full_verifier_ns", 1000))


def validate_verifier(row, identity, *, historical=False):
    fields = ["schema", "sdk", "outcome", "image_id", "work_id", "receipt_sha256",
              "receipt_bytes", "control_id", "hash_function", "verifier_parameters_digest",
              "seal_words", "header_sha256", "journal_sha256", "decode_ns", "first_verify_ns",
              "verifier_ns", "decode_verify_ns", "independent_proof_trials",
              "production_tail_established", "proof_randomness_tickets", "consensus_admission"]
    if historical:
        exact_keys(row, fields, "historical hardened report")
        scalar(row, "schema", "TRNM-W1-HARDENED-FULL-VERIFY1")
    else:
        exact_keys(row, fields + ["profile_id"], "hardened report")
        scalar(row, "schema", "TRNM-W1-HARDENED-FULL-VERIFY2")
        scalar(row, "profile_id", PROFILE_ID)
    scalar(row, "sdk", "3.0.6")
    scalar(row, "outcome", "SAVED_FULL_SUCCINCT_STARK_VERIFIED")
    require(row["image_id"] == IMAGE_ID and all(type(x) is int for x in row["image_id"]), "image ID")
    scalar(row, "work_id", identity["work_id"])
    for key, asset in [("receipt_sha256", "succinct.bin"), ("header_sha256", "header.bin"),
                       ("journal_sha256", "expected-journal.bin")]:
        scalar(row, key, identity["assets"][asset]["sha256"])
    scalar(row, "receipt_bytes", identity["assets"]["succinct.bin"]["bytes"])
    scalar(row, "independent_proof_trials", 1)
    scalar(row, "proof_randomness_tickets", 0)
    for key in ["production_tail_established", "consensus_admission"]:
        scalar(row, key, False)
    for key in ["seal_words", "decode_ns", "first_verify_ns"]:
        positive_integer(row[key], key)
    scalar(row, "control_id", CONTROL_ID)
    scalar(row, "verifier_parameters_digest", VERIFIER_PARAMETERS)
    scalar(row, "hash_function", "poseidon2")
    return {"verify_only": statistics_ns(samples(row, "verifier_ns", 100)),
            "decode_and_verify": statistics_ns(samples(row, "decode_verify_ns", 100))}


def execute(command, directory, deadline):
    """Own one subprocess session; retain timeout/output/exit observations."""
    directory.mkdir()
    write_new(directory / "command.json", {"argv": command,
              "remaining_wall_seconds": max(0, deadline - time.monotonic()),
              "max_bytes_per_log": MAX_LOG_BYTES})
    started = time.monotonic()
    reason, usage, returncode = None, None, None
    child = None
    with (directory / "stdout.log").open("xb") as stdout, (directory / "stderr.log").open("xb") as stderr:
        try:
            require(time.monotonic() < deadline, "total deadline exhausted before process spawn")
            child = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
            while True:
                pid, status, usage = os.wait4(child.pid, os.WNOHANG)
                if pid:
                    returncode = child.returncode = os.waitstatus_to_exitcode(status)
                    if time.monotonic() >= deadline:
                        reason = "COMPLETION_NOT_OBSERVED_BEFORE_DEADLINE"
                    break
                if time.monotonic() >= deadline:
                    reason = "TIMEOUT"
                elif max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) > MAX_LOG_BYTES:
                    reason = "OUTPUT_LIMIT"
                if reason:
                    os.killpg(child.pid, signal.SIGKILL)
                    _, status, usage = os.wait4(child.pid, 0)
                    returncode = child.returncode = os.waitstatus_to_exitcode(status)
                    break
                time.sleep(.01)
            if max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) > MAX_LOG_BYTES:
                reason = "OUTPUT_LIMIT"
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                pass
            else:
                reason = "DESCENDANTS_REMAINED"
                os.killpg(child.pid, signal.SIGKILL)
        except BaseException as error:
            reason = f"INTERRUPTED_OR_NOT_STARTED:{type(error).__name__}"
            if child and child.returncode is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                _, status, usage = os.wait4(child.pid, 0)
                returncode = child.returncode = os.waitstatus_to_exitcode(status)
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                write_new(directory / "interrupted.json", {"reason": reason, "returncode": returncode})
                raise
    result = {"returncode": returncode, "termination_reason": reason,
              "elapsed_wall_seconds": time.monotonic() - started,
              "child_user_cpu_seconds": usage.ru_utime if usage else None,
              "child_system_cpu_seconds": usage.ru_stime if usage else None,
              "child_peak_rss_bytes": usage.ru_maxrss * 1024 if usage else None,
              "rusage_scope": "Linux wait4 of direct child; no aggregate process-tree peak or host isolation claim",
              "stdout_sha256": file_digest(directory / "stdout.log"),
              "stderr_sha256": file_digest(directory / "stderr.log")}
    write_new(directory / "process.json", result)
    return result


def source_identity(root, commit):
    require(type(commit) is str and len(commit) == 40 and all(c in "0123456789abcdef" for c in commit),
            "explicit full source commit required")
    resolved = subprocess.check_output(["git", "rev-parse", f"{commit}^{{commit}}"], cwd=root, text=True).strip()
    require(resolved == commit, "source commit mismatch")
    tree = subprocess.check_output(["git", "rev-parse", f"{commit}^{{tree}}"], cwd=root, text=True).strip()
    return {"commit": commit, "tree": tree,
            "elf_build_link": "caller-declared source; this observer does not certify reproducible compilation"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proof-dir", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--native-sha256", required=True)
    parser.add_argument("--verifier-sha256", required=True)
    parser.add_argument("--native-source-commit", required=True)
    parser.add_argument("--verifier-source-commit", required=True)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--total-wall-seconds", type=int, default=120)
    parser.add_argument("--bandwidth-bps", type=int)
    args = parser.parse_args(argv)
    require(1 <= args.total_wall_seconds <= 600, "wall budget outside [1,600]")
    if args.bandwidth_bps is not None:
        positive_integer(args.bandwidth_bps, "bandwidth")
    args.out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    deadline = started + args.total_wall_seconds
    report = {"schema": SCHEMA, "outcome": "INCOMPLETE", "error": None,
              "planned_stages": ["native", "transparent"], "stages": {},
              "wall_budget_scope": "One shared deadline through final acceptance; final report write excluded.",
              "new_proofs_generated": 0, "logical_work_items": 1,
              "prover_cost": None, "post_find_publication_delay": None,
              "independent_confirmation_latency": None, "stale_block_observation": None,
              "production_tail_established": False, "end_to_end_benefit_established": False,
              "quantum_soundness_qualified": False, "consensus_admission": False,
              "qualification": "HOLD",
              "relation_scope": "Saved guest W1 relation; Node parent-state task eligibility and separately committed A/B artifacts are not established by this observation.",
              "source_equivalence_established": False}
    try:
        require(all(os.environ.get(name) is None for name in FORBIDDEN_ENV), "unexpected proof environment")
        assets = {name: bounded_read(args.proof_dir / name, limit) for name, limit in ASSETS.items()}
        identity = validate_assets(assets)
        report["identity"] = identity
        inputs = args.out / "inputs"
        inputs.mkdir()
        for name, content in assets.items():
            with (inputs / name).open("xb") as stream:
                stream.write(content)
        binaries = {"native": args.native.resolve(strict=True), "transparent": args.verifier.resolve(strict=True)}
        pins = {"native": args.native_sha256, "transparent": args.verifier_sha256}
        for name, binary in binaries.items():
            require(binary.is_file() and os.access(binary, os.X_OK), f"{name} executable required")
            require(file_digest(binary) == pins[name], f"{name} executable pin mismatch")
        declared = {"native": source_identity(args.source_root, args.native_source_commit),
                    "transparent": source_identity(args.source_root, args.verifier_source_commit)}
        report["executables"] = {name: {"path": str(path), "sha256": pins[name], "source": declared[name]}
                                 for name, path in binaries.items()}
        write_new(args.out / "declaration.json", {"schema": SCHEMA, "identity": identity,
                  "executables": report["executables"], "observer_sha256": file_digest(Path(__file__)),
                  "total_wall_seconds": args.total_wall_seconds, "clock": "monotonic",
                  "machine": dict(zip(("sysname", "nodename", "release", "version", "machine"), os.uname()))})
        commands = {"native": [str(binaries["native"]), str((inputs / "input.bin").resolve())],
                    "transparent": [str(binaries["transparent"]), "benchmark",
                                    str((inputs / "header.bin").resolve()), str((inputs / "succinct.bin").resolve())]}
        errors = []
        validated = {}
        for name in ["native", "transparent"]:
            row = execute(commands[name], args.out / name, deadline)
            report["stages"][name] = row
            try:
                require(row["returncode"] == 0 and row["termination_reason"] is None,
                        f"{name} process failed or incomplete")
                observed = strict_json(bounded_read(args.out / name / "stdout.log", MAX_LOG_BYTES))
                validated[name] = (validate_native if name == "native" else validate_verifier)(observed, identity)
            except (OSError, InvalidObservation) as error:
                errors.append(str(error))
        for name, path in binaries.items():
            require(file_digest(path) == pins[name], f"{name} executable changed during run")
        for name, content in assets.items():
            require(file_digest(inputs / name) == digest(content), f"snapshot changed: {name}")
        require(not errors, "; ".join(errors))
        native, candidate = validated["native"], validated["transparent"]
        receipt_bytes = identity["assets"]["succinct.bin"]["bytes"]
        cost_ratio = candidate["decode_and_verify"]["median_ns"] / native["median_ns"]
        report.update(fixed_input_native=native,
                      fixed_receipt_transparent=candidate,
                      fixed_input_decode_verify_median_ratio=cost_ratio,
                      native_witness_bytes=WITNESS_BYTES, transparent_receipt_bytes=receipt_bytes,
                      receipt_over_witness_ratio=receipt_bytes / WITNESS_BYTES,
                      header_witness_plus_receipt_bytes=HEADER_BYTES + WITNESS_BYTES + receipt_bytes,
                      size_scope="Encoding sizes only. The current journal does not bind separate A/B artifacts; proof acceptance does not establish that Node can omit its native witness.",
                      selected_components_improve=receipt_bytes < WITNESS_BYTES and cost_ratio < 1,
                      comparison_scope="Both include decode; exclude file I/O, prove, transport and confirmation. Native excludes extra journal construction. Frozen guest and current native source remain distinct.")
        if args.bandwidth_bps is not None:
            report["payload_only_transmission_model"] = {
                "bandwidth_bps": args.bandwidth_bps,
                "header_and_witness_encoding_seconds": 8 * (HEADER_BYTES + WITNESS_BYTES) / args.bandwidth_bps,
                "header_and_receipt_encoding_seconds": 8 * (HEADER_BYTES + receipt_bytes) / args.bandwidth_bps,
                "header_witness_and_receipt_encoding_seconds": 8 * (HEADER_BYTES + WITNESS_BYTES + receipt_bytes) / args.bandwidth_bps,
                "scope": "Analytic encoding bits/rate only, not valid Node block wire-size or propagation equivalence. No network, queue, loss, gossip, overlap or stale-block observation."}
        require(time.monotonic() < deadline, "COMPARISON_ACCEPTANCE_NOT_OBSERVED_BEFORE_DEADLINE")
        report["outcome"] = "SAVED_PROOF_COMPARISON_COMPLETE"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        report["observer_wall_seconds"] = time.monotonic() - started
        write_new(args.out / "result.json", report)
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return 0 if report["outcome"] == "SAVED_PROOF_COMPARISON_COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
