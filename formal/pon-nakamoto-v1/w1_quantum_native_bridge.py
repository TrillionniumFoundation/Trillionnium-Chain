#!/usr/bin/env python3
"""Read one externally pinned native cohort and replay its W1 winner predicate.

The archive is read only. Its original nine process records are rechecked by the
existing native adapter in a temporary directory. One native-sized PGH2 macro
execution is compared with the separate scalar relation and the retained native
observations. This is neither a native rerun nor quantum hardware execution.
Exit zero means these finite bridge checks agree; qualification remains HOLD.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import subprocess
import sys
import tempfile
import zipfile

sys.dont_write_bytecode = True
FORMAL = Path(__file__).resolve().parent
ROOT = FORMAL.parents[1]
NATIVE = ROOT / "formal/pon-native-fullpath-v1"
sys.path.insert(0, str(NATIVE))
import adapt_native
import fullpath_gate as gate
import work_oracle
from w1_quantum_oracle import FixedTemplate, OracleProgram, SOURCE_FILES

SCHEMA = "trnm-w1-native-oracle-bridge-v1"
MAX_ARCHIVE = 8 * 1024 * 1024
MAX_MEMBER = 4 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024
PROCESS_IDS = (
    "produce", "receive", "observe", "duplicate", "duplicate-observe",
    "late-product", "late-product-observe", "cancelled", "cancelled-observe",
)
READER_SOURCES = tuple(dict.fromkeys(SOURCE_FILES + (
    "formal/pon-nakamoto-v1/w1_quantum_native_bridge.py",
    "formal/pon-nakamoto-v1/contract_wire.py",
    "formal/pon-native-fullpath-v1/adapt_native.py",
    "formal/pon-native-fullpath-v1/fullpath_gate.py",
    "formal/pon-native-fullpath-v1/collect_native.py",
    "config/pon/ledger-v1.json", "config/pon/work-profile-v1.json",
    "config/pon/model-family-v1.json", "config/pon/devnet-v1.json",
    "config/pon/evaluation-round-v1.json",
)))
QUALIFICATION = {
    "overall_gate": "HOLD", "quantum_hardware_executed": False,
    "native_node_executed_by_bridge": False, "native_leaf_gate_execution": False,
    "native_admission_authorized_by_oracle": False,
    "native_binary_rebuilt_or_reauthenticated_by_bridge": False,
    "physical_hardware_calibrated": False, "attacker_optimality_proved": False,
    "quantum_work_lower_bound_proved": False, "quantum_mining_qualified": False,
    "public_network_qualified": False, "production_activation": False,
}


@dataclass(frozen=True)
class NativePins:
    artifact_sha256: str
    native_source: str
    native_tree: str
    preregistration_sha256: str
    binary_sha256: str

    def validate(self):
        for key, value in asdict(self).items():
            gate.hex_value(value, "EXTERNAL_PIN_" + key.upper(),
                           20 if key in {"native_source", "native_tree"} else 32)


def source_commitment(root, files, ref="HEAD"):
    """Check actual Git objects for the declared inputs, not whole-tree cleanliness."""
    if ref != "HEAD":
        gate.hex_value(ref, "HISTORICAL_SOURCE_COMMIT", 20)

    def git(*args):
        try:
            result = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)
        except OSError:
            return None
        return result.stdout.strip() if result.returncode == 0 else None

    head = git("rev-parse", "--verify", ref + "^{commit}")
    if ref != "HEAD":
        gate.require(head == ref, "HISTORICAL_SOURCE_UNAVAILABLE")
    tree = git("rev-parse", "--verify", head + "^{tree}") if head else None
    different = [name for name, row in files.items()
                 if head is None or git("rev-parse", "--verify", head + ":" + name) != row["git_blob_sha1"]]
    committed = head is not None and tree is not None and not different
    return {"git_head": head, "git_tree": tree, "all_sources_committed_at_head": committed,
            "uncommitted_source_files": different,
            "source_commitment_state": "COMMITTED_DECLARED_INPUTS" if committed else
                "NO_GIT_HEAD" if head is None else "UNCOMMITTED_DECLARED_INPUTS"}


def source_record():
    rows = {}
    for name in READER_SOURCES:
        raw = gate.Evidence(ROOT).read(name, MAX_MEMBER)
        rows[name] = {"bytes": len(raw), "sha256": gate.sha256(raw),
                      "git_blob_sha1": hashlib.sha1(b"blob " + str(len(raw)).encode()
                                                   + b"\0" + raw).hexdigest()}
    return {**source_commitment(ROOT, rows),
            "files": rows, "scope": "explicit reader and relation inputs; not a full native build graph"}


def verify_source_record(recorded, current, root=ROOT):
    """Allow an evidence-only descendant after checking the historical commit/tree/blobs."""
    gate.keys(recorded, current, "BRIDGE_SOURCE_SCHEMA")
    gate.require(recorded["scope"] == current["scope"]
                 and gate.canonical(recorded["files"]) == gate.canonical(current["files"]),
                 "BRIDGE_SOURCE_FILES")
    if gate.canonical(recorded) == gate.canonical(current):
        return current
    # A development report may be checked on exactly the same observed inputs
    # and metadata; it cannot borrow an arbitrary HEAD to acquire provenance.
    gate.require(recorded["all_sources_committed_at_head"] is True,
                 "HISTORICAL_SOURCE_WAS_NOT_COMMITTED")
    verified = {**source_commitment(root, current["files"], recorded["git_head"]),
                "files": current["files"], "scope": current["scope"]}
    gate.require(verified["all_sources_committed_at_head"] is True
                 and gate.canonical(recorded) == gate.canonical(verified),
                 "HISTORICAL_SOURCE_TREE_OR_BLOBS")
    return verified


def extract_archive(raw, root):
    """Bound decompression and reject aliases before writing into a fresh temp dir."""
    gate.require(type(raw) is bytes and len(raw) <= MAX_ARCHIVE, "ARCHIVE_SIZE")
    members, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        gate.require(0 < len(infos) <= 128, "ARCHIVE_MEMBER_COUNT")
        names = set()
        for item in infos:
            name = item.filename
            path = PurePosixPath(name)
            # ZipInfo truncates filename at NUL while retaining orig_filename.
            # Reject that alias rather than validating only the truncated view.
            gate.require(item.orig_filename == name and 0 < len(name) <= 256 and not path.is_absolute()
                         and "\\" not in name and "\0" not in name
                         and all(part not in {"", ".", ".."} for part in name.split("/"))
                         and str(path) == name and name not in names,
                         "ARCHIVE_MEMBER_PATH_OR_DUPLICATE")
            names.add(name)
            mode = item.external_attr >> 16
            gate.require(not item.is_dir() and stat.S_IFMT(mode) in {0, stat.S_IFREG}
                         and item.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                         and not item.flag_bits & 1, "ARCHIVE_MEMBER_TYPE")
            gate.require(0 <= item.file_size <= MAX_MEMBER, "ARCHIVE_MEMBER_SIZE")
            total += item.file_size
            gate.require(total <= MAX_EXPANDED, "ARCHIVE_EXPANSION_BOUND")
        for name in names:
            gate.require(not any(str(parent) in names for parent in PurePosixPath(name).parents),
                         "ARCHIVE_FILE_PARENT_COLLISION")
        for item in infos:
            name = item.filename
            with archive.open(item) as stream:
                data = stream.read(MAX_MEMBER + 1)
            gate.require(len(data) == item.file_size, "ARCHIVE_MEMBER_LENGTH")
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("xb") as stream:
                stream.write(data)
            members[name] = {"bytes": len(data), "sha256": gate.sha256(data)}
    return members


def validate_native(root, pins):
    """Recheck original source guards, process bytes and the unchanged native gate."""
    pins.validate()
    evidence = gate.Evidence(root)
    guards = []
    for name in ("source-before.json", "source-after.json"):
        value = gate.decode(evidence.read(name))
        gate.keys(value, "base candidate kind prospective_merge schema tested_commit tested_tree "
                  "tests_executed_by_identity_check tracked_bytes tracked_entries tracked_worktree_verified".split(),
                  "SOURCE_GUARD_SCHEMA")
        gate.require(value["schema"] == "trnm-ci-source-v1" and value["kind"] == "head"
                     and value["candidate"] == value["tested_commit"] == pins.native_source
                     and value["tested_tree"] == pins.native_tree
                     and value["base"] is value["prospective_merge"] is None
                     and value["tracked_worktree_verified"] is True
                     and value["tests_executed_by_identity_check"] is False, "SOURCE_GUARD_BINDING")
        gate.integer(value["tracked_entries"], "SOURCE_ENTRIES", 1)
        gate.integer(value["tracked_bytes"], "SOURCE_BYTES", 1)
        guards.append(value)
    gate.require(guards[0] == guards[1], "SOURCE_GUARD_CHANGED")
    capture = gate.decode(evidence.read("collector-output.json"))
    gate.keys(capture, "manifest_sha256 observations_sha256 observed_through_ns output processes "
              "qualification source_and_binary_unchanged".split(), "COLLECTOR_OUTPUT_SCHEMA")
    original = gate.Evidence(root / "processes")
    context = gate.decode(original.read("context.json"))
    gate.keys(context, "binary_sha256 clock collector_sha256 hardware native_context original_business_contract "
              "process_timeout_seconds production_activation resource_enforcement resource_measurement "
              "schema scope source_commit source_tree transport workload".split(), "NATIVE_CONTEXT_SCHEMA")
    gate.require(context["source_commit"] == pins.native_source
                 and context["source_tree"] == pins.native_tree
                 and context["binary_sha256"] == pins.binary_sha256, "NATIVE_SOURCE_OR_BINARY_BINDING")
    gate.require(context["collector_sha256"] == gate.sha256((NATIVE / "collect_native.py").read_bytes()),
                 "COLLECTOR_SOURCE_BINDING")
    native_context = context["native_context"]
    gate.require(context["production_activation"] is False
                 and native_context.get("development") is True
                 and native_context.get("namespace") == "pon-native-fullpath-development-v1"
                 and native_context.get("production_activation") is False
                 and native_context.get("quantum_lower_bound_proved") is False, "NATIVE_SCOPE_PROMOTION")
    observed_raw = original.read("process-observations.json")
    observed = gate.decode(observed_raw)
    gate.keys(observed, "attempts collection_errors compressed_path_executed context_sha256 cpu_ns "
              "manifest_sha256 observed_through_ns original_host_contract_qualified owner_unresolved "
              "peak_rss_upper_bound_bytes processes production_activation qualification quantum_lower_bound_proved "
              "resource_accounting_complete schema security_gate source_and_binary_unchanged stdin_bytes_written "
              "unresolved_owner".split(), "NATIVE_OBSERVATIONS_SCHEMA")
    gate.require(capture["manifest_sha256"] == pins.preregistration_sha256
                 and capture["observations_sha256"] == gate.sha256(observed_raw)
                 and capture["observed_through_ns"] == observed["observed_through_ns"]
                 and type(capture["processes"]) is int and capture["processes"] == 9
                 and capture["source_and_binary_unchanged"] is True
                 and capture["qualification"] == "HOLD", "COLLECTOR_OUTPUT_BINDING")
    gate.require(observed["source_and_binary_unchanged"] is True
                 and observed["owner_unresolved"] is False and observed["unresolved_owner"] is None
                 and observed["resource_accounting_complete"] is True
                 and observed["collection_errors"] == [], "NATIVE_COLLECTION_INCOMPLETE")
    gate.require(observed["qualification"] == observed["security_gate"] == "HOLD"
                 and all(observed[field] is False for field in (
                     "production_activation", "quantum_lower_bound_proved",
                     "compressed_path_executed", "original_host_contract_qualified")), "NATIVE_SCOPE_PROMOTION")
    gate.require([row.get("id") for row in observed["processes"]] == list(PROCESS_IDS),
                 "NINE_ORIGINAL_PROCESSES_REQUIRED")
    # Original argv values are checked only as evidence; never execute archive commands.
    base = capture["output"]
    gate.require(type(base) is str and base.startswith("/") and str(PurePosixPath(base)) == base
                 and ".." not in PurePosixPath(base).parts, "ORIGINAL_OUTPUT_PATH")
    binary = observed["processes"][0]["argv"][0]
    gate.require(type(binary) is str and PurePosixPath(binary).name == "native_fullpath_v1",
                 "ORIGINAL_BINARY_PATH")
    expected_args = (
        ["produce", "--development", base + "/producer", base + "/candidate.pnp2", "4096"],
        ["receive", "--development", base + "/receiver"],
        ["observe", "--development", base + "/receiver", base + "/candidate.pnp2"],
        ["resubmit", "--development", base + "/receiver"],
        ["observe", "--development", base + "/receiver", base + "/candidate.pnp2"],
        ["receive", "--development", base + "/late-product-store"],
        ["observe", "--development", base + "/late-product-store", base + "/late-product.pnp2"],
        ["receive-cancel", "--development", base + "/cancelled-store"],
        ["observe", "--development", base + "/cancelled-store", base + "/candidate.pnp2"],
    )
    for row, argv in zip(observed["processes"], expected_args):
        gate.require(row.get("argv") == [binary, *argv], "ORIGINAL_PROCESS_ARGV")
    readback = adapt_native.adapt(root / "processes", pins.preregistration_sha256)
    gate.require(gate.decode(evidence.read("reader-stdout.json")) == readback,
                 "STORED_NATIVE_READBACK_DIFFERS")
    attempts = {row["id"]: row for row in readback["attempts"]}
    gate.require({key: row["status"] for key, row in attempts.items()} == {
        "valid": "accepted", "duplicate": "duplicate", "late_product": "rejected", "cancelled": "cancelled"
    } and readback["scheduled"] == readback["recorded"] == 4 and readback["missing"] == [],
        "ORIGINAL_COHORT_OUTCOMES")
    gate.require(attempts["valid"]["full_native_replay_observed"] is True
                 and attempts["valid"]["full_path_completed"] is True
                 and attempts["valid"]["last_canonical_depth"] == 0
                 and attempts["late_product"]["late_product_rejection_observed"] is True
                 and all(attempts[key]["full_native_replay_observed"] is False
                         for key in ("duplicate", "late_product", "cancelled"))
                 and readback["recorded_unique_new_native_blocks"] == 1
                 and readback["timely_accepted_progress"] == 0
                 and readback["overall_gate"] == readback["security_gate"] == "HOLD",
                 "NATIVE_OBSERVATION_BOUNDARY")
    return context, observed, readback


def differential(candidate, late_product):
    """Run one native-shaped macro; the two packets have the same predicate input."""
    statement = gate.parse_packet(candidate)
    late_statement = gate.parse_packet(late_product)
    changed = bytearray(candidate)
    original_word = int.from_bytes(changed[-36:-32], "little")
    changed[-36:-32] = ((original_word + 1) % work_oracle.Q).to_bytes(4, "little")
    gate.require(bytes(changed) == late_product and late_product != candidate, "LATE_PRODUCT_MUTATION")
    proof = candidate[-work_oracle.PROOF_BYTES:]
    header = bytes.fromhex(statement["claim"]["header_hex"])
    challenge, task, target = (bytes.fromhex(statement[key])
                               for key in ("challenge_hex", "task_hex", "target_hex"))
    ticket, product = work_oracle.verify(challenge, task, target, proof)
    try:
        work_oracle.verify(challenge, task, target, late_product[-work_oracle.PROOF_BYTES:])
    except ValueError as error:
        gate.require(str(error) == "PRODUCT", "LATE_PRODUCT_SCALAR_REASON")
    else:
        raise ValueError("LATE_PRODUCT_SCALAR_ACCEPTED")
    ab = struct.unpack("<" + "I" * (2 * work_oracle.CELLS), proof[4:4 + 8 * work_oracle.CELLS])
    template = FixedTemplate.from_header(header, ab[:work_oracle.CELLS], ab[work_oracle.CELLS:])
    gate.require(template.profile == "PGH2" and template.shape.native, "NATIVE_PGH2_SHAPE")
    program = OracleProgram(template)
    oracle = program.execute(statement["nonce"], mode="macro")
    gate.require(oracle["challenge"] == challenge.hex() and oracle["trace"] == proof[-32:].hex()
                 and oracle["ticket"] == ticket.hex() and oracle["winner"] is True
                 and oracle["phase"] == -1 and oracle["noise_complete"] == [True] * 4,
                 "SCALAR_ORACLE_DIFFERENTIAL")
    gate.require(oracle["clean_ancillas"] is True and oracle["nonce_preserved"] is True
                 and oracle["inverse_executed"] is True and oracle["native_shape"] is True
                 and oracle["mode"] == "macro" and oracle["leaf_gates_executed"] is None
                 and oracle["quantum_hardware_executed"] is False, "ORACLE_EXECUTION_SCOPE")
    for field in ("challenge_hex", "task_hex", "target_hex", "nonce", "block_hex"):
        gate.require(statement[field] == late_statement[field], "LATE_PRODUCT_STATEMENT_CHANGED")
    return {
        "valid_packet": {"identity": statement, "scalar_full_relation_valid": True,
                         "scalar_ticket_hex": ticket.hex(),
                         "scalar_product_sha256": gate.sha256(work_oracle.field_bytes(product))},
        "oracle": oracle,
        "construction_sha256": program.resources()["construction_sha256"],
        "late_product_counterexample": {
            "identity": late_statement, "scalar_full_relation_valid": False,
            "scalar_error": "PRODUCT", "native_error_observed": "WORK:Product",
            "same_fixed_template_and_nonce": True, "oracle_observation_reused_from_valid": True,
            "oracle_winner": oracle["winner"], "separate_oracle_execution": False,
            "changed_product_word_index": work_oracle.CELLS - 1,
            "original_product_word": original_word,
            "changed_product_word": (original_word + 1) % work_oracle.Q,
            "oracle_winner_is_not_submitted_proof_validity_or_admission": True,
        },
        "counts": {"distinct_packet_bytes": 2, "scalar_full_relation_attempts": 2,
                   "scalar_valid_packets": 1, "scalar_product_refusals": 1,
                   "distinct_oracle_templates": 1, "native_sized_macro_executions": 1,
                   "native_sized_leaf_gate_executions": 0, "new_native_processes": 0},
    }


def run_bridge(archive, pins):
    pins.validate()
    before = source_record()
    archive = Path(archive)
    raw = gate.Evidence(archive.parent).read(archive.name, MAX_ARCHIVE)
    gate.require(gate.sha256(raw) == pins.artifact_sha256, "ARCHIVE_SHA256")
    with tempfile.TemporaryDirectory(prefix="trnm-w1-native-bridge-") as temporary:
        root = Path(temporary)
        members = extract_archive(raw, root)
        context, observed, native = validate_native(root, pins)
        evidence = gate.Evidence(root / "processes")
        compared = differential(evidence.read("candidate.pnp2", gate.PACKET_LIMIT),
                                evidence.read("late-product.pnp2", gate.PACKET_LIMIT))
        gate.require(compared["valid_packet"]["identity"]["block_hex"]
                     == native["attempts"][0]["block_hex"], "NATIVE_ORACLE_BLOCK_IDENTITY")
    after = source_record()
    gate.require(before == after, "READER_SOURCE_CHANGED")
    return {"schema": SCHEMA, "result": "BOUNDED_BRIDGE_OBSERVATIONS_CONSISTENT",
            "scope": "one retained exact-source development native cohort and one PGH2 macro differential",
            "external_pins": asdict(pins), "source": before, "source_inputs_unchanged": True,
            "archive_members": members,
            "native_provenance": {"source_commit": context["source_commit"],
                "source_tree": context["source_tree"], "binary_sha256": context["binary_sha256"],
                "collector_sha256": context["collector_sha256"],
                "source_guard_matches_external_pins": True,
                "pin_authenticity_verified_by_bridge": False,
                "original_preregistration_sha256": pins.preregistration_sha256,
                "processes": [{"id": row["id"], "pid": row["pid"], "exit_code": row["exit_code"],
                               "stdout": row["stdout"], "stderr": row["stderr"]}
                              for row in observed["processes"]]},
            "native_readback": native, "differential": compared,
            "qualification": dict(QUALIFICATION)}


def verify(record, archive, expected_pins):
    """Regenerate from original bytes/external pins and validate execution-source identity.

Identical declared inputs on a later evidence-only commit may verify the old
report only after its actual historical commit, tree and every blob are checked.
The returned value retains that original report identity, not a new native run.
"""
    expected_pins.validate()
    gate.require(type(record) is dict and record.get("schema") == SCHEMA,
                 "BRIDGE_REPORT_SCHEMA")
    gate.require(gate.canonical(record.get("external_pins")) == gate.canonical(asdict(expected_pins)),
                 "BRIDGE_REPORT_EXTERNAL_PINS")
    rebuilt = run_bridge(archive, expected_pins)
    rebuilt["source"] = verify_source_record(record.get("source"), rebuilt["source"])
    gate.require(gate.canonical(record) == gate.canonical(rebuilt), "BRIDGE_REPORT_REBUILD_MISMATCH")
    return rebuilt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--native-source", required=True)
    parser.add_argument("--native-tree", required=True)
    parser.add_argument("--preregistration-sha256", required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--verify", type=Path, help="rebuild and compare this saved report using the external pins")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        pins = NativePins(args.artifact_sha256, args.native_source, args.native_tree,
                          args.preregistration_sha256, args.binary_sha256)
        if args.verify is None:
            result = run_bridge(args.archive, pins)
        else:
            record = gate.decode(gate.Evidence(args.verify.parent).read(args.verify.name, MAX_MEMBER))
            result = verify(record, args.archive, pins)
        raw = json.dumps(result, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n"
        if args.output is not None:
            with args.output.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        else:
            sys.stdout.buffer.write(raw)
    except (ValueError, OSError, KeyError, TypeError, IndexError, zipfile.BadZipFile) as error:
        print(json.dumps({"schema": SCHEMA, "result": "REFUSED", "error": str(error),
                          "qualification": dict(QUALIFICATION)}, sort_keys=True))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
