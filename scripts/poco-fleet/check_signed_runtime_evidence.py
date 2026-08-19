#!/usr/bin/env python3
"""Independently verify signed PoCO G3 per-validator runtime evidence.

This checker consumes the content-addressed artifacts of a prospective raw
run bundle.  It deliberately ignores the older unsigned validator event log:
that log may provide external wall-clock observations, but it is not Safety,
finality, process-ancestry, or run-completion authority.

The accepted bundle must contain, for every validator, one canonical fleet
StartCertificate, signed runtime-event journal, terminal consensus report,
runtime metrics value, and final-state value. All hashes, cross-artifact
bindings, and Ed25519 signatures are recomputed here without importing the
Rust validator implementation.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import pathlib
import re
import subprocess
import tempfile
from typing import Any

import check_run_evidence
import evidence_bundle_profiles_v1 as evidence_profiles

from poco_consensus_contract import (
    PARAMETERS_DOMAIN,
    canonical_lab_genesis_hash,
    cev0_hash,
    reference_parameters_bytes,
)


HEX32 = re.compile(r"^[0-9a-f]{64}$")
HEX64 = re.compile(r"^[0-9a-f]{128}$")
RUN_ID = re.compile(
    r"^poco-g3-(7|31|100)-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$"
)
VALID_COUNTS = {7, 31, 100}
REQUIRED_FAULTS = {
    "leader_loss",
    "validator_process_kill",
    "host_loss",
    "asymmetric_partition",
    "bounded_delay_loss",
    "stale_snapshot",
    "rollback_attempt",
    "epoch_handoff",
}
KNOWN_RUNTIME_EVENT_KINDS = {
    "process_start",
    "peer_session_established",
    "fleet_ready",
    "fleet_started",
    "restart",
    "proposal_admitted",
    "vote_broadcast",
    "quorum_certificate_admitted",
    "timeout_vote_broadcast",
    "timeout_certificate_admitted",
    "finalized",
    "application_acknowledged",
    "catchup_complete",
    "fault_applied",
    "fault_recovered",
    "final_tip",
    "safety_halted",
    "clean_stop",
}
REQUIRED_CONTINUOUS_EVENT_KINDS = {
    "fleet_ready",
    "fleet_started",
    "vote_broadcast",
    "quorum_certificate_admitted",
    "finalized",
    "application_acknowledged",
    "final_tip",
    "clean_stop",
}
MAX_JOURNAL_BYTES = 32 * 1024 * 1024
MAX_EVENTS = 262_144
MAX_REPORT_BYTES = 512 * 1024
MAX_RUNTIME_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_FLEET_START_CERTIFICATE_BYTES = 4 * 1024 * 1024
MAX_DURATION_SECONDS = 7 * 24 * 60 * 60
MAX_BLOCKS = 10_000_000
MAX_SIGNER_INTENTS = 4_096
MAX_SIGNED_REPLAY_ARCHIVE_ENTRIES = 8_192
PACEMAKER_BASE_TIMEOUT_SECONDS = 2
TERMINAL_DRAIN_ALLOWANCE_SECONDS = 30
TIMEOUT_VIEW_BUDGET_ALLOWANCE_SECONDS = 30
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
_VERIFIED_ED25519: set[tuple[str, bytes, str]] = set()

EVENT_HASH_DOMAIN = b"trnm.poco-g3.runtime-event.v1"
EVENT_SIGNATURE_DOMAIN = b"trnm.poco-g3.runtime-event-signature.v1"
REPORT_HASH_DOMAIN = b"trnm.poco-g3.consensus-run-report.v3"
REPORT_SIGNATURE_DOMAIN = b"trnm.poco-g3.consensus-run-report-signature.v3"
METRICS_HASH_DOMAIN = b"trnm.poco-g3.runtime-metrics.body.v2"
METRICS_SIGNATURE_DOMAIN = b"trnm.poco-g3.runtime-metrics.signature.v2"
FINAL_STATE_HASH_DOMAIN = b"trnm.poco-g3.runtime-final-state.body.v3"
FINAL_STATE_SIGNATURE_DOMAIN = b"trnm.poco-g3.runtime-final-state.signature.v3"
VALIDATOR_SET_DOMAIN = b"trnm.poco-bft.validator-set.v0"

EVENT_KEYS = (
    "schema_version",
    "run_id",
    "validator_id",
    "process_instance",
    "sequence",
    "monotonic_ns",
    "kind",
    "subject",
    "value",
    "coordinator_manifest_sha256",
    "validator_set_sha256",
    "config_sha256",
    "candidate_source_sha256",
    "binary_sha256",
    "previous_event_sha256",
    "event_sha256",
    "signature",
    "production_activation",
)
EVENT_BODY_KEYS = tuple(
    key for key in EVENT_KEYS if key not in {"event_sha256", "signature"}
)
REPORT_KEYS = (
    "schema_version",
    "run_id",
    "protocol_id",
    "profile",
    "network_scope",
    "validator_id",
    "validator_set_id",
    "validator_set_sha256",
    "topology_sha256",
    "coordinator_manifest_sha256",
    "candidate_source_sha256",
    "binary_sha256",
    "config_sha256",
    "host_id",
    "process_id",
    "process_instance",
    "requested_duration_seconds",
    "requested_max_blocks",
    "pacemaker_base_timeout_seconds",
    "terminal_drain_allowance_seconds",
    "timeout_view_budget_allowance_seconds",
    "signer_journal_capacity",
    "maximum_timeout_view_advances",
    "maximum_local_vote_intents",
    "maximum_local_timeout_intents",
    "maximum_total_signer_intents",
    "signed_replay_archive_capacity",
    "maximum_proposal_archive_entries",
    "maximum_quorum_certificate_archive_entries",
    "maximum_signed_replay_archive_entries",
    "ordinary_start_height",
    "started_monotonic_ns",
    "ended_monotonic_ns",
    "monotonic_clock",
    "external_wall_clock_temporal_provenance",
    "submitted_height",
    "committed_height",
    "finalized_height",
    "submitted_ordinary_block_count",
    "committed_ordinary_block_count",
    "finalized_ordinary_block_count",
    "application_head_block_id",
    "application_committed_height",
    "application_state_root",
    "safety_revision",
    "safety_state_record_checksum",
    "safety_record_chain_checksum",
    "application_store_id",
    "application_store_sequence",
    "application_head_row_checksum",
    "whole_node_checkpoint_generation",
    "whole_node_checkpoint_checksum",
    "signer_scope",
    "signer_journal_id",
    "signer_watermark_sequence",
    "signer_chain_checksum",
    "continuous_signed_vote_intents",
    "continuous_signed_timeout_intents",
    "runtime_event_sequence",
    "runtime_event_sha256",
    "safety_halt_count",
    "double_vote_count",
    "double_timeout_count",
    "conflicting_certificate_count",
    "pending_safety_persistence_count",
    "pending_payload_validation_count",
    "pending_signature_count",
    "pending_finalization_count",
    "pending_sync_count",
    "unresolved_obligation_count",
    "clean_stop",
    "validator_run_completed",
    "continuous_consensus_runtime",
    "g3_evidence_complete",
    "geo_wan_evidence",
    "production_activation",
    "report_sha256",
    "signature",
)
REPORT_BODY_KEYS = tuple(
    key for key in REPORT_KEYS if key not in {"report_sha256", "signature"}
)
METRICS_KEYS = (
    "schema_version",
    "run_id",
    "validator_id",
    "validator_set_sha256",
    "topology_sha256",
    "coordinator_manifest_sha256",
    "candidate_source_sha256",
    "binary_sha256",
    "config_sha256",
    "process_id",
    "process_instance_count",
    "ordinary_start_height",
    "runtime_event_sequence",
    "runtime_event_sha256",
    "consensus_report_sha256",
    "measurement_started_at",
    "measurement_ended_at",
    "runtime_started_monotonic_ns",
    "runtime_ended_monotonic_ns",
    "finality_samples_ms",
    "fsync_count",
    "cpu_seconds",
    "peak_rss_bytes",
    "disk_bytes",
    "network_tx_bytes",
    "network_rx_bytes",
    "os_metrics_corroboration",
    "validator_run_completed",
    "g3_evidence_complete",
    "geo_wan_evidence",
    "production_activation",
    "body_sha256",
    "signature",
)
METRICS_BODY_KEYS = tuple(
    key for key in METRICS_KEYS if key not in {"body_sha256", "signature"}
)
FINAL_STATE_KEYS = (
    "schema_version",
    "run_id",
    "validator_id",
    "validator_set_sha256",
    "topology_sha256",
    "coordinator_manifest_sha256",
    "candidate_source_sha256",
    "binary_sha256",
    "config_sha256",
    "process_id",
    "process_instance_count",
    "ordinary_start_height",
    "finalized_height",
    "finalized_ordinary_block_count",
    "finalized_block_id",
    "finalized_state_root",
    "finalized_chain_root",
    "applied_height",
    "finalized_nonempty_ordinary_block_count",
    "runtime_event_sequence",
    "runtime_event_sha256",
    "consensus_report_sha256",
    "runtime_metrics_sha256",
    "recovered_faults",
    "restart_completed",
    "double_sign_events",
    "duplicate_apply_events",
    "state_drift_events",
    "safety_halt_violations",
    "validator_run_completed",
    "g3_evidence_complete",
    "geo_wan_evidence",
    "production_activation",
    "body_sha256",
    "signature",
)
FINAL_STATE_BODY_KEYS = tuple(
    key for key in FINAL_STATE_KEYS if key not in {"body_sha256", "signature"}
)

REQUIRED_SINGLETON_ROLES = {
    "candidate_source",
    "linux_binary",
    "macos_binary",
    "material_builder_binary",
    "build_report",
    "coordinator_manifest",
} | set(evidence_profiles.COORDINATOR_PUBLIC_SINGLETON_PATHS)
REQUIRED_VALIDATOR_ROLES = {
    "validator_config",
    "validator_fleet_start_certificate",
    "validator_runtime_event_journal",
    "validator_consensus_run_report",
    "validator_runtime_metrics",
    "validator_runtime_final_state",
}


def fail(message: str) -> None:
    raise SystemExit(f"PoCO G3 signed runtime evidence invalid: {message}")


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON object name {key!r}")
        result[key] = value
    return result


def compact_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def ordered(value: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {key: value[key] for key in keys}


def exact(value: object, keys: set[str] | tuple[str, ...], field: str) -> dict[str, Any]:
    expected = set(keys)
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{field} keys must be exactly {sorted(expected)!r}")
    return value


def read_json_bytes(path: pathlib.Path, field: str, maximum: int | None = None) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        fail(f"cannot read {field}: {error}")
    if not raw or (maximum is not None and len(raw) > maximum):
        fail(f"{field} crosses its size bound")
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{field} is not one UTF-8 JSON document: {error}")
    if not isinstance(value, dict):
        fail(f"{field} must be one JSON object")
    return value, raw


def hex_bytes(value: object, length: int, field: str, *, nonzero: bool = False) -> bytes:
    pattern = HEX32 if length == 32 else HEX64 if length == 64 else None
    if not isinstance(value, str) or pattern is None or not pattern.fullmatch(value):
        fail(f"{field} must be canonical lowercase {length}-byte hex")
    decoded = bytes.fromhex(value)
    if nonzero and decoded == bytes(length):
        fail(f"{field} must not be zero")
    return decoded


def uint(value: object, field: str, *, positive: bool = False, maximum: int = (1 << 64) - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
        fail(f"{field} must be an unsigned integer")
    if positive and value == 0:
        fail(f"{field} must be positive")
    return value


def positive_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{field} must be a finite positive number")
    converted = float(value)
    if not math.isfinite(converted) or converted <= 0.0:
        fail(f"{field} must be a finite positive number")
    return converted


def canonical_utc_interval(start: object, end: object, field: str) -> None:
    pattern = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
    if not isinstance(start, str) or not isinstance(end, str):
        fail(f"{field} must be a canonical second-resolution UTC interval")
    if re.fullmatch(pattern, start) is None or re.fullmatch(pattern, end) is None:
        fail(f"{field} must be a canonical second-resolution UTC interval")
    try:
        started = datetime.datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ")
        ended = datetime.datetime.strptime(end, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        fail(f"{field} must be a canonical second-resolution UTC interval")
    if started >= ended:
        fail(f"{field} must be an increasing UTC interval")


def domain_hash(domain: bytes, body: bytes) -> bytes:
    return hashlib.sha256(domain + len(body).to_bytes(8, "big") + body).digest()


def validator_set_id(descriptor: dict[str, Any]) -> str:
    parameters_hash = cev0_hash(PARAMETERS_DOMAIN, reference_parameters_bytes())
    chain_id = descriptor["chain_id"].encode("utf-8")
    if len(chain_id) > 0xFFFF:
        fail("validator_set.chain_id crosses the CEV0 bound")
    body = bytearray()
    body.extend((0).to_bytes(2, "big"))
    body.extend(hex_bytes(descriptor["genesis_hash"], 32, "validator_set.genesis_hash", nonzero=True))
    body.extend(len(chain_id).to_bytes(2, "big"))
    body.extend(chain_id)
    body.extend(uint(descriptor["protocol_version"], "validator_set.protocol_version", maximum=(1 << 32) - 1).to_bytes(4, "big"))
    body.extend(uint(descriptor["epoch"], "validator_set.epoch").to_bytes(8, "big"))
    body.extend(parameters_hash)
    validators = descriptor["validators"]
    body.extend(len(validators).to_bytes(4, "big"))
    for index, validator in enumerate(validators):
        validator_id = hex_bytes(validator["validator_id"], 32, f"validator_set.validators[{index}].validator_id")
        body.extend(len(validator_id).to_bytes(4, "big"))
        body.extend(validator_id)
        body.extend(hex_bytes(validator["consensus_public_key"], 32, f"validator_set.validators[{index}].consensus_public_key"))
        body.extend(uint(validator["voting_power"], f"validator_set.validators[{index}].voting_power", positive=True).to_bytes(8, "big"))
    return cev0_hash(VALIDATOR_SET_DOMAIN, bytes(body)).hex()


def verify_ed25519(public_key: str, message: bytes, signature: str, field: str) -> None:
    public = ED25519_SPKI_PREFIX + hex_bytes(public_key, 32, f"{field}.public_key")
    signed = hex_bytes(signature, 64, f"{field}.signature")
    cache_key = (public_key, message, signature)
    if cache_key in _VERIFIED_ED25519:
        return
    with tempfile.TemporaryDirectory(prefix="poco-g3-signed-evidence-") as raw:
        root = pathlib.Path(raw)
        (root / "public.der").write_bytes(public)
        (root / "message.bin").write_bytes(message)
        (root / "signature.bin").write_bytes(signed)
        try:
            result = subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                    "-keyform", "DER", "-inkey", str(root / "public.der"),
                    "-in", str(root / "message.bin"), "-sigfile",
                    str(root / "signature.bin"),
                ],
                capture_output=True,
                check=False,
            )
        except OSError as error:
            fail(f"OpenSSL Ed25519 verifier unavailable: {error}")
    if result.returncode != 0:
        fail(f"{field} Ed25519 signature is invalid")
    _VERIFIED_ED25519.add(cache_key)


def safe_relative(value: object, field: str) -> pathlib.PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        fail(f"{field} must be a non-empty POSIX relative path")
    path = pathlib.PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        fail(f"{field} escapes the bundle")
    return path


def load_artifacts(root: pathlib.Path) -> tuple[dict[str, Any], dict[tuple[str, str], tuple[dict[str, Any], pathlib.Path]]]:
    manifest, _ = read_json_bytes(root / "manifest.json", "bundle manifest")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        fail("bundle manifest artifacts must be a list")
    records: dict[tuple[str, str], tuple[dict[str, Any], pathlib.Path]] = {}
    for index, raw in enumerate(artifacts):
        record = exact(raw, {"role", "subject", "path", "sha256", "bytes"}, f"artifacts[{index}]")
        role = record["role"]
        subject = record["subject"]
        if not isinstance(role, str) or not isinstance(subject, str):
            fail(f"artifacts[{index}] role/subject must be strings")
        pair = (role, subject)
        if pair in records:
            fail(f"duplicate artifact role/subject {pair!r}")
        relative = safe_relative(record["path"], f"artifacts[{index}].path")
        path = root.joinpath(*relative.parts)
        if path.is_symlink() or not path.is_file():
            fail(f"artifacts[{index}] must reference a regular non-symlink file")
        size = uint(record["bytes"], f"artifacts[{index}].bytes", positive=True)
        digest = hex_bytes(record["sha256"], 32, f"artifacts[{index}].sha256")
        content = path.read_bytes()
        if len(content) != size or hashlib.sha256(content).digest() != digest:
            fail(f"artifacts[{index}] content address mismatch")
        records[pair] = (record, path)
    return manifest, records


def artifact(records: dict[tuple[str, str], tuple[dict[str, Any], pathlib.Path]], role: str, subject: str = "") -> tuple[dict[str, Any], pathlib.Path]:
    try:
        return records[(role, subject)]
    except KeyError:
        fail(f"missing signed runtime artifact role={role!r} subject={subject!r}")


def verify_journal(
    path: pathlib.Path,
    expected: dict[str, Any],
    public_key: str,
) -> tuple[dict[str, Any], int, int, dict[str, Any]]:
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_JOURNAL_BYTES or not raw.endswith(b"\n"):
        fail(f"runtime journal[{expected['validator_id']}] crosses its exact framing bound")
    lines = raw[:-1].split(b"\n")
    if not lines or len(lines) > MAX_EVENTS or any(not line for line in lines):
        fail(f"runtime journal[{expected['validator_id']}] has invalid record cardinality")
    previous = bytes(32)
    process_instance = 0
    prior_monotonic: int | None = None
    last: dict[str, Any] | None = None
    safety_halts = 0
    current_process_id = 0
    kinds_seen: set[str] = set()
    restart_sequences: list[int] = []
    catchup_sequences: list[int] = []
    restart_event: dict[str, Any] | None = None
    catchup_event: dict[str, Any] | None = None
    restart_marker_pending = False
    restart_pending_catchup = False
    fleet_ready: dict[str, Any] | None = None
    fleet_started: dict[str, Any] | None = None
    finalized_height = 0
    application_height = 0
    fault_transitions: dict[str, dict[str, int]] = {}
    fault_values: dict[str, dict[str, int]] = {}
    final_tip_count = 0
    clean_stop_count = 0
    final_tip: dict[str, Any] | None = None
    for index, line in enumerate(lines):
        try:
            event = json.loads(line, object_pairs_hook=unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(f"runtime journal event[{index}] is invalid JSON: {error}")
        event = exact(event, EVENT_KEYS, f"runtime journal event[{index}]")
        if compact_json(ordered(event, EVENT_KEYS)) != line:
            fail(f"runtime journal event[{index}] is not canonical Rust JSON")
        kind = event["kind"]
        subject = event["subject"]
        if (
            not isinstance(kind, str)
            or not kind
            or len(kind.encode("utf-8")) > 64
            or re.fullmatch(r"[a-z0-9_]+", kind) is None
            or not isinstance(subject, str)
            or len(subject.encode("utf-8")) > 512
            or "\n" in subject
            or "\r" in subject
        ):
            fail(f"runtime journal event[{index}] kind/subject is invalid")
        if kind not in KNOWN_RUNTIME_EVENT_KINDS:
            fail(f"runtime journal event[{index}] has an unknown event kind")
        if kind == "process_start":
            process_instance += 1
            prior_monotonic = 0
        elif process_instance == 0:
            fail("runtime journal does not begin with process_start")
        sequence = uint(event["sequence"], f"event[{index}].sequence")
        instance = uint(event["process_instance"], f"event[{index}].process_instance", positive=True)
        monotonic = uint(event["monotonic_ns"], f"event[{index}].monotonic_ns")
        value = uint(event["value"], f"event[{index}].value")
        if (
            event["schema_version"] != 1
            or event["run_id"] != expected["run_id"]
            or event["validator_id"] != expected["validator_id"]
            or sequence != index
            or instance != process_instance
            or event["coordinator_manifest_sha256"] != expected["coordinator_manifest_sha256"]
            or event["validator_set_sha256"] != expected["validator_set_sha256"]
            or event["config_sha256"] != expected["config_sha256"]
            or event["candidate_source_sha256"] != expected["candidate_source_sha256"]
            or event["binary_sha256"] != expected["binary_sha256"]
            or event["previous_event_sha256"] != previous.hex()
            or event["production_activation"] is not False
        ):
            fail(f"runtime journal event[{index}] deployment/ancestry binding differs")
        if kind == "process_start":
            if monotonic != 0 or subject != f"instance-{instance}" or value == 0:
                fail(f"runtime journal event[{index}] process_start is invalid")
            if process_instance > 2 or (process_instance == 2 and fleet_started is None):
                fail("signed process restart crosses the fleet-start boundary")
            current_process_id = value
            restart_marker_pending = process_instance == 2
        elif prior_monotonic is None or monotonic < prior_monotonic:
            fail(f"runtime journal event[{index}] monotonic time regresses")
        body = compact_json(ordered(event, EVENT_BODY_KEYS))
        computed = domain_hash(EVENT_HASH_DOMAIN, body)
        if event["event_sha256"] != computed.hex():
            fail(f"runtime journal event[{index}] hash differs")
        verify_ed25519(
            public_key,
            domain_hash(EVENT_SIGNATURE_DOMAIN, computed),
            event["signature"],
            f"runtime journal event[{index}]",
        )
        previous = computed
        prior_monotonic = monotonic
        safety_halts += int(kind == "safety_halted")
        kinds_seen.add(kind)
        if restart_marker_pending and kind != "process_start" and kind != "restart":
            fail("signed restart marker must immediately follow process_start")
        if kind == "restart":
            if (
                instance < 2
                or subject != f"instance-{instance}"
                or value != current_process_id
                or restart_sequences
                or not restart_marker_pending
            ):
                fail("signed restart event does not bind one terminal process incarnation")
            restart_sequences.append(sequence)
            restart_event = event
            restart_marker_pending = False
            restart_pending_catchup = True
        elif kind == "peer_session_established":
            if not subject or (fleet_ready is not None and fleet_started is None):
                fail("signed peer session changes inside the fleet barrier")
        elif kind == "fleet_ready":
            if (
                instance != 1
                or fleet_ready is not None
                or fleet_started is not None
                or restart_marker_pending
                or restart_pending_catchup
                or finalized_height == 0
                or finalized_height != application_height
                or value == 0
                or HEX32.fullmatch(subject) is None
                or bytes.fromhex(subject) == bytes(32)
            ):
                fail("signed fleet Ready lacks one exact commissioned cut")
            fleet_ready = event
        elif kind == "fleet_started":
            if (
                instance != 1
                or fleet_ready is None
                or fleet_started is not None
                or last is None
                or last["kind"] != "fleet_ready"
                or value != fleet_ready["value"]
                or HEX32.fullmatch(subject) is None
                or bytes.fromhex(subject) == bytes(32)
            ):
                fail("signed fleet Started does not immediately bind Ready")
            fleet_started = event
        elif kind == "catchup_complete":
            if (
                not restart_sequences
                or catchup_sequences
                or sequence <= restart_sequences[0]
                or not subject
                or value == 0
                or fleet_started is None
                or not restart_pending_catchup
            ):
                fail("signed catch-up event has no unique preceding restart")
            catchup_sequences.append(sequence)
            catchup_event = event
            restart_pending_catchup = False
            finalized_height = max(finalized_height, value)
            application_height = max(application_height, value)
        elif kind in {
            "proposal_admitted",
            "vote_broadcast",
            "quorum_certificate_admitted",
            "timeout_vote_broadcast",
            "timeout_certificate_admitted",
        }:
            if fleet_started is None or restart_pending_catchup or not subject:
                fail("signed ordinary consensus event precedes fleet Started/catch-up")
        elif kind == "finalized":
            if (
                value == 0
                or value < finalized_height
                or HEX32.fullmatch(subject) is None
                or bytes.fromhex(subject) == bytes(32)
            ):
                fail("signed finalized event is malformed or regresses")
            if fleet_started is None:
                if fleet_ready is not None or finalized_height != 0 or application_height != 0:
                    fail("signed initial finalized cut is duplicate or follows fleet Ready")
            elif restart_pending_catchup:
                fail("signed finalized event precedes restart catch-up")
            finalized_height = value
        elif kind == "application_acknowledged":
            if (
                value == 0
                or value < application_height
                or value > finalized_height
                or HEX32.fullmatch(subject) is None
                or bytes.fromhex(subject) == bytes(32)
            ):
                fail("signed application event is malformed or crosses finality")
            if fleet_started is None:
                if (
                    fleet_ready is not None
                    or application_height != 0
                    or finalized_height == 0
                    or last is None
                    or last["kind"] != "finalized"
                    or value != finalized_height
                ):
                    fail("signed initial application cut does not exactly follow finality")
            elif restart_pending_catchup:
                fail("signed application event precedes restart catch-up")
            application_height = value
        elif kind == "fault_applied":
            if (
                fleet_started is None
                or restart_pending_catchup
                or subject not in REQUIRED_FAULTS
                or value != 1
                or subject in fault_transitions
            ):
                fail("signed fault application is unknown, duplicated, or malformed")
            fault_transitions[subject] = {"applied": sequence}
            fault_values[subject] = {"applied": value}
        elif kind == "fault_recovered":
            transition = fault_transitions.get(subject)
            if (
                subject not in REQUIRED_FAULTS
                or transition is None
                or "recovered" in transition
                or sequence <= transition["applied"]
                or value == 0
                or fleet_started is None
                or restart_pending_catchup
            ):
                fail("signed fault recovery has no unique preceding application")
            transition["recovered"] = sequence
            fault_values[subject]["recovered"] = value
        elif kind == "final_tip":
            final_tip_count += 1
            tip_parts = subject.split(":") if isinstance(subject, str) else []
            if (
                final_tip_count != 1
                or len(tip_parts) != 3
                or value == 0
                or fleet_started is None
                or restart_pending_catchup
                or value != finalized_height
                or value != application_height
                or any(HEX32.fullmatch(part) is None for part in tip_parts)
                or any(bytes.fromhex(part) == bytes(32) for part in tip_parts)
            ):
                fail("signed runtime journal must contain one non-empty final tip")
            final_tip = event
        elif kind == "clean_stop":
            clean_stop_count += 1
            if (
                clean_stop_count != 1
                or subject != "bounded-run-complete"
                or value != current_process_id
                or fleet_started is None
                or restart_pending_catchup
            ):
                fail("signed clean-stop event does not bind the terminal process")
        last = event
    assert last is not None
    if last["kind"] != "clean_stop":
        fail("runtime journal terminal event must be clean_stop")
    if final_tip is None or final_tip["sequence"] + 1 != last["sequence"]:
        fail("signed FinalTip must immediately precede CleanStop")
    if fleet_ready is None or fleet_started is None:
        fail("signed runtime journal omits the N/N fleet barrier")
    final_tip_block = str(final_tip["subject"]).split(":", maxsplit=1)[0]
    if catchup_event is not None and (
        catchup_event["subject"] != final_tip_block
        or catchup_event["value"] != final_tip["value"]
    ):
        fail("signed catch-up event does not bind the terminal FinalTip")
    if any(
        values.get("recovered") != final_tip["value"]
        for values in fault_values.values()
    ):
        fail("signed fault recovery does not bind the terminal FinalTip")
    missing = REQUIRED_CONTINUOUS_EVENT_KINDS - kinds_seen
    if missing:
        fail(f"runtime journal omits continuous-consensus events {sorted(missing)!r}")
    if process_instance not in {1, 2}:
        fail("runtime journal may contain only the initial and one restarted incarnation")
    if process_instance == 1 and (restart_sequences or catchup_sequences):
        fail("restart/catch-up events exist without a second process incarnation")
    if process_instance == 2 and (
        len(restart_sequences) != 1 or len(catchup_sequences) != 1
    ):
        fail("a second process incarnation requires one signed restart/catch-up pair")
    if any(set(transition) != {"applied", "recovered"} for transition in fault_transitions.values()):
        fail("signed fault transition is not fully recovered")
    return last, safety_halts, current_process_id, {
        "process_instance": process_instance,
        "restart_sequences": restart_sequences,
        "catchup_sequences": catchup_sequences,
        "restart_event": restart_event,
        "catchup_event": catchup_event,
        "fleet_ready": fleet_ready,
        "fleet_started": fleet_started,
        "fault_transitions": fault_transitions,
        "fault_values": fault_values,
        "final_tip": final_tip,
    }


def verify_report(
    path: pathlib.Path,
    expected: dict[str, Any],
    public_key: str,
    set_id: str,
    last_event: dict[str, Any],
    final_tip: dict[str, Any],
    safety_halts: int,
    process_id: int,
) -> dict[str, Any]:
    report, raw = read_json_bytes(path, f"consensus report[{expected['validator_id']}]", MAX_REPORT_BYTES)
    report = exact(report, REPORT_KEYS, f"consensus report[{expected['validator_id']}]")
    if compact_json(ordered(report, REPORT_KEYS)) != raw:
        fail("consensus report is not canonical Rust JSON")
    fixed = {
        "schema_version": 3,
        "run_id": expected["run_id"],
        "protocol_id": "poco-bft-v0",
        "profile": "authenticated-h1-h3-bootstrap-single-epoch-bounded-consensus-v3",
        "network_scope": "single-lan",
        "validator_id": expected["validator_id"],
        "validator_set_id": set_id,
        "validator_set_sha256": expected["validator_set_sha256"],
        "topology_sha256": expected["topology_sha256"],
        "coordinator_manifest_sha256": expected["coordinator_manifest_sha256"],
        "candidate_source_sha256": expected["candidate_source_sha256"],
        "binary_sha256": expected["binary_sha256"],
        "config_sha256": expected["config_sha256"],
        "host_id": expected["host_id"],
        "ordinary_start_height": expected["ordinary_start_height"],
        "started_monotonic_ns": 0,
        "monotonic_clock": "process-local-std-instant",
        "external_wall_clock_temporal_provenance": False,
        "clean_stop": True,
        "validator_run_completed": True,
        "continuous_consensus_runtime": True,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    for key, value in fixed.items():
        if report[key] != value:
            fail(f"consensus report {key} differs from observer-public trust input")
    positive_fields = (
        "process_id", "process_instance", "requested_duration_seconds",
        "requested_max_blocks", "pacemaker_base_timeout_seconds",
        "terminal_drain_allowance_seconds", "timeout_view_budget_allowance_seconds",
        "signer_journal_capacity", "maximum_timeout_view_advances",
        "maximum_local_vote_intents", "maximum_local_timeout_intents",
        "maximum_total_signer_intents", "signed_replay_archive_capacity",
        "maximum_proposal_archive_entries",
        "maximum_quorum_certificate_archive_entries",
        "maximum_signed_replay_archive_entries",
        "ended_monotonic_ns", "submitted_height",
        "committed_height", "finalized_height", "safety_revision",
        "submitted_ordinary_block_count", "committed_ordinary_block_count",
        "finalized_ordinary_block_count",
        "application_store_sequence", "whole_node_checkpoint_generation",
        "signer_watermark_sequence", "runtime_event_sequence",
    )
    for field in positive_fields:
        uint(report[field], f"report.{field}", positive=True)
    if report["requested_duration_seconds"] > MAX_DURATION_SECONDS:
        fail("consensus report duration crosses its bound")
    if (
        report["requested_max_blocks"] > MAX_BLOCKS
        or report["submitted_ordinary_block_count"] > report["requested_max_blocks"]
    ):
        fail("consensus report block count crosses its bound")
    timeout_view_budget_horizon = (
        report["requested_duration_seconds"]
        + report["terminal_drain_allowance_seconds"]
        + report["timeout_view_budget_allowance_seconds"]
    )
    base_timeout = report["pacemaker_base_timeout_seconds"]
    expected_view_advances = (
        timeout_view_budget_horizon + base_timeout - 1
    ) // base_timeout
    expected_local_timeouts = expected_view_advances
    expected_votes = report["requested_max_blocks"] + expected_view_advances
    expected_total_signer = expected_votes + expected_local_timeouts
    expected_qcs = expected_votes + 1
    expected_archive = expected_votes + expected_qcs
    actual_votes = uint(
        report["continuous_signed_vote_intents"],
        "report.continuous_signed_vote_intents",
    )
    actual_timeouts = uint(
        report["continuous_signed_timeout_intents"],
        "report.continuous_signed_timeout_intents",
    )
    if (
        report["pacemaker_base_timeout_seconds"]
        != PACEMAKER_BASE_TIMEOUT_SECONDS
        or report["terminal_drain_allowance_seconds"]
        != TERMINAL_DRAIN_ALLOWANCE_SECONDS
        or report["timeout_view_budget_allowance_seconds"]
        != TIMEOUT_VIEW_BUDGET_ALLOWANCE_SECONDS
        or report["signer_journal_capacity"] != MAX_SIGNER_INTENTS
        or report["maximum_timeout_view_advances"] != expected_view_advances
        or report["maximum_local_vote_intents"] != expected_votes
        or report["maximum_local_timeout_intents"] != expected_local_timeouts
        or report["maximum_total_signer_intents"] != expected_total_signer
        or expected_total_signer > MAX_SIGNER_INTENTS
        or report["signed_replay_archive_capacity"]
        != MAX_SIGNED_REPLAY_ARCHIVE_ENTRIES
        or report["maximum_proposal_archive_entries"] != expected_votes
        or report["maximum_quorum_certificate_archive_entries"] != expected_qcs
        or report["maximum_signed_replay_archive_entries"] != expected_archive
        or expected_archive > MAX_SIGNED_REPLAY_ARCHIVE_ENTRIES
        or actual_votes > expected_votes
        or actual_timeouts > expected_local_timeouts
        or actual_votes + actual_timeouts > expected_total_signer
        or actual_votes + actual_timeouts > report["signer_watermark_sequence"]
    ):
        fail("consensus report signer/archive lifetime accounting differs")
    if not report["submitted_height"] >= report["committed_height"] >= report["finalized_height"]:
        fail("consensus report height relation is invalid")
    if report["application_committed_height"] != report["finalized_height"]:
        fail("consensus report application/finality height differs")
    for height_field, count_field in (
        ("submitted_height", "submitted_ordinary_block_count"),
        ("committed_height", "committed_ordinary_block_count"),
        ("finalized_height", "finalized_ordinary_block_count"),
    ):
        if report[height_field] != report["ordinary_start_height"] + report[count_field] - 1:
            fail(f"consensus report {height_field}/{count_field} mapping differs")
    if not (
        report["submitted_ordinary_block_count"]
        >= report["committed_ordinary_block_count"]
        >= report["finalized_ordinary_block_count"]
    ):
        fail("consensus report ordinary-block count relation is invalid")
    zero_fields = (
        "safety_halt_count", "double_vote_count", "double_timeout_count",
        "conflicting_certificate_count", "pending_safety_persistence_count",
        "pending_payload_validation_count", "pending_signature_count",
        "pending_finalization_count", "pending_sync_count",
        "unresolved_obligation_count",
    )
    for field in zero_fields:
        if uint(report[field], f"report.{field}") != 0:
            fail(f"consensus report {field} must be zero")
    nonzero_hex = (
        "application_head_block_id", "application_state_root",
        "safety_state_record_checksum", "safety_record_chain_checksum",
        "application_store_id", "application_head_row_checksum",
        "whole_node_checkpoint_checksum", "signer_scope", "signer_journal_id",
        "signer_chain_checksum", "runtime_event_sha256",
    )
    for field in nonzero_hex:
        hex_bytes(report[field], 32, f"report.{field}", nonzero=True)
    tip_block, tip_state, _tip_chain = final_tip["subject"].split(":")
    if (
        report["process_id"] != process_id
        or report["process_instance"] != last_event["process_instance"]
        or report["ended_monotonic_ns"] != last_event["monotonic_ns"]
        or report["runtime_event_sequence"] != last_event["sequence"]
        or report["runtime_event_sha256"] != last_event["event_sha256"]
        or report["safety_halt_count"] != safety_halts
        or report["finalized_height"] != final_tip["value"]
        or report["application_committed_height"] != final_tip["value"]
        or report["application_head_block_id"] != tip_block
        or report["application_state_root"] != tip_state
    ):
        fail("consensus report does not bind the signed runtime journal terminal cut")
    body = compact_json(ordered(report, REPORT_BODY_KEYS))
    computed = domain_hash(REPORT_HASH_DOMAIN, body)
    if report["report_sha256"] != computed.hex():
        fail("consensus report hash differs")
    verify_ed25519(
        public_key,
        domain_hash(REPORT_SIGNATURE_DOMAIN, computed),
        report["signature"],
        "consensus report",
    )
    return report


def verify_metrics(
    path: pathlib.Path,
    expected: dict[str, Any],
    public_key: str,
    last_event: dict[str, Any],
    report: dict[str, Any],
) -> dict[str, Any]:
    metrics, raw = read_json_bytes(
        path,
        f"runtime metrics[{expected['validator_id']}]",
        MAX_RUNTIME_EVIDENCE_BYTES,
    )
    metrics = exact(metrics, METRICS_KEYS, f"runtime metrics[{expected['validator_id']}]")
    if compact_json(ordered(metrics, METRICS_KEYS)) != raw:
        fail("runtime metrics is not canonical Rust JSON")
    fixed = {
        "schema_version": 2,
        "run_id": expected["run_id"],
        "validator_id": expected["validator_id"],
        "validator_set_sha256": expected["validator_set_sha256"],
        "topology_sha256": expected["topology_sha256"],
        "coordinator_manifest_sha256": expected["coordinator_manifest_sha256"],
        "candidate_source_sha256": expected["candidate_source_sha256"],
        "binary_sha256": expected["binary_sha256"],
        "config_sha256": expected["config_sha256"],
        "process_id": report["process_id"],
        "process_instance_count": report["process_instance"],
        "ordinary_start_height": expected["ordinary_start_height"],
        "runtime_event_sequence": last_event["sequence"],
        "runtime_event_sha256": last_event["event_sha256"],
        "consensus_report_sha256": report["report_sha256"],
        "runtime_started_monotonic_ns": 0,
        "runtime_ended_monotonic_ns": last_event["monotonic_ns"],
        "os_metrics_corroboration": True,
        "validator_run_completed": True,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    for key, value in fixed.items():
        if metrics[key] != value:
            fail(f"runtime metrics {key} differs from the terminal cut")
    canonical_utc_interval(
        metrics["measurement_started_at"],
        metrics["measurement_ended_at"],
        "runtime metrics measurement interval",
    )
    samples = metrics["finality_samples_ms"]
    if not isinstance(samples, list) or not 1 <= len(samples) <= 1_000_000:
        fail("runtime metrics finality sample cardinality differs")
    for index, sample in enumerate(samples):
        positive_number(sample, f"runtime metrics finality_samples_ms[{index}]")
    uint(metrics["fsync_count"], "runtime metrics fsync_count", positive=True)
    positive_number(metrics["cpu_seconds"], "runtime metrics cpu_seconds")
    for field in (
        "peak_rss_bytes",
        "disk_bytes",
        "network_tx_bytes",
        "network_rx_bytes",
    ):
        uint(metrics[field], f"runtime metrics {field}", positive=True)
    for field in (
        "runtime_event_sha256",
        "consensus_report_sha256",
    ):
        hex_bytes(metrics[field], 32, f"runtime metrics {field}", nonzero=True)
    body_hash = domain_hash(
        METRICS_HASH_DOMAIN,
        compact_json(ordered(metrics, METRICS_BODY_KEYS)),
    )
    if metrics["body_sha256"] != body_hash.hex():
        fail("runtime metrics body hash differs")
    verify_ed25519(
        public_key,
        domain_hash(METRICS_SIGNATURE_DOMAIN, body_hash),
        metrics["signature"],
        "runtime metrics",
    )
    return metrics


def verify_final_state(
    path: pathlib.Path,
    expected: dict[str, Any],
    public_key: str,
    last_event: dict[str, Any],
    journal_facts: dict[str, Any],
    report: dict[str, Any],
    metrics: dict[str, Any],
) -> dict[str, Any]:
    final_state, raw = read_json_bytes(
        path,
        f"runtime final state[{expected['validator_id']}]",
        MAX_RUNTIME_EVIDENCE_BYTES,
    )
    final_state = exact(
        final_state,
        FINAL_STATE_KEYS,
        f"runtime final state[{expected['validator_id']}]",
    )
    if compact_json(ordered(final_state, FINAL_STATE_KEYS)) != raw:
        fail("runtime final state is not canonical Rust JSON")
    final_tip = journal_facts["final_tip"]
    tip_block, tip_state, tip_chain = final_tip["subject"].split(":")
    recovered_faults = sorted(journal_facts["fault_transitions"])
    fixed = {
        "schema_version": 3,
        "run_id": expected["run_id"],
        "validator_id": expected["validator_id"],
        "validator_set_sha256": expected["validator_set_sha256"],
        "topology_sha256": expected["topology_sha256"],
        "coordinator_manifest_sha256": expected["coordinator_manifest_sha256"],
        "candidate_source_sha256": expected["candidate_source_sha256"],
        "binary_sha256": expected["binary_sha256"],
        "config_sha256": expected["config_sha256"],
        "process_id": report["process_id"],
        "process_instance_count": report["process_instance"],
        "ordinary_start_height": expected["ordinary_start_height"],
        "finalized_height": report["finalized_height"],
        "finalized_ordinary_block_count": report["finalized_ordinary_block_count"],
        "finalized_block_id": tip_block,
        "finalized_state_root": tip_state,
        "finalized_chain_root": tip_chain,
        "applied_height": report["application_committed_height"],
        "runtime_event_sequence": last_event["sequence"],
        "runtime_event_sha256": last_event["event_sha256"],
        "consensus_report_sha256": report["report_sha256"],
        "runtime_metrics_sha256": metrics["body_sha256"],
        "recovered_faults": recovered_faults,
        "restart_completed": report["process_instance"] == 2,
        "validator_run_completed": True,
        "g3_evidence_complete": False,
        "geo_wan_evidence": False,
        "production_activation": False,
    }
    for key, value in fixed.items():
        if final_state[key] != value:
            fail(f"runtime final state {key} differs from the terminal evidence chain")
    if (
        uint(
            final_state["finalized_nonempty_ordinary_block_count"],
            "runtime final state finalized_nonempty_ordinary_block_count",
            positive=True,
        )
        != final_state["finalized_ordinary_block_count"]
    ):
        fail("runtime final state includes an empty finalized ordinary block")
    for field in (
        "double_sign_events",
        "duplicate_apply_events",
        "state_drift_events",
        "safety_halt_violations",
    ):
        if uint(final_state[field], f"runtime final state {field}") != 0:
            fail(f"runtime final state {field} must be zero")
    for field in (
        "finalized_block_id",
        "finalized_state_root",
        "finalized_chain_root",
        "runtime_event_sha256",
        "consensus_report_sha256",
        "runtime_metrics_sha256",
    ):
        hex_bytes(final_state[field], 32, f"runtime final state {field}", nonzero=True)
    body_hash = domain_hash(
        FINAL_STATE_HASH_DOMAIN,
        compact_json(ordered(final_state, FINAL_STATE_BODY_KEYS)),
    )
    if final_state["body_sha256"] != body_hash.hex():
        fail("runtime final state body hash differs")
    verify_ed25519(
        public_key,
        domain_hash(FINAL_STATE_SIGNATURE_DOMAIN, body_hash),
        final_state["signature"],
        "runtime final state",
    )
    return final_state


def validate(
    root: pathlib.Path,
    expected_count: int,
    coordinator_manifest_sha256: str,
    *,
    profile: str,
    emit: bool = True,
) -> dict[str, Any]:
    try:
        selected_profile = evidence_profiles.require_active(profile)
    except (ValueError, RuntimeError) as error:
        fail(str(error))
    if expected_count not in VALID_COUNTS:
        fail("validator count must be 7, 31, or 100")
    if root.is_symlink() or not root.is_dir():
        fail("bundle root must be one real directory")
    anchor = hex_bytes(coordinator_manifest_sha256, 32, "coordinator manifest anchor", nonzero=True).hex()
    manifest, records = load_artifacts(root)
    if manifest.get("evidence_profile") != selected_profile:
        fail("bundle evidence_profile differs from the explicit CLI profile")
    run_id = manifest.get("run_id")
    if not isinstance(run_id, str) or RUN_ID.fullmatch(run_id) is None or int(RUN_ID.fullmatch(run_id).group(1)) != expected_count:
        fail("bundle run_id does not bind the validator count")
    if (
        manifest.get("validator_count") != expected_count
        or manifest.get("network_scope") != "single-lan"
        or manifest.get("geo_wan_evidence") is not False
    ):
        fail("bundle manifest crosses the single-LAN validator-count boundary")
    for role in REQUIRED_SINGLETON_ROLES:
        artifact(records, role)
    coordinator_ref, coordinator_path = artifact(records, "coordinator_manifest")
    if coordinator_ref["sha256"] != anchor:
        fail("coordinator manifest differs from the out-of-band anchor")
    coordinator, _ = read_json_bytes(coordinator_path, "coordinator manifest")
    exact(
        coordinator,
        {
            "schema_version", "run_id", "fleet_id", "validator_count",
            "weight_profile", "network_scope", "geo_wan_evidence", "candidate",
            "material_author",
            "validator_set_sha256", "public_files", "secret_files",
            "production_activation",
        },
        "coordinator manifest",
    )
    if (
        coordinator["schema_version"] != 2
        or coordinator["run_id"] != run_id
        or coordinator["validator_count"] != expected_count
    ):
        fail("coordinator manifest run/count differs")
    if coordinator.get("network_scope") != "single-lan" or coordinator.get("geo_wan_evidence") is not False or coordinator.get("production_activation") is not False:
        fail("coordinator manifest crosses the single-LAN non-production boundary")

    source_ref, _ = artifact(records, "candidate_source")
    binary_ref, _ = artifact(records, "linux_binary")
    macos_ref, _ = artifact(records, "macos_binary")
    material_builder_ref, _ = artifact(records, "material_builder_binary")
    _, build_report_path = artifact(records, "build_report")
    topology_ref, topology_path = artifact(records, "topology")
    set_ref, set_path = artifact(records, "validator_set")
    public_singleton_refs = {
        path: artifact(records, role)[0]
        for role, path in evidence_profiles.COORDINATOR_PUBLIC_SINGLETON_PATHS.items()
    }
    candidate = exact(
        coordinator["candidate"],
        {"source_tree_sha256", "linux_x86_64_sha256", "macos_arm64_sha256"},
        "coordinator candidate",
    )
    material_author = exact(
        coordinator["material_author"],
        {"binary_sha256", "runtime_deployed"},
        "coordinator material_author",
    )
    build_report, _ = read_json_bytes(build_report_path, "aggregate build report")
    build_report = exact(
        build_report,
        {
            "schema_version",
            "source_tree_sha256",
            "linux_first_sha256",
            "linux_second_sha256",
            "linux_material_builder_first_sha256",
            "linux_material_builder_second_sha256",
            "macos_first_sha256",
            "macos_second_sha256",
            "macos_material_builder_first_sha256",
            "macos_material_builder_second_sha256",
            "independent_build_roots",
            "production_activation",
        }
        | check_run_evidence.SOURCE_PROVENANCE_KEYS,
        "aggregate build report",
    )
    check_run_evidence.validate_source_provenance(
        build_report,
        "aggregate build report",
        fail_fn=fail,
    )
    if (
        candidate["source_tree_sha256"] != source_ref["sha256"]
        or candidate["linux_x86_64_sha256"] != binary_ref["sha256"]
        or candidate["macos_arm64_sha256"] != macos_ref["sha256"]
        or material_author["binary_sha256"] != material_builder_ref["sha256"]
        or material_author["runtime_deployed"] is not False
        or coordinator["validator_set_sha256"] != set_ref["sha256"]
        or build_report["schema_version"] != 3
        or build_report["source_tree_sha256"] != source_ref["sha256"]
        or build_report["linux_first_sha256"] != binary_ref["sha256"]
        or build_report["linux_second_sha256"] != binary_ref["sha256"]
        or build_report["linux_material_builder_first_sha256"]
        != material_builder_ref["sha256"]
        or build_report["linux_material_builder_second_sha256"]
        != material_builder_ref["sha256"]
        or build_report["macos_first_sha256"] != macos_ref["sha256"]
        or build_report["macos_second_sha256"] != macos_ref["sha256"]
        or build_report["independent_build_roots"] is not True
        or build_report["production_activation"] is not False
    ):
        fail("coordinator candidate/material author/build binding differs from raw artifacts")
    for field in (
        "macos_material_builder_first_sha256",
        "macos_material_builder_second_sha256",
    ):
        hex_bytes(build_report[field], 32, f"aggregate build report {field}", nonzero=True)
    if (
        build_report["macos_material_builder_first_sha256"]
        != build_report["macos_material_builder_second_sha256"]
        or material_builder_ref["sha256"]
        in {
            source_ref["sha256"],
            binary_ref["sha256"],
            macos_ref["sha256"],
        }
    ):
        fail("material author reproducibility or role separation differs")
    topology, _ = read_json_bytes(topology_path, "topology")
    descriptor, _ = read_json_bytes(set_path, "validator set")
    exact(
        descriptor,
        {
            "schema_version", "run_id", "chain_id", "genesis_hash",
            "protocol_version", "epoch", "consensus_parameters_profile",
            "candidate_source_sha256", "production_activation", "validators",
        },
        "validator set",
    )
    validators = descriptor["validators"]
    if (
        descriptor["schema_version"] != 1
        or descriptor["run_id"] != run_id
        or descriptor["chain_id"] != "trnm-poco-g3-lab-v0"
        or descriptor["protocol_version"] != 0
        or descriptor["epoch"] != 0
        or descriptor["consensus_parameters_profile"] != "reference-shadow-v0"
        or descriptor["candidate_source_sha256"] != source_ref["sha256"]
        or descriptor["production_activation"] is not False
        or not isinstance(validators, list)
        or len(validators) != expected_count
    ):
        fail("validator set differs from the frozen observer-public contract")
    by_id: dict[str, dict[str, Any]] = {}
    canonical_inventory: list[tuple[bytes, bytes, int]] = []
    previous = ""
    keys: set[str] = set()
    for index, raw in enumerate(validators):
        record = exact(raw, {"validator_id", "consensus_public_key", "voting_power", "key_pop_signature"}, f"validator[{index}]")
        validator_id = record["validator_id"]
        public_key = record["consensus_public_key"]
        validator_id_bytes = hex_bytes(validator_id, 32, f"validator[{index}].validator_id")
        public_key_bytes = hex_bytes(public_key, 32, f"validator[{index}].consensus_public_key")
        hex_bytes(record["key_pop_signature"], 64, f"validator[{index}].key_pop_signature")
        voting_power = uint(record["voting_power"], f"validator[{index}].voting_power", positive=True)
        if validator_id <= previous or public_key in keys:
            fail("validator set order/key uniqueness differs")
        previous = validator_id
        keys.add(public_key)
        run = run_id.encode("ascii")
        author = validator_id.encode("ascii")
        pop_message = (
            b"TRNM/PoCO/G3/EphemeralKeyPoP/v1\0"
            + len(run).to_bytes(4, "big")
            + run
            + len(author).to_bytes(4, "big")
            + author
        )
        verify_ed25519(
            public_key,
            pop_message,
            record["key_pop_signature"],
            f"validator[{index}] proof-of-possession",
        )
        by_id[validator_id] = record
        canonical_inventory.append(
            (validator_id_bytes, public_key_bytes, voting_power)
        )
    try:
        expected_genesis = canonical_lab_genesis_hash(
            descriptor["chain_id"], canonical_inventory
        ).hex()
    except (UnicodeError, ValueError) as error:
        fail(f"validator-set canonical genesis input is invalid: {error}")
    if descriptor["genesis_hash"] != expected_genesis:
        fail("validator-set genesis differs from canonical chain-only inputs")
    validator_ids = set(by_id)
    for role in REQUIRED_VALIDATOR_ROLES:
        subjects = {subject for candidate_role, subject in records if candidate_role == role}
        if subjects != validator_ids:
            fail(f"bundle requires one {role} per validator")
    if topology.get("run_id") != run_id or topology.get("validator_count") != expected_count:
        fail("topology run/count differs")
    if topology.get("network_scope") != "single-lan" or topology.get("geo_wan_evidence") is not False:
        fail("topology crosses the single-LAN boundary")
    planned = topology.get("validators")
    if not isinstance(planned, list) or {item.get("validator_id") for item in planned if isinstance(item, dict)} != validator_ids:
        fail("topology validator inventory differs")
    plan_by_id = {item["validator_id"]: item for item in planned}
    set_id = validator_set_id(descriptor)
    reports: list[dict[str, Any]] = []
    metrics_values: list[dict[str, Any]] = []
    final_states: list[dict[str, Any]] = []
    journal_facts: dict[str, dict[str, Any]] = {}
    signed_validators: dict[str, dict[str, Any]] = {}
    config_refs: dict[str, dict[str, Any]] = {}
    workload_bindings: set[tuple[int, str, str]] = set()
    for validator_id in sorted(validator_ids):
        config_ref, config_path = artifact(records, "validator_config", validator_id)
        config_refs[validator_id] = config_ref
        config, _ = read_json_bytes(config_path, f"validator config[{validator_id}]")
        exact(
            config,
            {
                "schema_version", "run_id", "validator_id", "host_id", "lan_ip",
                "p2p_port", "metrics_port", "weight", "consensus_public_key",
                "validator_set_sha256", "binary_sha256", "ordinary_start_height",
                "workload_corpus_sha256", "workload_policy_sha256", "secret_key_path",
                "peers", "network_scope", "geo_wan_evidence", "production_activation",
            },
            f"validator config[{validator_id}]",
        )
        plan = plan_by_id[validator_id]
        if (
            config["schema_version"] != 1
            or config["run_id"] != run_id
            or config["validator_id"] != validator_id
            or config["host_id"] != plan.get("host_id")
            or config["weight"] != by_id[validator_id]["voting_power"]
            or config["consensus_public_key"] != by_id[validator_id]["consensus_public_key"]
            or config["validator_set_sha256"] != set_ref["sha256"]
            or config["binary_sha256"] != binary_ref["sha256"]
            or isinstance(config["ordinary_start_height"], bool)
            or not isinstance(config["ordinary_start_height"], int)
            or config["ordinary_start_height"] != 4
            or not isinstance(config["workload_corpus_sha256"], str)
            or not HEX32.fullmatch(config["workload_corpus_sha256"])
            or not isinstance(config["workload_policy_sha256"], str)
            or not HEX32.fullmatch(config["workload_policy_sha256"])
            or config["network_scope"] != "single-lan"
            or config["geo_wan_evidence"] is not False
            or config["production_activation"] is not False
        ):
            fail(f"validator config[{validator_id}] differs from observer-public inputs")
        workload_bindings.add(
            (
                config["ordinary_start_height"],
                config["workload_corpus_sha256"],
                config["workload_policy_sha256"],
            )
        )
        expected = {
            "run_id": run_id,
            "validator_id": validator_id,
            "host_id": config["host_id"],
            "validator_set_sha256": set_ref["sha256"],
            "topology_sha256": topology_ref["sha256"],
            "coordinator_manifest_sha256": anchor,
            "candidate_source_sha256": source_ref["sha256"],
            "binary_sha256": binary_ref["sha256"],
            "config_sha256": config_ref["sha256"],
            "ordinary_start_height": config["ordinary_start_height"],
        }
        _, journal_path = artifact(records, "validator_runtime_event_journal", validator_id)
        last, safety_halts, process_id, facts = verify_journal(
            journal_path, expected, by_id[validator_id]["consensus_public_key"]
        )
        journal_facts[validator_id] = facts
        certificate_ref, certificate_path = artifact(
            records, "validator_fleet_start_certificate", validator_id
        )
        certificate_size = certificate_path.stat().st_size
        if (
            certificate_size <= 0
            or certificate_size > MAX_FLEET_START_CERTIFICATE_BYTES
            or certificate_ref["sha256"] != facts["fleet_started"]["subject"]
        ):
            fail(
                "fleet StartCertificate artifact does not bind the signed "
                "FleetStarted event"
            )
        _, report_path = artifact(records, "validator_consensus_run_report", validator_id)
        report = verify_report(
            report_path,
            expected,
            by_id[validator_id]["consensus_public_key"],
            set_id,
            last,
            facts["final_tip"],
            safety_halts,
            process_id,
        )
        reports.append(report)
        _, metrics_path = artifact(records, "validator_runtime_metrics", validator_id)
        metrics = verify_metrics(
            metrics_path,
            expected,
            by_id[validator_id]["consensus_public_key"],
            last,
            report,
        )
        metrics_values.append(metrics)
        _, final_state_path = artifact(
            records, "validator_runtime_final_state", validator_id
        )
        final_state = verify_final_state(
            final_state_path,
            expected,
            by_id[validator_id]["consensus_public_key"],
            last,
            facts,
            report,
            metrics,
        )
        final_states.append(final_state)
        signed_validators[validator_id] = {
            "last_event": last,
            "journal": facts,
            "report": report,
            "metrics": metrics,
            "final_state": final_state,
        }
    if len(workload_bindings) != 1:
        fail("validator configs do not share one exact ordinary workload binding")
    workload_binding = next(iter(workload_bindings))
    if workload_binding != (
        4,
        public_singleton_refs["public/workload.corpus"]["sha256"],
        public_singleton_refs["public/workload-policy.json"]["sha256"],
    ):
        fail("validator configs do not bind the exact public workload artifacts")
    barrier_rounds = {
        facts["fleet_started"]["value"] for facts in journal_facts.values()
    }
    ready_set_digests = {
        facts["fleet_ready"]["subject"] for facts in journal_facts.values()
    }
    start_certificate_digests = {
        facts["fleet_started"]["subject"] for facts in journal_facts.values()
    }
    if (
        len(barrier_rounds) != 1
        or len(ready_set_digests) != 1
        or len(start_certificate_digests) != 1
    ):
        fail("signed validators disagree on the exact N/N fleet barrier")
    public_values = coordinator["public_files"]
    if not isinstance(public_values, list):
        fail("coordinator public_files must be a list")
    public_by_path: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(public_values):
        record = exact(value, {"path", "sha256", "bytes"}, f"coordinator.public_files[{index}]")
        relative = str(safe_relative(record["path"], f"coordinator.public_files[{index}].path"))
        hex_bytes(record["sha256"], 32, f"coordinator.public_files[{index}].sha256")
        uint(record["bytes"], f"coordinator.public_files[{index}].bytes", positive=True)
        if relative in public_by_path:
            fail("coordinator public_files contains a duplicate path")
        public_by_path[relative] = record
    expected_public = {
        **public_singleton_refs,
        **{
            f"public/configs/{validator_id}.json": config_refs[validator_id]
            for validator_id in sorted(validator_ids)
        },
    }
    observer_config = artifact(records, "observer_config", "mac")
    expected_public["public/observer-configs/mac.json"] = observer_config[0]
    if set(public_by_path) != set(expected_public):
        fail("coordinator public inventory differs from observer-public inputs")
    for logical_path, expected_ref in expected_public.items():
        observed = public_by_path[logical_path]
        if (
            observed["sha256"] != expected_ref["sha256"]
            or observed["bytes"] != expected_ref["bytes"]
        ):
            fail("coordinator public reference differs from observer-public bytes")
    secret_values = coordinator["secret_files"]
    if not isinstance(secret_values, list) or len(secret_values) != expected_count:
        fail("coordinator secret-reference inventory cardinality differs")
    secret_ids: set[str] = set()
    for index, value in enumerate(secret_values):
        record = exact(value, {"path", "sha256", "bytes"}, f"coordinator.secret_files[{index}]")
        relative = str(safe_relative(record["path"], f"coordinator.secret_files[{index}].path"))
        match = re.fullmatch(r"secrets/([0-9a-f]{64})\.pk8", relative)
        hex_bytes(record["sha256"], 32, f"coordinator.secret_files[{index}].sha256", nonzero=True)
        uint(record["bytes"], f"coordinator.secret_files[{index}].bytes", positive=True)
        if match is None or match.group(1) in secret_ids:
            fail("coordinator secret-reference inventory is not closed")
        secret_ids.add(match.group(1))
    if secret_ids != validator_ids:
        fail("coordinator secret-reference inventory differs from validators")
    agreement_fields = (
        "requested_duration_seconds", "requested_max_blocks",
        "pacemaker_base_timeout_seconds",
        "terminal_drain_allowance_seconds",
        "timeout_view_budget_allowance_seconds",
        "signer_journal_capacity", "maximum_timeout_view_advances",
        "maximum_local_vote_intents", "maximum_local_timeout_intents",
        "maximum_total_signer_intents", "signed_replay_archive_capacity",
        "maximum_proposal_archive_entries",
        "maximum_quorum_certificate_archive_entries",
        "maximum_signed_replay_archive_entries",
        "ordinary_start_height", "finalized_height",
        "submitted_ordinary_block_count", "committed_ordinary_block_count",
        "finalized_ordinary_block_count", "application_head_block_id",
        "application_state_root",
    )
    for field in agreement_fields:
        if len({report[field] for report in reports}) != 1:
            fail(f"signed validator reports disagree on {field}")
    for field in (
        "ordinary_start_height",
        "finalized_height",
        "finalized_ordinary_block_count",
        "finalized_nonempty_ordinary_block_count",
        "finalized_block_id",
        "finalized_state_root",
        "finalized_chain_root",
    ):
        if len({state[field] for state in final_states}) != 1:
            fail(f"signed validator final states disagree on {field}")
    restarted = [
        validator_id
        for validator_id, facts in journal_facts.items()
        if facts["process_instance"] == 2
    ]
    if restarted:
        fail("no-fault-v1 requires process_instance=1 for every validator")
    signed_fault_owners: dict[str, str] = {}
    for validator_id, facts in journal_facts.items():
        for fault, transition in facts["fault_transitions"].items():
            if fault in signed_fault_owners:
                fail("signed runtime evidence duplicates one mandatory fault")
            if set(transition) != {"applied", "recovered"}:
                fail("signed runtime evidence contains an incomplete fault transition")
            signed_fault_owners[fault] = validator_id
    if signed_fault_owners:
        fail("no-fault-v1 requires zero signed fault transitions")
    if emit:
        print(
            f"poco_g3_signed_runtime_evidence=passed validators={expected_count} "
            "journal_signatures=all report_signatures=all metrics_signatures=all "
            "final_state_signatures=all terminal_binding=exact "
            "profile=no-fault-v1 restart_catchup=zero faults=0 "
            "fleet_barrier=n-of-n-exact "
            "unsigned_observation_authority=false g3_complete=false geo_wan=false"
        )
    return {
        "run_id": run_id,
        "evidence_profile": selected_profile,
        "validator_count": expected_count,
        "validators": signed_validators,
        "restarted_validator_id": None,
        "fault_owners": signed_fault_owners,
        "fleet_barrier_round": next(iter(barrier_rounds)),
        "fleet_ready_set_sha256": next(iter(ready_set_digests)),
        "fleet_start_certificate_sha256": next(
            iter(start_certificate_digests)
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=pathlib.Path)
    parser.add_argument("--validators", required=True, type=int, choices=(7, 31, 100))
    parser.add_argument("--coordinator-manifest-sha256", required=True)
    parser.add_argument(
        "--profile", required=True, choices=sorted(evidence_profiles.KNOWN_PROFILES)
    )
    args = parser.parse_args()
    validate(
        args.bundle,
        args.validators,
        args.coordinator_manifest_sha256,
        profile=args.profile,
    )


if __name__ == "__main__":
    main()
