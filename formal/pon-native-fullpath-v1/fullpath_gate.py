#!/usr/bin/env python3
"""Bounded readback of the native collector; never a security/release authority.

Packet parsing checks byte identities and commitment bindings, NOT FullLimb,
transaction signatures, task eligibility, or a consensus transition. Those are
observations from the source-bound native process, retained verbatim below.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import struct
import sys

U64 = (1 << 64) - 1
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_ROWS = 1024
MAX_CHECKS = 64
MAX_PATH = 1024
PACKET_LIMIT = 1_048_576
PROOF_BYTES = 4 + 3 * 64 * 64 * 4 + 32
HEADER_BYTES = 354
PHASES = ("search", "winner_prepare", "propagation", "verification", "acceptance")
EVENTS = dict(zip(PHASES, ("search_complete", "produce_complete", "packet_received",
                          "admission_complete", "observe_complete")))
OUTCOMES = {"accepted", "rejected", "timeout", "cancelled", "error", "busy",
            "stale", "duplicate", "send_failed"}
PHASE_OUTCOMES = {"complete", "cancelled", "error", "partial", "rejected", "timeout"}
RESOURCES = ("cpu_ns", "peak_rss_bytes", "wire_bytes")
PROCESS_SCHEMA = "pon-native-fullpath-process-v1"
OBSERVATION_SCHEMA = "pon-native-exact-growth-packet-observation-v1"
MANIFEST_SCHEMA = "trnm-pon-fullpath-preregistration-v1"
REPORT_SCHEMA = "trnm-pon-fullpath-observations-v1"


def require(condition, label):
    if not condition:
        raise ValueError(label)


def integer(value, label, minimum=0, maximum=U64):
    require(type(value) is int and minimum <= value <= maximum, label)
    return value


def name(value, label):
    require(type(value) is str and 0 < len(value) <= 256
            and value.strip() == value and all(ord(c) >= 32 for c in value), label)
    return value


def hex_value(value, label, size=32):
    require(type(value) is str and len(value) == 2 * size
            and all(c in "0123456789abcdef" for c in value), label)
    return bytes.fromhex(value)


def keys(value, expected, label):
    require(type(value) is dict and set(value) == set(expected), label)


def rows(value, label, maximum=MAX_ROWS):
    require(type(value) is list and len(value) <= maximum, label)
    return value


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def decode(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, "DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def nonfinite(_):
        raise ValueError("NONFINITE_JSON_NUMBER")

    def finite_float(value):
        result = float(value)
        require(math.isfinite(result), "NONFINITE_JSON_NUMBER")
        return result

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite, parse_float=finite_float)
    except (UnicodeError, RecursionError) as exc:
        raise ValueError("JSON_ENCODING_OR_DEPTH") from exc


class Evidence:
    """Relative regular files only; O_NOFOLLOW on every path component."""

    def __init__(self, root):
        root = Path(root)
        require(not root.is_symlink() and root.is_dir(), "EVIDENCE_DIRECTORY")
        self.root = root.resolve()
        self.cache = {}
        self.total = 0

    def read(self, path, maximum=MAX_FILE):
        require(type(path) is str and 0 < len(path) <= 1024 and "\\" not in path
                and "\0" not in path, "ARTIFACT_PATH")
        parts = path.split("/")
        require(all(part not in {"", ".", ".."} for part in parts), "ARTIFACT_PATH")
        if path in self.cache:
            raw = self.cache[path]
            require(len(raw) <= maximum, "ARTIFACT_SIZE")
            return raw
        require(len(self.cache) < 16_384, "ARTIFACT_COUNT")
        directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts[:-1]:
                following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=directory)
                os.close(directory)
                directory = following
            descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=directory)
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum,
                        "ARTIFACT_SIZE_OR_TYPE")
                raw = stream.read(maximum + 1)
        finally:
            os.close(directory)
        require(len(raw) <= maximum, "ARTIFACT_SIZE")
        self.total += len(raw)
        require(self.total <= MAX_TOTAL, "TOTAL_EVIDENCE_SIZE")
        self.cache[path] = raw
        return raw

    def artifact(self, reference, maximum=MAX_FILE):
        keys(reference, {"path", "sha256"}, "ARTIFACT_REFERENCE")
        hex_value(reference["sha256"], "ARTIFACT_DIGEST")
        raw = self.read(reference["path"], maximum)
        require(sha256(raw) == reference["sha256"], "ARTIFACT_HASH_MISMATCH")
        return raw


def domain_hash(tag, *parts):
    tag = tag.encode()
    return hashlib.sha256(b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag
                          + b"".join(struct.pack("<I", len(p)) + p for p in parts)).digest()


def sequence_root(items):
    leaves = [domain_hash("transactions-leaf", struct.pack("<Q", i), item)
              for i, item in enumerate(items)]
    if not leaves:
        return domain_hash("transactions-empty")
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves.append(leaves[-1])
        leaves = [domain_hash("transactions-node", leaves[i], leaves[i + 1])
                  for i in range(0, len(leaves), 2)]
    return leaves[0]


def parse_packet(raw):
    """Return native collector-compatible identity; NOT a packet validity verdict.

    body_sha256 covers the u16 transaction count and all u16 length-prefixed
    transaction bytes, excluding the following u32 witness length. witness_sha256
    covers raw accounts.encode() bytes. Invalid C/trace relations remain parseable
    so an expensive native rejection can be retained in its original denominator.
    """
    require(type(raw) is bytes and 4 + HEADER_BYTES + 2 + 4 + 44 + PROOF_BYTES
            <= len(raw) <= PACKET_LIMIT, "PACKET_LENGTH")
    require(raw[:4] == b"PNP2", "PACKET_VERSION")
    header = raw[4:4 + HEADER_BYTES]
    require(header[:10] == b"PGH2PNH1\x01\0", "HEADER_VERSION")
    pos = 4 + HEADER_BYTES
    body_start = pos

    def take(length):
        nonlocal pos
        require(pos + length <= len(raw), "PACKET_TRUNCATED")
        data = raw[pos:pos + length]
        pos += length
        return data

    count = int.from_bytes(take(2), "little")
    require(count <= 256, "TRANSACTION_COUNT")
    transactions = []
    for _ in range(count):
        length = int.from_bytes(take(2), "little")
        require(159 <= length <= 2048, "TRANSACTION_LENGTH")
        transactions.append(take(length))
    body_end = pos
    length = int.from_bytes(take(4), "little")
    require(44 <= length <= 786_432, "WITNESS_LENGTH")
    witness = take(length)
    require(int.from_bytes(witness[36:40], "little") <= 1024, "WITNESS_ACCOUNT_COUNT")
    proof = take(PROOF_BYTES)
    require(pos == len(raw) and proof[:4] == b"PNW1", "PROOF_ENVELOPE")
    require(sequence_root(transactions) == header[186:218], "BODY_COMMITMENT")
    require(domain_hash("native-growth-account-witness-v2", witness) == header[322:354],
            "WITNESS_COMMITMENT")
    trace = proof[-32:]
    claim = dict(header_hex=header.hex(), trace_hex=trace.hex(),
                 body_sha256=sha256(raw[body_start:body_end]),
                 witness_sha256=sha256(witness), packet_sha256=sha256(raw))
    return dict(claim=claim, claim_sha256=sha256(canonical(claim)),
                block_hex=domain_hash("permanent-account-growth-block-v2", header, trace).hex(),
                challenge_hex=domain_hash("permanent-account-growth-challenge-v2", header).hex(),
                parent_hex=header[74:106].hex(), task_hex=header[282:314].hex(),
                network_hex=header[10:42].hex(), parameters_hex=header[42:74].hex(),
                target_hex=header[122:154].hex(), height=int.from_bytes(header[106:114], "little"),
                timestamp=int.from_bytes(header[114:122], "little"),
                nonce=int.from_bytes(header[314:322], "little"), packet_bytes=len(raw),
                transaction_count=count)


def process_events(raw):
    lines = raw.splitlines()
    require(0 < len(lines) <= 32 and all(line for line in lines), "PROCESS_RECORD_COUNT")
    events = [decode(line) for line in lines]
    require(all(type(event) is dict and event.get("schema") == PROCESS_SCHEMA for event in events),
            "PROCESS_RECORD_SCHEMA")
    return events


def process_identity(event, packet):
    require(event.get("claim") == packet["claim"], "PROCESS_CLAIM")
    for field in ("block_hex", "parent_hex", "task_hex", "challenge_hex", "packet_bytes"):
        require(event.get(field) == packet[field], "PROCESS_" + field.upper())


def native_observation(raw, packet):
    """Read the exact Node schema or the real collector's observe_complete event."""
    value = decode(raw)
    if type(value) is dict and value.get("schema") == PROCESS_SCHEMA:
        require(value.get("event") == "observe_complete", "OBSERVER_EVENT")
        process_identity(value, packet)
        value = value.get("native_observation")
    require(type(value) is dict and value.get("schema") == OBSERVATION_SCHEMA,
            "NATIVE_OBSERVATION_SCHEMA")
    return value


def check_canonical(check, packet, evidence, context):
    """Check recorded ancestry/chainwork against raw PNP2 and the native snapshot.

    A native membership boolean without the corresponding exact identity, numeric
    depths/work and parent-linked packets cannot constitute canonical progress.
    The returned status is still a recorded observation, not authenticated finality.
    """
    keys(check, {"at_ns", "receipt", "canonical_path"}, "CANONICAL_CHECK_KEYS")
    at = integer(check["at_ns"], "CANONICAL_TIME")
    obs = native_observation(evidence.artifact(check["receipt"]), packet)
    for field in ("network", "parameters", "genesis"):
        require(obs.get(field) == context[field + "_hex"], "OBSERVATION_CONTEXT")
    require(obs.get("block") == packet["block_hex"] and obs.get("packet_profile") == "PNP2",
            "OBSERVATION_BLOCK")
    for field in ("stored_exact", "active_chain_member"):
        require(type(obs.get(field)) is bool, "OBSERVATION_BOOLEAN_TYPE")
    for field in ("global_absence_authority", "confirmation_authority", "finality_authority",
                  "execution_authority", "production_activation"):
        require(obs.get(field) is False, "OBSERVATION_AUTHORITY")
    integer(obs.get("generation"), "OBSERVATION_GENERATION")
    height = integer(obs.get("active_tip_height"), "TIP_HEIGHT")
    hex_value(obs.get("active_tip"), "TIP_IDENTITY")
    tip_work = int.from_bytes(hex_value(obs.get("active_tip_chainwork_hex"), "TIP_WORK", 64), "big")
    path = rows(check["canonical_path"], "CANONICAL_PATH_BOUND", MAX_PATH)
    if not obs["stored_exact"]:
        require(not obs["active_chain_member"] and not path
                and all(obs.get(field) is None for field in
                        ("block_height", "block_chainwork_hex", "active_depth", "active_work_depth_hex")),
                "ABSENT_OBSERVATION")
        return dict(at_ns=at, status="absent", depth=None)
    require(integer(obs.get("block_height"), "BLOCK_HEIGHT") == packet["height"], "BLOCK_HEIGHT")
    block_work = int.from_bytes(hex_value(obs.get("block_chainwork_hex"), "BLOCK_WORK", 64), "big")
    if not obs["active_chain_member"]:
        require(not path and obs.get("active_depth") is None and obs.get("active_work_depth_hex") is None,
                "REORG_OBSERVATION")
        return dict(at_ns=at, status="reorged", depth=None)
    require(path, "MISSING_CANONICAL_PATH")
    packets = [parse_packet(evidence.artifact(ref, PACKET_LIMIT)) for ref in path]
    require(packets[0]["claim"] == packet["claim"], "CANONICAL_INCLUSION_BYTES")
    delta = 0
    for previous, following in zip(packets, packets[1:]):
        require(following["parent_hex"] == previous["block_hex"]
                and following["height"] == previous["height"] + 1
                and following["network_hex"] == packet["network_hex"]
                and following["parameters_hex"] == packet["parameters_hex"], "CANONICAL_PARENT_CHAIN")
        target = int(following["target_hex"], 16)
        require(target > 0, "CANONICAL_TARGET")
        delta += (1 << 256) // (target + 1)
    depth = len(packets) - 1
    require(packets[-1]["block_hex"] == obs["active_tip"] and packets[-1]["height"] == height,
            "CANONICAL_TIP")
    require(integer(obs.get("active_depth"), "ACTIVE_DEPTH") == depth
            and height - packet["height"] == depth, "CANONICAL_DEPTH")
    observed_delta = int.from_bytes(hex_value(obs.get("active_work_depth_hex"), "WORK_DEPTH", 64), "big")
    require(tip_work >= block_work and tip_work - block_work == observed_delta == delta,
            "CANONICAL_CHAINWORK")
    return dict(at_ns=at, status="canonical", depth=depth)


def context_document(manifest, evidence):
    context = decode(evidence.artifact(manifest["context"]))
    require(type(context) is dict and context.get("schema") == "trnm-pon-fullpath-context-v1",
            "CONTEXT_SCHEMA")
    require(context.get("scope") in {"same-host-component-observation", "campaign"}, "CONTEXT_SCOPE")
    name(context.get("clock_id"), "CLOCK_ID")
    for field in ("source_sha256", "binary_sha256", "resource_contract_sha256", "workload_sha256",
                  "network_hex", "parameters_hex", "genesis_hex"):
        hex_value(context.get(field), "CONTEXT_" + field.upper())
    keys(context.get("stage_semantics"), PHASES, "STAGE_SEMANTICS")
    for description in context["stage_semantics"].values():
        name(description, "STAGE_BOUNDARY_DESCRIPTION")
    return context


def progress_counts(event):
    progress = event.get("work_progress")
    require(type(progress) is dict and progress.get("expected_transcript_tiles") == 512,
            "NATIVE_PROGRESS_SCHEMA")
    names = ("BeforeReplay", "TranscriptTile", "BeforeProduct", "BeforeVerifiedWork")
    counts = []
    previous = 0
    for field, maximum in zip(names, (1, 512, 1, 1)):
        value = progress.get(field)
        keys(value, {"count", "first_ns", "last_ns"}, "NATIVE_PROGRESS_FIELDS")
        count = integer(value["count"], "NATIVE_PROGRESS_COUNT", maximum=maximum)
        counts.append(count)
        if count:
            first = integer(value["first_ns"], "NATIVE_FIRST_CALLBACK", previous)
            previous = integer(value["last_ns"], "NATIVE_LAST_CALLBACK", first)
        else:
            require(value["first_ns"] is None and value["last_ns"] is None, "EMPTY_CALLBACK_TIME")
    require(previous <= integer(event.get("admission_call_ns"), "NATIVE_ADMISSION_DURATION"),
            "CALLBACK_AFTER_ADMISSION_RETURN")
    return counts


def stage_evidence(stage, packet, evidence, terminal_status):
    """No full-work verdict follows from a callback count without its success event."""
    complete = stage["status"] == "complete"
    if stage["receipt"] is None:
        require(not complete, "MISSING_COMPLETE_STAGE_RECEIPT")
        return False, False
    raw = evidence.artifact(stage["receipt"])
    try:
        events = process_events(raw)
    except ValueError:
        require(not complete, "UNREADABLE_COMPLETE_STAGE_RECEIPT")
        return False, False  # A panic/partial error log is retained, never a rejection success.
    if complete:
        require(not any(event.get("event") == "error" or event.get("status") == "error" for event in events),
                "ERROR_IN_COMPLETE_STAGE_RECEIPT")
        selected = [event for event in events if event.get("event") == EVENTS[stage["phase"]]]
        require(len(selected) == 1 and packet is not None, "MISSING_OR_DUPLICATE_STAGE_EVENT")
        event = selected[0]
        process_identity(event, packet)
        require(event.get("development") is True
                and event.get("compression_status") == "not_applicable_native_full_verification"
                and event.get("compressed_proof_generation_ns") is None, "NATIVE_COLLECTOR_SCOPE")
        if stage["phase"] == "search":
            require(integer(event.get("nonce_attempts"), "SEARCH_ATTEMPTS", 1)
                    == packet["nonce"] + 1, "SEARCH_NONCE_COUNT")
        if stage["phase"] == "verification":
            counts = progress_counts(event)
            require(event.get("admitted_block_hex") == packet["block_hex"], "ADMISSION_IDENTITY")
            if counts == [0, 0, 0, 0]:
                require(event.get("admission_reused_existing") is True
                        and terminal_status == "duplicate", "REUSED_WORK_IS_NOT_NEW_VERIFICATION")
                return False, False
            require(counts == [1, 512, 1, 1]
                    and event.get("admission_reused_existing") is False, "INCOMPLETE_FULL_NATIVE_REPLAY")
            return True, False
        return False, False
    errors = [event for event in events if event.get("event") == "error"]
    if not errors:
        return False, False
    require(len(errors) == 1, "DUPLICATE_ERROR_EVENT")
    error = errors[0]
    require(type(error.get("error")) is str and error["error"], "ERROR_RECEIPT")
    if packet is not None and "claim" in error:
        process_identity(error, packet)
    if stage["status"] == "cancelled":
        require(error.get("cancelled") is True, "CANCELLATION_RECEIPT")
    # This v1 hostile observation is specifically a late product rejection.
    # Earlier/capped/unavailable rejection never substitutes for its CPU work.
    late_rejection = (stage["phase"] == "verification" and stage["status"] == "rejected"
                      and error.get("stage") == "verification" and packet is not None
                      and error.get("claim") == packet["claim"]
                      and error.get("error") == "WORK:Product"
                      and error.get("cancelled") is False
                      and progress_counts(error) == [1, 512, 1, 0])
    return False, late_rejection


def counters(value, label):
    keys(value, RESOURCES, label)
    for field in RESOURCES:
        if value[field] is not None:
            integer(value[field], label + ":" + field)
    return all(value[field] is not None for field in RESOURCES)


def evaluate(manifest, report, evidence, manifest_sha256):
    keys(manifest, {"schema", "context", "observation_end_ns", "required_depth",
                    "minimum_reorg_window_ns", "maximum_total_cpu_ns", "maximum_peak_rss_bytes",
                    "maximum_total_wire_bytes", "minimum_timely_ppm", "minimum_samples_per_group",
                    "schedule"}, "MANIFEST_KEYS")
    require(manifest["schema"] == MANIFEST_SCHEMA, "MANIFEST_SCHEMA")
    context = context_document(manifest, evidence)
    end = integer(manifest["observation_end_ns"], "OBSERVATION_END", 1)
    depth = integer(manifest["required_depth"], "REQUIRED_DEPTH", maximum=MAX_PATH - 1)
    retention = integer(manifest["minimum_reorg_window_ns"], "REORG_WINDOW")
    ppm = integer(manifest["minimum_timely_ppm"], "MINIMUM_TIMELY_PPM", 1, 1_000_000)
    minimum = integer(manifest["minimum_samples_per_group"], "MINIMUM_SAMPLES", 1, MAX_ROWS)
    limits = dict(zip(RESOURCES, (integer(manifest["maximum_total_cpu_ns"], "CPU_LIMIT", 1),
                                 integer(manifest["maximum_peak_rss_bytes"], "RSS_LIMIT", 1),
                                 integer(manifest["maximum_total_wire_bytes"], "WIRE_LIMIT", 1))))
    schedule = {}
    for row in rows(manifest["schedule"], "SCHEDULE_BOUND"):
        keys(row, {"id", "cohort", "mode", "scheduled_ns", "deadline_ns", "reorg_observe_until_ns",
                   "parent_hex", "task_hex"}, "SCHEDULE_KEYS")
        identity = name(row["id"], "ATTEMPT_ID")
        require(identity not in schedule and row["cohort"] in {"honest", "hostile"}
                and row["mode"] in {"native", "compressed"}, "SCHEDULE_IDENTITY")
        start = integer(row["scheduled_ns"], "SCHEDULE_START")
        deadline = integer(row["deadline_ns"], "DEADLINE", start + 1)
        until = integer(row["reorg_observe_until_ns"], "REORG_UNTIL", deadline + retention)
        require(until <= end, "SCHEDULE_WINDOW")
        hex_value(row["parent_hex"], "SCHEDULE_PARENT")
        hex_value(row["task_hex"], "SCHEDULE_TASK")
        schedule[identity] = row
    require(schedule, "EMPTY_DENOMINATOR")
    keys(report, {"schema", "manifest_sha256", "context_sha256", "clock_id", "observed_through_ns",
                  "resources", "attempts"}, "REPORT_KEYS")
    require(report["schema"] == REPORT_SCHEMA and report["manifest_sha256"] == manifest_sha256,
            "REPORT_MANIFEST_BINDING")
    require(report["context_sha256"] == manifest["context"]["sha256"]
            and report["clock_id"] == context["clock_id"], "REPORT_CONTEXT_OR_CLOCK")
    through = integer(report["observed_through_ns"], "OBSERVED_THROUGH")
    total_available = counters(report["resources"], "CAMPAIGN_RESOURCES")
    actual, details, accepted_blocks = {}, {}, set()
    known_totals = dict.fromkeys(RESOURCES, 0)
    all_attempt_resources = True
    for row in rows(report["attempts"], "OBSERVATION_BOUND"):
        keys(row, {"id", "context_sha256", "status", "packet", "claim", "stages", "cpu_ns",
                   "peak_rss_bytes", "wire_bytes", "canonical_checks"}, "ATTEMPT_KEYS")
        identity = name(row["id"], "OBSERVED_ATTEMPT_ID")
        require(identity in schedule and identity not in actual, "UNSCHEDULED_OR_DUPLICATE_OBSERVATION")
        actual[identity] = row
        planned = schedule[identity]
        require(row["context_sha256"] == report["context_sha256"]
                and row["status"] in OUTCOMES, "ATTEMPT_CONTEXT_OR_STATUS")
        resources = {field: row[field] for field in RESOURCES}
        all_attempt_resources &= counters(resources, "ATTEMPT_RESOURCES")
        for field in RESOURCES:
            if resources[field] is not None:
                known_totals[field] = (max(known_totals[field], resources[field]) if field == "peak_rss_bytes"
                                       else known_totals[field] + resources[field])
        packet = None
        if row["packet"] is not None:
            raw = evidence.artifact(row["packet"], PACKET_LIMIT)
            try:
                packet = parse_packet(raw)
            except ValueError:
                require(row["status"] != "accepted" and row["claim"] is None, "ACCEPTED_MALFORMED_PACKET")
            if packet is not None:
                require(row["claim"] == packet["claim"], "ATTEMPT_CLAIM")
                require(packet["parent_hex"] == planned["parent_hex"]
                        and packet["task_hex"] == planned["task_hex"]
                        and packet["network_hex"] == context["network_hex"]
                        and packet["parameters_hex"] == context["parameters_hex"], "ATTEMPT_PACKET_CONTEXT")
        else:
            require(row["claim"] is None, "CLAIM_WITHOUT_PACKET")
        stages = rows(row["stages"], "PHASE_COUNT", len(PHASES))
        previous_end, previous_index, failed = planned["scheduled_ns"], -1, False
        full_replay, late_rejection = False, False
        for stage in stages:
            keys(stage, {"phase", "started_ns", "ended_ns", "status", "claim_sha256", "receipt"}, "PHASE_KEYS")
            require(stage["phase"] in PHASES and stage["status"] in PHASE_OUTCOMES, "PHASE_IDENTITY")
            index = PHASES.index(stage["phase"])
            require(index > previous_index and not failed, "PHASE_ORDER_OR_POST_FAILURE_PROGRESS")
            start = integer(stage["started_ns"], "PHASE_START", previous_end)
            previous_end = integer(stage["ended_ns"], "PHASE_END", start)
            require(previous_end <= through, "PHASE_AFTER_OBSERVATION_END")
            require(stage["claim_sha256"] == (packet["claim_sha256"] if packet else None), "PHASE_CLAIM")
            verified, rejected = stage_evidence(stage, packet, evidence, row["status"])
            full_replay |= verified
            late_rejection |= rejected
            previous_index = index
            failed = stage["status"] != "complete"
        full_path = (len(stages) == len(PHASES) and not failed and full_replay)
        if row["status"] == "accepted":
            require(full_path and packet is not None, "ACCEPTED_WITHOUT_FULL_PATH")
            require(int(packet["target_hex"], 16) > 0, "ACCEPTED_ZERO_TARGET")
        checks = [check_canonical(check, packet, evidence, context)
                  for check in rows(row["canonical_checks"], "CANONICAL_CHECK_BOUND", MAX_CHECKS)
                  if packet is not None]
        require(packet is not None or not row["canonical_checks"], "CHECK_WITHOUT_PACKET")
        require(all(check["at_ns"] <= through for check in checks)
                and all(a["at_ns"] < b["at_ns"] for a, b in zip(checks, checks[1:])), "CANONICAL_CLOCK")
        if row["status"] == "accepted":
            require(checks and checks[0]["status"] == "canonical", "ACCEPTED_WITHOUT_CANONICAL_READBACK")
            require(row["canonical_checks"][0]["receipt"] == stages[-1]["receipt"],
                    "ACCEPTANCE_SNAPSHOT_BINDING")
            verification_end = stages[3]["ended_ns"]
            require(verification_end <= checks[0]["at_ns"] <= stages[-1]["ended_ns"],
                    "CANONICAL_OUTSIDE_ACCEPTANCE")
        qualifies = [max(check["at_ns"], previous_end) for check in checks
                     if check["status"] == "canonical" and check["depth"] >= depth]
        first_progress = min(qualifies) if qualifies else None
        lost = any(check["status"] != "canonical" for check in checks)
        retained = bool(checks and checks[-1]["at_ns"] >= planned["reorg_observe_until_ns"]
                        and checks[-1]["status"] == "canonical" and checks[-1]["depth"] >= depth
                        and through >= planned["reorg_observe_until_ns"] and not lost)
        duplicate = row["status"] == "duplicate"
        if row["status"] == "accepted":
            duplicate = packet["block_hex"] in accepted_blocks
            accepted_blocks.add(packet["block_hex"])
        timely = (row["status"] == "accepted" and not duplicate and retained and first_progress is not None
                  and first_progress <= planned["deadline_ns"] and planned["mode"] == "native")
        hostile_timely = (row["status"] == "rejected" and late_rejection
                          and previous_end <= planned["deadline_ns"] and planned["mode"] == "native")
        details[identity] = dict(id=identity, status=row["status"], full_path_completed=full_path,
            full_native_replay_observed=full_replay, late_product_rejection_observed=late_rejection,
            block_hex=packet["block_hex"] if packet else None, duplicate_progress=duplicate,
            first_required_depth_progress_ns=first_progress,
            latency_from_scheduled_ns=first_progress - planned["scheduled_ns"] if first_progress is not None else None,
            reorg_or_absence_observed=lost, reorg_window_covered=retained,
            last_canonical_depth=checks[-1]["depth"] if checks else None,
            timely_accepted_progress=timely, timely_hostile_rejection=hostile_timely)
    resources_met = total_available and all_attempt_resources
    for field in RESOURCES:
        total = report["resources"][field]
        if total is not None:
            require(total >= known_totals[field], "CAMPAIGN_RESOURCE_UNDERCOUNT:" + field)
            resources_met &= total <= limits[field]
    groups = []
    for cohort, mode in sorted({(row["cohort"], row["mode"]) for row in schedule.values()}):
        ids = [identity for identity, row in schedule.items() if (row["cohort"], row["mode"]) == (cohort, mode)]
        field = "timely_accepted_progress" if cohort == "honest" else "timely_hostile_rejection"
        successes = sum(bool(details.get(identity, {}).get(field)) for identity in ids)
        missing = sum(identity not in actual for identity in ids)
        outcomes = collections.Counter(actual[identity]["status"] if identity in actual else "missing" for identity in ids)
        groups.append(dict(cohort=cohort, mode=mode, scheduled=len(ids), missing=missing,
                           outcomes=dict(sorted(outcomes.items())), timely_successes=successes,
                           timely_ppm_floor=successes * 1_000_000 // len(ids),
                           recorded_arithmetic_met=(not missing and len(ids) >= minimum
                               and successes * 1_000_000 >= ppm * len(ids))))
    missing = [identity for identity in schedule if identity not in actual]
    modes = {row["mode"] for row in schedule.values()}
    missing_groups = [dict(cohort=cohort, mode=mode) for mode in sorted(modes)
                      for cohort in ("honest", "hostile")
                      if not any(row["cohort"] == cohort and row["mode"] == mode for row in schedule.values())]
    arithmetic = (not missing and not missing_groups and through >= end and resources_met
                  and all(group["recorded_arithmetic_met"] for group in groups))
    # The only admitted receipt schema is the explicit development native
    # collector. Relabeling context.scope must not upgrade it into a campaign.
    return dict(schema="trnm-pon-fullpath-readback-v1", manifest_sha256=manifest_sha256,
        context_sha256=manifest["context"]["sha256"], scheduled=len(schedule), recorded=len(actual),
        missing=missing, missing_cohort_groups=missing_groups, groups=groups,
        attempts=[details[identity] for identity in schedule if identity in details],
        recorded_unique_new_native_blocks=len(accepted_blocks),
        timely_accepted_progress=sum(row["timely_accepted_progress"] for row in details.values()),
        observation_window_covered=through >= end, resources=report["resources"],
        known_attempt_resources=known_totals, recorded_resource_thresholds_met=bool(resources_met),
        recorded_arithmetic_thresholds_met=bool(arithmetic),
        performance_gate="COMPONENT_OBSERVATION_ONLY", security_gate="HOLD", overall_gate="HOLD",
        scope=context["scope"], stage_semantics=context["stage_semantics"],
        compressed_path_qualified=False, source_integrity_authenticated=False,
        raw_receipts_cryptographically_authenticated=False, physical_clock_authenticated=False,
        resource_contract_enforcement_verified=False, native_relation_replayed_by_reader=False,
        security_qualification_verified=False, quantum_lower_bound_proved=False,
        public_network_ready=False, production_activation=False)


def read_campaign(root, expected_manifest_sha256, *, manifest_path="manifest.json",
                  report_path="observations.json"):
    hex_value(expected_manifest_sha256, "EXPECTED_MANIFEST_DIGEST")
    evidence = Evidence(root)
    raw = evidence.read(manifest_path)
    require(sha256(raw) == expected_manifest_sha256, "FROZEN_MANIFEST_HASH_MISMATCH")
    return evaluate(decode(raw), decode(evidence.read(report_path)), evidence, expected_manifest_sha256)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--manifest", default="manifest.json")
    parser.add_argument("--observations", default="observations.json")
    args = parser.parse_args()
    try:
        result = read_campaign(args.evidence, args.manifest_sha256,
                               manifest_path=args.manifest, report_path=args.observations)
    except (OSError, ValueError, TypeError, KeyError, OverflowError) as exc:
        print(json.dumps(dict(schema="trnm-pon-fullpath-readback-v1", evidence_valid=False,
                              error=str(exc), security_gate="HOLD", overall_gate="HOLD",
                              production_activation=False), sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 1  # A component observation is deliberately not a passing gate.


if __name__ == "__main__":
    sys.exit(main())
