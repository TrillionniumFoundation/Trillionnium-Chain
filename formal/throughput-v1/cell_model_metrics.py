#!/usr/bin/env python3
"""Project pinned original SmolLM/Cell research records without upgrading scope.

This version recognizes the historical one-host replica experiment, including
its earlier optimized-transfer failure. It does not run a model, authenticate a
meter, grant FinalUse, or qualify the distinct original 35-second cold cohort.
"""
from __future__ import annotations

import argparse
from decimal import Decimal
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

SCHEMA = "trnm-cell-model-projection-input-v1"
PREFIX = "evidence/smollm-cell-replica-research-v1/"
MAX_FILE = 2 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
AUTHORITY = dict.fromkeys(("hepta_final_use", "independent_accepted", "installation_authorized",
    "prospective_accepted", "public_reward_eligible", "selection_authorized"), False)
PROFILE = "hepta-smollm-single-token-action-score-v1"
TRANSFERS = ("publisher-to-replica", "offline-publisher-negative", "replica-to-consumer")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def fields(value, names, code):
    require(type(value) is dict and set(value) == set(names.split()), code)


def same(left, right):
    """JSON equality without bool/int/decimal aliases."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return set(left) == set(right) and all(same(left[k], right[k]) for k in left)
    if type(left) is list:
        return len(left) == len(right) and all(same(a, b) for a, b in zip(left, right))
    return left == right


def integer(value, code, minimum=0):
    require(type(value) is int and minimum <= value < 1 << 127, code)
    return value


def digest(value, length=64):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % length, value), "DIGEST")
    return value


def rational(value):
    value = Fraction(value)
    return {"numerator": value.numerator, "denominator": value.denominator}


def seconds(value):
    require(type(value) in (int, Decimal) and 0 < value <= 86400, "DURATION_SECONDS")
    return Fraction(value)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def decimal(token):
    require(len(token) <= 64, "NUMBER_LIMIT")
    value = Decimal(token)
    require(value.is_finite() and -24 <= value.as_tuple().exponent <= 24, "NUMBER_LIMIT")
    return value


def parse(raw):
    require(type(raw) is bytes and len(raw) <= MAX_FILE, "INPUT_LIMIT")
    def bounded_int(token):
        require(len(token) <= 40, "INTEGER_LIMIT")
        return int(token)
    def constant(_):
        raise ValueError("NONFINITE_JSON")
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_float=decimal,
                          parse_int=bounded_int, parse_constant=constant)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("JSON_ENCODING_OR_DEPTH") from error


def read_regular(root, relative):
    """Walk every component with O_NOFOLLOW, cap reads, reject special files."""
    require(type(relative) is str and 0 < len(relative) <= 1024, "RECORD_PATH")
    path = PurePosixPath(relative)
    require(not path.is_absolute() and str(path) == relative and
            all(p not in (".", "..") for p in path.parts), "RECORD_PATH")
    root = Path(root).absolute()
    parts = (*root.parts[1:], *path.parts)
    require(all(p not in (".", "..") for p in parts), "ROOT_PATH")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    descriptor = None
    try:
        for component in parts[:-1]:
            next_directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                     dir_fd=directory)
            os.close(directory)
            directory = next_directory
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "REGULAR_SINGLE_LINK_REQUIRED")
        require(0 <= before.st_size <= MAX_FILE, "INPUT_LIMIT")
        chunks, count = [], 0
        while True:
            block = os.read(descriptor, min(65536, MAX_FILE + 1 - count))
            if not block:
                break
            chunks.append(block)
            count += len(block)
            require(count <= MAX_FILE, "INPUT_LIMIT")
        after = os.fstat(descriptor)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "INPUT_CHANGED")
        require(count == before.st_size, "INPUT_CHANGED")
        return b"".join(chunks)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def required_records(cells):
    result = {"actual/research-result.json", "actual/frozen-comparison.json",
              "actual/baseline-read/ready.json", "actual/candidate-read/ready.json",
              "actual/transport/source-release.tcr1"}
    for name in TRANSFERS:
        result |= {f"actual/transport/{name}-command.json", f"actual/transport/{name}.log"}
        if name != "offline-publisher-negative":
            result.add(f"actual/transport/{name}.tcr1")
    for index in range(cells):
        result |= {f"actual/transport/materialize-{index}-command.json",
                   f"actual/transport/materialize-{index}.log"}
    for generation in (1, 2, 3):
        result |= {f"training/gen{generation}/actual-receipt.json", f"training/gen{generation}/command.json"}
    result |= {"failures/optimized-original/failure-summary.json",
               "failures/optimized-original/publisher-to-replica-command.json",
               "failures/optimized-original/publisher-to-replica.log"}
    return result


def load_bundle(path, expected_sha256):
    path = Path(path).absolute()
    raw = read_regular(path.parent, path.name)
    require(hashlib.sha256(raw).hexdigest() == digest(expected_sha256), "MANIFEST_PIN")
    manifest = parse(raw)
    fields(manifest, "schema scope retained_at_commit recorded_native_source_commit expected_release files", "MANIFEST_FIELDS")
    require(manifest["schema"] == SCHEMA and manifest["scope"] == "historical-smollm-replica-v1", "MANIFEST_SCOPE")
    for name in ("retained_at_commit", "recorded_native_source_commit"):
        digest(manifest[name], 40)
    release = manifest["expected_release"]
    fields(release, "release cells payload_bytes chunks", "RELEASE_PIN_FIELDS")
    digest(release["release"])
    for name in ("cells", "payload_bytes", "chunks"):
        integer(release[name], "RELEASE_PIN", 1)
    require(release["cells"] <= 256, "CELL_COUNT_LIMIT")
    require(type(manifest["files"]) is dict and set(manifest["files"]) == required_records(release["cells"]),
            "COMPLETE_RECORD_DENOMINATOR")
    records, paths, total = {}, set(), 0
    for original, pin in manifest["files"].items():
        fields(pin, "path sha256 git_blob_sha1 source_path", "FILE_PIN_FIELDS")
        require(pin["source_path"] == PREFIX + original, "ORIGINAL_SOURCE_PATH")
        require(type(pin["path"]) is str and pin["path"] not in paths, "DUPLICATE_RECORD_PATH")
        paths.add(pin["path"])
        data = read_regular(path.parent, pin["path"])
        total += len(data)
        require(total <= MAX_TOTAL, "BUNDLE_SIZE_LIMIT")
        require(hashlib.sha256(data).hexdigest() == digest(pin["sha256"]), "FILE_SHA256")
        git_blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        require(git_blob == digest(pin["git_blob_sha1"], 40), "GIT_BLOB_IDENTITY")
        records[original] = data
    return manifest, records


def no_authority(value):
    require(type(value) is dict and set(value) == set(AUTHORITY) and
            all(v is False for v in value.values()), "AUTHORITY_ESCALATION")


def command(raw):
    value = parse(raw)
    # Historical v1 lacks monotonic endpoints and direct resource accounting.
    # Do not synthesize them from elapsed_seconds or import later v2 receipts.
    fields(value, "argv elapsed_seconds returncode", "HISTORICAL_COMMAND_FIELDS")
    require(type(value["argv"]) is list and 2 <= len(value["argv"]) <= 128 and
            all(type(v) is str and len(v) <= 4096 for v in value["argv"]), "COMMAND_ARGV")
    require(type(value["returncode"]) is int and -128 <= value["returncode"] <= 255, "COMMAND_EXIT")
    return value, seconds(value["elapsed_seconds"])


def option(value, name):
    argv = value["argv"]
    require(argv.count(name) == 1 and argv.index(name) + 1 < len(argv), "COMMAND_OPTION:" + name)
    return argv[argv.index(name) + 1]


def recorded_path(value, code):
    """Validate inert historical path text; never open an old host's path."""
    require(type(value) is str and 0 < len(value) <= 4096 and
            all(ord(character) >= 32 for character in value), code)
    path = PurePosixPath(value)
    require(path.is_absolute() and str(path) == value and
            all(part not in (".", "..") for part in path.parts), code)
    return path


def release_members(raw):
    require(raw[:4] == b"TCR1" and len(raw) >= 169, "TCR1_HEADER")
    length = raw[4]
    require(1 <= length <= 64 and len(raw) >= 169 + length, "TCR1_FAMILY")
    family = raw[5:5 + length]
    require(re.fullmatch(rb"[A-Za-z0-9._-]+", family), "TCR1_FAMILY")
    offset = 5 + length
    context = {}
    for index, name in enumerate(("base", "parent", "tokenizer", "layout", "runtime")):
        value = raw[offset + 32 * index:offset + 32 * (index + 1)]
        require(value != bytes(32), "TCR1_CONTEXT")
        context[name] = value.hex()
    offset += 160
    count = int.from_bytes(raw[offset:offset + 4], "big")
    require(1 <= count <= 256 and len(raw) == offset + 4 + 32 * count, "TCR1_COVERAGE")
    members = [raw[offset + 4 + 32 * i:offset + 36 + 32 * i].hex() for i in range(count)]
    require(members == sorted(set(members)) and all(m != "0" * 64 for m in members), "TCR1_ORDER")
    return hashlib.sha256(b"trnm.cell-release-manifest.v1\0" + raw).hexdigest(), members, context


def project_transfers(manifest, raw, research):
    transport, expected = research["transport"], manifest["expected_release"]
    fields(transport, "all_model_dependencies_rehashed authority connection_budget consumer_acquisition consumer_materials "
           "consumer_parent hepta_final_use independent_operators members offline_publisher_negative original_hepta_installed "
           "parent_sha256 pq_authenticated_transport publisher release release_sha256 replica replica_acquisition "
           "response_byte_budget scope", "TRANSPORT_FIELDS")
    no_authority(transport["authority"])
    require(all(transport[k] is False for k in ("hepta_final_use", "independent_operators", "original_hepta_installed",
            "pq_authenticated_transport")), "TRANSPORT_AUTHORITY")
    require(transport["scope"] == "one-host-controlled-native-TCL4-complete-model-and-LoRA-replica" and
            transport["all_model_dependencies_rehashed"] is True, "TRANSPORT_SCOPE")
    require(same(transport["release"], dict(expected, schema="trnm.cell.release.prepare.v1")), "RELEASE_CONTEXT")
    for key in ("connection_budget", "response_byte_budget"):
        integer(transport[key], "TRANSPORT_BUDGET", 1)
    for role in ("publisher", "replica"):
        process = transport[role]
        fields(process, "address pid returncode stopped store", "PEER_PROCESS_FIELDS")
        require(process["stopped"] is True and type(process["returncode"]) is int, "PEER_TERMINATION_RECORD")
        integer(process["pid"], "PEER_PID", 1)
        require(type(process["address"]) is str and re.fullmatch(r"127\.0\.0\.1:[1-9][0-9]{0,4}", process["address"]) and
                int(process["address"].rsplit(":", 1)[1]) <= 65535, "PEER_ADDRESS")
        recorded_path(process["store"], "PEER_STORE")
    materials = recorded_path(transport["consumer_materials"], "CONSUMER_MATERIALS_PATH")
    parent_file = recorded_path(transport["consumer_parent"], "CONSUMER_PARENT_PATH")
    require(parent_file.name == "parent-material.json" and parent_file.parent != materials and
            parent_file.parent.parent == materials.parent, "CONSUMER_PATH_LAYOUT")
    consumer_command, _ = command(raw["actual/transport/replica-to-consumer-command.json"])
    consumer_store = recorded_path(option(consumer_command, "--store"), "CONSUMER_CACHE_BINDING")
    require(consumer_store.parent == materials.parent and str(consumer_store) not in
            {transport["publisher"]["store"], transport["replica"]["store"]}, "CONSUMER_CACHE_BINDING")
    marker = raw["actual/transport/source-release.tcr1"]
    release_id, member_ids, context = release_members(marker)
    require(release_id == expected["release"] and hashlib.sha256(marker).hexdigest() == transport["release_sha256"],
            "TCR1_IDENTITY")
    candidate = parse(raw["actual/frozen-comparison.json"])["candidate"]
    ready = parse(raw["actual/candidate-read/ready.json"])
    require(context == {"base": ready["backbone"], "parent": candidate["file_sha256"],
            "tokenizer": ready["tokenizer"], "layout": candidate["contract"], "runtime": research["worker_sha256"]},
            "RELEASE_MODEL_CONTEXT")
    members = transport["members"]
    require(type(members) is list and len(members) == expected["cells"], "COMPLETE_VERSION_MEMBERS")
    seen, names, destinations, materializations = set(), set(), set(), []
    for index, member in enumerate(members):
        fields(member, "destination materialization name pack source", "MEMBER_FIELDS")
        pack = member["pack"]
        fields(pack, "bytes chunks manifest payload_sha256 schema", "PACK_FIELDS")
        require(pack["schema"] == "trnm.cell.pack.v1", "PACK_SCHEMA")
        integer(pack["bytes"], "PACK_BYTES", 1); integer(pack["chunks"], "PACK_CHUNKS", 1)
        digest(pack["payload_sha256"]); digest(pack["manifest"])
        require(type(member["name"]) is str and member["name"] not in names and pack["manifest"] not in seen,
                "DUPLICATE_MEMBER")
        seen.add(pack["manifest"]); names.add(member["name"])
        logical = PurePosixPath(member["name"])
        require(str(logical) == member["name"] and len(logical.parts) == 2 and logical.parts[0] in ("base", "adapter") and
                logical.parts[1] not in (".", ".."), "MEMBER_NAME_MAPPING")
        destination = recorded_path(member["destination"], "MATERIALIZATION_DESTINATION")
        expected_destination = (materials if logical.parts[0] == "base" else parent_file.parent) / logical.parts[1]
        require(destination == expected_destination and destination not in destinations, "MATERIALIZATION_DESTINATION")
        destinations.add(destination)
        output = parse(raw[f"actual/transport/materialize-{index}.log"])
        require(same(output, member["materialization"]), "MATERIALIZATION_RAW_BINDING")
        fields(output, "bytes cached_chunks connection_attempts downloaded_bytes downloaded_chunks manifest max_response_bytes "
               "payload_sha256 received_response_bytes rejected_responses schema suppliers", "MATERIALIZATION_FIELDS")
        require(output["schema"] == "trnm.cell.fetch.v1" and output["manifest"] == pack["manifest"] and
                output["payload_sha256"] == pack["payload_sha256"], "MATERIALIZATION_IDENTITY")
        for key in set(output) - {"schema", "manifest", "payload_sha256"}:
            integer(output[key], "MATERIALIZATION_INTEGER")
        require(output["bytes"] == pack["bytes"] and output["cached_chunks"] == pack["chunks"] and
                all(output[k] == 0 for k in ("downloaded_chunks", "downloaded_bytes", "connection_attempts",
                    "received_response_bytes", "max_response_bytes", "rejected_responses", "suppliers")), "CACHE_ONLY_COMPLETION")
        cmd, duration = command(raw[f"actual/transport/materialize-{index}-command.json"])
        require(cmd["returncode"] == 0 and cmd["argv"][1] == "fetch" and
                option(cmd, "--manifest") == pack["manifest"] and option(cmd, "--output") == member["destination"],
                "MATERIALIZATION_COMMAND")
        require(option(cmd, "--store") == str(consumer_store), "CONSUMER_CACHE_BINDING")
        materializations.append({"member": member["name"], "reported_command_seconds": rational(duration)})
    require(sorted(seen) == member_ids and sum(m["pack"]["bytes"] for m in members) == expected["payload_bytes"] and
            sum(m["pack"]["chunks"] for m in members) == expected["chunks"], "COMPLETE_RELEASE_COVERAGE")
    artifact_members = [m for m in members if m["name"] == "adapter/artifact.safetensors"]
    require(len(artifact_members) == 1 and artifact_members[0]["pack"]["payload_sha256"] == candidate["file_sha256"],
            "RELEASE_CANDIDATE_BYTES")
    observations = []
    for name in TRANSFERS:
        cmd, duration = command(raw[f"actual/transport/{name}-command.json"])
        require(cmd["argv"][1] == "fetch-release" and option(cmd, "--release") == release_id and
                option(cmd, "--max-bytes") == str(expected["payload_bytes"]) and
                option(cmd, "--max-chunks") == str(expected["chunks"]) and
                re.fullmatch(r"127\.0\.0\.1:[1-9][0-9]{0,4}", option(cmd, "--peers")), "TRANSFER_COMMAND")
        negative = name == "offline-publisher-negative"
        peer_role = "replica" if name == "replica-to-consumer" else "publisher"
        require(option(cmd, "--peers") == transport[peer_role]["address"], "TRANSFER_PEER_ROLE")
        if name == "publisher-to-replica":
            require(option(cmd, "--store") == transport["replica"]["store"], "REPLICA_CACHE_BINDING")
        budget_ms = 2000 if negative else 180000
        require(option(cmd, "--overall-ms") == str(budget_ms), "ORIGINAL_TRANSFER_BUDGET")
        if negative:
            require(cmd["returncode"] > 0 and same(transport["offline_publisher_negative"],
                    {"no_completion_file": True, "returncode": cmd["returncode"]}), "OFFLINE_REFUSAL")
            refusal_log = raw[f"actual/transport/{name}.log"]
            require(b"Connection refused" in refusal_log and
                    b"peer=" + transport["publisher"]["address"].encode() + b" " in refusal_log,
                    "OFFLINE_RAW_REFUSAL")
            payload, response_bytes = 0, None
        else:
            output = parse(raw[f"actual/transport/{name}.log"])
            fields(output, "schema release cells payload_bytes chunks cached_chunks downloaded_chunks downloaded_bytes "
                   "received_response_bytes max_response_bytes connection_attempts rejected_responses suppliers", "FETCH_FIELDS")
            for key in set(output) - {"schema", "release"}:
                integer(output[key], "FETCH_INTEGER")
            require(output["schema"] == "trnm.cell.release.fetch.v1" and
                    all(output[k] == v for k, v in expected.items()), "FETCH_RELEASE_BINDING")
            role = "replica_acquisition" if name == TRANSFERS[0] else "consumer_acquisition"
            require(same(output, transport[role]) and raw[f"actual/transport/{name}.tcr1"] == marker, "FETCH_RAW_BINDING")
            require(cmd["returncode"] == 0 and duration <= Fraction(budget_ms, 1000) and
                    output["cached_chunks"] == 0 and output["downloaded_chunks"] == expected["chunks"] and
                    output["downloaded_bytes"] == expected["payload_bytes"] and
                    output["received_response_bytes"] >= output["downloaded_bytes"] and
                    output["received_response_bytes"] <= output["max_response_bytes"] == transport["response_byte_budget"] and
                    output["connection_attempts"] <= transport["connection_budget"] and output["suppliers"] == 1,
                    "FRESH_COMPLETE_FETCH")
            payload, response_bytes = expected["payload_bytes"], output["received_response_bytes"]
        observations.append({"command": name, "outcome": "controlled-refusal" if negative else "reported-complete-release",
            "original_overall_budget_ms": budget_ms, "reported_command_seconds": rational(duration),
            "reported_useful_bytes": payload, "reported_response_bytes": response_bytes,
            "decimal_MB_per_command_second": rational(Fraction(payload, 1_000_000) / duration) if not negative else None})
    return {"cohort": expected, "topology": "one-host-loopback", "recorded_transfer_commands": len(observations),
        "reported_complete_release_acquisitions": 2, "controlled_refusals": 1,
        "observations": observations, "complete_consumer_member_readbacks": len(members),
        "materialization_commands": materializations,
        "complete_pipeline_MB_per_second": None, "independent_version_recovery_rate": None,
        "cold_model_load_seconds": None, "original_35_second_cohort_retested": False,
        "complete_global_attempt_denominator": False, "native_bytes_rehashed_by_this_reader": False}


def quantile(values, numerator, denominator):
    ordered = sorted(values)
    return ordered[(len(ordered) * numerator + denominator - 1) // denominator - 1]


def project_forwards(raw, research):
    comparison = parse(raw["actual/frozen-comparison.json"])
    fields(comparison, "authority baseline candidate independently_custodied profile prospective_accepted schema scope seed tasks", "COMPARISON_FIELDS")
    no_authority(comparison["authority"])
    require(comparison["schema"] == "trnm-smollm-public-post-artifact-comparison-v1" and comparison["profile"] == PROFILE and
            comparison["scope"] == "operator-controlled-public-fixtures" and comparison["independently_custodied"] is False and
            comparison["prospective_accepted"] is False, "COMPARISON_SCOPE")
    require(hashlib.sha256(raw["actual/frozen-comparison.json"]).hexdigest() == research["frozen_comparison_sha256"], "COMPARISON_PIN")
    tasks = comparison["tasks"]
    require(type(tasks) is list and 1 <= len(tasks) <= 128 and integer(research["tasks_per_model"], "TASK_COUNT", 1) == len(tasks), "TASK_DENOMINATOR")
    task_map = {}
    for task in tasks:
        fields(task, "expected_output prompt request_id", "TASK_FIELDS")
        require(type(task["request_id"]) is str and 0 < len(task["request_id"]) <= 128 and task["request_id"] not in task_map and
                type(task["prompt"]) is str and 0 < len(task["prompt"]) <= 16384 and task["expected_output"] in ("no", "yes"), "TASK_ID")
        task_map[task["request_id"]] = task
    groups = {}
    for role in ("baseline", "candidate"):
        parent = comparison[role]
        fields(parent, "adapter contract directory file_sha256 generation operation_id schema", "PARENT_FIELDS")
        require(parent["schema"] == "hepta-smollm-parent-material-v1", "PARENT_SCHEMA")
        for key in ("adapter", "contract", "file_sha256"):
            digest(parent[key])
        integer(parent["generation"], "PARENT_GENERATION", 1)
        ready = parse(raw[f"actual/{role}-read/ready.json"])
        fields(ready, "actions actual_loaded_parent authority backbone contract file_sha256 generation observed_rss_bytes schema source_pins tokenizer worker_source", "READY_FIELDS")
        no_authority(ready["authority"])
        integer(ready["generation"], "READY_GENERATION", 1)
        require(ready["schema"] == "hepta-smollm-neural-read-worker-v1" and ready["worker_source"] == research["worker_sha256"] and
                ready["source_pins"] == research["source_pins"] and ready["actual_loaded_parent"] == parent["adapter"] and
                all(ready[k] == parent[k] for k in ("contract", "file_sha256", "generation")), "READY_IDENTITY")
        require(ready["actions"] == [{"action_id": "no", "completion": "no"}, {"action_id": "yes", "completion": "yes"}], "ACTION_PROFILE")
        integer(ready["observed_rss_bytes"], "READY_RSS", 1)
        require(parent["adapter"] not in groups, "DUPLICATE_PARENT")
        groups[parent["adapter"]] = {"role": role, "parent": parent, "seen": set(), "latencies": [], "rss": [], "correct": 0}
    require(comparison["candidate"]["generation"] == comparison["baseline"]["generation"] + 1 and
            comparison["candidate"]["contract"] == comparison["baseline"]["contract"], "PARENT_GENERATION_LINK")
    rows = research["raw_forward_observations"]
    require(type(rows) is list and len(rows) == 2 * len(tasks), "COMPLETE_FORWARD_DENOMINATOR")
    for row in rows:
        fields(row, "correct observation predicted request", "FORWARD_ROW_FIELDS")
        observed, request = row["observation"], row["request"]
        fields(observed, "action_ids artifact authority contract execution_ns file_sha256 input_sha256 input_tokens logits_sha256 "
               "observed_rss_bytes profile request_id schema scores_q32", "FORWARD_FIELDS")
        no_authority(observed["authority"])
        require(type(observed["artifact"]) is str and observed["artifact"] in groups, "FORWARD_MODEL")
        group = groups[observed["artifact"]]
        rid = observed["request_id"]
        require(type(rid) is str and rid in task_map and rid not in group["seen"] and same(request, task_map[rid]), "FORWARD_REQUEST")
        group["seen"].add(rid)
        require(observed["schema"] == "hepta-smollm-neural-read-worker-v1" and observed["profile"] == PROFILE and
                observed["action_ids"] == ["no", "yes"] and all(observed[k] == group["parent"][k] for k in ("contract", "file_sha256")), "FORWARD_BINDING")
        inp = {"schema": "hepta-smollm-inference-input-v1", "request_id": rid, "prompt": request["prompt"]}
        encoded = json.dumps(inp, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        require(hashlib.sha256(encoded).hexdigest() == digest(observed["input_sha256"]), "FORWARD_INPUT")
        digest(observed["logits_sha256"])
        scores = observed["scores_q32"]
        require(type(scores) is list and len(scores) == 2 and all(type(v) is int and -(1 << 63) <= v < 1 << 63 for v in scores), "FORWARD_SCORES")
        predicted = ("no", "yes")[int(scores[1] > scores[0])]
        correct = predicted == request["expected_output"]
        require(row["predicted"] == predicted and type(row["correct"]) is bool and row["correct"] == correct, "FORWARD_SCORING")
        integer(observed["input_tokens"], "INPUT_TOKENS", 1)
        group["correct"] += int(correct)
        group["latencies"].append(integer(observed["execution_ns"], "EXECUTION_NS", 1))
        group["rss"].append(integer(observed["observed_rss_bytes"], "OBSERVED_RSS", 1))
    metrics = {}
    for group in groups.values():
        require(group["seen"] == set(task_map), "COMPLETE_FORWARD_DENOMINATOR")
        role, latency = group["role"], group["latencies"]
        require(integer(research[role + "_correct"], "CORRECT_COUNT") == group["correct"], "CORRECT_COUNT")
        metrics[role] = {"planned_requests": len(tasks), "observed_forwards": len(latency), "correct": group["correct"],
            "accuracy": rational(Fraction(group["correct"], len(tasks))),
            "reported_execution_ns_sum": sum(latency),
            "forwards_per_reported_execution_second": rational(Fraction(len(latency) * 10**9, sum(latency))),
            "generated_tokens": None, "generated_tokens_per_second": None,
            "execution_latency_p50_nearest_rank_ns": quantile(latency, 1, 2),
            "execution_latency_p95_nearest_rank_ns": quantile(latency, 95, 100) if len(latency) >= 20 else None,
            "execution_latency_p99_nearest_rank_ns": quantile(latency, 99, 100) if len(latency) >= 100 else None,
            "maximum_reported_process_rss_bytes": max(group["rss"]), "cpu_ns": None,
            "population_tail_latency_qualified": False, "first_response_from_cold_start_ns": None}
    delta = Fraction(metrics["candidate"]["correct"] - metrics["baseline"]["correct"], len(tasks))
    require(type(research["observed_accuracy_difference"]) in (int, Decimal) and Fraction(research["observed_accuracy_difference"]) == delta,
            "QUALITY_DELTA")
    return {"profile": PROFILE, "scope": "reported-request-execution-only-excludes-load-network-queue-and-training",
        "models": metrics, "accuracy_difference": rational(delta), "selection_outcome": research["decision"],
        "actual_adoption_rate": None, "independent_quality_gain_qualified": False, "end_to_end_tokens_per_second": None}


def stage_metrics(events, generation):
    """Only complete original stage rosters yield per-stage cost projections."""
    expected = ["material-verification", "runtime-import", "model-load", "complete-backbone-tokenizer-verification"]
    if generation > 1:
        expected += ["parent-material-verification"]
    expected += ["adapter-insertion"]
    if generation > 1:
        expected += ["actual-parent-reload"]
    expected += ["training", "artifact-save"]
    require(type(events) is list and len(events) <= len(expected), "STAGE_LIMIT")
    names = []
    for event in events:
        fields(event, "bytes_read bytes_written cpu_ns error_type gpu_ns memory_peak_bytes outcome stage wall_ns", "STAGE_FIELDS")
        require(event["stage"] in expected and event["stage"] not in names and event["outcome"] in ("success", "failed"), "STAGE_IDENTITY")
        names.append(event["stage"])
        for key in ("wall_ns", "cpu_ns", "memory_peak_bytes"):
            integer(event[key], "STAGE_METER")
        for key in ("bytes_read", "bytes_written"):
            if event[key] is not None:
                integer(event[key], "STAGE_IO")
        require(type(event["gpu_ns"]) is int and event["gpu_ns"] == 0, "CPU_PROFILE_GPU")
        require((event["outcome"] == "success" and event["error_type"] is None) or
                (event["outcome"] == "failed" and type(event["error_type"]) is str), "STAGE_OUTCOME")
    complete = names == expected and all(e["outcome"] == "success" for e in events)
    return {"complete_original_stage_roster": complete, "observed_stages": names,
        "stage_costs": {e["stage"]: {k: e[k] for k in ("wall_ns", "cpu_ns", "memory_peak_bytes", "bytes_read", "bytes_written")}
                        for e in events} if complete else None,
        "cold_load_to_first_response_ns": None, "gpu_transfer_ns": None, "complete_model_loading_latency_ns": None}


def project_training(raw, research):
    rows, previous = [], None
    for generation in (1, 2, 3):
        receipt = parse(raw[f"training/gen{generation}/actual-receipt.json"])
        fields(receipt, "actual_backend actual_loaded_parent artifact authority backbone contract cost_events disposition generation input_sha256 "
               "operation_id outcome parameter_change parent parent_material_sha256 phase plan_sha256 process_peak_rss_bytes "
               "process_wall_ns schema scope source_pins tokenizer training", "TRAINING_FIELDS")
        no_authority(receipt["authority"])
        require(receipt["schema"] == "hepta-smollm-inherited-execution-v1" and receipt["actual_backend"] == "cpu" and
                receipt["scope"] == "actual-inherited-execution-no-owner-admission" and receipt["outcome"] == "success" and
                receipt["phase"] == "train" and receipt["disposition"] == "candidate-produced" and receipt["parameter_change"] is True and
                integer(receipt["generation"], "GENERATION", 1) == generation and receipt["source_pins"] == research["source_pins"], "TRAINING_SCOPE")
        for key in ("actual_loaded_parent", "artifact", "backbone", "contract", "input_sha256", "parent_material_sha256", "plan_sha256", "tokenizer"):
            digest(receipt[key])
        if previous is None:
            require(receipt["parent"] is None, "TRAINING_BOOTSTRAP")
        else:
            require(type(receipt["parent"]) is dict and receipt["parent"]["adapter"] == previous["artifact"] == receipt["actual_loaded_parent"] and
                    receipt["parent"]["generation"] == generation - 1, "TRAINING_PARENT")
        cmd, duration = command(raw[f"training/gen{generation}/command.json"])
        require(cmd["returncode"] == 0 and len(cmd["argv"]) >= 3 and cmd["argv"][2] == "train" and option(cmd, "--operation-id") == receipt["operation_id"] and
                option(cmd, "--input-sha256") == receipt["input_sha256"], "TRAINING_COMMAND")
        training = receipt["training"]
        fields(training, "flop_scope loss steps supervised_tokens supported_profile_flops tokens", "TRAINING_COST_FIELDS")
        for key in ("steps", "supervised_tokens", "supported_profile_flops", "tokens"):
            integer(training[key], "TRAINING_INTEGER", 1)
        require(option(cmd, "--steps") == str(training["steps"]) and type(training["loss"]) is list and
                len(training["loss"]) == training["steps"], "TRAINING_STEPS")
        stages = stage_metrics(receipt["cost_events"], generation)
        require(stages["complete_original_stage_roster"], "INCOMPLETE_SUCCESSFUL_TRAINING_STAGES")
        process_wall = integer(receipt["process_wall_ns"], "TRAINING_PROCESS_WALL", 1)
        require(sum(e["wall_ns"] for e in receipt["cost_events"]) <= process_wall <= duration * 10**9, "TRAINING_INTERVALS")
        rows.append({"generation": generation, "operation_id": receipt["operation_id"], "reported_outer_command_seconds": rational(duration),
            "reported_process_wall_ns": process_wall, "reported_training_steps": training["steps"],
            "reported_process_peak_rss_bytes": integer(receipt["process_peak_rss_bytes"], "TRAINING_RSS", 1),
            "stage_projection": stages, "full_process_family_cpu_ns": None, "complete_iteration_cost_minor": None})
        previous = receipt
    comparison = parse(raw["actual/frozen-comparison.json"])
    for index, role in ((2, "baseline"), (3, "candidate")):
        require(parse(raw[f"training/gen{index}/actual-receipt.json"])["artifact"] == comparison[role]["adapter"], "TRAINING_COMPARISON_LINK")
    return {"recorded_training_rounds": len(rows), "rounds": rows, "complete_product_iteration_cost": None,
        "scope": "reported-CPU-worker-stages-exclude-complete-selection-installation-adoption-and-payment"}


def project(manifest, raw):
    research = parse(raw["actual/research-result.json"])
    fields(research, "authority baseline_correct candidate_correct cell_binary_sha256 decision elapsed_seconds frozen_comparison_sha256 "
           "independent_operators no_update_reasons observed_accuracy_difference original_hepta_final_use pq_authenticated_transport "
           "product_artifact_installed public_wan_accepted python_packages raw_forward_observations runner_sha256 schema scope source_pins "
           "status tasks_per_model transport worker_sha256", "RESEARCH_FIELDS")
    no_authority(research["authority"])
    require(research["schema"] == "trnm-smollm-cell-replica-research-v1" and research["status"] == "research-completed-no-update" and
            research["decision"] == "no-update" and research["scope"] == "one-host-public-fixtures-real-model-bytes-and-forwards",
            "RESEARCH_SCOPE")
    for key in ("independent_operators", "original_hepta_final_use", "pq_authenticated_transport", "product_artifact_installed", "public_wan_accepted"):
        require(research[key] is False, "RESEARCH_AUTHORITY")
    for key in ("cell_binary_sha256", "runner_sha256", "worker_sha256"):
        digest(research[key])
    require(type(research["source_pins"]) is dict and 1 <= len(research["source_pins"]) <= 32, "SOURCE_PINS")
    for pin in research["source_pins"].values():
        digest(pin)
    failure = parse(raw["failures/optimized-original/failure-summary.json"])
    fields(failure, "status native_source_commit build_profile cell_binary_sha256 runner_sha256 observed_failure "
           "transfer_completed model_forwards_run root_cause_status production_activation independent_accepted", "PRIOR_FAILURE_FIELDS")
    digest(failure["cell_binary_sha256"])
    require(failure["status"] == "failed-optimized-transfer" and failure["build_profile"] == "release" and
            failure["native_source_commit"] == manifest["recorded_native_source_commit"] and
            failure["runner_sha256"] == research["runner_sha256"] and all(failure[k] is False for k in
            ("transfer_completed", "model_forwards_run", "production_activation", "independent_accepted")), "PRIOR_FAILURE_SCOPE")
    failed_cmd, failed_duration = command(raw["failures/optimized-original/publisher-to-replica-command.json"])
    require(failed_cmd["returncode"] != 0 and option(failed_cmd, "--release") == manifest["expected_release"]["release"] and
            b"Connection reset" in raw["failures/optimized-original/publisher-to-replica.log"], "PRIOR_FAILURE_RECORD")
    return {"schema": "trnm-cell-model-projection-report-v1", "scope": manifest["scope"],
        "records_retained_at_commit": manifest["retained_at_commit"],
        "recorded_native_source_commit": manifest["recorded_native_source_commit"],
        "recorded_native_binary_sha256": research["cell_binary_sha256"],
        "raw_file_count": len(raw), "cell_distribution": project_transfers(manifest, raw, research),
        "model_compute": project_forwards(raw, research), "training_and_loading": project_training(raw, research),
        "earlier_failed_attempt": {"profile": failure["build_profile"], "outcome": failure["status"],
            "reported_command_seconds": rational(failed_duration), "reported_completed_release": False,
            "recorded_native_binary_sha256": failure["cell_binary_sha256"], "root_cause_qualified": False},
        "qualification": "HOLD_NO_GO", "native_origin_authenticated": False, "source_execution_authenticated": False,
        "public_throughput_qualified": False, "independent_provider_custody_qualified": False,
        "model_adoption_qualified": False, "production_activation": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    manifest, records = load_bundle(args.manifest, args.manifest_sha256)
    print(json.dumps(project(manifest, records), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
