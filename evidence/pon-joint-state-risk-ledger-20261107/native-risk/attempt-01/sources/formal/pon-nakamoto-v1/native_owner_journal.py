"""Check the actual native-owner sidecar and retain every unresolved interval.

This reader checks bytes, event order, native identities/weights and local fork
witnesses. It does not turn caller-supplied JSON, a hash chain or a previous pin
into authenticated physical execution, fresh resource state or world coverage.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from native_execution_certificate import CertificateError, require, strict_json
from native_owner_score_bridge import (
    check_census, check_confirmation, compare, fields, hx, uint, work,
)

MAGIC = b"PNOJ1\0\0\0"
DOMAIN = b"pon-native-owner-journal-frame-v1\0"
MAX_RECORDS = 4096
MAX_BYTES = 128 * 1024 * 1024
MAX_FRAME = 4 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
HEADER_BYTES = 318
PROOF_BYTES = 4 + 3 * 64 * 64 * 4 + 32
ORIGINS = (
    "initial_carry_in", "recorded_local_production", "external_input",
    "gap_or_recovery_discovery",
)


def _wire_hash(tag: bytes, *parts: bytes) -> str:
    encoded = b"TRNM-PON1\0" + len(tag).to_bytes(2, "little") + tag
    encoded += b"".join(len(part).to_bytes(4, "little") + part for part in parts)
    return hashlib.sha256(encoded).hexdigest()


def _sequence_root(tag: str, items: list[bytes]) -> str:
    leaves = [bytes.fromhex(_wire_hash((tag + "-leaf").encode(),
                                     index.to_bytes(8, "little"), data))
              for index, data in enumerate(items)]
    if not leaves:
        return _wire_hash((tag + "-empty").encode())
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves.append(leaves[-1])
        leaves = [bytes.fromhex(_wire_hash((tag + "-node").encode(), *leaves[i:i + 2]))
                  for i in range(0, len(leaves), 2)]
    return leaves[0].hex()


def _packet(data: bytes) -> dict:
    """Native wire/identity binding only; complete W1 is observed in Rust."""
    require(HEADER_BYTES + 2 + PROOF_BYTES <= len(data) <= 1_048_576, "J_PACKET_LENGTH")
    require(data[:6] == b"PNH1\x01\0", "J_PACKET_HEADER")
    fields_at = {"network": (6, 38), "parameters": (38, 70), "parent": (70, 102),
                 "target": (118, 150), "miner": (150, 182),
                 "transactions_root": (182, 214)}
    value = {key: data[start:end].hex() for key, (start, end) in fields_at.items()}
    value.update(height=int.from_bytes(data[102:110], "little"),
                 timestamp=int.from_bytes(data[110:118], "little"))
    count = int.from_bytes(data[318:320], "little")
    require(count <= 256, "J_PACKET_TRANSACTION_COUNT")
    position, transactions = 320, []
    for _ in range(count):
        require(position + 2 <= len(data), "J_PACKET_TRANSACTION_LENGTH")
        size = int.from_bytes(data[position:position + 2], "little")
        position += 2
        maximum = 8192 if data[position:position + 4] == b"QTX1" else 2048
        require(159 <= size <= maximum and position + size <= len(data), "J_PACKET_TRANSACTION_LENGTH")
        transactions.append(data[position:position + size])
        position += size
    require(len(data) - position == PROOF_BYTES, "J_PACKET_PROOF_LENGTH")
    proof = data[position:]
    value.update(id=_wire_hash(b"block", data[:HEADER_BYTES], proof[-32:]),
                 packet_sha256=hashlib.sha256(data).hexdigest(), packet_bytes=len(data),
                 proof_sha256=hashlib.sha256(proof).hexdigest(),
                 transaction_ids=[_wire_hash(b"tx-id", raw) for raw in transactions],
                 encoded_transactions=[raw.hex() for raw in transactions],
                 transactions_root_matches=(value["transactions_root"] == _sequence_root("transactions", transactions)))
    target = int(value["target"], 16)
    value["required_work_hex"] = None if target == 0 else f"{(1 << 256) // (target + 1):0128x}"
    return value


def read_frames(path: Path) -> list[dict]:
    require(path.is_file() and not path.is_symlink(), "J_JOURNAL_PATH")
    require(8 <= path.stat().st_size <= MAX_BYTES, "J_JOURNAL_LENGTH")
    with path.open("rb") as source:
        data = source.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, "J_JOURNAL_LENGTH")
    require(data[:8] == MAGIC, "J_MAGIC")
    records, position, previous = [], 8, "00" * 32
    while position < len(data):
        require(len(records) < MAX_RECORDS, "J_RECORD_LIMIT")
        require(position + 4 <= len(data), "J_TORN_TAIL")
        size = int.from_bytes(data[position:position + 4], "big")
        require(1 <= size <= MAX_FRAME, "J_FRAME_LENGTH")
        end = position + 4 + size + 32
        require(end <= len(data), "J_TORN_TAIL")
        raw = data[position + 4:position + 4 + size]
        digest = hashlib.sha256(DOMAIN + raw).hexdigest()
        require(data[end - 32:end].hex() == digest, "J_FRAME_HASH")
        frame = strict_json(raw.decode("utf-8"))
        fields(frame, {"sequence", "previous_hash", "payload"}, "J_FRAME_FIELDS")
        require(uint(frame["sequence"], "J_SEQUENCE") == len(records)
                and frame["previous_hash"] == previous, "J_CHAIN")
        require(type(frame["payload"]) is dict, "J_PAYLOAD")
        records.append({**frame, "record_hash": digest})
        previous, position = digest, end
    require(bool(records), "J_HEADER_MISSING")
    return records


def _references(value):
    if isinstance(value, dict):
        if value.get("artifact_kind") == "native-pnp1-packet":
            yield value
        for child in value.values():
            yield from _references(child)
    elif isinstance(value, list):
        for child in value:
            yield from _references(child)


def _intrinsic_rows(census):
    return {block: {key: value for key, value in row.items()
                    if key not in ("ancestry_time_eligible", "active_chain_member")}
            for block, row in census.rows.items()}


def _state(census):
    return (census.raw["active_tip"], census.raw["active_generation"],
            census.raw["state_slot"], _intrinsic_rows(census))


def read_journal(directory: Path, expected_checkpoint: dict | None = None) -> dict:
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink()
            and not (directory / "packets").is_symlink(), "J_DIRECTORY")
    records = read_frames(directory / "journal.pnoj1")
    header = records[0]["payload"]
    fields(header, {"kind", "schema", "journal_id", "store_path", "backend", "context", "scope",
                    "initial_resource_state_known", "initial_world_inventory_bound",
                    "fresh_resource_state_attested", "physical_clock_authenticated",
                    "history_before_first_open_known", "world_coverage_attested"}, "J_HEADER_FIELDS")
    require(header["kind"] == "header" and header["schema"] == "pon-native-owner-journal-v1", "J_HEADER")
    journal_id = hx(header["journal_id"], 32, "J_ID")
    require(header["backend"] in ("legacy-v2", "authenticated-v1"), "J_BACKEND")
    fields(header["context"], {"network", "parameters", "genesis"}, "J_CONTEXT_FIELDS")
    for name, digest in header["context"].items():
        hx(digest, 32, "J_CONTEXT_" + name)
    for name in ("initial_resource_state_known", "fresh_resource_state_attested",
                 "physical_clock_authenticated", "history_before_first_open_known", "world_coverage_attested"):
        require(header[name] is False, "J_ESCALATION:" + name)
    require(header["initial_world_inventory_bound"] is None, "J_INITIAL_STOCK_ERASURE")
    require(type(header["scope"]) is str and type(header["store_path"]) is str
            and Path(header["store_path"]).is_absolute(), "J_SCOPE")

    def check_pin(pin):
        fields(pin, {"journal_id", "sequence", "record_hash"}, "J_CHECKPOINT_FIELDS")
        index = uint(pin["sequence"], "J_CHECKPOINT_SEQUENCE")
        require(pin["journal_id"] == journal_id and index < len(records)
                and records[index]["record_hash"] == hx(pin["record_hash"], 32, "J_CHECKPOINT_HASH"),
                "J_CHECKPOINT_MISMATCH")

    if expected_checkpoint is not None:
        check_pin(expected_checkpoint)
    packets, raw_artifacts, total_artifact_bytes = {}, {}, 0
    for record in records:
        for artifact in _references(record["payload"]):
            fields(artifact, {"artifact_kind", "sha256", "bytes", "id", "path"}, "J_ARTIFACT_FIELDS")
            digest = hx(artifact["sha256"], 32, "J_ARTIFACT_SHA")
            size = uint(artifact["bytes"], "J_ARTIFACT_LENGTH", 1_048_576)
            require(artifact["path"] == f"packets/{digest}.pnp1", "J_ARTIFACT_PATH")
            block = hx(artifact["id"], 32, "J_ARTIFACT_ID")
            if digest not in packets:
                path = directory / artifact["path"]
                require(path.is_file() and not path.is_symlink() and path.stat().st_size == size
                        and path.resolve().parent == directory.resolve() / "packets", "J_ARTIFACT_FILE")
                with path.open("rb") as source:
                    data = source.read(size + 1)
                require(len(data) == size, "J_ARTIFACT_LENGTH")
                require(hashlib.sha256(data).hexdigest() == digest, "J_ARTIFACT_HASH")
                packets[digest] = _packet(data)
                total_artifact_bytes += size
                require(total_artifact_bytes <= MAX_ARTIFACT_BYTES, "J_ARTIFACT_BUDGET")
                raw_artifacts[digest] = {"block_id": block, "bytes": size,
                    "first_raw_sequence": record["sequence"], "first_raw_kind": record["payload"]["kind"],
                    "first_raw_epoch": record["payload"].get("epoch"),
                    "first_raw_operation": record["payload"].get("operation"),
                    "native_effective_validity_established_by_raw_identity": False}
            require(packets[digest]["id"] == block and packets[digest]["packet_bytes"] == size,
                    "J_ARTIFACT_NATIVE_ID")
    unreferenced_artifacts = []
    for index, path in enumerate((directory / "packets").iterdir()):
        require(index < MAX_RECORDS and path.is_file() and not path.is_symlink(), "J_ARTIFACT_DIRECTORY")
        require(path.name.endswith(".pnp1"), "J_ARTIFACT_FILENAME")
        digest = hx(path.name[:-5], 32, "J_ARTIFACT_FILENAME")
        if digest in packets:
            continue
        size = path.stat().st_size
        require(1 <= size <= 1_048_576, "J_ARTIFACT_LENGTH")
        total_artifact_bytes += size
        require(total_artifact_bytes <= MAX_ARTIFACT_BYTES, "J_ARTIFACT_BUDGET")
        with path.open("rb") as source:
            data = source.read(size + 1)
        require(len(data) == size and hashlib.sha256(data).hexdigest() == digest, "J_ARTIFACT_HASH")
        packets[digest] = _packet(data)
        raw_artifacts[digest] = {"block_id": packets[digest]["id"], "bytes": size,
            "first_raw_sequence": None, "first_raw_kind": "unreferenced_file_at_reader",
            "first_raw_epoch": None, "first_raw_operation": None,
            "native_effective_validity_established_by_raw_identity": False}
        unreferenced_artifacts.append({"sha256": digest, "block_id": packets[digest]["id"],
            "bytes": size, "effective_weight_credited": False, "origin_and_first_ready_unknown": True})

    pending, registry, valid_packet_bindings, raw_sources = {}, {}, {}, {}
    epochs, active_epoch, current_intent, last_census, last_clock = 0, None, None, None, None
    outside, regressions, confirmations, rollback_witnesses, failures, orphan_observations = [], [], [], [], [], []
    owner_scopes, epoch_processes, elapsed, reported_failures, stopped_epochs = {}, {}, {}, set(), set()
    completed = 0

    def clock(sequence, epoch, now):
        nonlocal last_clock
        uint(now, "J_VALIDATION_CLOCK")
        if last_clock is not None and now < last_clock:
            regressions.append({"sequence": sequence, "epoch": epoch,
                "previous_validation_now": last_clock, "validation_now": now})
        last_clock = now

    def instant(payload, epoch):
        now = uint(payload["elapsed_ns"], "J_INSTANT")
        require(now >= elapsed.get(epoch, 0), "J_INSTANT_REWIND")
        elapsed[epoch] = now

    def see(row, origin, sequence, epoch, checked):
        block, digest, weight = row["id"], row["packet_sha256"], row["required_work_hex"]
        require(origin in ORIGINS and work(weight) > 0, "J_REGISTRY_WEIGHT")
        source = raw_sources.setdefault(digest, {"origin_class": origin, "first_sequence": sequence, "first_epoch": epoch})
        if block in registry:
            old = registry[block]
            require(old["required_work_hex"] == weight and old["packet_sha256"] == digest, "J_BLOCK_SUBSTITUTION")
            old["native_relation_rechecked_by_census"] |= checked
        else:
            registry[block] = {"origin_class": source["origin_class"], "first_seen_sequence": source["first_sequence"],
                "first_seen_epoch": source["first_epoch"], "required_work_hex": weight, "packet_sha256": digest,
                "native_relation_rechecked_by_census": checked}

    def census(value, artifact_list, origin, sequence, epoch):
        checked = check_census(value)
        require(all(value[key] == digest for key, digest in header["context"].items())
                and value["state_backend"] == header["backend"], "J_CENSUS_CONTEXT")
        require(value["owner_process_id"] == epoch_processes[epoch], "J_OWNER_PROCESS_BINDING")
        require(type(artifact_list) is list, "J_CENSUS_ARTIFACTS")
        listed = [artifact["sha256"] for artifact in artifact_list]
        required = [row["packet_sha256"] for row in checked.rows.values() if row["parent"] is not None]
        require(len(listed) == len(set(listed)) and set(listed) == set(required), "J_CENSUS_ARTIFACT_COVERAGE")
        scope = tuple(value[key] for key in ("owner_process_id", "owner_observation_instance", "directory_device",
                     "directory_inode", "database_device", "database_inode", "lock_device", "lock_inode"))
        if epoch in owner_scopes:
            old_scope, attempt, ended = owner_scopes[epoch]
            require(scope == old_scope and value["owner_attempt"] > attempt and value["started_ns"] >= ended,
                    "J_OWNER_EPOCH_ORDER")
        owner_scopes[epoch] = scope, value["owner_attempt"], value["ended_ns"]
        for row in checked.rows.values():
            if row["parent"] is None:
                continue
            digest = row["packet_sha256"]
            require(digest in packets, "J_CENSUS_PACKET_MISSING")
            packet = packets[digest]
            require(all(packet[key] == row[key] for key in ("id", "parent", "height", "timestamp", "target",
                        "packet_bytes", "packet_sha256", "proof_sha256", "required_work_hex"))
                    and packet["network"] == value["network"] and packet["parameters"] == value["parameters"]
                    and packet["transactions_root_matches"], "J_CENSUS_PACKET_BINDING")
            see(row, origin, sequence, epoch, True)
            old = valid_packet_bindings.setdefault(digest, {"block_id": row["id"],
                "required_work_hex": row["required_work_hex"], "first_census_sequence": sequence,
                "first_census_epoch": epoch, "native_census_claims_complete_relation_replay": True,
                "python_replays_full_work_relation": False, "execution_independently_attested": False})
            require(old["block_id"] == row["id"] and old["required_work_hex"] == row["required_work_hex"],
                    "J_VALID_PACKET_SUBSTITUTION")
        return checked

    def observe_failures(checked, sequence, epoch, event_kind):
        for reference in confirmations:
            if not reference["checked"]["confirmed"] or reference["sequence"] in reported_failures:
                continue
            block = reference["observation"]["included_block"]
            if block in checked.paths[checked.raw["active_tip"]]:
                continue
            reported_failures.add(reference["sequence"])
            result = None
            if checked.raw["active_time_eligible"] and reference["checked"]["six_successor_profile"]:
                result = compare(reference["census"], checked, reference["observation"])
            failures.append({"confirmation_sequence": reference["sequence"], "first_observed_failure_sequence": sequence,
                "epoch": epoch, "event_kind": event_kind, "block": block,
                "eligible_local_deficit_witness": result, "unresolved_intents_at_observation": sorted(pending),
                "global_time_or_delay_bound": None, "failure_probability": None})

    for record in records[1:]:
        p, sequence = record["payload"], record["sequence"]
        kind, epoch = p.get("kind"), uint(p.get("epoch"), "J_EPOCH")
        if kind == "open_intent":
            fields(p, {"kind", "epoch", "process_id", "observed_now", "prior_unresolved_intents",
                       "expected_checkpoint", "clock_scope", "orphan_artifacts_at_open"}, "J_OPEN_INTENT_FIELDS")
            require(epoch == epochs + 1 and p["prior_unresolved_intents"] == sorted(pending), "J_GAP_ERASURE")
            epoch_processes[epoch] = uint(p["process_id"], "J_PROCESS_ID")
            require(type(p["clock_scope"]) is str and p["clock_scope"], "J_CLOCK_SCOPE")
            require(type(p["orphan_artifacts_at_open"]) is list, "J_ORPHAN_LIST")
            orphan_hashes = [item["sha256"] for item in p["orphan_artifacts_at_open"]]
            require(orphan_hashes == sorted(set(orphan_hashes)), "J_ORPHAN_ORDER")
            for artifact in p["orphan_artifacts_at_open"]:
                require(raw_artifacts[artifact["sha256"]]["first_raw_sequence"] == sequence, "J_ORPHAN_PREVIOUSLY_REFERENCED")
                raw_sources.setdefault(artifact["sha256"], {"origin_class": "gap_or_recovery_discovery",
                    "first_sequence": sequence, "first_epoch": epoch})
                orphan_observations.append({"open_intent_sequence": sequence, "epoch": epoch,
                    "sha256": artifact["sha256"], "block_id": artifact["id"], "bytes": artifact["bytes"],
                    "effective_weight_credited_by_orphan_observation": False,
                    "origin_and_first_ready_unknown": True})
            if p["expected_checkpoint"] is not None:
                check_pin(p["expected_checkpoint"])
                require(p["expected_checkpoint"]["sequence"] < sequence, "J_FUTURE_PIN")
            if epochs:
                outside.append({"from_epoch": epochs, "to_epoch": epoch, "open_intent_sequence": sequence,
                    "prior_lease_closed": active_epoch is None and current_intent is None,
                    "physical_elapsed_bound": None, "unobserved_operation_bound": None})
            clock(sequence, epoch, p["observed_now"])
            epochs, active_epoch, current_intent = epoch, None, sequence
            elapsed[epoch] = 0
            pending[sequence] = {"epoch": epoch, "operation": "open", "observed_now": p["observed_now"],
                                 "before": None, "input": None}
        elif kind == "open_observed":
            fields(p, {"kind", "epoch", "intent_sequence", "elapsed_ns", "observed_now", "census", "artifacts"},
                   "J_OPEN_OBSERVED_FIELDS")
            intent = uint(p["intent_sequence"], "J_INTENT")
            require(current_intent == intent and intent in pending and epoch == epochs
                    and pending[intent]["operation"] == "open" and pending[intent]["epoch"] == epoch,
                    "J_OPEN_WITHOUT_INTENT")
            require(p["observed_now"] == pending[intent]["observed_now"] == p["census"]["observed_now"], "J_CLOCK_BINDING")
            instant(p, epoch)
            last_census = census(p["census"], p["artifacts"], "initial_carry_in" if epoch == 1
                                 else "gap_or_recovery_discovery", sequence, epoch)
            del pending[intent]
            active_epoch, current_intent = epoch, None
            observe_failures(last_census, sequence, epoch, kind)
        elif kind == "intent":
            fields(p, {"kind", "epoch", "operation", "observed_now", "elapsed_ns", "input"}, "J_INTENT_FIELDS")
            require(active_epoch == epoch and current_intent is None, "J_CONCURRENT_OR_OUTSIDE_CALL")
            require(epoch not in stopped_epochs, "J_NATIVE_STOP_REQUIRED")
            require(p["operation"] in ("make", "admit", "activate_observed", "confirmation", "census"), "J_OPERATION")
            operation, request = p["operation"], p["input"]
            if operation == "admit":
                fields(request, {"id", "artifact"}, "J_ADMIT_INPUT")
                require(request["id"] == request["artifact"]["id"], "J_ADMIT_INPUT_ID")
                raw_sources.setdefault(request["artifact"]["sha256"], {"origin_class": "external_input",
                    "first_sequence": sequence, "first_epoch": epoch})
            elif operation == "activate_observed":
                fields(request, {"target"}, "J_ACTIVATE_INPUT")
                hx(request["target"], 32, "J_ACTIVATE_TARGET")
            elif operation == "confirmation":
                fields(request, {"transaction", "included"}, "J_CONFIRM_INPUT")
                hx(request["transaction"], 32, "J_TRANSACTION")
                hx(request["included"], 32, "J_INCLUDED")
            elif operation == "make":
                fields(request, {"parent", "transactions", "miner", "timestamp", "max_attempts"}, "J_MAKE_INPUT")
                hx(request["parent"], 32, "J_MAKE_PARENT")
                hx(request["miner"], 32, "J_MAKE_MINER")
                uint(request["timestamp"], "J_MAKE_TIMESTAMP")
                uint(request["max_attempts"], "J_MAKE_ATTEMPTS")
                require(type(request["transactions"]) is list, "J_MAKE_TRANSACTIONS")
                for raw in request["transactions"]:
                    require(type(raw) is str and len(raw) % 2 == 0
                            and bytes.fromhex(raw).hex() == raw, "J_MAKE_TRANSACTION_ENCODING")
            else:
                require(request is None, "J_CENSUS_INPUT")
            clock(sequence, epoch, p["observed_now"])
            instant(p, epoch)
            pending[sequence] = {"epoch": epoch, "operation": p["operation"], "observed_now": p["observed_now"],
                                 "before": None, "input": p["input"]}
            current_intent = sequence
        elif kind == "prepared":
            fields(p, {"kind", "epoch", "intent_sequence", "elapsed_ns", "census", "artifacts"}, "J_PREPARED_FIELDS")
            intent = uint(p["intent_sequence"], "J_INTENT")
            require(current_intent == intent and active_epoch == epoch and intent in pending
                    and pending[intent]["epoch"] == epoch and pending[intent]["before"] is None,
                    "J_PREPARED_WITHOUT_INTENT")
            require(p["census"]["observed_now"] == pending[intent]["observed_now"], "J_CLOCK_BINDING")
            instant(p, epoch)
            before = census(p["census"], p["artifacts"], "gap_or_recovery_discovery", sequence, epoch)
            require(last_census is not None and _state(last_census) == _state(before), "J_UNOBSERVED_IN_LEASE_CHANGE")
            pending[intent]["before"] = before
            last_census = before
        elif kind == "terminal":
            fields(p, {"kind", "epoch", "intent_sequence", "operation", "elapsed_ns", "result", "census", "artifacts"},
                   "J_TERMINAL_FIELDS")
            intent = uint(p["intent_sequence"], "J_INTENT")
            require(current_intent == intent and active_epoch == epoch and intent in pending, "J_TERMINAL_WITHOUT_INTENT")
            call = pending[intent]
            require(call["epoch"] == epoch and call["before"] is not None and call["operation"] == p["operation"],
                    "J_TERMINAL_OPERATION")
            require(call["observed_now"] == p["census"]["observed_now"], "J_CLOCK_BINDING")
            instant(p, epoch)
            before, result = call["before"], p["result"]
            require(type(result) is dict and type(result.get("ok")) is bool, "J_RESULT")
            fields(result, {"ok", "value"} if result["ok"] else
                   {"ok", "error", "error_kind", "requires_owner_stop"}, "J_RESULT_FIELDS")
            if not result["ok"]:
                require(type(result["error"]) is str and type(result["error_kind"]) is str
                        and type(result["requires_owner_stop"]) is bool, "J_NATIVE_ERROR")
                if result["requires_owner_stop"]:
                    stopped_epochs.add(epoch)
            elif p["operation"] == "make":
                item = result["value"]
                fields(item, {"id", "parent", "height", "target", "timestamp", "required_work_hex",
                              "packet_sha256", "proof_sha256", "packet_bytes", "artifact"}, "J_MAKE_RESULT")
                packet = packets.get(item["packet_sha256"])
                require(packet is not None and all(item[key] == packet[key] for key in item if key != "artifact"),
                        "J_PRODUCED_PACKET_BINDING")
                require(item["artifact"]["sha256"] == item["packet_sha256"]
                        and item["artifact"]["id"] == item["id"]
                        and item["artifact"]["bytes"] == item["packet_bytes"], "J_PRODUCED_ARTIFACT_BINDING")
                request = call["input"]
                fields(request, {"parent", "transactions", "miner", "timestamp", "max_attempts"}, "J_MAKE_INPUT")
                require(request["parent"] in before.rows and packet["height"] == before.rows[request["parent"]]["height"] + 1
                        and packet["parent"] == request["parent"] and packet["timestamp"] == request["timestamp"]
                        and packet["miner"] == request["miner"] and packet["encoded_transactions"] == request["transactions"]
                        and packet["transactions_root_matches"], "J_NATIVE_MAKE_INPUT_BINDING")
                see(item, "recorded_local_production", sequence, epoch, False)
            elif p["operation"] == "census":
                extra = check_census(result["value"])
                scope = owner_scopes[epoch]
                extra_scope = tuple(extra.raw[key] for key in ("owner_process_id", "owner_observation_instance",
                    "directory_device", "directory_inode", "database_device", "database_inode", "lock_device", "lock_inode"))
                require(extra_scope == scope[0] and all(extra.raw[key] == value for key, value in header["context"].items())
                        and extra.raw["state_backend"] == header["backend"]
                        and extra.raw["observed_now"] == call["observed_now"]
                        and extra.raw["owner_attempt"] > scope[1] and extra.raw["started_ns"] >= scope[2]
                        and _state(extra) == _state(before), "J_CENSUS_CALL_RESULT")
                owner_scopes[epoch] = scope[0], extra.raw["owner_attempt"], extra.raw["ended_ns"]
            after = census(p["census"], p["artifacts"], "external_input" if p["operation"] == "admit"
                           else "gap_or_recovery_discovery", sequence, epoch)
            old_rows, new_rows = _intrinsic_rows(before), _intrinsic_rows(after)
            require(all(new_rows.get(block) == row for block, row in old_rows.items()), "J_RETAINED_ROW_REWRITE")
            operation = p["operation"]
            if operation == "admit" and result["ok"]:
                fields(call["input"], {"id", "artifact"}, "J_ADMIT_INPUT")
                fields(result["value"], {"id"}, "J_ADMIT_RESULT")
                block = call["input"]["id"]
                require(result["value"]["id"] == block and block in after.rows
                        and after.rows[block]["packet_sha256"] == call["input"]["artifact"]["sha256"]
                        and set(new_rows) - set(old_rows) <= {block}, "J_ADMISSION_BINDING")
                require(before.raw["active_tip"] == after.raw["active_tip"]
                        and before.raw["active_generation"] == after.raw["active_generation"]
                        and before.raw["state_slot"] == after.raw["state_slot"], "J_ADMIT_SELECTION_CHANGE")
            elif operation == "activate_observed" and result["ok"]:
                fields(call["input"], {"target"}, "J_ACTIVATE_INPUT")
                fields(result["value"], {"selected"}, "J_ACTIVATE_RESULT")
                target, old = call["input"]["target"], before.raw["active_tip"]
                require(target in before.eligible and old_rows == new_rows, "J_ACTIVATE_CANDIDATE")
                selected = target if before.scores[target] > before.scores[old] else old
                require(result["value"]["selected"] == after.raw["active_tip"] == selected
                        and after.raw["active_generation"] == before.raw["active_generation"] + int(selected != old),
                        "J_NATIVE_STRICT_SELECTION")
                left, right = before.paths[old], after.paths[selected]
                length = 0
                while length < min(len(left), len(right)) and left[length] == right[length]:
                    length += 1
                if length < len(left):
                    ancestor = left[length - 1]
                    suffix = right[length:]
                    partition = {origin: 0 for origin in ORIGINS}
                    for block in suffix:
                        require(block in registry and registry[block]["native_relation_rechecked_by_census"],
                                "J_UNREGISTERED_COMPETING_BLOCK")
                        partition[registry[block]["origin_class"]] += work(registry[block]["required_work_hex"])
                    competing_weight = after.scores[selected] - after.scores[ancestor]
                    incumbent_weight = before.scores[old] - before.scores[ancestor]
                    require(sum(partition.values()) == competing_weight > incumbent_weight, "J_STRICT_FORK_PARTITION")
                    rollback_witnesses.append({"terminal_sequence": sequence, "intent_sequence": intent, "epoch": epoch,
                        "old_tip": old, "new_tip": selected, "lca": ancestor, "removed_suffix": list(left[length:]),
                        "competing_suffix": list(suffix), "incumbent_suffix_weight": incumbent_weight,
                        "competing_suffix_weight": competing_weight, "origin_partition": partition,
                        "native_block_ids_counted_once": True, "origin_partition_is_global_ready_partition": False,
                        "global_adversarial_weight_lower_bound": None, "failure_probability": None})
            else:
                require(_state(before) == _state(after), "J_UNEXPECTED_NATIVE_STATE_CHANGE")
            if operation == "confirmation" and result["ok"]:
                fields(call["input"], {"transaction", "included"}, "J_CONFIRM_INPUT")
                observation = result["value"]
                require(observation["transaction"] == call["input"]["transaction"]
                        and observation["included_block"] == call["input"]["included"], "J_CONFIRM_QUERY_BINDING")
                checked = check_confirmation(observation, after)
                row = after.rows[observation["included_block"]]
                require(observation["transaction"] in packets[row["packet_sha256"]]["transaction_ids"],
                        "J_CONFIRM_TRANSACTION_MEMBERSHIP")
                checked["membership_rechecked_by_reader"] = True
                confirmations.append({"sequence": sequence, "epoch": epoch, "observation": observation,
                                      "checked": checked, "census": after})
            del pending[intent]
            current_intent, last_census = None, after
            completed += 1
            observe_failures(after, sequence, epoch, kind)
        elif kind == "lease_end":
            fields(p, {"kind", "epoch", "observed_now", "elapsed_ns", "census", "artifacts",
                       "coverage_ends_before_native_owner_drop"}, "J_LEASE_END_FIELDS")
            require(active_epoch == epoch and current_intent is None
                    and p["coverage_ends_before_native_owner_drop"] is True, "J_LEASE_END")
            require(epoch not in stopped_epochs, "J_NATIVE_STOP_REQUIRED")
            require(p["observed_now"] == p["census"]["observed_now"], "J_CLOCK_BINDING")
            clock(sequence, epoch, p["observed_now"])
            instant(p, epoch)
            after = census(p["census"], p["artifacts"], "gap_or_recovery_discovery", sequence, epoch)
            require(last_census is not None and _state(last_census) == _state(after), "J_LEASE_END_STATE_CHANGE")
            last_census, active_epoch = after, None
        else:
            raise CertificateError("J_RECORD_KIND")

    checkpoint = {"journal_id": journal_id, "sequence": records[-1]["sequence"],
                  "record_hash": records[-1]["record_hash"]}
    unresolved = [{"intent_sequence": sequence, "epoch": item["epoch"], "operation": item["operation"],
                   "input": item["input"], "prepared": item["before"] is not None}
                  for sequence, item in sorted(pending.items())]
    return {"schema": "pon-native-owner-journal-check-v1", "checkpoint": checkpoint,
        "records_checked": len(records), "artifacts_checked": len(packets), "artifact_bytes_checked": total_artifact_bytes,
        "supplied_checkpoint_matches": None if expected_checkpoint is None else True,
        "epochs": epochs, "active_epoch": active_epoch, "recorded_calls_completed": completed,
        "native_stop_required_epochs": sorted(stopped_epochs),
        "unresolved_intents": unresolved, "all_recorded_intents_have_terminal_observations": not pending,
        "outside_lease_intervals": outside, "clock_regressions": regressions, "registry": registry,
        "raw_artifacts": raw_artifacts, "valid_packet_bindings": valid_packet_bindings,
        "raw_artifact_sources": raw_sources,
        "orphan_artifact_observations": orphan_observations, "unreferenced_artifacts": unreferenced_artifacts,
        "confirmations": [{key: value for key, value in item.items() if key != "census"} for item in confirmations],
        "rollback_witnesses": rollback_witnesses, "confirmation_failures": failures,
        "last_census": None if last_census is None else last_census.raw,
        "initial_resource_state_known": False, "initial_world_inventory_bound": None,
        "fresh_resource_state_attested": False, "native_runtime_attested": False,
        "trusted_history_anchor": False, "physical_clock_authenticated": False,
        "world_coverage_attested": False, "all_ever_native_api_calls_covered": False,
        "probabilistic_environment_bound": False, "six_successor_risk_qualified": False,
        "probability_bound": None}


def read_run_journals(path: Path) -> dict:
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 32 * 1024 * 1024, "J_RUN_PATH")
    document = strict_json(path.read_text(encoding="utf-8"))
    require(type(document) is dict and document.get("schema") == "pon-native-owner-journal-run-v1"
            and document.get("native_execution_exercised") is True, "J_NATIVE_RUN_SCHEMA")
    for flag in ("native_runtime_attested", "trusted_history_anchor", "world_coverage_attested",
                 "fresh_resource_state_attested", "physical_clock_authenticated", "probabilistic_environment_bound",
                 "six_successor_risk_qualified"):
        require(document.get(flag) is False, "J_RUN_ESCALATION:" + flag)
    require(document.get("probability_bound") is None, "J_RUN_RISK")
    hx(document.get("starting_source_commit"), 20, "J_RUN_SOURCE_PIN")
    manifests = document.get("journals")
    require(type(manifests) is list and 1 <= len(manifests) <= 16, "J_RUN_JOURNAL_LIMIT")
    checked = {}
    for item in manifests:
        fields(item, {"name", "path", "checkpoint"}, "J_RUN_MANIFEST")
        name, relative = item["name"], Path(item["path"])
        require(type(name) is str and 0 < len(name) <= 64 and name not in checked
                and not relative.is_absolute() and len(relative.parts) == 1 and relative.name not in (".", ".."),
                "J_RUN_DIRECTORY")
        directory = path.parent / relative
        require(directory.resolve().parent == path.parent.resolve(), "J_RUN_PATH_ESCAPE")
        checked[name] = read_journal(directory, item["checkpoint"])
    return {"schema": "pon-native-owner-journal-run-check-v1", "run_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "starting_source_commit": document["starting_source_commit"], "journal_count": len(checked), "journals": checked,
        "record_count": sum(item["records_checked"] for item in checked.values()),
        "native_execution_independently_attested": False, "world_coverage_attested": False,
        "fresh_resource_state_attested": False, "physical_clock_authenticated": False,
        "six_successor_risk_qualified": False, "probability_bound": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?")
    parser.add_argument("--run", type=Path)
    parser.add_argument("--expected-checkpoint", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        require((args.directory is None) != (args.run is None), "J_CLI_INPUT")
        pin = None if args.expected_checkpoint is None else strict_json(args.expected_checkpoint.read_text())
        if args.run is not None:
            require(pin is None, "J_RUN_PIN_IS_IN_MANIFEST")
            result = read_run_journals(args.run)
        else:
            result = read_journal(args.directory, pin)
    except (CertificateError, OSError, UnicodeError, ValueError) as error:
        result = {"schema": "pon-native-owner-journal-refusal-v1", "accepted": False, "error": str(error),
                  "six_successor_risk_qualified": False, "probability_bound": None}
        print(json.dumps(result, sort_keys=True))
        raise SystemExit(1) from error
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8") as output:
            output.write(encoded)
    else:
        print(encoded, end="")


if __name__ == "__main__":
    main()
