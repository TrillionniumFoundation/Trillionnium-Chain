#!/usr/bin/env python3
"""Read pinned original ZIPs; never invoke Rust, a native binary, or upstream readers.

This is a measurement audit, not a new execution or a verification of native
cryptography. All arithmetic is exact integer arithmetic. Null measurements stay
null. Source/ZIP/binary identities, full planned denominators, and time epochs are
retained. Shared raw phases are recorded once, then referenced by papers 02/06.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

HERE = Path(__file__).resolve().parent
M14 = "ac8501a85a770ba34f34e1bed507ca747e5c3f8d"
NEW = "81f00ca62d9ce53483d56d2f2ec12fb871a0b3ae"
ARCHIVES = {
    "m14_campaign": ("chain-m14-native-campaign.zip", 81456978, "7996763ffc628f025f2d8e47bf3a6f184805a4b5b24dd13b273ee508903b1f78", M14),
    "m14_protocol": ("chain-m14-protocol.zip", 6362296, "d9579ae0a3bda17909d7f102103c329919bc9d6deee63018a3de9d7f807da404", M14),
    "m14_fresh": ("chain-m14-fresh.zip", 6048083, "29ad680f3f8a39143669524296cb2d4065f1086bc0cd0ed8ff455ad9ec49c4d4", M14),
    "m14_f0": ("chain-m14-f0.zip", 16812128, "8185871bcc22c9c3d67a99620ccafc9b5457fab24a4924c629ac5d5ddba2e238", M14),
    "pr856_campaign": ("chain-81f-native-campaign.zip", 83146334, "f004b1cf52aca7f84b2eb24c75d6a43fd5dd95a7c0ff86cbb97a31afd0c575d5", NEW),
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(value, label):
    if not value:
        raise ValueError(label)


def integer(value):
    return type(value) is int and value >= 0


def complete_sum(values):
    values = list(values)
    return sum(values) if all(integer(v) for v in values) else None


def wire_hash(tag: bytes, *parts: bytes):
    h = hashlib.sha256(b"TRNM-PON1\0" + len(tag).to_bytes(2, "little") + tag)
    for part in parts:
        h.update(len(part).to_bytes(4, "little") + part)
    return h.hexdigest()


def decode_packet_fields(encoded):
    """Only decode header/transaction lengths and identity; NOT a W1/signature verifier.

    Exact source: retained pon_wire.rs HEADER_BYTES/hash/Header.block_id and
    pon_node_lib.rs Packet::encode/decode/id. The final 32 proof bytes are trace.
    """
    raw = bytes.fromhex(encoded)
    require(len(raw) >= 352 and raw[:4] == b"PNH1", "PACKET_HEADER")
    header, offset = raw[:318], 320
    count = int.from_bytes(raw[318:320], "little")
    require(count <= 256, "PACKET_TRANSACTION_COUNT")
    transactions = []
    for _ in range(count):
        require(offset + 2 <= len(raw), "PACKET_TRANSACTION_LENGTH")
        length = int.from_bytes(raw[offset:offset+2], "little")
        offset += 2
        require(159 <= length <= 2048 and offset + length <= len(raw), "PACKET_TRANSACTION_BOUNDS")
        transactions.append(raw[offset:offset+length].hex())
        offset += length
    require(raw[offset:offset+4] == b"PNW1" and len(raw)-offset == 49188, "PACKET_PROOF_LAYOUT")
    return {"header": header.hex(), "id": wire_hash(b"block", header, raw[-32:]), "transactions": transactions}


def dump(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


class Archive:
    def __init__(self, key: str, path: Path):
        name, size, digest, commit = ARCHIVES[key]
        require(path.stat().st_size == size, f"{key}: ZIP_SIZE")
        h = hashlib.sha256()
        with path.open("rb") as f:
            while block := f.read(1048576):
                h.update(block)
        require(h.hexdigest() == digest, f"{key}: ZIP_DIGEST")
        self.z = ZipFile(path)
        names = self.z.namelist()
        require(len(names) == len(set(names)), f"{key}: DUPLICATE_MEMBER")
        require(all(not PurePosixPath(n).is_absolute() and ".." not in PurePosixPath(n).parts for n in names), f"{key}: UNSAFE_MEMBER")
        self.key, self.commit, self.reads = key, commit, {}
        self.identity = {"archive": name, "zip_bytes": size, "zip_sha256": digest,
                         "commit": commit, "member_count": len(names),
                         "uncompressed_bytes": sum(i.file_size for i in self.z.infolist()),
                         "duplicate_member_names": False, "unsafe_member_names": False,
                         "method": "ZIP member reads only; no path extraction or code execution"}

    def raw(self, member):
        data = self.z.read(member)  # zipfile validates this member's CRC.
        self.reads[member] = {"bytes": len(data), "sha256": sha(data)}
        return data

    def read(self, member):
        return json.loads(self.raw(member))

    def source(self, member):
        d = self.read(member)
        require(d["tested_commit"] == self.commit and d["tracked_worktree_verified"] is True, f"{self.key}: SOURCE")
        require(d["kind"] == "head" and d["prospective_merge"] is None, f"{self.key}: HEAD_SCOPE")
        return d

    def finish(self):
        self.identity["read_members"] = self.reads
        self.z.close()
        return self.identity


def interval_summary(rows, window, start_key="started_ns", end_key="ended_ns"):
    """Count fixed-clock spans; never apportion CPU using their wall-time ratio."""
    intervals = []
    unknown = 0
    for row in rows:
        a, b = row.get(start_key), row.get(end_key)
        if not integer(a) or not integer(b):
            unknown += 1
        else:
            require(a <= b, "REVERSED_INTERVAL")
            intervals.append((a, b))
    return {
        "records": len(rows), "known_intervals": len(intervals), "unknown_intervals": unknown,
        "started_before_window_end": sum(a < window for a, _ in intervals),
        "ended_inside_window": sum(b <= window for _, b in intervals),
        "crossed_window_end": sum(a < window < b for a, b in intervals),
        "started_at_or_after_window_end": sum(a >= window for a, _ in intervals),
        "last_ended_ns": max((b for _, b in intervals), default=None),
        "sum_known_wall_ns": sum(b-a for a, b in intervals),
        "sum_known_wall_outside_window_ns": sum(max(0, b-max(window, a)) for a, b in intervals),
        "cpu_inside_window_ns": None,
        "cpu_rule": "No exact in-window CPU attribution from start/end wall clocks alone",
    }


def is_native_confirmation(row, window):
    obs = row.get("observation")
    if not isinstance(obs, dict) or obs.get("confirmed") is not True:
        return False
    require(obs.get("transaction") == row.get("transaction"), "TRANSACTION_BINDING")
    require(obs.get("included_block") == row.get("included_block"), "BLOCK_BINDING")
    require(obs.get("policy") == "installed-depth-and-required-work", "CONFIRMATION_POLICY")
    require(obs.get("depth", -1) >= 6 and int(obs["work_delta"], 16) >= int(obs["required_work_delta"], 16), "DEPTH_WORK")
    require(obs.get("execution_authority") is False, "OBSERVATION_AUTHORITY")
    return integer(row.get("ended_ns")) and row["ended_ns"] <= window


def stage_audit(import_rows):
    """Keep aggregate Host, enclosing import, packet stages separate."""
    natives = [r.get("native_import_observation") for r in import_rows]
    valid = [n for n in natives if isinstance(n, dict)]
    checkpoints, packet_rows, stages = [], [], {}
    contained, bad_containment, unfinished = 0, 0, 0
    for n in valid:
        c = [c for c in n.get("host_checks", []) if c.get("phase") == "checkpoint"]
        checkpoints.append(c[0] if len(c) == 1 else {})
        require(n.get("cpu_intervals_are_nested_not_additive") is True, "IMPORT_NESTING_FLAG")
        for packet in n.get("packets", []):
            packet_rows.append(packet)
            by_name = {s["phase"]: s for s in packet["phases"]}
            require(len(by_name) == len(packet["phases"]), "DUPLICATE_PACKET_STAGE")
            for s in packet["phases"]:
                stages.setdefault(s["phase"], []).append(s)
                if s.get("started") and not s.get("completed"):
                    unfinished += 1
                p = by_name.get(s.get("parent_phase"))
                vals = [s.get("started_ns"), s.get("ended_ns"), (p or {}).get("started_ns"), (p or {}).get("ended_ns")]
                if p and all(integer(v) for v in vals):
                    child_a, child_b, parent_a, parent_b = vals
                    if parent_a <= child_a <= child_b <= parent_b:
                        contained += 1
                    else:
                        bad_containment += 1
    metrics = {}
    for name, rows in sorted(stages.items()):
        started = [s for s in rows if s.get("started")]
        metrics[name] = {"packet_slots": len(rows), "started": len(started),
                         "completed": sum(s.get("completed") is True for s in rows),
                         "wall_ns_all_packet_slots": complete_sum(s.get("wall_ns") for s in rows),
                         "thread_cpu_ns_all_packet_slots": complete_sum(s.get("thread_cpu_ns") for s in rows),
                         "wall_ns_started_slots": complete_sum(s.get("wall_ns") for s in started)}
    return {
        "import_records": len(import_rows), "native_import_records": len(valid),
        "native_import_measurement_failures": complete_sum(n.get("measurement_failures") for n in valid),
        "host_checkpoint_calls": complete_sum(c.get("calls_accepted") for c in checkpoints),
        "host_checkpoint_thread_cpu_ns": complete_sum(c.get("thread_cpu_ns") for c in checkpoints),
        "host_checkpoint_wall_ns": complete_sum(c.get("wall_ns") for c in checkpoints),
        "host_checkpoint_rejected": complete_sum(c.get("calls_rejected") for c in checkpoints),
        "host_checkpoint_unfinished": complete_sum(c.get("calls_unfinished") for c in checkpoints),
        "host_checkpoint_cpu_unknown": complete_sum(c.get("cpu_clock_unknown_calls") for c in checkpoints),
        "native_packets": len(packet_rows), "packet_stages": metrics,
        "explicit_parent_containment_checks": contained + bad_containment,
        "explicit_parent_containment_violations": bad_containment,
        "started_unfinished_packet_stages": unfinished,
        "nested_costs_added": False,
        "scoped_worker_cpu_reconstructed": False,
        "unmeasured_stages_zero_filled": False,
    }


def receiver_audit(obs):
    rows = obs["records"]
    ids = [r["connection_id"] for r in rows]
    require(len(ids) == len(set(ids)), "DUPLICATE_RECEIVER_RECORD")
    return {
        "records": len(rows), "accepted_connections_seen": obs["accepted_connections_seen"],
        "records_not_retained": obs["records_not_retained"], "counter_overflow": obs["counter_overflow"],
        "measurement_failures": obs["measurement_failures"],
        "record_observation_failures": sum(r.get("observation_failed") is True for r in rows),
        "full_work_started": sum(r.get("full_work_started") is True for r in rows),
        "full_work_accepted": sum(r.get("full_work_accepted") is True for r in rows),
        "dispatch_error_codes": dict(Counter(str(r.get("dispatch_error_code")) for r in rows if r.get("dispatch_error_code") is not None)),
        "cpu_intervals_nested_not_additive": obs["cpu_intervals_are_nested_not_additive"],
        "observer_clock_local": obs["monotonic_epoch_is_observer_local"],
        "cross_clock_cpu_join_performed": False,
    }


def native_phase(a, member, p, prep, run, mode_index, fixture):
    window = p["duration_seconds"] * 1_000_000_000
    require(window == 30_000_000_000 and len(prep["business"]) == 21, "ORIGINAL_NATIVE_INPUTS")
    business_tx = [(i, len(x["transactions"])) for i, x in enumerate(prep["business"]) if x["transactions"]]
    require(business_tx == [(0, 1), (7, 1), (14, 1)], "THREE_SIGNED_TRANSACTIONS")
    require(prep["actual_signed_seed_transfers"] == 1024, "SEED_DENOMINATOR")
    rounds = []
    for i in range(3):
        matches = [r for r in p["confirmations"] if r["round"] == i]
        require(len(matches) <= 1, "DUPLICATE_ROUND")
        r = matches[0] if matches else None
        scheduled = (1 + 4*i) * 1_000_000_000
        confirmed = bool(r and is_native_confirmation(r, window))
        if r:
            require(r["included_block"] == prep["business"][7*i]["id"], "PREPARED_BLOCK_BINDING")
            expected_tx = wire_hash(b"tx-id", bytes.fromhex(prep["business"][7*i]["transactions"][0]))
            require(r["transaction"] == expected_tx, "PREPARED_TRANSACTION_BINDING")
            require(confirmed == r["confirmed_inside_pressure_window"], "ORIGINAL_CONFIRM_FLAG")
        rounds.append({"round": i, "scheduled_ns": scheduled, "observed": r is not None,
                       "started_ns": r["started_ns"] if r else None, "ended_ns": r["ended_ns"] if r else None,
                       "confirmed_in_30s": confirmed,
                       "four_second_slo_from_schedule": bool(confirmed and r["ended_ns"] <= scheduled + 4_000_000_000),
                       "start_lateness_ns": max(0, r["started_ns"]-scheduled) if r else None,
                       "reported_observation_confirmed": (r.get("observation") or {}).get("confirmed") if r else None,
                       "confirmation_not_finality": True})
    require(len(p["confirmations"]) == sum(r["observed"] for r in rounds), "UNEXPECTED_ROUND")
    packets = []
    for i in range(21):
        calls = [x for x in p["submissions"] if x["packet_index"] == i]
        timely = [x for x in calls if x.get("status") == "ok" and integer(x.get("ended_ns")) and x["ended_ns"] <= window]
        packets.append({"packet_index": i, "signed_transactions": len(prep["business"][i]["transactions"]),
                        "attempts": len(calls), "ack_inside_window": bool(timely), "ack_is_not_confirmation": True})
    require(sum(x["attempts"] for x in packets) == len(p["submissions"]), "UNEXPECTED_PACKET")
    imports = [x["client_import"] for x in p["history"] if isinstance(x.get("client_import"), dict)]
    out = {
        "phase_id": f"{a.key}/run-{run}/{p['mode']}", "fixture": fixture,
        "archive_key": a.key, "report_member": member, "report_sha256": a.reads[member]["sha256"],
        "json_pointer": f"/phases/{mode_index}", "source_commit": a.commit, "run": run, "mode": p["mode"],
        "window_ns": window, "window_epoch": "original native phase epoch; no setup/drain credit",
        "seed_transfers_excluded_from_goodput": 1024, "planned_packets": 21, "planned_signed_transactions": 3,
        "planned_rounds": rounds, "planned_packet_records": packets,
        "rounds_observed": len(p["confirmations"]), "rounds_unstarted": sum(not r["observed"] for r in rounds),
        "confirmed_in_window": sum(r["confirmed_in_30s"] for r in rounds),
        "four_second_slo_successes": sum(r["four_second_slo_from_schedule"] for r in rounds),
        "successful_ack_packets": sum(r["ack_inside_window"] for r in packets),
        "packets_unattempted": sum(not r["attempts"] for r in packets),
        "submissions": interval_summary(p["submissions"], window),
        "history_network": interval_summary(p["history"], window),
        "history_import": interval_summary(imports, window),
        "history_import_calling_thread_cpu_ns": complete_sum(i.get("thread_cpu_ns") for i in imports),
        "history_rows_without_import": len(p["history"]) - len(imports),
        "history_import_failed": sum(i.get("succeeded") is False for i in imports),
        "history_import_errors": dict(Counter(str(i.get("error")) for i in imports if i.get("error") is not None)),
        "stage_audit": stage_audit(imports), "receiver": receiver_audit(p["receiver_observation"]),
        "original_finite_phase_criteria_met": p["finite_phase_criteria_met"],
        "original_all_signed_rounds_confirmed": p["all_signed_rounds_confirmed_in_window"],
        "original_depletion_observed": p["genuine_budget_depletion_observed"],
        "receiver_client_state_equal": p["receiver_client_state_equal"],
        "attacker_processes_requested": p["attacker_processes_requested"],
        "attacker_processes_ready": p["attacker_processes_ready"],
        "observed_attack_overlap_by_started_round": p["attack_calls_overlapping_each_signed_round"],
        "verifier_errors": p["verifier_errors"],
        "whole_parent_phase_cpu_ns": p["whole_parent_phase_cpu_ns"],
        "whole_parent_phase_wall_ns": p["whole_parent_phase_wall_ns"],
        "phase_parent_totals_are_not_exact_window_costs": True,
        "same_host_only": True, "stark_adapter_executed": False,
    }
    if "root_supplement" in p:
        q = p["root_supplement"]
        out["root_supplement"] = {k:q[k] for k in ["criteria_met", "cold_state_equal", "hostile_packets_absent_cold", "hostile_packets_absent_live", "whole_domain_paid_reconciled", "expected_legal_counts_and_tip", "aggregate_scoped_cpu_ns", "mutation_owner_cpu_ns"]}
        out["root_supplement"]["scope"] = q["scope"]
        out["root_supplement"]["acquisitions"] = len(q["acquisitions"])
    return out


def campaign(a):
    before, after = a.source("source-before.json"), a.source("source-after.json")
    require(before["tested_tree"] == after["tested_tree"], "SOURCE_TREE_CHANGED")
    meta = a.read("results.json")
    binary = meta["binary"]
    require(binary["sha256_before"] == binary["sha256_after"] == sha(a.raw(binary["retained"])), "BINARY_CHANGED")
    require(meta["planned_complete_runs"] == 3, "CAMPAIGN_RUN_DENOMINATOR")
    out = []
    for run in range(1, 4):
        member = f"run-{run}-raw/report.json"
        d = a.read(member)
        require(a.reads[member]["sha256"] == meta["attempts"][run-1]["report_sha256"], "RETAINED_REPORT")
        require([p["mode"] for p in d["phases"]] == ["baseline", "from-zero", "late-product"], "MODE_ORDER")
        for i, p in enumerate(d["phases"]):
            out.append(native_phase(a, member, p, d["preparation"], run, i, "original-3x3-native"))
    a.identity.update({"source_before": before, "source_after": after, "binary": binary,
                       "native_exit_codes": [x["step"]["returncode"] for x in meta["attempts"]],
                       "original_complete_success": meta["complete_success"], "phase_count": len(out),
                       "original_inputs": meta["original_inputs"]})
    return out


def pair_phase(a, member, p, phase_index, pair_name):
    window = p["requested_window_ns"]
    require(window == 4_000_000_000, "ORIGINAL_FOUR_SECOND_WINDOW")
    calls = [c for actor in p["attacks"] for c in actor["calls"]]
    start = p["business_started_ns"]
    overlap = [c for c in calls if c["started_ns"] < window and c["ended_ns"] > start]
    reported_end = p["confirmation_ended_ns"]
    conditioned = 0 if reported_end is None else sum(c["started_ns"] < reported_end and c["ended_ns"] > start for c in calls)
    require(conditioned == p["overlapping_false_calls"], "CONFIRMATION_CONDITIONED_OVERLAP")
    require(p["no_attack_accepted"] == all(c["status"] != "ok" for c in calls), "ATTACK_ACCEPTANCE")
    obs = p.get("independent_client_confirmation")
    confirmed = bool(obs and obs.get("confirmed") is True and integer(reported_end) and reported_end <= window)
    require(confirmed == p["client_confirmed_before_original_window_end"], "PAIR_CONFIRMATION_FLAG")
    require(int(confirmed) == p["client_confirmed_transactions"], "PAIR_DENOMINATOR")
    clock = p["business_receive_clock"]
    require(clock["clock_scope"] == "same-process-monotonic-observer", "PAIR_CLOCK_SCOPE")
    require(clock["independent_confirmation_in_observer_ns"] == (None if reported_end is None else reported_end + clock["traffic_epoch_in_observer_ns"]), "PAIR_CLOCK_MAPPING")
    replays = p["independent_history_page_replay"]
    imports = [{"native_import_observation": x["native_import_observation"]} for x in replays]
    return {
        "phase_id": f"{a.key}/{pair_name}/{p['mode']}", "fixture": "original-four-second-pair",
        "archive_key": a.key, "report_member": member, "report_sha256": a.reads[member]["sha256"],
        "json_pointer": f"/phases/{phase_index}", "source_commit": a.commit, "pair_name": pair_name,
        "mode": p["mode"], "window_ns": window, "window_epoch": "original traffic epoch, NOT business start plus four seconds",
        "business_started_ns": start, "planned_packets": 7, "planned_signed_transactions": 1,
        "confirmed_in_window": int(confirmed), "confirmation_ended_ns": reported_end,
        "confirmation_latency_ns": p["client_confirmation_latency_ns"], "confirmed_failure_is_not_zero_latency": True,
        "attack_workers": p["workers"], "attack_calls": interval_summary(calls, window),
        "attack_calls_overlapping_fixed_business_window": len(overlap),
        "reported_confirmation_conditioned_overlap_count": conditioned,
        "reported_overlap_demonstrated": p["overlap_demonstrated"],
        "confirmation_conditioned_overlap_censored": reported_end is None,
        "no_attack_accepted": p["no_attack_accepted"], "invariant_target_met": p["invariant_target_met"],
        "accounting_closed": p["accounting_closed"],
        "original_finite_business_target_met": p["finite_business_target_met"],
        "full_native_state_equal": p["full_native_state_equal"],
        "receiver_matches_valid_honest_prefix": p["receiver_matches_valid_honest_prefix"],
        "honest_head_successes_in_window": p["honest_head_successes_in_window"],
        "submissions": interval_summary(p["honest_submissions"], window),
        "history_network": interval_summary(p["honest_history"], window),
        "history_import": interval_summary(replays, window, "replay_started_ns", "replay_ended_ns"),
        "history_replay_failed": sum(x.get("replay_accepted") is False for x in replays),
        "receiver": receiver_audit(p["observations"]), "stage_audit": stage_audit(imports),
        "clock_mapping": clock, "verification_errors": p["verification_errors"],
        "resource_fairness_qualified": p["resource_fairness_qualified"],
        "same_host_only": True, "stark_adapter_executed": False,
    }


def pairs(a, fresh=False):
    prefix = "fresh-service" if fresh else "from-zero-native"
    manifest = a.read(prefix + "/manifest.json")
    source_before = manifest["source_before"]["tracked_source_identity"]
    source_after = manifest["source_after"]["tracked_source_identity"]
    for s in [source_before, source_after]:
        require(s["tested_commit"] == a.commit and s["tracked_worktree_verified"] is True, "PAIR_SOURCE")
    require(source_before["tested_tree"] == source_after["tested_tree"], "PAIR_SOURCE_TREE")
    actual_binary = sha(a.raw(prefix + "/public_v3_from_zero"))
    require(manifest["binary_sha256_before"] == manifest["binary_sha256_after"] == actual_binary, "PAIR_BINARY")
    reports = [("original", "original/report.json"), ("fresh", "fresh/report.json")] if fresh else [("confirmation", "confirmation/report.json")]
    out = []
    for label, name in reports:
        member = prefix + "/" + name
        d = a.read(member)
        same_packets = d.get("same_packet_sequence_in_both_runs", d.get("same_signed_business_packets"))
        require(same_packets is True and len(d["signed_honest_packets"]) == 7, "PAIR_PACKETS")
        decoded = [decode_packet_fields(x) for x in d["signed_honest_packets"]]
        require([len(x["transactions"]) for x in decoded] == [1, 0, 0, 0, 0, 0, 0], "PAIR_SIGNED_TRANSACTION_DENOMINATOR")
        expected_tx = wire_hash(b"tx-id", bytes.fromhex(decoded[0]["transactions"][0]))
        require(len(d["phases"]) == 2, "PAIR_PHASE_DENOMINATOR")
        require(len({p["initial_tip"] for p in d["phases"]}) == 1 and len({p["initial_state_root"] for p in d["phases"]}) == 1, "PAIR_INITIAL_STATE")
        for i, p in enumerate(d["phases"]):
            observation = p.get("independent_client_confirmation")
            if observation:
                require(observation["included_block"] == decoded[0]["id"] and observation["transaction"] == expected_tx, "PAIR_PREPARED_IDENTITY")
                require(observation["depth"] >= 6 and int(observation["work_delta"], 16) >= int(observation["required_work_delta"], 16), "PAIR_DEPTH_WORK")
            row = pair_phase(a, member, p, i, label)
            row["report_schema"] = d["schema"]
            row["fixture"] = "fresh-challenge-four-second-pair" if label == "fresh" else "original-four-second-pair"
            row["same_signed_packets_reported"] = same_packets
            row["prepared_transaction_id"] = expected_tx
            row["prepared_packet_ids"] = [x["id"] for x in decoded]
            row["initial_state_equal_across_pair"] = True
            row["construction_coverage"] = d.get("construction_coverage")
            out.append(row)
    a.identity.update({"source_before": source_before, "source_after": source_after,
                       "binary_sha256": actual_binary, "source_recompiled": manifest["source_recompiled"],
                       "manifest_passed": manifest["passed"], "manifest_failures": manifest["failures"],
                       "native_exit_codes": [x["process"]["exit_code"] for x in manifest["runs"]],
                       "terminal": manifest.get("terminal"), "phase_count": len(out)})
    if not fresh:
        member = "from-zero-native/format-copy-source/tests/public_v3_from_zero.rs"
        source = a.raw(member)
        dest = HERE / "sources" / "public_v3_from_zero.rs"
        dest.write_bytes(source)
        a.identity["retained_overlap_source"] = {"member": member, "sha256": sha(source)}
    return out


def f0(a):
    before, after = a.source("source-before.json"), a.source("source-after.json")
    require(before["tested_tree"] == after["tested_tree"], "F0_SOURCE_TREE_CHANGED")
    meta = a.read("execution/results.json")
    prepared = a.read("execution/predeclared.json")
    member = "execution/raw/report.json"
    d = a.read(member)
    require(meta["report_sha256"] == a.reads[member]["sha256"], "F0_REPORT_DIGEST")
    require(meta["inputs"]["round_start_seconds"] == [1, 5, 9], "F0_SCHEDULE")
    require(prepared["inputs"]["planned_confirmations"] == d["planned_confirmations"] == 6, "F0_PLANNED_CONFIRMATIONS")
    binary_matches = [n for n in a.z.namelist() if n.endswith("public_v3_multiprocess.bin")]
    require(len(binary_matches) == 1 and sha(a.raw(binary_matches[0])) == meta["binary"]["sha256"], "F0_BINARY")
    # F0 retains encoded packets, whereas the campaign retains decoded fields.
    prep = d["preparation"]
    business = [decode_packet_fields(x) for x in prep["business_packets"]]
    seed = [decode_packet_fields(x) for x in prep["seed_packets"]]
    decoded = {"business": business, "actual_signed_seed_transfers": sum(len(x["transactions"]) for x in seed)}
    out = [native_phase(a, member, p, decoded, 1, i, "fixed-root-f0") for i, p in enumerate(d["phases"])]
    reported = {(r["phase"], r["round"]):r for r in d["all_planned_rounds"]}
    for p in out:
        for r in p["planned_rounds"]:
            old = reported[p["mode"], r["round"]]
            require(old["four_second_slo_met"] == r["four_second_slo_from_schedule"], "F0_INDEPENDENT_SLO")
            require(old["confirmed_inside_original_window"] == r["confirmed_in_30s"], "F0_INDEPENDENT_30S")
    a.identity.update({"source_before": before, "source_after": after, "binary": meta["binary"],
                       "planned_confirmations": d["planned_confirmations"],
                       "planned_business_packet_exposures": d["planned_business_packet_exposures"],
                       "original_complete_success": meta["complete_success"],
                       "report_validation_failure": meta["report_validation_failure"],
                       "failure": meta["failure"], "phase_count": len(out)})
    return out


def compare_upstream(phases):
    upstream = json.loads((HERE / "sources" / "latest-host-summary.json").read_text())
    by_key = {(p["run"], p["mode"]):p for p in phases if p["archive_key"] == "pr856_campaign"}
    checks = []
    for row in upstream["observations"]:
        p = by_key[row["run"], row["phase"]]
        s = p["stage_audit"]
        actual = {"history_import_calls": s["import_records"],
                  "history_import_thread_cpu_ns": p["history_import_calling_thread_cpu_ns"],
                  "native_packets": s["native_packets"],
                  "admission_wall_ns": s["packet_stages"]["admission"]["wall_ns_all_packet_slots"],
                  "commit_wall_ns": s["packet_stages"]["commit"]["wall_ns_all_packet_slots"],
                  "raw_report_sha256": p["report_sha256"]}
        for name in ["host_checkpoint_calls", "host_checkpoint_thread_cpu_ns", "host_checkpoint_wall_ns", "host_checkpoint_rejected", "host_checkpoint_unfinished"]:
            actual[name] = s[name]
        matches = {k: actual[k] == row[k] for k in actual}
        require(all(matches.values()), f"UPSTREAM_COMPARISON_{row['run']}_{row['phase']}")
        checks.append({"phase_id":p["phase_id"], "fields_compared":matches})
    return {"summary_is_not_input_to_measurements": True, "comparison_rows": checks,
            "upstream_nominal_cpu_share_recomputed": False,
            "raw_report_identity_verified": True, "new_native_execution": False}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--m14-dir", type=Path, required=True)
    ap.add_argument("--latest-zip", type=Path, default=HERE / "inputs" / "chain-81f-native-campaign.zip")
    ap.add_argument("--output", type=Path, default=HERE / "results" / "20261110_01")
    args = ap.parse_args()
    phases, identities = [], []
    for key, (name, *_rest) in ARCHIVES.items():
        path = args.latest_zip if key == "pr856_campaign" else args.m14_dir / name
        a = Archive(key, path)
        if key.endswith("campaign"):
            phases.extend(campaign(a))
        elif key == "m14_f0":
            phases.extend(f0(a))
        else:
            phases.extend(pairs(a, key == "m14_fresh"))
        identities.append(a.finish())
    require(len(phases) == 26 and len({p["phase_id"] for p in phases}) == 26, "PHASE_DEDUP")
    comparison = compare_upstream(phases)
    summary = []
    for key in ARCHIVES:
        selected = [p for p in phases if p["archive_key"] == key]
        modes = list(dict.fromkeys(p["mode"] for p in selected))
        for mode in modes:
            group = [p for p in selected if p["mode"] == mode]
            summary.append({"archive_key": key, "mode": mode, "phase_count": len(group),
                            "planned_signed_transactions": sum(p["planned_signed_transactions"] for p in group),
                            "confirmed_in_window": sum(p["confirmed_in_window"] for p in group),
                            "window_ns": group[0]["window_ns"],
                            "unstarted_rounds": sum(p.get("rounds_unstarted", 0) for p in group),
                            "same_family_descriptive_aggregation_only": True})
    result = {"schema": "sp27-native-independent-readback-v1", "reader_sha256": sha(Path(__file__).read_bytes()),
              "native_code_executed_by_this_reader": False, "standalone_phase_duplicates_counted": False,
              "summary_rows": summary, "phases": phases, "upstream_comparison": comparison}
    dump(args.output / "archive_identity.json", {"archives": identities})
    dump(args.output / "native_readback.json", result)
    print(json.dumps({"status":"READBACK_PASS_ORIGINAL_GATES_UNCHANGED", "archives":len(identities), "phases":len(phases), "summary":summary}, indent=2))


if __name__ == "__main__":
    main()
