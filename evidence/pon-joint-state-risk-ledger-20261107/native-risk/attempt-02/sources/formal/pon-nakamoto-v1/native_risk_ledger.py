"""Independently read the entire PNRL1 bank and actual PNOJ1 native journal.

This is exact local registration/spending consistency, not a probability law,
physical order attestation or proof that a supplied checkpoint is the newest.
No serialized `verified` report or selected claim list substitutes for bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from native_execution_certificate import CertificateError, require, strict_json
from native_owner_journal import read_frames as read_native_frames, read_journal
from native_owner_score_bridge import fields, hx, uint

MAGIC = b"PNRL1\0\0\0"
DOMAIN = b"pon-native-risk-ledger-frame-v1\0"
MAX_RECORDS = 4096
MAX_BYTES = 16 * 1024 * 1024
MAX_FRAME = 64 * 1024
MAX_DENOMINATOR = 10**18


def _read_snapshot(path: Path) -> tuple[list[dict], str]:
    """Return parsed records and the digest of those exact same bounded bytes."""
    require(path.is_file() and not path.is_symlink(), "R_FILE")
    meta = path.stat()
    require(meta.st_nlink == 1 and 8 <= meta.st_size <= MAX_BYTES, "R_FILE_LENGTH")
    with path.open("rb") as source:
        data = source.read(MAX_BYTES + 1)
    require(len(data) == meta.st_size and data[:8] == MAGIC, "R_MAGIC_OR_LENGTH")
    records, previous, position = [], "00" * 32, 8
    while position < len(data):
        require(len(records) < MAX_RECORDS, "R_RECORD_LIMIT")
        require(position + 4 <= len(data), "R_TORN_TAIL")
        size = int.from_bytes(data[position:position + 4], "big")
        require(1 <= size <= MAX_FRAME, "R_FRAME_LENGTH")
        end = position + 4 + size + 32
        require(end <= len(data), "R_TORN_TAIL")
        raw = data[position + 4:position + 4 + size]
        digest = hashlib.sha256(DOMAIN + raw).hexdigest()
        require(data[end - 32:end].hex() == digest, "R_FRAME_HASH")
        frame = strict_json(raw.decode("utf-8"))
        fields(frame, {"sequence", "previous_hash", "payload"}, "R_FRAME_FIELDS")
        require(uint(frame["sequence"], "R_SEQUENCE") == len(records)
                and frame["previous_hash"] == previous and type(frame["payload"]) is dict, "R_CHAIN")
        records.append({**frame, "record_hash": digest})
        previous, position = digest, end
    require(bool(records), "R_EMPTY_BANK")
    return records, hashlib.sha256(data).hexdigest()


def read_frames(path: Path) -> list[dict]:
    return _read_snapshot(path)[0]


def _result(value):
    require(type(value) is dict and type(value.get("ok")) is bool, "R_RESULT")
    if value["ok"]:
        fields(value, {"ok", "value"}, "R_RESULT_FIELDS")
        require(type(value["value"]) is dict, "R_RESULT_VALUE")
    else:
        fields(value, {"ok", "error", "error_kind", "requires_owner_stop"}, "R_RESULT_FIELDS")
        require(type(value["error"]) is str and type(value["error_kind"]) is str
                and type(value["requires_owner_stop"]) is bool, "R_RESULT_ERROR")


def read_risk_ledger(directory: Path, native_directory: Path,
                     expected_checkpoint: dict | None = None,
                     expected_native_checkpoint: dict | None = None) -> dict:
    directory, native_directory = Path(directory), Path(native_directory)
    require(directory.is_dir() and not directory.is_symlink(), "R_DIRECTORY")
    path = directory / "risk.pnrl1"
    records, source_sha256 = _read_snapshot(path)
    native_frames = read_native_frames(native_directory / "journal.pnoj1")
    # Mandatory independent native reader checks raw packets, full census and
    # actual transaction membership, including successful unconfirmed results.
    native = read_journal(native_directory, expected_checkpoint=expected_native_checkpoint)
    native_id = native_frames[0]["payload"]["journal_id"]
    native_end = {"journal_id": native_id, "sequence": native_frames[-1]["sequence"],
                  "record_hash": native_frames[-1]["record_hash"]}
    require(native["checkpoint"] == native_end, "R_NATIVE_CHANGED_DURING_READ")
    header = records[0]["payload"]
    fields(header, {"kind", "schema", "bank_id", "native_journal_id", "native_journal_header_hash",
                    "native_journal_path", "native_anchor", "unit_denominator", "budget_units",
                    "law_scope_sha256", "actual_probability_law_authenticated",
                    "native_conditional_risk_certified", "global_failure_probability"}, "R_HEADER_FIELDS")
    require(header["kind"] == "header" and header["schema"] == "pon-native-risk-ledger-v1", "R_HEADER")
    bank_id = hx(header["bank_id"], 32, "R_BANK_ID")
    require(hx(header["native_journal_id"], 32, "R_NATIVE_ID") == native_id
            and hx(header["native_journal_header_hash"], 32, "R_NATIVE_HEADER_HASH")
            == native_frames[0]["record_hash"], "R_NATIVE_ID")
    require(type(header["native_journal_path"]) is str and Path(header["native_journal_path"]).is_absolute(),
            "R_NATIVE_ORIGIN_PATH")
    denominator = uint(header["unit_denominator"], "R_DENOMINATOR", MAX_DENOMINATOR)
    budget = uint(header["budget_units"], "R_BUDGET", denominator)
    require(denominator > 0 and budget > 0, "R_BUDGET")
    scope = hx(header["law_scope_sha256"], 32, "R_SCOPE")
    require(header["actual_probability_law_authenticated"] is False
            and header["native_conditional_risk_certified"] is False
            and header["global_failure_probability"] is None, "R_ESCALATION")

    def bank_pin(pin):
        fields(pin, {"bank_id", "sequence", "record_hash"}, "R_CHECKPOINT_FIELDS")
        index = uint(pin["sequence"], "R_CHECKPOINT_SEQUENCE")
        require(pin["bank_id"] == bank_id and index < len(records)
                and records[index]["record_hash"] == hx(pin["record_hash"], 32, "R_CHECKPOINT_HASH"),
                "R_CHECKPOINT_MISMATCH")

    def native_pin(pin):
        fields(pin, {"journal_id", "sequence", "record_hash"}, "R_NATIVE_CHECKPOINT_FIELDS")
        index = uint(pin["sequence"], "R_NATIVE_CHECKPOINT_SEQUENCE")
        require(pin["journal_id"] == native_id and index < len(native_frames)
                and native_frames[index]["record_hash"] == hx(pin["record_hash"], 32, "R_NATIVE_CHECKPOINT_HASH"),
                "R_NATIVE_CHECKPOINT_MISMATCH")
        return native_frames[index]["payload"]

    if expected_checkpoint is not None:
        bank_pin(expected_checkpoint)
    native_pin(header["native_anchor"])
    anchor_sequence = header["native_anchor"]["sequence"]
    prior_native = header["native_anchor"]
    epoch, native_epoch, active, current, spent = 0, 0, False, None, 0
    starts, outcomes, pending = {}, {}, set()
    covered_native, expected_intents, leases, cuts = set(), set(), [], []

    def advance(pin):
        nonlocal prior_native
        value = native_pin(pin)
        require(pin["sequence"] >= prior_native["sequence"]
                and (pin["sequence"] != prior_native["sequence"]
                     or pin["record_hash"] == prior_native["record_hash"]), "R_NATIVE_ORDER")
        prior_native = pin
        return value

    def call_binding(start, outcome=None):
        expected = start["expected_native_intent_sequence"]
        p = native_frames[expected]["payload"] if expected < len(native_frames) else None
        invoked = p is not None and p.get("kind") == "intent" and p.get("operation") == "confirmation"
        prepared, terminal = None, None
        if invoked:
            require(p["epoch"] == start["native_owner_epoch"] and p["observed_now"] == start["observed_now"]
                    and p["input"] == {"transaction": start["transaction"], "included": start["included"]},
                    "R_NATIVE_QUERY_BINDING")
            covered_native.add(expected)
            if expected + 1 < len(native_frames):
                candidate = native_frames[expected + 1]["payload"]
                if candidate.get("kind") == "prepared" and candidate.get("intent_sequence") == expected:
                    require(candidate["epoch"] == start["native_owner_epoch"], "R_NATIVE_PREPARED_BINDING")
                    prepared = candidate
            if expected + 2 < len(native_frames):
                candidate = native_frames[expected + 2]["payload"]
                if candidate.get("kind") == "terminal" and candidate.get("intent_sequence") == expected:
                    require(prepared is not None and candidate["epoch"] == start["native_owner_epoch"]
                            and candidate["operation"] == "confirmation", "R_NATIVE_TERMINAL_BINDING")
                    terminal = candidate
        elif p is not None:
            require(p.get("kind") == "open_intent" and p["epoch"] > start["native_owner_epoch"],
                    "R_NATIVE_DISPATCH_ORDER")
        if outcome is not None:
            post = outcome["native_after"]["sequence"]
            result = outcome["confirmation_wrapper_result"]
            require(start["native_before"]["sequence"] <= post <= expected + 2, "R_OUTCOME_RANGE")
            if post == expected + 2:
                require(invoked and terminal is not None and terminal["result"] == result, "R_NATIVE_OUTCOME_BINDING")
            else:
                require(result["ok"] is False and (invoked or post == start["native_before"]["sequence"]),
                        "R_INCOMPLETE_RESULT_PROMOTED")
        return {"native_intent_observed": invoked, "native_prepared_observed": prepared is not None,
                "native_terminal_observed": terminal is not None,
                "native_confirmation_result": None if terminal is None else terminal["result"]}

    for frame in records[1:]:
        p, sequence = frame["payload"], frame["sequence"]
        kind = p.get("kind")
        if kind == "lease_open":
            fields(p, {"kind", "epoch", "native_owner_epoch", "native_checkpoint", "prior_unresolved_starts", "spent_units"},
                   "R_OPEN_FIELDS")
            require(uint(p["epoch"], "R_EPOCH") == epoch + 1
                    and uint(p["native_owner_epoch"], "R_NATIVE_EPOCH") > native_epoch
                    and uint(p["spent_units"], "R_SPENT") == spent
                    and type(p["prior_unresolved_starts"]) is list
                    and all(type(i) is int for i in p["prior_unresolved_starts"])
                    and p["prior_unresolved_starts"] == sorted(pending), "R_OPEN_STATE")
            native_open = advance(p["native_checkpoint"])
            require(native_open["kind"] == "open_observed" and native_open["epoch"] == p["native_owner_epoch"],
                    "R_LEASE_NATIVE_BINDING")
            if epoch:
                cuts.append({"prior_epoch": epoch, "next_epoch": p["epoch"],
                             "prior_lease_cleanly_ended": not active,
                             "pending_starts_retained": sorted(pending), "unobserved_time_bound": None})
            epoch, native_epoch, active, current = p["epoch"], p["native_owner_epoch"], True, None
            leases.append({"epoch": epoch, "native_owner_epoch": native_epoch,
                           "open_sequence": sequence, "open_native_checkpoint": p["native_checkpoint"], "end_sequence": None})
        elif kind == "start":
            fields(p, {"kind", "epoch", "native_owner_epoch", "native_before", "expected_native_intent_sequence",
                       "transaction", "included", "observed_now", "allowance_units", "law_scope_sha256",
                       "statement_sha256", "spent_units"}, "R_START_FIELDS")
            require(active and current is None and uint(p["epoch"], "R_EPOCH") == epoch
                    and uint(p["native_owner_epoch"], "R_NATIVE_EPOCH") == native_epoch, "R_START_STATE")
            require(hx(p["law_scope_sha256"], 32, "R_SCOPE") == scope, "R_SCOPE_MISMATCH")
            for key in ("transaction", "included", "statement_sha256"):
                hx(p[key], 32, "R_" + key.upper())
            uint(p["observed_now"], "R_OBSERVED_NOW")
            allowance = uint(p["allowance_units"], "R_ALLOWANCE", denominator)
            require(allowance > 0 and uint(p["spent_units"], "R_SPENT") == spent + allowance
                    and spent + allowance <= budget, "R_BUDGET_SPEND")
            advance(p["native_before"])
            expected = uint(p["expected_native_intent_sequence"], "R_NATIVE_INTENT")
            require(expected == p["native_before"]["sequence"] + 1 and expected not in expected_intents,
                    "R_DUPLICATE_OR_WRONG_NATIVE_INTENT")
            expected_intents.add(expected)
            spent += allowance
            starts[sequence] = p
            pending.add(sequence)
            current = sequence
            call_binding(p)
        elif kind == "outcome":
            fields(p, {"kind", "epoch", "start_sequence", "native_after", "confirmation_wrapper_result"}, "R_OUTCOME_FIELDS")
            start_sequence = uint(p["start_sequence"], "R_START_SEQUENCE")
            require(active and uint(p["epoch"], "R_EPOCH") == epoch and current == start_sequence
                    and start_sequence in pending, "R_OUTCOME_STATE")
            _result(p["confirmation_wrapper_result"])
            advance(p["native_after"])
            call_binding(starts[start_sequence], p)
            outcomes[start_sequence] = p
            pending.remove(start_sequence)
            current = None
        elif kind == "lease_end":
            fields(p, {"kind", "epoch", "native_checkpoint", "spent_units"}, "R_END_FIELDS")
            require(active and current is None and uint(p["epoch"], "R_EPOCH") == epoch
                    and uint(p["spent_units"], "R_SPENT") == spent, "R_END_STATE")
            native_close = advance(p["native_checkpoint"])
            require(native_close["kind"] == "lease_end" and native_close["epoch"] == native_epoch,
                    "R_LEASE_NATIVE_BINDING")
            leases[-1]["end_sequence"] = sequence
            active = False
        else:
            raise CertificateError("R_RECORD_KIND")

    actual_confirmation_intents = {
        frame["sequence"] for frame in native_frames
        if frame["payload"].get("kind") == "intent" and frame["payload"].get("operation") == "confirmation"
    }
    require(all(index > anchor_sequence for index in actual_confirmation_intents), "R_PRIOR_UNREGISTERED_CONFIRMATION")
    require(actual_confirmation_intents == covered_native, "R_UNREGISTERED_NATIVE_CONFIRMATION")
    checked_starts = []
    for sequence, start in starts.items():
        binding = call_binding(start, outcomes.get(sequence))
        checked_starts.append({"start_sequence": sequence, "epoch": start["epoch"],
            "native_owner_epoch": start["native_owner_epoch"],
            "expected_native_intent_sequence": start["expected_native_intent_sequence"],
            "transaction": start["transaction"], "included": start["included"],
            "statement_sha256": start["statement_sha256"], "law_scope_sha256": scope,
            "allowance_units": start["allowance_units"], "spent_units_at_start": start["spent_units"],
            "outcome_recorded": sequence in outcomes, "charge_retained": True, **binding})
    require(_read_snapshot(path)[1] == source_sha256
            and read_native_frames(native_directory / "journal.pnoj1")[-1]["record_hash"]
            == native_end["record_hash"], "R_SOURCES_CHANGED_DURING_READ")
    checkpoint = {"bank_id": bank_id, "sequence": records[-1]["sequence"], "record_hash": records[-1]["record_hash"]}
    return {"schema": "pon-native-risk-ledger-check-v1", "checkpoint": checkpoint,
        "native_checkpoint": native_end, "bank_file_sha256": source_sha256,
        "supplied_bank_checkpoint_matches": None if expected_checkpoint is None else True,
        "supplied_native_checkpoint_matches": None if expected_native_checkpoint is None else True,
        "raw_native_journal_and_packets_rechecked": True, "records_checked": len(records),
        "epochs": epoch, "active_epoch": epoch if active else None, "leases": leases, "lease_transitions": cuts,
        "unit_denominator": denominator, "budget_units": budget, "spent_units": spent, "remaining_units": budget-spent,
        "starts_registered": len(starts), "outcomes_recorded": len(outcomes), "unresolved_starts": sorted(pending),
        "native_confirmation_intents_covered": len(actual_confirmation_intents), "starts": checked_starts,
        "all_observed_native_confirmation_intents_registered": True,
        "all_registered_starts_charged_without_refunds": True,
        "new_outcomes_for_old_pending_starts_inferred": False,
        "native_unresolved_intents": native["unresolved_intents"],
        "native_outside_lease_intervals": native["outside_lease_intervals"],
        "native_clock_regressions": native["clock_regressions"],
        "physical_pre_registration_independently_attested": False,
        "trusted_history_anchor": False, "latest_checkpoint_authenticated": False,
        "actual_probability_law_authenticated": False, "conditional_allowances_proved": False,
        "world_confirmation_attempts_covered": False, "native_conditional_risk_certified": False,
        "global_failure_probability": None}


def read_run(path: Path) -> dict:
    path = Path(path)
    value = strict_json(path.read_text())
    require(value.get("schema") == "pon-native-risk-ledger-run-v1", "R_RUN_SCHEMA")
    for flag in ("actual_probability_law_authenticated", "native_conditional_risk_certified"):
        require(value.get(flag) is False, "R_RUN_ESCALATION")
    require(value.get("global_failure_probability") is None, "R_RUN_ESCALATION")
    bank_relative, native_relative = value["bank_directory"], value["native_directory"]
    for relative in (bank_relative, native_relative):
        require(type(relative) is str and not Path(relative).is_absolute()
                and ".." not in Path(relative).parts, "R_RUN_PATH")
    checked = read_risk_ledger(path.parent / bank_relative, path.parent / native_relative,
                              expected_checkpoint=value["bank_checkpoint"],
                              expected_native_checkpoint=value["native_checkpoint"])
    require(checked["spent_units"] == value["final_status"]["spent_units"]
            and checked["starts_registered"] == value["final_status"]["starts_registered"], "R_RUN_STATUS")
    return checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = read_run(args.run)
    with args.output.open("x") as out:
        json.dump(report, out, sort_keys=True, indent=2)
        out.write("\n")


if __name__ == "__main__":
    main()
