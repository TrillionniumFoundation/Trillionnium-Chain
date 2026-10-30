#!/usr/bin/env python3
"""Reproduce synthetic reader counterexamples; no native work or admission runs."""
from datetime import datetime, timezone
import copy
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))
import check_legal_ticket_cost_v5 as current
from test_legal_ticket_cost_v5 import control, exhausted_control, fixture_challenge, NATIVE_TEMPLATE

path = HERE / "original-reader.py.txt"
loader = SourceFileLoader("original_v5_reader", str(path))
spec = importlib.util.spec_from_loader(loader.name, loader)
old = importlib.util.module_from_spec(spec)
loader.exec_module(old)


def outcome(reader, rows):
    try:
        reader.validate(rows)
        return {"accepted": True, "error": None}
    except (ValueError, KeyError, TypeError) as error:
        return {"accepted": False, "error": str(error)}


def mutate(rows, name):
    if name == "coordinated_late_missed_challenge":
        for row in rows[1:-1]:
            if row["round"] == 0 and row["search_horizon"] == 1:
                row["searches"][0]["trials"][7]["challenge"] = "ab" * 32
        return
    for row in rows[1:-1]:
        if name == "coordinated_challenges":
            for search in row["searches"]:
                for trial in search["trials"]:
                    trial["challenge"] = "ab" * 32
        elif name == "coordinated_header_magic":
            row["native_template_header"] = "00" * 318
        elif name == "coordinated_target":
            row["target"] = "03" * 32
        elif name == "coordinated_task":
            row["task"] = "ab" * 32
        elif name == "coordinated_state_with_rehashed_challenges":
            template = bytearray(NATIVE_TEMPLATE)
            template[214] ^= 1
            row["native_template_header"] = template.hex()
            for search in row["searches"]:
                for trial in search["trials"]:
                    trial["challenge"] = fixture_challenge(trial["nonce"], bytes(template))
        elif name == "coordinated_short_packet":
            for search in row["searches"]:
                for trial in search["trials"]:
                    trial["packet_bytes"] -= 1
            for packet in row["retained_packets"]:
                packet["bytes"] -= 1
        elif name != "positive":
            raise ValueError("unregistered synthetic mutation")


def main():
    cases = ["positive", "coordinated_challenges", "coordinated_header_magic",
             "coordinated_target", "coordinated_task",
             "coordinated_state_with_rehashed_challenges", "coordinated_short_packet",
             "coordinated_late_missed_challenge"]
    records = []
    for name in cases:
        rows = exhausted_control() if name == "coordinated_late_missed_challenge" else control()
        mutate(rows, name)
        original = outcome(old, copy.deepcopy(rows))
        hardened = outcome(current, copy.deepcopy(rows))
        if not original["accepted"] or hardened["accepted"] != (name == "positive"):
            raise ValueError(f"unexpected real reader result: {name}: {original}, {hardened}")
        records.append({"case": name, "old": original, "hardened": hardened,
                        "synthetic_rows_sha256": hashlib.sha256(json.dumps(
                            rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()})
    source_paths = [path, ROOT / "scripts/ci/check_legal_ticket_cost_v5.py",
                    ROOT / "scripts/ci/test_legal_ticket_cost_v5.py", Path(__file__)]
    record = {"schema": "pon-v5-synthetic-reader-red-green-v1",
              "observed_utc": datetime.now(timezone.utc).isoformat(), "cases": records,
              "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in source_paths},
              "old_reader_source_commit": "540d72356a921da31dde1113537382e5c0f0c4fd",
              "native_work_or_admission_executed": False,
              "synthetic_records_are_cost_measurements": False,
              "demonstrates_forged_valid_native_work": False}
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
