#!/usr/bin/env python3
"""Audit all six original ZIPs directly; never wait for a repackaged capsule.

This supplemental reader does not change CONTRACT_FREEZE.json. Its own digest
is retained in the historical consumer's input identity. Both reader versions
and the original 06 consumer remain the already frozen implementations.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import consume_native_v2 as consume
import native_reader_v2 as v2

PINNED_INPUTS = {
    "archive_verification.json": "b330ec3e355286951cb98ae502369bec0bb2f7530aac17e4b6c74af1d0a5a5a1",
    "original_members.json": "c2dd662930f985406be69b53baca3afbe0a7cb6083411a869a8db657dec368f7",
    "contract.json": "b4f95c4be83e6b2e07e492282b2c6f20d525d3be7d69580596eef89d3ffe3c1a",
    "schedule.jsonl": "96c7ccbc5edb58abb60cdbfa6e7258cf0f3f0fb31c0809e4c7f569bd86bff0c7",
    "events.jsonl": "6b042ec6f4abb6dcdfd6f59985c4aaae8aeb88b79018005c2eac96ede95a28ba",
}


def audit(zips, inputs, out):
    exporter = v2.load_frozen("exporter")
    for name, expected in PINNED_INPUTS.items():
        v2.require(consume.sha((inputs / name).read_bytes()) == expected, "ORIGINAL_INPUT_DIGEST:" + name)
    manifests = exporter.strict_json((inputs / "original_members.json").read_bytes())
    imported = exporter.strict_json((inputs / "archive_verification.json").read_bytes())
    identities = {x["archive"]: x for x in imported["archives"]}
    v1, version2 = v2.get_reader(version=1), v2.get_reader(version=2)
    old, new = exporter.Export(), exporter.Export()
    boundary_records, verified_archives, verified_members, phase_counts = [], [], [], []
    for key, (name, size, digest, commit) in version2.ARCHIVES.items():
        archive = version2.Archive(key, zips / name)
        identity = identities[name]
        v2.require(identity["zip_bytes"] == size and identity["zip_sha256"] == digest
                   and identity["commit"] == commit, "ARCHIVE_RECEIPT_IDENTITY")
        # Verify the complete 53-member capsule selection against actual ZIP
        # bytes, not against a derived event stream or an old result summary.
        for full_name, expected in sorted(manifests.items()):
            if not full_name.startswith(key + "/"):
                continue
            member = full_name[len(key) + 1:]
            raw = archive.raw(member)
            v2.require(len(raw) == expected["bytes"] and consume.sha(raw) == expected["sha256"],
                       "ORIGINAL_SELECTED_MEMBER:" + full_name)
            verified_members.append({"name": full_name, **expected})
        exporter.validate_retained_identity(key, identity, archive.raw, commit)
        if key in {"m14_protocol", "m14_fresh"}:
            prefix = "from-zero-native" if key == "m14_protocol" else "fresh-service"
            binary_member = prefix + "/public_v3_from_zero"
        elif key == "m14_f0":
            matches = [n for n in archive.z.namelist() if n.endswith("public_v3_multiprocess.bin")]
            v2.require(len(matches) == 1, "ORIGINAL_F0_BINARY_SET")
            binary_member = matches[0]
        else:
            binary_member = identity["binary"]["retained"]
        binary = archive.raw(binary_member)
        v2.require(consume.sha(binary) == exporter.BINARY_SHA256[key], "ORIGINAL_BINARY_BYTES:" + key)
        verified_archives.append({"archive": name, "bytes": size, "sha256": digest,
                                  "source_commit": commit, "source_tree": identity["source_before"]["tested_tree"],
                                  "binary_member": binary_member, "binary_bytes": len(binary),
                                  "binary_sha256": consume.sha(binary),
                                  "actions_run_id": identity["actions_run_id"], "artifact_id": identity["artifact_id"]})
        del binary
        if key.endswith("campaign"):
            reports = [(i, f"run-{i}-raw/report.json") for i in range(1, 4)]
        elif key == "m14_f0":
            reports = [(1, "execution/raw/report.json")]
        elif key == "m14_fresh":
            reports = [("original", "fresh-service/original/report.json"), ("fresh", "fresh-service/fresh/report.json")]
        else:
            reports = [("confirmation", "from-zero-native/confirmation/report.json")]
        for label, member in reports:
            report = archive.read(member)
            if key.endswith("campaign") or key == "m14_f0":
                preparation = report["preparation"]
                if key == "m14_f0":
                    preparation = {"business": [version2.decode_packet_fields(x) for x in preparation["business_packets"]],
                                   "actual_signed_seed_transfers": sum(len(version2.decode_packet_fields(x)["transactions"])
                                                                     for x in preparation["seed_packets"])}
                fixture = "fixed-root-f0" if key == "m14_f0" else "original-3x3-native"
                for i, phase in enumerate(report["phases"]):
                    a = v1.native_phase(archive, member, phase, preparation, label, i, fixture)
                    b = version2.native_phase(archive, member, phase, preparation, label, i, fixture)
                    old.campaign_phase(v1, archive, member, report, a, identity)
                    new.campaign_phase(version2, archive, member, report, b, identity)
                    phase_counts.append({"phase_id": b["phase_id"], "planned": b["planned_signed_transactions"],
                                         "v1_confirmed": a["confirmed_in_window"], "v2_confirmed": b["confirmed_in_window"]})
                    for j, attempt in enumerate(phase["confirmations"]):
                        boundary_records.append({"artifact_sha256": digest, "member": member,
                                                 "pointer": f"/phases/{i}/confirmations/{j}",
                                                 "endpoint_ns": attempt["ended_ns"], "window_ns": b["window_ns"],
                                                 "native_gate": attempt["confirmed_inside_pressure_window"],
                                                 "observation": attempt.get("observation")})
            else:
                same = report.get("same_packet_sequence_in_both_runs", report.get("same_signed_business_packets"))
                v2.require(same is True, "ORIGINAL_PAIR_SIGNED_SEQUENCE")
                decoded = [version2.decode_packet_fields(x) for x in report["signed_honest_packets"]]
                v2.require([len(x["transactions"]) for x in decoded] == [1, 0, 0, 0, 0, 0, 0], "ORIGINAL_PAIR_DENOMINATOR")
                tx = version2.wire_hash(b"tx-id", bytes.fromhex(decoded[0]["transactions"][0]))
                v2.require(len(report["phases"]) == 2 and len({p["initial_tip"] for p in report["phases"]}) == 1
                           and len({p["initial_state_root"] for p in report["phases"]}) == 1, "ORIGINAL_PAIR_INITIAL_STATE")
                for i, phase in enumerate(report["phases"]):
                    observation = phase.get("independent_client_confirmation")
                    if observation:
                        v2.require(observation["transaction"] == tx and observation["included_block"] == decoded[0]["id"],
                                   "ORIGINAL_PAIR_PREPARED_BINDING")
                    a = v1.pair_phase(archive, member, phase, i, label)
                    b = version2.pair_phase(archive, member, phase, i, label)
                    for row in (a, b):
                        row.update(prepared_transaction_id=tx, prepared_packet_ids=[x["id"] for x in decoded])
                        row["fixture"] = "fresh-challenge-four-second-pair" if label == "fresh" else "original-four-second-pair"
                    old.pair_phase(v1, archive, member, report, a, identity)
                    new.pair_phase(version2, archive, member, report, b, identity)
                    phase_counts.append({"phase_id": b["phase_id"], "planned": 1,
                                         "v1_confirmed": a["confirmed_in_window"], "v2_confirmed": b["confirmed_in_window"]})
                    boundary_records.append({"artifact_sha256": digest, "member": member,
                                             "pointer": f"/phases/{i}", "endpoint_ns": phase["confirmation_ended_ns"],
                                             "window_ns": phase["requested_window_ns"],
                                             "native_gate": phase["client_confirmed_before_original_window_end"],
                                             "observation": observation})
        archive.z.close()
        print(json.dumps({"archive_verified": name, "phases_rederived_so_far": len(new.runs)}, sort_keys=True), flush=True)
    v2.require(len(verified_members) == len(manifests) == 53, "ORIGINAL_SELECTED_MEMBER_COUNT")
    v2.require(len(new.runs) == 35 and len(new.schedule) == 93, "ORIGINAL_CORPUS_DENOMINATOR")
    v2.require(old.runs == new.runs and old.schedule == new.schedule and old.events == new.events, "V1_V2_EVENT_DIFFERENCE")
    v2.require(consume.sha(consume.jsonl(old.schedule)) == PINNED_INPUTS["schedule.jsonl"], "RECONSTRUCTED_ORIGINAL_SCHEDULE")
    v2.require(consume.sha(consume.jsonl(old.events)) == PINNED_INPUTS["events.jsonl"], "RECONSTRUCTED_ORIGINAL_EVENTS")
    original_contract = exporter.strict_json((inputs / "contract.json").read_bytes())
    v2.require(old.runs == original_contract["runs"], "RECONSTRUCTED_ORIGINAL_RUN_CONTRACTS")
    boundary = consume.audit_endpoints(boundary_records)
    boundary.update(all_six_original_zips_rehashed=True, all_six_original_binary_bytes_rehashed=True,
                    all_53_selected_raw_members_rehashed=True, old_corpus_actual_credit_changed=False,
                    v1_v2_rederived_events_equal=True, rederived_events_equal_original_export=True,
                    phase_counts=phase_counts, raw_scope="original CI ZIPs including actual retained binaries; no native execution")
    identity = {"supplemental_reader": "sp27-02-original-zip-audit-v2",
                "supplemental_reader_sha256": consume.sha(Path(__file__).read_bytes()),
                "inputs": PINNED_INPUTS, "original_archives": verified_archives,
                "selected_raw_members": verified_members, "original_raw_bytes_reverified": True,
                "repacked_capsule_required": False, "native_experiments": 0}
    consume.write_consumed(new, out, "historical-original-six-zips-v2-reanalysis", boundary, identity)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zips", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    audit(args.zips, args.inputs, args.out)


if __name__ == "__main__":
    main()
