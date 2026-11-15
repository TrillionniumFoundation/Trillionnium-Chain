#!/usr/bin/env python3
"""Read transaction observations without promoting block/ACK counts to TPS.

The growth collector provides exact packet snapshots, not native transaction
confirmation returns. Its derived depth-and-work eligibility is kept separate
from the original Host's independent-confirmation report. Neither source proves
operator independence, resource enforcement, risk or production capacity.

``original`` reuses adapt_native's create-only deterministic normalization; raw
collector files are unchanged. ``fullpath`` only reads normalized raw receipts.
``host`` reuses the existing original Host reader on a bounded pinned snapshot.
All valid results deliberately return exit 1 / HOLD; malformed inputs return 2.
"""
from __future__ import annotations

import argparse
from collections import Counter
from fractions import Fraction
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

import fullpath_gate as gate

SCHEMA = "trnm-transaction-throughput-observation-v1"
WINDOW_NS = 4_000_000_000
DEPTH = 6
WORK_MULTIPLIER = 6
ROOT = Path(__file__).resolve().parents[2]


def rate(count, duration_ns=WINDOW_NS):
    """Exact descriptive rate; None remains unknown, never a measured zero."""
    if count is None:
        return None
    gate.integer(count, "RATE_COUNT")
    gate.integer(duration_ns, "RATE_WINDOW", 1)
    value = Fraction(count * 1_000_000_000, duration_ns)
    return {"numerator": value.numerator, "denominator": value.denominator,
            "unit": "transactions/second"}


def latency_samples(values):
    values = sorted(gate.integer(value, "LATENCY") for value in values)
    count = len(values)
    minimum = {50: 2, 95: 20, 99: 100}
    return {"samples": count, "min_ns": min(values) if values else None,
            "max_ns": max(values) if values else None,
            "method": "nearest-rank; descriptive only; no independence or confidence claim",
            "minimum_samples": {f"p{p}": n for p, n in minimum.items()},
            **{f"p{p}_ns": values[(count * p + 99) // 100 - 1] if count >= n else None
               for p, n in minimum.items()}}


def transaction_identities(raw):
    """Fingerprint each exact body entry after the existing packet binding check.

    The native transaction ID hashes the COMPLETE original bytes, including the
    signature. This does not validate a transaction's encoding, signature or
    execution. Even a hostile packet's entries retain byte identities.
    """
    packet = gate.parse_packet(raw)
    pos = 4 + gate.HEADER_BYTES
    count = int.from_bytes(raw[pos:pos + 2], "little")
    pos += 2
    identities = []
    for _ in range(count):
        length = int.from_bytes(raw[pos:pos + 2], "little")
        pos += 2
        transaction = raw[pos:pos + length]
        pos += length
        identities.append({"transaction": gate.domain_hash("tx-id", transaction).hex(),
                           "sha256": gate.sha256(transaction), "bytes": len(transaction)})
    gate.require(len(identities) == packet["transaction_count"], "TRANSACTION_BODY_COUNT")
    return identities


def held_fields():
    # These are constants, never copied from a producer's serialized claims.
    return {"performance_gate": "COMPONENT_OBSERVATION_ONLY", "overall_gate": "HOLD",
            "qualified_confirmed_tps": None, "qualified_wan_tps": None,
            "production_activation": False, "network_capacity_qualified": False,
            "source_integrity_authenticated": False, "native_origin_authenticated": False,
            "physical_clock_authenticated": False, "resource_contract_enforcement_verified": False,
            "risk_ledger_consistency_verified": False, "confirmation_risk_authenticated": False,
            "confirmation_risk_bound": None, "tail_latency_qualified": False}


def check_original_window(manifest):
    gate.require(manifest["required_depth"] == DEPTH
                 and manifest["observation_end_ns"] == WINDOW_NS, "ORIGINAL_DEPTH_OR_WINDOW")
    for row in manifest["schedule"]:
        gate.require(row["deadline_ns"] == WINDOW_NS
                     and 0 <= row["scheduled_ns"] < WINDOW_NS, "ORIGINAL_DEADLINE")


def _fullpath(manifest, report, evidence, expected_manifest_sha256):
    checked = gate.evaluate(manifest, report, evidence, expected_manifest_sha256)
    check_original_window(manifest)
    context = gate.context_document(manifest, evidence)
    schedule = {row["id"]: row for row in manifest["schedule"]}
    observed = {row["id"]: row for row in report["attempts"]}
    checked_attempts = {row["id"]: row for row in checked["attempts"]}
    accepted_claims = {row["claim"]["packet_sha256"] for row in observed.values()
                       if row["status"] == "accepted"}
    attempts, identities, eligible = [], {}, {}
    contributing_cuts = []
    losses = set()
    known_packet_ids = set()
    unknown_packets = []
    for identity, planned in schedule.items():
        row = observed.get(identity)
        if row is None:
            attempts.append({"id": identity, "cohort": planned["cohort"], "status": "missing",
                             "transaction_ids": None, "packet_bytes_known": False,
                             "timely_depth_and_work_eligible": False})
            unknown_packets.append(identity)
            continue
        detail = checked_attempts[identity]
        packet, transactions = None, None
        if row["packet"] is not None:
            raw = evidence.artifact(row["packet"], gate.PACKET_LIMIT)
            try:
                packet = gate.parse_packet(raw)
            except ValueError:
                # The parent gate already refuses accepted malformed packets.
                pass
            if packet is not None:
                transactions = transaction_identities(raw)
        txids = None if transactions is None else sorted({tx["transaction"] for tx in transactions})
        if transactions is None:
            unknown_packets.append(identity)
        else:
            for tx in transactions:
                if tx["transaction"] in identities:
                    previous = identities[tx["transaction"]]
                    gate.require(previous["sha256"] == tx["sha256"]
                                 and previous["bytes"] == tx["bytes"], "TRANSACTION_ID_COLLISION")
                else:
                    identities[tx["transaction"]] = dict(tx, observed_attempt_ids=[])
                names = identities[tx["transaction"]]["observed_attempt_ids"]
                if identity not in names:
                    names.append(identity)
                known_packet_ids.add(tx["transaction"])
        checks = []
        required_work = None
        if packet is not None:
            target = int(packet["target_hex"], 16)
            required_work = WORK_MULTIPLIER * ((1 << 256) // (target + 1))
            previous_generation = 0
            for original in row["canonical_checks"]:
                check = gate.check_canonical(original, packet, evidence, context)
                native = gate.native_observation(evidence.artifact(original["receipt"]), packet)
                generation = gate.integer(native["generation"], "CANONICAL_GENERATION", previous_generation)
                previous_generation = generation
                work = (int(native["active_work_depth_hex"], 16)
                        if check["status"] == "canonical" else None)
                check.update(generation=generation,
                             canonical_tip=native["active_tip"],
                             canonical_tip_height=native["active_tip_height"],
                             canonical_tip_chainwork_hex=native["active_tip_chainwork_hex"],
                             work_delta_hex=f"{work:0128x}" if work is not None else None,
                             depth_and_work_eligible=check["status"] == "canonical"
                             and check["depth"] >= DEPTH and work >= required_work)
                checks.append(check)
        end_of_path = max((stage["ended_ns"] for stage in row["stages"]),
                          default=planned["scheduled_ns"])
        qualifying = [max(check["at_ns"], end_of_path) for check in checks
                      if check["depth_and_work_eligible"]]
        first = min(qualifying) if qualifying else None
        lost = any(check["status"] != "canonical" for check in checks)
        retained = bool(checks and checks[-1]["at_ns"] >= planned["reorg_observe_until_ns"]
                        and checks[-1]["depth_and_work_eligible"]
                        and report["observed_through_ns"] >= planned["reorg_observe_until_ns"]
                        and not lost)
        # Equality at 4s is late under the actual original Host contract.
        timely = bool(row["status"] == "accepted" and detail["full_path_completed"]
                      and detail["full_native_replay_observed"] and not detail["duplicate_progress"]
                      and planned["cohort"] == "honest" and planned["mode"] == "native"
                      and retained and first is not None and first < WINDOW_NS)
        # An exact resubmission can expose a later loss of the admitted claim.
        # A rejected hostile proof sharing its block ID cannot veto the valid
        # claim: only byte-identical accepted/duplicate observations qualify here.
        admitted_claim = (row["claim"] is not None
                          and row["claim"]["packet_sha256"] in accepted_claims
                          and row["status"] in {"accepted", "duplicate"})
        if admitted_claim and lost:
            losses.update(txids or [])
        if timely:
            for txid in txids or []:
                eligible[txid] = min(eligible.get(txid, first), first)
            if txids:
                last = checks[-1]
                contributing_cuts.append({"attempt_id": identity, "transaction_ids": txids,
                    "observed_at_ns": last["at_ns"],
                    "cut": {key: last[key] for key in ("canonical_tip", "canonical_tip_height",
                                                       "canonical_tip_chainwork_hex", "generation")}})
        attempts.append({"id": identity, "cohort": planned["cohort"], "status": row["status"],
                         "transaction_ids": txids, "packet_bytes_known": packet is not None,
                         "transaction_entries": len(transactions) if transactions is not None else None,
                         "duplicate_transaction_entries": len(transactions) - len(txids)
                         if transactions is not None else None,
                         "required_work_delta_hex": f"{required_work:0128x}"
                         if required_work is not None else None,
                         "canonical_checks": checks,
                         "first_depth_and_work_eligible_ns": first,
                         "latency_from_this_scheduled_start_ns": first - planned["scheduled_ns"]
                         if first is not None else None,
                         "reorg_or_absence_observed": lost,
                         "eligible_at_retention_window_end": retained,
                         "timely_depth_and_work_eligible": timely})
    for txid in losses:
        eligible.pop(txid, None)
    # Per-row ancestry checks cannot turn incompatible fork snapshots into
    # one transaction numerator. Require one common retained tip/work/generation
    # for all contributing claims. Snapshot timestamps are retained separately;
    # equality of a logical cut does not authenticate a physical observer.
    cuts = {}
    for observation in contributing_cuts:
        surviving = sorted(set(observation["transaction_ids"]) & set(eligible))
        if not surviving:
            continue
        key = gate.canonical(observation["cut"])
        group = cuts.setdefault(key, {"cut": observation["cut"], "observations": []})
        group["observations"].append({"attempt_id": observation["attempt_id"],
                                      "transaction_ids": surviving,
                                      "observed_at_ns": observation["observed_at_ns"]})
    cut_consistent = len(cuts) <= 1
    aggregate_count = len(eligible) if cut_consistent else None
    for txid, record in identities.items():
        start = min(schedule[name]["scheduled_ns"] for name in record["observed_attempt_ids"])
        record.update(first_matching_scheduled_start_ns=start,
                      observed_reorg_or_absence_after_admission=txid in losses,
                      first_retained_eligible_ns=eligible.get(txid),
                      latency_from_first_matching_scheduled_start_ns=eligible[txid] - start
                      if txid in eligible else None)
    window_covered = report["observed_through_ns"] >= WINDOW_NS
    coverage = window_covered and not checked["missing"]
    # This is only a rate of retained positive eligibility observations. With
    # missing starts/packet identities/window coverage it is unknown, not zero.
    arithmetic_complete = coverage and not unknown_packets
    reason_codes = ["GROWTH_SNAPSHOTS_ARE_NOT_NATIVE_CONFIRMATION_RETURNS",
                    "EXACT_TRANSACTION_OFFERS_NOT_PREREGISTERED", "RISK_LEDGER_NOT_BOUND",
                    "RESOURCE_ENFORCEMENT_UNQUALIFIED", "WAN_NOT_MEASURED"]
    if checked["missing"]:
        reason_codes.append("MISSING_SCHEDULED_STARTS")
    if unknown_packets:
        reason_codes.append("UNKNOWN_TRANSACTION_IDENTITIES")
    if not window_covered:
        reason_codes.append("INCOMPLETE_OBSERVATION_WINDOW")
    if not cut_consistent:
        reason_codes.append("CONFLICTING_CANONICAL_RETENTION_CUTS")
    return {"schema": SCHEMA, "source_kind": "native-growth-fullpath",
            "manifest_sha256": expected_manifest_sha256,
            "context_sha256": manifest["context"]["sha256"],
            "clock_id": context["clock_id"], "window_start_ns": 0, "window_end_ns": WINDOW_NS,
            "deadline_comparison": "strictly before original window end",
            "required_depth": DEPTH, "confirmation_work_multiplier": WORK_MULTIPLIER,
            "observed_through_ns": report["observed_through_ns"],
            "observation_window_covered": window_covered,
            "scheduled_starts": checked["scheduled"], "recorded_starts": checked["recorded"],
            "missing_start_ids": checked["missing"], "unknown_packet_attempt_ids": unknown_packets,
            "outcomes": dict(sorted(Counter(item["status"] for item in attempts).items())),
            "observed_unique_packet_transaction_ids": sorted(known_packet_ids),
            "observed_unique_packet_transactions": len(known_packet_ids),
            "preregistered_unique_transaction_offers": None,
            "exact_transaction_offer_denominator_known": False,
            "observed_unique_depth_and_work_eligible_transactions": aggregate_count,
            "eligible_transaction_ids": sorted(eligible) if cut_consistent else None,
            "individually_observed_unique_depth_and_work_eligible_transactions": len(eligible),
            "individually_observed_eligible_transaction_ids": sorted(eligible),
            "joint_retention_cut_consistent": cut_consistent if cuts else None,
            "retention_cut_observations": [cuts[key] for key in sorted(cuts)],
            "eligibility_observation_rate": rate(aggregate_count) if arithmetic_complete else None,
            "eligibility_rate_scope": "retained mathematical eligibility observations; not native confirmation TPS",
            "observed_independently_confirmed_transactions": None,
            "independent_confirmation_observation_rate": None,
            "matching_start_eligible_latency": latency_samples([
                row["latency_from_first_matching_scheduled_start_ns"]
                for row in identities.values() if row["first_retained_eligible_ns"] is not None])
                if cut_consistent else None,
            "latency_scope": "earliest scheduled start among observed matching packet bytes; no frozen transaction-offer census",
            "fullpath_readback": checked, "attempts": attempts,
            "transactions": [identities[key] for key in sorted(identities)],
            "original_process_records_rechecked": False,
            "normalization_is_new_preregistration": False,
            "reason_codes": reason_codes, **held_fields()}


def read_fullpath(root, expected_manifest_sha256, *, manifest_path="manifest.json",
                  report_path="observations.json"):
    gate.hex_value(expected_manifest_sha256, "EXPECTED_MANIFEST_DIGEST")
    evidence = gate.Evidence(root)
    manifest_raw = evidence.read(manifest_path)
    gate.require(gate.sha256(manifest_raw) == expected_manifest_sha256, "FROZEN_MANIFEST_HASH_MISMATCH")
    report_raw = evidence.read(report_path)
    result = _fullpath(gate.decode(manifest_raw), gate.decode(report_raw), evidence,
                       expected_manifest_sha256)
    result["observations_sha256"] = gate.sha256(report_raw)
    return result


def read_original(root, expected_preregistration_sha256):
    import adapt_native
    # Never trust a cached gate-readback.json. The existing adapter reconciles
    # original process records/streams and refuses inconsistent derived files.
    adapted = adapt_native.adapt(root, expected_preregistration_sha256)
    result = read_fullpath(root, adapted["manifest_sha256"], manifest_path="gate-manifest.json",
                           report_path="gate-observations.json")
    evidence = gate.Evidence(root)
    context = gate.decode(evidence.read("gate-context.json"))
    for name in ("original_context", "original_preregistration", "original_observations"):
        evidence.artifact(context[name])
    gate.require(context["original_preregistration"]["sha256"] == expected_preregistration_sha256
                 and context["original_observations"]["sha256"] == adapted["original_observations_sha256"],
                 "ORIGINAL_READBACK_CHANGED")
    result.update(original_preregistration_sha256=expected_preregistration_sha256,
                  original_observations_sha256=adapted["original_observations_sha256"],
                  original_process_records_rechecked=True)
    return result


def host_driver():
    """Load the repository's existing validator, never a path from evidence."""
    directory = ROOT / "scripts" / "ci"
    sys.path.insert(0, str(directory))
    spec = importlib.util.spec_from_file_location("_throughput_original_host_reader",
                                                directory / "run_from_zero_native.py")
    gate.require(spec is not None and spec.loader is not None, "HOST_READER_UNAVAILABLE")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_host_report(path, expected_report_sha256):
    """Project both original Host phases, retaining unknown and failed outcomes.

    The original v2 reader independently binds each positive report to exact
    transaction bytes, seven parent-linked packets, depth/work and the final
    independent native replay/confirmation return. This is still consistency of
    recorded observations, not cryptographic origin or production qualification.
    """
    path = Path(path)
    gate.hex_value(expected_report_sha256, "EXPECTED_REPORT_DIGEST")
    raw = gate.Evidence(path.parent).read(path.name, 32 * 1024 * 1024)
    gate.require(gate.sha256(raw) == expected_report_sha256, "HOST_REPORT_HASH_MISMATCH")
    document = gate.decode(raw)  # Strict duplicate-key/nonfinite/depth handling before reuse.
    driver = host_driver()
    # Bind all of the original reader's rereads to the same captured bytes.
    with tempfile.TemporaryDirectory(prefix="trnm-host-throughput-readback-") as directory:
        snapshot = Path(directory) / "report.json"
        snapshot.write_bytes(raw)
        summary = driver.summarize_confirmation_report(snapshot, observation_version=2)
    gate.require(summary["sha256"] == expected_report_sha256, "HOST_READER_SNAPSHOT_BINDING")
    phases = []
    contradictions = []
    for original, phase in zip(document["phases"], summary["phases"]):
        business = phase["business"]
        reported = business["reported_independently_confirmed_in_window"]
        covered = business["lower_bound_reaches_original_window_end"] is True
        known = reported if reported == 1 or (reported == 0 and covered) else None
        inconsistency = None
        if reported == 0:
            native = original.get("independent_client_confirmation")
            ended = original.get("confirmation_ended_ns")
            if native is not None:
                if type(native) is not dict or type(native.get("confirmed")) is not bool:
                    inconsistency = "ZERO_COUNT_WITH_UNINTERPRETABLE_NATIVE_OBSERVATION"
                elif native["confirmed"] is True and (type(ended) is not int or ended < WINDOW_NS):
                    inconsistency = "ZERO_COUNT_WITH_EARLIER_OR_UNTIMED_POSITIVE_NATIVE_OBSERVATION"
            if inconsistency is not None:
                # Do not infer either 0 or 1 from inconsistent aggregate/native
                # records. An authentic late positive remains a separate case.
                known = None
                contradictions.append({"mode": phase["mode"], "issue": inconsistency})
        phases.append({"mode": phase["mode"], "hostile_workers": phase["workers"],
                       "window_ns": phase["window_ns"], "required_unique_transactions": 1,
                       "reported_independently_confirmed_in_window": reported,
                       "supported_independent_confirmation_count": known,
                       "confirmation_record_inconsistency": inconsistency,
                       "recorded_native_confirmation": original.get("independent_client_confirmation"),
                       "recorded_confirmation_ended_ns": original.get("confirmation_ended_ns"),
                       "independent_confirmation_observation_rate": rate(known),
                       "missing_confirmation_count": reported is None,
                       "reported_zero_has_full_censor_window": covered if reported == 0 else None,
                       "business": business, "signed_submit_ack": phase["signed_submit_ack"],
                       "history_response": phase["history_response"],
                       "independent_page_replay": phase["independent_page_replay"],
                       "verification_errors": phase["verification_errors"]})
    return {"schema": SCHEMA, "source_kind": "original-host-confirmation-report",
            "report_sha256": expected_report_sha256,
            "reader_sha256": gate.sha256(Path(driver.__file__).read_bytes()),
            "simulated_control": summary["simulated_control"], "phases": phases,
            "original_gate_consistency_validated": summary["original_gate_validated"],
            "original_gate_validation_error": summary["original_gate_validation_error"],
            "original_host_readback": summary,
            "confirmation_record_inconsistencies": contradictions,
            "aggregate_confirmation_rate": None,
            "aggregation_scope": "baseline and pressure are separate cohorts of the same offered transaction; never summed",
            "reason_codes": ["FINITE_SINGLE_TRANSACTION_OFFER_NOT_SATURATED_CAPACITY",
                             "RISK_LEDGER_NOT_BOUND", "NATIVE_ORIGIN_NOT_AUTHENTICATED",
                             "RESOURCE_ENFORCEMENT_UNQUALIFIED", "WAN_NOT_MEASURED"],
            **held_fields()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    normalized = modes.add_parser("fullpath")
    normalized.add_argument("evidence", type=Path)
    normalized.add_argument("--manifest-sha256", required=True)
    normalized.add_argument("--manifest", default="manifest.json")
    normalized.add_argument("--observations", default="observations.json")
    original = modes.add_parser("original")
    original.add_argument("evidence", type=Path)
    original.add_argument("--preregistration-sha256", required=True)
    host = modes.add_parser("host")
    host.add_argument("report", type=Path)
    host.add_argument("--report-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == "original":
            result = read_original(args.evidence, args.preregistration_sha256)
        elif args.mode == "host":
            result = read_host_report(args.report, args.report_sha256)
        else:
            result = read_fullpath(args.evidence, args.manifest_sha256,
                                   manifest_path=args.manifest, report_path=args.observations)
    except (OSError, ValueError, TypeError, KeyError, OverflowError) as exc:
        print(json.dumps({"schema": SCHEMA, "evidence_valid": False, "error": str(exc),
                          **held_fields()}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 1


if __name__ == "__main__":
    sys.exit(main())
