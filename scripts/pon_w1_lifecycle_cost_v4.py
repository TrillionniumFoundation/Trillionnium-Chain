#!/usr/bin/env python3
"""Validate the V4 native lifecycle event grammar, including incomplete prefixes.

This is an observation reader, not an execution authenticator or a proof of
the cheapest legal work cost. Source, binary, process and resource receipts
remain external requirements. A killed or truncated run never has zero cost.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

import pon_w1_cost_matrix_reader as fixed_material

SCHEMA = "pon-w1-lifecycle-cost-v4"
SELECTOR = "--actual-lifecycle-v4"
TARGET = "7f" + "ff" * 31
ARMS = (
    "scalar-original", "prepared-generic", "prepared-structured",
    "tiled-classical", "tiled-strassen-one-level", "paired-product",
    "blocked-zero", "blocked-zero-integer-paired", "blocked-one-zero-rank-one",
    "maintenance-periodic", "maintenance-integer-paired", "maintenance-prefix",
    "maintenance-limb",
)
CLASSES = (
    "periodic-dense-fixture", "full-rank-field", "zero", "identity", "rank-one",
    "sparse-diagonal", "continuity-maintenance-v1",
    "one-zero-left-rank-one", "one-zero-right-rank-one",
)
SAMPLES, SEARCHES, LIMIT = 8, 4, 4096
MAX_LINE_BYTES, MAX_TOTAL_BYTES = 262144, 256 * 1024 * 1024
Q, CELLS, PROOF_BYTES = 4294967291, 4096, 49188
KEYS = {"class", "sample", "arm", "invocation_order", "task", "target"}


def need(value, code):
    if not value:
        raise ValueError(code)


def integer(value, code, maximum=(1 << 64) - 1):
    need(type(value) is int and 0 <= value <= maximum, code)
    return value


def hex_bytes(value, length, code):
    need(type(value) is str and len(value) == length * 2
         and all(char in "0123456789abcdef" for char in value), code)
    return bytes.fromhex(value)


def digest(tag, *parts):
    raw = b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag
    for part in parts:
        raw += struct.pack("<I", len(part)) + part
    return hashlib.sha256(raw).digest()


def challenge(task, sample, search, nonce):
    return digest(b"pon-w1-reused-challenge-v3", bytes.fromhex(task),
                  struct.pack("<Q", 0), struct.pack("<Q", sample),
                  struct.pack("<Q", search), struct.pack("<Q", nonce)).hex()


def timing(value):
    need(type(value) is dict and set(value) == {"cpu_ns", "wall_ns"}, "TIMING_FIELDS")
    for item in value.values():
        if item is not None:
            integer(item, "TIMING_VALUE")
    return value


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        need(key not in out, "DUPLICATE_JSON_KEY")
        out[key] = value
    return out


def reject_float(_):
    raise ValueError("INEXACT_JSON_NUMBER")


class Reader:
    def __init__(self):
        self.sequence = 0
        self.phase = "start"
        self.materials = {}
        self.proof_prefix_hashes = {}
        self.cohorts = set()
        self.active = None
        self.search = None
        self.canonical = {}
        self.canonical_streams = {}
        self.search_hasher = None
        self.candidates = set()
        self.counts = dict(cohorts=0, searches=0, attempts=0, candidates=0,
                           verifiers=0, verified_searches=0)
        self.generation_cpu = 0
        self.missing_generation_cpu = 0
        self.terminal = False
        self.complete = False
        self.failure = None

    def same_key(self, row, *, searching=False):
        need(self.active is not None, "NO_ACTIVE_COHORT")
        need(all(type(row.get(key)) is type(self.active[key])
                 and row.get(key) == self.active[key] for key in KEYS), "COHORT_BINDING")
        if searching:
            need(self.search is not None and type(row.get("search_index")) is int
                 and row["search_index"] == self.search["index"], "SEARCH_BINDING")

    def observe_generation(self, row):
        data = timing(row["timing"])
        if data["cpu_ns"] is None:
            self.missing_generation_cpu += 1
        else:
            self.generation_cpu += data["cpu_ns"]

    def consume(self, row):
        need(type(row) is dict and row.get("schema") == SCHEMA, "RECORD_SCHEMA")
        need(integer(row.get("sequence"), "SEQUENCE") == self.sequence, "SEQUENCE_GAP")
        need(not self.terminal, "RECORD_AFTER_TERMINAL")
        self.sequence += 1
        kind = row.get("kind")
        need(type(kind) is str, "RECORD_KIND")

        base = {"schema", "sequence", "kind"}
        search_keys = KEYS | {"search_index"}
        verify_keys = search_keys | {"path", "verification_order", "challenge", "proof_sha256"}
        event_fields = {
            "start": {"selector", "samples", "searches_per_setup", "attempt_budget", "seed",
                      "target", "arms", "clock", "setup_reuse", "attempt_timing_scope",
                      "search_timing_scope", "verifier_timing_scope", "missing_finish",
                      "sink_guarantee", "raw_process_and_source_receipts_required",
                      "hardness_accepted", "work_profile_qualified", "public_service_measured",
                      "production_activation", "consensus_credit_added"},
            "material-setup-start": set(),
            "material-setup-finish": {"timing", "classes"},
            "material": {"class", "source", "task", "a_hex", "b_hex"},
            "cohort-start": KEYS,
            "prepare-start": KEYS,
            "prepare-finish": KEYS | {"timing", "setup_calls", "status"}
                              | ({"reason"} if row.get("status") == "error" else set()),
            "search-start": search_keys,
            "attempt-start": search_keys | {"nonce", "challenge"},
            "attempt-finish": search_keys | {"trial", "timing", "accepted_work"},
            "attempt-error": search_keys | {"nonce", "reason", "timing", "accepted_work"},
            "search-finish": search_keys | {"timing", "attempt_count", "status"},
            "verify-start": verify_keys,
            "verify-finish": verify_keys | {"outcome", "timing", "consensus_credit_added"},
            "cohort-finish": KEYS | {"status", "total_with_observation_and_verification"},
            "candidate": {"class", "sample", "search_index", "task", "target", "challenge",
                          "proof_hex", "proof_sha256", "consensus_credit_added"},
            "end": {"material_count", "cohort_count", "search_count", "attempt_count",
                    "candidate_count", "verifier_count", "fully_verified_search_count",
                    "total_before_terminal_record", "complete", "consensus_credit_added",
                    "work_cost_lower_bound_proved", "production_qualified"},
            "failure": {"reason", "complete", "unfinished_cost", "consensus_credit_added",
                        "production_qualified"},
        }
        need(kind in event_fields and set(row) == base | event_fields[kind], "RECORD_FIELDS")

        if kind == "failure":
            need(self.phase != "start", "FAILURE_WITHOUT_START")
            need(row.get("complete") is False and row.get("unfinished_cost") is None
                 and type(row.get("reason")) is str and bool(row["reason"])
                 and row.get("production_qualified") is False
                 and type(row.get("consensus_credit_added")) is int
                 and row["consensus_credit_added"] == 0, "FAILURE_FIELDS")
            self.failure, self.terminal = row["reason"], True
            return

        if kind == "start":
            need(self.phase == "start" and self.sequence == 1, "START_ORDER")
            expected = dict(selector=SELECTOR, samples=SAMPLES, searches_per_setup=SEARCHES,
                            attempt_budget=LIMIT, seed=0, target=TARGET, arms=list(ARMS),
                            hardness_accepted=False, work_profile_qualified=False,
                            public_service_measured=False, production_activation=False,
                            consensus_credit_added=0, raw_process_and_source_receipts_required=True,
                            missing_finish="INCOMPLETE_COST_UNKNOWN_NEVER_ZERO",
                            clock="thread-cpu-and-monotonic-wall-ns",
                            setup_reuse="one-actual-preparation-four-distinct-domain-searches",
                            attempt_timing_scope="proof-generation-and-trial-digest-before-finish-observation",
                            search_timing_scope="native-search-with-v4-streaming-observation",
                            verifier_timing_scope="complete-native-verification-call",
                            sink_guarantee="line-write-and-flush-not-power-loss-durability")
            for key, value in expected.items():
                need(type(row.get(key)) is type(value) and row.get(key) == value,
                     "START_CONTRACT:" + key)
            self.phase = "material-setup-start"
        elif kind == "material-setup-start":
            need(self.phase == kind, "MATERIAL_SETUP_ORDER")
            self.phase = "material-setup-finish"
        elif kind == "material-setup-finish":
            need(self.phase == kind and row.get("classes") == list(CLASSES), "MATERIAL_ROSTER")
            timing(row.get("timing"))
            self.phase = "idle"
        elif kind == "material":
            need(self.phase == "idle" and row.get("class") in CLASSES, "MATERIAL_ORDER")
            name = row["class"]
            need(name not in self.materials, "DUPLICATE_MATERIAL")
            expected_source = ("hash-generated-rank-checked" if name == "full-rank-field"
                               else "synthetic-fixture")
            need(row.get("source") == expected_source, "MATERIAL_SOURCE")
            a = hex_bytes(row.get("a_hex"), CELLS * 4, "MATERIAL_A")
            b = hex_bytes(row.get("b_hex"), CELLS * 4, "MATERIAL_B")
            need(all(x[0] < Q for x in struct.iter_unpack("<I", a + b)), "MATERIAL_FIELD")
            task = digest(b"task", a, b).hex()
            need(row.get("task") == task, "MATERIAL_TASK")
            expected_a, expected_b, expected_task, proof_prefix = fixed_material.material(name)
            need((a, b, task) == (expected_a, expected_b, expected_task.hex()),
                 "MATERIAL_RECIPE")
            self.materials[name] = task
            self.proof_prefix_hashes[name] = hashlib.sha256(proof_prefix)
        elif kind == "cohort-start":
            need(self.phase == "idle", "COHORT_OVERLAP")
            name = row.get("class")
            need(name in self.materials and row.get("task") == self.materials[name], "COHORT_TASK")
            sample = integer(row.get("sample"), "SAMPLE", SAMPLES - 1)
            order = integer(row.get("invocation_order"), "ARM_ORDER", len(ARMS) - 1)
            arm = row.get("arm")
            need(arm == ARMS[(sample + order) % len(ARMS)]
                 and row.get("target") == TARGET, "COHORT_ARM_TARGET")
            key = (name, sample, arm)
            need(key not in self.cohorts, "DUPLICATE_COHORT")
            self.cohorts.add(key)
            self.active = {key: row[key] for key in KEYS}
            self.active.update(next_search=0, supported=None)
            self.phase = "prepare-start"
        elif kind == "prepare-start":
            self.same_key(row)
            need(self.phase == kind, "PREPARATION_ORDER")
            self.phase = "prepare-finish"
        elif kind == "prepare-finish":
            self.same_key(row)
            need(self.phase == kind and type(row.get("setup_calls")) is int
                 and row["setup_calls"] == 1, "PREPARATION_FINISH")
            timing(row.get("timing"))
            status = row.get("status")
            need(status in ("supported", "unsupported", "error"), "PREPARATION_STATUS")
            if status == "error":
                need(type(row.get("reason")) is str and bool(row["reason"]), "PREPARATION_ERROR")
                self.phase = "await-failure"
                return
            expected_supported = fixed_material.supported(self.active["arm"], self.active["class"])
            need((status == "supported") == expected_supported, "PRODUCER_SUPPORT_MATRIX")
            self.active["supported"] = status == "supported"
            self.counts["cohorts"] += 1
            self.phase = "search-start" if status == "supported" else "cohort-finish"
        elif kind == "search-start":
            self.same_key(row)
            need(self.phase == kind and type(row.get("search_index")) is int
                 and row["search_index"] == self.active["next_search"]
                 and row["search_index"] < SEARCHES, "SEARCH_START")
            self.search_hasher = hashlib.sha256()
            self.search = dict(index=row["search_index"], attempts=0, pending=None,
                               winner=None, verifiers=0,
                               trial_stream_sha256=self.search_hasher.hexdigest())
            self.phase = "attempt-start"
        elif kind == "attempt-start":
            self.same_key(row, searching=True)
            need(self.phase == kind and self.search["winner"] is None
                 and self.search["attempts"] < LIMIT, "ATTEMPT_START")
            nonce = integer(row.get("nonce"), "NONCE", LIMIT - 1)
            need(nonce == self.search["attempts"], "NONCE_SEQUENCE")
            expected = challenge(self.active["task"], self.active["sample"],
                                 self.search["index"], nonce)
            need(row.get("challenge") == expected, "ATTEMPT_CHALLENGE")
            self.search["pending"] = (nonce, expected)
            self.phase = "attempt-finish"
        elif kind in ("attempt-finish", "attempt-error"):
            self.same_key(row, searching=True)
            need(self.phase == "attempt-finish" and row.get("accepted_work") is False,
                 "ATTEMPT_FINISH")
            nonce, context = self.search["pending"]
            self.observe_generation(row)
            if kind == "attempt-error":
                need(type(row.get("nonce")) is int and row["nonce"] == nonce
                     and type(row.get("reason")) is str and bool(row["reason"]), "ATTEMPT_ERROR")
                self.phase = "await-failure"
                return
            trial = row.get("trial")
            need(type(trial) is dict and set(trial) == {
                "nonce", "challenge", "trace", "ticket", "proof_sha256", "target_hit"
            }, "TRIAL_FIELDS")
            need(type(trial["nonce"]) is int and trial["nonce"] == nonce
                 and trial["challenge"] == context, "TRIAL_BINDING")
            trace = hex_bytes(trial["trace"], 32, "TRIAL_TRACE")
            ticket = digest(b"ticket", bytes.fromhex(context), trace).hex()
            need(trial["ticket"] == ticket and type(trial["target_hit"]) is bool
                 and trial["target_hit"] == (ticket <= TARGET), "TRIAL_TICKET")
            hex_bytes(trial["proof_sha256"], 32, "TRIAL_PROOF_DIGEST")
            proof_hash = self.proof_prefix_hashes[self.active["class"]].copy()
            proof_hash.update(trace)
            need(trial["proof_sha256"] == proof_hash.hexdigest(), "TRIAL_PROOF_BINDING")
            # Bind every completed trial, including all losing attempts.
            # Timings differ across producers and are intentionally excluded.
            self.search_hasher.update(json.dumps(
                trial, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("ascii") + b"\n")
            self.search["trial_stream_sha256"] = self.search_hasher.hexdigest()
            self.search["pending"] = None
            self.search["attempts"] += 1
            self.counts["attempts"] += 1
            if trial["target_hit"]:
                self.search["winner"] = trial
            self.phase = ("search-finish" if trial["target_hit"]
                          or self.search["attempts"] == LIMIT else "attempt-start")
        elif kind == "search-finish":
            self.same_key(row, searching=True)
            need(self.phase == kind and type(row.get("attempt_count")) is int
                 and row["attempt_count"] == self.search["attempts"], "SEARCH_FINISH")
            timing(row.get("timing"))
            winner = self.search["winner"]
            need(row.get("status") == ("target-hit-unverified" if winner else "exhausted"),
                 "SEARCH_OUTCOME")
            self.counts["searches"] += 1
            canon = (self.active["class"], self.active["sample"], self.search["index"])
            stream_signature = (self.search["attempts"], self.search["trial_stream_sha256"])
            if canon in self.canonical_streams:
                need(self.canonical_streams[canon] == stream_signature,
                     "PRODUCER_TRIAL_STREAM_DISAGREEMENT")
            else:
                self.canonical_streams[canon] = stream_signature
            signature = None if winner is None else tuple(winner[key] for key in
                        ("nonce", "challenge", "trace", "ticket", "proof_sha256"))
            if canon in self.canonical:
                need(self.canonical[canon] == signature, "PRODUCER_STREAM_DISAGREEMENT")
            else:
                self.canonical[canon] = signature
            self.phase = "verify-start" if winner else "search-closed"
            if winner is None:
                self.close_search()
        elif kind == "verify-start":
            self.same_key(row, searching=True)
            need(self.phase == kind, "VERIFICATION_ORDER")
            order = integer(row.get("verification_order"), "VERIFICATION_INDEX", 1)
            need(order == self.search["verifiers"], "VERIFICATION_SEQUENCE")
            reference = (self.active["sample"] + self.active["invocation_order"]
                         + self.search["index"] + order) % 2 == 1
            need(row.get("path") == ("reference" if reference else "production"),
                 "VERIFICATION_PATH")
            winner = self.search["winner"]
            need(row.get("challenge") == winner["challenge"]
                 and row.get("proof_sha256") == winner["proof_sha256"], "VERIFICATION_BINDING")
            self.search["verify_key"] = (order, row["path"])
            self.phase = "verify-finish"
        elif kind == "verify-finish":
            self.same_key(row, searching=True)
            need(self.phase == kind and type(row.get("verification_order")) is int
                 and (row["verification_order"], row.get("path")) == self.search["verify_key"],
                 "VERIFICATION_FINISH")
            winner = self.search["winner"]
            need(row.get("challenge") == winner["challenge"]
                 and row.get("proof_sha256") == winner["proof_sha256"], "VERIFICATION_BINDING")
            timing(row.get("timing"))
            need(type(row.get("consensus_credit_added")) is int
                 and row["consensus_credit_added"] == 0, "OBSERVATION_CANNOT_ADD_CREDIT")
            self.counts["verifiers"] += 1
            if row.get("outcome") != "Accepted":
                self.phase = "await-failure"
                return
            self.search["verifiers"] += 1
            if self.search["verifiers"] == 2:
                self.counts["verified_searches"] += 1
                self.close_search()
            else:
                self.phase = "verify-start"
        elif kind == "cohort-finish":
            self.same_key(row)
            need(self.phase == kind, "COHORT_UNFINISHED")
            expected = "supported" if self.active["supported"] else "unsupported"
            need(row.get("status") == expected, "COHORT_STATUS")
            timing(row.get("total_with_observation_and_verification"))
            self.active, self.search, self.phase = None, None, "idle"
        elif kind == "candidate":
            need(self.phase == "idle", "CANDIDATE_ORDER")
            name = row.get("class")
            sample = integer(row.get("sample"), "CANDIDATE_SAMPLE", SAMPLES - 1)
            index = integer(row.get("search_index"), "CANDIDATE_SEARCH", SEARCHES - 1)
            key = (name, sample, index)
            need(key in self.canonical and self.canonical[key] is not None
                 and key not in self.candidates, "CANDIDATE_IDENTITY")
            _, context, trace, _, proof_digest = self.canonical[key]
            need(row.get("task") == self.materials.get(name) and row.get("target") == TARGET
                 and row.get("challenge") == context and row.get("proof_sha256") == proof_digest
                 and type(row.get("consensus_credit_added")) is int
                 and row["consensus_credit_added"] == 0, "CANDIDATE_BINDING")
            proof = hex_bytes(row.get("proof_hex"), PROOF_BYTES, "CANDIDATE_PROOF")
            need(proof[:4] == b"PNW1" and hashlib.sha256(proof).hexdigest() == proof_digest
                 and proof[-32:].hex() == trace, "CANDIDATE_BYTES")
            need(digest(b"task", proof[4:4 + CELLS * 4],
                        proof[4 + CELLS * 4:4 + CELLS * 8]).hex() == row["task"],
                 "CANDIDATE_TASK")
            need(all(x[0] < Q for x in struct.iter_unpack("<I", proof[4:-32])),
                 "CANDIDATE_FIELD")
            self.candidates.add(key)
            self.counts["candidates"] += 1
        elif kind == "end":
            need(self.phase == "idle", "END_WITH_OPEN_WORK")
            expected_cohorts = {(name, sample, arm) for name in CLASSES
                                for sample in range(SAMPLES) for arm in ARMS}
            need(set(self.materials) == set(CLASSES) and self.cohorts == expected_cohorts,
                 "END_ROSTER")
            need(self.candidates == {key for key, value in self.canonical.items()
                                      if value is not None}, "END_CANDIDATES")
            fields = dict(material_count=len(CLASSES), cohort_count=self.counts["cohorts"],
                          search_count=self.counts["searches"], attempt_count=self.counts["attempts"],
                          candidate_count=self.counts["candidates"],
                          verifier_count=self.counts["verifiers"],
                          fully_verified_search_count=self.counts["verified_searches"],
                          consensus_credit_added=0, complete=True,
                          work_cost_lower_bound_proved=False, production_qualified=False)
            for key, value in fields.items():
                need(type(row.get(key)) is type(value) and row.get(key) == value,
                     "END_COUNTER_OR_CLAIM:" + key)
            timing(row.get("total_before_terminal_record"))
            self.complete, self.terminal, self.phase = True, True, "complete"
        else:
            raise ValueError("UNEXPECTED_EVENT:" + kind)

    def close_search(self):
        self.active["next_search"] += 1
        self.search = None
        self.search_hasher = None
        self.phase = ("cohort-finish" if self.active["next_search"] == SEARCHES
                      else "search-start")

    def report(self, *, process_exit_code, trailing_partial_bytes, raw_sha256):
        complete = self.complete and process_exit_code == 0 and trailing_partial_bytes == 0
        return {
            "schema": "pon-w1-lifecycle-readback-v4",
            "status": "COMPLETE_DECLARED_OBSERVATION" if complete else "INCOMPLETE",
            "native_process_exit_code": process_exit_code,
            "raw_sha256": raw_sha256, "complete_records": self.sequence,
            "trailing_partial_bytes": trailing_partial_bytes,
            "last_phase": self.phase,
            "unfinished_cohort": self.active,
            "unfinished_search": self.search,
            "failure": self.failure,
            "observed_counts": self.counts,
            "observed_generation_cpu_subtotal_ns": self.generation_cpu,
            "generation_records_with_unknown_cpu": self.missing_generation_cpu,
            "unfinished_resource_cost": None,
            "source_binary_resource_identity_authenticated_by_reader": False,
            "full_relation_replayed_by_reader": False,
            "all_legal_work_cost_lower_bound_proved": False,
            "consensus_credit_added": 0,
            "production_qualified": False,
        }


def read_stream(stream, *, process_exit_code=None):
    if process_exit_code is not None:
        need(type(process_exit_code) is int, "PROCESS_EXIT_TYPE")
    reader, sha, total, partial = Reader(), hashlib.sha256(), 0, 0
    while True:
        line = stream.readline(MAX_LINE_BYTES + 1)
        if not line:
            break
        total += len(line)
        need(len(line) <= MAX_LINE_BYTES and total <= MAX_TOTAL_BYTES, "JOURNAL_BYTE_LIMIT")
        sha.update(line)
        if not line.endswith(b"\n"):
            partial = len(line)
            need(not reader.complete, "TRAILING_BYTES_AFTER_COMPLETE")
            break
        try:
            row = json.loads(line, object_pairs_hook=unique_object,
                             parse_float=reject_float, parse_constant=reject_float)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise ValueError("JOURNAL_JSON") from error
        reader.consume(row)
    return reader.report(process_exit_code=process_exit_code,
                         trailing_partial_bytes=partial, raw_sha256=sha.hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("journal", type=Path)
    parser.add_argument("--process-exit-code", type=int)
    args = parser.parse_args()
    try:
        with args.journal.open("rb") as stream:
            result = read_stream(stream, process_exit_code=args.process_exit_code)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0 if result["status"] == "COMPLETE_DECLARED_OBSERVATION" else 3
    except (OSError, ValueError) as error:
        print("lifecycle-readback: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
