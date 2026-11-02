#!/usr/bin/env python3
"""Check complete correct-product/fresh-false-trace records, not native provenance.

The scalar Python material recipe independently reconstructs every canonical AB.
Exit 0 certifies record consistency only; native refusals, clocks, source and
hardware still require external exact-source execution evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import pon_w1_false_trace_reuse_reader_v1 as original

common = original.common
SCHEMA = "pon-w1-false-trace-correct-product-v1"
SELECTOR = "--false-trace-correct-product-v1"
SAMPLES, SEARCHES, ATTEMPT_BUDGET = 8, 4, 4096
CLASSES, TARGET = original.CLASSES, original.TARGET
PATHS = ("production",)
FALSE_FLAGS = original.FALSE_FLAGS.copy()
SETUP_SCOPE = "one-public-scalar-product-prefix-four-independent-false-trace-searches"
ATTACK_SCOPE = "actual-scalar-product-prefix-setup-and-all-searches-including-challenge-hashes-trial-retention-and-winner-clone"
VERIFY_SCOPE = original.VERIFY_SCOPE
MAX_LINE, MAX_BYTES = original.MAX_LINE, original.MAX_BYTES
measured = original.measured


def challenge(task, sample, search):
    return common.pon_hash(b"pon-w1-false-trace-correct-product-challenge-v1", task,
        bytes(8), sample.to_bytes(8, "little"), search.to_bytes(8, "little"))


class Records(original.Records):
    """Explicit separate schema; no mutation or auto-detection of old profiles."""
    def __init__(self):
        super().__init__()
        self.schema, self.selector, self.paths = SCHEMA, SELECTOR, PATHS
        self.max_records = 2 + len(CLASSES) + original.COHORTS + original.SEARCH_COUNT * (2 + len(PATHS))

    def add(self, row):
        common.require(type(row) is dict and row.get("schema") == SCHEMA,
                       "explicit correct-product V1 schema required")
        super().add(row)

    def add_campaign(self, row):
        common.require(self.campaign is None, "duplicate campaign")
        for key, value in (("samples", SAMPLES), ("searches_per_setup", SEARCHES),
                           ("attempt_budget", ATTEMPT_BUDGET), ("seed", 0)):
            common.require(common.integer(row[key], key) == value,
                           "fixed campaign parameter changed: " + key)
        common.require(row["selector"] == SELECTOR and row["paths"] == list(PATHS)
                       and row["classes"] == list(CLASSES) and row["target"] == TARGET,
                       "fixed selector/verifier/material/target grid changed")
        common.require(row["clock"] == "thread-cpu-and-monotonic-wall-ns"
                       and row["setup_reuse"] == SETUP_SCOPE,
                       "one actual public scalar-product-prefix setup required")
        common.require(row["attacker_timing_scope"] == ATTACK_SCOPE
                       and row["verifier_timing_scope"] == VERIFY_SCOPE,
                       "measurement scope changed")
        for flag in FALSE_FLAGS:
            common.require(row[flag] is False,
                           "observation cannot acquire proof/qualification: " + flag)
        measured(row["material_setup"], "material_setup")
        self.campaign = row

    def add_material(self, row):
        self.close_current()
        index = len(self.materials)
        common.require(index < len(CLASSES) and row["class"] == CLASSES[index]
                       and self.counts["cohort"] == index * SAMPLES,
                       "material coverage/order incomplete")
        name = row["class"]
        # This independent scalar Python dot-product implementation computes
        # canonical AB directly from the exact public recipe. It never reads a
        # caller-provided product or assumes C=0 for a structured task.
        a, b, task, prefix = common.material(name)
        source = "hash-generated-rank-checked" if name == "full-rank-field" else "synthetic-fixture"
        common.require(row["source"] == source and row["task"] == task.hex(),
                       "material source/task mismatch")
        common.require(common.hex_bytes(row["a_hex"], common.CELLS * 4, "A") == a
                       and common.hex_bytes(row["b_hex"], common.CELLS * 4, "B") == b,
                       "diagnostic matrix recipe mismatch")
        self.materials[name] = a, b, task, prefix

    def add_search(self, row):
        self.close_search()
        current = self.same_current(row)
        index = common.integer(row["search_index"], "search_index", SEARCHES - 1)
        common.require(index == len(current["searches"]), "independent search coverage/order incomplete")
        common.require(common.integer(row["setup_calls"], "search.setup_calls") == 0,
                       "public prefix rebuilt inside search")
        name, sample = current["key"]
        _, _, task, prefix = self.materials[name]
        context = challenge(task, sample, index)
        stream, last = common._trials(row, task, sample, prefix, context=context)
        if row["status"] == "target-hit-unverified":
            proof = prefix + bytes.fromhex(last["trace"])
            expected = {"challenge": context.hex(), "proof_sha256": common.sha(proof)}
            common.exact(row["winner"], expected, "search.winner")
            common.require(row["winner"] == expected, "winner does not bind full forged bytes")
        else:
            proof = None
            common.require(row["winner"] is None, "exhaustion cannot invent a winner")
        current["searches"].append({"index": index, "status": row["status"],
            "context": context, "proof": proof, "attempt_count": len(stream),
            "timing": measured(row["timing"], "search.timing"), "candidate": None, "verifiers": []})


def analyze(path):
    path = Path(path)
    common.require(path.is_file() and not path.is_symlink(), "regular retained JSONL required")
    records, digest, size, number = Records(), hashlib.sha256(), 0, 0
    with path.open("rb") as source:
        while True:
            line = source.readline(MAX_LINE + 1)
            if not line:
                break
            size += len(line)
            number += 1
            common.require(len(line) <= MAX_LINE and line.endswith(b"\n")
                           and size <= MAX_BYTES and number <= records.max_records,
                           "bounded complete JSONL required")
            digest.update(line)
            try:
                records.add(common.decode(line))
            except (ValueError, UnicodeError, RecursionError) as error:
                raise ValueError(f"line {number}: {error}") from error
    common.require(records.ended, "missing complete end record")
    return {"schema": "pon-w1-correct-product-false-trace-report-v1", "record_consistency": "PASS",
        "input_sha256": digest.hexdigest(), "input_bytes": size,
        "record_counts": dict(records.counts), "semantic_alerts": records.alerts,
        "actual_reuse_cohorts": original.summary(records),
        "canonical_product_independently_reconstructed": True,
        "complete_attack_bytes_reconstructed": True, "modeled_setup_division_used": False,
        "w1_transcript_replayed": False, "source_applicability_verified": False,
        "independent_verification": False, "fresh_measurement": False,
        "fastest_adversary_lower_bound": False, "public_attack_amplification_measured": False,
        "limitations": ["Native source, exact binary, execution, clocks and verdicts need external provenance.",
            "Public scalar AB preparation, all failed two-hash trials and winning-buffer serialization are charged.",
            "This deliberately generic AB setup is not the cheapest legal structured or amortized strategy.",
            "Material generation is separate; trial retention is included; later evidence output and network sending are excluded.",
            "Correct AB does not authenticate the independently forged final transcript digest.",
            "No product-first verifier, changed rejection order or proof/consensus format is enabled.",
            "No public service, admission fairness, hardware lower bound or model utility is established."],
        **FALSE_FLAGS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    try:
        report = analyze(args.input)
    except (OSError, ValueError, OverflowError) as error:
        print(json.dumps({"record_consistency": "FAIL", "error": str(error), **FALSE_FLAGS}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 1 if report["semantic_alerts"] else 0


if __name__ == "__main__":
    sys.exit(main())
