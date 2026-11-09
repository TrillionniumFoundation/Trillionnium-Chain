#!/usr/bin/env python3
"""Check MMCS per-call frame arithmetic; do not infer a quantum query budget.

Consumes the new additive accounting fields in tagged_sha3_mmcs_binding's JSON.
This independently recomputes lengths, SHA3 padding and all aggregate counters.
Only explicitly reported ledgers are checked; extension/base parity has none.
It does not authenticate the report's source, measure Keccak invocations, or
turn an honest execution into an adversary lifetime bound.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

U64_MAX = (1 << 64) - 1
RATE = 72
SUFFIX = 8
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_CALLS = 8192
MAGIC = b"TRNM-W1-SHARED-HASH\0"
PROFILE = b"TRNM-W1-P3-SHA3-512-TAGGED-R1"
DESCRIPTOR = (
    b"p3=0.8.0;sha3=512;r=576;c=1024;F=18446744069414584321;E=X^2-7;binary;cap=0;"
    b"log_blowup=2;log_final_poly=0;max_log_arity=1;queries=64;pow=0;zk=0;"
    b"sha=d13,w7728,p27,q2,next1;carry=d14,w370,p180,q1,next0"
)
PREFIX = (MAGIC + struct.pack("<HH", 1, len(PROFILE)) + PROFILE
          + struct.pack("<H", len(DESCRIPTOR)) + DESCRIPTOR)
HEADER_BYTES = len(PREFIX) + 4 + 1 + 64
CACHED = "native-sha3-cached-prefix"
FRESH = "native-sha3-full-message"
ARTIFICIAL = "artificial-override-NOT-SHA3"
ARTIFICIAL_ORACLES = {
    "artificial-zero-leaf-oracle-NOT-SHA3": "Leaf",
    "artificial-zero-branch-oracle-NOT-SHA3": "Branch",
}
TOTAL_FIELDS = (
    "whole_message_calls", "complete_message_bytes",
    "complete_message_equivalent_absorption_blocks", "native_cached_prefix_calls",
    "native_cached_prefix_reused_block_equivalents",
    "native_cached_prefix_continuation_block_equivalents", "native_full_message_calls",
    "native_full_message_block_equivalents", "artificial_override_calls",
    "artificial_message_block_equivalents",
)


class AccountingError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AccountingError(message)


def u64(value: object) -> int:
    require(type(value) is int and 0 <= value <= U64_MAX, "expected a bounded u64 integer")
    return value


def frame_cost(header: int, payload: int) -> tuple[int, int]:
    size = u64(u64(header) + u64(payload) + SUFFIX)
    full_blocks, _ = divmod(size, RATE)
    return size, full_blocks + 1


def check_accounting(value: dict, *, overridden_role: str | None, recheck: bool) -> int:
    require(type(value) is dict, "accounting must be an object")
    require(value["schema"] == "p3.tagged-mmcs.sponge-accounting.v1", "accounting schema drift")
    require(type(value["rate_bytes"]) is int and value["rate_bytes"] == RATE, "rate drift")
    require(type(value["digest_bytes"]) is int and value["digest_bytes"] == 64, "digest drift")
    require(value["counting_unit"] == "complete-message-equivalent-absorption-blocks", "unit drift")
    for name in ("prefix_initializations_counted", "native_permutation_telemetry", "qualified"):
        require(value[name] is False, "unsupported positive claim: " + name)
    for name in ("native_permutation_calls", "adversary_lifetime_query_budget", "security_bits"):
        require(value[name] is None, "unsupported numeric claim: " + name)
    calls = value["calls"]
    require(type(calls) is list and 0 < len(calls) <= MAX_CALLS, "call list outside checker scope")
    totals = dict.fromkeys(TOTAL_FIELDS, 0)

    def add(name: str, amount: int) -> None:
        totals[name] = u64(totals[name] + amount)

    for index, call in enumerate(calls, 1):
        require(type(call) is dict and u64(call["call"]) == index, "call order/count mismatch")
        role = call["role"]
        require(role in ("Leaf", "Branch"), "uncovered hash role")
        require(u64(call["header_bytes"]) == HEADER_BYTES, "R1 header length drift")
        require(u64(call["length_suffix_bytes"]) == SUFFIX, "missing length suffix")
        payload = u64(call["payload_bytes"])
        require(payload % 8 == 0, "noncanonical field/digest payload length")
        if role == "Branch":
            require(payload == 128, "branch does not contain two full digests")
        size, blocks = frame_cost(HEADER_BYTES, payload)
        require(u64(call["complete_message_bytes"]) == size, "complete frame length mismatch")
        require(u64(call["complete_message_equivalent_absorption_blocks"]) == blocks,
                "padded block count mismatch")
        expected_evaluation = ARTIFICIAL if role == overridden_role else (FRESH if recheck else CACHED)
        require(call["evaluation"] == expected_evaluation, "native/artificial/prefix classification mismatch")
        add("whole_message_calls", 1)
        add("complete_message_bytes", size)
        add("complete_message_equivalent_absorption_blocks", blocks)
        if expected_evaluation == ARTIFICIAL:
            add("artificial_override_calls", 1)
            add("artificial_message_block_equivalents", blocks)
        elif expected_evaluation == CACHED:
            add("native_cached_prefix_calls", 1)
            reused = HEADER_BYTES // RATE
            add("native_cached_prefix_reused_block_equivalents", reused)
            add("native_cached_prefix_continuation_block_equivalents", blocks - reused)
        else:
            add("native_full_message_calls", 1)
            add("native_full_message_block_equivalents", blocks)
    actual = value["totals"]
    require(type(actual) is dict and set(actual) == set(totals), "counter set drift")
    for name, expected in totals.items():
        require(u64(actual[name]) == expected, "aggregate mismatch: " + name)
    return len(calls)


def check_collision(case: dict, overridden_role: str) -> None:
    collision = case["collision"]
    calls = case["collision_recheck_sponge_accounting"]["calls"]
    require(len(calls) == 2, "collision recheck must retain both calls")
    messages = [bytes.fromhex(collision[f"message{i}_hex"]) for i in range(2)]
    digest = bytes.fromhex(collision["full_digest_hex"])
    require(messages[0] != messages[1] and digest == bytes(64), "artificial witness drift")
    contexts = []
    for index, (message, call) in enumerate(zip(messages, calls)):
        role = collision[f"role{index}"]
        require(role == overridden_role == call["role"], "collision role mismatch")
        require(len(message) == call["complete_message_bytes"], "collision output length mismatch")
        require(len(message) >= HEADER_BYTES + SUFFIX, "truncated collision frame")
        contexts.append(message[HEADER_BYTES - 64:HEADER_BYTES])
        expected_header = PREFIX + struct.pack("<I", 1) + bytes([1 if role == "Leaf" else 2]) + contexts[-1]
        require(message[:HEADER_BYTES] == expected_header, "collision frame/profile/component mismatch")
        require(int.from_bytes(message[-SUFFIX:], "little") == call["payload_bytes"], "collision suffix mismatch")
    require(contexts[0] == contexts[1], "collision contexts differ")
    require(hashlib.sha3_512(messages[0]).digest() != hashlib.sha3_512(messages[1]).digest(),
            "fixture unexpectedly collides under real SHA3")
    expected_l = sum(divmod(len(message), RATE)[0] + 1 for message in messages)
    require(u64(case["candidate_collision_padded_block_total"]) == expected_l,
            "collision candidate L must sum both complete padded messages")


def check_report(report: dict) -> dict:
    require(type(report) is dict, "report must be an object")
    require(report["schema"] == "p3.tagged-mmcs.two-opening-reduction-check.v1", "report schema drift")
    require(report["qualification"] == "HOLD_NO_GO", "qualification drift")
    for name in ("qualified", "native_permutation_telemetry", "actual_w1_forgery",
                 "quantum_pcs_extraction", "fiat_shamir_knowledge_soundness", "production_activation"):
        require(report[name] is False, "unsupported positive report claim: " + name)
    for name in ("security_bits", "concrete_hash_binding_bits", "complete_noninteractive_security_bits"):
        require(report[name] is None, "unsupported numeric report claim: " + name)
    native = report["native"]
    require(type(native) is list and [u64(case["component"]) for case in native] == [1, 4], "native component coverage drift")
    checked_calls = 0
    for case in native:
        count = check_accounting(case["verification_sponge_accounting"], overridden_role=None, recheck=False)
        require(count == u64(case["native_pruned_hash_calls"]), "native whole-hash total mismatch")
        require(count <= u64(case["unpruned_upper_bound"]), "native whole-hash bound exceeded")
        checked_calls += count
    artificial = report["artificial_collision_extractions"]
    require(type(artificial) is list and len(artificial) == 2, "artificial coverage drift")
    require({case["oracle"] for case in artificial} == set(ARTIFICIAL_ORACLES), "artificial oracle drift")
    for case in artificial:
        require(case["real_sha3_collision"] is False and case["w1_forgery"] is False, "artificial scope drift")
        overridden = ARTIFICIAL_ORACLES[case["oracle"]]
        count = check_accounting(case["verification_sponge_accounting"], overridden_role=overridden, recheck=False)
        require(count == u64(case["verification_whole_hash_calls"]), "verification whole-hash total mismatch")
        require(count <= u64(case["verification_whole_hash_call_bound"]), "verification whole-hash bound exceeded")
        rechecks = check_accounting(case["collision_recheck_sponge_accounting"], overridden_role=overridden, recheck=True)
        require(rechecks == u64(case["independent_collision_recheck_calls"]) == 2, "independent recheck count mismatch")
        check_collision(case, overridden)
        checked_calls += count + rechecks
    return {
        "schema": "p3.tagged-mmcs.sponge-accounting-check.v1",
        "status": "ACCOUNTING_CONSISTENT", "checked_call_records": checked_calls,
        "qualified": False, "security_bits": None, "native_permutation_telemetry": False,
        "adversary_lifetime_query_budget": None,
    }


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def load_report(path: Path) -> tuple[dict, str]:
    with path.open("rb") as handle:
        raw = handle.read(MAX_REPORT_BYTES + 1)
    require(len(raw) <= MAX_REPORT_BYTES, "report exceeds local checker limit")
    value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    return value, hashlib.sha256(raw).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    try:
        report, digest = load_report(args.report)
        result = check_report(report)
        result["source_report_sha256"] = digest
    except (AccountingError, OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, "ACCOUNTING_REJECTED: " + str(error) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
