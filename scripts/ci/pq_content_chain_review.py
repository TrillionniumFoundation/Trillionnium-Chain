#!/usr/bin/env python3
"""Check one archived research cohort; never authorize installation or use.

Fixed copied records establish supplied-record consistency, not authenticated
execution, byte provenance, cryptographic soundness or ordinary Hepta use.
This is a reconstruction after scratch loss, not recovery of prior test logs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from pq_source_reader import SourceReadError, read_regular

PUBLICATION = "06233be630f8eff6cea59cd5111e5941135a4aa5"
RECORDED_RUNTIME = "6ea3bf3fe13d66333bba3a8c7b97e14b4319b39f"
INPUT = "evidence/pq-content-chain-review-20261110/input/"
PINS = {
    "native-result.json": (18354, "b6f25ae1ee224ab9a619b7d7993635284495f43bc28f05f7c2b1bd8eacd4dc4b"),
    "next-use-result.json": (1697, "a1d4948b0a904ac9d12da251222907c6cbe936f3b62fbf17a2412aa98043871a"),
    "next-use-observations.json": (2354, "8b3c438eea2d1199aa0d753c36e5d64506f042dd6984f9f819b02273d840e242"),
    "independent-execution-inputs.json": (3538, "f8814c99415b552c3664318dadb7dd1b692ea63e6171fa8ad9df5854872db00b"),
    "worker/ready.json": (4247, "cfd0380d9f66c025bbf0bd4da3d6a4d00594684e70c3ada5e163eae408b2911c"),
}
AUTHORITY = frozenset(("hepta_final_use", "independent_accepted", "installation_authorized",
    "prospective_accepted", "public_reward_eligible", "selection_authorized"))
NEXT_SCHEMA = "trnm.cell-sealed-research-next-use.v1"
HOST_SCOPE = "original independently pinned host snapshot; not sealed transport"
MATERIAL_PROFILE = "smollm2-public-v2-material-runtime-bridge-v1"


class ReviewError(ValueError):
    """Incomplete, malformed or inconsistent records are refused."""


def require(ok, message):
    if not ok:
        raise ReviewError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def strict_json(raw):
    require(type(raw) is bytes and len(raw) <= 65536, "invalid JSON byte input")
    # Bound nesting before the C JSON decoder, regardless of Python's global
    # recursion limit. Quoted and escaped brackets are not container nesting.
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            require(depth <= 64, "JSON nesting limit")
        elif byte in (93, 125):
            depth -= 1
            require(depth >= 0, "invalid JSON nesting")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def integer(value):
        require(len(value) <= 20, "oversized JSON integer")
        return int(value)

    def refused(value):
        raise ReviewError("floating-point/nonfinite JSON refused")

    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
            parse_int=integer, parse_float=refused, parse_constant=refused)
        pending = [(result, 0)]
        while pending:
            item, level = pending.pop()
            require(level <= 64, "JSON nesting limit")
            if type(item) is str:
                item.encode("utf-8")
            elif type(item) is dict:
                pending.extend((key, level + 1) for key in item)
                pending.extend((value, level + 1) for value in item.values())
            elif type(item) is list:
                pending.extend((value, level + 1) for value in item)
        return result
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ReviewError("invalid evidence JSON") from error


def number(value, label, low=0, high=(1 << 63) - 1):
    require(type(value) is int and low <= value <= high, "invalid integer: " + label)
    return value


def digest(value, width=64):
    require(type(value) is str and re.fullmatch("[0-9a-f]{%d}" % width, value) is not None,
            "invalid digest")
    return value


def flag(mapping, key, expected):
    require(type(mapping) is dict and mapping.get(key) is expected, "flag: " + key)


def authority(value):
    require(type(value) is dict and set(value) == AUTHORITY, "authority fields")
    for key in AUTHORITY:
        flag(value, key, False)


def evaluate(documents):
    """Check decoded supplied records; inspect additionally verifies fixed bytes."""
    try:
        require(type(documents) is dict and set(documents) == set(PINS), "document set")
        n, u, obs, x, ready = (documents[name] for name in PINS)
        require(all(type(item) is dict for item in (n, u, x, ready)), "object record")
        require(n["schema"] == "trnm.cell-sealed-research-native.v2", "native schema")
        require(x["schema"] == "trnm.cell-sealed-research-execution.v1", "input schema")
        require(u["schema"] == ready["schema"] == NEXT_SCHEMA, "next-use schema")
        require(type(obs) is list and len(obs) == 2, "two observation records required")
        require(canonical(n["actual_next_use"]) == canonical(u), "nested next-use mismatch")
        for record in [u, ready, *obs]:
            authority(record["authority"])
        for key in ("hepta_final_use", "installation_authorized", "m12_funding_admitted",
                    "original_hepta_owner_used", "production_activation", "independent_operators"):
            flag(n, key, False)
        for key in ("passed", "composition_worker_executed", "typed_snapshot_admitted", "loopback_only"):
            flag(n, key, True)
        require(n["actual_model_run"] == "observed_two_forwards", "execution scope")
        p = n["operation_pins"]
        require(type(p) is dict and set(p) == {"operation", "bep52_plan", "tcv1", "tcv2", "cts1", "chb1"}, "operation pins")
        for key, value in p.items():
            digest(value, 64 if key == "operation" else 128)
        require(x["operation"] == n["bep52"]["operation"] == p["operation"], "operation mismatch")
        require(x["descriptor"] == ready["descriptor"] == u["descriptor"]
            == n["handoff"]["descriptor"] == p["chb1"], "descriptor mismatch")
        require(u["content"] == ready["content"] == n["input"]["tcv2"] == p["tcv2"], "content mismatch")
        require(n["input"]["tcv1"] == n["bep52"]["tcv1"] == ready["version"] == p["tcv1"], "version mismatch")
        require(n["snapshot"]["cts1"] == p["cts1"] and n["bep52"]["plan"] == p["bep52_plan"], "snapshot/plan mismatch")
        flag(n["snapshot"], "compatibility_from_hashes_alone", False)
        for key in ("typed_snapshot_admitted", "composition_worker_executed"):
            flag(n["snapshot"], key, True)
        for key in ("transport_plan_includes_cts1", "independent_failure_domains"):
            flag(n["bep52"], key, False)
        for key in ("single_operator", "loopback_only", "empty_initial_cache", "complete_readback", "original_absolute_deadline"):
            flag(n["bep52"], key, True)
        for key in ("actual_target_readback", "anchored_reopen", "bep52_cache_absent", "source_cache_absent", "retained_from_bep52_received_cache"):
            flag(n["cold_restore"], key, True)
        flag(n["cold_restore"], "m12_funding_admitted", False)
        for key in ("bep52_cache_absent", "consumer_cache_absent", "publisher_cache_absent"):
            flag(n["sealed_cache_independence"], key, True)
        flag(n["handoff"], "single_operator_research_key", True)
        flag(n["input"], "independent_input_pins", True)
        digest(n["source_input_sha256"])
        digest(x["python_sha256"])
        number(x["threads"], "threads", 1, 256)
        members = n["bep52"]["members"]
        count = number(n["input"]["manifest_count"], "manifest count", 1, 4096)
        require(type(members) is list and len(members) == count, "member count")
        manifests, payload, downloaded, chunks = set(), 0, 0, 0
        for index, member in enumerate(members):
            require(number(member["index"], "member index") == index, "member ordering")
            manifests.add(digest(member["manifest"]))
            payload += number(member["payload_bytes"], "payload bytes", 1)
            downloaded += number(member["downloaded_bytes"], "download bytes", 1)
            chunks += number(member["downloaded_chunks"], "download chunks", 1)
            require(number(member["cached_chunks"], "cached chunks") == 0, "nonempty cache")
            require(member["downloaded_bytes"] == member["payload_bytes"], "incomplete download")
        require(len(manifests) == count, "duplicate member")
        require(payload == downloaded == number(n["input"]["payload_bytes"], "total bytes"), "payload sum")
        usage = n["bep52"]["consumer_usage"]
        for key, expected in (("completed_fetches", count), ("readback_completed", 1), ("readback_reserved_bytes", payload), ("readback_reserved_chunks", chunks)):
            require(number(usage[key], key) == expected, "readback accounting: " + key)
        require(number(n["cold_restore"]["consumer_chunks"], "restored chunks") == chunks, "restore count")
        require(number(n["handoff"]["kernel_descriptors"], "descriptor count") == count, "handoff count")
        require(number(n["handoff"]["environment_bytes"], "environment bytes") + number(n["handoff"]["model_bytes"], "model bytes") == payload, "handoff bytes")
        require(payload <= number(x["max_snapshot_bytes"], "snapshot budget", 1), "payload budget")
        process = n["process"]
        require(number(process["exit_code"], "native exit") == 0, "native exit")
        require(number(process["elapsed_ms"], "native wall", 1) <= 1000 * number(process["original_seconds"], "native deadline", 1), "deadline exceeded")
        flag(process, "termination_requested", False)
        flag(process, "sealed_bundles_held_until_supervisor_exit", True)
        require(process["termination_error"] is None, "termination error")
        supervisor = u["supervisor"]
        for key in ("child_spawned", "owned_child_exit_observed", "owned_child_reap_resolved", "waited_child_reaped"):
            flag(supervisor, key, True)
        require(number(supervisor["exit_code"], "worker exit") == 0 and supervisor["outcome"] == "success" and supervisor["cleanup_method"] == "wait4", "worker termination")
        require(supervisor["waited_child_observation_error"] is None and supervisor["stop_reason"] is None, "worker observation error")
        require(number(supervisor["observed_wall_ns"], "worker wall", 1) <= 1000000000 * number(supervisor["budget"]["wall_seconds"], "worker deadline", 1), "worker deadline")
        rss_limit = number(x["runtime_rss_bytes"], "RSS limit", 1)
        require(number(supervisor["waited_child_peak_rss_bytes"], "worker RSS", 1) <= rss_limit == number(supervisor["budget"]["rss_bytes"], "supervisor RSS limit", 1), "worker RSS limit")
        require(u["interpreter_and_native_dependencies"] == ready["interpreter_and_native_dependencies"] == HOST_SCOPE, "host dependency scope")
        flag(u, "connector_complete", True)
        require(u["failures"] == [] and number(u["observations"], "observation count") == len(obs), "execution failures/count")
        require(x["material_profile"] == ready["material_profile"] == ready["material_runtime_bridge"]["profile"] == MATERIAL_PROFILE, "material profile")
        require(canonical(x["environment_pins"]) == canonical(ready["environment_pins"]), "environment pins")
        for value in x["environment_pins"].values():
            digest(value)
        require(ready["runtime_snapshot_sha256"] == x["environment_pins"]["runtime/runtime-snapshot.json"], "runtime snapshot")
        require(n["handoff"]["worker_sha256"] == ready["worker_sha256"] == x["environment_pins"]["scripts/llm_cell_sealed_worker_v1.py"], "worker identity")
        require(ready["actual_loaded_parent"] == x["parent"]["adapter"] and ready["contract"] == x["parent"]["contract"] and ready["file_sha256"] == x["parent"]["file_sha256"], "parent identity")
        require(number(ready["generation"], "loaded generation", 1) == number(x["parent"]["generation"], "parent generation", 1), "parent generation")
        require(type(x["requests"]) is list and len(x["requests"]) == len(obs), "request count")
        seen, actions = set(), []
        for query, row in zip(x["requests"], obs):
            require(type(query) is dict and set(query) == {"request_id", "prompt"}, "request fields")
            require(type(query["request_id"]) is str and 1 <= len(query["request_id"]) <= 128 and type(query["prompt"]) is str and 1 <= len(query["prompt"]) <= 2048, "request strings")
            require(query["request_id"] not in seen, "duplicate request")
            seen.add(query["request_id"])
            require(row["schema"] == NEXT_SCHEMA and row["request_id"] == query["request_id"], "request join")
            require(row["input_sha256"] == hashlib.sha256(canonical(dict(schema="hepta-smollm-inference-input-v1", **query))).hexdigest(), "request byte hash")
            for key in ("descriptor", "content", "contract", "file_sha256"):
                require(row[key] == ready[key], "observation join: " + key)
            require(row["artifact"] == ready["actual_loaded_parent"], "loaded parent join")
            require(row["profile"] == "hepta-smollm-single-token-action-score-v1" and row["action_ids"] == ["no", "yes"], "action profile")
            scores = row["scores_q32"]
            require(type(scores) is list and len(scores) == 2, "score shape")
            for score in scores:
                number(score, "score", -(1 << 63))
            number(row["execution_ns"], "forward duration", 1)
            number(row["input_tokens"], "input tokens", 1)
            number(row["observed_rss_bytes"], "forward RSS", 1, rss_limit)
            digest(row["logits_sha256"])
            actions.append(row["action_ids"][max(range(2), key=lambda i: scores[i])])
        return {"schema": "trnm-pq-content-chain-review-v1", "status": "HOLD_NO_GO", "evidence_consistent": True,
            "ordinary_hepta_use_proved": False,
            "observed": {"operation": p["operation"], "pins": dict(p), "payload_bytes": payload, "members": count,
                "restored_chunks": chunks, "recorded_forwards": len(obs), "recorded_actions": actions},
            "hash_scope": {"CCH1_TCV2": "full-content claims in archived research observations",
                "TCV1_CTS1_CHB1": "structural/version/descriptor claims; no inherited security-bit bound",
                "source_and_interpreter_SHA256": "identity consistency; host dependencies are not sealed transport"},
            "actual_lifetime_failure_bound": None, "security_bits": None, "whole_chain_pq_qualified": False,
            "installation_authorized": False, "hepta_final_use": False, "model_efficacy_accepted": False,
            "production_activation": False,
            "limits": ["Record agreement is not execution authentication or a full-byte replay.",
                "No new native/model execution is performed by this reader.",
                "Single-operator loopback and research authority do not establish ordinary installation or FinalUse.",
                "Hash query complexities do not supply protocol or physical-cost bounds."]}
    except (KeyError, TypeError, AttributeError, IndexError, ValueError, RecursionError) as error:
        raise ReviewError("invalid/inconsistent evidence: " + str(error)) from error


def inspect(root):
    documents = {}
    for name, (size, expected) in PINS.items():
        raw = read_regular(Path(root), INPUT + name, size)
        require(len(raw) == size and hashlib.sha256(raw).hexdigest() == expected, "evidence pin: " + name)
        documents[name] = strict_json(raw)
    result = evaluate(documents)
    result["provenance"] = {"publication_commit": PUBLICATION, "recorded_runtime_commit": RECORDED_RUNTIME,
        "evidence_sha256_pins_checked": True, "execution_authenticated": False, "source_or_authority_authenticated": False}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    try:
        print(json.dumps(inspect(args.root), sort_keys=True))
    except (ReviewError, SourceReadError, OSError) as error:
        print("content-chain review refused: " + str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
