"""Finite execution accounting for PoN fork witnesses and paid view deficits.

This validates a declared finite event model. It does NOT authenticate native
execution, a physical clock, unseen private branches, initial quantum state,
W1 validity, or a probabilistic environment envelope. Native labels and hashes
are not trust roots. All such qualification flags remain explicitly false.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any


SCHEMA = "pon-native-execution-certificate-v1"
BASE_COMMIT = "2789e9d9999920d858c1b65d3bff29122079cb4e"
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE_FILES = (
    "formal/pon-nakamoto-v1/native_execution_certificate.py",
    "formal/pon-nakamoto-v1/test_native_execution_certificate.py",
    "formal/pon-nakamoto-v1/NATIVE_EXECUTION_CERTIFICATE_V1.md",
    "trillionnium/crates/trnm-pon-node/src/store.rs",
    "trillionnium/crates/trnm-pon-node/src/consensus.rs",
    "trillionnium/crates/trnm-pon-node/src/store/growth/recovery.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/request_observation.rs",
    "config/pon/devnet-v1.json",
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class CertificateError(ValueError):
    """A failed declared-record invariant; never a consensus Invalid verdict."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise CertificateError(code)


def integer(value: Any, code: str, *, minimum: int = 0) -> int:
    require(type(value) is int and value >= minimum, code)
    return value


def label(value: Any, code: str) -> str:
    require(type(value) is str and 0 < len(value) <= 256, code)
    return value


def fields(value: Any, names: set[str], code: str) -> dict:
    require(type(value) is dict and set(value) == names, code)
    return value


def boolean(value: Any, code: str) -> bool:
    require(type(value) is bool, code)
    return value


def unique_rows(value: Any, code: str) -> list:
    require(type(value) is list, code)
    require(all(type(row) is str for row in value), code)
    require(len(set(value)) == len(value), code)
    return value


def strict_json(text: str) -> Any:
    def pairs(rows):
        out = {}
        for key, value in rows:
            if key in out:
                raise CertificateError("DUPLICATE_JSON_KEY:" + key)
            out[key] = value
        return out
    def nonfinite(value):
        raise CertificateError("NONFINITE_JSON:" + value)
    return json.loads(text, object_pairs_hook=pairs, parse_constant=nonfinite)


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


@dataclass(frozen=True)
class Cut:
    seq: int
    time: int
    ready: frozenset[str]
    views: dict[str, frozenset[str]]
    active: dict[str, str]
    generations: dict[str, int]


def view_deficits(reference: int, maximum: int, selected: int) -> dict:
    """Exact capped split: availability + selection = (reference-selected)+."""
    for value in (reference, maximum, selected):
        integer(value, "SCORE")
    require(selected <= maximum, "SELECTED_EXCEEDS_COMPLETE_VIEW_MAXIMUM")
    unavailable = max(0, reference - maximum)
    selection = max(0, min(reference, maximum) - selected)
    total = max(0, reference - selected)
    require(unavailable + selection == total, "DEFICIT_IDENTITY")
    return {"availability_score_deficit": unavailable,
            "selection_score_deficit": selection,
            "raw_selection_score_deficit": maximum - selected,
            "total_comparison_score_deficit": total}


class Execution:
    """Replay complete-data model events without assuming instantaneous argmax."""

    def __init__(self, document: dict):
        self.document = document
        self._validate_header()
        self.blocks = {"g": {"id": "g", "parent": None, "weight": 0,
                             "producer": "G", "miner": "genesis", "header_timestamp": 0}}
        for block in document["blocks"]:
            fields(block, {"id", "parent", "weight", "producer", "miner", "header_timestamp"},
                   "BLOCK_FIELDS")
            block_id = label(block["id"], "BLOCK_ID")
            require(block_id not in self.blocks, "DUPLICATE_BLOCK_ID")
            label(block["parent"], "PARENT_ID")
            integer(block["weight"], "POSITIVE_BLOCK_WEIGHT", minimum=1)
            integer(block["header_timestamp"], "HEADER_TIMESTAMP")
            require(block["producer"] in ("H", "A"), "PRODUCER_LABEL")
            if block["producer"] == "H":
                require(block["miner"] in self.owners, "UNKNOWN_HONEST_MINER")
            else:
                require(block["miner"] == "adversary", "ADVERSARY_ACCOUNT")
            self.blocks[block_id] = dict(block)
        self.paths: dict[str, tuple[str, ...]] = {"g": ("g",)}
        self.scores = {"g": 0}
        visiting: set[str] = set()
        def walk(block_id: str):
            require(block_id in self.blocks, "UNKNOWN_BLOCK_PARENT")
            if block_id in self.paths:
                return
            require(block_id not in visiting, "BLOCK_CYCLE")
            visiting.add(block_id)
            parent = self.blocks[block_id]["parent"]
            walk(parent)
            self.paths[block_id] = self.paths[parent] + (block_id,)
            self.scores[block_id] = self.scores[parent] + self.blocks[block_id]["weight"]
            visiting.remove(block_id)
        for block_id in self.blocks:
            walk(block_id)
        self.ready_at: dict[str, tuple[int, int]] = {}
        self.bindings: dict[str, dict] = {}
        self.observations: dict[str, dict] = {}
        self.transitions: list[dict] = []
        self.resources: list[dict] = []
        self.cuts: list[Cut] = []
        self._replay()

    def _validate_header(self) -> None:
        doc = fields(self.document, {"schema", "provenance", "clock", "scope", "owners",
                                     "initial", "blocks", "events", "comparisons"},
                     "CERTIFICATE_FIELDS")
        require(doc["schema"] == SCHEMA, "SCHEMA")
        provenance = fields(doc["provenance"], {"origin", "role", "source_commit",
                                               "evidence_id", "raw_artifact_hashes"},
                            "PROVENANCE_FIELDS")
        require(provenance["origin"] in ("model_fixture", "observed_native"), "ORIGIN")
        expected_role = {"model_fixture": "declared_finite_model",
                         "observed_native": "unattested_native_record_conversion"}
        require(provenance["role"] == expected_role[provenance["origin"]], "ORIGIN_ROLE_MISMATCH")
        require(type(provenance["source_commit"]) is str
                and HEX40.fullmatch(provenance["source_commit"]) is not None, "SOURCE_COMMIT")
        label(provenance["evidence_id"], "EVIDENCE_ID")
        require(type(provenance["raw_artifact_hashes"]) is dict, "RAW_HASHES")
        for name, value in provenance["raw_artifact_hashes"].items():
            label(name, "RAW_ARTIFACT_NAME")
            require(type(value) is str and HEX64.fullmatch(value) is not None, "RAW_HASH")
        clock = fields(doc["clock"], {"domain", "unit", "binding_receipt"}, "CLOCK_FIELDS")
        require(clock["domain"] in ("model_ticks", "physical_monotonic", "unknown"), "CLOCK_DOMAIN")
        require(clock["unit"] in ("tick", "ns", "unknown"), "CLOCK_UNIT")
        if clock["domain"] == "model_ticks":
            require(clock["unit"] == "tick", "CLOCK_UNIT_MISMATCH")
        if clock["domain"] == "physical_monotonic":
            require(clock["unit"] == "ns", "CLOCK_UNIT_MISMATCH")
        require(clock["binding_receipt"] is None or type(clock["binding_receipt"]) is str,
                "CLOCK_BINDING_RECEIPT")
        scope = fields(doc["scope"], {"execution_id", "first_seq", "last_seq", "start_time",
                                     "end_time", "nodes", "declared_all_branches",
                                     "declared_no_missing_events"}, "SCOPE_FIELDS")
        label(scope["execution_id"], "EXECUTION_ID")
        require(type(scope["first_seq"]) is int and scope["first_seq"] == 0, "FIRST_SEQ")
        for name in ("last_seq", "start_time", "end_time"):
            integer(scope[name], "SCOPE_" + name.upper())
        require(scope["end_time"] >= scope["start_time"], "SCOPE_TIME_ORDER")
        nodes = unique_rows(scope["nodes"], "SCOPE_NODES")
        require(0 < len(nodes) <= 32, "NODE_LIMIT")
        for node in nodes:
            label(node, "NODE_ID")
        for name in ("declared_all_branches", "declared_no_missing_events"):
            boolean(scope[name], "SCOPE_" + name.upper())
        require(type(doc["owners"]) is list, "OWNERS")
        self.owners = {}
        for owner in doc["owners"]:
            fields(owner, {"node", "owner_instance", "namespace", "configuration_digest"},
                   "OWNER_FIELDS")
            for name in ("node", "owner_instance", "namespace"):
                label(owner[name], "OWNER_" + name.upper())
            require(owner["node"] not in self.owners, "DUPLICATE_NODE_OWNER")
            require(type(owner["configuration_digest"]) is str
                    and HEX64.fullmatch(owner["configuration_digest"]) is not None, "OWNER_CONFIG")
            self.owners[owner["node"]] = dict(owner)
        require(set(self.owners) == set(nodes), "OWNER_SCOPE_MISMATCH")
        require(len({o["owner_instance"] for o in doc["owners"]}) == len(nodes), "SHARED_OWNER_INSTANCE")
        require(len({o["configuration_digest"] for o in doc["owners"]}) == 1,
                "INCOMPATIBLE_MODEL_CONFIGURATION")
        require(type(doc["blocks"]) is list and len(doc["blocks"]) <= 512, "BLOCK_LIMIT")
        require(type(doc["events"]) is list and len(doc["events"]) <= 8192, "EVENT_LIMIT")
        require(scope["last_seq"] == len(doc["events"]), "EVENT_COUNT_COVERAGE")
        require((len(doc["blocks"]) + 1) * (len(doc["events"]) + 1) * len(nodes) <= 2_000_000,
                "FINITE_MODEL_STATE_LIMIT")
        require(type(doc["comparisons"]) is list and len(doc["comparisons"]) <= 256, "COMPARISON_LIMIT")
        names = []
        for row in doc["comparisons"]:
            fields(row, {"name", "confirmed_observation", "later_observation"}, "COMPARISON_FIELDS")
            names.append(label(row["name"], "COMPARISON_NAME"))
            label(row["confirmed_observation"], "CONFIRMED_OBSERVATION")
            label(row["later_observation"], "LATER_OBSERVATION")
        require(len(names) == len(set(names)), "DUPLICATE_COMPARISON")

    def contains(self, tip: str, included: str) -> bool:
        return included in self.paths[tip]

    def lca(self, left: str, right: str) -> str:
        common = set(self.paths[left]).intersection(self.paths[right])
        return max(common, key=lambda block: len(self.paths[block]))

    def suffix(self, tip: str, ancestor: str) -> tuple[str, ...]:
        path = self.paths[tip]
        return path[path.index(ancestor) + 1:]

    def score(self, tip: str) -> int:
        require(tip in self.scores, "UNKNOWN_TIP")
        return self.scores[tip]

    def maximum(self, available: set[str] | frozenset[str]) -> int:
        require(bool(available), "EMPTY_AVAILABLE_VIEW")
        return max(self.score(block) for block in available)

    def observation(self, tip: str, included: str | None) -> dict:
        if included is None:
            return {"included": None, "confirmed": None}
        require(included in self.blocks and included != "g", "INCLUDED_BLOCK")
        present = self.contains(tip, included)
        depth = len(self.paths[tip]) - len(self.paths[included]) if present else None
        delta = self.score(tip) - self.score(included) if present else None
        threshold = 6 * self.blocks[included]["weight"]
        return {"included": included, "present": present, "depth": depth,
                "work_delta": delta, "work_threshold": threshold,
                "confirmed": bool(present and depth >= 6 and delta >= threshold),
                "formula_profile": "six_successors_and_six_times_supplied_inclusion_weight",
                "native_weight_relation_validated": False}

    def _replay(self) -> None:
        doc = self.document
        initial = fields(doc["initial"], {"ready", "available", "active", "generations",
                                          "complete_material", "residual_state"}, "INITIAL_FIELDS")
        material = fields(initial["complete_material"], {"body", "proof", "application"},
                          "INITIAL_MATERIAL_FIELDS")
        require(all(type(v) is bool and v for v in material.values()), "INITIAL_INCOMPLETE_MATERIAL")
        residual = fields(initial["residual_state"], {"status", "reference"}, "RESIDUAL_STATE_FIELDS")
        require(residual["status"] in ("declared_empty_model", "declared_external_bound", "unknown"),
                "RESIDUAL_STATE_STATUS")
        require(residual["reference"] is None or type(residual["reference"]) is str, "RESIDUAL_REFERENCE")
        ready = set(unique_rows(initial["ready"], "INITIAL_READY"))
        require("g" in ready and ready <= self.blocks.keys(), "INITIAL_READY_IDS")
        for block in ready:
            require(set(self.paths[block]) <= ready, "INITIAL_READY_NOT_PREFIX_CLOSED")
            self.ready_at[block] = (0, doc["scope"]["start_time"])
        available = {}
        for name in ("available", "active", "generations"):
            require(type(initial[name]) is dict and set(initial[name]) == set(self.owners),
                    "INITIAL_OWNER_COVERAGE:" + name)
        active = dict(initial["active"])
        generations = dict(initial["generations"])
        for node in self.owners:
            view = set(unique_rows(initial["available"][node], "INITIAL_VIEW"))
            require("g" in view and view <= ready, "INITIAL_VIEW_READY")
            for block in view:
                require(set(self.paths[block]) <= view, "INITIAL_VIEW_NOT_PREFIX_CLOSED")
            available[node] = view
            require(active[node] in view, "INITIAL_ACTIVE_UNAVAILABLE")
            integer(generations[node], "INITIAL_GENERATION")
        def record(seq: int, time: int) -> Cut:
            cut = Cut(seq, time, frozenset(ready),
                      {node: frozenset(view) for node, view in available.items()},
                      dict(active), dict(generations))
            self.cuts.append(cut)
            return cut
        record(0, doc["scope"]["start_time"])
        last_time = doc["scope"]["start_time"]
        for expected_seq, event in enumerate(doc["events"], 1):
            require(type(event) is dict, "EVENT_OBJECT")
            require(type(event.get("seq")) is int and event["seq"] == expected_seq,
                    "EVENT_TOTAL_ORDER_OR_GAP")
            time = integer(event.get("time"), "EVENT_CLOCK_MISSING")
            require(last_time <= time <= doc["scope"]["end_time"], "EVENT_CLOCK_ORDER")
            last_time = time
            kind = event.get("kind")
            common = {"seq", "time", "kind"}
            if kind == "ready":
                fields(event, common | {"block", "complete_material"}, "READY_FIELDS")
                block = event["block"]
                require(block in self.blocks and block not in ready, "READY_ID_OR_DUPLICATE_CREDIT")
                proof = fields(event["complete_material"], {"body", "proof", "application"},
                               "READY_MATERIAL_FIELDS")
                require(all(type(v) is bool and v for v in proof.values()), "READY_INCOMPLETE_MATERIAL")
                require(self.blocks[block]["parent"] in ready, "READY_ANCESTRY_INCOMPLETE")
                if self.blocks[block]["producer"] == "H":
                    require(block in self.bindings, "HONEST_READY_WITHOUT_PARENT_BINDING")
                ready.add(block)
                self.ready_at[block] = (expected_seq, time)
            elif kind == "resource":
                fields(event, common | {"actor", "account", "amount"}, "RESOURCE_FIELDS")
                require(event["actor"] in self.owners or event["actor"] == "adversary", "RESOURCE_OWNER")
                require(event["account"] in ("logical_gates", "cpu_ns", "bytes"), "RESOURCE_ACCOUNT")
                integer(event["amount"], "RESOURCE_AMOUNT")
                self.resources.append(dict(event))
            elif kind in ("available", "header", "lose_available", "bind", "select", "observe"):
                node = event.get("node")
                require(node in self.owners, "UNKNOWN_EVENT_OWNER")
                require(event.get("owner_instance") == self.owners[node]["owner_instance"],
                        "OWNER_INSTANCE_MISMATCH")
                owner_fields = common | {"node", "owner_instance"}
                if kind in ("available", "header", "lose_available"):
                    fields(event, owner_fields | {"generation", "block"}, "VIEW_EVENT_FIELDS")
                    require(type(event["generation"]) is int and event["generation"] == generations[node],
                            "STALE_VIEW_GENERATION")
                    block = event["block"]
                    require(block in self.blocks, "UNKNOWN_VIEW_BLOCK")
                    if kind == "available":
                        require(block in ready, "AVAILABLE_BEFORE_READY")
                        available[node].update(self.paths[block])
                    elif kind == "lose_available":
                        require(block != "g" and block in available[node], "AVAILABILITY_LOSS_ID")
                        available[node] = {x for x in available[node] if not self.contains(x, block)}
                    # header-only reception changes no eligible/full-data view.
                elif kind == "bind":
                    fields(event, owner_fields | {"generation", "block", "parent"}, "BIND_FIELDS")
                    require(type(event["generation"]) is int and event["generation"] == generations[node],
                            "STALE_BIND_GENERATION")
                    block, parent = event["block"], event["parent"]
                    require(block in self.blocks and block not in ready and block not in self.bindings,
                            "BIND_ID")
                    require(self.blocks[block]["producer"] == "H" and self.blocks[block]["miner"] == node,
                            "BIND_PRODUCER")
                    require(self.blocks[block]["parent"] == parent and parent == active[node],
                            "BIND_PARENT_ACTIVE_MISMATCH")
                    require(parent in available[node], "BIND_PARENT_UNAVAILABLE")
                    maximum = self.maximum(available[node])
                    self.bindings[block] = {"seq": expected_seq, "time": time, "node": node,
                                            "parent": parent, "maximum": maximum,
                                            "parent_score": self.score(parent),
                                            "raw_selection_deficit": maximum - self.score(parent)}
                elif kind == "select":
                    fields(event, owner_fields | {"generation_before", "generation_after", "candidate",
                                                   "selected"}, "SELECT_FIELDS")
                    require(type(event["generation_before"]) is int
                            and event["generation_before"] == generations[node], "STALE_SELECT_GENERATION")
                    candidate = event["candidate"]
                    require(candidate in available[node], "SELECT_CANDIDATE_UNAVAILABLE")
                    old = active[node]
                    require(old in available[node], "SELECT_INCUMBENT_UNAVAILABLE")
                    selected = candidate if self.score(candidate) > self.score(old) else old
                    require(event["selected"] == selected, "NATIVE_STRICT_SELECTION_MISMATCH")
                    generation = generations[node] + int(selected != old)
                    require(type(event["generation_after"]) is int
                            and event["generation_after"] == generation, "SELECT_GENERATION_TRANSITION")
                    active[node], generations[node] = selected, generation
                    self.transitions.append({"seq": expected_seq, "time": time, "node": node,
                                             "from": old, "to": selected,
                                             "raw_selection_deficit": self.maximum(available[node]) - self.score(selected)})
                elif kind == "observe":
                    fields(event, owner_fields | {"generation", "tip", "included", "claim_confirmed",
                                                   "observation_id"}, "OBSERVATION_FIELDS")
                    require(type(event["generation"]) is int and event["generation"] == generations[node],
                            "STALE_OBSERVATION_GENERATION")
                    require(event["tip"] == active[node], "OBSERVED_TIP_MISMATCH")
                    require(active[node] in available[node], "OBSERVED_ACTIVE_UNAVAILABLE")
                    observation_id = label(event["observation_id"], "OBSERVATION_ID")
                    require(observation_id not in self.observations, "DUPLICATE_OBSERVATION_ID")
                    result = self.observation(active[node], event["included"])
                    claimed = event["claim_confirmed"]
                    require((claimed is None if result["confirmed"] is None else type(claimed) is bool)
                            and claimed == result["confirmed"], "CONFIRMATION_CLAIM_MISMATCH")
                    if event["included"] is not None:
                        require(event["included"] in available[node], "INCLUDED_PACKET_UNAVAILABLE")
                    self.observations[observation_id] = {
                        "seq": expected_seq, "time": time, "node": node, "tip": active[node], **result}
            else:
                raise CertificateError("UNKNOWN_EVENT_KIND")
            record(expected_seq, time)
        if doc["scope"]["declared_all_branches"] and doc["scope"]["declared_no_missing_events"]:
            require(ready == set(self.blocks), "DECLARED_MODEL_HAS_UNACCOUNTED_OUTPUTS")

    def compare(self, query: dict) -> dict:
        earlier = self.observations.get(query["confirmed_observation"])
        later = self.observations.get(query["later_observation"])
        require(earlier is not None and later is not None, "COMPARISON_UNKNOWN_OBSERVATION")
        require(earlier["confirmed"] is True, "COMPARISON_SOURCE_NOT_CONFIRMED")
        require(later["seq"] >= earlier["seq"], "COMPARISON_TIME_REVERSED")
        b, c0, competing = earlier["included"], earlier["tip"], later["tip"]
        if self.contains(competing, b):
            return {"name": query["name"], "outcome": "no_prefix_failure_in_this_pair",
                    "probability_bound": None}
        tau, cut = self.cuts[earlier["seq"]], self.cuts[later["seq"]]
        parent_b = self.blocks[b]["parent"]
        k_b = self.score(c0) - self.score(parent_b)
        require(k_b >= 7 * self.blocks[b]["weight"], "SIX_SUCCESSOR_INCLUSION_BOUND")
        a = self.lca(c0, competing)
        suffix = self.suffix(competing, a)
        inventory = sum(self.blocks[x]["weight"] for x in suffix if x in tau.ready)
        a_comp = sum(self.blocks[x]["weight"] for x in suffix
                     if x not in tau.ready and self.blocks[x]["producer"] == "A")
        h_comp = sum(self.blocks[x]["weight"] for x in suffix
                     if x not in tau.ready and self.blocks[x]["producer"] == "H")
        new = cut.ready - tau.ready
        a_all = sum(self.blocks[x]["weight"] for x in new if self.blocks[x]["producer"] == "A")
        h_all_off = sum(self.blocks[x]["weight"] for x in new
                        if self.blocks[x]["producer"] == "H" and not self.contains(x, b))
        b0 = max((max(0, self.score(x) - self.score(parent_b)) for x in tau.ready
                  if not self.contains(x, b)), default=0)
        reference_candidates = {x for view in cut.views.values() for x in view if self.contains(x, b)}
        reference = max([self.score(c0)] + [self.score(x) for x in reference_candidates])
        growth = reference - self.score(c0)
        maximum = self.maximum(cut.views[later["node"]])
        deficits = view_deficits(reference, maximum, self.score(competing))
        loss = deficits["total_comparison_score_deficit"]
        exact_left = inventory + a_comp + h_comp + loss
        exact_right = self.score(c0) - self.score(a) + growth
        all_left = b0 + a_all + h_all_off + loss
        all_right = k_b + growth
        require(inventory + a_comp + h_comp == self.score(competing) - self.score(a), "CUT_DECOMPOSITION")
        require(exact_left >= exact_right and all_left >= all_right, "PAID_DEFICIT_WITNESS_FAILURE")
        own_b = [x for x in cut.views[later["node"]] if self.contains(x, b)]
        best_b_score = max((self.score(x) for x in own_b), default=None)
        q = deficits["raw_selection_score_deficit"]
        early_threshold = (best_b_score - self.score(parent_b) - q - b0 - h_all_off
                           if best_b_score is not None else None)
        if early_threshold is not None:
            require(a_all >= early_threshold, "PARTIAL_VIEW_EARLY_BOUND")
        first_removal = next((event["seq"] for event in self.transitions
                              if earlier["seq"] < event["seq"] <= later["seq"]
                              and event["node"] == earlier["node"]
                              and self.contains(event["from"], b) and not self.contains(event["to"], b)), None)
        accounts: dict[str, int] = {}
        for row in self.resources:
            if earlier["seq"] < row["seq"] <= later["seq"] and row["actor"] == "adversary":
                accounts[row["account"]] = accounts.get(row["account"], 0) + row["amount"]
        return {
            "name": query["name"], "outcome": "prefix_failure_with_paid_deficit_witness",
            "tau_seq": tau.seq, "comparison_seq": cut.seq, "tau_time": tau.time,
            "comparison_time": cut.time, "observer": later["node"], "included": b,
            "confirmed_tip": c0, "selected_tip": competing, "lca": a,
            "confirmation_cut_from_parent": k_b,
            "inclusion_weight": self.blocks[b]["weight"],
            "reference_score": reference, "reference_growth": growth,
            "reference_definition": "max(original_confirmation_score, b_scores_in_declared_complete_views)",
            "view_maximum_score": maximum, "selected_score": self.score(competing),
            **deficits,
            "competing_suffix_inventory_all_producers": inventory,
            "new_adversarial_competing_weight": a_comp,
            "new_honest_competing_weight": h_comp,
            "relative_initial_inventory_all_branches": b0,
            "new_adversarial_all_branch_weight": a_all,
            "new_honest_all_b_free_weight": h_all_off,
            "exact_cut_left": exact_left, "exact_cut_right": exact_right,
            "global_left": all_left, "global_right": all_right,
            "first_local_removal_seq": first_removal,
            "early_known_b_reference_score": best_b_score,
            "early_required_new_attack_weight": early_threshold,
            "early_threshold_is_positive": early_threshold is not None and early_threshold > 0,
            "adversarial_resource_accounts_as_declared": accounts,
            "physical_cost_authenticated": False, "probability_bound": None,
        }

    def check_window_contract(self, confirmed_observation: str, *, delta_pub: int, gamma: int,
                              parent_lag: int, observer_lag: int, maximum_weight: int) -> dict:
        """Check explicit finite-model lag premises; does not estimate their probability.

        Late/censored deadlines are reported, not assumed to have succeeded.
        This is an audit of supplied event records, never an actual WAN SLO.
        """
        for value in (delta_pub, gamma, parent_lag, observer_lag):
            integer(value, "WINDOW_PARAMETER")
        integer(maximum_weight, "MAXIMUM_WEIGHT", minimum=1)
        source = self.observations.get(confirmed_observation)
        require(source is not None and source["confirmed"] is True, "WINDOW_SOURCE")
        b, tau, start = source["included"], source["seq"], source["time"]
        failures: list[dict] = []
        if not (self.document["scope"]["declared_all_branches"]
                and self.document["scope"]["declared_no_missing_events"]):
            failures.append({"code": "INCOMPLETE_DECLARED_MODEL_WINDOW"})
        if self.document["clock"]["domain"] == "unknown":
            failures.append({"code": "UNSPECIFIED_MODEL_CLOCK"})
        for block, row in self.blocks.items():
            if row["weight"] > maximum_weight:
                failures.append({"code": "BLOCK_WEIGHT_CAP", "block": block})
        for block, binding in self.bindings.items():
            if block in self.ready_at and self.ready_at[block][0] > tau:
                duration = self.ready_at[block][1] - binding["time"]
                if duration > gamma:
                    failures.append({"code": "STALE_PARENT_COMPLETION_LAG", "block": block,
                                     "observed_duration": duration})
                if binding["seq"] > tau and binding["raw_selection_deficit"] > parent_lag:
                    failures.append({"code": "PARENT_SELECTION_SCORE_LAG", "block": block,
                                     "observed_score_lag": binding["raw_selection_deficit"]})
        for obs in self.observations.values():
            if obs["seq"] > tau:
                cut = self.cuts[obs["seq"]]
                lag = self.maximum(cut.views[obs["node"]]) - self.score(obs["tip"])
                if lag > observer_lag:
                    failures.append({"code": "OBSERVATION_SELECTION_SCORE_LAG", "seq": obs["seq"],
                                     "observed_score_lag": lag})
        def delivery_check(label_: str, score: int, ready_time: int) -> None:
            deadline = ready_time + delta_pub
            if deadline > self.document["scope"]["end_time"]:
                failures.append({"code": "DELIVERY_DEADLINE_CENSORED", "block": label_})
                return
            # Delivery "by deadline" means after all supplied events at that
            # physical time. Comparisons retain their own earlier causal cut.
            boundary = max((cut for cut in self.cuts if cut.time <= deadline),
                           key=lambda cut: cut.seq)
            checked = [boundary] + [cut for cut in self.cuts if cut.time > deadline]
            for cut in checked:
                for node, view in cut.views.items():
                    best = max((self.score(x) for x in view if self.contains(x, b)), default=None)
                    if best is None or best < score:
                        failures.append({"code": "FULL_VIEW_DELIVERY_OR_RETENTION_DEFICIT",
                                         "block": label_, "node": node, "seq": cut.seq})
                        return
        delivery_check(source["tip"], self.score(source["tip"]), start)
        length = delta_pub + gamma
        pacers = []
        last = None
        for cut in self.cuts[tau+1:]:
            event = self.document["events"][cut.seq - 1]
            if event["kind"] != "ready":
                continue
            block = event["block"]
            if self.blocks[block]["producer"] != "H" or cut.time <= start + length:
                continue
            if last is None or cut.time > last + length:
                last = cut.time
                weight = self.blocks[block]["weight"]
                pacers.append({"block": block, "seq": cut.seq, "time": cut.time,
                               "weight": weight, "paid_progress": max(0, weight - parent_lag)})
                if not self.contains(block, b):
                    failures.append({"code": "PACER_OUTSIDE_TARGET_PREFIX_REQUIRES_STOPPING", "block": block})
                else:
                    delivery_check(block, self.score(block), cut.time)
        return {"scope": "finite_declared_model_contract_check", "failures": failures,
                "model_contracts_hold_on_checked_complete_window": not failures,
                "pacers": pacers, "parent_lag_is_paid_per_pacer": True,
                "checks_are_not_a_stopped_pacer_theorem": True,
                "physical_slo_qualified": False, "probabilistic_failure_bound": None}

    def report(self) -> dict:
        doc = self.document
        refusals = ["NATIVE_LIFECYCLE_EXPORT_NOT_AUTHENTICATED", "PHYSICAL_CLOCK_NOT_AUTHENTICATED",
                    "PRIVATE_INITIAL_INVENTORY_NOT_AUTHENTICATED", "WORLD_ALL_BRANCH_COVERAGE_NOT_AUTHENTICATED",
                    "W1_AND_APPLICATION_VALIDITY_NOT_REPLAYED", "PROBABILISTIC_ENVIRONMENT_ENVELOPE_NOT_PROVED"]
        if doc["provenance"]["origin"] == "model_fixture":
            refusals.insert(0, "MODEL_FIXTURE_IS_NOT_NATIVE_OBSERVATION")
        if doc["clock"]["domain"] == "unknown" or doc["clock"]["binding_receipt"] is None:
            refusals.append("NO_INDEPENDENT_CLOCK_BINDING")
        if doc["initial"]["residual_state"]["status"] == "unknown":
            refusals.append("UNKNOWN_INITIAL_RESIDUAL_STATE")
        if not doc["scope"]["declared_all_branches"]:
            refusals.append("NO_DECLARED_ALL_BRANCH_COVERAGE")
        if not doc["scope"]["declared_no_missing_events"]:
            refusals.append("NO_DECLARED_COMPLETE_EVENT_WINDOW")
        return {"schema": "pon-native-execution-accounting-result-v1",
                "certificate_sha256": digest(doc), "origin_as_declared": doc["provenance"]["origin"],
                "record_schema_and_finite_algebra_valid": True,
                "complete_declared_model_checked": bool(doc["scope"]["declared_all_branches"]
                                                         and doc["scope"]["declared_no_missing_events"]),
                "source_commit_as_declared": doc["provenance"]["source_commit"],
                "events_checked": len(doc["events"]), "blocks_in_declared_universe": len(self.blocks),
                "owner_fields_consistent": True, "physical_clock_authenticated": False,
                "native_runtime_attested": False, "all_branch_world_coverage_attested": False,
                "initial_residual_state_attested": False, "probabilistic_environment_bound": False,
                "six_successor_risk_qualified": False, "native_execution_qualified": False,
                "qualification_refusals": refusals,
                "comparisons": [self.compare(row) for row in doc["comparisons"]]}


class ModelBuilder:
    """Explicitly synthetic valid-record fixtures; never a native runtime adapter."""
    def __init__(self, name: str):
        self.name = name
        self.blocks: list[dict] = []
        self.events: list[dict] = []
        self.active = {"h0": "g", "h1": "g"}
        self.generations = {"h0": 0, "h1": 0}
        self.scores = {"g": 0}
        self.comparisons: list[dict] = []
    def block(self, name: str, parent: str, weight: int, producer: str = "H", miner: str = "h0") -> str:
        self.blocks.append({"id": name, "parent": parent, "weight": weight, "producer": producer,
                            "miner": miner if producer == "H" else "adversary", "header_timestamp": 1})
        self.scores[name] = self.scores[parent] + weight
        return name
    def emit(self, time: int, kind: str, **data) -> None:
        self.events.append({"seq": len(self.events) + 1, "time": time, "kind": kind, **data})
    def owner(self, node: str) -> dict:
        return {"node": node, "owner_instance": "model-owner-" + node}
    def bind(self, time: int, block: str, parent: str, node: str = "h0") -> None:
        self.emit(time, "bind", **self.owner(node), generation=self.generations[node], block=block, parent=parent)
    def ready(self, time: int, block: str) -> None:
        self.emit(time, "ready", block=block, complete_material={"body": True, "proof": True, "application": True})
    def available(self, time: int, block: str, node: str = "h0") -> None:
        self.emit(time, "available", **self.owner(node), generation=self.generations[node], block=block)
    def select(self, time: int, candidate: str, node: str = "h0") -> None:
        old, generation = self.active[node], self.generations[node]
        selected = candidate if self.scores[candidate] > self.scores[old] else old
        after = generation + int(selected != old)
        self.emit(time, "select", **self.owner(node), generation_before=generation,
                  generation_after=after, candidate=candidate, selected=selected)
        self.active[node], self.generations[node] = selected, after
    def observe(self, time: int, name: str, *, node: str = "h0", included: str | None = None,
                confirmed: bool | None = None) -> None:
        self.emit(time, "observe", **self.owner(node), generation=self.generations[node],
                  tip=self.active[node], included=included, claim_confirmed=confirmed, observation_id=name)
    def base(self) -> str:
        parent = "g"
        for i in range(1, 8):
            block = self.block("a" + str(i), parent, 1)
            self.bind(i-1, block, parent)
            self.ready(i, block)
            self.available(i, block)
            self.select(i, block)
            parent = block
        self.observe(7, "confirmed", included="a1", confirmed=True)
        return parent
    def compare(self, later: str, name: str = "comparison") -> None:
        self.comparisons.append({"name": name, "confirmed_observation": "confirmed", "later_observation": later})
    def document(self) -> dict:
        end = max((e["time"] for e in self.events), default=0)
        return {"schema": SCHEMA,
                "provenance": {"origin": "model_fixture", "role": "declared_finite_model",
                               "source_commit": BASE_COMMIT, "evidence_id": self.name, "raw_artifact_hashes": {}},
                "clock": {"domain": "model_ticks", "unit": "tick", "binding_receipt": None},
                "scope": {"execution_id": "model-" + self.name, "first_seq": 0,
                          "last_seq": len(self.events), "start_time": 0, "end_time": end,
                          "nodes": ["h0", "h1"], "declared_all_branches": True,
                          "declared_no_missing_events": True},
                "owners": [{"node": node, "owner_instance": "model-owner-" + node,
                            "namespace": "model-only-" + self.name, "configuration_digest": "0"*64}
                           for node in ("h0", "h1")],
                "initial": {"ready": ["g"], "available": {"h0": ["g"], "h1": ["g"]},
                            "active": {"h0": "g", "h1": "g"}, "generations": {"h0": 0, "h1": 0},
                            "complete_material": {"body": True, "proof": True, "application": True},
                            "residual_state": {"status": "declared_empty_model", "reference": None}},
                "blocks": self.blocks, "events": self.events, "comparisons": self.comparisons}


def model_fixtures() -> dict[str, dict]:
    fixtures = {}
    m = ModelBuilder("early_unseen_anchor")
    m.base()
    m.observe(7, "other_view", node="h1")
    m.compare("other_view")
    fixtures[m.name] = m.document()

    m = ModelBuilder("early_partial_view_positive_gap")
    m.base()
    m.available(8, "a1", "h1")
    d = m.block("rival", "g", 1, "A")
    m.ready(8, d)
    m.available(8, d, "h1")
    m.select(8, d, "h1")
    m.observe(8, "other_view", node="h1")
    m.compare("other_view")
    fixtures[m.name] = m.document()

    m = ModelBuilder("known_heavier_b_chain_selection_backlog")
    tip = m.base()
    h = m.block("known_score_100", tip, 93)
    m.bind(8, h, tip)
    m.ready(9, h)
    m.available(9, h)
    d = m.block("rival_score_8", "g", 8, "A")
    m.ready(9, d)
    m.available(9, d)
    m.select(9, d)
    m.observe(9, "rollback")
    m.compare("rollback")
    fixtures[m.name] = m.document()

    m = ModelBuilder("hidden_complete_inventory")
    d = m.block("hidden_8", "g", 8, "A")
    m.ready(0, d)
    m.base()
    m.available(8, d)
    m.select(8, d)
    m.observe(8, "rollback")
    m.compare("rollback")
    fixtures[m.name] = m.document()

    m = ModelBuilder("honest_stale_parent_pipeline")
    d = m.block("old_parent_8", "g", 8, "H", "h1")
    m.bind(0, d, "g", "h1")
    m.base()
    m.ready(100, d)
    m.available(100, d)
    m.select(100, d)
    m.observe(100, "rollback")
    m.compare("rollback")
    fixtures[m.name] = m.document()

    m = ModelBuilder("all_honest_bounded_delay_burst")
    left = right = "g"
    for i in range(1, 8):
        a = m.block("a" + str(i), left, 1, "H", "h0")
        b = m.block("b" + str(i), right, 1, "H", "h1")
        m.bind(i-1, a, left, "h0")
        m.bind(i-1, b, right, "h1")
        m.ready(i, a)
        m.available(i, a, "h0")
        m.select(i, a, "h0")
        if i == 7:
            m.observe(7, "confirmed", included="a1", confirmed=True)
        m.ready(i, b)
        m.available(i, b, "h1")
        m.select(i, b, "h1")
        left, right = a, b
    b = m.block("b8", right, 1, "H", "h1")
    m.bind(7, b, right, "h1")
    m.ready(8, b)
    m.available(8, b, "h1")
    m.select(8, b, "h1")
    m.available(8, b, "h0")
    m.select(8, b, "h0")
    m.observe(8, "rollback")
    m.compare("rollback")
    # The finite trace completes delivery to both miners: every full block is
    # present at both by time 9, within 8 model ticks of its ready event.
    m.available(9, left, "h1")
    fixtures[m.name] = m.document()

    m = ModelBuilder("same_timestamp_after_crossing_is_not_prior_progress")
    tip = m.base()
    h = m.block("later_b_score_100", tip, 93)
    m.bind(7, h, tip)
    d = m.block("rival_8", "g", 8, "A")
    m.ready(8, d)
    m.available(8, d)
    m.select(8, d)
    m.observe(8, "first_cut")
    m.ready(8, h)
    m.available(8, h)
    m.observe(8, "later_same_time_cut")
    m.compare("first_cut", "before_later_completion")
    m.compare("later_same_time_cut", "after_later_completion")
    fixtures[m.name] = m.document()

    m = ModelBuilder("unit_weight_batch_ready")
    m.base()
    parent = "g"
    for i in range(8):
        parent = m.block("r" + str(i), parent, 1, "A")
        m.ready(8, parent)
    m.available(8, parent)
    m.select(8, parent)
    m.observe(8, "rollback")
    m.compare("rollback")
    fixtures[m.name] = m.document()
    return fixtures


def source_bindings() -> dict[str, str]:
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCE_FILES}


def build_evidence() -> dict:
    fixtures = model_fixtures()
    results = {name: Execution(doc).report() for name, doc in fixtures.items()}
    return {"schema": "pon-native-execution-model-evidence-v1", "base_commit": BASE_COMMIT,
            "source_bindings": source_bindings(), "model_fixtures": fixtures, "model_results": results,
            "native_runtime_reexecuted": False, "actual_physical_execution_qualified": False,
            "common_prefix_proved": False, "native_six_successor_risk_bound": None}


def verify_evidence(document: dict) -> None:
    require(canonical(document) == canonical(build_evidence()), "EVIDENCE_OR_SOURCE_MISMATCH")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_mutually_exclusive_group(required=True)
    commands.add_argument("--check", type=Path, help="check a declared finite execution certificate")
    commands.add_argument("--write-evidence", type=Path, help="create a new model evidence JSON")
    commands.add_argument("--verify-evidence", type=Path)
    parser.add_argument("--require-native-qualification", action="store_true")
    args = parser.parse_args()
    try:
        if args.write_evidence:
            document = build_evidence()
            with args.write_evidence.open("x", encoding="utf-8") as out:
                json.dump(document, out, ensure_ascii=False, indent=2, allow_nan=False)
                out.write("\n")
            print(json.dumps({"written": str(args.write_evidence), "model_fixtures": len(document["model_fixtures"]),
                              "native_execution_qualified": False}))
        elif args.verify_evidence:
            require(args.verify_evidence.stat().st_size <= 8 * 1024 * 1024, "INPUT_SIZE")
            verify_evidence(strict_json(args.verify_evidence.read_text(encoding="utf-8")))
            print(json.dumps({"finite_model_source_readback": "PASS", "native_execution_qualified": False}))
        else:
            require(args.check.stat().st_size <= 8 * 1024 * 1024, "INPUT_SIZE")
            result = Execution(strict_json(args.check.read_text(encoding="utf-8"))).report()
            print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
        if args.require_native_qualification:
            print(json.dumps({"qualification": "REFUSED", "reason": "NO_AUTHENTICATED_NATIVE_EXECUTION_ADAPTER"}))
            return 2
        return 0
    except (CertificateError, OSError, json.JSONDecodeError, TypeError, KeyError, RecursionError) as error:
        print(json.dumps({"certificate_check": "REFUSED", "reason": str(error),
                          "native_execution_qualified": False}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
