#!/usr/bin/env python3
"""Independently replay retained native-v6 source-invariance model receipts.

Reads actual PNX1/ILF2 bytes to obtain component owners. Fixture author ordinals
are ignored. Replays complete ILM2 coefficients on the pinned evidence tasks.
This program neither executes native payments nor verifies Ed25519 signatures,
PoN work, ledger state roots, real funding, or collateral reservations.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import io
import json
import math
import pathlib
import struct
import sys
import unittest

PREFIX = "native-v6-source-invariance "
CASES = ("original", "split", "aliased", "permuted")
DIMENSION, CLASSES, COEFFICIENTS = 257, 3, 3855
MODEL_BYTES = 7756
MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_CONFIG_BYTES = 2 * 1024 * 1024
PROFILE = "linear-source-composition-dev-v6"
U64_MAX = (1 << 64) - 1


class AuditFailure(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise AuditFailure(reason)


def integer(value, name, low=0, high=U64_MAX):
    require(type(value) is int and low <= value <= high,
            f"{name}: exact integer out of range")
    return value


def hexbytes(value, name, size=None):
    require(isinstance(value, str) and len(value) % 2 == 0
            and all(c in "0123456789abcdef" for c in value),
            f"{name}: canonical lowercase hex required")
    result = bytes.fromhex(value)
    if size is not None:
        require(len(result) == size, f"{name}: incorrect byte length")
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def pon_hash(domain, parts):
    tag = domain.encode("ascii") if isinstance(domain, str) else domain
    require(len(tag) < 65536, "hash domain too long")
    digest = hashlib.sha256(b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag)
    for part in parts:
        require(len(part) < 1 << 32, "hash part too long")
        digest.update(struct.pack("<I", len(part)))
        digest.update(part)
    return digest.digest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def finite_float(token):
    value = float(token)
    require(math.isfinite(value), "non-finite JSON numeric literal")
    return value


def constant_error(token):
    raise AuditFailure("non-finite JSON constant: " + token)


def parse_json(raw):
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_float=finite_float, parse_constant=constant_error)


def read_bounded(path, limit):
    with pathlib.Path(path).open("rb") as handle:
        raw = handle.read(limit + 1)
    require(len(raw) <= limit, f"{path}: input size bound exceeded")
    return raw


def extract_native_record(raw):
    text = raw.decode("utf-8", errors="strict")
    matches = []
    for line in text.splitlines():
        position = line.find(PREFIX)
        if position >= 0:
            require(line.count(PREFIX) == 1, "multiple markers on a log line")
            matches.append(parse_json(line[position + len(PREFIX):]))
    require(len(matches) == 1, "expected exactly one native-v6 source marker")
    value = matches[0]
    require(isinstance(value, dict) and all(name in value for name in CASES),
            "native record must retain all four named variants")
    return value


def decode_model(raw):
    require(len(raw) == MODEL_BYTES, "ILM2 exact length mismatch")
    require(raw[:6] == b"ILM2" + struct.pack("<H", 2), "ILM2 version mismatch")
    require(raw[38:46] == struct.pack("<4H", 1024, 3, 257, 3),
            "ILM2 dimensions or numeric profile mismatch")
    coefficients = list(struct.unpack("<3855h", raw[46:]))
    require(-32768 not in coefficients, "ILM2 forbidden i16 minimum")
    return {"family": raw[6:38], "coefficients": coefficients,
            "artifact": pon_hash("integer-linear-model-artifact-v2", [raw]),
            "raw_sha256": hashlib.sha256(raw).hexdigest()}


def encode_model(family, coefficients):
    require(len(family) == 32 and len(coefficients) == COEFFICIENTS,
            "ILM2 model shape mismatch")
    for value in coefficients:
        integer(value, "model coefficient", -32767, 32767)
    return (b"ILM2" + struct.pack("<H", 2) + family
            + struct.pack("<4H", 1024, 3, 257, 3)
            + struct.pack("<3855h", *coefficients))


def argmax_lowest(values):
    # max() keeps the first equal maximum; range iteration is increasing.
    return max(range(len(values)), key=values.__getitem__)


def predictions(coefficients, tasks):
    require(len(coefficients) == COEFFICIENTS, "predictor shape mismatch")
    result = []
    for task in tasks:
        features = task["features"]
        router = [
            sum(coefficients[771 + row * DIMENSION + col] * features[col]
                for col in range(DIMENSION))
            for row in range(CLASSES)
        ]
        slot = argmax_lowest(router)
        offset = (2 + slot) * 771
        logits = [
            sum((coefficients[row * DIMENSION + col]
                 + coefficients[offset + row * DIMENSION + col]) * features[col]
                for col in range(DIMENSION))
            for row in range(CLASSES)
        ]
        result.append(argmax_lowest(logits))
    return result


def correct(predicted, tasks):
    return sum(value == task["label"] for value, task in zip(predicted, tasks))


def check_evidence(config, expected_rows=None):
    require(isinstance(config, dict), "evidence config must be an object")
    require(config.get("schema") == "native-integer-model-evidence-v3",
            "evidence schema mismatch")
    require(config.get("score_scale") == 1_000_000, "evidence score scale mismatch")
    tasks = config.get("tasks")
    require(isinstance(tasks, list) and 1 <= len(tasks) <= 1024,
            "bounded evidence tasks required")
    if expected_rows is not None:
        require(len(tasks) == expected_rows, "unexpected task denominator")
    ids, groups, contents = set(), set(), set()
    for task in tasks:
        require(isinstance(task, dict), "task must be an object")
        for field, seen in (("id", ids), ("source_group", groups),
                            ("source_content_sha256", contents)):
            value = task.get(field)
            hexbytes(value, field, 32)
            require(value not in seen, "duplicate task evidence identity: " + field)
            seen.add(value)
        path = task.get("source_path")
        require(isinstance(path, str) and path, "missing task source path")
        require(hashlib.sha256(path.encode("utf-8")).hexdigest()
                == task["source_group"], "task source-group hash mismatch")
        features = task.get("features")
        require(isinstance(features, list) and len(features) == DIMENSION,
                "task feature shape mismatch")
        for feature in features:
            integer(feature, "feature", -8, 8)
        require(features[-1] == 8, "task bias feature mismatch")
        integer(task.get("label"), "task label", 0, CLASSES - 1)
    source_map = {}
    require(isinstance(config.get("sources"), list), "installed source map missing")
    for row in config["sources"]:
        require(isinstance(row, dict), "source-map entry must be an object")
        author, source = row.get("author"), row.get("source")
        hexbytes(author, "registered author", 32)
        hexbytes(source, "registered source", 32)
        require(author not in source_map, "ambiguous or duplicate registered author")
        source_map[author] = source
    controls = {}
    require(isinstance(config.get("controls"), list), "frozen controls missing")
    for item in config["controls"]:
        require(isinstance(item, dict), "control must be an object")
        role = item.get("role")
        require(isinstance(role, str) and role not in controls, "duplicate control")
        raw = hexbytes(item.get("coefficients_le_i16_hex"), "control coefficients",
                       2 * COEFFICIENTS)
        coefficients = list(struct.unpack("<3855h", raw))
        require(-32768 not in coefficients, "invalid control coefficient")
        controls[role] = correct(predictions(coefficients, tasks), tasks)
    require(set(controls) == {"current", "best_single", "mean_merge", "pooled"},
            "frozen control role set mismatch")
    cap = integer(config.get("max_reserved_units_per_source_round"), "source cap")
    return {"tasks": tasks, "source_map": source_map, "controls_correct": controls,
            "maximum_source_cap": cap,
            "tasks_hash": pon_hash("native-model-evidence-tasks-v3",
                                   [canonical(tasks)]).hex(),
            "empirical_policy": pon_hash("native-model-evidence-policy-v3",
                                        [canonical(config)]).hex()}


def check_policy(policy):
    require(isinstance(policy, dict), "source policy must be an object")
    expected = {
        "schema": "native-integer-source-composition-v6",
        "profile": PROFILE,
        "consensus_revision": 17,
        "source_identity": "installed-author-to-source-map-only",
        "aggregation": "sum-complete-parent-relative-deltas-by-source-before-evaluation",
        "integer_rule": "checked-i64-no-intermediate-clipping-rounding-or-positive-part",
        "score_scale": 1_000_000,
        "component_wire_marker": 1,
        "component_min": 1,
        "component_max": 4,
    }
    for key, value in expected.items():
        require(policy.get(key) == value, "unsupported source-policy field: " + key)
    for key in ("unknown_sybil_resistance", "coalition_proofness", "truthful_bidding",
                "production_activation", "prospective_accepted", "independent_accepted",
                "public_reward_eligible", "shapley_fairness_accepted"):
        require(policy.get(key) is False, "source policy grants unsupported claim: " + key)
    integer(policy.get("maximum_source_record_bytes"), "record bound", 1, 4096)
    return pon_hash("native-source-composition-policy-v6", [canonical(policy)]).hex()


def decode_envelope(raw):
    require(159 <= len(raw) <= 2048 and raw[:4] == b"PNX1",
            "PNX1 header or length mismatch")
    length = struct.unpack_from("<H", raw, 93)[0]
    require(len(raw) == 159 + length, "PNX1 payload length mismatch")
    nonce, expiry, fee = struct.unpack_from("<3Q", raw, 68)
    require(nonce > 0 and fee <= 10_000_000, "PNX1 nonce or fee bound")
    return {"network": raw[4:36].hex(), "sender": raw[36:68].hex(),
            "nonce": nonce, "expiry": expiry, "fee_limit": fee, "tag": raw[92],
            "payload": raw[95:95+length], "signature": raw[95+length:],
            "tx_id": pon_hash("tx-id", [raw]).hex(),
            "signing_digest": pon_hash("tx-sign", [raw[:-64]]).hex()}


def decode_factor(raw):
    require(len(raw) >= 242 and raw[:6] == b"ILF2" + struct.pack("<H", 2),
            "ILF2 version or prefix mismatch")
    rank, slot = raw[6:8]
    require(rank in (1, 2) and slot < 3 and raw[8:10] == struct.pack("<H", 1024),
            "ILF2 rank, slot, or scale mismatch")
    require(len(raw) == 242 + 2 * 260 * rank, "ILF2 exact length mismatch")
    factors = list(struct.unpack("<" + str(260 * rank) + "h", raw[242:]))
    require(-32768 not in factors, "ILF2 forbidden coefficient")
    names = ("family", "parent_ref", "parent_artifact", "candidate_artifact",
             "update_id", "contribution_id", "components_root")
    witness = {name: raw[10+32*i:42+32*i].hex() for i, name in enumerate(names)}
    witness.update({"rank": rank, "slot": slot, "factors": factors,
                    "round": struct.unpack_from("<Q", raw, 234)[0]})
    return witness


def factor_candidate(parent, witness):
    require(witness["family"] == parent["family"].hex(), "factor family mismatch")
    require(witness["parent_artifact"] == parent["artifact"].hex(),
            "factor parent artifact mismatch")
    rank, factors = witness["rank"], witness["factors"]
    b = [factors[i*rank:(i+1)*rank] for i in range(3)]
    a = [factors[3*rank+i*DIMENSION:3*rank+(i+1)*DIMENSION]
         for i in range(rank)]
    normal = [sum(b[row][k] * a[k][col] for k in range(rank))
              for row in range(3) for col in range(DIMENSION)]
    for value in normal:
        integer(value, "BA exact delta", -32767, 32767)
    require(any(normal), "factor no-op is outside retained admission")
    coefficients = list(parent["coefficients"])
    start = (2 + witness["slot"]) * 771
    for i, value in enumerate(normal):
        coefficients[start+i] += value
    raw = encode_model(parent["family"], coefficients)
    require(pon_hash("integer-linear-model-artifact-v2", [raw]).hex()
            == witness["candidate_artifact"], "factor reconstructed artifact mismatch")
    return raw, normal


def contribution_id(network, parameters, sender, witness):
    parts = [hexbytes(network, "network", 32),
             hexbytes(parameters, "parameters", 32),
             hexbytes(sender, "sender", 32)]
    parts += [hexbytes(witness[key], key, 32) for key in
              ("family", "parent_ref", "parent_artifact", "candidate_artifact",
               "update_id", "components_root")]
    parts += [struct.pack("<Q", witness["round"])]
    return pon_hash("integer-factor-contribution-v2", parts).hex()


def function_update_id(network, parameters, witness, normal):
    parts = [hexbytes(network, "network", 32),
             hexbytes(parameters, "parameters", 32),
             hexbytes(witness["family"], "family", 32),
             hexbytes(witness["parent_ref"], "parent_ref", 32),
             hexbytes(witness["parent_artifact"], "parent_artifact", 32),
             struct.pack("<Q", witness["round"]), bytes([witness["slot"]]),
             struct.pack("<H", 1024), b"exact-i16-BA-add-delta-scale1024-v2",
             struct.pack("<771h", *normal)]
    return pon_hash("integer-linear-function-update-v2", parts).hex()


def collect_factor_submissions(case, parameters=None):
    commands = case.get("signed_commands")
    require(isinstance(commands, list) and commands, "signed command log missing")
    factors, networks, seen_tx, seen_nonce = {}, set(), set(), set()
    count, previous_height = 0, -1
    for block in commands:
        require(isinstance(block, dict), "signed-command block is not an object")
        height = integer(block.get("height"), "height", 1)
        require(height > previous_height, "signed-command heights not increasing")
        previous_height = height
        hexbytes(block.get("before_root"), "before_root", 32)
        transactions = block.get("transactions")
        require(isinstance(transactions, list) and transactions, "empty command record")
        for encoded in transactions:
            envelope = decode_envelope(hexbytes(encoded, "signed transaction"))
            require(envelope["tx_id"] not in seen_tx, "duplicate signed transaction")
            seen_tx.add(envelope["tx_id"])
            nonce_key = (envelope["sender"], envelope["nonce"])
            require(nonce_key not in seen_nonce, "duplicate sender nonce in retained trace")
            seen_nonce.add(nonce_key)
            require(envelope["expiry"] >= height, "transaction expired before recorded height")
            networks.add(envelope["network"])
            count += 1
            if envelope["tag"] == 23:
                witness = decode_factor(envelope["payload"])
                cid = witness["contribution_id"]
                require(cid not in factors, "ambiguous factor contribution owner")
                if parameters is not None:
                    require(contribution_id(envelope["network"], parameters,
                                            envelope["sender"], witness) == cid,
                            "factor contribution ID derivation mismatch")
                factors[cid] = {"witness": witness, "sender": envelope["sender"],
                                "height": height, "tx_id": envelope["tx_id"]}
    require(len(networks) == 1, "mixed networks in signed command log")
    return factors, next(iter(networks)), count



def allocation_root_v6(components, owners):
    require(components and components == sorted(components)
            and len(set(components)) == len(components),
            "bundle components must be strictly ordered")
    leaves = [pon_hash("source-allocation-leaf-v6",
                       [hexbytes(cid, "component", 32),
                        hexbytes(owners[cid], "component owner", 32),
                        struct.pack("<Q", 1)])
              for cid in components]
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves.append(leaves[-1])
        leaves = [pon_hash("allocation-node", sorted(leaves[i:i+2]))
                  for i in range(0, len(leaves), 2)]
    return leaves[0].hex()


def decode_admission(raw):
    require(len(raw) >= 145, "tag8 prefix truncated")
    count = raw[144]
    require(1 <= count <= 4 and len(raw) == 145 + count*40,
            "tag8 exact length or component bound")
    components = []
    for index in range(count):
        start = 145 + index*40
        cid = raw[start:start+32].hex()
        marker = struct.unpack_from("<Q", raw, start+32)[0]
        require(marker == 1, "tag8 non-unit source marker")
        components.append(cid)
    require(components == sorted(components) and len(set(components)) == count,
            "tag8 component order or duplicate")
    budget = struct.unpack_from("<Q", raw, 96)[0]
    total = struct.unpack_from("<Q", raw, 136)[0]
    require(total == count, "tag8 marker total mismatch")
    return {"release": raw[:32].hex(), "parent": raw[32:64].hex(),
            "bundle": raw[64:96].hex(), "budget": budget,
            "root": raw[104:136].hex(), "total": total,
            "components": components}


def find_bundle_admission(case, bundle_cid):
    found = []
    for block in case["signed_commands"]:
        for encoded in block["transactions"]:
            envelope = decode_envelope(hexbytes(encoded, "signed transaction"))
            if envelope["tag"] != 8:
                continue
            admission = decode_admission(envelope["payload"])
            if admission["bundle"] == bundle_cid:
                admission.update({"issuer": envelope["sender"],
                                  "tx_id": envelope["tx_id"], "height": block["height"]})
                found.append(admission)
    require(len(found) == 1, "bundle must have one retained tag8 admission")
    return found[0]


def load_reference(path):
    path = pathlib.Path(path)
    spec = importlib.util.spec_from_file_location("independent_source_reference_v6", path)
    require(spec is not None and spec.loader is not None, "reference reader unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def as_object(value, label):
    if isinstance(value, str):
        value = parse_json(value)
    require(isinstance(value, dict), label + " must be an object")
    return value


def audit_variant(name, case, evidence, policy, verify_arithmetic,
                  parameters=None, plan=None):
    require(isinstance(case, dict), name + ": variant object required")
    parent = decode_model(hexbytes(case.get("parent_model_hex"), "parent model"))
    full_raw = hexbytes(case.get("bundle_model_hex"), "bundle model")
    full = decode_model(full_raw)
    require(parent["family"] == full["family"], "bundle family mismatch")
    require(full["artifact"].hex() == case.get("bundle_artifact"), "bundle artifact mismatch")
    ids, encoded_models = case.get("component_ids"), case.get("component_model_hex")
    require(isinstance(ids, list) and isinstance(encoded_models, list)
            and len(ids) == len(encoded_models) and 1 <= len(ids) <= 4,
            "component model list mismatch or bound")
    require(len(set(ids)) == len(ids), "duplicate component identity")
    for cid in ids:
        hexbytes(cid, "component ID", 32)
    require(case.get("weights") == [1] * len(ids), "non-unit component wire marker")
    factors, network, command_count = collect_factor_submissions(case, parameters)
    groups, owners, component_report = {}, {}, []
    shared_context = None
    for cid, encoded in zip(ids, encoded_models):
        require(cid in factors, "component is not bound to a retained tag23 transaction")
        admitted = factors[cid]
        witness, owner = admitted["witness"], admitted["sender"]
        require(owner in evidence["source_map"], "component owner lacks installed source map")
        source = evidence["source_map"][owner]
        candidate_raw = hexbytes(encoded, "component model")
        candidate = decode_model(candidate_raw)
        reconstructed, normal = factor_candidate(parent, witness)
        if parameters is not None:
            require(function_update_id(network, parameters, witness, normal)
                    == witness["update_id"], "factor function update ID mismatch")
        require(reconstructed == candidate_raw, "complete model differs from signed BA witness")
        require(candidate["artifact"].hex() == witness["candidate_artifact"],
                "candidate artifact differs from transaction witness")
        context = (witness["parent_ref"], witness["round"], witness["slot"])
        if shared_context is None:
            shared_context = context
        require(context == shared_context, "mixed source parent, round, or slot")
        delta = [c-p for c, p in zip(candidate["coefficients"], parent["coefficients"])]
        group = groups.setdefault(source, {"delta": [0]*COEFFICIENTS, "components": []})
        group["delta"] = [a+b for a, b in zip(group["delta"], delta)]
        for value in group["delta"]:
            integer(value, "source delta", -(1 << 63), (1 << 63)-1)
        group["components"].append(cid)
        owners[cid] = owner
        component_report.append({"contribution": cid, "owner_from_pnx1": owner,
                                 "installed_source": source,
                                 "artifact": candidate["artifact"].hex(),
                                 "submit_tx": admitted["tx_id"]})
    bundle_cid = case.get("bundle_contribution")
    hexbytes(bundle_cid, "bundle contribution", 32)
    require(bundle_cid in factors, "bundle lacks retained signed factor witness")
    bundle_witness = factors[bundle_cid]["witness"]
    require((bundle_witness["parent_ref"], bundle_witness["round"], bundle_witness["slot"])
            == shared_context, "bundle witness context mismatch")
    bundle_rebuilt, bundle_normal = factor_candidate(parent, bundle_witness)
    if parameters is not None:
        require(function_update_id(network, parameters, bundle_witness, bundle_normal)
                == bundle_witness["update_id"], "bundle function update ID mismatch")
    require(bundle_rebuilt == full_raw, "bundle bytes differ from signed BA witness")
    composed = [parent["coefficients"][i] + sum(g["delta"][i] for g in groups.values())
                for i in range(COEFFICIENTS)]
    require(composed == full["coefficients"], "complete source sum differs from bundle")
    tasks = evidence["tasks"]
    full_pred = predictions(composed, tasks)
    full_correct = correct(full_pred, tasks)
    parent_correct = correct(predictions(parent["coefficients"], tasks), tasks)
    publication = as_object(case.get("publication"), "publication")
    manifest = find_bundle_admission(case, bundle_cid)
    require(bundle_cid not in ids and manifest["components"] == sorted(ids),
            "retained models differ from signed bundle component manifest")
    computed_root = allocation_root_v6(manifest["components"], owners)
    require(manifest["root"] == computed_root
            and bundle_witness["components_root"] == computed_root,
            "signed bundle source-allocation root mismatch")
    require(manifest["parent"] == shared_context[0], "signed admission parent mismatch")
    expected_release = pon_hash("source-release-v6", [
        hexbytes(manifest["parent"], "release parent", 32),
        hexbytes(bundle_cid, "release bundle", 32),
        struct.pack("<Q", manifest["budget"]), bytes.fromhex(computed_root),
        struct.pack("<Q", manifest["total"])]).hex()
    require(manifest["release"] == expected_release, "signed release ID mismatch")
    expected_publication = {
        "owner": manifest["issuer"], "parent": manifest["parent"], "bundle": bundle_cid,
        "artifact": full["artifact"].hex(), "family": parent["family"].hex(),
        "budget": manifest["budget"], "root": computed_root,
        "components_root": computed_root, "total": len(ids), "leaf_count": len(ids),
    }
    for field, value in expected_publication.items():
        require(publication.get(field) == value, "publication manifest mismatch: " + field)
    record = as_object(publication.get("model_composition_v6"), "source record")
    require(record.get("budget") == manifest["budget"], "source record budget not signed")
    require(record.get("schema") == "native-source-composition-record-v6",
            "source record schema mismatch")
    expected_policy = check_policy(policy)
    require(record.get("policy") == expected_policy, "source policy commitment mismatch")
    require(len(canonical(record)) <= policy["maximum_source_record_bytes"],
            "source record exceeds frozen byte bound")
    undigested = dict(record)
    recorded_digest = undigested.pop("digest", None)
    require(pon_hash("native-source-composition-record-v6", [canonical(undigested)]).hex()
            == recorded_digest, "record digest mismatch")
    require(record.get("fees_separate") is True, "fees are not separately identified")
    for flag in ("prospective_accepted", "public_reward_eligible",
                 "shapley_fairness_accepted", "unknown_sybil_resistance",
                 "production_activation"):
        require(record.get(flag) is False, "native record promotes unsupported flag: " + flag)
    require(record.get("rows") == len(tasks) and record.get("correct") == full_correct,
            "reported full correctness or denominator mismatch")
    rows = record.get("sources")
    require(isinstance(rows, list), "source rows missing")
    require([row.get("source") for row in rows] == sorted(groups),
            "record source set/order differs from installed source grouping")
    measured, game_sources = [], []
    strongest = max([parent_correct] + list(evidence["controls_correct"].values()))
    for row in rows:
        source = row["source"]
        delta = groups[source]["delta"]
        delta_raw = struct.pack("<3855q", *delta)
        expected_delta_hash = pon_hash("native-complete-source-delta-v6", [delta_raw]).hex()
        require(row.get("delta_hash") == expected_delta_hash, "full source delta hash mismatch")
        standalone = [p+d for p, d in zip(parent["coefficients"], delta)]
        without = [c-d for c, d in zip(composed, delta)]
        # Both counterfactuals must be complete loadable ILM2 models. An error
        # aborts this audit; invalid inference is never assigned zero utility.
        encode_model(parent["family"], standalone)
        encode_model(parent["family"], without)
        standalone_pred, without_pred = predictions(standalone, tasks), predictions(without, tasks)
        standalone_correct = correct(standalone_pred, tasks)
        without_correct = correct(without_pred, tasks)
        weight = max(0, full_correct-without_correct) * 1_000_000 // len(tasks)
        require(row.get("standalone_correct") == standalone_correct
                and row.get("without_correct") == without_correct
                and row.get("weight") == weight, "source correctness or weight mismatch")
        cap = integer(row.get("cap"), "reported source cap")
        require(cap <= evidence["maximum_source_cap"], "source cap exceeds installed maximum")
        if len(groups) > 1:
            strongest = max(strongest, standalone_correct)
        measured.append({"source": source, "delta_hash": expected_delta_hash,
                         "standalone_correct": standalone_correct,
                         "without_correct": without_correct, "weight": weight,
                         "cap": cap, "reward": row["reward"],
                         "standalone_predictions": standalone_pred,
                         "without_predictions": without_pred})
        game_sources.append({"source": source, "delta_i64_le": delta_raw.hex(), "cap": cap})
    require(record.get("strongest_correct") == strongest and full_correct > strongest,
            "independent complete-model adoption gate mismatch")
    arithmetic = verify_arithmetic(record)
    pay_by_cid = {}
    for payment in record["payments"]:
        cid = payment["contribution"]
        require(cid in owners and cid not in pay_by_cid, "unexpected internal payout identity")
        require(payment["payee"] == owners[cid], "payout is not to the submitted component owner")
        require(payment["source"] == evidence["source_map"][owners[cid]],
                "payout source differs from installed ownership")
        pay_by_cid[cid] = payment["amount"]
    for row in rows:
        members = sorted(groups[row["source"]]["components"])
        quotient, remainder = divmod(row["reward"], len(members))
        for index, cid in enumerate(members):
            expected = quotient + int(index < remainder)
            require(pay_by_cid.get(cid, 0) == expected,
                    "internal equal-share/cid-dust allocation mismatch")
            if expected:
                require(cid in pay_by_cid, "positive component payout missing")
    known_source = case.get("known_alias_source")
    alias_count = sum(s == known_source for s in evidence["source_map"].values())
    require(known_source in groups and alias_count > 1, "known alias source lacks installed linkage")
    alias_reward = next(row["reward"] for row in rows if row["source"] == known_source)
    require(case.get("alias_gross_payment") == alias_reward, "alias gross payment mismatch")
    expected_game = None
    if parameters is not None and plan is not None:
        context = {
            "profile": PROFILE, "network": network, "parameters": parameters,
            "family": parent["family"].hex(), "plan": plan, "policy": expected_policy,
            "tasks": evidence["tasks_hash"], "empirical_policy": evidence["empirical_policy"],
            "parent": shared_context[0], "parent_artifact": parent["artifact"].hex(),
            "round": shared_context[1], "slot": shared_context[2],
            "artifact": full["artifact"].hex(), "budget": record["budget"],
        }
        expected_game = pon_hash("native-source-value-game-v6",
                                 [canonical({"context": context, "sources": game_sources})]).hex()
        require(record["game_digest"] == expected_game, "native game digest mismatch")
    result = {
        "case": name, "result": "PASS_RETAINED_BYTES_AND_REPORTED_PAYMENTS",
        "retained_signed_transactions": command_count,
        "fixture_author_ordinals_ignored": True,
        "component_sender_source_bindings": component_report,
        "complete_factor_candidates_reconstructed": len(ids) + 1,
        "parent_artifact": parent["artifact"].hex(),
        "bundle_artifact": full["artifact"].hex(), "rows": len(tasks),
        "full_correct": full_correct, "parent_correct": parent_correct,
        "full_predictions": full_pred, "frozen_controls_correct": evidence["controls_correct"],
        "strongest_correct": strongest, "sources": measured,
        "record_digest_verified": True, "native_game_digest_recomputed": expected_game is not None,
        "factor_contribution_ids_rederived": parameters is not None,
        "factor_function_update_ids_rederived": parameters is not None,
        "reported_game_digest": record["game_digest"],
        "alias_gross_payment": alias_reward, "arithmetic": arithmetic,
        "internal_component_allocation_verified": True,
        "signed_tag8_component_manifest_bound": True,
        "v6_allocation_root_recomputed": computed_root,
        "release_id_recomputed": expected_release,
        "admission_transaction": manifest["tx_id"],
        "source_cap_maximum_checked": True,
        "prepublication_reservation_state_replayed": False,
        "source_cap_authority_independently_verified": False,
        "signatures_verified": False, "ledger_roots_replayed": False,
        "native_payment_executed_by_reader": False,
        "actual_claim_accounts_independently_replayed": False,
    }
    invariant = {
        "parent_artifact": parent["artifact"].hex(),
        "bundle_artifact": full["artifact"].hex(), "sources": measured,
        "budget": record["budget"], "allocated": record["allocated"], "refund": record["refund"],
        "known_alias_source": known_source, "alias_gross_payment": alias_reward,
        "reported_game_digest": record["game_digest"],
    }
    return result, invariant


def audit_all(native, evidence_config, policy, reference, expected_rows=25,
              parameters=None, plan=None):
    evidence = check_evidence(evidence_config, expected_rows)
    context = {key: native.get(key) for key in ("network", "parameters", "family", "plan")}
    for key, value in context.items():
        hexbytes(value, "native context " + key, 32)
    if parameters is not None:
        require(parameters == context["parameters"], "CLI parameters disagree with native context")
    if plan is not None:
        require(plan == context["plan"], "CLI plan disagrees with native context")
    parameters, plan = context["parameters"], context["plan"]
    results, invariants = {}, {}
    for name in CASES:
        model = decode_model(hexbytes(native[name].get("parent_model_hex"), "parent model"))
        require(model["family"].hex() == context["family"], "native family context mismatch")
        _, network, _ = collect_factor_submissions(native[name], parameters)
        require(network == context["network"], "native network context mismatch")
        results[name], invariants[name] = audit_variant(
            name, native[name], evidence, policy, reference.verify_receipt, parameters, plan)
    for name in CASES[1:]:
        require(invariants[name] == invariants["original"],
                "complete known-source game or total entitlement changed in " + name)
    return {
        "schema": "trnm.native-source-incentive-independent-readback.v6",
        "result": "PASS_FINITE_NATIVE_RECEIPT_RECOMPUTATION",
        "variants": results, "source_split_permutation_alias_invariance": True,
        "all_full_models_identical": True, "all_source_rewards_identical": True,
        "rows_per_evaluation": len(evidence["tasks"]),
        "retained_native_context": context,
        "tasks_hash": evidence["tasks_hash"], "empirical_policy": evidence["empirical_policy"],
        "source_policy": check_policy(policy),
        "native_payment_executed": False, "market_test": False,
        "native_acceptance_granted": False,
        "signature_verification_performed": False, "funding_verified": False,
        "source_registration_truth_verified": False,
        "historical_source_contents_reloaded": False,
        "independent_new_holdout": False,
        "scope": "recompute retained complete model bytes, reported source valuation and payout arithmetic",
    }


class ReaderTests(unittest.TestCase):
    def test_model_roundtrip_and_forbidden_i16(self):
        raw = encode_model(bytes(32), [0]*COEFFICIENTS)
        self.assertEqual(len(raw), MODEL_BYTES)
        self.assertEqual(decode_model(raw)["coefficients"], [0]*COEFFICIENTS)
        bad = raw[:46] + struct.pack("<h", -32768) + raw[48:]
        with self.assertRaises(AuditFailure):
            decode_model(bad)
        for bad in (raw[:-1], raw+b"\0", b"ILM3"+raw[4:]):
            with self.assertRaises(AuditFailure):
                decode_model(bad)

    def test_router_and_logit_ties_choose_lowest(self):
        task = {"features": [1]+[0]*255+[8], "label": 0}
        coefficients = [0]*COEFFICIENTS
        self.assertEqual(predictions(coefficients, [task]), [0])
        coefficients[771 + 257] = 1  # Route to expert 1.
        coefficients[3*771 + 2*257] = 2
        self.assertEqual(predictions(coefficients, [task]), [2])
        coefficients[3*771] = 2  # Equal logits return the lowest class.
        self.assertEqual(predictions(coefficients, [task]), [0])

    def test_known_pon_hash_vector(self):
        tag, part = b"unit", b"abc"
        direct = hashlib.sha256(b"TRNM-PON1\0\x04\x00unit\x03\x00\x00\x00abc").digest()
        self.assertEqual(pon_hash(tag, [part]), direct)
        self.assertNotEqual(pon_hash(tag, [b"a", b"bc"]), direct)

    def test_envelope_owner_is_actual_public_bytes(self):
        owner = bytes.fromhex("12"*32)
        raw = (b"PNX1" + bytes(32) + owner + struct.pack("<3QBH", 1, 100, 1000, 1, 40)
               + bytes(40) + bytes(64))
        parsed = decode_envelope(raw)
        self.assertEqual(parsed["sender"], owner.hex())
        self.assertEqual(parsed["tag"], 1)
        self.assertEqual(len(parsed["signature"]), 64)
        with self.assertRaises(AuditFailure):
            decode_envelope(raw[:-1])

    def test_factor_ba_reconstructs_complete_model_without_rounding(self):
        parent = decode_model(encode_model(bytes(32), [0]*COEFFICIENTS))
        factors = [0, 1, 0] + [3]+[0]*256
        candidate = [0]*COEFFICIENTS
        candidate[2*771 + 257] = 3
        raw_candidate = encode_model(bytes(32), candidate)
        witness = {"rank": 1, "slot": 0, "factors": factors, "family": bytes(32).hex(),
                   "parent_artifact": parent["artifact"].hex(),
                   "candidate_artifact": pon_hash("integer-linear-model-artifact-v2",
                                                  [raw_candidate]).hex()}
        rebuilt, normal = factor_candidate(parent, witness)
        self.assertEqual(rebuilt, raw_candidate)
        self.assertEqual(normal[257], 3)  # No division by the scale descriptor.
        witness["candidate_artifact"] = "ff"*32
        with self.assertRaises(AuditFailure):
            factor_candidate(parent, witness)

    def test_ilf2_codec_and_trailing_rejection(self):
        payload = (b"ILF2"+struct.pack("<HBBH", 2, 1, 0, 1024)
                   + bytes(7*32) + struct.pack("<Q", 2) + struct.pack("<260h", *([0]*260)))
        parsed = decode_factor(payload)
        self.assertEqual(parsed["round"], 2)
        self.assertEqual(parsed["rank"], 1)
        for bad in (payload[:-1], payload+b"\0", b"ILF3"+payload[4:]):
            with self.assertRaises(AuditFailure):
                decode_factor(bad)

    def test_duplicate_json_and_multiple_native_markers_rejected(self):
        with self.assertRaises(AuditFailure):
            parse_json('{"a":1,"a":2}')
        with self.assertRaises(AuditFailure):
            parse_json('{"a":1e999}')
        sample = {name: {} for name in CASES}
        line = PREFIX + canonical(sample).decode()
        self.assertEqual(extract_native_record(line.encode()), sample)
        with self.assertRaises(AuditFailure):
            extract_native_record((line+"\n"+line).encode())

    def test_undeclared_alias_and_duplicate_author_map_rejected(self):
        # Metadata-only synthetic fixture; it is never classified as native execution.
        features = [0]*256+[8]
        path = "synthetic/test"
        task = {"id": "01"*32, "source_group": hashlib.sha256(path.encode()).hexdigest(),
                "source_path": path, "source_content_sha256": "02"*32,
                "label": 0, "features": features}
        config = {"schema": "native-integer-model-evidence-v3", "score_scale": 1_000_000,
                  "max_reserved_units_per_source_round": 100000,
                  "tasks": [task], "sources": [{"author": "11"*32, "source": "22"*32}],
                  "controls": [{"role": role, "coefficients_le_i16_hex": "00"*(2*COEFFICIENTS)}
                               for role in ("current", "best_single", "mean_merge", "pooled")]}
        checked = check_evidence(config)
        self.assertEqual(checked["source_map"], {"11"*32: "22"*32})
        config["sources"].append({"author": "11"*32, "source": "33"*32})
        with self.assertRaises(AuditFailure):
            check_evidence(config)

    def test_v6_allocation_root_binds_actual_owner_and_marker(self):
        ids = ["11"*32, "22"*32, "33"*32]
        owners = {cid: "44"*32 for cid in ids}
        root = allocation_root_v6(ids, owners)
        leaves = [pon_hash("source-allocation-leaf-v6",
                          [bytes.fromhex(cid), bytes.fromhex(owners[cid]), struct.pack("<Q", 1)])
                  for cid in ids]
        left = pon_hash("allocation-node", sorted(leaves[:2]))
        right = pon_hash("allocation-node", [leaves[2], leaves[2]])
        self.assertEqual(root, pon_hash("allocation-node", sorted([left, right])).hex())
        changed = dict(owners)
        changed[ids[1]] = "55"*32
        self.assertNotEqual(allocation_root_v6(ids, changed), root)
        with self.assertRaises(AuditFailure):
            allocation_root_v6(ids[::-1], owners)
        with self.assertRaises(AuditFailure):
            allocation_root_v6([ids[0], ids[0]], owners)

    def test_tag8_exact_manifest_layout_and_malformed_rejection(self):
        ids = [bytes.fromhex("11"*32), bytes.fromhex("22"*32)]
        raw = (bytes.fromhex("aa"*32) + bytes.fromhex("bb"*32) + bytes.fromhex("cc"*32)
               + struct.pack("<Q", 101) + bytes.fromhex("dd"*32)
               + struct.pack("<QB", 2, 2)
               + b"".join(cid+struct.pack("<Q", 1) for cid in ids))
        result = decode_admission(raw)
        self.assertEqual(result["release"], "aa"*32)
        self.assertEqual(result["bundle"], "cc"*32)
        self.assertEqual(result["budget"], 101)
        self.assertEqual(result["root"], "dd"*32)
        self.assertEqual(result["components"], [cid.hex() for cid in ids])
        for bad in (raw[:-1], raw+b"\\0",
                    raw[:177]+struct.pack("<Q", 2)+raw[185:],
                    raw[:145]+raw[185:225]+raw[145:185]):
            with self.assertRaises(AuditFailure):
                decode_admission(bad)

    def test_counterfactual_unloadability_rejected(self):
        with self.assertRaises(AuditFailure):
            encode_model(bytes(32), [32768]+[0]*(COEFFICIENTS-1))


def run_self_tests():
    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ReaderTests))
    return {"result": "PASS" if result.wasSuccessful() else "FAIL",
            "tests_run": result.testsRun, "errors": len(result.errors),
            "failures": len(result.failures), "skipped": len(result.skipped),
            "synthetic_unit_tests": True, "native_payment_executed": False,
            "log": stream.getvalue()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parents[2])
    parser.add_argument("--log", type=pathlib.Path)
    parser.add_argument("--evidence-config", type=pathlib.Path)
    parser.add_argument("--policy-config", type=pathlib.Path)
    parser.add_argument("--reference", type=pathlib.Path)
    parser.add_argument("--expected-rows", type=int, default=25)
    parser.add_argument("--parameters", help="optional expected cfg.parameters; must match retained context")
    parser.add_argument("--plan", help="optional expected cfg.plan; must match retained context")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    report = {"schema": "trnm.native-source-incentive-reader.invocation.v6",
              "reader_sha512": hashlib.sha512(pathlib.Path(__file__).read_bytes()).hexdigest(),
              "native_payment_executed": False, "market_test": False,
              "native_acceptance_granted": False}
    exit_code = 0
    try:
        if args.self_test:
            report["self_test"] = run_self_tests()
            if report["self_test"]["result"] != "PASS":
                exit_code = 1
        if args.log is not None:
            config_path = args.evidence_config or args.repo/"config/pon/model-evidence-v3.json"
            policy_path = args.policy_config or args.repo/"config/pon/model-composition-v6.json"
            reference_path = args.reference or args.repo/"scripts/experiments/source_incentive_reference_v6.py"
            log_raw = read_bounded(args.log, MAX_LOG_BYTES)
            config_raw = read_bounded(config_path, MAX_CONFIG_BYTES)
            policy_raw = read_bounded(policy_path, MAX_CONFIG_BYTES)
            reference = load_reference(reference_path)
            report["input_hashes"] = {
                "native_log_sha512": hashlib.sha512(log_raw).hexdigest(),
                "evidence_config_sha512": hashlib.sha512(config_raw).hexdigest(),
                "source_policy_sha512": hashlib.sha512(policy_raw).hexdigest(),
                "arithmetic_reference_sha512": hashlib.sha512(reference_path.read_bytes()).hexdigest(),
            }
            report["audit"] = audit_all(
                extract_native_record(log_raw), parse_json(config_raw), parse_json(policy_raw),
                reference, args.expected_rows, args.parameters, args.plan)
            report["result"] = report["audit"]["result"] if exit_code == 0 else "FAIL_SELF_TEST"
        else:
            require(args.self_test, "supply an actual --log or explicitly request --self-test")
            report["result"] = "PASS_SYNTHETIC_UNIT_TESTS_ONLY" if exit_code == 0 else "FAIL_SELF_TEST"
    except (AuditFailure, ValueError, KeyError, IndexError, TypeError, AttributeError,
            OSError, struct.error, UnicodeError) as error:
        report["result"] = "FAIL_INDEPENDENT_NATIVE_READBACK"
        report["error"] = str(error)
        exit_code = 1
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
