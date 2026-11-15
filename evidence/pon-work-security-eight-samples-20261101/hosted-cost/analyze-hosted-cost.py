#!/usr/bin/env python3
"""Read-only independent audit of the 12 frozen hosted W1 cost artifacts.

Python 3.11+ stdlib only. Does not import project readers, run Cargo/native code,
replay the W1 transcript, authenticate clocks, or change original artifacts.
It verifies retained archive/extraction and manifest hashes, source identity,
ELF, locked graph membership, actual record coverage, integer cost denominators,
and exact search identity reuse. Candidate products are not rederived here.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import sys
import tomllib
import zipfile
import zlib

HEAD = "3bbc0288d6b7b6ed7f2bf0ee70d99b3b14236129"
MERGE = "ea43b65fdd91b741b8f9e577061710dd2aebbb2e"
TREE = "f52299288ca23426e5186f37fb3a58788e40dbee"
BASE = "0e9eac5d2a8cdb0a6f0cc7920f84e290e0d5d0d0"
IDS = ("13093136677", "13093301643", "13093396655", "13093416862",
       "13093421854", "13093436001", "13093480950", "13093776046",
       "13093880577", "13093891287", "13093926141", "13094025188")
CLASSES = ("full-rank-field", "zero", "continuity-maintenance-v1",
           "one-zero-left-rank-one", "one-zero-right-rank-one")
HORIZONS = (1, 8, 64)
STRATEGIES = ("prepared-generic", "frozen-public-dispatch-v1")
PATHS = ("production", "reference", "limb", "full-limb-experimental")
FLAGS = ("hardness_accepted", "work_profile_qualified", "resource_fairness_qualified",
         "public_service_measured", "independent_hardware_qualified",
         "public_network_ready", "production_activation")
Q = (1 << 32) - 5


def require(value, message):
    if not value:
        raise ValueError(message)


def unique_object(pairs):
    obj = {}
    for k, v in pairs:
        require(k not in obj, f"duplicate JSON key {k}")
        obj[k] = v
    return obj


def loads(raw):
    return json.loads(raw, object_pairs_hook=unique_object)


def read_json(path):
    return loads(path.read_bytes())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pon_hash(tag, *parts):
    h = hashlib.sha256(b"TRNM-PON1\0" + len(tag).to_bytes(2, "little") + tag)
    for part in parts:
        h.update(len(part).to_bytes(4, "little"))
        h.update(part)
    return h.digest()


def timing(row):
    require(set(row) == {"cpu_ns", "wall_ns"}, "unexpected timing fields")
    require(all(type(v) is int and v > 0 for v in row.values()), "invalid timing")
    return row


def false_flags(row):
    require(all(row.get(f) is False for f in FLAGS), "qualification flag changed")


def ratio(generic, dispatch):
    f = Fraction(generic, dispatch)
    return {"numerator": f.numerator, "denominator": f.denominator,
            "generic_over_dispatch": float(f),
            "dispatch_cpu_change_percent": (dispatch / generic - 1) * 100}


class Audit:
    def __init__(self, root, source):
        self.root, self.source = root, source
        self.hashes = {}
        self.streams = {"v1": {}, "v2": {}}
        self.challenge_ids = {"v1": {}, "v2": {}}
        self.false_streams = {}
        self.lock_raw = (source / "trillionnium/Cargo.lock").read_bytes()
        self.lock = tomllib.loads(self.lock_raw.decode())
        self.lock_packages = {(p["name"], p["version"], p.get("source")): p
                              for p in self.lock["package"]}
        self.normalized_graph_hash = None
        self.original_receipts = {}

    def identity(self, path):
        if path not in self.hashes:
            h, crc, size = hashlib.sha256(), 0, 0
            with path.open("rb") as f:
                for b in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(b)
                    crc = zlib.crc32(b, crc)
                    size += len(b)
            self.hashes[path] = {"sha256": h.hexdigest(), "bytes": size, "crc32": crc}
        return self.hashes[path]

    def archive(self, ident):
        root = self.root / ident
        rp = self.root / (ident + "-receipt.json")
        self.original_receipts[rp] = sha(rp.read_bytes())
        receipt = read_json(rp)
        archive = self.identity(self.root / (ident + ".zip"))
        require(archive["sha256"] == receipt["sha256"] and archive["bytes"] == receipt["size"],
                ident + ": archive digest/size mismatch")
        rows = receipt["members"]
        require(len({r["path"] for r in rows}) == len(rows), "duplicate archive members")
        expected = {r["path"] for r in rows}
        actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
        require(actual == expected, ident + ": extraction inventory mismatch")
        with zipfile.ZipFile(self.root / (ident + ".zip")) as z:
            central = {i.filename: i for i in z.infolist() if not i.is_dir()}
            require(set(central) == expected, "zip central inventory mismatch")
            for row in rows:
                path = row["path"]
                require(not Path(path).is_absolute() and ".." not in Path(path).parts,
                        "unsafe archive path")
                i, actual_file = central[path], self.identity(root / path)
                require(i.file_size == row["bytes"] == actual_file["bytes"] and
                        i.CRC == row["crc32"] == actual_file["crc32"],
                        f"{ident}: extracted member differs: {path}")
        return {"id": ident, "name": receipt["name"], "archive_sha256": archive["sha256"],
                "archive_bytes": archive["bytes"], "members_verified": len(rows),
                "receipt_sha256": self.original_receipts[rp]}

    def source_graph(self, artifact):
        root = self.root / artifact["id"]
        before, after = read_json(root / "source-before.json"), read_json(root / "source-after.json")
        require(before == after, "outer source changed")
        require(before["candidate"] == HEAD and before["tested_tree"] == TREE,
                "wrong source identity")
        expected_commit = HEAD if before["kind"] == "head" else MERGE
        require(before["tested_commit"] == expected_commit and
                before["tracked_worktree_verified"] is True and
                before["tracked_entries"] == 6856 and before["tracked_bytes"] == 792504967,
                "outer source not verified")
        if before["kind"] != "head":
            require(before["base"] == BASE and before["prospective_merge"] == MERGE,
                    "merge base/identity changed")
        graph_path = root / "cargo-graph.json"
        graph = read_json(graph_path)
        packages = graph["packages"]
        ids = {p["id"]: (p["name"], p["version"], p.get("source")) for p in packages}
        require(len(ids) == len(packages), "duplicate metadata package IDs")
        require(all(p in self.lock_packages for p in ids.values()), "graph package missing from lock")
        nodes = graph["resolve"]["nodes"]
        require({n["id"] for n in nodes} == set(ids), "resolve graph coverage differs")
        for node in nodes:
            locked_deps = self.lock_packages[ids[node["id"]]].get("dependencies", [])
            for dep in node["dependencies"]:
                require(dep in ids, "unresolved package edge")
                name, version, _ = ids[dep]
                require(any(d.split()[0] == name and
                            (len(d.split()) == 1 or d.split()[1] == version)
                            for d in locked_deps), "edge absent from Cargo.lock")
        normalized = {"packages": sorted(ids.values(), key=lambda p: (p[0], p[1], p[2] or "")),
                      "workspace_members": sorted(graph["workspace_members"]),
                      "resolve": graph["resolve"]}
        normalized_hash = sha(canonical(normalized))
        if self.normalized_graph_hash is None:
            self.normalized_graph_hash = normalized_hash
        require(normalized_hash == self.normalized_graph_hash, "resolved graph differs between lanes")
        return {"source": before, "source_before_after_equal": True,
                "graph_sha256": self.identity(graph_path)["sha256"],
                "normalized_resolved_graph_sha256": normalized_hash,
                "graph_packages": len(ids), "lock_packages": len(self.lock_packages),
                "graph_packages_and_edges_present_in_lock": True,
                "lock_sha256": sha(self.lock_raw),
                "lock_packages_not_selected": sorted(
                    [list(k) for k in set(self.lock_packages) - set(ids.values())], key=str)}

    def manifest(self, artifact, directory):
        path = directory / "manifest.json"
        m = read_json(path)
        self.original_receipts[path] = self.identity(path)["sha256"]
        require(m["result"] == "PASS", "manifest not PASS")
        false_flags(m)
        require(m["source_before"] == m["source_after"] and m["source_changed"] is False,
                "measured source changed")
        s = m["source_before"]
        require(s["commit"] == artifact["source"]["tested_commit"] == m["expected_source_commit"] and
                s["tree"] == TREE and s["source_state"] == "committed-clean" and
                s["tracked_worktree_verified"] is True and s["tracked_entries"] == 6856 and
                s["tracked_bytes"] == 792504967, "inner/outer source mismatch")
        require(m["execution_context"] == "github-hosted" and m["compiler_channel"] == "1.95.0" and
                m["build_profile"] == "release" and not m["build_environment_overrides"] and
                m["default_release_configuration_checked"] is True,
                "unexpected execution/build context")
        require(m["cargo_configuration_before"] == m["cargo_configuration_after"] and
                m["cargo_configuration_changed"] is False and
                not m["cargo_configuration_before"]["violations"], "Cargo configuration changed")
        for name, expected in m["artifact_sha256"].items():
            require(self.identity(directory / name)["sha256"] == expected,
                    f"manifest artifact mismatch: {directory.name}/{name}")
        binaries = [name for name in m["artifact_sha256"] if name.startswith("pon_w1_")]
        require(len(binaries) == 1, "retained executable not unique")
        binary = directory / binaries[0]
        digest = self.identity(binary)["sha256"]
        for k in ("binary_sha256_before", "binary_sha256_after",
                  "retained_binary_sha256_before", "retained_binary_sha256_after"):
            require(m[k] == digest, "binary identity changed")
        with binary.open("rb") as f:
            header = f.read(64)
        require(header[:6] == b"\x7fELF\x02\x01", "not a little-endian ELF64 binary")
        machine = struct.unpack_from("<H", header, 18)[0]
        expected_machine, target, runner_arch = ((62, "x86_64-unknown-linux-gnu", "X64")
            if m["architecture"] == "x64" else (183, "aarch64-unknown-linux-gnu", "ARM64"))
        require(machine == expected_machine == m["binary_elf_machine"] and m["target"] == target and
                m["runner_context"]["RUNNER_ARCH"] == runner_arch, "ELF/target/runner mismatch")
        require(m["runner_context"]["GITHUB_RUN_ID"] == "41330488677", "unexpected workflow run")
        observations = m["observations"]
        require(all(o["exit_code"] == 0 and o["timed_out"] is False for o in observations),
                "command failed/timed out")
        require([o["timeout_seconds"] for o in observations[:4]] == [30, 30, 30, 900] and
                all(o["timeout_seconds"] == 300 for o in observations[4:]), "original caps changed")
        require("--locked" in observations[3]["command"] and
                "--release" in observations[3]["command"], "build not locked release")
        reader = m["reader"]
        require(reader["record_consistency"] == "PASS" and not reader["semantic_alerts"],
                "original reader reported inconsistency/alerts")
        false_flags(reader)
        result = {"directory": directory.name, "manifest_sha256": self.identity(path)["sha256"],
                  "source_commit": s["commit"], "source_tree": s["tree"],
                  "architecture": m["architecture"], "target": target,
                  "elf_machine": machine, "retained_binary_sha256": digest,
                  "all_manifest_file_hashes_match": True, "source_before_after_equal": True,
                  "all_binary_pins_match": True, "execution_context": m["execution_context"],
                  "runner_context": m["runner_context"], "compiler_channel": m["compiler_channel"],
                  "command_count": len(observations), "all_commands_passed_original_caps": True,
                  "native_command_wall_ns": [o["elapsed_ns"] for o in observations[4:]],
                  "qualification_flags": {flag: m[flag] for flag in FLAGS},
                  "reader_flags": {k: v for k, v in reader.items() if isinstance(v, bool)},
                  "reader_semantic_alerts": reader["semantic_alerts"]}
        return m, result

    def legal(self, directory, m, version):
        samples = {"v1": 2, "v2": 8}[version]
        schema = "pon-w1-legal-strategy-" + version
        require(len(m["shards"]) == 30 and len(m["observations"]) == 34 and
                len(m["reader"]["shards"]) == 30, "incomplete legal shard grid")
        reader = m["reader"]
        require(reader["observed_samples_per_class"] == samples and
                reader["required_policy_samples_per_class"] == 8 and
                reader["policy_sample_count_satisfied"] is (version == "v2"), "sample policy changed")
        lane_counts, lane_attempts, lane_cpu, lane_wall = Counter(), Counter(), Counter(), Counter()
        lane_streams, lane_challenges, lane_winners = {}, set(), set()
        shard_reports, cohort_ratios, seen_grid = [], [], set()
        classes = defaultdict(lambda: Counter())
        for idx, shard in enumerate(m["shards"]):
            conf = shard["configuration"]
            key = (conf["class"], conf["target_index"], conf["reuse_winners"])
            require(key not in seen_grid, "duplicate shard")
            seen_grid.add(key)
            require(shard["result"] == "PASS", "shard failed")
            original = shard["reader"]
            false_flags(original)
            name = shard["observation"]["stdout"]
            require(name == f"campaign-{idx:02d}.stdout", "unexpected shard naming/order")
            require(self.identity(directory / name)["sha256"] == original["input_sha256"] and
                    self.identity(directory / name)["bytes"] == original["input_bytes"], "reader input hash differs")
            counts, cpu, wall, attempts, outcomes = Counter(), Counter(), Counter(), Counter(), Counter()
            cohorts, searches, verifiers, mutations, candidates = {}, {}, set(), set(), set()
            material = campaign = ended = None
            prefix = prefix_hash = None
            pending_proof_checks = []
            fingerprints = {(f["sample"], f["search_index"]): f for f in original["search_fingerprints"]}
            with (directory / name).open("rb") as f:
                for line in f:
                    row = loads(line)
                    require(ended is None and row["schema"] == schema, "trailing/wrong-schema record")
                    kind = row["kind"]
                    counts[kind] += 1
                    if kind == "campaign":
                        campaign = row
                        false_flags(row)
                        require((row["class"], row["target_index"], row["reuse_winners"]) == key and
                                row["samples"] == samples and row["attempt_budget"] == 4096 and
                                row["seed"] == 0 and row["paths"] == list(PATHS) and
                                row["strategies"] == list(STRATEGIES), "campaign profile mismatch")
                    elif kind == "material":
                        material = row
                        require(row["class"] == key[0], "material class mismatch")
                    elif kind == "cohort":
                        ck = (row["sample"], row["strategy"])
                        require(ck not in cohorts and 0 <= ck[0] < samples and ck[1] in STRATEGIES,
                                "duplicate/invalid cohort")
                        require(row["setup_calls"] == 1 and row["searches"] == key[2], "actual setup count")
                        timing(row["setup"]); timing(row["total"])
                        cohorts[ck] = row
                        cpu[ck[1]] += row["total"]["cpu_ns"]
                        wall[ck[1]] += row["total"]["wall_ns"]
                    elif kind == "search":
                        sk = (row["sample"], row["strategy"], row["search_index"])
                        require(sk not in searches and sk[:2] in cohorts and 0 <= sk[2] < key[2] and
                                row["setup_calls"] == 0, "search coverage")
                        timing(row["timing"])
                        trials = row["attempts"]
                        require(0 < len(trials) <= 4096, "attempt budget")
                        target, task = bytes.fromhex(campaign["target"]), bytes.fromhex(material["task"])
                        stream_hash = hashlib.sha256()
                        for nonce, trial in enumerate(trials):
                            require(trial["nonce"] == nonce, "nonce gap")
                            challenge = pon_hash(("pon-w1-legal-strategy-challenge-" + version).encode(),
                                task, target, bytes(8), sk[0].to_bytes(8, "little"),
                                sk[2].to_bytes(8, "little"), nonce.to_bytes(8, "little"))
                            trace = bytes.fromhex(trial["trace"])
                            ticket = pon_hash(b"ticket", challenge, trace)
                            hit = ticket <= target
                            require(trial["challenge"] == challenge.hex() and
                                    trial["ticket"] == ticket.hex() and trial["target_hit"] is hit and
                                    (not hit or nonce == len(trials) - 1), "challenge/ticket/first-hit mismatch")
                            if prefix_hash is None:
                                pending_proof_checks.append((trace, trial["proof_sha256"]))
                            else:
                                ph = prefix_hash.copy(); ph.update(trace)
                                require(ph.hexdigest() == trial["proof_sha256"], "attempt proof digest mismatch")
                            encoded = (nonce.to_bytes(8, "little") + challenge + trace + ticket +
                                       bytes.fromhex(trial["proof_sha256"]) + bytes([hit]))
                            stream_hash.update(encoded)
                            challenge_key = trial["challenge"]
                            trial_digest = sha(encoded)
                            previous = self.challenge_ids[version].setdefault(challenge_key, trial_digest)
                            require(previous == trial_digest, "same challenge changed across lanes")
                            lane_challenges.add(challenge_key)
                        won = row["status"] == "target-hit-unverified"
                        require(won == hit and (won or len(trials) == 4096), "incomplete search")
                        winner = {"challenge": trials[-1]["challenge"], "proof_sha256": trials[-1]["proof_sha256"]} if won else None
                        require(row["winner"] == winner, "wrong winner")
                        fp = {"sample": sk[0], "search_index": sk[2], "attempts": len(trials),
                              "stream_sha256": stream_hash.hexdigest(), "winner": winner}
                        require(fp == fingerprints[(sk[0], sk[2])], "raw/original reader stream mismatch")
                        global_key = (key[0], key[1], sk[0], sk[2])
                        identity = canonical(fp)
                        require(self.streams[version].setdefault(global_key, identity) == identity,
                                "cross-lane/horizon/strategy stream mismatch")
                        require(lane_streams.setdefault(global_key, identity) == identity, "lane stream mismatch")
                        searches[sk] = {"row": row, "attempts": len(trials), "trace": trace}
                        attempts[sk[1]] += len(trials)
                        if winner:
                            lane_winners.add((winner["challenge"], winner["proof_sha256"]))
                    elif kind == "candidate":
                        ck = (row["sample"], row["search_index"])
                        require(ck not in candidates, "duplicate candidate")
                        candidates.add(ck)
                        raw = bytes.fromhex(row["proof_hex"])
                        require(len(raw) == 49188 and raw[:4] == b"PNW1" and
                                raw[4:16388].hex() == material["a_hex"] and
                                raw[16388:32772].hex() == material["b_hex"] and
                                sha(raw) == row["proof_sha256"], "candidate bytes/hash mismatch")
                        require(all(int.from_bytes(raw[i:i+4], "little") < Q for i in range(4,49156,4)),
                                "noncanonical candidate field element")
                        winner = fingerprints[ck]["winner"]
                        require({k: row[k] for k in ("challenge", "proof_sha256")} == winner,
                                "candidate/winner mismatch")
                        if prefix is None:
                            prefix = raw[:-32]
                            prefix_hash = hashlib.sha256(prefix)
                            for trace, digest in pending_proof_checks:
                                ph = prefix_hash.copy(); ph.update(trace)
                                require(ph.hexdigest() == digest, "first attempt proof hash mismatch")
                            pending_proof_checks.clear()
                        require(raw[:-32] == prefix, "candidate product prefix changed")
                    elif kind == "product_mutation":
                        sk = (row["sample"], row["strategy"], row["search_index"])
                        require(sk in searches and sk not in mutations, "mutation coverage")
                        mutations.add(sk)
                        sr = searches[sk]
                        mutated = bytearray(prefix + sr["trace"])
                        before = int.from_bytes(mutated[49152:49156], "little")
                        after = (before + 1) % Q
                        mutated[49152:49156] = after.to_bytes(4, "little")
                        require(row["offset"] == 49152 and row["before"] == before and row["after"] == after and
                                row["source_proof_sha256"] == sr["row"]["winner"]["proof_sha256"] and
                                row["proof_sha256"] == sha(mutated), "product mutation identity")
                        sr["mutated_digest"] = row["proof_sha256"]
                        timing(row["timing"])
                    elif kind == "verifier":
                        sk = (row["sample"], row["strategy"], row["search_index"])
                        vk = (*sk, row["case"], row["path"])
                        require(sk in searches and vk not in verifiers and row["path"] in PATHS and
                                row["case"] in ("legal", "product-last"), "verifier coverage")
                        verifiers.add(vk)
                        sr = searches[sk]
                        digest = (sr["row"]["winner"]["proof_sha256"] if row["case"] == "legal"
                                  else sr["mutated_digest"])
                        require(row["challenge"] == sr["row"]["winner"]["challenge"] and
                                row["proof_sha256"] == digest and
                                row["outcome"] == ("Accepted" if row["case"] == "legal" else "Product"),
                                "native verifier identity/outcome")
                        timing(row["timing"])
                        outcomes[row["case"] + "/" + row["outcome"]] += 1
                    elif kind == "end":
                        ended = row
                        require(row["complete"] is True, "incomplete end")
                    else:
                        raise ValueError("unexpected legal record " + kind)
            expected = {"campaign": 1, "material": 1, "cohort": samples*2,
                        "search": samples*2*key[2], "candidate": samples*key[2],
                        "product_mutation": samples*2*key[2], "verifier": samples*16*key[2], "end": 1}
            require(dict(counts) == expected == original["record_counts"], "complete raw counts differ")
            for k in ("cohort", "search", "candidate", "product_mutation", "verifier"):
                require(ended[k + "_count"] == expected[k], "end counters differ")
            require(not pending_proof_checks, "unverified first proof digest")
            for ck, cohort in cohorts.items():
                child = [s["row"] for sk, s in searches.items() if sk[:2] == ck]
                require(len(child) == key[2], "missing cohort searches")
                for axis in ("cpu_ns", "wall_ns"):
                    require(cohort["total"][axis] >= cohort["setup"][axis] +
                            sum(s["timing"][axis] for s in child), "cohort timer denominator")
            for original_cost in original["strategy_costs"]:
                strategy = original_cost["strategy"]
                require(original_cost["inclusive_cohort_total"] == {"cpu_ns": cpu[strategy], "wall_ns": wall[strategy]} and
                        original_cost["attempts"] == attempts[strategy] and
                        original_cost["actual_setup_calls"] == samples and original_cost["exhausted_searches"] == 0,
                        "raw/original strategy denominator mismatch")
            shard_ratio = ratio(cpu[STRATEGIES[0]], cpu[STRATEGIES[1]])
            f = original["generic_over_frozen_dispatch_cpu"]
            require(Fraction(f["numerator"], f["denominator"]) ==
                    Fraction(shard_ratio["numerator"], shard_ratio["denominator"]), "reader ratio mismatch")
            shard_reports.append({"class": key[0], "target_index": key[1], "reuse": key[2],
                                  "cpu_ns": dict(cpu), "wall_ns": dict(wall), "attempts": dict(attempts),
                                  "input_sha256": original["input_sha256"], **shard_ratio})
            for sample in range(samples):
                cohort_ratios.append(cohorts[(sample, STRATEGIES[0])]["total"]["cpu_ns"] /
                                     cohorts[(sample, STRATEGIES[1])]["total"]["cpu_ns"])
            lane_counts.update(counts); lane_attempts.update(attempts); lane_cpu.update(cpu); lane_wall.update(wall)
            classes[key[0]].update(cpu)
        require(seen_grid == {(c,t,h) for c in CLASSES for t in (0,1) for h in HORIZONS}, "fixed grid differs")
        require(len(lane_streams) == samples*5*2*64 == reader["unique_search_streams"], "dedup stream count")
        return {"version": version, "shards": 30, "samples_per_shard": samples,
                "policy_sample_count_satisfied": version == "v2", "counts": dict(lane_counts),
                "attempts": dict(lane_attempts), "cpu_ns": dict(lane_cpu), "wall_ns": dict(lane_wall),
                "whole_lane_ratio": ratio(lane_cpu[STRATEGIES[0]], lane_cpu[STRATEGIES[1]]),
                "unique_search_streams": len(lane_streams), "unique_attempt_challenges": len(lane_challenges),
                "unique_winning_challenge_and_proof": len(lane_winners),
                "stream_identity_inventory_sha256": sha(canonical([[list(k),v.decode()] for k,v in sorted(lane_streams.items())])),
                "per_class": [{"class": c, "cpu_ns": dict(classes[c]),
                               **ratio(classes[c][STRATEGIES[0]], classes[c][STRATEGIES[1]])} for c in CLASSES],
                "shard_ratio_min": min(s["generic_over_dispatch"] for s in shard_reports),
                "shard_ratio_max": max(s["generic_over_dispatch"] for s in shard_reports),
                "dispatcher_faster_shards": sum(s["generic_over_dispatch"] > 1 for s in shard_reports),
                "dispatcher_slower_shards": sum(s["generic_over_dispatch"] < 1 for s in shard_reports),
                "cohort_ratio_min": min(cohort_ratios), "cohort_ratio_max": max(cohort_ratios),
                "per_shard": shard_reports,
                "scope": "Independent raw cost/count/challenge/ticket/proof-digest audit; candidate AB products and full W1 transcripts are not rederived or replayed by this script."}

    def false_trace(self, directory, m):
        reader = m["reader"]
        p = directory / "campaign.stdout"
        require(self.identity(p)["sha256"] == reader["input_sha256"] and
                self.identity(p)["bytes"] == reader["input_bytes"], "false trace raw digest")
        require(m["valid_proof_acquisition_used"] is False and len(m["observations"]) == 5,
                "unexpected acquisition or command count")
        counts, attempts = Counter(), Counter()
        cohorts, searches, candidates, verifiers = {}, {}, {}, set()
        receiver = defaultdict(Counter)
        campaign = end = None
        with p.open("rb") as f:
            for line in f:
                row = loads(line); kind = row["kind"]
                require(end is None, "trailing false trace records")
                counts[kind] += 1
                if kind == "campaign":
                    campaign = row
                    false_flags(row)
                    require(row["samples"] == 8 and row["searches_per_setup"] == 4 and
                            row["attempt_budget"] == 4096 and row["valid_proof_acquisition_used"] is False,
                            "false trace fixed profile")
                elif kind == "material":
                    pass
                elif kind == "cohort":
                    ck = row["class"], row["sample"]
                    require(ck not in cohorts and row["setup_calls"] == 1 and row["searches"] == 4,
                            "false trace setup coverage")
                    timing(row["setup"]); timing(row["total"])
                    cohorts[ck] = row
                elif kind == "search":
                    sk = row["class"], row["sample"], row["search_index"]
                    require(sk not in searches and sk[:2] in cohorts and row["setup_calls"] == 0,
                            "false trace search coverage")
                    timing(row["timing"])
                    require(row["status"] == "target-hit-unverified", "false trace exhaustion")
                    require(0 < len(row["attempts"]) <= 4096, "false trace attempts")
                    for nonce, trial in enumerate(row["attempts"]):
                        require(trial["nonce"] == nonce and trial["proof_sha256"] is None,
                                "false trace nonce/digest scope")
                        ticket = pon_hash(b"ticket", bytes.fromhex(trial["challenge"]), bytes.fromhex(trial["trace"]))
                        hit = ticket <= bytes.fromhex(row["target"])
                        require(ticket.hex() == trial["ticket"] and trial["target_hit"] is hit and
                                hit == (nonce == len(row["attempts"])-1), "false trace first hit")
                    identity = canonical({"attempts": row["attempts"], "winner": row["winner"]})
                    require(self.false_streams.setdefault(sk,identity) == identity,
                            "false trace exact stream differs across lanes")
                    searches[sk] = row
                    attempts[sk[0]] += len(row["attempts"])
                elif kind == "candidate":
                    sk = row["class"], row["sample"], row["search_index"]
                    require(sk not in candidates and sk in searches, "false candidate coverage")
                    raw = bytes.fromhex(row["proof_hex"])
                    require(len(raw) == 49188 and sha(raw) == row["proof_sha256"] and
                            searches[sk]["winner"] == {k:row[k] for k in ("challenge","proof_sha256")},
                            "false candidate digest")
                    candidates[sk] = row["proof_sha256"]
                elif kind == "verifier":
                    sk = row["class"], row["sample"], row["search_index"]
                    vk = (*sk,row["path"])
                    require(vk not in verifiers and sk in candidates and row["path"] in campaign["paths"] and
                            row["outcome"] == "Transcript" and row["proof_sha256"] == candidates[sk],
                            "false verifier coverage/outcome")
                    verifiers.add(vk); timing(row["timing"])
                    receiver[sk[0]][row["path"]] += row["timing"]["cpu_ns"]
                elif kind == "end":
                    end = row
                    require(row["complete"] is True, "incomplete false trace end")
                else:
                    raise ValueError("unexpected false trace record")
        require(dict(counts) == reader["record_counts"], "false trace raw counts differ")
        require(len(cohorts) == 72 and len(searches) == len(candidates) == 288 and
                len(verifiers) == 288*len(campaign["paths"]), "false trace complete coverage")
        for kind in ("material", "cohort", "search", "candidate", "verifier"):
            require(end[kind+"_count"] == counts[kind], "false trace end counts")
        for ck, c in cohorts.items():
            child = [r for k,r in searches.items() if k[:2] == ck]
            require(len(child) == 4 and {r["search_index"] for r in child} == {0,1,2,3},
                    "false trace search completeness")
            for axis in ("cpu_ns","wall_ns"):
                require(c["total"][axis] >= c["setup"][axis] + sum(r["timing"][axis] for r in child),
                        "false trace inclusive timer")
        per_class, total_attacker, total_receiver = [], 0, Counter()
        for r in reader["actual_reuse_cohorts"]:
            cls = r["class"]
            cpu = sum(c["total"]["cpu_ns"] for k,c in cohorts.items() if k[0] == cls)
            require(cpu == r["full_attacker_cohort_total"]["cpu_ns"] and attempts[cls] == r["attempts"],
                    "false attacker denominator mismatch")
            ratios = {}
            for path, value in receiver[cls].items():
                require(value == r["verification"][path]["cpu_ns"] and
                        value/cpu == r["receiver_rejection_cpu_over_full_attacker_cpu"][path],
                        "false receiver ratio mismatch")
                ratios[path] = {"numerator": value,"denominator": cpu,"ratio": value/cpu}
            per_class.append({"class":cls,"attacker_cpu_ns":cpu,"attempts":attempts[cls],
                              "receiver_cpu_ns":dict(receiver[cls]),"ratios":ratios})
            total_attacker += cpu; total_receiver.update(receiver[cls])
        return {"counts":dict(counts),"samples":8,"classes":9,"searches_per_setup":4,
                "attempts":sum(attempts.values()),"attacker_cpu_ns":total_attacker,
                "receiver_cpu_ns":dict(total_receiver),
                "overall_receiver_over_full_attacker_cpu":{p:{"numerator":n,"denominator":total_attacker,
                                                               "ratio":n/total_attacker}
                                                            for p,n in total_receiver.items()},
                "per_class_production_ratio_min":min(r["ratios"]["production"]["ratio"] for r in per_class),
                "per_class_production_ratio_max":max(r["ratios"]["production"]["ratio"] for r in per_class),
                "per_class":per_class,"all_native_outcomes":"Transcript",
                "public_attack_amplification_measured":False,
                "scope":"Full primitive rejection CPU / actual complete setup-plus-all-search attacker CPU; not public fanout, queueing or network amplification."}

    def run(self):
        artifacts = []
        for ident in IDS:
            artifact = self.archive(ident)
            artifact.update(self.source_graph(artifact))
            artifact["lanes"] = []
            for directory in sorted((self.root/ident).iterdir()):
                if not directory.is_dir():
                    continue
                m, lane = self.manifest(artifact,directory)
                if directory.name.startswith("w1-legal-strategy-"):
                    lane["legal"] = self.legal(directory,m,directory.name.rsplit("-",1)[1])
                else:
                    lane["false_trace"] = self.false_trace(directory,m)
                artifact["lanes"].append(lane)
            artifacts.append(artifact)
            print(f"PASS {ident} {artifact['name']}",flush=True)
        for p, digest in self.original_receipts.items():
            require(sha(p.read_bytes()) == digest,"original manifest/receipt changed during audit")
        v2 = [l for a in artifacts for l in a["lanes"] if l.get("legal",{}).get("version") == "v2"]
        v1 = [l for a in artifacts for l in a["lanes"] if l.get("legal",{}).get("version") == "v1"]
        false = [l for a in artifacts for l in a["lanes"] if "false_trace" in l]
        require(len(v2)==len(v1)==4 and len(false)==8,"artifact family coverage")
        require(len({l["legal"]["stream_identity_inventory_sha256"] for l in v2}) == 1 and
                len({l["legal"]["stream_identity_inventory_sha256"] for l in v1}) == 1,
                "same version stream inventory changed across architecture/source")
        return {"schema":"independent-hosted-w1-cost-audit-v1","result":"PASS",
                "head":HEAD,"prospective_merge":MERGE,"tree":TREE,"base":BASE,
                "workflow_run_id":"41330488677","artifacts":artifacts,
                "script_sha256":sha(Path(__file__).read_bytes()),
                "locked_graph":{"lock_sha256":sha(self.lock_raw),
                    "normalized_resolved_graph_sha256":self.normalized_graph_hash,
                    "all_12_graphs_equal_after_path_metadata_exclusion":True,
                    "all_resolved_package_identities_and_edges_in_lock":True},
                "cross_lane_dedup":{
                    v:{"lanes":4,"unique_search_streams":len(self.streams[v]),
                       "unique_attempt_challenges":len(self.challenge_ids[v]),
                       "same_streams_across_architectures_and_source_refs":True}
                    for v in ("v1","v2")},
                "false_trace_unique_search_streams_all_eight_lanes":len(self.false_streams),
                "v2_whole_lane_generic_over_dispatch_range":[min(l["legal"]["whole_lane_ratio"]["generic_over_dispatch"] for l in v2),
                                                           max(l["legal"]["whole_lane_ratio"]["generic_over_dispatch"] for l in v2)],
                "false_trace_overall_production_ratio_range":[min(l["false_trace"]["overall_receiver_over_full_attacker_cpu"]["production"]["ratio"] for l in false),
                                                              max(l["false_trace"]["overall_receiver_over_full_attacker_cpu"]["production"]["ratio"] for l in false)],
                "all_qualification_flags_false":True,
                "limitations":[
                    "Readback independently checks retained bytes, recorded execution identity and integer arithmetic, not remote process authentication or clocks.",
                    "No W1 transcript replay or fresh native campaign is executed; AB products are not rederived in this hosted audit.",
                    "Same deterministic stream on x64/ARM/head/merge is repeated measurement, not a new independent mining stream or credited chainwork.",
                    "V2 meets only the unchanged eight-sample count on the fixed five-class/two-target/three-horizon grid.",
                    "Complete strategy CPU includes binary retention and proof hashing but excludes separate material generation, later evidence output/destruction and verification.",
                    "False-trace ratios are single full-primitive receiver rejection CPU over complete actual attacker cohort CPU, not measured network amplification.",
                    "No fastest-adversary lower bound, independent-hardware qualification, model benefit, quantum claim, public-service qualification or production activation follows.",
                    "Hosted x64 and ARM timing varies by runner; cross-host absolute CPU values are not controlled causal performance comparisons."]}


def markdown(report):
    text = ["# Hosted W1 成本原始记录：独立复核", "",
        "**12 个 artifacts、16 个 native 捕获均完成独立记录复核。V2 四条 lane 的八样本固定网格成立，全部安全/资源/上线资格仍为 false。**", "",
        f"Head `{HEAD}`；prospective merge `{MERGE}`；两者 tree `{TREE}`。", "",
        "本报告直接读取冻结 JSONL，未导入项目 reader，未重新执行 native。整数成本先由 cohort/search/verifier 记录求和，再逐项对照原 reader。保留的 archive、成员大小/CRC、manifest SHA-256、ELF、source 前后与锁图均检查。完整 W1 transcript 和 AB product 没有在本脚本内再次计算。", "",
        "## V2：完整固定策略", "",
        "CPU 包括一次实际 setup、全部失败与成功 attempts、trial retention 和 proof hashing；不含另记公共材料生成、后续输出/销毁或 native verifier。`Δ` 为 dispatcher / generic − 1。", "",
        "| Lane | Artifact | Generic CPU 秒 | Dispatcher CPU 秒 | Dispatcher Δ | Shard 比值区间 generic/dispatch |",
        "| --- | --- | ---: | ---: | ---: | ---: |"]
    for a in report["artifacts"]:
        for l in a["lanes"]:
            legal=l.get("legal")
            if not legal or legal["version"]!="v2": continue
            cpu=legal["cpu_ns"]
            text.append(f"| {a['source']['kind']} / {l['architecture']} | {a['id']} | {cpu[STRATEGIES[0]]/1e9:.9f} | {cpu[STRATEGIES[1]]/1e9:.9f} | {legal['whole_lane_ratio']['dispatch_cpu_change_percent']:+.6f}% | {legal['shard_ratio_min']:.6f}–{legal['shard_ratio_max']:.6f} |")
    first=next(l["legal"] for a in report["artifacts"] for l in a["lanes"] if l.get("legal",{}).get("version")=="v2")
    text += ["",f"每个 V2 lane：30 shards；每 shard 实际 8 samples；{first['counts']['cohort']:,} setups/cohorts；{first['counts']['search']:,} complete searches；{sum(first['attempts'].values()):,} paid attempts；{first['counts']['candidate']:,} 完整 candidate 记录；{first['counts']['verifier']:,} native verifier calls。全部 search 找到 first hit，所有失败尝试计入成本。legal 均为 Accepted，product-last 均为 Product。", "",
        f"四条 V2 lane 共同使用同一组 **{first['unique_search_streams']:,} 搜索流 / {first['unique_attempt_challenges']:,} attempted challenge 身份**。策略、horizon 前缀、head/merge、x64/ARM 的相同流已逐项匹配；四次执行不能写成四倍独立流或新增 chainwork。", "",
        "### 按材料类保留全部结果", "",
        "下表仍是每类全部 target/horizon/sample 的完整聚合，百分比不能跨 lane 拼接成事后最优策略。", "",
        "| Lane | 材料类 | Generic CPU 秒 | Dispatcher CPU 秒 | Dispatcher Δ |",
        "| --- | --- | ---: | ---: | ---: |"]
    for a in report["artifacts"]:
        for l in a["lanes"]:
            legal=l.get("legal")
            if not legal or legal["version"]!="v2": continue
            for r in legal["per_class"]:
                text.append(f"| {a['source']['kind']} / {l['architecture']} | {r['class']} | {r['cpu_ns'][STRATEGIES[0]]/1e9:.9f} | {r['cpu_ns'][STRATEGIES[1]]/1e9:.9f} | {r['dispatch_cpu_change_percent']:+.6f}% |")
    text += ["", "## V1 历史两样本 lane", "",
        "V1 保持原两样本语义，样本政策仍未满足；下列计数与成本来自其自身版本的挑战域，未重标为 V2。", "",
        "| Lane | Artifact | 完整 attempts | Verifier calls | Generic CPU 秒 | Dispatcher CPU 秒 | Dispatcher Δ |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |"]
    for a in report["artifacts"]:
        for l in a["lanes"]:
            legal=l.get("legal")
            if not legal or legal["version"]!="v1": continue
            cpu=legal["cpu_ns"]
            text.append(f"| {a['source']['kind']} / {l['architecture']} | {a['id']} | {sum(legal['attempts'].values()):,} | {legal['counts']['verifier']:,} | {cpu[STRATEGIES[0]]/1e9:.9f} | {cpu[STRATEGIES[1]]/1e9:.9f} | {legal['whole_lane_ratio']['dispatch_cpu_change_percent']:+.6f}% |")
    text += ["", "## False-trace：完整拒绝成本", "",
        "每条捕获为九类 × 八个实际 setup × 每 setup 四次搜索。比值分母是全部 attacker cohort CPU，含 setup 与全部 misses；分子为同捕获完整 production verifier 的拒绝 CPU。四路径与五路径捕获分别保留，不合并成一个不同计时窗口。", "",
        "| Lane | Artifact / 路径组 | Attacker CPU 秒 | Production 拒绝 CPU 秒 | 完整比值 | 九类比值范围 |",
        "| --- | --- | ---: | ---: | ---: | ---: |"]
    for a in report["artifacts"]:
        for l in a["lanes"]:
            f=l.get("false_trace")
            if not f: continue
            group="4 paths" if l["directory"]=="w1-false-trace-reuse-v1" else "5 paths"
            text.append(f"| {a['source']['kind']} / {l['architecture']} | {a['id']} / {group} | {f['attacker_cpu_ns']/1e9:.9f} | {f['receiver_cpu_ns']['production']/1e9:.9f} | {f['overall_receiver_over_full_attacker_cpu']['production']['ratio']:.6f} | {f['per_class_production_ratio_min']:.6f}–{f['per_class_production_ratio_max']:.6f} |")
    text += ["", "全部 false-trace native 结果为 Transcript 拒绝；零 valid-proof acquisition。各路径、各类整数分子分母及完整 record counts 保存在 JSON。八份捕获的 deterministic search identities 相同，不能当作八倍独立挑战。此比值仅是本次 hosted 原语拒绝观察，不是公网 fanout/队列/存储/签名/业务确认放大系数，也不与历史不同分母/源码/主机观察作因果比较。", "",
        "## 身份、锁图与资格边界", "",
        f"Cargo.lock SHA-256：`{report['locked_graph']['lock_sha256']}`。12 个 metadata 图各有 174 selected packages，均在 179-package lock 中；逐边核对后，忽略文件系统定位元数据的 normalized resolved graph 全部一致：`{report['locked_graph']['normalized_resolved_graph_sha256']}`。", "",
        "x64 retained ELF machine 为 62，ARM64 为 183；每条 lane 的 measured-before/after 与 retained-before/after binary pin 均匹配实际文件。source 前后同一 tree，6,856 tracked entries / 792,504,967 bytes。所有 identity/build/native commands 均 exit 0、无 timeout，原 30/900/300 秒 caps 不变。", "",
        "`hardness_accepted`、`work_profile_qualified`、`resource_fairness_qualified`、`public_service_measured`、`independent_hardware_qualified`、`public_network_ready`、`production_activation` 在全部 manifest/reader/raw campaign 中均为 false。reader 的 `native_execution_authenticated` / `w1_transcript_replayed` 等边界保持原值；run success 不替代成本安全证明。", "",
        "这是 hosted x64 与 ARM 上的固定原始记录复核。跨主机绝对 CPU 不构成受控因果性能比较，也不证明最快合法策略、GPU/ASIC/量子成本、模型增益、公开网络业务确认或生产激活。完整结构策略中的正负结果全部保留。", "",
        "## 复现", "", "使用 Python 3.11 或更新版本，在保留的原 artifacts 与最终源码上运行：", "", "```sh",
        "python3 analyze-hosted-cost.py --root /tmp/trnm-pon-hosted-3bbc/cost-artifacts --source /tmp/trnm-pon-security-final", "```", "",
        "脚本只读取原 artifact 子目录、ZIP 与 receipt，仅写同级 `hosted-cost-analysis.json` 和 `hosted-cost-analysis.md`。它不会运行 native/Cargo、不会修改 raw 或原 manifest。", ""]
    return "\n".join(text)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,default=Path(__file__).resolve().parent)
    parser.add_argument("--source",type=Path,default=Path("/tmp/trnm-pon-security-final"))
    args=parser.parse_args()
    report=Audit(args.root,args.source).run()
    jp=args.root/"hosted-cost-analysis.json"
    mp=args.root/"hosted-cost-analysis.md"
    jp.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
    mp.write_text(markdown(report))
    print(json.dumps({"result":"PASS","json":str(jp),"markdown":str(mp),
        "v2_ratio_range":report["v2_whole_lane_generic_over_dispatch_range"],
        "false_trace_ratio_range":report["false_trace_overall_production_ratio_range"]}))


if __name__=="__main__":
    main()
