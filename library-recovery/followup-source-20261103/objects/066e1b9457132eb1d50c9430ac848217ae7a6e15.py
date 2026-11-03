#!/usr/bin/env python3
"""Read-only independent audit of exact-E pure-PoN two-architecture observations.

Requires the two original ZIP files and the six exact source files in PINS.
No native ELF or network is executed. Original pinned readers are re-run.
"""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import zipfile

HEAD = "974932be6dcfe830ce1ce92d58cb10e89cb8358d"
TREE = "d4435ebdecac15e9a3fb2852eb1f835b336e452e"
PINS = [
  {
    "path": "scripts/ci/check_pure_pon_pressure_v2.py",
    "blob": "ae2e538bf45caa7fe55e3bb403befe630b0109be",
    "sha256": "250bd0bbeacab71cb8117e7b70feb69c90e3fb35620d1798935db465b55f03d3",
    "bytes": 37383
  },
  {
    "path": "scripts/ci/check_pure_pon_attacker_cost_v1.py",
    "blob": "1df10c633661e019a38bd7f8c6e6601462e6cd2c",
    "sha256": "be86027666c7bd4db7b846cbce2467c22a8646a1a291c556d74b24a0bd2892be",
    "bytes": 28456
  },
  {
    "path": "scripts/ci/check_pure_pon_process_cost_v1.py",
    "blob": "0b1b1f5257e3eb7f17d08dd51e02d94e26b2d1a6",
    "sha256": "ac856100e75ac9fa4052c6661d956df1968823b88246fc3bf2cdef6a04d9d83d",
    "bytes": 25769
  },
  {
    "path": "scripts/ci/check_pure_pon_receiver_owner_v1.py",
    "blob": "ed93516b5328d808976a28b47079f15a719ddf0b",
    "sha256": "53828887bceba5286628379b03277d9aeca6b434588c171807ae1884d20d5594",
    "bytes": 24713
  },
  {
    "path": "scripts/ci/run_pure_pon_admission_daa_v2.py",
    "blob": "ad8251620ea4e2bc69483b9b298d62b94db63fd1",
    "sha256": "c32b39097b412cb843fa6162207c9cb9da163d5390bb08b48a920c3272417452",
    "bytes": 21618
  },
  {
    "path": "scripts/ci/pure_pon_binary_archive_v1.py",
    "blob": "3f90dcc838a466e721fa12c0966f2d4bce000151",
    "sha256": "aa39279fa0c8d207fc8e27dcf4457e83d53b306a64e7a747cc395f6d6911c8da",
    "bytes": 12265
  }
]
ARCHIVES = {
    "x86_64": (12885297427, 79757873, "8fae551af24227ddd5bcc42eae507ebaf7ae5ed99deba24250cd7861d2c3b465", 62),
    "aarch64": (12885821097, 78022473, "926a7007584415f17bfcabad92bfc47145e523e40510b224187d974b962eec59", 183),
}
ROSTER = re.compile(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in \d+(?:\.\d+)?s")

def require(ok, message):
    if not ok:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def strict(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, "duplicate JSON key")
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))

def load_module(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[path.stem] = module
    spec.loader.exec_module(module)
    return module

def sources(root):
    for pin in PINS:
        path = root / pin["path"]
        require(path.is_file() and not path.is_symlink(), "source input")
        raw = path.read_bytes()
        require(len(raw) == pin["bytes"] and sha(raw) == pin["sha256"], "source SHA")
        require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
                == pin["blob"], "source Git blob")
    return [load_module(root / p["path"]) for p in PINS[:4]]

def audit_archive(path, architecture, modules):
    aid, expected_bytes, expected_hash, elf_machine = ARCHIVES[architecture]
    require(path.is_file() and not path.is_symlink(), "archive input")
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    require(path.stat().st_size == expected_bytes and h.hexdigest() == expected_hash, "ZIP binding")
    pressure, actor, process, receiver = modules
    inventory = []
    with zipfile.ZipFile(path) as archive, tempfile.TemporaryDirectory(prefix="pure-E-readback-") as temp:
        entries = archive.infolist()
        require(len(entries) == len({e.filename for e in entries}), "duplicate ZIP paths")
        require(sum(e.file_size for e in entries) <= 512 * 1024 * 1024, "total ZIP bound")
        root = Path(temp)
        for e in entries:
            parts = PurePosixPath(e.filename)
            require(not parts.is_absolute() and ".." not in parts.parts
                    and not stat.S_ISLNK(e.external_attr >> 16), "unsafe ZIP member")
            require(e.file_size <= 64 * 1024 * 1024, "member bound")
            raw = archive.read(e)
            inventory.append({"path": e.filename, "bytes": len(raw), "sha256": sha(raw)})
            if e.filename.startswith(("campaign/pressure-native/", "campaign/receiver-owner-native/")):
                destination = root.joinpath(*parts.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as out:
                    out.write(raw)
        def read(name):
            return archive.read("campaign/" + name)
        def value(name):
            return strict(read(name))
        original = value("results.json")
        require(original["expected_head"] == HEAD and original["complete_success"] is True
                and original["failure"] is None and original["finalization_failures"] == [], "terminal")
        source_records = [strict(archive.read(n)) for n in
                          ("source-checkout.json", "source-final.json", "campaign/source-before.json",
                           "campaign/source-after.json")]
        require(all(r["tested_commit"] == HEAD and r["tested_tree"] == TREE
                    and r["tracked_worktree_verified"] is True for r in source_records), "source records")
        require(original["source_before"] == source_records[2]
                and original["source_after"] == source_records[3], "terminal source records")
        require(original["toolchain_observation"]["native_machine"] == architecture
                and original["toolchain_observation"]["rustc"]["release"] == "1.95.0", "native compiler")
        steps = original["steps"]
        require(len(steps) == 35 and len({s["name"] for s in steps}) == 35, "step roster")
        for step in steps:
            require(step == value(step["name"] + ".step.json"), "step exact report")
            require(step["complete_success"] is True and step["returncode"] == 0
                    and step["error"] is None, "actual successful step")
            for label in ("stdout", "stderr"):
                raw = read(step[label])
                require(len(raw) == step[label + "_bytes"]
                        and sha(raw) == step[label + "_sha256"]
                        and step[label + "_truncated"] is False, "raw step log binding")
        totals = Counter()
        gates = original["native_verdicts"]
        require(set(original["required_native_gates"]) == {g["name"] for g in gates}
                and len(gates) == 13, "native gate coverage")
        for gate in gates:
            require(gate == value(gate["name"] + ".native-verdict.json"), "verdict raw binding")
            final = read(gate["name"] + ".stdout.log").decode().rstrip().splitlines()[-1]
            m = ROSTER.fullmatch(final)
            require(m is not None, "native terminal summary")
            counts = dict(zip(("passed", "failed", "ignored", "measured", "filtered_out"),
                              map(int, m.groups())))
            require(counts == gate["terminal_summary"] and counts["passed"] > 0
                    and counts["failed"] == 0 and gate["qualified"] is True, "native roster counts")
            totals.update(counts)
        binaries = value("binaries.json")
        archive_manifest = value("binary-archive-v1.json")
        require(archive_manifest["complete"] is True and archive_manifest["errors"] == []
                and archive_manifest["expected_head"] == HEAD
                and archive_manifest["expected_tree"] == TREE, "binary archive terminal")
        require(set(binaries) == {f["name"] for f in archive_manifest["files"]}
                and len(binaries) == 6, "binary roster")
        binary_rows = []
        for f in archive_manifest["files"]:
            raw = read(f["retained_path"])
            b = binaries[f["name"]]
            require(raw.startswith(b"\x7fELF")
                    and int.from_bytes(raw[18:20], "little") == elf_machine, "ELF architecture")
            require(len(raw) == b["bytes"] == f["copied_bytes"] == f["expected_bytes"]
                    and sha(raw) == b["sha256"] == f["sha256"] == f["expected_sha256"], "ELF byte binding")
            require(b["profile"]["opt_level"] == "3" and b["profile"]["debug_assertions"] is False,
                    "release compilation")
            binary_rows.append({"name": f["name"], "bytes": len(raw), "sha256": sha(raw)})
        native_dir = root / "campaign/pressure-native"
        pure = pressure.check(pressure.load(native_dir / "campaign.json"),
                              pressure.load(native_dir / "preparation.json"),
                              [pressure.load(native_dir / (p + ".json")) for p in pressure.PHASES])
        nested = actor.check_directory(native_dir)
        whole = process.check_directory(native_dir)
        owners = receiver.check_directory(root / "campaign/receiver-owner-native")
        for actual, name in ((pure, "pressure-qualification.json"),
                             (nested, "attacker-cost-observation-v1.json"),
                             (whole, "process-cost-observation-v2.json"),
                             (owners, "receiver-owner-observation-v2.json")):
            require(actual == value(name), "recomputed original reader differs: " + name)
        require(pure["finite_qualification"] is True and owners["supplemental_finite_qualification"] is True,
                "finite observed service")
        # Independently sum disjoint whole actor process rows. Never add their nested thread CPU.
        actor_phase_cpu = {}
        for phase in whole["phases"]:
            total = sum(a["user_cpu_ns"] + a["system_cpu_ns"] for a in phase["actors"])
            require(all(a["total_cpu_ns"] == a["user_cpu_ns"] + a["system_cpu_ns"]
                        and a["exit_success"] is True and a["parent_forced_kill"] is False
                        for a in phase["actors"]), "actor raw CPU/terminal")
            require(total == phase["whole_actor_process_cpu"]["total_ns"], "independent actor sum")
            actor_phase_cpu[phase["phase"]] = total
        for r in owners["receiver_processes"]:
            require(r["total_cpu_ns"] == r["user_cpu_ns"] + r["system_cpu_ns"]
                    and r["exit_success"] is True and r["parent_forced_kill"] is False, "receiver CPU/terminal")
        return {"architecture": architecture, "artifact_id": aid, "archive_bytes": expected_bytes,
                "archive_sha256": expected_hash, "archive_members": len(entries),
                "all_members_crc_sha_checked": True, "archive_inventory": inventory,
                "source_records": source_records, "native_test_executions": dict(totals),
                "native_gates": gates, "successful_guarded_steps": len(steps),
                "retained_binaries": binary_rows,
                "finite_original_pressure": pure,
                "original_attacker_whole_process_cpu_ns": actor_phase_cpu,
                "original_actor_process_coverage_complete": whole["process_coverage_complete"],
                "original_actor_descendants_quiescent_observed": whole["descendants_quiescent_observed"],
                "all_hash_search_attempts_observed": nested["all_hash_search_attempts_observed"],
                "template_acquisition_search_trials_observed": nested["template_acquisition_search_trials_observed"],
                "separate_receiver_experiment": {
                    "supplemental_finite_qualification": owners["supplemental_finite_qualification"],
                    "original_campaign_qualification": owners["original_campaign_qualification"],
                    "exclusive_receiver_cgroup_observed": owners["exclusive_receiver_cgroup_observed"],
                    "fixed_parent_provisioned": owners["fixed_parent_provisioned"],
                    "receiver_processes": owners["receiver_processes"],
                    "service_phases": owners["service_phases"],
                    "actor_whole_process_cpu_ns": {
                        p["phase"]: p["whole_actor_process_cpu"]["total_ns"]
                        for p in owners["actor_process_phases"]}},
                "all_checks_passed": True}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--x64-archive", required=True, type=Path)
    parser.add_argument("--arm64-archive", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    modules = sources(args.source_root)
    results = [audit_archive(args.x64_archive, "x86_64", modules),
               audit_archive(args.arm64_archive, "aarch64", modules)]
    result = {
        "schema": "pon-pure-pressure-E-two-architecture-independent-audit-v1",
        "all_checks_passed": True, "source_commit": HEAD, "source_tree": TREE,
        "original_run": 40845715553, "source_pins": PINS,
        "audit_script_sha256": sha(Path(__file__).read_bytes()), "results": results,
        "scope": [
            "The original exact-source pressure, actor thread, whole-process and separate receiver readers were replayed over retained raw bytes; native ELFs and cryptography were not independently re-executed.",
            "Both architectures preserve actual zero-bit pure-v2 service predicates under a finite 90-second, 24-actor-per-attack observation. This is neither arbitrary Sybil fairness nor a deployed service.",
            "Pure-v2 uses the original public-product prefilter/arithmetic-fact path. It is not the RawR13 pure-History profile and does not qualify the independent History verifier's 25-percent CPU / 2-GiB envelope.",
            "205 native test executions pass per architecture; the transparent-complete-proof selector also retains one ignored expensive test. These native relation controls are not a generated transparent receipt.",
            "Whole-process actor CPU includes setup and tails; receiver CPU is from a distinct supplemental experiment. Nested CPU scopes and distinct campaigns must not be added together.",
            "Template acquisition trial count remains unknown even though process CPU captures its execution. No complete search-trial-count claim is made.",
            "The receiver supplement has no exclusive receiver cgroup observation and never grants original-campaign or fixed-parent installation authority.",
            "Source records attest their own exact tracked checks; this audit does not reconstruct the full Git tree, reproduce compiler output, authenticate hardware, or establish crash-safe durable business-child settlement.",
            "No WAN, energy, global worst-input, quantum hardness or production qualification is established."
        ]}
    with args.output.open("x") as out:
        json.dump(result, out, indent=2, allow_nan=False)
        out.write("\n")
    print(json.dumps({"all_checks_passed": True, "architectures": [
        {"arch": r["architecture"], "members": r["archive_members"],
         "native_tests": r["native_test_executions"],
         "original_actor_cpu_ns": r["original_attacker_whole_process_cpu_ns"],
         "finite_pressure": r["finite_original_pressure"]["finite_qualification"]}
        for r in results], "output": str(args.output)}))

if __name__ == "__main__":
    main()

