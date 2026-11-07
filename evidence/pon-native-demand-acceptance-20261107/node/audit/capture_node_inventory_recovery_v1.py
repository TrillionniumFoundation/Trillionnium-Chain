#!/usr/bin/env python3
"""New recovery tool; original scratch artifacts were unavailable, not recovered.

Run only read-only Git/preflight/Cargo metadata commands. No build, test, source
edit, job mutation, branch mutation, or publication. New evidence is create-only
under recovery-evidence-tools. Final Node log/result are not parsed here.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

BASE = Path("/home/qian-qi/workspace/pon-demand-acceptance-20261107-root525798dad3c2")
SOURCE = BASE / "chain-source-bounded"
RUN = BASE / "build-receipts/complete-node-690f710c-v1"
OUT = BASE / "recovery-evidence-tools"
COMMIT = "690f710c1b6808787996e86aa4c36bd53e1f3939"
TREE = "b9ff2e5c4ca6e465b86cb4b2bd466ad831147899"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def fact(path):
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}


def create(name, raw):
    path = OUT / name
    with path.open("xb") as stream:
        stream.write(raw)
    return {"path": name, "bytes": len(raw), "sha256": sha(raw)}


def write(name, value):
    return create(name, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def git(*args):
    return subprocess.check_output(
        ["/usr/bin/git", "--no-replace-objects", *args], cwd=SOURCE)


def source_identity():
    value = {
        "commit": git("rev-parse", "HEAD").decode().strip(),
        "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
        "status": git("status", "--porcelain=v1", "-z", "--untracked-files=all").decode(),
    }
    assert value == {"commit": COMMIT, "tree": TREE, "status": ""}, value
    return value


def main():
    started_wall = time.time()
    before = source_identity()
    run_started = json.loads((RUN / "started.json").read_text())
    recorded_env = json.loads((RUN / "environment.json").read_text())
    source_manifest = json.loads((RUN / "source-before.json").read_text())
    assert run_started["expected_commit"] == COMMIT
    assert source_manifest["head"] == COMMIT and source_manifest["tree"] == TREE
    assert sha(canonical(source_manifest)) == run_started["source_sha256"]
    materialized = {row["path"]: row for row in source_manifest["materialized"]}
    assert len(materialized) == len(source_manifest["materialized"])

    for relative in ("trillionnium/Cargo.toml", "trillionnium/Cargo.lock",
                     "trillionnium/crates/trnm-pon-node/Cargo.toml"):
        observed = fact(SOURCE / relative)
        declared = materialized[relative]
        assert observed["sha256"] == declared["sha256"]
        assert observed["bytes"] == declared["bytes"]

    env = dict(os.environ)
    overrides = [key for key, value in env.items() if value and
                 (key.startswith("CARGO_PROFILE_") or key in
                  ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                   "RUSTC_WORKSPACE_WRAPPER"))]
    assert not overrides, overrides
    env.update(recorded_env)
    rustc = Path(recorded_env["RUSTC"])
    assert rustc.is_absolute()
    cargo = rustc.parent / "cargo"
    assert str(cargo) == run_started["command"][0]
    env["PATH"] = str(cargo.parent) + os.pathsep + env.get("PATH", "")
    preflight = subprocess.run(
        ["/usr/bin/bash", "scripts/project-preflight.sh", "--audit"],
        cwd=SOURCE, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        check=False, timeout=60)
    preflight_artifact = create("preflight-recovery-v1.log", preflight.stdout)
    assert preflight.returncode == 0, preflight.returncode

    command = [str(cargo), "metadata", "--locked", "--offline", "--manifest-path",
               "trillionnium/Cargo.toml", "--all-features", "--format-version", "1"]
    observed = subprocess.run(command, cwd=SOURCE, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=False, timeout=120)
    metadata_artifact = create("cargo-metadata-recovery-v1.json", observed.stdout)
    stderr_artifact = create("cargo-metadata-recovery-v1.stderr.log", observed.stderr)
    assert observed.returncode == 0, observed.returncode
    metadata = json.loads(observed.stdout)
    package = [row for row in metadata["packages"] if row["name"] == "trnm-pon-node"]
    assert len(package) == 1
    package = package[0]
    assert Path(package["manifest_path"]) == SOURCE / "trillionnium/crates/trnm-pon-node/Cargo.toml"
    targets = []
    for target in package["targets"]:
        relative = str(Path(target["src_path"]).relative_to(SOURCE))
        source_raw = (SOURCE / relative).read_bytes()
        expected = materialized[relative]
        assert len(source_raw) == expected["bytes"] and sha(source_raw) == expected["sha256"]
        assert target["kind"] in (["lib"], ["bin"], ["example"], ["test"])
        targets.append({
            "name": target["name"], "kind": target["kind"],
            "test": target["test"], "harness": target.get("harness"),
            "source": relative, "source_sha256": sha(source_raw),
            "required_features": target.get("required-features", []),
        })
    kind_counts = {kind: sum(row["kind"] == [kind] for row in targets)
                   for kind in ("lib", "bin", "test", "example")}
    assert kind_counts == {"lib": 1, "bin": 1, "test": 69, "example": 20}, kind_counts
    assert len(targets) == 91
    after = source_identity()
    assert after == before
    for relative in ("trillionnium/Cargo.toml", "trillionnium/Cargo.lock",
                     "trillionnium/crates/trnm-pon-node/Cargo.toml"):
        assert fact(SOURCE / relative)["sha256"] == materialized[relative]["sha256"]
    run_inputs = {
        "started": fact(RUN / "started.json"),
        "environment": fact(RUN / "environment.json"),
        "source_before": fact(RUN / "source-before.json"),
        "run_recorder": fact(BASE / "run_remote_node_gate.py"),
    }
    inventory = {
        "schema": "pon-complete-node-target-inventory-recovery-v1",
        "recovery_provenance": "Newly authored on desktop after scratch became unavailable; "
                               "no old local artifact bytes were recovered or reused.",
        "source_commit": COMMIT, "source_tree": TREE,
        "source_before_canonical_sha256": run_started["source_sha256"],
        "metadata": metadata_artifact, "run_inputs": run_inputs,
        "targets": targets, "target_count": len(targets), "kind_counts": kind_counts,
        "workspace_members": len(metadata["workspace_members"]),
        "resolved_packages": len(metadata["packages"]),
        "ignored_campaigns_executed_by_inventory": False,
        "complete_node_result_parsed": False,
        "independent_acceptance": False, "production_activation": False,
    }
    inventory_artifact = write("node-target-inventory-recovery-v1.json", inventory)
    parser_path = OUT / "parse_complete_node_log_recovery_v1.py"
    parser_syntax = None
    if parser_path.exists():
        parser_raw = parser_path.read_bytes()
        ast.parse(parser_raw, filename=str(parser_path))
        parser_syntax = {**fact(parser_path), "syntax_check": "AST only; parser not executed"}
    receipt = {
        "schema": "pon-node-inventory-capture-recovery-v1",
        "recovery_provenance": inventory["recovery_provenance"],
        "source_before": before, "source_after": after, "source_unchanged": before == after,
        "command": command, "cwd": str(SOURCE), "exit_code": observed.returncode,
        "started_unix_seconds": started_wall, "elapsed_seconds": time.time() - started_wall,
        "preflight": preflight_artifact, "metadata": metadata_artifact,
        "metadata_stderr": stderr_artifact, "inventory": inventory_artifact,
        "run_inputs": run_inputs, "script": fact(Path(__file__)),
        "parser_syntax_observation": parser_syntax, "tests_started": False,
        "source_modified": False, "original_job_modified": False,
        "original_recorder_modified": False, "production_activation": False,
    }
    result = write("inventory-capture-recovery-v1.json", receipt)
    print(json.dumps({"result": "INVENTORY_CAPTURED", "inventory": inventory_artifact,
                      "receipt": result, "targets": len(targets),
                      "workspace_members": len(metadata["workspace_members"]),
                      "resolved_packages": len(metadata["packages"]),
                      "complete_node_result_parsed": False}, sort_keys=True))


if __name__ == "__main__":
    main()
