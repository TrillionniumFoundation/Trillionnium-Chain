#!/usr/bin/env python3
"""Apply only the reviewed admission-fence change to a new isolated worktree."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

BASE = Path("/home/qian-qi/chain-throughput-local-admin-20261107")
BASE_HEAD = "819309fd312298e099642e1253b1d4ba07113e98"
BASE_TREE = "f9d63abb9e2931fd78e26ccb87e3a7955068f267"
PROPOSAL = BASE / "admission-fence-followup-819309-20261107/proposal"
PATCHES = {
    "production-v1.patch": "8e93c923fd0379e37cd79fe430fb2e686cafcf9fc6d461697e211cc165ecb9a8",
    "regression-v1.patch": "416a86230434742de34406220342a2eb56efbe9160262d39c5e9c02abc290a32",
}
STORE = "trillionnium/crates/trnm-pon-node/src/store.rs"
OLD_TEST = "trillionnium/crates/trnm-pon-node/src/store/legacy_reorg_root_tests.rs"
NEW_TEST = "trillionnium/crates/trnm-pon-node/src/store/legacy_admission_root_tests.rs"
INVENTORY = "trillionnium/crates/trnm-pon-node/examples/support/distributed_source_inventory.rs"
CORPUS = "config/pon/pq-cross-branch-corpus-v1.json"
WORKFLOW = ".github/workflows/pon-recent-batch-acceptance.yml"
OLD_STORE_BLOB = "6769b89e1544d82fb41d418adf11d6b26ef01cc3"

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worktree", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--execute", action="store_true", required=True)
    args = parser.parse_args()
    root = Path(args.worktree).resolve(strict=True)
    out = Path(args.output).absolute()
    assert root.parent == BASE and root.name.startswith("work-admission-fence-")
    assert not out.is_relative_to(root) and out.is_relative_to(BASE)
    out.mkdir(parents=True, exist_ok=False)
    commands = []
    receipt = {"schema": "trnm-admission-fence-source-integration-v1",
               "state": "running", "root": str(root), "baseline": BASE_HEAD,
               "baseline_tree": BASE_TREE, "commands": commands,
               "native_test_execution": False, "commit_or_push": False}
    def save():
        (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    env = os.environ.copy()
    env.update({"CARGO_HOME": str(BASE / "local-build/cargo"),
                "CARGO_TARGET_DIR": str(BASE / "local-build/admission-fence-target"),
                "GIT_NO_LAZY_FETCH": "1", "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_OPTIONAL_LOCKS": "0", "PYTHONDONTWRITEBYTECODE": "1"})
    def run(label, argv):
        stdout = out / (label + ".stdout")
        stderr = out / (label + ".stderr")
        row = {"label": label, "argv": argv, "state": "attempted",
               "exit": None, "timed_out": False}
        commands.append(row)
        save()
        def retain_logs():
            for name, path in (("stdout", stdout), ("stderr", stderr)):
                row[name + "_present"] = path.is_file()
                if path.is_file():
                    row[name + "_bytes"] = path.stat().st_size
                    row[name + "_sha256"] = sha(path)
        try:
            with stdout.open("xb") as output_file, stderr.open("xb") as error_file:
                p = subprocess.run(argv, cwd=root, env=env, stdout=output_file,
                                   stderr=error_file, timeout=600)
        except BaseException as error:
            row["state"] = ("timed_out" if isinstance(error, subprocess.TimeoutExpired)
                            else "launch_failed" if isinstance(error, OSError)
                            else "interrupted_completion_unknown")
            row["timed_out"] = isinstance(error, subprocess.TimeoutExpired)
            row["exception"] = f"{type(error).__name__}: {error}"
            retain_logs()
            save()
            raise
        row.update({"state": "completed", "exit": p.returncode})
        retain_logs()
        save()
        if p.returncode:
            raise RuntimeError(f"{label}: exit {p.returncode}")
        return stdout.read_text()
    save()
    try:
        assert run("baseline-head", ["git", "rev-parse", "HEAD"]).strip() == BASE_HEAD
        assert run("baseline-tree", ["git", "rev-parse", "HEAD^{tree}"]).strip() == BASE_TREE
        assert run("baseline-status", ["git", "status", "--porcelain=v1"]) == ""
        assert Path(run("worktree-root", ["git", "rev-parse", "--show-toplevel"]).strip()).resolve() == root
        assert run("git-name", ["git", "config", "--local", "--get", "user.name"]).strip() == "ProfHepta"
        assert run("git-email", ["git", "config", "--local", "--get", "user.email"]).strip() == "102159240+ProfHepta@users.noreply.github.com"
        identity = json.loads(run("github-identity", ["/usr/bin/gh", "api", "user", "--jq", "{login:.login,id:.id}"]))
        assert identity == {"login": "ProfHepta", "id": 102159240}
        receipt["identity"] = identity
        run("preflight", ["bash", "scripts/project-preflight.sh"])
        for name, digest in PATCHES.items():
            assert sha(PROPOSAL / name) == digest
        paths = [str(PROPOSAL / name) for name in PATCHES]
        run("apply-check", ["git", "apply", "--check", *paths])
        run("apply-reviewed", ["git", "apply", *paths])
        cargo = "/home/qian-qi/.cargo/bin/cargo"
        run("format-source", [cargo, "+1.95.0", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all"])
        run("refresh-inventory", ["/usr/bin/python3", "scripts/refresh_distributed_source_inventory.py"])
        run("format-generated", [cargo, "+1.95.0", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all"])
        changed = set(run("changed-before-pins", ["git", "diff", "--name-only"]).splitlines())
        new = set(run("untracked-before-pins", ["git", "ls-files", "--others", "--exclude-standard"]).splitlines())
        assert changed == {STORE, OLD_TEST, INVENTORY}, changed
        assert new == {NEW_TEST}, new
        blobs = {}
        for n, path in enumerate((STORE, OLD_TEST, NEW_TEST, INVENTORY)):
            blobs[path] = run(f"source-blob-{n}", ["git", "hash-object", "--", path]).strip()
        raw = (root / CORPUS).read_text()
        corpus = json.loads(raw)
        assert json.dumps(corpus, indent=2) + "\n" == raw
        assert corpus["pinned_blobs"][STORE] == OLD_STORE_BLOB
        assert NEW_TEST not in corpus["pinned_blobs"] and NEW_TEST not in corpus["required_paths"]
        corpus["pinned_blobs"].update(blobs)
        corpus["pinned_blobs"] = dict(sorted(corpus["pinned_blobs"].items()))
        corpus["required_paths"] = sorted([*corpus["required_paths"], NEW_TEST])
        (root / CORPUS).write_text(json.dumps(corpus, indent=2) + "\n")
        workflow = (root / WORKFLOW).read_text()
        assert workflow.count(OLD_STORE_BLOB) == 1
        (root / WORKFLOW).write_text(workflow.replace(OLD_STORE_BLOB, blobs[STORE]))
        run("diff-whitespace", ["git", "diff", "--check"])
        run("inventory-check", ["/usr/bin/python3", "scripts/refresh_distributed_source_inventory.py", "--check"])
        run("format-check", [cargo, "+1.95.0", "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"])
        run("source-diff", ["git", "diff", "--", STORE, OLD_TEST, INVENTORY, CORPUS, WORKFLOW])
        receipt["source_blobs"] = blobs
        receipt["final_status"] = run("final-status", ["git", "status", "--porcelain=v1"])
        receipt["source_sha256"] = {p: sha(root / p) for p in (*blobs, CORPUS, WORKFLOW)}
        receipt["state"] = "reviewed_source_applied_pending_docs_and_frozen_validation"
        save()
        print(json.dumps({k: v for k, v in receipt.items() if k != "commands"}, indent=2))
    except BaseException as error:
        receipt["state"] = "failed"
        receipt["error"] = f"{type(error).__name__}: {error}"
        receipt["traceback"] = traceback.format_exc()
        save()
        raise

if __name__ == "__main__":
    main()
