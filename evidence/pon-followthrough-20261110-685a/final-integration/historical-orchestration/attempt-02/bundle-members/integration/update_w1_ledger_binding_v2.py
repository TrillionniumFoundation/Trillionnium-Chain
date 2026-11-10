#!/usr/bin/env python3
"""Review the existing twenty-path ledger against a real code checkpoint.

This integration recorder changes selected-source identity, never qualification.
Run once in the owned full checkout, after the Rust source checkpoint is committed.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

BASE = "da1374a200022bc14dc2bd325cc9ba29dbcd24ab"
OLD_SOURCE = "189b9b5959d836ef6ae96e14fb285948e4920aa9"
OLD_DIR = "evidence/pon-w1-lifetime-current-20261109"
NEW_DIR = "evidence/pon-w1-lifetime-current-20261110-685a"
STORE = "trillionnium/crates/trnm-pon-node/src/store.rs"
PINS = {
    "scripts/w1_lifetime_ledger.py": "a09b37a7187ceaee515ee37cceef09df6a6d337f670862d7cf2f3d75368c8303",
    "scripts/ci/test_w1_lifetime_ledger.py": "6be1706c1ded1a8efa02ee5c3ca04352fa989dbcf728d6f041192200921a5fa6",
    ".github/workflows/pon-w1-qrom-closure.yml": "f25dcf2021a1f8e4770f5df88299d1bd13b57686a10eff6242dc46018837620e",
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    root = args.root
    require(root.is_absolute() and root.is_dir() and root.resolve() == root, "regular absolute checkout root required")
    require(re.fullmatch(r"[0-9a-f]{40}", args.source), "full source commit required")
    env = dict(os.environ, GIT_NO_LAZY_FETCH="1", GIT_NO_REPLACE_OBJECTS="1", PYTHONDONTWRITEBYTECODE="1")

    def git(*argv):
        return subprocess.check_output(["git", "--no-replace-objects", *argv], cwd=root, env=env, timeout=60)

    def read_regular(relative):
        require(not Path(relative).is_absolute() and ".." not in Path(relative).parts, "unsafe relative source")
        parts = Path(relative).parts
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptor = None
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = child
            descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_size <= 2 * 1024 * 1024,
                    "nonregular or oversized source: " + relative)
            chunks = []
            count = 0
            while count <= 2 * 1024 * 1024:
                chunk = os.read(descriptor, min(65536, 2 * 1024 * 1024 + 1 - count))
                if not chunk:
                    break
                chunks.append(chunk)
                count += len(chunk)
            after = os.fstat(descriptor)
            identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                                      value.st_mtime_ns, value.st_ctime_ns)
            require(count <= 2 * 1024 * 1024 and count == before.st_size and identity(before) == identity(after),
                    "source changed while reading: " + relative)
            return b"".join(chunks)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)

    def blob(commit, relative):
        entry = git("ls-tree", commit, "--", relative).decode().strip()
        fields = entry.split(None, 3)
        require(len(fields) == 4 and fields[0] in ("100644", "100755") and fields[1] == "blob" and fields[3] == relative,
                "missing or nonregular Git blob: " + relative)
        return git("show", commit + ":" + relative)

    require(git("cat-file", "-t", args.source).strip() == b"commit", "source is not a commit")
    require(git("rev-parse", args.source).decode().strip() == args.source, "source identity mismatch")
    require(git("rev-parse", "--show-toplevel").decode().strip() == str(root), "full checkout root required")
    history_shallow = git("rev-parse", "--is-shallow-repository").strip()
    require(history_shallow in (b"true", b"false"), "unknown Git history depth")
    # All selected objects and the complete BASE -> C1 -> C2 segment are
    # required. Earlier history outside this segment is not a source claim.
    selected_c1 = "11c9562252d3cf56b423c7756569be0c669d9606"
    selected_c2 = "8d8c0e64e7a301fc111a6720721a14816639e5aa"
    require(args.source == selected_c2, "unreviewed selected checkpoint")
    expected_lineage = [
        (BASE, "00479a98dabc6b1fd91a0ceef82ffbdbffb78067", None),
        (selected_c1, "94e1b4f1718dec1b88bccd7e1996ba83ca29ff8a", BASE),
        (selected_c2, "7c003a3d183ad33ff4f3349cbcce61564f73a2ba", selected_c1),
    ]
    selected_lineage = []
    for commit, expected_tree, parent in expected_lineage:
        require(git("cat-file", "-t", commit).strip() == b"commit", "selected commit missing")
        require(git("rev-parse", commit + "^{tree}").decode().strip() == expected_tree, "selected tree differs")
        if parent is not None:
            require(git("rev-list", "--parents", "-n", "1", commit).decode().split() == [commit, parent],
                    "selected parent segment missing or differs")
        selected_lineage.append({"commit": commit, "tree": expected_tree, "required_parent": parent})
    require(all(not row or row.startswith(b"H ") for row in git("ls-files", "-v", "-z").split(b"\0")),
            "hidden or nonordinary index entries refused")
    sparse = subprocess.run(["git", "config", "--bool", "core.sparseCheckout"], cwd=root, env=env,
                            capture_output=True, timeout=60, check=False)
    require(sparse.returncode in (0, 1) and sparse.stdout.strip() in (b"", b"false"), "sparse checkout refused")
    git("merge-base", "--is-ancestor", BASE, args.source)
    git("merge-base", "--is-ancestor", args.source, "HEAD")
    subprocess.run(["bash", "scripts/project-preflight.sh"], cwd=root, env=env, timeout=60, check=True)
    current = {}
    for relative, expected in PINS.items():
        data = read_regular(relative)
        require(sha(data) == expected and data == blob(BASE, relative), "unexpected binding base: " + relative)
        current[relative] = data
    module = current["scripts/w1_lifetime_ledger.py"].decode()
    values = {}
    for node in ast.parse(module).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in ("SOURCE_BASE", "SOURCE_PINS"):
                values[node.targets[0].id] = ast.literal_eval(node.value)
    require(values["SOURCE_BASE"] == OLD_SOURCE and len(values["SOURCE_PINS"]) == 20, "twenty-path reviewed roster changed")
    records = []
    changed = []
    for relative, prior in values["SOURCE_PINS"].items():
        data = blob(args.source, relative)
        require(data == read_regular(relative), "working source differs from code checkpoint: " + relative)
        actual = sha(data)
        if actual != prior:
            changed.append(relative)
        records.append({"path": relative, "prior_sha256": prior, "source_sha256": actual, "bytes": len(data)})
    require(changed == [STORE], "unexpected selected-source changes: " + repr(changed))
    new_store = next(row["source_sha256"] for row in records if row["path"] == STORE)
    require(module.count('SOURCE_BASE = "' + OLD_SOURCE + '"') == 1, "ambiguous source base")
    module = module.replace('SOURCE_BASE = "' + OLD_SOURCE + '"', 'SOURCE_BASE = "' + args.source + '"')
    old_line = '"' + STORE + '": "' + values["SOURCE_PINS"][STORE] + '"'
    require(module.count(old_line) == 1, "ambiguous source pin")
    module = module.replace(old_line, '"' + STORE + '": "' + new_store + '"')
    controls = current["scripts/ci/test_w1_lifetime_ledger.py"].decode()
    workflow = current[".github/workflows/pon-w1-qrom-closure.yml"].decode()
    require(controls.count(OLD_DIR) == 1 and workflow.count(OLD_DIR) == 2, "unexpected fixture references")
    historical = {}
    for folder in (OLD_DIR, "evidence/pon-w1-lifetime-20261107"):
        for name in ("project-input.json", "project-report.json", "README.md"):
            relative = folder + "/" + name
            data = read_regular(relative)
            require(data == blob(BASE, relative), "historical evidence already changed: " + relative)
            historical[relative] = sha(data)
    old_input = read_regular(OLD_DIR + "/project-input.json")
    require(sha(old_input) == "a6e43a5c55e71154592a3489f566995e7961b91611e15d40a18a948a495f9f89", "unknown input identity changed")
    destination = root / NEW_DIR
    require(not destination.exists(), "successor evidence already exists")
    (root / "scripts/w1_lifetime_ledger.py").write_text(module)
    (root / "scripts/ci/test_w1_lifetime_ledger.py").write_text(controls.replace(OLD_DIR, NEW_DIR))
    workflow = workflow.replace(OLD_DIR, NEW_DIR).replace("selected M8 source", "reviewed PoN follow-through source")
    (root / ".github/workflows/pon-w1-qrom-closure.yml").write_text(workflow)
    destination.mkdir()
    (destination / "project-input.json").write_bytes(old_input)
    process = subprocess.run([sys.executable, "-B", "scripts/w1_lifetime_ledger.py", "--input", NEW_DIR + "/project-input.json"],
                             cwd=root, env=env, capture_output=True, timeout=60, check=False)
    require(process.returncode == 0, "successor report refused: " + process.stderr.decode(errors="replace"))
    new_report = json.loads(process.stdout)
    old_report = json.loads(read_regular(OLD_DIR + "/project-report.json"))
    require(set(new_report) == set(old_report), "report schema changed")
    for key in old_report:
        if key != "selected_source_survey":
            require(old_report[key] == new_report[key], "non-source report changed: " + key)
    survey = new_report["selected_source_survey"]
    require(survey["base_commit"] == args.source and len(survey["sources"]) == 20, "report source set mismatch")
    require(survey["whole_repository_build_or_behavior_verified"] is False, "source review is not execution")
    require(new_report["independent_acceptance"]["production_activation"] is False, "activation changed")
    (destination / "project-report.json").write_bytes(process.stdout)
    tree = git("rev-parse", args.source + "^{tree}").decode().strip()
    readme = f"""# Current W1 lifetime ledger observation, 2026-11-10

Status: **selected source identities and conditional arithmetic reproduced; security HOLD**.

The selected code checkpoint is [`{args.source}`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/{args.source}), tree `{tree}`. All twenty selected Git blobs were compared with regular working files before rebinding. Within that roster only `trillionnium/crates/trnm-pon-node/src/store.rs` changes, to SHA256 `{new_store}`. Its added retained-chainwork and readback consistency checks do not establish cheapest legal work cost, a QROM reduction, public-prefix security, or confirmation failure probabilities.

The [ledger](../../scripts/w1_lifetime_ledger.py), binding controls and this report are in a later child of the code checkpoint. This field does not claim they existed in that checkpoint or identify a newly executed binary. Native execution receipts have their own source and binary identities.

The [input](project-input.json) is byte-identical to the [previous unknown input](../pon-w1-lifetime-current-20261109/project-input.json): {len(old_input)} bytes, SHA256 `{sha(old_input)}`. The [report](project-report.json) is {len(process.stdout)} bytes, SHA256 `{sha(process.stdout)}`. Only its selected source survey differs from the previous report. Lifetime arithmetic, counterexamples and all three independent acceptance objects are equal. Project lifetime queries, failure probability and target comparison remain null; all qualification and production activation fields remain false.

The [2026-11-09 report](../pon-w1-lifetime-current-20261109/project-report.json) and [original 2026-11-07 report](../pon-w1-lifetime-20261107/project-report.json) retain their original bytes. The same nineteen named ledger controls and original acceptance conditions remain required. Test results and hosted completion are recorded separately; creating this report does not count as passing them.

```sh
python3 -B scripts/ci/test_w1_lifetime_ledger.py -v
python3 -B scripts/w1_lifetime_ledger.py --input {NEW_DIR}/project-input.json
```
"""
    (destination / "README.md").write_text(readme)
    for relative, expected in historical.items():
        require(sha(read_regular(relative)) == expected, "historical evidence changed: " + relative)
    for record in records:
        require(sha(read_regular(record["path"])) == record["source_sha256"], "selected source changed after review: " + record["path"])
    receipt = {"schema": "pon-followthrough-ledger-source-review-v2", "baseline": BASE,
               "git_history_shallow": history_shallow == b"true",
               "complete_global_history_claimed": False, "selected_lineage": selected_lineage,
               "selected_lineage_complete": True,
               "selected_code_commit": args.source, "selected_code_tree": tree,
               "selected_files": records, "changed_selected_files": changed,
               "historical_files_sha256": historical, "successor_directory": NEW_DIR,
               "non_source_report_objects_equal": True, "tests_executed": False,
               "binary_executed": False, "production_activation": False}
    args.receipt.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": "REVIEWED_SELECTED_SOURCE_ONLY_SECURITY_HOLD", "source": args.source,
                      "selected_files": len(records), "changed_selected_files": changed, "report_sha256": sha(process.stdout)}))


if __name__ == "__main__":
    main()
