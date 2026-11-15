#!/usr/bin/env python3
"""Read existing b811-dirty registry evidence; never build or execute native tests."""

import ast
import gzip
import hashlib
import json
from pathlib import Path
import textwrap


HERE = Path(__file__).resolve().parent


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_artifact(record):
    stored = (HERE / record["path"]).read_bytes()
    assert sha256(stored) == record["stored_sha256"], record["path"]
    data = gzip.decompress(stored) if record["compression"] == "gzip" else stored
    assert len(data) == record["original_bytes"], record["path"]
    assert sha256(data) == record["original_sha256"], record["path"]
    return data


def selected_groups(workflow):
    lines = workflow.decode().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "groups = []")
    end = next(
        i
        for i in range(start + 1, len(lines))
        if lines[i].strip().startswith("assert len({(crate, test)")
    )
    tree = ast.parse(textwrap.dedent("\n".join(lines[start:end])))
    groups = []
    for node in tree.body:
        if not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id in ("prefix", "exact")
        ):
            continue
        args = [ast.literal_eval(arg) for arg in node.value.args]
        groups.append(
            {
                "kind": node.value.func.id,
                "crate": args[0],
                "group": args[1],
                "selectors": args[2],
                "count": args[3] if len(args) > 3 else len(args[2]),
            }
        )
    return groups


def without_direct_append(workflow):
    lines = workflow.splitlines(keepends=True)
    starts = [
        i
        for i, line in enumerate(lines)
        if line.strip().startswith(b'exact("node", "direct-append-readback", [')
    ]
    assert len(starts) == 1
    start = starts[0]
    end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == b"])" )
    return b"".join(lines[:start] + lines[end + 1 :])


def test_names(raw):
    names = [line[:-6] for line in raw.decode().splitlines() if line.endswith(": test")]
    assert len(names) == len(set(names)), "duplicate registry names"
    return set(names)


def main():
    summary = json.loads((HERE / "summary.json").read_text())
    raw = {key: read_artifact(record) for key, record in summary["artifacts"].items()}
    source = json.loads(raw["source_before"])
    observation = json.loads(raw["native_observation"])
    assert source["head"] == summary["source"]["base_commit"]
    assert len(source["native_input_files"]) == 1190
    assert source["manifest_sha256"] == summary["source"]["native_manifest_sha256"]
    assert observation["source_manifest_sha256"] == source["manifest_sha256"]
    assert observation["source_unchanged"] is True
    assert observation["binary_sha256"] == observation["binary_after_sha256"]
    assert observation["binary_sha256"] == summary["source"]["elf_sha256"]
    assert observation["full_node_suite_executed"] is False
    assert observation["public_confirmation_measured"] is False
    assert summary["source"]["source_after_original_sha256"] == sha256(raw["source_before"])

    for label in ("all", "ignored"):
        receipt = json.loads(raw[f"registry_{label}_receipt"])
        assert receipt["exit_code"] == 0
        assert receipt["stdout_sha256"] == sha256(raw[f"registry_{label}_stdout"])
        assert receipt["stderr_sha256"] == sha256(raw[f"registry_{label}_stderr"])
        assert "--list" in receipt["argv"]
        assert ("--ignored" in receipt["argv"]) == (label == "ignored")

    all_names = test_names(raw["registry_all_stdout"])
    ignored_names = test_names(raw["registry_ignored_stdout"])
    assert len(all_names) == 1019
    assert len(ignored_names) == 27
    assert ignored_names <= all_names

    final_workflow = raw["final_workspace_workflow"]
    base_workflow = raw["base_workspace_workflow"]
    final_groups = selected_groups(final_workflow)
    base_groups = selected_groups(base_workflow)
    assert sum(group["count"] for group in base_groups) == 56
    assert sum(group["count"] for group in final_groups) == 58
    assert all(group in final_groups for group in base_groups)
    additions = [group for group in final_groups if group not in base_groups]
    assert len(additions) == 1
    assert additions[0]["group"] == "direct-append-readback"
    assert additions[0]["count"] == 2
    assert without_direct_append(final_workflow) == base_workflow

    node_groups = []
    selected = []
    for group in final_groups:
        if group["crate"] != "node":
            continue
        names = (
            sorted(name for name in all_names if name.startswith(group["selectors"]))
            if group["kind"] == "prefix"
            else group["selectors"]
        )
        assert len(names) == group["count"], group["group"]
        assert set(names) <= all_names, group["group"]
        assert not (set(names) & ignored_names), group["group"]
        selected.extend(names)
        node_groups.append({"group": group["group"], "count": len(names), "tests": names})
    assert len(selected) == len(set(selected)) == 40
    m06_groups = [group for group in final_groups if group["crate"] == "m06"]
    assert sum(group["count"] for group in m06_groups) == 18

    print(
        json.dumps(
            {
                "result": "PASS_WITH_EXPLICIT_M06_REGISTRY_GAP",
                "scope": "Offline readback of existing Node registry and frozen workflow only; no build or native test execution.",
                "base_commit": source["head"],
                "source_kind": "dirty composed b811 source; neither clean b811 nor later 69d2",
                "native_input_files": 1190,
                "native_manifest_sha256": source["manifest_sha256"],
                "elf_sha256": observation["binary_sha256"],
                "registered_node_tests": 1019,
                "ignored_node_tests": 27,
                "node_selected_actual_registry": 40,
                "node_selected_ignored": 0,
                "node_groups": node_groups,
                "m06_static_selected": 18,
                "m06_actual_registry_observed_here": False,
                "m06_static_groups": m06_groups,
                "all_original_b811_56_selectors_and_counts_preserved": True,
                "removing_only_direct_append_2_recovers_b811_workflow_bytes": True,
                "full_node_suite_verdict": None,
                "public_confirmation_verdict": None,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
