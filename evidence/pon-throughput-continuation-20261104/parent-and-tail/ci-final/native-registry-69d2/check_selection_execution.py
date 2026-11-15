#!/usr/bin/env python3
"""Reconcile preserved registries and execution logs; never run native code."""

import ast
import gzip
import hashlib
import json
from pathlib import Path
import re
import textwrap


HERE = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def groups_from(workflow):
    lines = workflow.decode().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "groups = []")
    end = next(i for i in range(start + 1, len(lines))
               if lines[i].strip().startswith("assert len({(crate, test)"))
    tree = ast.parse(textwrap.dedent("\n".join(lines[start:end])))
    groups = []
    for node in tree.body:
        if not (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id in ("prefix", "exact")):
            continue
        args = [ast.literal_eval(arg) for arg in node.value.args]
        groups.append({"kind": node.value.func.id, "crate": args[0], "group": args[1],
                       "selectors": args[2], "count": args[3] if len(args) > 3 else len(args[2])})
    return groups


def registry(data):
    names = [line[:-6] for line in data.decode().splitlines() if line.endswith(": test")]
    assert len(names) == len(set(names)), "duplicate registry names"
    return set(names)


def passed(data):
    text = data.decode()
    names = re.findall(r"^test ([A-Za-z0-9_:]+) \.\.\. ok$", text, re.M)
    summaries = re.findall(
        r"^test result: ok\. ([0-9]+) passed; 0 failed; ([0-9]+) ignored; 0 measured; "
        r"([0-9]+) filtered out; finished in [0-9]+(?:\.[0-9]+)?s$", text, re.M)
    assert len(summaries) == 1, "missing or repeated passing harness summary"
    assert int(summaries[0][0]) == len(names) == len(set(names))
    return set(names)


def main():
    summary = json.loads((HERE / "summary.json").read_text())
    raw = {}
    for key, item in summary["artifacts"].items():
        stored = (HERE / item["path"]).read_bytes()
        assert digest(stored) == item["stored_sha256"], key
        data = gzip.decompress(stored) if item["compression"] == "gzip" else stored
        assert digest(data) == item["original_sha256"], key
        assert len(data) == item["original_bytes"], key
        raw[key] = data

    sources = [json.loads(raw[key]) for key in summary["source_keys"]]
    assert all(source == sources[0] for source in sources)
    source = sources[0]
    assert source["head"] == "69d2e06c48bbbd1e22432f9b557727b140aba361"
    assert len(source["native_input_files"]) == 1190
    assert digest(json.dumps(source["native_input_files"], sort_keys=True,
                             separators=(",", ":")).encode()) == source["manifest_sha256"]
    assert source["manifest_sha256"] == summary["native_manifest_sha256"]
    node = json.loads(raw["node_result"])
    components = json.loads(raw["components_result"])
    nine = json.loads(raw["nine_result"])
    for result in (node, components):
        assert result["source_manifest_sha256"] == source["manifest_sha256"]
        assert result["source_unchanged"] and result["all_commands_succeeded"]
        assert not result["full_node_suite_executed"]
        assert not result["public_confirmation_measured"]
    assert node["binary_sha256"] == node["binary_after_sha256"] == summary["node_elf_sha256"]
    m06 = components["component_artifacts"]["trnm_mvcc_fee"]
    assert m06["binary_sha256"] == m06["binary_after_sha256"] == summary["m06_elf_sha256"]
    assert nine["native_manifest_sha256"] == source["manifest_sha256"]
    assert nine["binary_sha256"] == nine["binary_after_sha256"] == node["binary_sha256"]
    assert nine["source_before_after_equal"] and nine["all_native_and_readers_succeeded"]
    assert nine["overlap_with_previous_passed"] == []

    def command(key):
        receipt = json.loads(raw[key + "_receipt"])
        assert receipt["exit_code"] == 0, key
        assert digest(raw[key + "_stdout"]) == receipt["stdout_sha256"], key
        assert digest(raw[key + "_stderr"]) == receipt["stderr_sha256"], key
        return receipt

    registries, ignored = {}, {}
    for crate, total, skipped in (("node", 1019, 27), ("m06", 120, 7)):
        for kind in ("all", "ignored"):
            receipt = command(crate + "_registry_" + kind)
            assert "--list" in receipt["argv"]
            assert ("--ignored" in receipt["argv"]) == (kind == "ignored")
        registries[crate] = registry(raw[crate + "_registry_all_stdout"])
        ignored[crate] = registry(raw[crate + "_registry_ignored_stdout"])
        assert len(registries[crate]) == total and len(ignored[crate]) == skipped
        assert ignored[crate] <= registries[crate]

    previous = {}
    for key in summary["previous_node_execution_keys"]:
        command(key)
        for name in passed(raw[key + "_stdout"]):
            assert name not in previous, "duplicate original execution"
            previous[name] = key
    assert len(previous) == 118
    new = {}
    for index, record in enumerate(nine["records"], 1):
        key = "nine_" + str(index)
        reader_key = key + "_reader"
        command(key)
        command(reader_key)
        selector = record["selector"]
        assert passed(raw[key + "_stdout"]) == {selector}
        check = json.loads(raw[reader_key + "_stdout"])
        assert check["result"] == "PASS" and check["test"] == selector
        assert check["executed_tests"] == 1
        assert selector not in previous and selector not in new
        assert record["source_and_elf_unchanged"]
        assert record["guard_before"] == record["guard_after"]
        assert record["guard_before"]["native_manifest_sha256"] == source["manifest_sha256"]
        assert record["guard_before"]["elf_sha256"] == node["binary_sha256"]
        new[selector] = key
    assert len(new) == 9
    command("m06_library")
    m06_passed = passed(raw["m06_library_stdout"])
    assert len(m06_passed) == 113
    assert m06_passed == registries["m06"] - ignored["m06"]
    command("sqlite_scope")
    sqlite_names = passed(raw["sqlite_scope_stdout"])
    assert len(sqlite_names) == 13

    final = groups_from(raw["final_workflow"])
    base = groups_from(raw["base_workflow"])
    assert sum(group["count"] for group in base) == 56
    assert sum(group["count"] for group in final) == 58
    assert all(group in final for group in base)
    additions = [group for group in final if group not in base]
    assert len(additions) == 1 and additions[0]["group"] == "direct-append-readback"
    assert additions[0]["count"] == 2
    lines = raw["final_workflow"].splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines)
                 if line.strip().startswith(b'exact("node", "direct-append-readback", ['))
    end = next(i for i in range(start + 1, len(lines)) if lines[i].strip() == b"])")
    assert b"".join(lines[:start] + lines[end + 1:]) == raw["base_workflow"]

    execution = {"node": {**previous, **new}, "m06": {name: "m06_library" for name in m06_passed}}
    mapping = []
    for group in final:
        crate = group["crate"]
        names = (sorted(name for name in registries[crate] if name.startswith(group["selectors"]))
                 if group["kind"] == "prefix" else group["selectors"])
        assert len(names) == group["count"], group["group"]
        assert set(names) <= registries[crate]
        assert not set(names) & ignored[crate]
        for name in names:
            assert name in execution[crate], name
            key = execution[crate][name]
            mapping.append({"crate": crate, "group": group["group"], "selector": name,
                            "execution_key": key, "registered": True, "passed": True,
                            "log": summary["artifacts"][key + "_stdout"]["path"]})
    assert len(mapping) == len({(item["crate"], item["selector"]) for item in mapping}) == 58
    assert sum(item["crate"] == "node" for item in mapping) == 40
    assert sum(item["crate"] == "node" and item["selector"] in previous for item in mapping) == 31
    assert sum(item["crate"] == "node" and item["selector"] in new for item in mapping) == 9
    assert sum(item["crate"] == "m06" for item in mapping) == 18
    print(json.dumps({
        "result": "PASS", "scope": "Exact selected registry and execution coverage only; no complete Node or public-service verdict.",
        "source_kind": "dirty composed 69d2 source", "head": source["head"],
        "native_manifest_sha256": source["manifest_sha256"],
        "node_elf_sha256": node["binary_sha256"], "m06_elf_sha256": m06["binary_sha256"],
        "node_registry": 1019, "node_registry_ignored": 27,
        "m06_registry": 120, "m06_registry_ignored": 7,
        "node_selected_registered_and_passed": 40, "node_selected_from_original_execution": 31,
        "node_selected_from_additional_nine": 9, "m06_selected_registered_and_passed": 18,
        "selected_unique_passed": 58, "all_original_b811_56_selections_preserved": True,
        "node_original_passed": 118, "node_additional_unique_passed": 9,
        "m06_complete_library_passed": 113, "m06_complete_library_ignored": 7,
        "original_sqlite_scopes_passed": 13,
        "full_node_suite_executed": False, "public_confirmation_measured": False,
        "mapping": mapping,
    }, indent=2))


if __name__ == "__main__":
    main()
