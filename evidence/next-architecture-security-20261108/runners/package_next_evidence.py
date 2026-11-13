#!/usr/bin/env python3
"""Copy quiescent evidence verbatim; index recorded outcomes without qualification."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
from urllib.parse import quote

SOURCES = {"A": "539738590dbfd4449bc0ca2718462670245f3ab6",
           "B": "bced22f712552302848e3e04f7acf24068af2048",
           "C3": "a93024cfdd4f4a4dfede03507f3b3289385bfc49",
           "C4-CI-only": "9f54b05c643185a5041fc1f78cef77e95877f52a"}
PLANNED = {"cell_bep52_cost_v1": 15, "cell_rs46_cost_v1": 12}
CI = [f"ci-{fixed}{arch}-{ref}" for fixed in ("", "fixed-") for arch in ("x86", "arm") for ref in ("head", "merge")]
EXPECTED = [f"attempt-{i}" for i in range(1, 5)] + ["attempt-2-continuation"] + CI
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
RESULT = re.compile(r"test result:\s+(ok|FAILED)\.\s+(\d+) passed;\s+(\d+) failed;\s+(\d+) ignored;\s+(\d+) measured;\s+(\d+) filtered out")

def require(condition, message):
    if not condition:
        raise ValueError(message)

def safe(path):
    for item in (path, *path.parents):
        require(not item.is_symlink(), "source/path symlink refused: " + str(item))

def sha(path):
    safe(path)
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def inventory(root):
    safe(root)
    require(root.is_dir(), "directory required: " + str(root))
    found = {}
    for path in sorted(root.rglob("*")):
        safe(path)
        mode = path.lstat().st_mode
        require(stat.S_ISREG(mode) or stat.S_ISDIR(mode), "nonregular input refused: " + str(path))
        require(not any(c in str(path.relative_to(root)) for c in "\n\r"), "newline in evidence path")
        if stat.S_ISREG(mode):
            found[path.relative_to(root).as_posix()] = sha(path)
    return found

def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key: " + key)
        value[key] = item
    return value


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError("nonfinite JSON: " + x)))


def recorded(path):
    try:
        return read_json(path) if path.suffix == ".json" else path.read_text(errors="replace")
    except (ValueError, UnicodeError) as error:
        return {"parse_error": str(error), "status": "uninterpreted; original bytes retained"}


def statuses(value, path=""):
    if isinstance(value, dict):
        return [{"field": path + "/" + k, "value": v} for k, v in value.items()
                if k in {"status", "result", "outcome", "conclusion", "exit_code", "returncode", "return_code", "ok", "all_passed"} and not isinstance(v, (dict, list))] + [r for k, v in value.items() for r in statuses(v, path + "/" + k)]
    return [r for i, v in enumerate(value) for r in statuses(v, path + "/" + str(i))] if isinstance(value, list) else []


def test_records(raw):
    records = []
    for path in sorted(raw.rglob("*")):
        if not path.is_file() or not (path.suffix == ".log" or "stdout" in path.name):
            continue
        suite, kind = "unidentified runner", "unspecified"
        with path.open(errors="replace") as stream:
            for number, line in enumerate(stream, 1):
                line = ANSI.sub("", line).strip()
                if re.search(r"\bDoc-tests\s+", line):
                    suite, kind = line, "doctest"
                elif re.match(r"test\s+\S+\.rs\s+-.*\(line\s+\d+\)\s+\.\.\.", line):
                    suite, kind = "rustdoc test-case format in this stream", "doctest"
                elif re.search(r"\bRunning\s+(?:unittests|tests/|[^ ]*\()", line):
                    suite, kind = line, "ordinary"
                match = RESULT.search(line)
                if match:
                    records.append(dict(log="raw/" + path.relative_to(raw).as_posix(), line=number,
                                        suite=suite, kind=kind, status=match[1], text=line,
                                        **dict(zip(("passed", "failed", "ignored", "measured", "filtered_out"), map(int, match.groups()[1:])))))
                    suite, kind = "unidentified runner", "unspecified"
    return records


def link(path):
    return "[" + path + "](" + quote(path, safe="/._-") + ")"


def cell(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True) if value is not None else "unknown").replace("|", "&#124;")


def obj(value):
    return value if isinstance(value, dict) else {}


def commit(*values):
    return next((v for v in values if isinstance(v, str) and re.fullmatch(r"[0-9a-f]{40}", v)), None)


def group_view(name, records, hashes):
    prefix = "raw/" + name + "/"
    summary = obj(records.get(prefix + "summary.json"))
    before, after = [obj(records.get(prefix + "source-" + stage + ".json")) for stage in ("before", "after")]
    source = commit(summary.get("source_commit"), before.get("candidate"), after.get("candidate"), summary.get("repo_head"))
    tested = commit(summary.get("tested_commit"), before.get("tested_commit"), after.get("tested_commit"), summary.get("source_commit"), summary.get("repo_head"))
    source_hashes = [hashes.get(name + "/source-" + stage + ".json") for stage in ("before", "after")]
    same = source_hashes[0] == source_hashes[1] if all(source_hashes) else None
    commands = records.get(prefix + "commands.json")
    overview = "recorded outcomes unknown; inspect raw group"
    if isinstance(commands, list):
        rows = [(str(obj(r).get("name", "command-" + str(i))), obj(r)) for i, r in enumerate(commands)]
        failed = [n for n, r in rows if r.get("timeout") is True or (type(r.get("exit_code")) is int and r["exit_code"] != 0)]
        unknown = [n for n, r in rows if type(r.get("exit_code")) is not int or type(r.get("timeout")) is not bool]
        overview = f"commands recorded/attempted: {len(rows)}; failed/timeout: {', '.join(failed) or 'none recorded'}; incomplete fields: {', '.join(unknown) or 'none'}"
        if prefix + "summary.json" not in records:
            overview = "PARTIAL: no terminal summary; " + overview
        elif "parse_error" in summary:
            overview = "UNKNOWN: terminal summary parse error; " + overview
    steps = obj(records.get(prefix + "stage-outcomes.json")).get("steps")
    if isinstance(steps, dict):
        pairs = [(str(n), obj(r).get("outcome") or "unknown", obj(r).get("conclusion") or "unknown") for n, r in steps.items()]
        counts = Counter(str(o) + "/" + str(c) for _, o, c in pairs)
        failed = [n for n, o, c in pairs if o in ("failure", "cancelled") or c in ("failure", "cancelled")]
        incomplete = [n for n, o, c in pairs if o == "unknown" or c == "unknown"]
        overview = "steps outcome/conclusion: " + ("; ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "empty; completion unknown")
        overview += "; failed/cancelled: " + (", ".join(failed) or "none recorded") + "; incomplete: " + (", ".join(incomplete) or "none recorded")
    return {"source_commit_or_ci_candidate": source, "tested_commit": tested,
            "source_record_bytes_equal": same, "outcome_overview": overview}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "validation", "delivery"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    repo, validation, delivery = [p.absolute() for p in (args.repo, args.validation, args.delivery)]
    for path in (repo, validation, delivery):
        safe(path)
        require(path.is_dir(), "directory required: " + str(path))
    output = repo / "evidence/next-architecture-security-20261108"
    safe(output)
    require(not output.exists(), "output must not already exist")
    require(output.parent.is_dir(), "existing repository evidence directory required")
    require(not output.is_relative_to(validation) and not validation.is_relative_to(output), "input/output overlap")
    before = inventory(validation)
    runner_names = ("measure_next_cells.py", "run_final_campaign.py", "package_next_evidence.py")
    inputs = {name: delivery / name for name in (*runner_names, "report-static.md", "report-executive-summary.md")}
    for path in inputs.values():
        safe(path)
        require(path.is_file() and stat.S_ISREG(path.lstat().st_mode), "regular delivery file required: " + str(path))
    delivery_hashes = {name: sha(path) for name, path in inputs.items()}
    costs = read_json(validation / "cell-cost-observation/summary.json")
    require(costs.get("schema") == "trnm.cell-cost-wrapper.v1" and isinstance(costs.get("results"), list), "required cell cost summary schema")
    static_text = inputs["report-static.md"].read_text()
    executive_text = inputs["report-executive-summary.md"].read_text()
    output.mkdir()
    raw, runners = output / "raw", output / "runners"
    shutil.copytree(validation, raw, symlinks=True)
    runners.mkdir()
    for name in runner_names:
        shutil.copy2(inputs[name], runners / name, follow_symlinks=False)
        require(sha(runners / name) == delivery_hashes[name], "runner changed during copy")
    require(inventory(raw) == before == inventory(validation), "validation changed or incomplete copy; partial output retained")
    require({name: sha(path) for name, path in inputs.items()} == delivery_hashes, "delivery changed; partial output retained")
    costs = read_json(raw / "cell-cost-observation/summary.json")
    metadata = {"raw/" + name: recorded(raw / name) for name in before
                if Path(name).name in {"summary.json", "commands.json"} or Path(name).name.startswith(("source-before", "source-after", "stage-outcomes"))}
    groups = {}
    for name in sorted(set(EXPECTED) | {p.name for p in raw.iterdir() if p.is_dir()}):
        records = {p: v for p, v in metadata.items() if p.startswith("raw/" + name + "/")}
        groups[name] = {"directory_present": (raw / name).is_dir(), "terminal_summary_present": (raw / name / "summary.json").is_file(),
                        "metadata_paths": list(records), "recorded_status_fields": statuses(records), **group_view(name, records, before)}
    tests = test_records(raw)
    index = {"schema": "trnm.next-evidence-index.v1", "qualification": "HOLD_NO_GO", "source_reference_commits": SOURCES,
             "groups": groups, "metadata": metadata, "test_result_records": tests, "cell_cost_observation": costs,
             "planned_cell_workload_repeats": PLANNED, "planned_cell_denominator": 27, "delivery_sha256": delivery_hashes,
             "missing_planned_cell_examples": sorted(set(PLANNED) - {r.get("example") for r in costs["results"]}),
             "scope": "Recorded outcomes only; no cross-source aggregation/deduplication, native-execution inference or independent qualification."}
    with (output / "execution-index.json").open("x") as stream:
        json.dump(index, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    lines = ["# Next architecture and security evidence", "", "**HOLD_NO_GO.** Failures and partial attempts are retained. This index packages observations; it does not run tests or establish native execution from source checks.", "", "## Source identities", "", "| Label | Reference commit |", "| --- | --- |"]
    lines[4:4] = [executive_text, ""]
    lines += [f"| {name} | `{head}` |" for name, head in SOURCES.items()]
    lines += ["", "C4 changes only CI workflow; its CI observations remain separate from A, B and C3 local runs. The table reads summary.source_commit first, then explicit CI candidate/tested_commit fields; the cost wrapper uses repo_head. It does not infer source identity from arbitrary JSON text. Source-record byte equality compares the two raw JSON files, not a newly executed source check.", "", "## Execution groups", "", "| Raw group | Source commit / CI candidate | Tested commit | Recorded outcomes | Source record bytes equal |", "| --- | --- | --- | --- | --- |"]
    for name, g in groups.items():
        group_link = link("raw/" + name) if g["directory_present"] else name + " (missing)"
        overview = g["outcome_overview"].replace("|", "&#124;").replace("\n", " ")
        lines.append(f"| {group_link} | {g['source_commit_or_ci_candidate'] or 'unknown'} | {g['tested_commit'] or 'unknown'} | {overview} | {cell(g['source_record_bytes_equal'])} |")
    lines += ["", "Incomplete CI steps remain unknown; outcome and conclusion are reported separately, including continued failures. Complete metadata and statuses are in " + link("execution-index.json") + "; every literal test-result line is in " + link("test-result-records.md") + ". There is no cross-file, suite, attempt or source sum/deduplication. Unidentified stdout remains unspecified; local final counts are not assumed to be native tests or doctests."]
    detailed = ["# Literal test-result records", "", "All records remain separate. A Doc-tests marker or explicit rustdoc test-case format identifies doctests; other unmarked streams remain unspecified."]
    for doc, title in ((False, "Ordinary or unspecified runner records"), (True, "Doc-tests, including P2P, listed separately")):
        detailed += ["", "## " + title, "", "| Log / line | Kind / suite | Result | Passed | Failed | Ignored | Measured | Filtered |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        detailed += [f"| {link(r['log'])} / {r['line']} | {r['kind']} / {cell(r['suite'])} | {r['status']} | {r['passed']} | {r['failed']} | {r['ignored']} | {r['measured']} | {r['filtered_out']} |" for r in tests if (r["kind"] == "doctest") == doc]
    with (output / "test-result-records.md").open("x") as stream:
        stream.write("\n".join(detailed) + "\n")
    lines += ["", "## Whole-run Cell observations", "", "The fixed planned denominator is 27 workload repeats (15 BEP52 + 12 RS46). Missing/failed observations do not reduce it. CPU/RSS cover the reaped child tree including timeout and optional GNU time overhead, not phase attribution or simultaneous summed RSS. All original counters, phase data and failures remain in " + link("raw/cell-cost-observation/summary.json") + ".", "", "| Example | Planned / reported verified | Validation / CPU-RSS complete | Wall seconds | User CPU seconds | System CPU seconds | RSS KiB | Errors |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for result in costs["results"]:
        name = result.get("example")
        whole = obj(result.get("whole_run"))
        ns = whole.get("wall_ns")
        wall = f"{ns // 10**9}.{ns % 10**9:09d}" if type(ns) is int and ns >= 0 else "unknown"
        rss = whole.get("peak_rss_kib") if whole.get("rss_unit_bytes") == 1024 else None
        lines.append(f"| {cell(name)} | {cell(PLANNED.get(name))} / {cell(obj(result.get('validation')).get('workloads_verified'))} | {cell([result.get('validation_passed'), result.get('cpu_rss_complete_for_example')])} | {wall} | {cell(whole.get('user_cpu_seconds'))} | {cell(whole.get('system_cpu_seconds'))} | {cell(rss)} | {cell(result.get('errors'))} |")
    if (raw / "ci-x86-head-cost-analysis.json").is_file():
        lines += ["", "Earlier phase analysis: " + link("raw/ci-x86-head-cost-analysis.json") + "."]
    lines += ["", "All supplied input bytes are preserved under `raw/`; runners are copied unchanged. " + link("SHA256SUMS") + " hashes every packaged file except itself. Integrity hashes do not authenticate operators, meters, payments or qualification.", "", static_text]
    with (output / "README.md").open("x") as stream:
        stream.write("\n".join(lines).rstrip() + "\n")
    hashes = inventory(output)
    with (output / "SHA256SUMS").open("x") as stream:
        stream.writelines(f"{digest}  {name}\n" for name, digest in sorted(hashes.items()))
    print(json.dumps({"output": str(output), "qualification": "HOLD_NO_GO", "hashed_files": len(hashes)}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise SystemExit("package_next_evidence: " + str(error))
