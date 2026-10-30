#!/usr/bin/env python3
"""Execute pinned, artifact-only CodeQL research; never write the security gate."""
from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import sys
import time
from urllib.parse import unquote, urlsplit

import verify_ci_source
import build_pinned_codeql_cpp_v1 as cpp_build

ROOT = Path(__file__).resolve().parents[2]
VERSION = "2.27.3"
CLI_SHA = "d7421f46364160506f767a928cbe5297a02d0bb0"
PACKS = {"actions": "0.6.38", "python": "1.8.13", "rust": "0.1.45", "cpp": "1.9.2"}
QUERY_COUNTS = {"actions": 18, "python": 45, "rust": 37, "cpp": 61}
LOG_LIMIT = 32 * 1024 * 1024
SARIF_LIMIT = 128 * 1024 * 1024
SEMANTIC_DIAGNOSTIC_LIMIT = 10000
SEMANTIC_MARKERS = (b"semantic analyzer unavailable", b"failed to load workspace",
                    b"macro expansion will be skipped")
RUST_ALL_TARGETS_ENV = "CODEQL_EXTRACTOR_RUST_OPTION_CARGO_ALL_TARGETS"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, "duplicate JSON member")
        value[key] = item
    return value


def parsed(raw):
    def finite_number(text):
        value = float(text)
        require(math.isfinite(value), "nonfinite JSON number")
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_float=finite_number,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resource_hints(language):
    require(language in PACKS, "known CodeQL language required")
    # Exact D's original Rust suite exited 99 with an evaluator allocation
    # failure at 4096. This is only an analysis resource profile; the original
    # failure, two threads, query suite, source scope and deadlines remain.
    return {"schema": "pon-pinned-codeql-resource-hints-v1", "threads_hint": 2,
            "ram_hint_mb": 8192 if language == "rust" else 4096}


def host_memory_observation(ram_hint_mb, path=Path("/proc/meminfo")):
    observation = {"schema": "pon-codeql-host-memory-observation-v1", "observed": False,
                   "scope": "One kernel memory snapshot; not effective cgroup/family capacity, a hard resource cap or a future availability guarantee."}
    try:
        raw = cpp_build.raw(path, 65536)
        observation["meminfo"] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                                  "raw_utf8": raw.decode("utf-8")}
        values = {}
        for name in ("MemTotal", "MemAvailable"):
            matches = re.findall(rb"^" + name.encode() + rb":[ \t]+([0-9]+)[ \t]+kB$", raw, re.MULTILINE)
            require(len(matches) == 1, "unique memory observation required")
            values[name] = int(matches[0]) * 1024
        require(values["MemTotal"] > 0 and values["MemAvailable"] <= values["MemTotal"],
                "memory snapshot contradicts total")
        observation.update(observed=True, physical_memory_bytes=values["MemTotal"],
                           available_memory_bytes=values["MemAvailable"],
                           hint_below_observed_available_memory=ram_hint_mb * 1024 * 1024 <= values["MemAvailable"])
    except (OSError, UnicodeError, ValueError) as error:
        observation["failure_type"] = type(error).__name__
    return observation


def write_new(path, value):
    with path.open("x", encoding="utf-8") as output:
        output.write(json.dumps(value, indent=2, allow_nan=False) + "\n")


def cpp_source_copy(source, destination, tracked, create=False):
    """Keep the C analysis root narrow without changing any original input.

    Only the already verified tracked inventory is copied, with no symlink or
    special-file fallback. Hash both real byte streams again after extraction.
    This copy is not a new Git checkout or native-runtime qualification.
    """
    require(source.is_absolute() and destination.is_absolute()
            and not destination.is_relative_to(source), "C copy must be outside source")
    require(type(tracked) is list and 0 < len(tracked) <= 10000
            and len(set(tracked)) == len(tracked), "C copy inventory bound")
    if create:
        destination.mkdir(parents=True, exist_ok=False)
    rows, total = [], 0
    for relative in sorted(tracked):
        path = PurePosixPath(relative)
        require(not path.is_absolute() and path.parts and ".." not in path.parts
                and str(path) == relative, "C copy path traversal")
        original, target = source / relative, destination / relative
        require(original.resolve(strict=True) == original, "C source symlink refused")
        meta = original.lstat()
        total += meta.st_size
        require(stat.S_ISREG(meta.st_mode) and meta.st_size <= 256 * 1024 * 1024
                and total <= 2 * 1024 * 1024 * 1024, "C source-copy regular-file/size bound")
        if create:
            target.parent.mkdir(parents=True, exist_ok=True)
            with original.open("rb") as src, target.open("xb") as dst:
                while block := src.read(1024 * 1024):
                    dst.write(block)
            target.chmod(stat.S_IMODE(meta.st_mode))
        require(target.resolve(strict=True) == target, "C copy symlink refused")
        target_meta = target.lstat()
        require(stat.S_ISREG(target_meta.st_mode) and target_meta.st_size == meta.st_size
                and stat.S_IMODE(target_meta.st_mode) == stat.S_IMODE(meta.st_mode),
                "C copied file identity mismatch")
        hashes = []
        for filename in (original, target):
            hasher = hashlib.sha256()
            with filename.open("rb") as file:
                for block in iter(lambda: file.read(1024 * 1024), b""):
                    hasher.update(block)
            hashes.append(hasher.hexdigest())
        require(hashes[0] == hashes[1], "C copied source bytes differ")
        rows.append({"path": relative, "bytes": meta.st_size, "mode": stat.S_IMODE(meta.st_mode), "sha256": hashes[0]})
    found = set()
    for directory, directories, filenames in os.walk(destination, followlinks=False):
        for name in directories + filenames:
            item = Path(directory) / name
            require(not item.is_symlink(), "C analysis copy contains symlink")
        found.update(str((Path(directory) / name).relative_to(destination)) for name in filenames)
    require(found == set(tracked), "C analysis copy has omitted or extra files")
    return {"schema": "pon-cpp-analysis-source-copy-v1", "tracked_entries": len(rows),
            "tracked_bytes": total, "original_root": str(source), "analysis_project": str(destination), "files": rows}


def source_uri(uri, root):
    require(type(uri) is str, "diagnostic source URI type")
    url = urlsplit(uri)
    require(url.scheme in ("", "file") and not url.netloc and not url.query and not url.fragment,
            "diagnostic source URI scheme")
    path = PurePosixPath(unquote(url.path))
    require(".." not in path.parts, "diagnostic source traversal")
    if path.is_absolute():
        try:
            return str(path.relative_to(PurePosixPath(str(root))))
        except ValueError:
            return None
    return str(path)


def expected_inputs(paths, language):
    if language == "actions":
        return {p for p in paths if p.startswith(".github/workflows/")
                and Path(p).suffix in (".yml", ".yaml")}
    suffixes = {"python": {".py"}, "rust": {".rs"},
                "cpp": {".c", ".cc", ".cpp", ".cxx", ".C"}}[language]
    return {p for p in paths if Path(p).suffix in suffixes}


def semantic_extraction_observations(streams, tracked, source_root):
    """Locate retained semantic failures, including informational diagnostics.

    Extraction success only establishes that a file entered the database. The
    extractor can emit INFO-level semantic failures that SARIF does not retain
    as warnings. This inventory never infers an active module from its path or
    excuses archived, platform-specific or include!-composed source files.
    """
    require(set(streams) == {"stdout", "stderr"}, "both retained creation streams required")
    require(all(type(raw) is bytes and len(raw) <= LOG_LIMIT for raw in streams.values()),
            "creation stream bound")
    tracked = set(tracked)
    rows, reasons, markers, unlocated = [], collections.Counter(), collections.Counter(), 0
    count = 0
    ansi = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
    location = re.compile(r"(?P<path>[^\s\x00]+\.rs):(?P<line>[0-9]+):(?P<column>[0-9]+): "
                          r"semantic analyzer unavailable \((?P<reason>[^\r\n]+)\):")
    for stream, raw in streams.items():
        for line_number, original in enumerate(raw.splitlines(), 1):
            clean = ansi.sub(b"", original)
            present = [marker for marker in SEMANTIC_MARKERS if marker in clean.lower()]
            if not present:
                continue
            count += 1
            markers.update(marker.decode("ascii") for marker in present)
            text = clean.decode("utf-8", errors="replace")
            match = location.search(text)
            relative = None
            if match:
                try:
                    relative = source_uri(match["path"], source_root)
                except ValueError:
                    pass
                reasons[match["reason"]] += 1
            if relative is None:
                unlocated += 1
            if len(rows) < SEMANTIC_DIAGNOSTIC_LIMIT:
                rows.append({"stream": stream, "retained_log_line": line_number,
                             "raw_line_sha256": hashlib.sha256(original).hexdigest(),
                             "source_path": relative, "tracked_source": relative in tracked,
                             "source_line": int(match["line"]) if match else None,
                             "source_column": int(match["column"]) if match else None,
                             "reason": match["reason"] if match else None,
                             "failure_markers": [marker.decode("ascii") for marker in present]})
    return {"schema": "pon-pinned-codeql-semantic-extraction-v1",
            "scope": "Retained creation-log observations only; no active-module, feature, platform, semantic-success or security qualification is inferred.",
            "retained_logs": {name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                              for name, raw in streams.items()},
            "diagnostic_line_count": count, "retained_diagnostic_count": len(rows),
            "diagnostic_inventory_complete": count == len(rows), "diagnostic_limit": SEMANTIC_DIAGNOSTIC_LIMIT,
            "failure_markers": sorted(markers), "marker_line_counts": dict(sorted(markers.items())),
            "reason_counts": dict(sorted(reasons.items())), "unlocated_diagnostic_count": unlocated,
            "affected_tracked_files": sorted({row["source_path"] for row in rows if row["tracked_source"]}),
            "diagnostics": rows, "semantic_coverage_qualified": False,
            "official_security_gate_qualified": False}


def diagnostic_source(artifact, bases, source_root):
    base = artifact.get("uriBaseId")
    require(base is None or base == "%SRCROOT%", "unknown diagnostic source base")
    if base in bases:
        mapping = bases[base]
        require(type(mapping) is dict and "uriBaseId" not in mapping,
                "nested diagnostic source base unsupported")
        uri = mapping.get("uri")
        require(type(uri) is str and PurePosixPath(unquote(urlsplit(uri).path)).is_absolute()
                and source_uri(uri, source_root) == ".", "diagnostic source base changed")
    return source_uri(artifact["uri"], source_root)


def assess_sarif(sarif, language, tracked, source_root, category, cpp_context=None, cpp_output=None, analysis_root=None):
    require(sarif.get("version") == "2.1.0" and type(sarif.get("runs")) is list
            and len(sarif["runs"]) == 1, "one original SARIF run required")
    run = sarif["runs"][0]
    require(run["tool"]["driver"]["name"] == "CodeQL"
            and run["tool"]["driver"]["semanticVersion"] == VERSION,
            "SARIF tool version mismatch")
    require(run["automationDetails"]["id"] == category + "/", "SARIF category mismatch")
    invocations = run.get("invocations")
    require(type(invocations) is list and bool(invocations)
            and all(i.get("executionSuccessful") is True for i in invocations),
            "SARIF invocation incomplete")
    require(type(run.get("results")) is list, "SARIF results missing")
    successful, composed, warnings, errors = set(), set(), [], []
    analysis_root = source_root if analysis_root is None else analysis_root
    require(analysis_root == source_root or (language == "cpp" and cpp_context is not None
            and source_root == analysis_root / "project" and cpp_output == analysis_root / "build"),
            "unexpected analysis root/source mapping")
    cpp_mapping = None
    if cpp_context is not None:
        require(language == "cpp" and isinstance(cpp_output, Path), "C context on wrong language")
        cpp_mapping = cpp_build.validate_context(cpp_context, source_root, cpp_output)
    bases = run.get("originalUriBaseIds", {})
    require(type(bases) is dict, "diagnostic source bases type")
    for invocation in invocations:
        configuration = invocation.get("toolConfigurationNotifications", [])
        execution = invocation.get("toolExecutionNotifications", [])
        require(type(configuration) is list and type(execution) is list,
                "diagnostic notification lists")
        for notification in configuration + execution:
            level = notification.get("level", "warning")
            require(level in ("none", "note", "warning", "error"), "unknown diagnostic level")
            if level in ("warning", "error"):
                (errors if level == "error" else warnings).append(notification)
        for notification in execution:
            level = notification.get("level", "warning")
            if notification.get("descriptor", {}).get("id", "").endswith("/successfully-extracted-files"):
                require(level in ("none", "note"), "failed extraction mislabeled successful")
                for location in notification.get("locations", []):
                    artifact = location["physicalLocation"]["artifactLocation"]
                    relative = diagnostic_source(artifact, bases, analysis_root)
                    absolute = str(analysis_root / relative) if relative is not None else unquote(urlsplit(artifact["uri"]).path)
                    try:
                        direct = str(PurePosixPath(absolute).relative_to(PurePosixPath(str(source_root))))
                        successful.add(direct)
                    except ValueError:
                        pass
                    if cpp_mapping is not None and absolute == cpp_mapping["generated_path"]:
                        composed.update(row["source"] for row in cpp_mapping["components"])
    inputs = expected_inputs(tracked, language)
    require(bool(inputs), "no tracked inputs for selected language")
    missing = sorted(inputs - successful - composed)
    findings = collections.Counter()
    for item in run["results"]:
        require(type(item) is dict and type(item.get("ruleId")) is str, "finding rule identity")
        findings[item["ruleId"]] += 1
    return {"tracked_input_count": len(inputs), "successful_tracked_inputs": len(inputs & (successful | composed)),
            "direct_successful_tracked_inputs": len(inputs & successful),
            "composed_successful_tracked_inputs": sorted((inputs & composed) - successful),
            "validated_cpp_context": cpp_mapping,
            "analysis_root": str(analysis_root), "tracked_project_root": str(source_root),
            "missing_tracked_inputs": missing, "warning_diagnostics": warnings,
            "error_diagnostics": errors, "finding_count": len(run["results"]),
            "findings_by_rule": dict(sorted(findings.items())),
            "extraction_coverage_complete": not missing and not warnings and not errors,
            "coverage_scope": "Tracked language extraction inventory plus retained failures; direct extraction is not independent proof of semantic coverage. C/C++ includes only direct units or byte-bound original components in a successfully extracted generated unit; not independent header semantics or runtime build qualification.",
            "official_security_gate_qualified": False, "production_qualified": False}


def query_bindings(query_paths, pack_root, database):
    require(type(query_paths) is list and bool(query_paths)
            and all(type(p) is str for p in query_paths)
            and len(set(query_paths)) == len(query_paths), "nonempty unique query list required")
    bindings = []
    for raw in query_paths:
        path = Path(raw)
        require(path.is_absolute() and path.is_file() and not path.is_symlink(), "query file unavailable")
        relative = path.resolve(strict=True).relative_to(pack_root.resolve(strict=True))
        require(relative.suffix == ".ql", "unexpected query extension")
        bqrs = database / "results" / "codeql" / pack_root.parent.name / relative.with_suffix(".bqrs")
        present = bqrs.is_file() and not bqrs.is_symlink() and bqrs.stat().st_size > 0
        bindings.append({"query": relative.as_posix(), "sha256": digest(path),
                         "bqrs": str(bqrs.relative_to(database)),
                         "bqrs_present": present,
                         "bqrs_bytes": bqrs.stat().st_size if present else None,
                         "bqrs_sha256": digest(bqrs) if present else None})
    return bindings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=tuple(PACKS), required=True)
    parser.add_argument("--codeql", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    require(not output.is_relative_to(ROOT), "analysis output must be outside source")
    output.mkdir(parents=True, exist_ok=False)
    resources = resource_hints(args.language)
    ram_hint = str(resources["ram_hint_mb"])
    thread_hint = str(resources["threads_hint"])
    result = {"schema": "pon-pinned-codeql-analysis-v1", "language": args.language,
              "expected_head": args.expected_head, "analysis_execution_complete": False,
              "source_stable": False, "passed": False,
              "official_security_gate_qualified": False, "production_qualified": False,
              "query_or_model_changes": False, "findings_require_separate_review": True,
              "threads_hint": resources["threads_hint"], "ram_hint_mb": resources["ram_hint_mb"],
              "resource_hints": resources,
              "resource_scope": "CLI hints; not a two-thread or process-family hard resource cap.",
              "phases": []}
    bounded = None
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                       CODEQL_THREADS=thread_hint, CODEQL_RAM=ram_hint)
    # Public source analysis needs no service credentials; do not forward them
    # to dependency build scripts or log an inherited environment.
    for key in list(environment):
        if any(part in key.upper() for part in ("TOKEN", "PASSWORD", "SECRET", "CREDENTIAL", "AUTHORIZATION")):
            environment.pop(key)
        elif key.startswith(("CODEQL_EXTRACTOR_RUST_", "CODEQL_RUST_EXTRACTOR_")):
            # Ambient feature/cfg/target overrides must not narrow the recorded
            # source analysis. The pinned runner supplies its own options below.
            environment.pop(key)
    if args.language == "rust":
        # The 2.27.3 extractor's config.rs accepts this environment field and
        # defaults it to false; codeql-extractor.yml does not expose a CLI
        # cargo_all_targets option. This expands Cargo target loading only.
        # Actual semantic diagnostics still decide whether coverage is complete.
        environment[RUST_ALL_TARGETS_ENV] = "true"
        result["rust_all_targets_requested"] = True

    def phase(name, argv, budget):
        started = time.monotonic()
        record = {"name": name, "argv": list(map(str, argv)), "wall_budget_seconds": budget,
                  "codeql_environment": {key: environment[key] for key in
                                         ("CODEQL_THREADS", "CODEQL_RAM", RUST_ALL_TARGETS_ENV)
                                         if key in environment}}
        try:
            capture = bounded.run_bounded(record["argv"], b"", cwd=ROOT, env=environment,
                                          timeout=budget, stdout_limit=LOG_LIMIT, stderr_limit=LOG_LIMIT)
            record.update(returncode=capture.returncode, complete=capture.returncode == 0)
        except bounded.ProcessFailure as error:
            capture = error
            record.update(returncode=error.returncode, complete=False, failure_code=str(error),
                          stdout_truncated=error.stdout_truncated, stderr_truncated=error.stderr_truncated)
        for stream in ("stdout", "stderr"):
            raw = getattr(capture, stream)
            path = output / (name + "." + stream + ".log")
            with path.open("xb") as file:
                file.write(raw)
            record[stream] = {"bytes": len(raw), "sha256": digest(path)}
        record["elapsed_seconds"] = time.monotonic() - started
        write_new(output / (name + ".execution.json"), record)
        result["phases"].append(record)
        require(record["complete"], "CodeQL phase failed: " + name)
        return capture.stdout

    before = None
    cpp_copy_before = None
    cpp_project = cpp_output = None
    try:
        before = verify_ci_source.verify("head", args.expected_head, root=ROOT)
        write_new(output / "source-before.json", before)
        if args.language == "rust":
            result["host_memory_observation"] = host_memory_observation(resources["ram_hint_mb"])
        bounded_path = ROOT / "formal/pon-nakamoto-v1/bounded_process.py"
        spec = importlib.util.spec_from_file_location("_pinned_codeql_bounded", bounded_path)
        bounded = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = bounded
        spec.loader.exec_module(bounded)
        executable = args.codeql.resolve(strict=True)
        tracked = subprocess.check_output(["git", "ls-tree", "-rz", "--name-only", args.expected_head], cwd=ROOT)
        tracked = [p.decode("utf-8") for p in tracked.split(b"\0") if p]
        version = parsed(phase("version", [executable, "version", "--format=json"], 30))
        require(version["version"] == VERSION and version["sha"] == CLI_SHA
                and version["configFileFound"] is False, "pinned CodeQL or ambient config mismatch")
        pack_root = executable.parent / "qlpacks/codeql" / (args.language + "-queries") / PACKS[args.language]
        suite = f"codeql/{args.language}-queries@{PACKS[args.language]}:codeql-suites/{args.language}-code-scanning.qls"
        phase("packs", [executable, "resolve", "packs", "--format=json"], 30)
        queries = parsed(phase("queries", [executable, "resolve", "queries", "--format=json", suite], 30))
        require(len(queries) == QUERY_COUNTS[args.language], "fixed official suite query count changed")
        database = output / "database"
        originals = query_bindings(queries, pack_root, database)
        write_new(output / "queries-before.json", originals)
        analysis_root = ROOT
        if args.language == "cpp":
            analysis_root = output / "cpp-scope"
            cpp_project, cpp_output = analysis_root / "project", analysis_root / "build"
            cpp_copy_before = cpp_source_copy(ROOT, cpp_project, tracked, create=True)
            write_new(output / "cpp-source-copy-before.json", cpp_copy_before)
        command = [executable, "database", "create", database, "--language=" + args.language,
                   "--source-root=" + str(analysis_root), "--threads=" + thread_hint, "--ram=" + ram_hint]
        if args.language in ("rust", "cpp"):
            phase("project-toolchain", ["rustup", "run", "1.95.0", "rustc", "-Vv"], 30)
        if args.language == "rust":
            phase("extractor-options", [executable, "resolve", "extractor",
                                        "--language=rust", "--format=betterjson"], 30)
            phase("extractor-toolchain", ["rustup", "run", "1.99.0", "rustc", "-Vv"], 30)
            command.append("--extractor-option=rust.cargo_target_dir=" + str(output / "cargo-target"))
        if args.language == "cpp":
            command.extend(["--build-mode=manual", "--command=" + shlex.join([
                sys.executable, str(ROOT / "scripts/ci/build_pinned_codeql_cpp_v1.py"),
                "--source-root", str(cpp_project), "--output", str(cpp_output)])])
        else:
            command.append("--build-mode=none")
        phase("create", command, 1200)
        semantic = semantic_extraction_observations(
            {stream: (output / f"create.{stream}.log").read_bytes() for stream in ("stdout", "stderr")},
            tracked, ROOT)
        write_new(output / "semantic-extraction.json", semantic)
        result["semantic_extraction_observation"] = {
            "file": "semantic-extraction.json", "sha256": digest(output / "semantic-extraction.json"),
            "diagnostic_line_count": semantic["diagnostic_line_count"],
            "diagnostic_inventory_complete": semantic["diagnostic_inventory_complete"],
            "affected_tracked_file_count": len(semantic["affected_tracked_files"]),
            "reason_counts": semantic["reason_counts"]}
        category = f"independent-artifact/{args.expected_head}/{args.language}/code-scanning"
        sarif = output / "analysis.sarif"
        phase("analyze", [executable, "database", "analyze", database, suite, "--no-download",
                          "--threads=" + thread_hint, "--ram=" + ram_hint, "--format=sarifv2.1.0",
                          "--sarif-category=" + category, "--output=" + str(sarif)], 1200)
        final_queries = query_bindings(queries, pack_root, database)
        write_new(output / "queries-after.json", final_queries)
        require([(q["query"], q["sha256"]) for q in originals]
                == [(q["query"], q["sha256"]) for q in final_queries], "selected query bytes changed")
        require(all(q["bqrs_present"] for q in final_queries), "selected query missing BQRS result")
        require(sarif.is_file() and not sarif.is_symlink() and sarif.stat().st_size <= SARIF_LIMIT,
                "SARIF missing or over bound")
        context = parsed(cpp_build.raw(cpp_output / "context.json")) if args.language == "cpp" else None
        assessment = assess_sarif(parsed(sarif.read_bytes()), args.language, tracked, cpp_project or ROOT, category,
                                  context, cpp_output, analysis_root)
        markers = semantic["failure_markers"]
        assessment["semantic_extraction_failure_markers"] = markers
        assessment["extraction_coverage_complete"] &= not markers
        result.update(assessment, analysis_execution_complete=True, selected_query_count=len(final_queries),
                      sarif={"bytes": sarif.stat().st_size, "sha256": digest(sarif)})
        result["passed"] = assessment["extraction_coverage_complete"]
    except Exception as error:
        result["failure"] = {"type": type(error).__name__,
                             "code": str(error) if isinstance(error, ValueError) else "analysis operation failed"}
    finally:
        if cpp_copy_before is not None:
            try:
                cpp_after = cpp_source_copy(ROOT, cpp_project, tracked)
                write_new(output / "cpp-source-copy-after.json", cpp_after)
                result["cpp_source_copy_stable"] = cpp_copy_before == cpp_after
                result["passed"] &= result["cpp_source_copy_stable"]
            except Exception as error:
                result["passed"] = False
                result["cpp_source_copy_after_failure"] = type(error).__name__
        try:
            after = verify_ci_source.verify("head", args.expected_head, root=ROOT)
            write_new(output / "source-after.json", after)
            result["source_stable"] = before is not None and before == after
        except Exception as error:
            result["source_after_failure"] = type(error).__name__
        result["passed"] &= result["source_stable"]
        write_new(output / "result.json", result)
        print(json.dumps({k: result.get(k) for k in ("schema", "language", "analysis_execution_complete",
              "source_stable", "passed", "finding_count", "extraction_coverage_complete",
              "official_security_gate_qualified")}, allow_nan=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
