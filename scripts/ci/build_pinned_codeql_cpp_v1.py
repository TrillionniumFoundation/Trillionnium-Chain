#!/usr/bin/env python3
"""Compile original C bytes in an explicit analysis context, without activation.

This is not the production native-loader or SQLite qualification path. CodeQL's
tracer may inject loader state which that path deliberately refuses. The two
source recipes below are hash-bound to the reviewed original build owners; a
changed owner requires a new review, never inferred flags or a silent fallback.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
SPAWN = "scripts/llm_runtime_kernel_spawn.c"
RETIREMENT = "scripts/llm_runtime_retirement_slot.c"
WITNESS = "trillionnium/crates/trnm-sqlite-io-boundary/unix_layout_witness.c"
OWNERS = {
    "scripts/llm_runtime_kernel_owned.py": "5c046187dc1c28c25fbf475e1961bc7e09dcf0ab196b454a830fd95ed2bf8387",
    "trillionnium/crates/trnm-sqlite-io-boundary/build.rs": "eeb5102f07506ef674db1cd8e104860232d800bf5db1dc4ad6b745a63cc83a81",
}
SQLITE_SHA = "9512509b1bccb7461f79bea8aad6280ae4699e925fa4804381b71f59e7efb0c5"
SQLITE_BUILD_SHA = "239297962bfdc78cd420b44142ee6801d2fc9375bf8470207669f416446ebb9e"
FLAGS = ["SQLITE_CORE", "SQLITE_DEFAULT_FOREIGN_KEYS=1", "SQLITE_ENABLE_API_ARMOR",
         "SQLITE_ENABLE_COLUMN_METADATA", "SQLITE_ENABLE_DBSTAT_VTAB", "SQLITE_ENABLE_FTS3",
         "SQLITE_ENABLE_FTS3_PARENTHESIS", "SQLITE_ENABLE_FTS5", "SQLITE_ENABLE_JSON1",
         "SQLITE_ENABLE_LOAD_EXTENSION=1", "SQLITE_ENABLE_MEMORY_MANAGEMENT", "SQLITE_ENABLE_RTREE",
         "SQLITE_ENABLE_STAT4", "SQLITE_SOUNDEX", "SQLITE_THREADSAFE=1", "SQLITE_USE_URI",
         "HAVE_USLEEP=1", "HAVE_ISNAN", "_POSIX_THREAD_SAFE_FUNCTIONS", "HAVE_LOCALTIME_R"]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def raw(path, limit=16 * 1024 * 1024):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as file:
        before = os.fstat(file.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "bounded regular source required")
        data = file.read(limit + 1)
        after = os.fstat(file.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    require(len(data) <= limit and identity(before) == identity(after), "source changed while reading")
    return data


def fingerprint(path):
    data = raw(path, 32 * 1024 * 1024)
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def inputs(root):
    rows = {p: fingerprint(root / p) for p in (*OWNERS, SPAWN, RETIREMENT, WITNESS)}
    require(all(rows[p]["sha256"] == expected for p, expected in OWNERS.items()),
            "reviewed C build owner changed")
    return rows


def combined(root):
    first, second = raw(root / SPAWN), raw(root / RETIREMENT)
    joined = first + b"\n" + second
    # A named analysis input replaces stdin. Refuse path/line-sensitive macros
    # rather than claiming that this transport change is always equivalent.
    require(re.search(rb"\b__(?:FILE|BASE_FILE|FILE_NAME|LINE)__\b", joined) is None,
            "source depends on analysis input identity")
    return joined, [
        {"source": SPAWN, "byte_start": 0, "byte_end_exclusive": len(first), "line_start": 1},
        {"source": RETIREMENT, "byte_start": len(first) + 1,
         "byte_end_exclusive": len(joined), "line_start": first.count(b"\n") + 2},
    ]


def sqlite_dependency(metadata):
    packages = [p for p in metadata["packages"]
                if p["name"] == "libsqlite3-sys" and p["version"] == "0.37.0"]
    require(len(packages) == 1 and packages[0]["source"]
            == "registry+https://github.com/rust-lang/crates.io-index", "exact registry SQLite dependency required")
    dependency = Path(packages[0]["manifest_path"]).resolve(strict=True).parent
    require(dependency.name == "libsqlite3-sys-0.37.0", "unexpected SQLite source directory")
    include = dependency / "sqlite3"
    amalgamation = include / "sqlite3.c"
    pins = {"amalgamation": fingerprint(amalgamation), "upstream_build": fingerprint(dependency / "build.rs")}
    require(pins["amalgamation"] == {"bytes": 9390466, "sha256": SQLITE_SHA}
            and pins["upstream_build"] == {"bytes": 33727, "sha256": SQLITE_BUILD_SHA},
            "SQLite original source pins changed")
    require(not any(c in str(amalgamation) for c in ('"', "\\", "\n", "\r")), "unsafe C include path")
    return include, pins


def commands(root, output, include):
    generated = output / "kernel-owned-original.c"
    return {
        "kernel": ["/usr/bin/cc", "-std=c11", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra",
                   "-Werror", "-pthread", "-x", "c", str(generated), "-o", str(output / "kernel-analysis.so")],
        "sqlite": ["/usr/bin/cc", "-O2", "-w", "-fPIC", "-I", str(include),
                   '-DTRNM_SQLITE_AMALGAMATION="' + str(include / "sqlite3.c") + '"',
                   *("-D" + flag for flag in FLAGS), "-c", str(root / WITNESS),
                   "-o", str(output / "sqlite-analysis.o")],
    }


def validate_context(context, root, output):
    """Reconstruct the mapping; never trust a reported covered-source list."""
    require(context.get("schema") == "pon-pinned-codeql-cpp-context-v1"
            and context.get("complete") is True and context.get("source_root") == str(root)
            and context.get("output") == str(output) and not output.is_relative_to(root),
            "C analysis context identity or completion")
    before = inputs(root)
    require(context["inputs_before"] == before == context["inputs_after"], "C context source changed")
    joined, components = combined(root)
    generated = output / "kernel-owned-original.c"
    require(raw(generated) == joined and context["components"] == components
            and context["generated"] == fingerprint(generated), "C generated input/component mismatch")
    metadata = json.loads(raw(output / "cargo-metadata.stdout.log", 32 * 1024 * 1024))
    include, pins = sqlite_dependency(metadata)
    require(context["sqlite_dependency"] == {"include": str(include), **pins}, "C dependency pin mismatch")
    recipes = commands(root, output, include)
    phase_commands = {
        "compiler-version": ["/usr/bin/cc", "--version"],
        "cargo-metadata": ["cargo", "+1.95.0", "metadata", "--locked", "--format-version=1",
                           "--manifest-path", str(root / "trillionnium/Cargo.toml")],
        **recipes,
    }
    phases = context["phases"]
    require(type(phases) is list and [row.get("name") for row in phases] == list(phase_commands),
            "C build phases missing or reordered")
    for row in phases:
        name = row["name"]
        require(row["argv"] == phase_commands[name] and row["complete"] is True
                and type(row["returncode"]) is int and row["returncode"] == 0
                and not row.get("stdout_truncated", False) and not row.get("stderr_truncated", False),
                "C build phase incomplete or changed")
        for stream in ("stdout", "stderr"):
            require(row[stream] == fingerprint(output / f"{name}.{stream}.log"), "C build phase log changed")
        if name in recipes:
            require({key: value for key, value in row.items() if key != "name"}
                    == context["compilations"][name], "C compilation/phase mismatch")
    require(set(context["compilations"]) == set(recipes), "C compilation inventory")
    for name, argv in recipes.items():
        row = context["compilations"][name]
        require(row["argv"] == argv and row["complete"] is True
                and type(row["returncode"]) is int and row["returncode"] == 0
                and not row.get("stdout_truncated", False) and not row.get("stderr_truncated", False),
                "C compilation incomplete or changed")
        for stream in ("stdout", "stderr"):
            require(row[stream] == fingerprint(output / f"{name}.{stream}.log"), "C compiler log changed")
        require(context["outputs"][name] == fingerprint(Path(argv[-1]))
                and context["outputs"][name]["bytes"] > 0, "C compiler output changed")
    require(context.get("runtime_build_qualified") is False and context.get("native_code_executed") is False,
            "analysis cannot assert runtime qualification")
    return {"generated_path": str(generated), "components": components,
            "direct_source": WITNESS, "scope": "Exact original C bytes in explicitly separate analysis compilations; no runtime build qualification."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root, output = args.source_root.resolve(strict=True), args.output.resolve()
    require(not output.is_relative_to(root), "analysis output must be outside source")
    output.mkdir(parents=True, exist_ok=False)
    result = {"schema": "pon-pinned-codeql-cpp-context-v1", "source_root": str(root), "output": str(output),
              "complete": False, "runtime_build_qualified": False, "native_code_executed": False,
              "scope": "Standalone analysis recipe; original production loader/build fence is unchanged.",
              "analysis_harness": {"path": str(Path(__file__).resolve()), **fingerprint(Path(__file__))},
              "kernel_input_transport": "Original stdin bytes saved unchanged in a named analysis file; no native library loaded.",
              "compilations": {}, "outputs": {}, "phases": []}
    spec = importlib.util.spec_from_file_location("_codeql_cpp_bounded", root / "formal/pon-nakamoto-v1/bounded_process.py")
    bounded = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = bounded
    spec.loader.exec_module(bounded)

    def phase(name, argv, budget):
        record = {"argv": argv, "wall_budget_seconds": budget}
        start = time.monotonic()
        try:
            capture = bounded.run_bounded(argv, b"", cwd=root, env=dict(os.environ), timeout=budget,
                                          stdout_limit=32 * 1024 * 1024, stderr_limit=16 * 1024 * 1024)
            record.update(complete=capture.returncode == 0, returncode=capture.returncode)
        except bounded.ProcessFailure as error:
            capture = error
            record.update(complete=False, returncode=error.returncode, failure_code=str(error),
                          stdout_truncated=error.stdout_truncated, stderr_truncated=error.stderr_truncated)
        for stream in ("stdout", "stderr"):
            path = output / f"{name}.{stream}.log"
            with path.open("xb") as file:
                file.write(getattr(capture, stream))
            record[stream] = fingerprint(path)
        record["elapsed_seconds"] = time.monotonic() - start
        result["phases"].append({"name": name, **record})
        if name in ("kernel", "sqlite"):
            result["compilations"][name] = record
        require(record["complete"], "C analysis phase failed: " + name)
        return capture.stdout

    try:
        result["inputs_before"] = inputs(root)
        phase("compiler-version", ["/usr/bin/cc", "--version"], 30)
        metadata = json.loads(phase("cargo-metadata", ["cargo", "+1.95.0", "metadata", "--locked",
                              "--format-version=1", "--manifest-path", str(root / "trillionnium/Cargo.toml")], 300))
        include, pins = sqlite_dependency(metadata)
        result["sqlite_dependency"] = {"include": str(include), **pins}
        joined, result["components"] = combined(root)
        generated = output / "kernel-owned-original.c"
        with generated.open("xb") as file:
            file.write(joined)
        result["generated"] = fingerprint(generated)
        for name, argv in commands(root, output, include).items():
            phase(name, argv, 300)
            result["outputs"][name] = fingerprint(Path(argv[-1]))
        result["inputs_after"] = inputs(root)
        require(result["inputs_after"] == result["inputs_before"], "source changed during analysis compilation")
        result["complete"] = True
        validate_context(result, root, output)
    except Exception as error:
        result["complete"] = False
        result["failure"] = {"type": type(error).__name__, "code": str(error) if isinstance(error, ValueError) else "analysis compile failed"}
    finally:
        if "inputs_before" in result:
            try:
                result["inputs_after"] = inputs(root)
                result["complete"] &= result["inputs_after"] == result["inputs_before"]
            except Exception as error:
                result["complete"] = False
                result["source_after_failure"] = type(error).__name__
        with (output / "context.json").open("x") as file:
            json.dump(result, file, indent=2, allow_nan=False)
            file.write("\n")
        print(json.dumps({"complete": result["complete"], "runtime_build_qualified": False}))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
