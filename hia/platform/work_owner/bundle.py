"""Admit the complete current Work owner source and actual native artifacts."""
from __future__ import annotations
import lzma
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tomllib
from .build import ROOT, HERE, OWNED, COMPILER, compose, digest, identity, inspect_owner, need, read_json, source_manifest
from .cases import corpus, corpus_bytes, native_options, require_semantics
from .native_io import decode
from .trace_audit import audit_trace
from .faults import profiles

OMIT = frozenset(("report.json", "artifacts.json"))
SKIP = frozenset(("target", "__pycache__", ".pytest_cache"))

TRACE_CONTROL_PROFILE = (
    ("baseline-no-notifications", True), ("optional-worker-notification", True),
    ("optional-main-notification", True), ("optional-both-notifications", True),
    ("unknown-tid-notification", False), ("worker-notification-before-birth", False),
    ("main-notification-before-exit", False), ("duplicate-worker-notification", False),
    ("wrong-worker-notification-code", False), ("worker-call-before-birth", False),
    ("worker-call-after-exit", False), ("unknown-thread-syscall", False),
    ("main-observation-before-worker-exit", False), ("remove-clear-tid-clone-flag", False),
    ("replace-clone-parent-tid", False), ("join-private-instead-of-shared", False),
    ("boot-read-byte-substitution", False), ("limit-read-byte-substitution", False),
    ("counter-read-byte-substitution", False), ("parent-open-loses-nofollow", False),
    ("missing-actual-worker-exit", False), ("output-byte-substitution", False),
    ("main-call-after-terminal", False), ("worker-wrong-clock", False),
    ("remove-resource-eof", False), ("extra-resource-eof", False), ("two-space-pid-rendering", True),
)
SIGNAL_CONTROL_PROFILE = (
    ("actual-signal-baseline", True), ("signal-after-successful-ack", True),
    ("signal-before-ack-read", True), ("missing-signal-return", False),
    ("duplicate-signal-return", False), ("signal-return-wrong-tid", False),
    ("signal-delivery-wrong-tid", False), ("signal-return-wrong-mask", False),
    ("wrong-signal-name", False), ("return-before-delivery", False),
    ("work-before-signal-return", False), ("signal-return-after-lifetime", False),
    ("injected-signal-return", False), ("eintr-without-interrupted-read", False),
)

def validate_control_roster(report, profile, schema):
    need(type(report) is dict and report.get("schema") == schema and report.get("status") == "PASS",
         "Wrong control report schema/status")
    rows = report.get("rows")
    need(type(rows) is list and len(rows) == len(profile)
         and type(report.get("count")) is int and report["count"] == len(profile)
         and report.get("positive") == sum(accepted for _, accepted in profile)
         and report.get("negative") == sum(not accepted for _, accepted in profile),
         "Incomplete actual control roster")
    need([(r.get("name"), r.get("expected_acceptance")) for r in rows] == list(profile),
         "Actual control names/order/expectations differ")
    need(all(type(r.get("expected_acceptance")) is bool and type(r.get("actual_acceptance")) is bool
             and r["actual_acceptance"] is r["expected_acceptance"] and r.get("status") == "PASS"
             for r in rows), "A required control did not execute its expected decision")


def canonical_root(value):
    path = Path(value).absolute()
    need(path.is_dir() and path.resolve(strict=True) == path and not path.is_symlink(),
         "Canonical existing directory required: " + str(path))
    return path

def canonical_file(root, name):
    need(type(name) is str and name and "\\" not in name and "\0" not in name,
         "Invalid evidence/source name")
    relative = Path(name)
    need(not relative.is_absolute() and ".." not in relative.parts and "." not in relative.parts
         and relative.as_posix() == name, "Noncanonical relative artifact path")
    path = Path(root) / relative
    identity(path)
    return path

def overlap(first, second):
    first = Path(first).absolute(); second = Path(second).absolute()
    return first == second or first in second.parents or second in first.parents

def require_output_and_target(output, target, *protected):
    output = Path(output).absolute(); target = Path(target).absolute()
    need(output.resolve() == output and not output.exists() and not output.is_symlink(),
         "Fresh canonical original output required")
    need(target.resolve() == target and not target.is_symlink(), "Canonical Cargo target required")
    if target.exists(): need(target.is_dir(), "Cargo target is not a directory")
    need(not overlap(output, target), "Cargo target overlaps output or its isolated source")
    for root in protected:
        root = Path(root).absolute()
        need(not overlap(output, root) and not overlap(target, root),
             "Output or Cargo target overlaps a protected source/native bundle")
    return output, target

def include_graph(repository):
    """Resolve literal source/data includes in the complete local Node graph."""
    repository = canonical_root(repository)
    workspace = tomllib.loads(canonical_file(repository, "trillionnium/Cargo.toml").read_text())
    inherited = workspace.get("workspace", {}).get("dependencies", {})
    pending = ["trillionnium/crates/trnm-pon-node"]; visited = set(); includes = {}
    literal = re.compile(rb'\b(include|include_str|include_bytes)!\s*\(\s*"([^"\\\r\n]*)"\s*,?\s*\)')
    occurrence = re.compile(rb"\b(?:include|include_str|include_bytes)!\s*\(")
    manifest_literal = re.compile(
        rb'\b(include_str|include_bytes)!\s*\(\s*concat!\s*\(\s*env!\s*\(\s*"CARGO_MANIFEST_DIR"\s*\)\s*,\s*"(/[^"\\\r\n]*)"\s*,?\s*\)\s*,?\s*\)')
    def relative(base, value):
        need(type(value) is str and value and not value.startswith("/") and "\\" not in value and "\0" not in value,
             "Noncanonical local Cargo/include path")
        parts = base.split("/")
        for part in value.split("/"):
            need(part != "", "Empty original path component")
            if part == ".": continue
            if part == "..":
                need(bool(parts), "Original path escaped repository"); parts.pop()
            else: parts.append(part)
        need(bool(parts), "Original include resolves to repository")
        return "/".join(parts)
    while pending:
        package = pending.pop()
        if package in visited: continue
        visited.add(package)
        manifest = tomllib.loads(canonical_file(repository, package + "/Cargo.toml").read_text())
        tables = [manifest, *manifest.get("target", {}).values()]
        for table in tables:
            need(type(table) is dict, "Malformed original Cargo target table")
            for category in ("dependencies", "dev-dependencies", "build-dependencies"):
                for name, value in table.get(category, {}).items():
                    if type(value) is str: continue
                    need(type(value) is dict, "Malformed original Cargo dependency")
                    base = package
                    if value.get("workspace") is True:
                        need(name in inherited, "Missing inherited original dependency")
                        value = inherited[name]; base = "trillionnium"
                        if type(value) is str: continue
                    if "path" in value:
                        target = relative(base, value["path"])
                        canonical_file(repository, target + "/Cargo.toml"); pending.append(target)
        for path in sorted((repository / package).rglob("*.rs")):
            if any(p in SKIP for p in path.relative_to(repository).parts): continue
            source = path.relative_to(repository).as_posix()
            raw = canonical_file(repository, source).read_bytes()
            found = list(literal.finditer(raw))
            bound_manifest = list(manifest_literal.finditer(raw))
            need(len(found) + len(bound_manifest) == len(occurrence.findall(raw)),
                 "Unsupported original include expression: " + source)
            for match, base, value, form in [
                    *[(m, path.parent.relative_to(repository).as_posix(), m[2].decode(), "file-relative")
                      for m in found],
                    *[(m, package, m[2].decode()[1:], "bound-CARGO_MANIFEST_DIR")
                      for m in bound_manifest]]:
                target = relative(base, value)
                canonical_file(repository, target)
                includes.setdefault(target, []).append({"source": source, "kind": match[1].decode(),
                                                         "literal": match[2].decode(), "form": form})
    return {"local_packages": sorted(visited), "includes": dict(sorted(includes.items()))}

def original_manifest(repository):
    repository = canonical_root(repository); rows = {}
    for directory in ("trillionnium", "config", "formal"):
        need((repository / directory).is_dir(), "Missing original input root")
        for path in sorted((repository / directory).rglob("*")):
            relative = path.relative_to(repository)
            if any(part in SKIP for part in relative.parts): continue
            need(not path.is_symlink(), "Symbolic original source")
            if path.is_file(): rows[relative.as_posix()] = identity(path)
    tracked = subprocess.run(["git", "-C", str(repository), "ls-tree", "-r", "--name-only", "-z",
                              "HEAD", "--", "trillionnium", "config", "formal"],
                             capture_output=True, timeout=30, check=True).stdout
    names = {p.decode() for p in tracked.split(b"\0") if p}
    need(names and names <= set(rows), "Original source copy omits tracked retained inputs")
    graph = include_graph(repository)
    for name in graph["includes"]: rows[name] = identity(canonical_file(repository, name))
    need(all(name in rows for name in ("trillionnium/Cargo.toml", "trillionnium/Cargo.lock",
             "trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs",
             "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs")), "Incomplete original Node source graph")
    return dict(sorted(rows.items()))

def artifacts(directory):
    root = canonical_root(directory); result = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        need(not path.is_symlink(), "Symbolic native qualification artifact")
        if path.is_dir(): continue
        if relative not in OMIT: result[relative] = identity(path)
    return result

def snapshot(directory):
    root = canonical_root(directory)
    return {"files": artifacts(root), "report": identity(root / "report.json"),
            "index": identity(root / "artifacts.json")}

def source_bindings(report):
    need(type(report) is dict and type(report.get("build")) is dict, "Missing native build binding")
    current = source_manifest()
    need(report.get("source_inputs") == report["build"].get("source_inputs") == current,
         "Top-level/build/current complete source maps differ")
    need(set("hia/platform/work_owner/" + n for n in OWNED) <= set(current), "Missing mandatory owner source")
    return current

def validate_build(root, report):
    build = read_json(root / "build/build.json")
    need(build == report["build"] and build["status"] == "PASS" and build["compiler_sha256"] == COMPILER,
         "Native build report/compiler binding differs")
    captured = {name: (HERE / name).read_bytes() for name in OWNED if name.endswith(".hepta")}
    from .build import FROZEN
    captured.update({name: (ROOT / name).read_bytes() for name in FROZEN})
    programs = compose(captured)
    need(set(build["native_images"]) == set(build["composed_sources"]) == set(programs),
         "Compiled/composed native section roster differs")
    labels = ["compile-" + name for name in programs] + ["emit-owner", "emit-fixture", "emit-closed-fd"]
    need([row["stage"] for row in build["stages"]] == labels, "Complete actual compile/emission stage roster differs")
    for name, raw in programs.items():
        need((root / "build" / (name + ".hepta")).read_bytes() == raw
             and build["composed_sources"][name] == {"bytes": len(raw), "sha256": digest(raw)},
             "Composed full HIA source differs")
        flat = root / "build" / (name + (".elf" if name.endswith("emitter") else ".flat.bin"))
        need(identity(flat) == build["native_images"][name], "Actual compiled native section differs")
        stage = root / "build" / ("compile-" + name)
        need((stage / "stdin.raw").read_bytes() == raw
             and (stage / "stdout.raw").read_bytes() == flat.read_bytes(),
             "Actual compiler stdin/source or stdout/flat linkage differs")
    for stage in build["stages"]:
        directory = root / "build" / stage["stage"]
        need(read_json(directory / "receipt.json") == stage and stage["exit_code"] == 0
             and stage["timed_out"] is False and stage["cleanup"] is None and stage["stderr_hex"] == "",
             "Actual native build stage did not complete cleanly")
        for filename, prefix in (("stdin.raw", "input"), ("stdout.raw", "output"), ("stderr.raw", "stderr")):
            need(identity(directory / filename) == {"bytes": (len(bytes.fromhex(stage["stderr_hex"])) if prefix == "stderr" else stage[prefix + "_bytes"]),
                 "sha256": stage[prefix + "_sha256"]}, "Native build raw stream differs")
    contract = read_json(HERE / "abi.json")
    need(set(build["images"]) == {"owner", "fixture", "closed-fd"}, "Final native image roster differs")
    for name, owner, host in (("owner", "owner", "host"), ("fixture", "owner-fixture", "host-fixture"),
                             ("closed-fd", "owner-fixture", "host-fixture")):
        raw = (root / "build" / (name + ".elf")).read_bytes()
        inspect_owner(raw); binding = contract["images"][name]
        need(identity(root / "build" / (name + ".elf")) == binding["executable"],
             "Native image no longer equals the reviewed adapter/HIA")
        a, work, c = [(root / "build" / (part + ".flat.bin")).read_bytes() for part in (owner, "work", host)]
        need(all(0 < len(part) <= 524288 for part in (a, work, c)), "Captured flat exceeds the fixed native profile")
        payload = struct.pack("<4Q", int.from_bytes(b"OWBND001", "little"), len(a), len(work), len(c)) + a + work + c
        prefix = binding["prefix_bytes"]
        need(raw[prefix:] == payload and digest(raw[232:prefix]) == binding["adapter_sha256"],
             "Actual flat sections are not the complete payload of the pinned native ELF")
        stage = root / "build" / ("emit-" + name)
        need((stage / "stdin.raw").read_bytes() == payload and (stage / "stdout.raw").read_bytes() == raw,
             "Actual emitter input/payload or output/native image linkage differs")
        image = build["images"][name]
        need(image["path"] == name + ".elf" and image["bytes"] == len(raw)
             and image["sha256"] == digest(raw) and image["prefix_bytes"] == prefix,
             "Final native image receipt differs from the retained executable")

def validate_physical(case, physical, directory, image_sha):
    need(read_json(directory / "physical.json") == physical and physical["image_sha256"] == image_sha,
         "Physical receipt or actual image differs")
    for name in ("stdout", "stderr"):
        need(identity(directory / (name + ".raw")) == physical[name], "Actual native raw output changed")
    raw = (directory / "stdout.raw").read_bytes()
    need(decode(raw) == physical["decoded"], "Claimed native decoded frame differs from actual bytes")
    expected = struct.pack("<8Q", int.from_bytes(b"WOFIX001", "little"),
                           case["options"].get("gate_sequence", 0), case["options"].get("gate_stage", 0),
                           0, 0, 0, 0, 0) + bytes.fromhex(case["request_hex"])
    need((directory / "stdin.raw").read_bytes() == expected, "Actual native proof or private callback differs")
    options = case["options"]
    need(physical["fixture"] is True and physical["gate_sequence"] == options.get("gate_sequence", 0)
         and physical["gate_stage"] == options.get("gate_stage", 0)
         and physical["signal_number"] == options.get("signal_number")
         and physical["actions"] == options.get("actions", []), "Actual private callback profile differs")
    h = physical["decoded"]["header"]
    need(physical["exit_code"] == (0 if h["domain"] == 0 else 64 + h["domain"])
         and physical["stderr_hex"] == "" and not (directory / "stderr.raw").read_bytes(),
         "Actual process terminal/stderr differs")
    return require_semantics(case, physical)

def validate_bundle(directory, repository, *, require_trace=True):
    need(__debug__, "Work owner admission refuses optimized Python")
    root = canonical_root(directory); repository = canonical_root(repository)
    report = read_json(root / "report.json")
    need(report.get("schema") == "trnm.hia.work-owner-qualification.v1"
         and report.get("status") == "PASS", "No complete successful native qualification")
    sources = source_bindings(report)
    original = original_manifest(repository)
    need(report.get("original_sources") == original, "Complete current original Node graph differs")
    need(read_json(root / "artifacts.json") == artifacts(root), "Native artifact inventory omitted or changed a file")
    before = read_json(root / "source-before.json"); after = read_json(root / "source-after.json")
    need(before == after and before["source_inputs"] == sources and before["original_sources"] == original
         and before["original_include_graph"] == include_graph(repository) and report.get("source_after") == "MATCH",
         "Native source-before/after closure differs")
    validate_build(root, report)
    cases = corpus()
    need((root / "cases.json").read_bytes() == corpus_bytes()
         and report["corpus"] == identity(root / "cases.json"), "Complete independent corpus changed")
    need(len(report["semantic"]) == len(cases) == 61
         and [r["name"] for r in report["semantic"]] == [r["name"] for r in cases],
         "Native semantic case roster/order differs")
    native = []
    fixture_sha = report["build"]["images"]["fixture"]["sha256"]
    for case, row in zip(cases, report["semantic"], strict=True):
        need(row["status"] == "PASS", "Failed native case")
        native.append(validate_physical(case, row["physical"], root / "semantic" / case["name"], fixture_sha))
    primitive = read_json(root / "primitives/report.json")
    need(primitive == report["primitives"] and primitive["status"] == "PASS"
         and [primitive.get(k) for k in ("sha_vectors", "sha_bounds", "work_histories", "work_bounds", "owner_identity_controls")]
             == [150, 4, 13, 4, 4]
         and len(primitive["rows"]) == 175 and all(r["status"] == "PASS" for r in primitive["rows"]),
         "Primitive arithmetic/bounds/identity qualification incomplete")
    for name in ("sha", "work", "owner"):
        need(primitive["images"][name] == identity(root / "build" / (name + ".flat.bin")),
             "Primitive was not executed from this actual native section")
    if require_trace:
        need(report["trace_status"] == "PASS", "Actual syscall tracing is mandatory")
        names = ("baseline", "late-cancel", "closed-parent")
        need([r["name"] for r in report["traces"]] == list(names), "Actual trace roster differs")
        for row in report["traces"]:
            d = root / "traces" / row["name"]
            audit = audit_trace((d / "syscalls.raw").read_text(), (d / "stdin.raw").read_bytes(),
                                (d / "stdout.raw").read_bytes(), expected_signal=row["signal"],
                                fault_profile=row["fault_profile"])
            need(audit == row["audit"] == read_json(d / "trace-audit.json"), "Complete actual trace audit differs")
            need(read_json(d / "physical.json") == row["physical"], "Actual traced process receipt differs")
        controls = read_json(root / "trace-controls/report.json")
        need(controls == report["trace_controls"] and controls["status"] == "PASS"
             and controls["count"] == 27 and controls["positive"] == 5 and controls["negative"] == 22,
             "Concrete trace admission controls incomplete")
        validate_control_roster(controls, TRACE_CONTROL_PROFILE, "trnm.hia.work-owner-trace-controls.v1")
        d = root / "traces/baseline"; stdin = (d / "stdin.raw").read_bytes(); stdout = (d / "stdout.raw").read_bytes()
        for row in controls["rows"]:
            packed = (root / "trace-controls" / (row["name"] + ".trace.xz")).read_bytes()
            need({"bytes": len(packed), "sha256": digest(packed)} == row["compressed_trace"], "Trace mutant archive differs")
            raw = lzma.decompress(packed)
            need({"bytes": len(raw), "sha256": digest(raw)} == row["trace"], "Complete trace mutant bytes differ")
            frame_path = root / "trace-controls" / (row["name"] + ".stdout.raw")
            frame = frame_path.read_bytes() if frame_path.exists() else stdout
            need({"bytes": len(frame), "sha256": digest(frame)} == row["stdout"], "Trace mutant frame differs")
            try: audit_trace(raw.decode(), stdin, frame); accepted = True
            except (ValueError, KeyError, IndexError, StopIteration): accepted = False
            need(accepted == row["expected_acceptance"] == row["actual_acceptance"]
                 and row["status"] == "PASS", "Concrete corrupt trace was accepted")
        signal_controls = read_json(root / "signal-controls/report.json")
        need(signal_controls == report["signal_controls"] and signal_controls["status"] == "PASS"
             and signal_controls["count"] == 14 and signal_controls["positive"] == 3
             and signal_controls["negative"] == 11, "Concrete signal interleaving controls incomplete")
        validate_control_roster(signal_controls, SIGNAL_CONTROL_PROFILE, "trnm.hia.work-owner-signal-trace-controls.v1")
        d = root / "traces/late-cancel"; stdin = (d / "stdin.raw").read_bytes(); stdout = (d / "stdout.raw").read_bytes()
        for row in signal_controls["rows"]:
            packed = (root / "signal-controls" / (row["name"] + ".trace.xz")).read_bytes()
            need({"bytes": len(packed), "sha256": digest(packed)} == row["compressed_trace"],
                 "Signal trace mutant archive differs")
            raw = lzma.decompress(packed)
            need({"bytes": len(raw), "sha256": digest(raw)} == row["trace"]
                 and {"bytes": len(stdout), "sha256": digest(stdout)} == row["stdout"],
                 "Signal trace mutant or native frame differs")
            try: audit_trace(raw.decode(), stdin, stdout, expected_signal=1); accepted = True
            except (ValueError, KeyError, IndexError, StopIteration): accepted = False
            need(accepted == row["expected_acceptance"] == row["actual_acceptance"]
                 and row["status"] == "PASS", "Corrupt signal scheduling trace was accepted")
        faults = read_json(root / "clock-faults/report.json")
        need(faults == report["clock_faults"] and faults["status"] == "PASS" and faults["count"] == 18
             and [r["profile"] for r in faults["rows"]] == profiles(), "Complete actual CLOCK1 fault roster differs")
        for row in faults["rows"]:
            d = root / "clock-faults" / row["name"]; profile = row["profile"]
            audit = audit_trace((d / "syscalls.raw").read_text(), (d / "stdin.raw").read_bytes(),
                                (d / "stdout.raw").read_bytes(),
                                fault_profile="worker-clock-" + profile["errno"] + "-" + str(profile["ordinal"]))
            need(audit == row["trace"] == read_json(d / "trace-audit.json")
                 and read_json(d / "physical.json") == row["physical"]
                 and row["physical"]["image_sha256"] == fixture_sha, "Actual controlled clock trace differs")
    need(source_manifest() == sources and original_manifest(repository) == original,
         "Source changed during native admission")
    return {"report": report, "native": native, "source_inputs": sources,
            "original_sources": original, "snapshot": snapshot(root)}

def check_snapshot(directory, accepted):
    need(snapshot(directory) == accepted["snapshot"], "Previously admitted complete native bundle changed")
    need(source_manifest() == accepted["source_inputs"], "Complete current owner source changed")
