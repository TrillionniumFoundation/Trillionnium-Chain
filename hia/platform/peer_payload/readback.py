"""Independently connect exact HIA inputs, executed children, original outputs and all observations."""
from __future__ import annotations

import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import sys

from hia.platform.peer_lease_unix.readback import processes, original_readback
from hia.platform.peer_lease_unix.original_build import cargo_events, PROFILE, TEST_COUNTS
from hia.platform.build import inspect_executable
from hia.tools.toolchain import checked_source, pinned_toolchain
from .contract import (ROOT, HERE, SCHEMA, COMPILER, LIMITS, FALSE, ORDER, IMAGES, OBJECTS,
    capture, canonical, corpus, document, identity, need, relative, repository_identity,
    source_capture, source_manifest, priority_cases, check_environment, wal_scope_history)

GROUPS = ("primitives", "runtime", "allocations", "views", "public", "syscalls", "crash", "boundaries",
          "wal-small", "wal-large", "wal-maximum-replay", "wal-maximum-index")
STATUS = {"public": "PASS_ACTUAL_ORIGINAL_NATIVE_PUBLIC_HISTORIES",
          "syscalls": "PASS_ACTUAL_ORIGINAL_NATIVE_SYSCALL_FAULTS",
          "crash": "PASS_ACTUAL_ORIGINAL_NATIVE_DURABILITY_CUTS",
          "boundaries": "PASS_ACTUAL_ORIGINAL_NATIVE_NAMESPACE_AND_LOCK_BOUNDARIES",
          "runtime": "PASS_ACTUAL_PRIVATE_ARENA_DISPATCH",
          "allocations": "PASS_ACTUAL_HIA_ALLOCATION_AND_LIFETIME"}
METHODS = ("open", "path", "head_path", "namespace", "last_hash", "record_count", "accepted_frame_count",
           "contains_session", "latest_generation", "verify_bound_endpoint_identity", "admit", "lookup_exact_v1")


def file_identity(path):
    path = Path(path).absolute()
    for ancestor in (path, *path.parents):
        need(not ancestor.is_symlink(), "Linked retained path or ancestor")
    before = path.stat()
    need(stat.S_ISREG(before.st_mode), "Retained file is not regular")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    after = path.stat()
    need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
         == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
         "Retained bytes changed during readback")
    return {"bytes": before.st_size, "sha256": digest}


def check_identity(path, value):
    need(type(value) is dict and type(value.get("bytes")) is int and value["bytes"] >= 0
         and type(value.get("sha256")) is str and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]),
         "Malformed retained identity")
    need(file_identity(path) == {key: value[key] for key in ("bytes", "sha256")}, "Retained bytes differ: " + str(path))


def inventory(root):
    root = Path(root)
    values = {}
    for directory, directories, filenames in os.walk(root, followlinks=False):
        for name in sorted([*directories, *filenames]):
            path = Path(directory) / name
            key = path.relative_to(root).as_posix()
            if key in {"report.json", "contents.json"}:
                continue
            status = path.lstat()
            row = {"mode": stat.S_IMODE(status.st_mode)}
            if stat.S_ISREG(status.st_mode):
                row.update(kind="file", **file_identity(path))
            elif stat.S_ISDIR(status.st_mode):
                row["kind"] = "directory"
            elif stat.S_ISLNK(status.st_mode):
                row.update(kind="symlink", target=os.readlink(path))
            elif stat.S_ISSOCK(status.st_mode):
                row["kind"] = "socket"
            elif stat.S_ISFIFO(status.st_mode):
                row["kind"] = "fifo"
            else:
                raise ValueError("Unexpected retained object: " + key)
            need(key not in values, "Duplicate retained member")
            values[key] = row
    return values


def header(report, *, final):
    need(report.get("schema") == SCHEMA and report.get("status") == ("PASS" if final else "RUNNING")
         and report.get("limits") == LIMITS and report.get("source_inputs_stable") is True
         and all(report.get(name) is False for name in FALSE)
         and report.get("metadata_owner_public_methods_qualified") == 12
         and report.get("original_tests_rerun_in_this_qualification") is True
         and report.get("public_observer_links_unchanged_original") is True
         and report.get("private_observer_append_only_test_hook") is True
         and report.get("failure") is None and report.get("traceback") is None,
         "Failed, partial or overstated metadata qualification")
    need(type(report.get("elapsed_ns")) is int and 0 < report["elapsed_ns"] <= 1_200_000_000_000,
         "Actual unchanged job budget is absent or exceeded")
    need(set(report.get("groups", {})) == set(GROUPS), "Complete native group roster changed")


def core_counts(value):
    counts = {"functions": len(value["functions"]), "blocks": sum(len(fn["blocks"]) for fn in value["functions"]),
              "ops": sum(len(block["ops"]) for fn in value["functions"] for block in fn["blocks"]),
              "max_blocks": max(len(fn["blocks"]) for fn in value["functions"])}
    need(counts["functions"] <= 128 and counts["blocks"] <= 1536 and counts["ops"] <= 8192
         and counts["max_blocks"] <= 256, "Compiler profile limits increased")
    return counts


def native_receipt(directory, row, executable, payload, stdout, expected_exit=0):
    need(document(directory / "receipt.json") == row and type(row.get("exit_code")) is int
         and row["exit_code"] == expected_exit and row.get("timed_out") is False
         and row.get("cleanup") is None and row.get("wall_limit_seconds") == 30
         and row.get("cleanup_limit_seconds") == 3 and row.get("environment") == {"PATH": ""}
         and row.get("stderr_hex") == "" and row.get("cwd") == str(directory)
         and type(row.get("start_monotonic_ns")) is int and type(row.get("end_monotonic_ns")) is int
         and 0 <= row["end_monotonic_ns"] - row["start_monotonic_ns"] <= 30_000_000_000,
         "Native stage failed, changed its deadline or renewed cleanup")
    need(capture(directory / "stdin.raw") == payload and capture(directory / "stdout.raw") == stdout
         and capture(directory / "stderr.raw") == b"", "Actual complete native streams changed")
    for raw, prefix in ((executable, "executable"), (payload, "input"), (stdout, "output")):
        need(identity(raw) == {"bytes": row[prefix + "_bytes"], "sha256": row[prefix + "_sha256"]},
             "Actual native execution identity changed")
    need(row["stderr_sha256"] == identity(b"")["sha256"], "Native stderr digest changed")


def build_readback(output, expected_sources):
    output = Path(output)
    value = document(output / "build.json")
    need(value.get("schema") == "trnm.hia.payload-metadata-build.v1" and value.get("status") == "PASS"
         and value.get("source_inputs_stable") is True and value.get("source_inputs") == expected_sources
         and value.get("limits") == LIMITS and all(value.get(name) is False for name in FALSE)
         and value.get("compiler_limits_preserved") is True
         and value.get("unchanged_production_functions_in_index_observer") is True,
         "Native build is partial or unbound")
    need(set(value["images"]) == set(IMAGES)
         and set(value["objects"]) == {*(name + "-object" for name in OBJECTS), "metadata-index-object"}
         and set(value["executables"]) == {"payload-owner", "view-fixture", *OBJECTS, "metadata-index", "metadata-observed"},
         "Native image/object/ELF roster changed")
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    from hepta.object_symbols import inspect_object_symbols
    from hepta.elf_shared_abi import inspect_owned_shared_elf
    documents = {}
    for name in dict.fromkeys((*IMAGES, *OBJECTS)):
        checked, composed, *_ = checked_source(HERE / (name + ".hepta"))
        documents[name] = (checked.as_dict(), composed)
    # This is an explicitly test-only entry. Every production function is
    # reconstructed from the actual canonical source and retained unchanged.
    entry = b'''fn f0(input:readbuf,output:mutbuf,scratch:mutbuf) -> (u32) effects(read,write,trap) entry(entry)
block entry(input:readbuf,output:mutbuf,scratch:mutbuf)
  zero:u64 = const() {"value":0}
  count:u64 = call(input,zero) {"function":"pl_read"}
  code:u64 = call(scratch,count) {"function":"pw_validate"}
  result:u32 = int.cast(code) {"mode":"wrap"}
  ret(result)
end
'''
    pattern = re.compile(rb"(?ms)^fn f0\([^\n]*\n.*?^end(?:\n|$)")
    product = documents["metadata_log"][1]
    need(len(pattern.findall(product)) == 1, "Original private f0 no longer unique")
    observed = pattern.sub(lambda _: entry, product, count=1)
    generated = (assemble_program(observed).as_dict(), observed)
    for name, row in {**value["images"], **value["objects"]}.items():
        object_profile = name in value["objects"]
        core, composed = generated if name == "metadata-index-object" else documents[name.removesuffix("-object")]
        need(document(output / (name + ".core.json")) == core and row["core"] == core_counts(core)
             and row["test_only_generated_entry"] is (name == "metadata-index-object"),
             "Retained checked Core differs from canonical HIA")
        wire_core = copy.deepcopy(core)
        if object_profile:
            wire_core["module"] = "selfhost_elf"
        wire = render_assembly(wire_core).encode()
        need(capture(output / (name + ".composed.hepta")) == composed
             and capture(output / (name + ".compiler-input.hepta")) == wire
             and row["wire"] == identity(wire) and row["composed"] == identity(composed),
             "Actual compiler input is not derived from the bound HIA source")
        need(row["path"] == name + (".o" if object_profile else ".native"), "Native artifact path changed")
        check_identity(output / row["path"], row)
        if object_profile:
            symbols = inspect_object_symbols(capture(output / row["path"]), "ELF64", 62)
            need(symbols["defined"] == frozenset({"f0"}) and symbols["undefined"] <= {"calloc", "free"},
                 "Private native object symbols changed")
    for name, order in (("payload-owner", ORDER), ("view-fixture", ("view_fixture", "metadata_runtime"))):
        row = value["executables"][name]
        raw = capture(output / row["path"])
        check_identity(output / row["path"], row)
        prefix = capture(output / (name + ".prefix"))
        need(row["path"] == name + ".elf" and row["module_order"] == list(order)
             and row["test_only"] is (name != "payload-owner") and len(prefix) == 5120
             and raw == prefix + b"".join(capture(output / (part + ".native")) for part in order)
             and row["elf"] == inspect_executable(raw), "Native executable image composition changed")
    for name in (*OBJECTS, "metadata-index", "metadata-observed"):
        row = value["executables"][name]
        need(row["path"] == name + ".so" and row["test_only"] is True, "Private DSO path/profile changed")
        check_identity(output / row["path"], row)
        if name != "metadata-observed":
            inspect_owned_shared_elf(capture(output / row["path"]), ("f0",))
    binding = document(ROOT / "hia/qualification/compiler-binding.json")
    need(value["compiler_sha256"] == COMPILER == binding["compiler_sha256"]
         and value["compiler_qualification_binding"] == binding
         and value["toolchain"] == document(ROOT / "hia/toolchain.lock.json"), "Pinned compiler binding changed")
    need(binding["toolchain_revision"] == value["toolchain"]["revision"]
         and identity(capture(ROOT / "hia/qualification" / relative(binding["outer_report"])))["sha256"] == binding["outer_sha256"]
         and identity(capture(ROOT / "hia/qualification" / relative(binding["nested_report"])))["sha256"] == binding["compressed_sha256"]
         and document(ROOT / "hia/qualification" / relative(binding["outer_report"]))["status"] == "COLD_SELFHOST_REPLAY_PASS",
         "Actual retained cold compiler qualification changed")
    compiler = capture(Path(os.environ["HIA_NATIVE_COMPILER"]).resolve(strict=True))
    need(identity(compiler)["sha256"] == COMPILER, "Live pinned native compiler changed")
    labels = ["compile-" + name for name in IMAGES] + ["emit-payload-owner", "emit-view-fixture"]
    labels += ["compile-" + name + "-object" for name in OBJECTS] + ["compile-metadata-index-object"]
    need([row["stage"] for row in value["compiler_stages"]] == labels, "Compiler/emitter stage roster changed")
    for row in value["compiler_stages"]:
        label = row["stage"]
        if label.startswith("compile-"):
            name = label[8:]
            artifact = value["objects"].get(name) or value["images"][name]
            native_receipt(output / "pinned-native" / label, row, compiler,
                capture(output / (name + ".compiler-input.hepta")), capture(output / artifact["path"]))
        else:
            name = label[5:]
            order = ORDER if name == "payload-owner" else ("view_fixture", "metadata_runtime")
            raw = b"HCSHD001" + struct.pack("<QQ", len(order), 2)
            raw += b"".join(struct.pack("<Q", value["images"][part]["bytes"]) for part in order)
            native_receipt(output / "pinned-native" / label, row, capture(output / "linux_emitter.native"),
                           raw, capture(output / (name + ".prefix")))
    rows = processes(output / "processes", value["tool_stages"])
    need(list(rows) == [*("link-" + name.replace("_", "-") for name in OBJECTS), "link-metadata-index",
                        "compile-allocator-observer", "link-metadata-observed"], "Link/observer stage roster differs")
    for name, tool in value["tools"].items():
        need(name in {"ld", "cc", "strace"} and tool["retained"] == "tools/" + name, "Unknown build tool")
        check_identity(Path(tool["path"]), tool)
        check_identity(output / tool["retained"], tool)
    need(set(value["tools"]) == {"ld", "cc", "strace"}, "Missing actual build tool")
    link_names = {"link-" + name.replace("_", "-"): name
                  for name in (*OBJECTS, "metadata-index", "metadata-observed")}
    for label, row in rows.items():
        if label == "compile-allocator-observer":
            argv = [value["tools"]["cc"]["path"], "-std=c11", "-O2", "-fPIC", "-Wall", "-Wextra", "-Werror",
                "-pthread", "-c", str(ROOT / "hia/platform/pq_auth/qualification/allocator_observer.c"),
                "-o", str(output / "allocator-observer.o")]
        else:
            name = link_names[label]
            argv = [value["tools"]["ld"]["path"], "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                    "-z", "relro", "-z", "now", "--build-id=none", "--hash-style=both"]
            if name == "metadata-observed":
                argv += ["--wrap=calloc", "--wrap=free", str(output / "metadata_log-object.o"),
                         str(output / "allocator-observer.o"), "-lc", "-lpthread"]
            else:
                argv += [str(output / (name + "-object.o")), "-lc"]
            argv += ["-o", str(output / (name + ".so"))]
        need(row["argv"] == argv and row["wall_limit_seconds"] == 30,
             "Actual link/observer command or compile deadline changed")
    return value


def original_observers(output):
    output = Path(output)
    value = document(output / "report.json")
    need(value.get("schema") == "trnm.hia.payload-metadata-original.v1" and value.get("status") == "PASS"
         and value.get("reused_prior_execution") is False and value.get("source_inputs_stable") is True
         and value.get("public_observer_links_unchanged_original") is True
         and value.get("private_observer_original_functions_replaced") is False
         and value.get("complete_original_tests_preserved") is True, "Original complete/public/private gate failed")
    check_identity(output / "complete/build.json", value["complete_report"])
    complete = document(output / "complete/build.json")
    tests = original_readback(output / "complete", complete)
    need(tests == value["retained_tests"] and tests["outer_tests"] == 121 and tests["child_reexecutions"] == 2,
         "Complete original 121 plus two existing child executions changed")
    # The generic original reader permits shorter budgets. This module also
    # binds every actual stage to its exact fixed original deadline.
    limits = {"project-preflight": 30, "rust-sysroot": 30, "rust-version": 30,
              "clippy-version": 30, "clippy-driver-version": 30, "complete-cargo-graph": 60,
              "retained-original-tests": 240, "workspace-fmt": 60, "strict-original-clippy": 240}
    limits.update({"original-roster-" + str(i).zfill(2): 30 for i in range(len(TEST_COUNTS))})
    limits.update({"build-observer-" + name: 240 for name in ("daemon", "client", "client-owner", "codec")})
    need({row["name"]: row["wall_limit_seconds"] for row in complete["stages"]} == limits,
         "An original full-gate budget changed")
    events = cargo_events(capture(output / "complete/processes/retained-original-tests/stdout.raw"))
    library_names = ("trnm_peer_lease", "fs2", "libc", "rustix", "sha2")
    libraries = {}
    for name in library_names:
        matches = [event for event in events if event["target"]["name"] == name
                   and not event["profile"]["test"] and any(path.endswith(".rlib") for path in event["filenames"])]
        expected_profile = {**PROFILE, "opt_level": "3"} if name == "sha2" else PROFILE
        need(len(matches) == 1 and matches[0]["profile"] == expected_profile,
             "Original dependency profile or selection changed")
        event = matches[0]
        paths = [path for path in event["filenames"] if path.endswith(".rlib")]
        need(len(paths) == 1, "Original dependency rlib is ambiguous")
        libraries[name] = {"path": paths[0], "cargo_event": event, **file_identity(paths[0])}
    need(libraries == value["libraries"], "Original observer was not linked to this fresh Cargo graph")
    dependencies = sorted({str(Path(path).parent) for event in events
                           for path in event["filenames"] if path.endswith((".rlib", ".rmeta"))})
    need(value["dependencies"] == dependencies, "Original dependency search path changed")
    source = ROOT / "trillionnium/crates/trnm-peer-lease"
    expected_files = {path.relative_to(source).as_posix(): capture(path)
                      for path in source.rglob("*") if path.is_file()}
    actual_files = {path.relative_to(output / "private-source").as_posix()
                    for path in (output / "private-source").rglob("*") if not path.is_dir()}
    need(set(expected_files) == set(value["instrumentation"]) == actual_files,
         "Instrumented original source namespace differs from unchanged crate")
    for name, raw in expected_files.items():
        wanted = raw
        if name == "src/payload.rs":
            wanted += b"\n" + capture(HERE / "metadata_reference_hook.rs")
        elif name == "src/lib.rs":
            wanted += b"\npub use payload::qualification_payload_codec_v1;\n"
        row = value["instrumentation"][name]
        need(row == {"original": identity(raw), "observed": identity(wanted), "appended_test_hook": wanted != raw}
             and capture(output / "private-source" / name) == wanted,
             "Private oracle replaced an original function or appended a different hook")
    tools = complete["tools"]
    common = [tools["rustc"]["path"], "--edition=2021", "-C", "opt-level=0", "-C", "debuginfo=2",
              "-C", "debug-assertions=yes", "-C", "overflow-checks=yes"]
    for path in dependencies:
        common += ["-L", "dependency=" + path]
    external = []
    for name in library_names[1:]:
        external += ["--extern", name + "=" + libraries[name]["path"]]
    commands = {
        "observer-rustfmt": [tools["rustfmt"]["path"], "--edition", "2021", "--check",
            str(HERE / "public_reference.rs"), str(HERE / "metadata_reference.rs"), str(HERE / "metadata_reference_hook.rs")],
        "public-observer": [*common, "--crate-name", "payload_public_observer", "--extern",
            "trnm_peer_lease=" + libraries["trnm_peer_lease"]["path"], str(HERE / "public_reference.rs"),
            "-o", str(output / "public-reference.elf")],
        "private-library": [*common, "--crate-name", "trnm_peer_lease", "--crate-type", "rlib", "--cfg",
            'feature="candidate-recovery-socket"', "--cfg", 'feature="default"', *external,
            str(output / "private-source/src/lib.rs"), "-o", str(output / "libpayload_private_reference.rlib")],
        "private-observer": [*common, "--crate-name", "payload_metadata_observer", "--extern",
            "trnm_peer_lease=" + str(output / "libpayload_private_reference.rlib"), str(HERE / "metadata_reference.rs"),
            "-o", str(output / "metadata-reference.elf")],
    }
    rows = processes(output / "processes", value["stages"])
    need(list(rows) == list(commands), "Original observer stage roster changed")
    for name, argv in commands.items():
        need(rows[name]["argv"] == argv and rows[name]["wall_limit_seconds"] == 30,
             "Original observer argv/profile/deadline changed")
    for key, filename in (("public_reference", "public-reference.elf"), ("private_reference", "metadata-reference.elf"),
                          ("private_library", "libpayload_private_reference.rlib")):
        row = value[key]
        need(row["path"] == filename, "Original observer artifact was relocated")
        check_identity(output / filename, row)
    return value


def history_names(group):
    if group == "public":
        answer = ["public-sequence", "many-peers-two-directions", "invalid-frames-and-context", "constructor-error-priority"]
        answer += ["journal-permission", "head-permission", "lock-permission", "journal-hardlink", "head-hardlink",
            "lock-hardlink", "journal-replace", "head-replace", "lock-replace", "journal-symlink", "head-symlink",
            "lock-symlink", "directory-permission", "wal-truncated", "wal-mutated", "head-mutated", "valid-prefix-rollback"]
        answer += ["open-" + name for name in ["namespace-zero", "missing-parent", "relative", "root", "empty",
            "dot-parent", "double-slash", "basename-dot", "basename-dotdot", "parent-dotdot", "invalid-utf8", "nul-name",
            "nul-parent", "empty-journal", "bad-journal-mode", "journal-directory", "journal-symlink", "head-collision",
            "head-symlink-collision", "stale-temp", "lock-mode", "lock-directory", "lock-symlink", "parent-mode",
            "parent-strict-mode", "long-basename", "overlong-parent"]]
        return answer
    if group == "boundaries":
        answer = ["directory-entry-bound-" + str(n) for n in (0, 4093, 4094, 4095, 4096, 4097)]
        answer += ["basename-bound-" + str(n) for n in (1, 100, 220, 223, 224, 236, 237, 240, 245, 246, 255, 256)]
        answer += ["closed-store-namespace-mismatch"] + ["closed-store-missing-" + n for n in ("head", "journal", "lock")]
        answer += ["ancestor-" + n for n in ("symlink", "writable", "shared", "owner-readonly", "create-nested", "parent-not-directory")]
        answer += ["simultaneous-owner-" + n for n in ("close-releases", "second-namespace-does-not-evade-lock",
                   "independent-file", "renamed-lock-does-not-authorize-old-owner")]
        return answer
    if group == "crash":
        return [phase + "-" + n for phase in ("open", "admit") for n in ("journal-write", "journal-fsync",
            "directory-fsync", "head-write", "head-fsync", "head-rename", "published-directory-fsync")]
    need(group == "syscalls", "Unknown public observation group")
    phases = [phase + "-" + n for phase in ("open", "admit") for n in ("journal-write", "journal-fsync",
        "directory-fsync", "head-open", "head-write", "head-fsync", "head-metadata", "head-rename",
        "published-head-metadata", "published-directory-fsync")]
    phases += ["open-" + n for n in ("directory-open", "lock-open", "lock-flock", "journal-open", "journal-fchmod", "journal-flock")]
    phases += ["admit-" + n for n in ("journal-metadata", "journal-seek", "journal-read", "head-read")]
    return ["probe", *(phase + "-" + error for phase in phases for error in ("EIO", "EINTR"))]


def source_readback(output, report):
    need(report.get("repository") == str(ROOT) and report.get("output") == str(output)
         and report.get("lineage") == repository_identity(), "Qualification Git/source identity changed")
    need(report.get("environment_guard") == check_environment(os.environ),
         "Current compiler environment differs from the admitted environment")
    need(report.get("compiler_environment") == {name: os.environ[name] for name in
         ("HIA_TOOLCHAIN_ROOT", "HIA_NATIVE_COMPILER", "HIA_NATIVE_COMPILER_SHA256")},
         "Admitted compiler/toolchain locations changed")
    current = source_capture()
    manifest = source_manifest(current)
    need(report.get("source_inputs") == manifest
         and report.get("source_set_sha256") == identity(canonical(manifest))["sha256"],
         "Complete declared source set changed")
    snapshot = output / "native/source-snapshot"
    names = set()
    for directory, dirs, files in os.walk(snapshot, followlinks=False):
        need(all(not (Path(directory) / name).is_symlink() for name in dirs), "Linked snapshot directory")
        for name in files:
            path = Path(directory) / name
            key = path.relative_to(snapshot).as_posix()
            need(key not in names and key in current and capture(path) == current[key],
                 "Missing, added or changed source snapshot member")
            names.add(key)
    need(names == set(current), "Portable snapshot omits a compiler, observer or original source")
    need(report.get("wal_scope_history") == wal_scope_history(),
         "Original per-call WAL definition or actual failed aggregate was omitted")
    return manifest


def maximum_reference(output):
    base = output / "cases/wal-maximum-replay"
    return {name: {"path": str(base / suffix), "identity": file_identity(base / suffix)} for name, suffix in (
        ("report", "report.json"), ("input", "fixtures/maximal-aligned-sorted.input.raw"),
        ("output", "results/maximal-aligned-sorted-replay/output.raw"),
        ("original_output", "processes/original-parser/stdout.raw"))}


def observation_commands(output, report, rows):
    environment = report.get("observation_environment")
    need(type(environment) is dict and set(environment) <= {"PATH", "HOME", "LANG", "LC_ALL", "TZ", "TMPDIR", "PYTHONDONTWRITEBYTECODE"}
         and environment.get("PYTHONDONTWRITEBYTECODE") == "1" and type(environment.get("PATH")) is str
         and all(type(value) is str for value in environment.values()), "Observation environment is unbound")
    files = {}
    def artifact(name):
        path = output / relative(name)
        return {"path": str(path), "identity": file_identity(path)}
    for kind in ("codec", "replay"):
        need(capture(output / "fixtures" / (kind + "-cases.json")) == corpus(kind)[0], "Frozen fixture was changed")
    need(capture(output / "fixtures/priority-cases.json") == canonical(priority_cases()),
         "Additional mixed-error wire fixtures were omitted or replaced")
    for group in GROUPS:
        directory = output / "cases" / group
        bound = report["groups"][group]
        need(bound.get("directory") == "cases/" + group and set(bound) == {"directory", "report"},
             "Observation report relocated or changed its binding")
        check_identity(directory / "report.json", bound["report"])
        files[group] = document(directory / "report.json")
        need(files[group].get("whole_payload_owner_qualified") is False
             and files[group].get("original_service_budget_qualified") is False,
             "An observation claims whole owner or four-second service qualification")
        if group in {"public", "syscalls", "crash", "boundaries"}:
            need(files[group].get("native") == file_identity(output / "native/payload-owner.elf")
                 and files[group].get("original") == file_identity(output / "original/public-reference.elf")
                 and files[group].get("fixtures") == file_identity(output / "fixtures/codec-cases.json")
                 and files[group].get("observer") == file_identity(HERE / "qualification" / (group + ".py")),
                 "Public observer source, fixture or actual image identity changed")
            argv = [sys.executable, "-B", HERE / "qualification" / (group + ".py"), "--native",
                output / "native/payload-owner.elf", "--original", output / "original/public-reference.elf",
                "--fixtures", output / "fixtures/codec-cases.json", "--output", directory]
        elif group == "views":
            argv = [sys.executable, "-B", "-m", "hia.platform.peer_payload.qualification.views", "--image",
                    output / "native/view-fixture.elf", "--output", directory]
        else:
            request = {"output": str(directory)}
            script = group + ".py"
            if group in {"primitives", "runtime"}:
                request.update(codec=artifact("native/metadata_codec.so"), replay=artifact("native/metadata_log.so"),
                    codec_cases=artifact("fixtures/codec-cases.json"), replay_cases=artifact("fixtures/replay-cases.json"),
                    priority_cases=artifact("fixtures/priority-cases.json"))
                request["original" if group == "primitives" else "runtime"] = artifact(
                    "original/metadata-reference.elf" if group == "primitives" else "native/metadata_runtime.so")
            elif group == "allocations":
                request.update(production=artifact("native/metadata_log.so"), observed=artifact("native/metadata-observed.so"),
                               cases=artifact("fixtures/replay-cases.json"))
            else:
                script = "wal.py"
                request.update(replay=artifact("native/metadata_log.so"), index=artifact("native/metadata-index.so"),
                    original=artifact("original/metadata-reference.elf"), partition=group.removeprefix("wal-"),
                    worker={"path": str(HERE / "qualification/wal_worker.py"),
                            "identity": file_identity(HERE / "qualification/wal_worker.py")})
                if group == "wal-maximum-index":
                    request["maximum_replay"] = maximum_reference(output)
            path = output / "requests" / (group + ".json")
            need(document(path) == request, "Actual observation request/ELF/fixture binding changed")
            argv = [sys.executable, "-B", HERE / "qualification" / script, path]
        need(rows[group]["argv"] == list(map(str, argv)) and rows[group]["wall_limit_seconds"] == 240,
             "Actual native group command or original 240-second limit changed")
        command = document(output / "observations" / group / "command.json")
        need(command["environment"] == environment, "An observation used a different environment")
        need(type(rows[group].get("elapsed_ns")) is int and 0 <= rows[group]["elapsed_ns"] <= 243_000_000_000,
             "Observation total elapsed time is not bounded")
    need(set(path.name for path in (output / "cases").iterdir()) == set(GROUPS), "Extra or missing observation group")
    return files


def wal_union(groups):
    from .qualification.wal_fixtures import names, specification
    pairs = [(row["name"], observation["mode"]) for key in ("wal-large", "wal-maximum-replay", "wal-maximum-index")
             for row in groups[key]["cases"] for observation in row["observations"]]
    expected = [(name, mode) for name in names(True)
                for mode in (("replay", "index") if specification(name, True)["observe_index"] else ("replay",))]
    need(len(pairs) == len(set(pairs)) == len(expected) == 23 and set(pairs) == set(expected),
         "Partitioned large WAL observations are not an exact disjoint full union")
    need(sum(groups[key]["original_cases"] for key in ("wal-large", "wal-maximum-replay", "wal-maximum-index")) == 13,
         "The original 13 large WAL comparisons were dropped or inflated")


def production_readback(output, report, *, final=False):
    from . import readback_observations as observed
    output = Path(output).absolute()
    header(report, final=final)
    sources = source_readback(output, report)
    check_identity(output / "native/build.json", report["native_build"])
    build_readback(output / "native", sources)
    check_identity(output / "original/report.json", report["original_build"])
    original = original_observers(output / "original")
    need(report.get("retained_tests") == original["retained_tests"], "Top-level original test count changed")
    rows = processes(output / "observations", report["stages"])
    need(list(rows) == [*GROUPS, *(["integrity-controls"] if final else [])],
         "Actual complete observation/control stage roster changed")
    groups = observation_commands(output, report, rows)
    expected = observed.primitives(output / "cases/primitives", groups["primitives"], output / "original/metadata-reference.elf")
    observed.runtime(output / "cases/runtime", groups["runtime"], expected)
    observed.allocations(output / "cases/allocations", groups["allocations"], expected)
    observed.views(output / "cases/views", groups["views"], capture(output / "native/view-fixture.elf"))
    public, boundary = (observed.public_histories(output / "cases" / key, groups[key], key,
        output / "original/public-reference.elf", output / "native/payload-owner.elf") for key in ("public", "boundaries"))
    observed.syscall_histories(output / "cases/syscalls", groups["syscalls"],
        output / "original/public-reference.elf", output / "native/payload-owner.elf")
    observed.crash_histories(output / "cases/crash", groups["crash"],
        output / "original/public-reference.elf", output / "native/payload-owner.elf")
    for key in ("wal-small", "wal-large", "wal-maximum-replay", "wal-maximum-index"):
        observed.wal(output / "cases" / key, groups[key], partition=key.removeprefix("wal-"),
            replay=output / "native/metadata_log.so", index=output / "native/metadata-index.so",
            original=output / "original/metadata-reference.elf",
            maximum_replay=maximum_reference(output) if key == "wal-maximum-index" else None)
    wal_union(groups)
    summary = {"schema": "trnm.hia.payload-metadata-production-readback.v1", "status": "PASS",
        "public_methods": list(METHODS), "retained_outer_tests": 121, "retained_nested_executions": 2,
        "codec_pairs": 4472, "wire_priority_pairs": 8, "replay_pairs": 840,
        "primitive_native_calls": 5320, "runtime_paired_native_calls": 10640,
        "runtime_boundary_calls": 21, "readonly_queries": 48, "incremental_histories": 8,
        "allocator_shapes": 857, "allocator_abi_calls": 2827, "actual_allocation_failures": 840,
        "allocator_threads": 8, "parallel_abi_calls": 256, "loader_views": 8,
        "public_histories": 48, "public_paired_calls": public, "syscall_histories": 61,
        "syscall_paired_calls": 488, "crash_histories": 14, "real_successful_syscall_cuts": 28,
        "boundary_histories": 32, "boundary_paired_calls": boundary, "small_wal_cases": 11,
        "small_wal_native_calls": 18, "small_wal_original_cases": 9,
        "large_wal_cases": 15, "large_wal_native_calls": 23, "large_wal_original_cases": 13,
        "maximum_authenticated_records": 176602, "same_round_maximum_replay_index_original": True,
        "prior_execution_reused": False, **dict.fromkeys(FALSE, False)}
    if final:
        need(report.get("production_readback") == summary, "Earlier production readback summary was substituted")
    return summary


def control_roster():
    import ast
    parsed = ast.parse(capture(HERE / "test_qualification.py"))
    classes = [node for node in parsed.body if isinstance(node, ast.ClassDef) and node.name == "QualificationControls"]
    need(len(classes) == 1, "Qualification control class missing")
    names = sorted(node.name for node in classes[0].body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"))
    need(len(names) == len(set(names)) and len(names) == 45, "Complete integrity control roster changed")
    return names


def controls_readback(output, row):
    output = Path(output)
    need(row.get("name") == "integrity-controls" and row.get("argv") == [sys.executable, "-B", "-m", "unittest", "-v",
         "hia.platform.peer_payload.test_qualification"] and row.get("wall_limit_seconds") == 30
         and row.get("exit_code") == 0 and row.get("timed_out") is False and row.get("failure") is None
         and row.get("cleanup_errors") == [] and row.get("cleanup_limit_seconds") == 3,
         "Actual integrity control command failed or changed")
    directory = output / "observations/integrity-controls"
    for stream in ("stdout", "stderr"):
        check_identity(directory / (stream + ".raw"), row[stream])
    raw = capture(directory / "stderr.raw").decode()
    names = control_roster()
    observed = re.findall(r"^(test_[a-z0-9_]+) \(hia\.platform\.peer_payload\.test_qualification\.QualificationControls(?:\.\1)?\) \.\.\. ok$", raw, re.M)
    need(observed == names and re.search(r"\nRan " + str(len(names)) + r" tests in [0-9.]+s\n\nOK\n$", raw)
         and not re.search(r"\b(?:skipped|FAIL|ERROR|expected failure|unexpected success)\b", raw),
         "Complete named integrity controls were not actually passed")
    root = output / "integrity-controls"
    need({path.name for path in root.iterdir()} == set(names), "Integrity evidence omitted named controls")
    from .control_readback import actual_controls
    actual = actual_controls(root, output)
    return {"status": "PASS", "tests": len(names), "methods": names, "actual": actual,
            "stdout": file_identity(directory / "stdout.raw"), "stderr": file_identity(directory / "stderr.raw")}


def contents_readback(output, report):
    output = Path(output)
    check_identity(output / "contents.json", report.get("contents"))
    entries = document(output / "contents.json")
    need(report.get("retained_entries") == len(entries) and entries == inventory(output),
         "Complete evidence member set/bytes/modes changed")
    return entries


def readback(output):
    output = Path(output).absolute()
    report = document(output / "report.json")
    summary = production_readback(output, report, final=True)
    need(report.get("complete_original_tests_preserved") is True, "Complete original gate was not retained")
    controls = controls_readback(output, report["stages"][-1])
    need(report.get("integrity_controls") == controls, "Integrity result differs from raw actual controls")
    entries = contents_readback(output, report)
    return {"schema": SCHEMA, "status": "PASS", "elapsed_ns": report["elapsed_ns"],
            "retained_entries": len(entries), "source_set_sha256": report["source_set_sha256"],
            "source_inputs": len(report["source_inputs"]), "lineage": report["lineage"],
            "report": file_identity(output / "report.json"), "production": summary, "integrity_controls": controls}
