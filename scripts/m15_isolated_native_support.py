#!/usr/bin/env python3
"""Exact inputs for the separately scheduled, rootless M15 native fixture.

All helpers are preparation code, not production provisioning. They neither
create a namespace nor execute a Node. The real fixture still validates its
own fixed /etc inputs, static ELF, same-FD execution and independent Claim.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import stat
import struct
import sys

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location(
    "m15_exact_build_support", Path(__file__).with_name("m15_native_build_support.py"))
support = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(support)

CASE = "release_owner::native_consumer_tests::isolated_fixed_root_static_node_claim_refresh_and_revocation"
TOOLS = {"python", "unshare", "mount", "setpriv", "newuidmap", "newgidmap", "chroot"}
NAMESPACES = ("user", "mnt", "pid")
TOOL_FIELDS = {"path", "sha256", "bytes", "uid", "gid", "mode"}


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def json_input(path, expected, maximum=16 * 1024**2):
    raw = support.read(path, maximum)
    if support.sha(raw) != expected:
        raise ValueError("explicit input digest differs")
    return json.loads(raw, object_pairs_hook=unique), raw


def pinned_file(entry, maximum=256 * 1024**2):
    if set(entry) != TOOL_FIELDS:
        raise ValueError("complete tool/file identity required")
    path = Path(entry["path"])
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("tool/source must name its explicit real absolute file")
    actual = support.fingerprint(path, maximum)
    info = os.stat(path, follow_symlinks=False)
    if (actual["sha256"], actual["bytes"], info.st_uid, info.st_gid,
            stat.S_IMODE(info.st_mode)) != (
            entry["sha256"], entry["bytes"], entry["uid"], entry["gid"], entry["mode"]):
        raise ValueError("actual tool/file identity differs")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("single-linked regular tool/source required")
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("namespace setup tools must retain protected host custody")
    return actual


def namespaces():
    return {name: os.stat("/proc/self/ns/" + name).st_ino for name in NAMESPACES}


def subordinate(spec, kind, outer):
    if set(spec) != {"name", "start", "count", "source_sha256"}:
        raise ValueError("exact subordinate allocation contract required")
    if type(spec["start"]) is not int or type(spec["count"]) is not int:
        raise ValueError("subordinate ranges must be integers")
    if not 0 < spec["start"] < 2**32 - 2000 or spec["count"] != 2000:
        raise ValueError("explicit separate runtime/service UID range required")
    if spec["start"] <= outer < spec["start"] + spec["count"]:
        raise ValueError("subordinate allocation overlaps the outer owner")
    actual_name = pwd.getpwuid(os.getuid()).pw_name
    if spec["name"] not in {actual_name, str(os.getuid())}:
        raise ValueError("subordinate allocation belongs to another caller")
    path = Path("/etc/subuid" if kind == "uid" else "/etc/subgid")
    info = os.stat(path, follow_symlinks=False)
    if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
        raise ValueError("subordinate mapping file lacks protected host custody")
    raw = support.read(path, 1024**2)
    if support.sha(raw) != spec["source_sha256"]:
        raise ValueError("reviewed subordinate mapping changed")
    matches = []
    for line in raw.decode("ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        name, start, count = line.split(":")
        if name == spec["name"]:
            matches.append((int(start), int(count)))
    if not any(start <= spec["start"] and spec["start"] + 2000 <= start + count
               for start, count in matches):
        raise ValueError("required independent UID/GID map is not allocated")
    return {"path": str(path), "sha256": support.sha(raw), "selected": spec}


def elf_dependencies(path):
    """Inspect only bounded declared ELF bytes; never execute ldd or the input."""
    raw = support.read(path, 256 * 1024**2)
    if len(raw) < 64 or raw[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("setup helper must be little-endian ELF64")
    if struct.unpack_from("<H", raw, 16)[0] not in {2, 3}:
        raise ValueError("helper must be executable or shared ELF")
    if struct.unpack_from("<H", raw, 18)[0] != 62:
        raise ValueError("setup helper ELF is not x86_64")
    offset = struct.unpack_from("<Q", raw, 32)[0]
    stride, count = struct.unpack_from("<HH", raw, 54)
    if stride != 56 or not 0 < count <= 4096 or offset + stride * count > len(raw):
        raise ValueError("invalid helper program-header bound")
    loads, dynamic, interpreter = [], None, None
    for index in range(count):
        entry = struct.unpack_from("<IIQQQQQQ", raw, offset + index * stride)
        kind, _, start, address, _, size, memory, _ = entry
        if start + size > len(raw) or size > memory:
            raise ValueError("helper segment escapes exact file")
        if kind == 1:
            loads.append((address, address + size, start))
        elif kind == 2:
            if dynamic is not None or size > 1024**2 or size % 16:
                raise ValueError("ambiguous/unbounded helper dynamic table")
            dynamic = (start, size)
        elif kind == 3:
            if interpreter is not None or not 2 <= size <= 4096:
                raise ValueError("ambiguous/unbounded helper interpreter")
            value = raw[start:start + size]
            if value[-1:] != b"\0" or b"\0" in value[:-1]:
                raise ValueError("invalid helper interpreter")
            interpreter = value[:-1].decode("ascii")
    if dynamic is None:
        return {"interpreter": interpreter, "needed": [], "soname": None}
    entries, terminated = [], False
    for position in range(dynamic[0], sum(dynamic), 16):
        tag, value = struct.unpack_from("<qQ", raw, position)
        if tag == 0:
            terminated = True
            break
        if tag in {15, 29}:
            raise ValueError("helper RPATH/RUNPATH is not admitted")
        entries.append((tag, value))
    if not terminated:
        raise ValueError("unterminated helper dynamic table")
    tables = [value for tag, value in entries if tag == 5]
    sizes = [value for tag, value in entries if tag == 10]
    if len(tables) != 1 or len(sizes) != 1 or not 0 < sizes[0] <= 16 * 1024**2:
        raise ValueError("exact helper string table required")
    matching = [(start + tables[0] - low, sizes[0]) for low, high, start in loads
                if low <= tables[0] and tables[0] + sizes[0] <= high]
    if len(matching) != 1:
        raise ValueError("ambiguous helper string-table mapping")
    start, size = matching[0]
    strings = raw[start:start + size]

    def name(offset):
        if offset >= len(strings):
            raise ValueError("helper string offset outside table")
        end = strings.find(b"\0", offset)
        if end < 0:
            raise ValueError("unterminated helper dependency name")
        value = strings[offset:end].decode("ascii")
        if not re.fullmatch(r"[A-Za-z0-9._+-]+", value):
            raise ValueError("helper dependency is not a single library name")
        return value

    needed = [name(value) for tag, value in entries if tag == 1]
    sonames = [name(value) for tag, value in entries if tag == 14]
    if len(needed) != len(set(needed)) or len(sonames) > 1:
        raise ValueError("ambiguous helper dependency roster")
    return {"interpreter": interpreter, "needed": needed, "soname": next(iter(sonames), None)}


def destination(value):
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ValueError("exact absolute namespace destination required")
    if not (value.startswith("/lib/") or value.startswith("/lib64/")
            or value.startswith("/usr/lib/")):
        raise ValueError("helper dependency destination is outside fixed library roots")
    return path


def helper_runtime(tools):
    runtime = tools["setpriv_runtime"]
    if set(runtime) != {"interpreter", "libraries"} or not isinstance(runtime["libraries"], list):
        raise ValueError("explicit setpriv runtime closure required")
    if len(runtime["libraries"]) > 32:
        raise ValueError("helper runtime closure too large")
    main = elf_dependencies(tools["tools"]["setpriv"]["path"])
    entries = list(runtime["libraries"])
    if runtime["interpreter"] is not None:
        entries.append(runtime["interpreter"])
    if main["interpreter"] is None:
        if entries or main["needed"]:
            raise ValueError("static setup helper has unexpected loader inputs")
    elif runtime["interpreter"] is None:
        raise ValueError("setup helper interpreter was not pinned")
    elif runtime["interpreter"]["destination"] != main["interpreter"]:
        raise ValueError("actual PT_INTERP differs from the pinned destination")
    files, by_name = {}, {}
    for entry in entries:
        if set(entry) != {"source", "destination"}:
            raise ValueError("helper runtime file contract")
        target = str(destination(entry["destination"]))
        pinned_file(entry["source"])
        dependency = elf_dependencies(entry["source"]["path"])
        if dependency["interpreter"] not in {None, main["interpreter"]}:
            raise ValueError("library names a different, unpinned helper interpreter")
        old = files.get(target)
        if old is not None and old != entry:
            raise ValueError("two helper inputs target the same namespace path")
        files[target] = entry
        name = dependency["soname"]
        if name is None:
            raise ValueError("pinned runtime dependency has no SONAME")
        if name is not None:
            if name in by_name and by_name[name]["entry"] != entry:
                raise ValueError("ambiguous helper SONAME")
            by_name[name] = {"entry": entry, "dependencies": dependency["needed"]}
    pending, seen = list(main["needed"]), set()
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        if name not in by_name:
            raise ValueError("unresolved pinned helper DT_NEEDED: " + name)
        seen.add(name)
        pending.extend(by_name[name]["dependencies"])
    for name, item in by_name.items():
        if name not in seen and item["entry"] != runtime["interpreter"]:
            raise ValueError("unused helper library is not part of the actual closure")
    return {"elf": main, "files": [files[key] for key in sorted(files)],
            "needed_closure": sorted(seen)}


def tools_input(path, expected):
    value, raw = json_input(path, expected)
    if set(value) != {"schema", "tools", "subuid", "subgid", "setpriv_runtime",
                      "unshare_version", "mount_version", "setpriv_version", "chroot_version", "python_version"}:
        raise ValueError("unknown/incomplete isolated-native tool inputs")
    if value["schema"] != "trnm-m15-isolated-native-tools-v1" or set(value["tools"]) != TOOLS:
        raise ValueError("exact isolated-native tool roster required")
    checked = {name: pinned_file(entry) for name, entry in value["tools"].items()}
    for name in ("newuidmap", "newgidmap"):
        if Path(value["tools"][name]["path"]).name != name:
            raise ValueError("mapping helper basename must be preserved")
    if Path(value["tools"]["newuidmap"]["path"]).parent != Path(value["tools"]["newgidmap"]["path"]).parent:
        raise ValueError("explicit single mapping-helper search directory required")
    mappings = {"uid": subordinate(value["subuid"], "uid", os.getuid()),
                "gid": subordinate(value["subgid"], "gid", os.getgid())}
    return value, raw, {"files": checked, "mappings": mappings, "setpriv": helper_runtime(value)}


def artifact_input(path, expected, head, tree):
    value, raw = json_input(path, expected, 32 * 1024**2)
    fields = {"schema", "source", "node", "tests", "build_input", "test_selector",
              "command_receipts", "rust_tests_executed", "independent_deployment_qualified"}
    if set(value) != fields or value["schema"] != "trnm-m15-static-native-artifacts-v1":
        raise ValueError("actual static builder artifact schema required")
    if value["source"] != {"head": head, "tree": tree} or value["test_selector"] != CASE:
        raise ValueError("actual artifact source/selector does not match the reviewed scope")
    if value["rust_tests_executed"] is not False or value["independent_deployment_qualified"] is not False:
        raise ValueError("artifact compilation must not masquerade as execution/deployment")
    for name in ("node", "tests", "build_input"):
        record = value[name]
        bound = 512 * 1024**2 if name == "node" else 4 * 1024**3 if name == "tests" else 4 * 1024**2
        if not Path(record["path"]).is_absolute():
            raise ValueError("absolute retained artifact path required")
        actual = support.fingerprint(record["path"], bound)
        if any(actual[key] != record[key] for key in ("sha256", "bytes", "identity")):
            raise ValueError("retained actual build artifact changed")
    support.elf_static(value["node"]["path"], 512 * 1024**2)
    support.elf_static(value["tests"]["path"], 4 * 1024**3)
    build = json.loads(support.read(value["build_input"]["path"], 4 * 1024**2), object_pairs_hook=unique)
    if (build["source_commit"], build["source_tree"], build["program"],
            bytes(build["program_sha256"]).hex(), build["program_bytes"]) != (
            head, tree, "/m15/bin/node", value["node"]["sha256"], value["node"]["bytes"]):
        raise ValueError("build DTO does not bind this exact Node/source")
    return value, raw


def namespace_view(record, maximum):
    """UID/GID are translated by this new user namespace; all other held
    identity fields and exact bytes must equal the verified outer observation.
    This is a fixture-copy check, never the product's fixed-root custody check.
    """
    actual = support.fingerprint(record["path"], maximum)
    indices = (0, 1, 2, 3, 6, 7, 8)
    if (actual["sha256"], actual["bytes"]) != (record["sha256"], record["bytes"]):
        raise ValueError("namespace input bytes changed")
    if any(actual["identity"][index] != record["identity"][index] for index in indices):
        raise ValueError("namespace input object changed")
    return actual
