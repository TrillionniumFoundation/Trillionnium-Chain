"""Bind finite State and preparation CI evidence to actual source and raw processes.

This reader never executes a native case or substitutes for a qualification.
Original test binaries and all process streams remain in the CI artifact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import tarfile
import traceback

from hia.tools import qualify_foundation_ci as base
from hia.tools import qualify_genesis_ci as transfer

ROOT = base.ROOT
SCHEMA = "trnm.hia.execution-ci-binding.v1"
PACKAGE = "trnm.hia.execution-ci-evidence.v1"
STAGES = ("execution-state", "prepare-semantic", "prepare-physical", "prepare-original")
require, read, write_new = base.require, base.read, base.write_new
identity, object_hash, lineage = base.identity, base.object_hash, base.lineage


def equal(left, right):
    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == \
        json.dumps(right, sort_keys=True, separators=(",", ":"), allow_nan=False)


def bytes_id(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def observations(root, stage):
    return root / ("hia-execution-state-observations" if stage == "execution-state"
                   else "hia-prepare-observations")


def source_maps(repository, component):
    if component == "state":
        from hia.platform.execution_state import rust_oracle as oracle
    else:
        from hia.platform.execution_prepare import rust_oracle as oracle
    sources = oracle.complete_source_manifest(repository)
    originals = oracle.original_manifest(repository)
    return sources, originals


def positive_test(raw, name):
    text = raw.decode("utf-8")
    require(re.search(r"(?m)^running 1 test\r?$", text) is not None
            and re.search(r"(?m)^test " + re.escape(name) + r" \.\.\.", text) is not None
            and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", text) is not None,
            "Exact original test was not positively executed: " + name)


def original_stages(directory, report, labels):
    stages = report.get("stages")
    require(isinstance(stages, list) and [row.get("stage") for row in stages] == list(labels),
            "Actual original stage inventory differs")
    result = {}
    for row in stages:
        name = row["stage"]
        path = directory / name
        require(equal(read(path / "receipt.json"), row), "Original receipt summary differs: " + name)
        require(row.get("status") == "PASS" and type(row.get("exit_code")) is int
                and row["exit_code"] == 0 and row.get("timed_out") is False
                and row.get("launch_error") is None and row.get("cleanup_error") is None
                and row.get("output_files_closed") is True
                and row.get("cleanup_limit_seconds") == 10
                and type(row.get("elapsed_ns")) is int and row["elapsed_ns"] > 0,
                "Original subprocess did not settle successfully: " + name)
        require(row["elapsed_ns"] == row["finished_monotonic_ns"] - row["started_monotonic_ns"],
                "Original elapsed accounting differs")
        for channel in ("stdout", "stderr"):
            require(identity(path / (channel + ".raw")) == row.get(channel),
                    "Original raw stream differs: " + name + "/" + channel)
        result[name] = (row, base.regular(path / "stdout.raw").read_bytes())
    return result


def composed_bytes(repository, relative):
    """Read the exact declared function bytes without importing or running Core."""
    manifest = read(repository / "hia/components.json")
    require(set(manifest) == {"schema", "includes"}
            and manifest["schema"] == "trnm.hia.component-includes.v1",
            "Canonical component manifest differs")
    cache = {}

    def component(name, ancestry):
        path = base.member_path(name)
        require(name.startswith(("src/", "platform/", "storage/")) and name.endswith(".hepta")
                and name not in ancestry, "Noncanonical or cyclic declared component")
        raw = base.regular(repository / "hia" / path).read_bytes()
        declared = re.findall(rb"(?m)^fn ([A-Za-z_][A-Za-z_0-9]*)\(", raw)
        matches = list(re.finditer(
            rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)", raw))
        own = {match.group(1).decode(): match.group(0) for match in matches}
        require(len(declared) == len(set(declared)) == len(matches) == len(own)
                and set(declared) == {name.encode() for name in own},
                "Ambiguous declared HIA function boundaries")
        names, blocks = set(own), [raw.rstrip() + b"\n"]
        rows = manifest["includes"].get(name, [])
        require(isinstance(rows, list), "Malformed declared include roster")
        for row in rows:
            require(isinstance(row, dict) and set(row) == {"source", "functions"}
                    and isinstance(row["functions"], list) and row["functions"],
                    "Malformed declared include")
            require(row["source"] not in (*ancestry, name), "Cyclic declared HIA component")
            if row["source"] not in cache:
                _, cache[row["source"]] = component(row["source"], (*ancestry, name))
            available = cache[row["source"]]
            for selected in row["functions"]:
                require(isinstance(selected, str) and selected in available and selected not in names,
                        "Missing or duplicate declared HIA function")
                names.add(selected)
                blocks.append(available[selected].rstrip() + b"\n")
        return b"".join(blocks), own

    return component(relative, ())[0]


def native_build(directory, repository, component):
    """Rebind every actual compiler/emitter input and emitted byte image."""
    if component == "state":
        from hia.platform.execution_state import rust_oracle as oracle
        built = read(directory / "build.json")
        sources = oracle.validate_source_bindings(repository, {
            "schema": oracle.COMP_SCHEMA, "status": "PASS", "build": built})
        _, composed = oracle.complete_sources(repository)
        images = {name: base.regular(directory / file).read_bytes() for name, file in (
            ("owner", "owner.flat"), ("root", "root.flat"),
            ("linux_emitter", "linux_emitter.elf"), ("executable", "owner.elf"))}
        require(built["images"] == {key: bytes_id(images[key]) for key in
                                    ("owner", "root", "linux_emitter")}
                and built["executable"] == bytes_id(images["executable"]),
                "Actual State image identities differ")
        require(images["executable"].startswith(b"\x7fELF")
                and images["executable"].endswith(images["owner"] + images["root"]),
                "State ELF does not contain its exact private images")
        joined = struct.pack("<QQ", len(images["owner"]), len(images["root"])) + \
            images["owner"] + images["root"]
        expectations = [(name, composed[name], images[name], built["compiler_sha256"])
                        for name in ("owner", "root", "linux_emitter")]
        expectations.append(("emit", joined, images["executable"],
                             bytes_id(images["linux_emitter"])["sha256"]))
        stage_names = ["compile-owner", "compile-root", "compile-linux_emitter", "emit-owner"]
    else:
        from hia.platform.execution_prepare import rust_oracle as oracle
        built = read(directory / "build.json")
        sources = oracle.validate_source_bindings(repository, {
            "schema": oracle.COMP_SCHEMA, "status": "PASS", "build": built})
        images = {key: base.regular(directory / (key + ".flat")).read_bytes()
                  for key in ("policy", "settings", "pnx", "sha", "ed")}
        writer = base.regular(directory / "emitter.elf").read_bytes()
        prefix = base.regular(directory / "elf-prefix.raw").read_bytes()
        executable = base.regular(directory / "legacy-prepare-owner.elf").read_bytes()
        require(built["images"] == {key: bytes_id(raw) for key, raw in images.items()}
                and built["emitter"] == bytes_id(writer) and built["elf_prefix"] == bytes_id(prefix)
                and {key: built["executable"][key] for key in ("bytes", "sha256")} == bytes_id(executable)
                and executable == prefix + b"".join(images.values())
                and executable.startswith(b"\x7fELF"),
                "Preparation ELF or exact linked images differ")
        composed = {"policy": base.regular(repository /
                    "hia/platform/execution_prepare/owner_policy.hepta").read_bytes()}
        for key, relative in (("settings", "src/node/settings_development.hepta"),
                              ("pnx", "src/protocol/pnx1.hepta"),
                              ("sha", "src/crypto/sha256.hepta"),
                              ("ed", "src/crypto/ed25519_verify.hepta")):
            composed[key] = composed_bytes(repository, relative)
        composed["emitter"] = base.regular(repository /
            "hia/platform/execution_prepare/linux_emitter.hepta").read_bytes()
        expectations = [(key, composed[key], images[key], built["compiler_sha256"]) for key in images]
        expectations.extend([
            ("emitter", composed["emitter"], writer, built["compiler_sha256"]),
            ("prefix", struct.pack("<5Q", *(len(raw) for raw in images.values())),
             prefix, bytes_id(writer)["sha256"])])
        stage_names = ["compile-" + key for key in images] + ["compile-emitter", "emit-prefix"]
    require(built.get("compiler_qualification_binding") == read(repository /
            "hia/qualification/compiler-binding.json")
            and built.get("toolchain") == read(repository / "hia/toolchain.lock.json")
            and built.get("compiler_sha256") == built["compiler_qualification_binding"]["compiler_sha256"],
            "Native compiler qualification or toolchain pin differs")
    require(built.get("original_sources") == oracle.original_manifest(repository),
            "Build original source closure differs")
    stages = built.get("stages")
    require(isinstance(stages, list) and [row.get("stage") for row in stages] == stage_names,
            "Actual native compiler stage inventory differs")
    for stage, (_, payload, emitted, executable_hash) in zip(stages, expectations, strict=True):
        require(stage.get("exit_code") == 0 and stage.get("timed_out") is False
                and stage.get("cleanup") is None and stage.get("stderr_hex") == ""
                and stage.get("executable_sha256") == executable_hash
                and {"bytes": stage.get("input_bytes"), "sha256": stage.get("input_sha256")} == bytes_id(payload)
                and {"bytes": stage.get("output_bytes"), "sha256": stage.get("output_sha256")} == bytes_id(emitted),
                "Actual native compiler input, output or termination differs")
    return built, sources


def captured_file(source, destination, expected):
    require(identity(source) == expected, "Captured evidence input differs: " + str(source))
    destination.parent.mkdir(parents=True, exist_ok=True)
    with base.regular(source).open("rb") as incoming, destination.open("xb") as outgoing:
        shutil.copyfileobj(incoming, outgoing, 1 << 20)
    require(identity(source) == identity(destination) == expected,
            "Evidence changed during independent capture")


def serde_binding(directory, report, rows, repository, component, *, capture):
    """Bind locked registry bytes to the actual Cargo lib artifact."""
    serde = report["serde_json_source" if component == "state" else "serde_json"]
    metadata_label = "cargo-original-metadata" if component == "state" else "cargo-metadata"
    metadata = json.loads(rows[metadata_label][1], object_pairs_hook=base.unique_object)
    package = serde["package"]
    selected = [row for row in metadata["packages"] if row.get("name") == "serde_json"]
    require(selected == [package], "Actual Cargo metadata package differs")
    nodes = [row for row in metadata["resolve"]["nodes"] if row.get("id") == package["id"]]
    require(nodes == [serde["resolve_node"]], "Actual resolved serde graph differs")
    events = [json.loads(line, object_pairs_hook=base.unique_object)
              for line in rows["cargo-original-test-build"][1].splitlines() if line.startswith(b"{")]
    artifacts = [row for row in events if row.get("reason") == "compiler-artifact"
                 and row.get("target", {}).get("name") == "serde_json"
                 and row.get("target", {}).get("kind") == ["lib"]]
    require(len(artifacts) == 1 and artifacts[0].get("package_id") == package["id"]
            and set(artifacts[0].get("features", [])) == {"default", "std"},
            "Actual compiled serde lib differs from locked metadata")
    claim = report.get("serde_json_artifact")
    require(isinstance(claim, dict), "Actual serde library binding is absent")
    if component == "prepare":
        require(equal(read(directory / "serde-library-before.json"), claim)
                and equal(claim.get("compiler_artifact"), artifacts[0])
                and claim.get("package_id") == package["id"]
                and claim.get("features") == artifacts[0]["features"]
                and claim.get("target_kind_filter") == ["lib"]
                and claim.get("custom_build_is_not_a_library") is True
                and claim.get("independent_directory") == "serde-library",
                "Independent actual serde library binding differs")
        files = claim.get("files")
        require(isinstance(files, dict) and len(files) == len(artifacts[0].get("filenames", []))
                and {entry["path"] for entry in files.values()} == set(artifacts[0]["filenames"]),
                "Actual serde library file inventory differs")
        for name, entry in files.items():
            require(Path(name).name == name and Path(entry["path"]).name == name
                    and identity(directory / "serde-library" / name) ==
                        {key: entry[key] for key in ("bytes", "sha256")},
                    "Independent actual serde library bytes differ")
    else:
        require(equal(claim, artifacts[0]), "Recorded serde library artifact differs")
    require(artifacts[0]["target"].get("src_path") ==
            str(Path(serde["crate_directory"]) / "src/lib.rs"),
            "Actual compiled serde source path differs")
    import tomllib
    lock = tomllib.loads(base.regular(repository / "trillionnium/Cargo.lock").read_text())
    locked = [row for row in lock["package"] if row.get("name") == "serde_json"]
    require(locked == [serde["locked_package"]] and locked[0]["version"] == "1.0.149"
            and locked[0]["source"] == package["source"],
            "Actual serde package differs from the committed Cargo lock")
    archive = serde["registry_archive"]
    require(identity(Path(archive["path"])) == {key: archive[key] for key in ("bytes", "sha256")}
            and archive["sha256"] == locked[0]["checksum"],
            "Actual dependency archive differs from its Cargo lock checksum")
    crate = Path(serde["crate_directory"])
    found = {}
    for path in sorted(crate.rglob("*")):
        require(not path.is_symlink(), "Symbolic actual dependency source")
        if path.is_file():
            found[path.relative_to(crate).as_posix()] = identity(path)
        else:
            require(path.is_dir(), "Special actual dependency source")
    require(found == serde["crate_sources"]
            and object_hash(found) == serde["crate_source_set_sha256"],
            "Actual dependency sources changed after compilation")
    if component == "prepare":
        require(claim.get("source") == str(crate / "src/lib.rs")
                and claim.get("source_identity") == found["src/lib.rs"],
                "Captured serde library source identity differs")
    if capture:
        target = directory / "dependency-snapshot"
        target.mkdir(mode=0o700)
        captured_file(Path(archive["path"]), target / "serde_json.crate",
                      {key: archive[key] for key in ("bytes", "sha256")})
        for name, expected in found.items():
            captured_file(crate / base.member_path(name), target / "serde-json" / name, expected)
    return {"package": package["id"], "locked_package": locked[0],
            "compiler_artifact": artifacts[0], "source_files": len(found),
            "source_set_sha256": object_hash(found),
            "registry_archive": {key: archive[key] for key in ("bytes", "sha256")}}


def original_adaptation(directory, repository, oracle, originals, *, capture):
    isolated = directory / ("isolated-source" if oracle.OWNED.endswith("execution_state") else "isolated")
    actual = base.regular(isolated / oracle.STORE).read_bytes()
    production = base.regular(repository / oracle.STORE).read_bytes()
    hook = base.regular(repository / oracle.OWNED / "rust_reference.rs").read_bytes()
    require(actual == production + oracle.DECLARATION
            and base.regular(isolated / Path(oracle.STORE).parent / oracle.HOOK).read_bytes() == hook,
            "Original production prefix or sole private test hook differs")
    names = {oracle.STORE: bytes_id(actual),
             (Path(oracle.STORE).parent / oracle.HOOK).as_posix(): bytes_id(hook),
             "trillionnium/Cargo.lock": originals["trillionnium/Cargo.lock"]}
    names.update({name: expected for name, expected in originals.items()
                  if Path(name).parts[0] not in ("trillionnium", "config", "formal")})
    if capture:
        for name, expected in names.items():
            captured_file(isolated / name, directory / "source-capture" / name, expected)
    return names


def original_binary(directory, report, rows, filename, expected_target=None):
    binary = directory / filename
    expected = report.get("original_test_binary") if filename == "original-test-binary" else report.get("actual_binary")
    require(isinstance(expected, dict), "Independent actual original binary is absent")
    expected_identity = {key: expected[key] for key in ("bytes", "sha256")}
    require(identity(binary) == expected_identity, "Independent actual original binary bytes differ")
    metadata = base.regular(binary).stat()
    require(metadata.st_nlink == 1 and stat.S_IMODE(metadata.st_mode) ==
            (0o500 if filename == "original-test-binary" else 0o700),
            "Original test executable mode or independent copy differs")
    events = [json.loads(line, object_pairs_hook=base.unique_object)
              for line in rows["cargo-original-test-build"][1].splitlines() if line.startswith(b"{")]
    candidates = [row for row in events if row.get("reason") == "compiler-artifact"
                  and row.get("target", {}).get("name") == "trnm_mvcc_fee"
                  and row.get("profile", {}).get("test") is True and row.get("executable")]
    require(len(candidates) == 1, "Actual compiled M06 test executable is not unique")
    if expected_target is not None:
        require(expected_target.resolve(strict=True) == expected_target
                and expected_target in Path(candidates[0]["executable"]).parents,
                "Actual compiled M06 executable escaped its CI target")
    if filename == "original-test-binary":
        before = read(directory / "original-binary-before.json")
        require(before.get("source") == candidates[0]["executable"]
                and before.get("retained") == str(binary)
                and before.get("independent_copy_before_all_tests") is True
                and before.get("mode") == 0o500
                and {key: before[key] for key in ("bytes", "sha256")} == expected_identity,
                "Original State independent-copy observation differs")
    return expected_identity


def original_tools(directory, report, rows, component, expected_target=None):
    """Verify the actually invoked absolute compiler/Cargo and source-manifest arguments."""
    isolated = directory / ("isolated-source" if component == "state" else "isolated")
    if component == "state":
        tools = report.get("actual_rust_tools")
        require(isinstance(tools, dict) and set(tools) == {"rustc", "cargo", "rustdoc"},
                "Actual State compiler/Cargo/rustdoc identities are missing")
        selected, bound_label = "rustc", "rustc-selected-version"
        version = report.get("compiler")
        for fence in report["source_fences"][-2:]:
            require(fence["observations"].get("actual_rust_tools") ==
                    {"status": "MATCH", "tools": tools}, "State compiler tools changed during execution")
    else:
        binding = report.get("original_toolchain")
        require(isinstance(binding, dict)
                and binding.get("schema") == "trnm.hia.prepare-original-toolchain.v1"
                and equal(read(directory / "original-toolchain-before.json"), binding),
                "Actual preparation compiler binding differs")
        tools = {"rustc": binding["compiler_executable"], "cargo": binding["cargo_executable"]}
        selected, bound_label = binding["selected_rustc"], "rustc-bound-version"
        require(Path(selected).is_absolute(), "Selected original compiler path is not absolute")
        version = binding["rustc_version"]
    sysroot = Path(rows["rustc-sysroot"][1].decode().strip())
    require(sysroot.is_absolute() and sysroot.resolve(strict=True) == sysroot,
            "Actual compiler sysroot is not canonical")
    if component == "prepare":
        require(binding["sysroot"] == str(sysroot), "Reported compiler sysroot differs")
    for name, item in tools.items():
        path = Path(item["path"])
        require(path == (sysroot / "bin" / name).resolve(strict=True)
                and path.is_absolute() and path.resolve(strict=True) == path
                and identity(path) == {key: item[key] for key in ("bytes", "sha256")},
                "Actual absolute compiler tool bytes differ: " + name)
    require(rows["rustc-version"][0]["argv"] == [selected, "-Vv"]
            and rows["rustc-sysroot"][0]["argv"] == [selected, "--print", "sysroot"]
            and rows[bound_label][0]["argv"] == [tools["rustc"]["path"], "-Vv"]
            and rows["rustc-version"][1] == rows[bound_label][1] == version.encode()
            and re.search(r"(?m)^host: x86_64-unknown-linux-gnu$", version) is not None,
            "Actual original compiler invocation/version/target differs")
    for label in ("rustc-version", "rustc-sysroot", bound_label):
        require(rows[label][0]["stderr"]["bytes"] == 0, "Unexpected compiler diagnostic")
    cargo = tools["cargo"]["path"]
    manifest = str(isolated / "trillionnium/Cargo.toml")
    if component == "state":
        metadata = [cargo, "metadata", "--locked", "--format-version=1", "--filter-platform",
                    "x86_64-unknown-linux-gnu", "--manifest-path", manifest]
        metadata_label = "cargo-original-metadata"
        build = [cargo, "test", "--locked", "--manifest-path", manifest, "-p", "trnm-mvcc-fee",
                 "--lib", "--no-run", "--message-format=json", "--target-dir"]
        argv = rows["cargo-original-test-build"][0]["argv"]
        require(len(argv) == len(build) + 1 and argv[:-1] == build
                and Path(argv[-1]).is_absolute(), "Actual original State Cargo build arguments differ")
        if expected_target is not None:
            require(argv[-1] == str(expected_target), "State Cargo target differs from the CI command")
    else:
        metadata = [cargo, "metadata", "--locked", "--format-version", "1", "--manifest-path", manifest]
        metadata_label = "cargo-metadata"
        build = [cargo, "test", "--locked", "--manifest-path", manifest, "-p", "trnm-mvcc-fee",
                 "--lib", "--no-run", "--message-format=json"]
        require(rows["cargo-original-test-build"][0]["argv"] == build,
                "Actual original preparation Cargo build arguments differ")
        if expected_target is not None:
            require(all(expected_target in Path(row["path"]).parents
                        for row in report["serde_json_artifact"]["files"].values()),
                    "Actual serde library escaped its CI Cargo target")
    require(rows[metadata_label][0]["argv"] == metadata
            and all(row[0].get("cwd") == str(isolated) for row in rows.values()),
            "Actual original Cargo metadata arguments or working directory differ")
    return tools


def private_journal(path, expected_calls, expected_counter):
    """Recheck complete direct native-call bytes and explicit private fixture writes."""
    pending = None
    completed = fixtures = records = 0
    previous = bytes(65536)
    with base.regular(path).open("rb") as stream:
        for raw in stream:
            require(len(raw) <= 1 << 20, "Oversized private-call journal record")
            row = json.loads(raw, object_pairs_hook=base.unique_object)
            records += 1
            kind = row.get("kind")
            if kind == "native-call-start":
                require(pending is None and row.get("index") == completed + 1
                        and type(row.get("index")) is int,
                        "Missing, repeated or reordered actual native-call start")
                body = bytes.fromhex(row["input_hex"])
                before = bytes.fromhex(row["heap_before_hex"])
                require(before == previous and row.get("input") == bytes_id(body)
                        and row.get("heap_before") == bytes_id(before)
                        and len(before) == 65536 and row.get("output_capacity") in (63, 64, 512)
                        and row.get("heap_capacity") in (4095, 65536)
                        and bytes.fromhex(row["output_before_hex"]) == b"\x5b" * row["output_capacity"],
                        "Private native-call input, capacities or prior heap bytes differ")
                pending = row
            elif kind == "native-call-complete":
                require(pending is not None and
                        all(row.get(key) == value for key, value in pending.items() if key != "kind"),
                        "Actual native completion does not match its start")
                output = bytes.fromhex(row["output_hex"])
                after = bytes.fromhex(row["heap_after_hex"])
                require(row.get("input_after_hex") == pending["input_hex"]
                        and row.get("output") == bytes_id(output)
                        and row.get("heap_after") == bytes_id(after)
                        and len(after) == 65536 and len(output) == pending["output_capacity"]
                        and type(row.get("return")) is int and row["return"] in (1, 2, 3, 4, 6),
                        "Actual complete native output, immutable input or private heap differs")
                if row["return"] == 6:
                    require(output == bytes.fromhex(pending["output_before_hex"]) and after == previous,
                            "Rejected private ABI call changed output or heap")
                if row["return"] in (1, 4):
                    require(len(output) >= 64 and output[:8] == b"SVPR0001",
                            "Actual native call lacks a complete response header")
                    extent = 64 + struct.unpack_from("<Q", output, 40)[0]
                    require(extent <= len(output) and output[extent:] == b"\x5b" * (len(output) - extent),
                            "Actual native response exceeds output or changes unused tail")
                previous, pending = after, None
                completed += 1
            elif kind == "private-fixture-counter-write":
                require(pending is None and expected_counter is not None and fixtures == 0
                        and row.get("offset") == expected_counter
                        and row.get("production_input") is False
                        and row.get("native_calls_before") == completed == 1,
                        "Unadmitted or reclassified private fixture mutation")
                before, after = bytes.fromhex(row["heap_before_hex"]), bytes.fromhex(row["heap_after_hex"])
                injected = bytes.fromhex(row["bytes_hex"])
                require(before == previous and injected == struct.pack("<Q", (1 << 64) - 1)
                        and after == before[:expected_counter] + injected + before[expected_counter + 8:],
                        "Private fixture changed bytes outside its sole declared counter")
                previous = after
                fixtures += 1
            else:
                raise ValueError("Unknown private native-call journal record")
    require(pending is None and completed == expected_calls
            and fixtures == int(expected_counter is not None) and records == completed * 2 + fixtures,
            "Incomplete private native calls or fixture journal")
    if expected_counter != 64:
        require(previous == bytes(65536), "Actual private close did not erase the complete heap")
    return {"records": records, "completed_native_calls": completed, "private_fixture_writes": fixtures}


def state_original(directory, repository, admitted, *, capture=False, expected_target=None):
    from hia.platform.execution_state import rust_oracle as oracle
    report = read(directory / "report.json")
    require(report.get("schema") == oracle.REPORT_SCHEMA and report.get("status") == "PASS"
            and report.get("primary_error") is None and report.get("final_errors") == []
            and report.get("missing_tools") == []
            and report.get("controls") == report.get("passed") == report.get("original_case_rows_observed") == 68
            and report.get("failed") == 0 and report.get("original_tests") == list(oracle.ORIGINAL_TESTS)
            and report.get("required_original_tests") == list(oracle.ORIGINAL_TESTS),
            "Complete actual State original differential is required")
    for key in ("production_runtime_dependency", "complete_node", "successor_admission",
                "arbitrary_commit", "native_allocator_matches_rust_allocator_claimed"):
        require(report.get(key) is False, "Finite State original scope changed: " + key)
    for key in ("original_state_view_patch_operations", "safe_test_only_immutable_base_materialization",
                "original_production_function_bytes_preserved"):
        require(report.get(key) is True, "Actual State method relationship is missing")
    require(report["source_inputs"] == admitted["source_inputs"]
            and report["original_sources"] == admitted["original_sources"]
            and report["native_bundle_artifacts"] == admitted["bundle_artifacts"]
            and report["exact_corpus"] == bytes_id(admitted["corpus_raw"])
            and report["native_source_set_sha256"] == object_hash(admitted["source_inputs"])
            and identity(directory / "corpus.jsonl") == report["exact_corpus"],
            "Original State execution is not bound to the complete native predecessor")
    labels = ("rustc-version", "rustc-sysroot", "rustc-selected-version",
              "cargo-original-metadata", "cargo-original-test-build",
              "list-original-tests", *(f"retained-original-{i}" for i in range(5)),
              "actual-execution-state-corpus")
    rows = original_stages(directory, report, labels)
    fence_labels = ("source-before", "isolated-source-before", "compiled-source-and-binary-before",
                    "source-and-binary-after")
    fences = report.get("source_fences")
    require(isinstance(fences, list) and [row.get("label") for row in fences] == list(fence_labels),
            "State source/binary fence inventory differs")
    for fence in fences:
        require(equal(read(directory / (fence["label"] + ".json")), fence)
                and fence.get("status") == "PASS" and fence.get("errors") == [],
                "Actual State source/binary fence failed")
    tools = original_tools(directory, report, rows, "state", expected_target)
    binary = original_binary(directory, report, rows, "original-test-binary", expected_target)
    require(report["original_test_binary"]["path"] == str(directory / "original-test-binary"),
            "Original State binary path differs")
    listed = {line.removesuffix(": test") for line in rows["list-original-tests"][1].decode().splitlines()
              if line.endswith(": test")}
    require({oracle.TEST, *oracle.ORIGINAL_TESTS} <= listed, "Actual linked State tests are missing")
    for label, test in [(f"retained-original-{i}", name) for i, name in enumerate(oracle.ORIGINAL_TESTS)] + \
                       [("actual-execution-state-corpus", oracle.TEST)]:
        stage, raw = rows[label]
        require(stage["argv"] == [str(directory / "original-test-binary"), "--exact", test,
                                  "--nocapture", "--test-threads=1"],
                "Actual State test arguments differ")
        positive_test(raw, test)
    actual = oracle.parse_original_rows(rows["actual-execution-state-corpus"][1])
    require(len(actual) == 68 and [row.get("name") for row in actual] ==
            [row["name"] for row in admitted["inputs"]], "Original State history order differs")
    controls = read(directory / "comparison.json")["controls"]
    observed_file = read(directory / "original-observations.json")
    require(observed_file.get("cases") == actual and observed_file.get("observed_case_rows") == 68
            and observed_file.get("complete_differential_pass") is True
            and len(controls) == 68, "State original observation files differ")
    count = 0
    for original, native, control in zip(actual, admitted["comparison"]["histories"], controls, strict=True):
        require(equal(original.get("observations"), native["observations"])
                and original.get("safe_test_base_clone") is True
                and original.get("native_runtime_host_proxy") is False
                and isinstance(original.get("actual_method_calls"), dict),
                "Actual State observations differ")
        errors = original.get("original_errors")
        require(isinstance(errors, list) and len(errors) == len(native["observations"])
                and all(error == {0: None, 69: "LIMIT", 70: "RANGE", 71: "NONCANONICAL"}.get(row["status"], "INVALID")
                        for row, error in zip(original["observations"], errors, strict=True)),
                "Original State error relationship differs")
        require(control == {"name": native["name"], "status": "PASS", "differences": [],
                            "native": native, "original": original}, "State comparison summary differs")
        count += len(native["observations"])
    require(count == 1075, "Complete original State operation count differs")
    dependency = serde_binding(directory, report, rows, repository, "state", capture=capture)
    adaptation = original_adaptation(directory, repository, oracle, admitted["original_sources"], capture=capture)
    return {"original_report": identity(directory / "report.json"), "original_binary": binary,
            "original_histories": 68, "original_observations": count,
            "original_retained_tests": list(oracle.ORIGINAL_TESTS), "actual_serde": dependency,
            "actual_rust_tools": tools,
            "captured_original_adaptation": adaptation}


def state_physical(directory, repository, admitted):
    report = read(directory / "report.json")
    require(report.get("schema") == "trnm.execution-state-physical.v1" and report.get("status") == "PASS"
            and report.get("controls_total") == 9 and report.get("actual_native_calls") == 97
            and report.get("primary_error") is None
            and report.get("source_after") == {"status": "PASS", "errors": []}
            and report.get("private_counter_fixtures_are_production_inputs") is False
            and report.get("kernel_enomem_fixture_is_real_host_memory_exhaustion_claim") is False
            and report.get("original_rust") == "NOT_RUN",
            "Complete actual State physical controls are required")
    built, sources = native_build(directory / "build", repository, "state")
    require(report.get("build") == built and sources == admitted["source_inputs"]
            and built["executable"] == admitted["comparison"]["build"]["executable"],
            "Physical State build differs from this native source")
    names = (
        "actual-process-consumption-borrow-clone-and-stale-handles",
        "guarded-short-output-and-private-arena-no-mutation",
        "heap-reservation-before-any-object-or-sequence-mutation",
        "output-reservation-before-object-mutation",
        "every-value-truncation-preserves-live-owner-and-close-erases-all",
        "private-fixture-last-u64-serial-never-wraps-or-revives",
        "private-fixture-sequence-exhaustion-before-mutation",
        "actual-mremap-relocation-retains-full-value-and-owner-state",
        "actual-kernel-enomem-refusal-without-false-success-or-limit")
    require([row.get("name") for row in report["controls"]] == list(names)
            and all(row.get("status") == "PASS" for row in report["controls"]),
            "State physical control inventory differs")
    processes = []
    for index, relative, exit_code in ((0, "lifetimes", 0), (7, "real-relocation", 0), (8, "actual-enomem", 72)):
        path = directory / relative
        receipt = read(path / "receipt.json")
        require(receipt == report["controls"][index]["process"]
                and receipt.get("exit_code") == exit_code and receipt.get("cleanup") is None
                and receipt.get("executable") == built["executable"]
                and receipt.get("runtime_host_proxy") is False
                and receipt.get("wall_limit_seconds") == 240 and receipt.get("cleanup_limit_seconds") == 3,
                "State actual physical process differs")
        for name, expected in receipt["files"].items():
            require(identity(path / base.member_path(name)) == expected,
                    "State actual physical stream differs")
        processes.append({"directory": relative, "receipt": identity(path / "receipt.json")})
    relocation = base.regular(directory / "real-relocation/syscalls.raw").read_text()
    moves = re.findall(r"mremap\((0x[0-9a-f]+),\s*(\d+),\s*(\d+),\s*MREMAP_MAYMOVE\)\s*=\s*(0x[0-9a-f]+)", relocation)
    require(moves and any(old != new for old, _, _, new in moves)
            and [list(row) for row in moves] == report["controls"][7]["actual_mremaps"],
            "Actual moving mremap evidence is missing")
    refusal = base.regular(directory / "actual-enomem/syscalls.raw").read_text()
    require(re.search(r"mremap\([^\n]*\)\s*=\s*-1 ENOMEM[^\n]*INJECTED", refusal) is not None
            and base.regular(directory / "actual-enomem/stderr.raw").read_bytes() ==
                b"SVPFAIL1" + struct.pack("<Q", 72), "Actual kernel ENOMEM refusal differs")
    journals = report.get("private_call_journals")
    expected_journals = (("private-abi-calls.jsonl", 53, None),
                         ("private-serial-calls.jsonl", 5, 48),
                         ("private-sequence-calls.jsonl", 2, 64))
    require(isinstance(journals, list) and len(journals) == 3,
            "All three complete private-call journals are required")
    for row, (name, count, counter) in zip(journals, expected_journals, strict=True):
        require(row.get("file") == name and row.get("full_input_output_and_private_heap_bytes") is True
                and identity(directory / name) == {key: row[key] for key in ("bytes", "sha256")},
                "Private actual call journal identity differs")
        checked = private_journal(directory / name, count, counter)
        require(all(row.get(key) == value for key, value in checked.items()),
                "Private actual call journal counts differ")
    require(sum(row["completed_native_calls"] for row in journals) +
            sum(read(directory / row["directory"] / "receipt.json")["commands"] for row in processes) == 97,
            "Actual direct and process State call accounting differs")
    return {"physical_report": identity(directory / "report.json"), "physical_controls": 9,
            "physical_native_calls": 97, "physical_processes": processes, "private_call_journals": journals}


def preparation_semantic(directory, repository):
    from hia.platform.execution_prepare.rust_oracle import validate_bundle
    admitted = validate_bundle(repository, directory / "bundle")
    comparison, corpus, inputs, sources, originals, report = admitted
    built, checked = native_build(directory / "build", repository, "prepare")
    require(built == comparison["build"] and checked == sources
            and equal(read(directory / "report.json"), report)
            and len(inputs) == report["native_cases"] == 723,
            "Complete actual preparation semantic output differs")
    bundle_files = {path.relative_to(directory / "bundle").as_posix(): identity(path)
                    for path in sorted((directory / "bundle").rglob("*")) if path.is_file()}
    return admitted, {"native_cases": 723, "native_processes": 1, "original_rust": "NOT_RUN",
        "source_inputs": sources, "source_set_sha256": object_hash(sources),
        "original_source_set_sha256": object_hash(originals), "bundle_artifacts": bundle_files,
        "native_report": identity(directory / "report.json"),
        "native_comparison": identity(directory / "bundle/native-comparison.json"),
        "executable": {key: built["executable"][key] for key in ("bytes", "sha256")}}


def preparation_physical(directory, repository):
    from hia.platform.execution_prepare import rust_oracle as oracle
    report = read(directory / "report.json")
    built, sources = native_build(directory / "build", repository, "prepare")
    originals = oracle.original_manifest(repository)
    verification = {"source_after": {"status": "PASS", "source_set_sha256": object_hash(sources),
                    "native_source_files": len(sources), "original_source_files": len(originals)},
                    "primary_error": None, "cleanup_errors": []}
    require(report.get("schema") == oracle.NATIVE_SCHEMA and report.get("status") == "PASS"
            and report.get("suite") == "physical" and report.get("source_set_sha256") == object_hash(sources)
            and equal(report.get("verification"), verification) and report.get("native_controls") == 52
            and report.get("native_processes") == 52 and report.get("original_rust") == "NOT_RUN"
            and report.get("full_node_qualified") is False and report.get("durable_admission_qualified") is False,
            "Complete current-source preparation physical qualification required")
    controls = report.get("controls")
    require(isinstance(controls, list) and len(controls) == 52
            and len({row.get("name") for row in controls}) == 52, "Physical control identities differ")
    expected = (
        ["boot-eof-" + str(n) for n in (0, 1, 7, 8, 63)] + ["boot-magic", "boot-reserved"] +
        ["request-eof-" + str(n) for n in (0, 1, 63)] + ["body-eof-0", "body-eof-1", "body-eof-198"] +
        ["request-sequence", "request-magic", "request-reserved", "unknown-operation", "read-before-prepare",
         "stale-generation", "clear-destroys-value", "rejection-destroys-old-value"] +
        ["regular-" + name for name in ("stdin", "stdout", "stderr")] +
        ["wrong-pipe-access-" + name for name in ("stdin", "stdout", "stderr")] +
        ["same-stdin-stdout-pipe"] +
        ["control-" + name for name in ("write-regular", "read-regular", "write-readonly", "read-writeonly",
         "same-pipe", "same-number", "mixed-disabled", "opath-write")] +
        ["control-distinct-fd-stdout-alias", "control-distinct-fd-stdin-alias", "control-progress-epipe",
         "control-reply-eof"] +
        ["cancel-" + name + "-" + str(kind) for name in ("success", "encoding", "signature", "network")
         for kind in (1, 2)] + ["reply-sequence", "reply-magic", "reply-classification", "fragmented-reuse"])
    require([row["name"] for row in controls] == expected, "Actual physical case inventory changed")
    executable = {key: built["executable"][key] for key in ("bytes", "sha256")}
    for row in controls:
        path = directory / "controls" / base.member_path(row["name"])
        saved, captured = read(path / "process.json"), row["process"]
        if "requested_input" in captured:
            require(saved == captured and saved.get("primary_error") is None
                    and saved.get("cleanup_errors") == []
                    and saved.get("actual_exit") == saved.get("expected_exit")
                    and saved.get("actual_stdin_write_extent") == "NOT_OBSERVED_BY_COMMUNICATE"
                    and identity(path / "requested-stdin.raw") == saved["requested_input"],
                    "Actual raw physical process or requested input differs")
            channels = ("stdout", "stderr")
        else:
            require({key: value for key, value in saved.items() if key != "wall_ns"} ==
                    {key: value for key, value in captured.items() if key != "wall_ns"}
                    and type(saved.get("wall_ns")) is int and saved["wall_ns"] >= captured["wall_ns"]
                    and saved.get("cleanup_errors") == [] and saved.get("executable") == executable
                    and saved.get("pending_progress_bytes") == 0,
                    "Actual physical session differs beyond its later elapsed snapshot")
            expected_exit = 80 if row["name"].startswith("cancel-") else \
                            64 if row["name"].startswith("reply-") else 0
            require(saved.get("exit_code") == expected_exit, "Physical session exit differs")
            channels = ("stdin", "stdout", "stderr", "progress", "replies")
            require(saved["stdin_written_bytes"] == saved["stdin"]["bytes"],
                    "Physical session actual stdin extent differs")
            require(bytes.fromhex("".join(event["raw_hex"] for event in saved["events"])) ==
                    base.regular(path / "progress.raw").read_bytes()
                    and bytes.fromhex("".join(event["reply_hex"] for event in saved["events"])) ==
                    base.regular(path / "replies.raw").read_bytes(), "Actual callback stream differs")
        for channel in channels:
            require(identity(path / (channel + ".raw")) == saved[channel],
                    "Physical raw stream differs")
        diagnostic = base.regular(path / "stderr.raw").read_bytes()
        if "diagnostic" in saved:
            require(len(diagnostic) == 56 and list(struct.unpack("<7Q", diagnostic)) == saved["diagnostic"],
                    "Actual physical diagnostic differs")
    return {"physical_controls": 52, "native_processes": 52, "original_rust": "NOT_RUN",
            "source_inputs": sources, "source_set_sha256": object_hash(sources),
            "original_source_set_sha256": object_hash(originals), "executable": executable,
            "native_report": identity(directory / "report.json")}


def preparation_original(directory, repository, admitted, *, capture=False, expected_target=None):
    from hia.platform.execution_prepare import rust_oracle as oracle
    comparison, corpus, inputs, sources, originals, native_report = admitted
    report = read(directory / "report.json")
    require(report.get("schema") == oracle.REPORT_SCHEMA and report.get("status") == "PASS"
            and report.get("primary_error") is None and report.get("cleanup_errors") == []
            and report.get("differences") == [] and report.get("native_cases") ==
                report.get("actual_original_cases") == len(inputs) == 723
            and report.get("retained_tests") == list(oracle.ORIGINAL_TESTS)
            and report.get("source_inputs") == sources and report.get("original_sources") == originals
            and report.get("source_set_sha256") == object_hash(sources)
            and report.get("whole_node_qualified") is False and report.get("durable_admission_qualified") is False,
            "Complete actual preparation original differential required")
    require(set(report.get("source_after", {})) == {"native_sources", "original_sources", "native_bundle",
                "isolated_original", "locked_serde_sources", "actual_binary",
                "compiler_tools", "serde_library_artifacts"}
            and all(row == {"status": "PASS"} for row in report["source_after"].values())
            and identity(directory / "corpus.jsonl") == bytes_id(corpus),
            "Preparation original source/binary/corpus fence differs")
    labels = ("rustc-version", "rustc-sysroot", "rustc-bound-version",
              "cargo-metadata", "cargo-original-test-build", "list-original-tests",
              "retained-0", "retained-1", "retained-2", "actual-private-prepare-corpus")
    rows = original_stages(directory, report, labels)
    tools = original_tools(directory, report, rows, "prepare", expected_target)
    binary = original_binary(directory, report, rows, "original-m06-tests", expected_target)
    require(report.get("independent_binary") == str(directory / "original-m06-tests"),
            "Original preparation binary path differs")
    listed = {line.rsplit(": ", 1)[0] for line in rows["list-original-tests"][1].decode().splitlines()
              if line.endswith(": test")}
    require({oracle.TEST, *oracle.ORIGINAL_TESTS} <= listed, "Actual preparation tests are not linked")
    for label, name in [(f"retained-{i}", name) for i, name in enumerate(oracle.ORIGINAL_TESTS)] + \
                       [("actual-private-prepare-corpus", oracle.TEST)]:
        stage, raw = rows[label]
        require(stage["argv"] == [str(directory / "original-m06-tests"), name, "--exact",
                                 "--nocapture", "--test-threads=1"],
                "Actual preparation test arguments differ")
        positive_test(raw, name)
    context, actual = oracle.collect_original(rows["actual-private-prepare-corpus"][1],
                                               [row["name"] for row in inputs])
    projected = oracle.context_projection(comparison["context"])
    require(equal(projected, {key: context[key] for key in projected})
            and context.get("task_profile") == "legacy-task-v1" and context.get("task_windows_none") is True
            and context.get("native_pq_none") is True and context.get("is_pq_account_profile") is False
            and context.get("account_profile_error") is None and context.get("funded_config_error") is None,
            "Actual installed original preparation context differs")
    require(equal(context, report["context"]) and equal(actual, report["original_cases"])
            and len(actual) == 723 and all(equal(native["observation"], original)
                for native, original in zip(comparison["cases"], actual, strict=True)),
            "Actual original preparation observations differ from raw output or native results")
    dependency = serde_binding(directory, report, rows, repository, "prepare", capture=capture)
    adaptation = original_adaptation(directory, repository, oracle, originals, capture=capture)
    return {"original_report": identity(directory / "report.json"), "original_binary": binary,
            "actual_original_cases": 723, "original_retained_tests": list(oracle.ORIGINAL_TESTS),
            "actual_serde": dependency, "actual_rust_tools": tools, "captured_original_adaptation": adaptation}


def check_parent(value, expected):
    require(isinstance(value, dict) and value.get("schema") == SCHEMA
            and value.get("stage") == "prepare-semantic" and value.get("status") == "PASS"
            and equal(value.get("lineage"), expected) and value.get("native_cases") == 723
            and type(value.get("native_cases")) is int and type(value.get("native_processes")) is int
            and value.get("native_processes") == 1 and value.get("original_rust") == "NOT_RUN"
            and value.get("whole_node_or_commit_authority") is False
            and value.get("batch_execution_qualified") is False,
            "Complete same-source/run/attempt preparation predecessor required")
    source = value.get("source_observations")
    require(isinstance(source, dict), "Predecessor full source observations absent")
    for name in ("before", "after"):
        row = source.get(name)
        require(isinstance(row, dict) and row.get("tested_commit") == row.get("candidate") == expected["git_head"]
                and row.get("kind") == "head" and row.get("tracked_worktree_verified") is True
                and type(row.get("tracked_entries")) is int and row["tracked_entries"] > 0,
                "Predecessor complete source proof differs")
    require(all(source["before"].get(key) == source["after"].get(key)
                for key in ("tested_tree", "tracked_entries")), "Predecessor source changed")


def bind(stage, root):
    require(stage in STAGES, "Unknown execution stage")
    expected = lineage()
    observed = observations(root, stage)
    result = {"schema": SCHEMA, "stage": stage, "status": "PASS", "lineage": expected,
              "whole_node_or_commit_authority": False, "batch_execution_qualified": False,
              "source_observations": transfer.source_pair(observed, expected)}
    if stage == "execution-state":
        from hia.platform.execution_state import rust_oracle as oracle
        native = root / "hia-execution-state-native"
        admitted = oracle.validate_bundle(ROOT, native / "bundle")
        require(equal(read(native / "report.json"), admitted["report"])
                and admitted["native_counts"] == {"histories": 68, "commands": 1075},
                "Complete current State native qualification differs")
        native_build(native / "build", ROOT, "state")
        result.update(source_inputs=admitted["source_inputs"],
            source_set_sha256=object_hash(admitted["source_inputs"]),
            original_source_set_sha256=object_hash(admitted["original_sources"]),
            native_histories=68, native_observations=1075, native_processes=68,
            native_report=identity(native / "report.json"),
            bundle_artifacts=admitted["bundle_artifacts"],
            executable=admitted["comparison"]["build"]["executable"])
        result.update(state_physical(root / "hia-execution-state-physical", ROOT, admitted))
        result.update(state_original(root / "hia-execution-state-original", ROOT, admitted, capture=True,
                                     expected_target=root / "hia-execution-state-cargo-target"))
        originals = admitted["original_sources"]
    elif stage == "prepare-semantic":
        admitted, summary = preparation_semantic(root / "hia-prepare-semantic", ROOT)
        result.update(summary)
        originals = admitted[4]
    elif stage == "prepare-physical":
        result.update(preparation_physical(root / "hia-prepare-physical", ROOT))
        _, originals = source_maps(ROOT, "prepare")
    else:
        prior = root / "hia-prepare-prior"
        parent = read(prior / "native-binding.json")
        check_parent(parent, expected)
        admitted, summary = preparation_semantic(prior / "native", ROOT)
        require(all(equal(parent.get(key), value) for key, value in summary.items()),
                "Extracted predecessor differs from semantic qualification")
        receipt = read(prior / "transfer-receipt.json")
        require(receipt.get("status") == "VERIFIED_COMPLETE_REGULAR_BYTES_TRANSFERRED"
                and receipt.get("lineage") == expected
                and receipt.get("native_binding") == identity(prior / "native-binding.json"),
                "Preparation transfer did not succeed")
        result.update(summary)
        result["original_rust"] = "PASS"
        result["native_binding"] = identity(prior / "native-binding.json")
        result["transfer_receipt"] = identity(prior / "transfer-receipt.json")
        result.update(preparation_original(root / "hia-prepare-original", ROOT, admitted, capture=True,
                                           expected_target=root / "hia-prepare-cargo-target"))
        originals = admitted[4]
    base.check_committed_sources({**originals, **result["source_inputs"]})
    write_new(observed / "binding.json", result)
    return result


def unpack(root):
    expected = lineage()
    before = base.check_source_observation(observations(root, "prepare-original"), expected)
    download = root / "hia-prepare-download"
    package = read(download / "package-manifest.json")
    require(package.get("schema") == PACKAGE and package.get("stage") == "prepare-semantic"
            and package.get("lineage") == expected and package.get("packing_status") == "PASS"
            and package.get("qualification_status_not_changed_by_packaging") is True,
            "Preparation download is from another or failed qualification")
    parent = read(download / "native-binding.json")
    check_parent(parent, expected)
    require(identity(download / "native-binding.json") == package["binding"]
            and all(parent["source_observations"]["before"].get(key) == before.get(key)
                    for key in ("tested_tree", "tracked_entries")),
            "Downloaded native binding or complete Git tree differs")
    sources, originals = source_maps(ROOT, "prepare")
    require(parent.get("source_inputs") == sources and parent.get("source_set_sha256") == object_hash(sources)
            and parent.get("original_source_set_sha256") == object_hash(originals),
            "Downloaded native dependency closure differs")
    archive = download / "complete-evidence.tar.xz"
    require(identity(archive) == package["archive"], "Downloaded archive bytes differ")
    output = root / "hia-prepare-prior"
    transfer.safe_extract(archive, output, package["entries"])
    require(equal(read(output / "observations/binding.json"), parent)
            and identity(output / "observations/source-before.json") == parent["source_observations"]["before_file"]
            and identity(output / "observations/source-after.json") == parent["source_observations"]["after_file"],
            "Transferred complete source proofs differ")
    _, summary = preparation_semantic(output / "native", ROOT)
    require(all(equal(parent.get(key), value) for key, value in summary.items()),
            "Transferred actual native observations differ")
    captured_file(download / "native-binding.json", output / "native-binding.json", package["binding"])
    write_new(output / "transfer-receipt.json", {
        "status": "VERIFIED_COMPLETE_REGULAR_BYTES_TRANSFERRED", "lineage": expected,
        "archive": package["archive"], "native_binding": package["binding"],
        "source_and_corpus_validated": True, "special_files_remain_metadata_only": package["special_entries"]})
    return {"lineage": expected, "regular_members": len(package["entries"])}


def pack(stage, root):
    require(stage in STAGES, "Unknown execution stage")
    prefix = "hia-execution-state" if stage == "execution-state" else "hia-prepare"
    output = root / (prefix + "-artifact")
    output.mkdir(mode=0o700)
    observed = observations(root, stage)
    observed.mkdir(mode=0o700, exist_ok=True)
    roots = {"observations": observed, "bootstrap": root / "hia-bootstrap"}
    if stage == "execution-state":
        roots.update(native=root / "hia-execution-state-native",
                     physical=root / "hia-execution-state-physical",
                     original=root / "hia-execution-state-original")
    elif stage == "prepare-original":
        roots.update(original=root / "hia-prepare-original", download=root / "hia-prepare-download")
    else:
        roots["native"] = root / ("hia-" + stage)
    record = {"schema": PACKAGE, "stage": stage, "lineage": lineage(),
              "qualification_status_not_changed_by_packaging": True, "packing_status": "FAIL",
              "entries": {}, "special_entries": {}, "transfer_receipts": {},
              "excluded_reconstructible_isolated_source_and_cargo_target": True,
              "complete_original_test_binary_is_not_excluded": stage in ("execution-state", "prepare-original"),
              "downloaded_package_retained_even_on_transfer_failure": stage == "prepare-original"}
    errors = []
    if stage == "prepare-original":
        for name in ("native-binding.json", "transfer-receipt.json"):
            source = root / "hia-prepare-prior" / name
            if not source.exists() and not source.is_symlink():
                record["transfer_receipts"][name] = {"status": "ABSENT"}
                continue
            try:
                before = identity(source)
                captured_file(source, observed / ("predecessor-" + name), before)
                record["transfer_receipts"][name] = {"status": "CAPTURED", **before}
            except (OSError, ValueError) as error:
                errors.append({"path": str(source), "error": repr(error)})
    archive = output / "complete-evidence.tar.xz"
    try:
        with tarfile.open(archive, "x:xz", preset=1) as packed:
            def retain(path, name):
                relative = base.member_path(name)
                if any(part in {"isolated-source", "isolated", "cargo-target"} for part in relative.parts):
                    return
                require(name not in record["entries"] and name not in record["special_entries"],
                        "Duplicate evidence path")
                before = path.lstat()
                if stat.S_ISDIR(before.st_mode):
                    member = tarfile.TarInfo(name)
                    member.type, member.mode = tarfile.DIRTYPE, 0o700
                    packed.addfile(member)
                    record["entries"][name] = {"type": "5", "bytes": 0, "linkname": ""}
                    for child in sorted(path.iterdir()):
                        retain(child, name + "/" + child.name)
                elif stat.S_ISREG(before.st_mode):
                    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(descriptor, "rb") as stream:
                        held = os.fstat(stream.fileno())
                        require(stat.S_ISREG(held.st_mode) and (held.st_dev, held.st_ino) ==
                                (before.st_dev, before.st_ino), "Evidence pathname changed before capture")
                        member = tarfile.TarInfo(name)
                        member.size, member.mode = held.st_size, 0o600
                        digest = hashlib.sha256()
                        class HashedReader:
                            def read(self, length):
                                raw = stream.read(length)
                                digest.update(raw)
                                return raw
                        packed.addfile(member, HashedReader())
                        after = os.fstat(stream.fileno())
                    current = path.lstat()
                    require((held.st_size, held.st_mtime_ns, held.st_ctime_ns) ==
                            (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                            and (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns) ==
                            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                            "Evidence file changed during capture")
                    record["entries"][name] = {"type": "0", "bytes": held.st_size,
                                               "sha256": digest.hexdigest(), "linkname": ""}
                else:
                    kind = "symlink" if stat.S_ISLNK(before.st_mode) else "fifo" if stat.S_ISFIFO(before.st_mode) else \
                        "socket" if stat.S_ISSOCK(before.st_mode) else "other"
                    row = {"type": kind, "mode": stat.S_IMODE(before.st_mode), "device": before.st_dev,
                           "inode": before.st_ino, "links": before.st_nlink, "bytes": before.st_size, "opened": False}
                    if kind == "symlink":
                        row["link_text"] = os.readlink(path)
                    record["special_entries"][name] = row
            for label, directory in roots.items():
                if not directory.exists() and not directory.is_symlink():
                    continue
                require(not directory.is_symlink() and directory.is_dir(), "Aliased evidence root")
                retain(directory, label)
        record["archive"] = identity(archive)
        binding = observed / "binding.json"
        if binding.exists() or binding.is_symlink():
            value = read(binding)
            require(value.get("schema") == SCHEMA and value.get("stage") == stage and value.get("status") == "PASS"
                    and value.get("lineage") == record["lineage"], "Qualification binding changed before packaging")
            transfer.source_pair(observed, record["lineage"])
            destination = output / ("native-binding.json" if stage == "prepare-semantic" else "binding.json")
            captured_file(binding, destination, identity(binding))
            record["binding"] = identity(destination)
        require(not errors, "Transfer receipt capture failed")
        record["packing_status"] = "PASS"
    except BaseException as error:
        errors.append({"error": repr(error), "traceback": traceback.format_exc()})
        if archive.is_file() and not archive.is_symlink():
            record["partial_archive"] = identity(archive)
    finally:
        record["capture_errors"] = errors
        write_new(output / "package-manifest.json", record)
    require(record["packing_status"] == "PASS", "Partial evidence and packaging failure retained")
    return {"stage": stage, "regular_and_directory_members": len(record["entries"]),
            "special_metadata_entries": len(record["special_entries"]), "archive": record["archive"],
            "qualification_status_not_changed_by_packaging": True}


def main():
    require(__debug__ and not os.environ.get("PYTHONOPTIMIZE"), "Optimized evidence reader is not admitted")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("bind", "pack", "unpack"))
    parser.add_argument("--stage", choices=STAGES)
    args = parser.parse_args()
    require(args.action == "unpack" or args.stage is not None, "Stage is required")
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    result = unpack(root) if args.action == "unpack" else globals()[args.action](args.stage, root)
    print(json.dumps({key: value for key, value in result.items()
                      if key not in {"source_inputs", "entries", "bundle_artifacts"}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
