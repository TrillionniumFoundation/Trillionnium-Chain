#!/usr/bin/env python3
"""Bind actual foundation results and preserve complete CI evidence.

This is a hosted qualification driver. It supplies no native runtime behavior.
Archive handling retains special-file metadata but never opens fixture FIFOs or
materializes links when transferring a native bundle to a dependent CI job.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
COMPILER = "87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"
STAGES = ("continuity-native", "continuity-original", "continuity-capacity", "thread-cpu")
SCHEMA = "trnm.hia.foundation-ci-binding.v1"
PACKAGE = "trnm.hia.foundation-ci-evidence.v1"


def require(value, message):
    if not value:
        raise ValueError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key: " + key)
        result[key] = value
    return result


def regular(path):
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path and path.is_file(),
            "Expected a regular unaliased file: " + str(path))
    return path


def identity(path):
    digest, size = hashlib.sha256(), 0
    with regular(path).open("rb") as stream:
        while block := stream.read(1 << 20):
            digest.update(block)
            size += len(block)
    return {"bytes": size, "sha256": digest.hexdigest()}


def read(path):
    path = regular(path)
    return json.loads(path.read_bytes(), object_pairs_hook=unique_object)


def write_new(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def object_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def lineage(environment=None):
    env = os.environ if environment is None else environment
    head, run, attempt = (env[key] for key in
                         ("TRNM_EXPECTED_SOURCE_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    require(len(head) == 40 and all(c in "0123456789abcdef" for c in head), "Invalid exact commit")
    require(run.isdecimal() and int(run) > 0 and attempt.isdecimal() and int(attempt) > 0,
            "Actual CI run and attempt required")
    return {"git_head": head, "run_id": run, "attempt": int(attempt)}


def check_parent(value, expected):
    require(type(value) is dict and value.get("schema") == SCHEMA
            and value.get("stage") == "continuity-native" and value.get("status") == "PASS",
            "Successful native predecessor required")
    require(value.get("lineage") == expected, "Predecessor source, run or attempt differs")
    require(value.get("native_controls") == 659 and value.get("semantic_cases") == 572
            and value.get("original_rust") == "NOT_RUN", "Complete native predecessor required")
    require(value.get("whole_node_or_commit_authority") is False
            and value.get("physical_power_loss") is False, "Predecessor scope changed")


def check_source_observation(observations, expected):
    source = read(observations / "source-before.json")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT).decode().strip()
    require(head == expected["git_head"] == source.get("tested_commit") == source.get("candidate")
            and source.get("tested_tree") == tree and source.get("kind") == "head"
            and source.get("tracked_worktree_verified") is True
            and type(source.get("tracked_entries")) is int and source["tracked_entries"] > 0,
            "Complete exact committed source observation required")
    return source


def check_committed_sources(sources, repository=ROOT):
    """Verify every captured input against its actual Git HEAD blob."""
    require(type(sources) is dict and sources, "Complete captured sources required")
    names = sorted(sources)
    for name in names:
        path = PurePosixPath(name)
        require(isinstance(name, str) and not path.is_absolute() and path.as_posix() == name
                and ".." not in path.parts and "\n" not in name and "\r" not in name,
                "Invalid captured source path")
    with tempfile.TemporaryFile() as requests, tempfile.TemporaryFile() as errors:
        requests.write("".join("HEAD:" + name + "\n" for name in names).encode())
        requests.seek(0)
        child = subprocess.Popen(["git", "cat-file", "--batch"], cwd=repository, stdin=requests,
                                 stdout=subprocess.PIPE, stderr=errors)
        try:
            for name in names:
                header = child.stdout.readline().split()
                require(len(header) == 3 and header[1] == b"blob" and header[2].isdigit(),
                        "Captured input is absent from committed source: " + name)
                remaining = total = int(header[2])
                digest = hashlib.sha256()
                while remaining:
                    block = child.stdout.read(min(remaining, 1 << 20))
                    require(block, "Truncated committed source blob")
                    remaining -= len(block)
                    digest.update(block)
                require(child.stdout.read(1) == b"\n", "Malformed committed source framing")
                require(sources[name] == {"bytes": total, "sha256": digest.hexdigest()},
                        "Captured input differs from committed source: " + name)
            require(not child.stdout.read() and child.wait(timeout=30) == 0,
                    "Committed source reader did not complete")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)
            child.stdout.close()
    return len(names)


def continuity_build(build, directory):
    from hia.platform.continuity_store.rust_oracle import complete_source_manifest
    from hia.platform.typed_store.build import original_manifest
    require(build.get("schema") == "trnm.hia.continuity-staging-build.v1"
            and build.get("status") == "PASS" and build.get("source_inputs_stable") is True,
            "Successful continuity build required")
    sources = complete_source_manifest(ROOT)
    require(build.get("source_inputs") == sources
            and build.get("source_set_sha256") == object_hash(sources),
            "Complete current continuity source closure differs")
    require(build.get("original_sources") == original_manifest(ROOT), "Original source closure differs")
    check_committed_sources({**build["original_sources"], **sources})
    require(build.get("compiler_sha256") == COMPILER
            and build.get("compiler_qualification_binding") == read(ROOT / "hia/qualification/compiler-binding.json"),
            "Pinned compiler qualification differs")
    require(identity(directory / "continuity-stage.elf") ==
            {key: build["executable"][key] for key in ("bytes", "sha256")},
            "Actual continuity executable differs")
    return {"source_inputs": sources, "source_set_sha256": object_hash(sources),
            "original_source_set_sha256": object_hash(build["original_sources"]),
            "executable": {key: build["executable"][key] for key in ("bytes", "sha256")}}


def bind(stage, root):
    expected = lineage()
    observations = root / "hia-foundation-observations"
    source = check_source_observation(observations, expected)
    result = {"schema": SCHEMA, "stage": stage, "status": "PASS", "lineage": expected,
              "whole_node_or_commit_authority": False, "physical_power_loss": False,
              "source_observation": source}
    if stage == "continuity-native":
        from hia.platform.continuity_store.rust_oracle import validate_bundle
        directory = root / "hia-continuity-native"
        report = read(directory / "report.json")
        comparison, captured, _, _ = validate_bundle(ROOT, directory)
        require(report.get("status") == "NATIVE_PASS_ORIGINAL_NOT_RUN"
                and report.get("original_rust") == "NOT_RUN"
                and report.get("source_inputs_stable") is True
                and report.get("semantic_cases") == 572
                and report.get("control_count") == len(report["controls"]) == 659
                and all(row["status"] == "PASS" for row in report["controls"]),
                "All actual continuity native controls required")
        require(report["build"] == comparison["build"] and report["contexts"] == comparison["contexts"]
                and report["corpus"] == comparison["corpus"] and len(comparison["cases"]) == 572,
                "Native report, contexts or corpus differ")
        result.update(continuity_build(report["build"], directory / "build"),
                      native_controls=659, semantic_cases=572, original_rust="NOT_RUN",
                      corpus=comparison["corpus"], native_report=identity(directory / "report.json"),
                      native_comparison_sha256=hashlib.sha256(captured).hexdigest())
    elif stage in ("continuity-original", "continuity-capacity"):
        prior = root / "hia-continuity-prior"
        parent_path = prior / "native-binding.json"
        parent = read(parent_path)
        check_parent(parent, expected)
        result["native_binding"] = identity(parent_path)
        for key in ("source_inputs", "source_set_sha256", "original_source_set_sha256",
                    "executable", "native_report", "native_comparison_sha256", "corpus"):
            result[key] = parent[key]
        directory = root / ("hia-" + stage)
        report = read(directory / "report.json")
        require(report.get("status") == "PASS" and report.get("source_inputs_stable") is True,
                "Actual continuity dependent stage did not pass")
        result["stage_report"] = identity(directory / "report.json")
        if stage == "continuity-original":
            from hia.platform.continuity_store.rust_oracle import ORIGINAL_TESTS
            require(report.get("schema") == "trnm.hia.original-continuity-staging-differential.v1"
                    and report.get("controls") == 572 and report.get("failed") == 0
                    and report.get("retained_original_tests") == list(ORIGINAL_TESTS),
                    "All actual original cases and four retained tests required")
            require(report.get("native_comparison_sha256") == parent["native_comparison_sha256"]
                    and report.get("native_source_set_sha256") == parent["source_set_sha256"]
                    and object_hash(report["original_sources"]) == parent["original_source_set_sha256"]
                    and report.get("exact_corpus") == parent["corpus"],
                    "Original result is not bound to this exact native predecessor")
            require(report.get("actual_private_original_apply_slot_state_continuity_and_root_called") is True
                    and report.get("original_production_function_bytes_preserved") is True
                    and len(report.get("exact_installed_constructor_snapshots", [])) == 4,
                    "Actual original implementation and installed contexts required")
            check_committed_sources({**report["original_sources"], **parent["source_inputs"]})
            result.update(actual_original_cases=572, actual_original_tests=list(ORIGINAL_TESTS),
                          actual_original_executable_sha256=report["executable_sha256"])
        else:
            checked = continuity_build(report["build"], directory / "build")
            require(all(checked[key] == parent[key] for key in checked),
                    "Capacity build differs from native predecessor")
            names = ["complete-maximum", "fresh-process-complete-cold", "corrupt-last-byte",
                     "row-1065537", "account-1000001", "working-65537",
                     "65515-exact-recipient-identities"]
            require(report.get("schema") == "trnm.hia.continuity-growth-capacity.v1"
                    and report.get("control_count") == 7
                    and [row["name"] for row in report["controls"]] == names
                    and all(row["status"] == "PASS" and all(row["checks"].values())
                            for row in report["controls"]), "All physical capacity controls required")
            require(report.get("maximum_rows") == 1065536
                    and report.get("maximum_permanent_accounts") == 1000000
                    and report.get("maximum_working_keys") == 65536
                    and report.get("physical_power_loss") is False
                    and report.get("original_rust_large_extent") == "NOT_RUN",
                    "Full capacity or explicit qualification scope changed")
            first, cold = report["controls"][:2]
            require(cold["source"] == {"bytes": first["actual"]["output_bytes"],
                                       "sha256": first["actual"]["output_sha256"]},
                    "Fresh-process input is not the complete preceding native output")
            result.update(capacity_controls=7, maximum_rows=1065536,
                          original_rust_large_extent="NOT_RUN")
    else:
        from hia.platform.thread_cpu.rust_oracle import validate_source_bindings
        directory = root / "hia-thread-cpu-native"
        native = read(directory / "native-comparison.json")
        original = read(root / "hia-thread-cpu-original/original/report.json")
        sources = validate_source_bindings(native)
        require(native.get("status") == "NATIVE_PASS_ORIGINAL_NOT_RUN" and len(native["cases"]) == 65
                and len(native["native_protocol_controls"]) == 74
                and all(row["status"] == "PASS" for row in native["native_protocol_controls"]),
                "Complete actual thread CPU native histories and physical controls required")
        require(original.get("status") == "PASS" and original.get("histories") == 65
                and original.get("operations") == 724 and original.get("source_after") == "MATCH"
                and original.get("source_inputs") == sources == native["source_inputs"]
                and original.get("original_sources") == native["original_sources"]
                and original.get("exact_corpus") == native["corpus"]
                and original.get("native_comparison_sha256") ==
                    identity(directory / "native-comparison.json")["sha256"]
                and original.get("mandatory_original_clock_available") is True
                and original.get("original_repository_modified") is False,
                "Actual original thread CPU differential required")
        require(original.get("whole_node_or_paid_account_qualified") is False
                and original.get("original_scoped_executor_or_shared_account_executed") is False,
                "Finite thread primitive cannot certify the full account or executor")
        check_committed_sources({**native["original_sources"], **sources})
        result.update(source_inputs=sources, source_set_sha256=object_hash(sources),
                      semantic_histories=65, operations=724, physical_controls=74,
                      native_comparison=identity(directory / "native-comparison.json"),
                      original_report=identity(root / "hia-thread-cpu-original/original/report.json"),
                      executable=native["build"]["executable"], paid_account_qualified=False)
    write_new(observations / "binding.json", result)
    return result


def member_path(name):
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.parts and ".." not in path.parts
            and path.as_posix() == name and "\x00" not in name, "Unsafe archive member")
    return path


def extract_regular(archive, destination, entries):
    """Check the full roster first, then copy only verified regular files."""
    require(not destination.exists() and not destination.is_symlink(), "Fresh extraction directory required")
    with tarfile.open(regular(archive), "r:xz") as stream:
        members = stream.getmembers()
        names = [member.name for member in members]
        require(len(names) == len(set(names)) and set(names) == set(entries),
                "Duplicate, extra or missing archive member")
        for member in members:
            path = member_path(member.name)
            require(path.parts[0] in {"native", "observations", "bootstrap"}, "Unexpected bundle root")
            expected = entries[member.name]
            require(expected["type"] == member.type.decode("ascii")
                    and expected["bytes"] == member.size
                    and expected["linkname"] == member.linkname, "Archive metadata changed")
        destination.mkdir(mode=0o700)
        omitted = []
        for member in members:
            if member.isdir():
                continue
            if not member.isfile():
                omitted.append({"name": member.name, "type": member.type.decode("ascii"),
                                "linkname": member.linkname})
                continue
            path = destination / member_path(member.name)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            digest, size = hashlib.sha256(), 0
            with stream.extractfile(member) as source, path.open("xb") as output:
                while block := source.read(1 << 20):
                    output.write(block)
                    digest.update(block)
                    size += len(block)
            require({"bytes": size, "sha256": digest.hexdigest()} ==
                    {"bytes": entries[member.name]["bytes"], "sha256": entries[member.name]["sha256"]},
                    "Transferred evidence bytes changed")
        return omitted


def pack(stage, root):
    output = root / "hia-foundation-artifact"
    output.mkdir(mode=0o700)
    roots = {"observations": root / "hia-foundation-observations",
             "bootstrap": root / "hia-bootstrap"}
    if stage == "thread-cpu":
        roots.update(native=root / "hia-thread-cpu-native", original=root / "hia-thread-cpu-original")
    elif stage == "continuity-native":
        roots["native"] = root / "hia-continuity-native"
    else:
        roots[stage.removeprefix("continuity-")] = root / ("hia-" + stage)
        # Preserve the actual download even when admission rejects its digest,
        # metadata or contents before an extraction receipt can be written.
        roots["download"] = root / "hia-continuity-download"
    transfer_records, transfer_errors = {}, []
    if stage in ("continuity-original", "continuity-capacity"):
        observations = roots["observations"]
        observations.mkdir(mode=0o700, exist_ok=True)
        for source_name, saved_name in (("native-binding.json", "predecessor-binding.json"),
                                        ("transfer-receipt.json", "transfer-receipt.json")):
            source = root / "hia-continuity-prior" / source_name
            if not source.exists() and not source.is_symlink():
                transfer_records[source_name] = {"status": "ABSENT"}
                continue
            try:
                before = identity(source)
                destination = observations / saved_name
                with regular(source).open("rb") as incoming, destination.open("xb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing)
                require(identity(source) == identity(destination) == before,
                        "Transfer receipt changed during capture")
                transfer_records[source_name] = {"status": "CAPTURED", **before}
            except (OSError, ValueError) as error:
                transfer_records[source_name] = {"status": "CAPTURE_FAILED", "error": repr(error)}
                transfer_errors.append(source_name)
    entries = {}
    archive = output / "complete-evidence.tar.xz"
    with tarfile.open(archive, "x:xz", preset=1, dereference=False) as stream:
        for label, directory in roots.items():
            if not directory.exists():
                continue
            require(not directory.is_symlink() and directory.is_dir(), "Aliased evidence root")
            def retain(member):
                relative = PurePosixPath(member.name).relative_to(label)
                if "isolated-source" in relative.parts or "cargo-target" in relative.parts:
                    return None
                require(member.name not in entries, "Duplicate evidence name")
                value = {"bytes": member.size, "type": member.type.decode("ascii"), "linkname": member.linkname}
                if member.isfile():
                    value.update(identity(directory / relative))
                entries[member.name] = value
                return member
            stream.add(directory, arcname=label, filter=retain)
    record = {"schema": PACKAGE, "stage": stage, "lineage": lineage(), "archive": identity(archive),
              "entries": entries, "qualification_status_not_changed_by_packaging": True,
              "excluded_reconstructible_isolated_source_and_cargo_target": True,
              "downloaded_package_retained_even_on_transfer_failure": stage in ("continuity-original", "continuity-capacity"),
              "transfer_receipts": transfer_records, "transfer_capture_errors": transfer_errors}
    binding = roots["observations"] / "binding.json"
    if binding.exists():
        target = output / ("native-binding.json" if stage == "continuity-native" else "binding.json")
        shutil.copyfile(regular(binding), target)
        require(identity(target) == identity(binding), "Binding changed during copy")
        record["binding"] = identity(target)
    write_new(output / "package-manifest.json", record)
    require(not transfer_errors, "Transfer receipt capture failed; partial archive and errors retained")
    return {"stage": stage, "files": len(entries), "archive": record["archive"],
            "qualification_status_not_changed_by_packaging": True}


def unpack(root):
    download = root / "hia-continuity-download"
    package = read(download / "package-manifest.json")
    require(package.get("schema") == PACKAGE and package.get("stage") == "continuity-native"
            and package.get("lineage") == lineage()
            and package.get("qualification_status_not_changed_by_packaging") is True,
            "Downloaded package belongs to another qualification")
    binding_path = download / "native-binding.json"
    parent = read(binding_path)
    check_parent(parent, lineage())
    from hia.platform.continuity_store.rust_oracle import complete_source_manifest
    from hia.platform.typed_store.build import original_manifest
    current = complete_source_manifest(ROOT)
    require(parent.get("source_inputs") == current
            and parent.get("source_set_sha256") == object_hash(current)
            and parent.get("original_source_set_sha256") == object_hash(original_manifest(ROOT)),
            "Predecessor complete source closure differs before execution")
    check_committed_sources({**original_manifest(ROOT), **current})
    require(identity(binding_path) == package["binding"], "Native binding bytes changed")
    archive = download / "complete-evidence.tar.xz"
    require(identity(archive) == package["archive"], "Native archive bytes changed")
    output = root / "hia-continuity-prior"
    omitted = extract_regular(archive, output, package["entries"])
    shutil.copyfile(binding_path, output / "native-binding.json")
    require(identity(output / "native/report.json") == parent["native_report"]
            and identity(output / "native/native-comparison.json")["sha256"] ==
                parent["native_comparison_sha256"]
            and identity(output / "native/corpus.jsonl") == parent["corpus"],
            "Extracted native results differ from predecessor")
    write_new(output / "transfer-receipt.json",
              {"status": "VERIFIED_REGULAR_BYTES_TRANSFERRED", "lineage": lineage(),
               "archive": package["archive"], "native_binding": package["binding"],
               "special_members_retained_only_as_archive_metadata": omitted})
    return {"lineage": lineage(), "omitted_special_members": len(omitted)}


def main():
    require(__debug__, "Foundation CI evidence refuses optimized Python")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("bind", "pack", "unpack"))
    parser.add_argument("--stage", choices=STAGES)
    args = parser.parse_args()
    require(args.action == "unpack" or args.stage is not None, "Stage is required")
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    result = unpack(root) if args.action == "unpack" else globals()[args.action](args.stage, root)
    print(json.dumps({key: value for key, value in result.items()
                      if key not in {"source_inputs", "entries"}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
