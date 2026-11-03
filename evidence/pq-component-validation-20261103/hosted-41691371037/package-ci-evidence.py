#!/usr/bin/env python3
"""Repackage supplied CI artifact payloads; never execute repository tests."""

import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import zipfile
from datetime import datetime, timezone

REPOSITORY = "TrillionniumFoundation/Trillionnium-Chain"
RUN_ID = 41691371037
RUN_URL = f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}"
HEAD = "45962558a7133375b16c0ac2600f2edb4a115585"
MERGE = "9762e8e5c0485d148a01cf0810790497cb21968f"
TREE = "8d1d6c4e18e395dfc842c3401844a8ddcd4c01d9"
FIX = "8a74a9e42a9efbc52d83e861f64f03efd40f1406"
FIX_TREE = "3d3ab7ff49c7f0b9109ba9e5ede1362cf6b290e7"
LANES = [
    ("x64-head", 13263326083, 13262116480, HEAD, "head"),
    ("arm64-head", 13263262338, 13262010223, HEAD, "head"),
    ("arm64-merge", 13263163201, 13261235455, MERGE, "prospective-merge"),
    ("x64-merge", 13261143324, 13260673197, MERGE, "prospective-merge"),
]
ARCHIVE = "chain-pq-ci-run-41691371037-full-members.tar.xz"
METADATA = [
    "source-artifacts.json",
    "full-members-manifest.json",
    "four-matrix-controls-summary.json",
    "four-matrix-complete-summary.json",
]
FAILURE_SELECTOR = (
    "store::pq_rollback_witness::tests::"
    "exact_cas_retry_is_idempotent_but_fork_skip_and_wrap_refuse"
)
NEW_TESTS = [
    "pq_rollback_witness::tests::"
    "known_checkpoint_preserves_exact_retry_and_unobserved_other_writer_progress",
    "pq_rollback_witness::tests::"
    "known_checkpoint_refuses_local_cas_conflicts_before_signing_or_transport",
]


def digest_stream(stream):
    digest = hashlib.sha256()
    size = 0
    while True:
        block = stream.read(1024 * 1024)
        if not block:
            break
        size += len(block)
        digest.update(block)
    return size, digest.hexdigest()


def digest_file(path):
    with path.open("rb") as stream:
        size, sha256 = digest_stream(stream)
    return {"bytes": size, "sha256": sha256}


def write_json(path, value):
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def checked_infos(archive):
    infos = archive.infolist()
    names = [info.filename for info in infos]
    if len(names) != len(set(names)):
        raise ValueError("duplicate ZIP member names cannot be silently collapsed")
    for info in infos:
        name = info.filename
        parts = PurePosixPath(name).parts
        if not name or name.startswith("/") or "\\" in name or ".." in parts:
            raise ValueError(f"unexpected ZIP member path: {name!r}")
        kind = stat.S_IFMT(info.external_attr >> 16)
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise ValueError(f"unexpected special ZIP entry: {name!r}")
    return infos


def tar_info(name, size, directory=False):
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.size = 0 if directory else size
    info.mode = 0o755 if directory else 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    return info


def verify_archive(output):
    manifest = json.loads((output / "full-members-manifest.json").read_text())
    expected = {entry["archive_member_path"]: entry for entry in manifest["members"]}
    for filename in METADATA:
        expected[f"metadata/{filename}"] = {
            "kind": "file", **digest_file(output / filename)
        }
    seen = set()
    raw_members = 0
    raw_bytes = 0
    with tarfile.open(output / ARCHIVE, "r:xz") as archive:
        for member in archive:
            if member.name in seen or member.name not in expected:
                raise ValueError(f"unexpected/duplicate TAR member: {member.name}")
            seen.add(member.name)
            wanted = expected[member.name]
            if wanted["kind"] == "directory":
                if not member.isdir():
                    raise ValueError(f"directory type mismatch: {member.name}")
                actual = {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
            else:
                if not member.isfile():
                    raise ValueError(f"regular file type mismatch: {member.name}")
                with archive.extractfile(member) as stream:
                    size, sha256 = digest_stream(stream)
                actual = {"bytes": size, "sha256": sha256}
            if actual != {key: wanted[key] for key in ("bytes", "sha256")}:
                raise ValueError(f"member byte/hash mismatch: {member.name}")
            if not member.name.startswith("metadata/"):
                raw_members += 1
                raw_bytes += actual["bytes"]
    if seen != set(expected):
        raise ValueError(f"missing TAR members: {sorted(set(expected) - seen)}")
    return {
        "archive": {"path": ARCHIVE, **digest_file(output / ARCHIVE)},
        "full_original_members_verified": raw_members,
        "full_original_member_bytes_verified": raw_bytes,
        "metadata_copies_verified": len(METADATA),
        "total_archive_members_verified": len(seen),
        "all_member_lengths_and_sha256_match": True,
        "no_missing_or_extra_members": True,
    }


def build(source, output):
    output.mkdir(parents=True, exist_ok=True)
    generated = [ARCHIVE, *METADATA, "README.md", "archive-verification.json",
                 "package-inventory.json", "SHA256SUMS"]
    if any((output / name).exists() for name in generated):
        raise FileExistsError("refusing to overwrite an existing evidence package")
    supplied_summaries = {}
    for name in METADATA[2:]:
        data = (source / name).read_bytes()
        (output / name).write_bytes(data)
        supplied_summaries[name] = {
            "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "copied_byte_exact": True,
        }
    controls = json.loads((output / METADATA[2]).read_text())
    completes = json.loads((output / METADATA[3]).read_text())
    if {row["artifact_id"] for row in controls} != {lane[2] for lane in LANES}:
        raise ValueError("unexpected control summary artifact set")
    if {row["artifact"] for row in completes} != {lane[1] for lane in LANES}:
        raise ValueError("unexpected complete summary artifact set")
    for lane, full, control, commit, kind in LANES:
        row = next(row for row in controls if row["artifact_id"] == control)
        if (row["commands"], row["passed"], row["failed"]) != (43, 42, 1):
            raise ValueError(f"unexpected retained control outcome: {lane}")
        if row["sources"] != [[commit, TREE, kind]]:
            raise ValueError(f"control source mismatch: {lane}")
        row = next(row for row in completes if row["artifact"] == full)
        for name in ("node-lib.json", "clippy.json", "build.json"):
            receipt = row["records"][name]
            if (receipt["source"], receipt["tree"], receipt["kind"]) != (commit, TREE, kind):
                raise ValueError(f"complete source mismatch: {lane}/{name}")
            if receipt["exit_code"] != (101 if name == "node-lib.json" else 0):
                raise ValueError(f"unexpected original exit code: {lane}/{name}")
        node = row["records"]["node-lib.json"]
        if not any("FAILED. 940 passed; 1 failed; 23 ignored;" in s for s in node["summaries"]):
            raise ValueError(f"missing original failed Node summary: {lane}")
        if any(f"test {name} ... ok" not in node["new_tests"] for name in NEW_TESTS):
            raise ValueError(f"missing added-test success: {lane}")

    sources = []
    members = []
    full_counts = []
    control_coverage = []
    initial_zip_hashes = {}
    for lane, full, control, commit, kind in LANES:
        for role, artifact in (("full", full), ("controls", control)):
            path = source / f"{artifact}.zip"
            identity = digest_file(path)
            initial_zip_hashes[path.name] = identity
            with zipfile.ZipFile(path) as archive:
                infos = checked_infos(archive)
                record = {
                    "lane": lane, "artifact_role": role, "artifact_id": artifact,
                    "original_zip_filename": path.name,
                    "original_zip_bytes": identity["bytes"],
                    "original_zip_sha256": identity["sha256"],
                    "run_id": RUN_ID, "run_url": RUN_URL,
                    "artifact_url": f"{RUN_URL}/artifacts/{artifact}",
                    "download_api_url": f"https://api.github.com/repos/{REPOSITORY}/actions/artifacts/{artifact}/zip",
                    "source_commit": commit, "source_tree": TREE, "source_kind": kind,
                    "zip_member_count": len(infos),
                    "zip_member_uncompressed_bytes": sum(info.file_size for info in infos),
                    "payload_archive_namespace": lane,
                    "original_zip_container_embedded": False,
                }
                if role == "controls":
                    with zipfile.ZipFile(source / f"{full}.zip") as complete:
                        count = 0
                        byte_count = 0
                        for info in infos:
                            # Exact byte comparison, not selected-field comparison.
                            data = archive.read(info)
                            if data != complete.read(info.filename):
                                raise ValueError(f"control payload differs: {lane}/{info.filename}")
                            count += 1
                            byte_count += len(data)
                    coverage = {
                        "lane": lane, "control_artifact_id": control,
                        "full_artifact_id": full, "members_compared": count,
                        "bytes_compared": byte_count, "all_payload_bytes_identical": True,
                        "path_mapping": f"ZIP member path -> {lane}/ZIP member path",
                    }
                    control_coverage.append(coverage)
                    record["all_control_members_covered_by_full"] = coverage
                else:
                    full_counts.append({
                        "lane": lane, "artifact_id": artifact,
                        "members": len(infos),
                        "uncompressed_bytes": sum(info.file_size for info in infos),
                    })
                    for index, info in enumerate(infos):
                        with archive.open(info) as stream:
                            size, sha256 = digest_stream(stream)
                        if size != info.file_size:
                            raise ValueError(f"ZIP length mismatch: {lane}/{info.filename}")
                        members.append({
                            "lane": lane, "artifact_id": artifact,
                            "zip_member_index": index,
                            "zip_member_path": info.filename,
                            "archive_member_path": f"{lane}/{info.filename}",
                            "kind": "directory" if info.is_dir() else "file",
                            "bytes": size, "sha256": sha256,
                            "zip_crc32": f"{info.CRC:08x}",
                        })
                sources.append(record)

    provenance = {
        "schema": "trnm-pq-ci-original-artifact-sources-v1",
        "repository": REPOSITORY, "run_id": RUN_ID, "run_url": RUN_URL,
        "source_scope": {"head_commit": HEAD, "prospective_merge_commit": MERGE, "tree": TREE},
        "hash_semantics": "original_zip_sha256 hashes the exact supplied GitHub ZIP container bytes; the new tar.xz has its own separate identity",
        "acquisition_scope": "Existing downloaded ZIP files supplied by the parent task; this packaging operation does not redownload artifacts or execute Rust",
        "original_zip_containers_embedded": False,
        "representation": "Every uncompressed member from each full ZIP is retained byte-exact under its lane namespace. Every control ZIP member was compared byte-for-byte with the paired full ZIP and is included there. ZIP container bytes and ZIP filesystem metadata are not reconstructed.",
        "artifacts": sources,
        "supplied_summary_files": supplied_summaries,
    }
    manifest = {
        "schema": "trnm-pq-ci-full-artifact-members-v1",
        "run_id": RUN_ID, "original_full_artifact_count": len(LANES),
        "member_count": len(members),
        "member_bytes": sum(row["bytes"] for row in members),
        "namespace_policy": "archive_member_path is lane + '/' + the unchanged original ZIP member path",
        "payload_policy": "No member omitted; no log truncation, text decoding, reformatting, field selection, or result rewriting",
        "container_metadata_policy": "Deterministic PAX TAR uses mtime 0, uid/gid 0, empty owner names and regular-file mode 0644/directory mode 0755; these are packaging metadata, not original ZIP metadata",
        "full_artifacts": full_counts,
        "members": members,
    }
    write_json(output / METADATA[0], provenance)
    write_json(output / METADATA[1], manifest)

    temporary = output / (ARCHIVE + ".partial")
    with lzma.open(temporary, "wb", preset=9 | lzma.PRESET_EXTREME) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
            for lane, full, _, _, _ in LANES:
                with zipfile.ZipFile(source / f"{full}.zip") as original:
                    for info in sorted(checked_infos(original), key=lambda item: item.filename):
                        header = tar_info(f"{lane}/{info.filename}", info.file_size, info.is_dir())
                        if info.is_dir():
                            archive.addfile(header)
                        else:
                            with original.open(info) as stream:
                                archive.addfile(header, stream)
            for name in METADATA:
                data = (output / name).read_bytes()
                archive.addfile(tar_info(f"metadata/{name}", len(data)), io.BytesIO(data))
    temporary.rename(output / ARCHIVE)
    verified = verify_archive(output)
    for name, identity in initial_zip_hashes.items():
        if digest_file(source / name) != identity:
            raise ValueError(f"source ZIP changed during packaging: {name}")
    for name in METADATA[2:]:
        if (source / name).read_bytes() != (output / name).read_bytes():
            raise ValueError(f"summary changed during packaging: {name}")

    verification = {
        "schema": "trnm-pq-ci-repack-verification-v1",
        "packaged_at_utc": datetime.now(timezone.utc).isoformat(),
        **verified,
        "original_zip_containers_hashed": len(sources),
        "original_zip_hashes_unchanged_before_after": True,
        "summary_files_copied_byte_exact": True,
        "original_control_payload_coverage": control_coverage,
        "rust_commands_executed_by_packager": 0,
        "original_failures_relabelled_as_pass": False,
        "later_fix_native_evidence": {
            "commit": FIX, "tree": FIX_TREE,
            "status": "PENDING_AT_HANDOFF_NOT_INCLUDED_IN_THIS_CI_ARCHIVE",
        },
    }
    write_json(output / "archive-verification.json", verification)

    source_table = "\n".join(
        f"| {row['lane']} | {row['artifact_role']} | {row['artifact_id']} | {row['original_zip_bytes']:,} | `{row['original_zip_sha256']}` |"
        for row in sources
    )
    lane_table = "\n".join(
        f"| {lane} | {full} | {control} | {kind} | 42 / 1 of 43 | 940 / 1 / 23 | 0 / 0 |"
        for lane, full, control, _, kind in LANES
    )
    README = f"""# Chain PQ witness CI evidence — original run {RUN_ID}

Status: **original four-lane CI remains FAILED; whole-chain qualification remains HOLD / UNQUALIFIED.**

This package preserves the original results from [GitHub Actions run {RUN_ID}]({RUN_URL}). It is a byte-preserving repack of supplied official artifacts, not a new CI execution or a repaired result. No Rust command was run while preparing this package.

## Exact source scope

- Head source: [`{HEAD}`](https://github.com/{REPOSITORY}/commit/{HEAD}).
- Actual prospective merge: [`{MERGE}`](https://github.com/{REPOSITORY}/commit/{MERGE}).
- Both recorded source trees: `{TREE}`. Equal trees do not make the head and prospective-merge source identities interchangeable.
- The two supplied four-matrix summary JSON files are copied without changing any byte or selecting fields. Original command receipts and complete logs are retained inside the archive.

## Retained original results

Counts are per lane and must not be added together as unique test coverage. The full artifacts retain the same control records as the earlier controls artifacts; those are overlapping evidence, not additional executions.

| Lane | Full artifact ID | Earlier controls artifact ID | Source kind | Controls passed / failed | Full Node passed / failed / ignored | Build / strict Clippy exit codes |
| --- | ---: | ---: | --- | --- | --- | --- |
{lane_table}

All four full Node runs exited **101**, with **940 passed, 1 failed and 23 ignored**. Each original 43-selector controls batch contains **42 successes and 1 failure**. Build and strict Clippy exited **0** in every lane. Both added witness tests passed in each full suite:

- `{NEW_TESTS[0]}`
- `{NEW_TESTS[1]}`

The retained failing selector is `{FAILURE_SELECTOR}`. Its original assertion expected `PQ_WITNESS_CAS` and received `PQ_WITNESS_OBSERVATION_ROLLBACK` at the new client-entry consistency check. Source review identified an expectation mismatch caused by the intended earlier refusal. That explanation does not turn the original test or the full suite into a pass. The archive retains each original exit code, failure log and diagnostic record.

## Later test correction is a separate source

The published correction [`{FIX}`](https://github.com/{REPOSITORY}/commit/{FIX}), tree `{FIX_TREE}`, preserves the original exact retry, sequence-skip and overflow controls, checks the known client's earlier local refusal, and uses a fresh client against the same existing owner to retain the original remote CAS refusal check.

**Native verification of that final correction was pending at this packaging handoff and is not contained in this archive.** These `45962558` / `9762e8e5` results cannot be relabelled as execution of `8a74a9e4`. The parent task will attach any later exact-source native receipt separately, retaining earlier failures.

The separately supplied local `witness-validation-45962558.tar.gz` receipt is not included here and does not supply final-correction evidence. Its parent-task identity is 105,006 bytes, SHA-256 `9dc5fc7159c99811dab7185fde572ba8d9cedeefe5d4e95320761f310f6c10ea`; publication of that independent local record is handled separately.

## Archive identity and byte preservation

- Archive: [`{ARCHIVE}`]({ARCHIVE})
- Compressed bytes: **{verified['archive']['bytes']:,}**
- Archive SHA-256: `{verified['archive']['sha256']}`
- Original full-ZIP payload members: **{verified['full_original_members_verified']}**, totalling **{verified['full_original_member_bytes_verified']:,} bytes**.
- All **636** earlier control-ZIP members were compared byte-for-byte against their paired full ZIPs; every one is identical and is already retained in the full payloads.
- The archive contains **{verified['total_archive_members_verified']}** members: **652 original payload members plus 4 metadata copies**.

Each original full member is stored under one namespace: `x64-head/`, `arm64-head/`, `arm64-merge/` or `x64-merge/`. Its bytes are unchanged. No log is truncated or reformatted, and no JSON field is discarded. `metadata/` contains byte-identical copies of the two manifests and two summaries presented alongside this README.

**The new TAR/XZ hash is not any original GitHub ZIP hash.** The archive preserves uncompressed ZIP member bytes, not the original ZIP container representation, its central directory or its filesystem metadata. The original container sizes and hashes below apply only to the supplied `.zip` files. Deterministic TAR metadata is documented in `full-members-manifest.json`.

| Lane | Artifact role | Original ZIP artifact ID | Original ZIP bytes | Original ZIP SHA-256 |
| --- | --- | ---: | ---: | --- |
{source_table}

## Browse and verify

- [`source-artifacts.json`](source-artifacts.json): all eight original ZIP sizes, hashes, run/artifact URLs and source identities; exact control-to-full coverage.
- [`full-members-manifest.json`](full-members-manifest.json): every original full member's source artifact, original path, archive path, byte count, SHA-256 and original CRC32.
- [`four-matrix-controls-summary.json`](four-matrix-controls-summary.json): unchanged supplied summary, including all failures and diagnostic fields.
- [`four-matrix-complete-summary.json`](four-matrix-complete-summary.json): unchanged supplied build, strict Clippy and full Node summary.
- [`archive-verification.json`](archive-verification.json): archive identity and verification of every payload and metadata member against the manifests, plus unchanged-input checks.
- [`package-inventory.json`](package-inventory.json) and [`SHA256SUMS`](SHA256SUMS): outer package file inventory and hashes, with explicit self-exclusions.
- [`package-ci-evidence.py`](package-ci-evidence.py): standard-library-only packager and archive verifier; it executes no repository code.

To verify the downloaded package without extracting its logs or rerunning tests:

```sh
sha256sum -c SHA256SUMS
python3 package-ci-evidence.py --verify-only
```

The verifier requires all 652 original members, checks every member length and SHA-256, compares all four embedded metadata files with their outer copies, and refuses missing, duplicate or extra members. This establishes packaging integrity relative to the recorded supplied artifacts; it is not a cryptographic attestation of test execution or whole-chain security qualification.
"""
    (output / "README.md").write_text(README, encoding="utf-8")
    inventory = {
        "schema": "trnm-pq-ci-package-inventory-v1",
        "self_exclusions": ["package-inventory.json", "SHA256SUMS"],
        "note": "SHA256SUMS separately includes package-inventory.json and excludes itself",
        "files": [
            {"path": path.name, **digest_file(path)}
            for path in sorted(output.iterdir()) if path.is_file()
        ],
    }
    write_json(output / "package-inventory.json", inventory)
    checksums = "".join(
        f"{digest_file(path)['sha256']}  {path.name}\n"
        for path in sorted(output.iterdir())
        if path.is_file() and path.name != "SHA256SUMS"
    )
    (output / "SHA256SUMS").write_text(checksums, encoding="ascii")
    print(json.dumps({"output": str(output), **verified,
                      "file_inventory": [p.name for p in sorted(output.iterdir())]}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path,
                        default=Path("/workspace/scratch/6f4fef89e370/pq-ci-controls-20261103"))
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    if args.verify_only:
        actual = verify_archive(args.output)
        recorded = json.loads((args.output / "archive-verification.json").read_text())
        for key, value in actual.items():
            if recorded.get(key) != value:
                raise ValueError(f"recorded archive verification differs: {key}")
        print(json.dumps(actual, indent=2))
    else:
        build(args.source, args.output)


if __name__ == "__main__":
    main()
