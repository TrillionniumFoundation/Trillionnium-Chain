#!/usr/bin/env python3
"""Read immutable C1 CI ZIPs and emit a compact diagnostic packet.

No archive member is executed. No native test is run. The source ZIP is opened
read-only. All generated files are outside any checkout and in a new directory.
Original ZIP bytes and the complete ZIP member hashes remain separately bound;
JSON projections are explicitly labelled and never replace original reports.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import zipfile

HEAD = "c09dbbe9921da12db8bf7240a8a95a0e9a789e50"
TREE = "f15a7ee4a0f5455eaf965db01dcd49e02a5f22b6"
EXPECTED = {
    "campaign": {
        "run_id": 42955583039, "job_id": 130309763995,
        "artifact_id": 13829055578, "bytes": 70936486,
        "sha256": "078f427e72d34dc1b0a96f13d16a231d78e9c949656ae57b1fe52665c91cfebe",
    },
    "cost-arm64": {
        "run_id": 42955583052, "job_id": 130309764639,
        "artifact_id": 13828821111, "bytes": 9018574,
        "sha256": "e9236a8d2bb85e343d1faa842a2b0e463593a7f7445649513eb835a369707de5",
    },
    "cost-x64": {
        "run_id": 42955583052, "job_id": 130309764652,
        "artifact_id": 13828657982, "bytes": 9298938,
        "sha256": "ceeaca9e857020eec7dc948e2a2b92ee5aa3e2bbf208270779fceb1284811946",
    },
}
MAX_UNCOMPRESSED = 2 * 1024**3
MAX_JSON = 128 * 1024**2
SMALL_RAW = 128 * 1024
RAW_TOTAL = 48 * 1024**2


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stream_hash(stream) -> tuple[str, int]:
    h, size = hashlib.sha256(), 0
    while chunk := stream.read(1024 * 1024):
        h.update(chunk)
        size += len(chunk)
    return h.hexdigest(), size


def json_bytes(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key {key!r}")
        obj[key] = value
    return obj


def json_load(raw: bytes):
    if len(raw) > MAX_JSON:
        raise ValueError("JSON exceeds explicit diagnostic reader limit")
    return json.loads(raw, object_pairs_hook=unique_pairs)


def safe_name(name: str) -> None:
    p = PurePosixPath(name)
    if (not name or "\\" in name or "\x00" in name or p.is_absolute()
            or ".." in p.parts or str(p) != name.rstrip("/")):
        raise ValueError(f"unsafe or noncanonical ZIP member {name!r}")


def write_new(root: Path, name: str, data: bytes):
    safe_name(name)
    target = root.joinpath(*PurePosixPath(name).parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        stream.write(data)


def projection(value, *, budget: int = SMALL_RAW):
    """Keep complete scalar/small fields; label each excluded large field."""
    if not isinstance(value, dict):
        return {"value": value, "omitted_fields": {}}
    kept, omitted = {}, {}
    for key, item in value.items():
        encoded = json_bytes(item)
        if not isinstance(item, (dict, list)) or len(encoded) <= budget:
            kept[key] = item
        else:
            omitted[key] = {
                "json_type": type(item).__name__, "length": len(item),
                "reencoded_json_sha256": sha(encoded),
                "reencoded_json_bytes": len(encoded),
                "reason": "explicit projection size bound; original retained in source ZIP",
            }
    return {"retained_original_field_values": kept, "omitted_fields": omitted}


def original_phase_projection(phase: dict):
    # Preserve these complete original values even when large. No reader verdict
    # or new criterion is substituted for the Rust report's own observations.
    fields = {
        "confirmations", "budget_samples", "depletion_meter", "initial_meter",
        "final_meter", "final_actual_flow", "service_outcome", "verifier_errors",
        "attack_calls_overlapping_each_signed_round", "public_resource_policy",
        "phase_process_context", "external_controller_observation",
        "completion_work_observation", "children_os_usage_after",
        "children_os_usage_before", "public_phase_children_os_usage_after",
        "public_phase_children_os_usage_before", "rss", "submissions",
    }
    kept, omitted = {}, {}
    for key, value in phase.items():
        if key in fields or not isinstance(value, (dict, list)):
            kept[key] = value
        else:
            encoded = json_bytes(value)
            omitted[key] = {"json_type": type(value).__name__, "length": len(value),
                "reencoded_json_sha256": sha(encoded), "reencoded_json_bytes": len(encoded)}
    # History errors and clocks are preserved without arbitrarily copying huge
    # wire/history payloads. Each projection retains its exact original index.
    if isinstance(phase.get("history"), list):
        kept["history_field_projections"] = [
            {"original_index": index, **projection(row, budget=8192)}
            for index, row in enumerate(phase["history"])
        ]
    return {"retained_original_field_values": kept, "omitted_fields": omitted}


def campaign_observation(z: zipfile.ZipFile, members: dict, destination: Path):
    result = json_load(z.read("results.json"))
    if result.get("expected_head") != HEAD or result.get("expected_tree") != TREE:
        raise ValueError("campaign result source is not the fixed C1 head/tree")
    after = result.get("source_after", {})
    if after.get("tested_commit") != HEAD or after.get("tested_tree") != TREE:
        raise ValueError("campaign source-after does not match fixed C1 head/tree")
    attempts = result.get("attempts")
    if not isinstance(attempts, list) or [a.get("number") for a in attempts] != [1, 2, 3]:
        raise ValueError("expected three original campaign observations")
    rows = []
    for attempt in attempts:
        n = attempt["number"]
        name = f"run-{n}-raw/report.json"
        raw = z.read(name)
        if sha(raw) != attempt.get("report_sha256"):
            raise ValueError(f"result-to-report hash mismatch: {name}")
        report = json_load(raw)
        phases = report.get("phases")
        if not isinstance(phases, list):
            raise ValueError(f"missing actual phase observations in {name}")
        projected = {
            "schema": "c1-original-campaign-report-projection-v1",
            "source_member": name, "source_bytes": len(raw), "source_sha256": sha(raw),
            "scope": "original field values selected from a verified report; not a full report or qualification",
            "top_level": projection({k: v for k, v in report.items() if k != "phases"}),
            "phases": [original_phase_projection(phase) for phase in phases],
        }
        write_new(destination, f"projections/run-{n}-report.json", json_bytes(projected))
        phase_rows = []
        for index, phase in enumerate(phases):
            fields = (
                "mode", "state_backend", "duration_seconds", "finite_phase_criteria_met",
                "all_signed_rounds_confirmed_in_window", "genuine_budget_depletion_observed",
                "depletion_at_ns", "receiver_client_state_equal", "verifier_errors",
                "startup_or_campaign_error", "actor_reports_successful_without_cap_or_kill",
                "attacker_processes_requested", "attacker_processes_ready", "business_started_ns",
            )
            phase_rows.append({"original_phase_index": index,
                "present_original_fields": {key: phase[key] for key in fields if key in phase},
                "absent_fields": [key for key in fields if key not in phase],
                "confirmation_count": len(phase["confirmations"]) if isinstance(phase.get("confirmations"), list) else None,
                "budget_sample_count": len(phase["budget_samples"]) if isinstance(phase.get("budget_samples"), list) else None,
            })
        rows.append({"attempt": attempt, "report_member": members[name],
            "original_top_level_flags": {key: report.get(key) for key in (
                "schema", "state_backend", "finite_experiment_criteria_met", "economics_complete",
                "production_candidate", "release_ready", "wan_qualified", "independent_operators",
                "cryptographic_hardness_qualified", "work_profile_qualified")}, "phases": phase_rows})
    observation = {"schema": "c1-original-native-artifact-observation-v1",
        "source_head": HEAD, "source_tree": TREE, "results": result, "runs": rows,
        "native_executions_started_by_this_reader": 0,
        "qualification_inferred": False}
    write_new(destination, "campaign-observation.json", json_bytes(observation))


def inspect(kind: str, path: Path, out: Path):
    expected = EXPECTED[kind]
    if path.is_symlink() or not path.is_file():
        raise ValueError("input must be an existing regular ZIP, not a symlink")
    with path.open("rb") as stream:
        digest, size = stream_hash(stream)
    if size != expected["bytes"] or digest != expected["sha256"]:
        raise ValueError(f"{kind}: ZIP does not match the recorded GitHub artifact size/digest")
    destination = out / kind
    destination.mkdir()
    members, directories = {}, []
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if len({info.filename for info in infos}) != len(infos):
            raise ValueError("duplicate ZIP member")
        if sum(info.file_size for info in infos) > MAX_UNCOMPRESSED:
            raise ValueError("ZIP exceeds explicit uncompressed byte bound")
        for info in infos:
            safe_name(info.filename)
            if info.flag_bits & 1:
                raise ValueError("encrypted ZIP member")
            mode = info.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if info.is_dir():
                directories.append(info.filename)
                continue
            if file_type not in (0, stat.S_IFREG):
                raise ValueError(f"nonregular archive member {info.filename}")
            with z.open(info) as stream:
                actual_digest, actual_size = stream_hash(stream)
            if actual_size != info.file_size:
                raise ValueError("ZIP member size mismatch")
            members[info.filename] = {"path": info.filename, "bytes": actual_size,
                "sha256": actual_digest, "zip_crc32": f"{info.CRC:08x}",
                "compressed_bytes": info.compress_size, "zip_external_mode": mode}
        manifest_status = {"present": "artifact-files.json" in members,
                           "all_listed_files_verified": None, "complete_coverage": None}
        if "artifact-files.json" in members:
            embedded = json_load(z.read("artifact-files.json"))
            records = embedded.get("files")
            if not isinstance(records, list):
                raise ValueError("embedded manifest files is not a list")
            names = [row["path"] for row in records]
            if len(set(names)) != len(names):
                raise ValueError("duplicate embedded manifest path")
            for row in records:
                observed = members.get(row["path"])
                if observed is None or row["sha256"] != observed["sha256"] or row["bytes"] != observed["bytes"]:
                    raise ValueError(f"embedded manifest mismatch: {row['path']}")
            covered = set(names) == set(members) - {"artifact-files.json"}
            if not covered:
                raise ValueError("embedded manifest does not cover every other regular member")
            manifest_status = {"present": True, "listed_file_count": len(records),
                "all_listed_files_verified": True, "complete_coverage": True,
                "manifest_member_sha256": members["artifact-files.json"]["sha256"]}
        elif kind == "campaign":
            raise ValueError("original campaign embedded manifest missing")
        nested_native_manifests = []
        if kind != "campaign":
            for name, meta in sorted(members.items()):
                if PurePosixPath(name).name != "manifest.json" or meta["bytes"] > MAX_JSON:
                    continue
                native = json_load(z.read(name))
                if not isinstance(native, dict) or native.get("schema") != "trnm-from-zero-native-execution-v3":
                    continue
                prefix = name[:-len("manifest.json")]
                files = native.get("files")
                status = {"manifest": name, "manifest_sha256": meta["sha256"],
                          "files_mapping_present": isinstance(files, dict),
                          "all_listed_hashes_verified": None, "complete_scope_coverage": None}
                for boundary in ("source_before", "source_after"):
                    identity = native.get(boundary)
                    status[boundary] = identity
                    if identity is not None and (identity.get("commit") != HEAD or identity.get("tree") != TREE):
                        raise ValueError(f"{kind}: native {boundary} is not C1")
                if isinstance(files, dict):
                    listed = set()
                    for relative, expected_digest in files.items():
                        safe_name(relative)
                        member = prefix + relative
                        observed = members.get(member)
                        if observed is None or expected_digest != observed["sha256"]:
                            raise ValueError(f"native manifest hash mismatch: {member}")
                        listed.add(member)
                    scope = {n for n in members if n.startswith(prefix)} - {name}
                    status.update(all_listed_hashes_verified=True, listed_file_count=len(files),
                                  complete_scope_coverage=listed == scope,
                                  unlisted_scope_members=sorted(scope - listed))
                nested_native_manifests.append(status)
        retained, omitted, total = [], [], 0
        for name, meta in sorted(members.items()):
            # Root campaign metadata/readback is kept verbatim. Nested small
            # reports and logs are selected deterministically with explicit caps.
            suffix = PurePosixPath(name).suffix
            basename = PurePosixPath(name).name
            eligible = suffix in (".json", ".log", ".txt", ".py", ".csv", ".tsv") or basename in ("stdout", "stderr")
            root_campaign = kind == "campaign" and "/" not in name
            important_diagnostic = basename in ("manifest.json", "stdout", "stderr") or suffix == ".log"
            cap = 8 * 1024**2 if root_campaign or important_diagnostic else SMALL_RAW
            if eligible and meta["bytes"] <= cap and total + meta["bytes"] <= RAW_TOTAL:
                raw = z.read(name)
                write_new(destination, "raw/" + name, raw)
                retained.append(meta)
                total += len(raw)
            else:
                omitted.append({"path": name, "bytes": meta["bytes"], "sha256": meta["sha256"],
                    "reason": "not selected by diagnostic suffix/size/total bound; retained in immutable source ZIP"})
                # Non-campaign result/report JSON may contain large wire fields.
                # Keep labelled top-level scalar and small field projections too.
                if kind != "campaign" and suffix == ".json" and meta["bytes"] <= MAX_JSON:
                    value = json_load(z.read(name))
                    if isinstance(value, dict):
                        doc = {
                            "source_member": meta, "scope": "labelled JSON field projection",
                            **projection(value)}
                        if isinstance(value.get("phases"), list):
                            doc["phase_projections"] = [{"original_phase_index": i, **projection(phase)}
                                                        for i, phase in enumerate(value["phases"])]
                        write_new(destination, "projections/" + name, json_bytes(doc))
        if kind == "campaign":
            campaign_observation(z, members, destination)
    record = {"schema": "c1-ci-artifact-complete-byte-verification-v1", "kind": kind,
        "artifact": expected, "observed_input_path": str(path), "zip_bytes": size,
        "zip_sha256": digest, "all_regular_members_read_and_hashed": True,
        "regular_member_count": len(members), "directory_count": len(directories),
        "uncompressed_regular_bytes": sum(row["bytes"] for row in members.values()),
        "embedded_manifest": manifest_status, "nested_native_manifests": nested_native_manifests,
        "native_commands_executed": False,
        "source_zip_modified": False, "retained_raw_bytes": total,
        "retained_raw_members": retained, "omitted_raw_members": omitted,
        "scope": "artifact integrity and retained native observations; no production/PQ qualification"}
    write_new(destination, "zip-member-index.json", json_bytes(list(members.values())))
    write_new(destination, "artifact-verification.json", json_bytes(record))
    return {key: record[key] for key in ("kind", "artifact", "zip_bytes", "zip_sha256",
        "regular_member_count", "uncompressed_regular_bytes", "embedded_manifest", "retained_raw_bytes")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for kind in EXPECTED:
        parser.add_argument("--" + kind, type=Path)
    parser.add_argument("--out", type=Path, required=True,
                        help="new directory; the .tar.xz packet is created beside it")
    args = parser.parse_args()
    if not any(getattr(args, kind.replace("-", "_")) for kind in EXPECTED):
        parser.error("at least one recorded C1 ZIP is required")
    out = args.out.absolute()
    if out.exists() or out.is_symlink() or out.with_suffix(".tar.xz").exists():
        parser.error("output directory/packet already exists; refusing overwrite")
    out.mkdir(parents=True)
    try:
        observations = []
        for kind in EXPECTED:
            path = getattr(args, kind.replace("-", "_"))
            if path:
                observations.append(inspect(kind, path.absolute(), out))
        script = Path(__file__).read_bytes()
        write_new(out, "extract_c1_native_artifacts.py", script)
        write_new(out, "packet-observation.json", json_bytes({
            "schema": "c1-hosted-native-read-only-packet-v1",
            "observed_utc": datetime.now(timezone.utc).isoformat(),
            "expected_head": HEAD, "expected_tree": TREE,
            "script_sha256": sha(script), "artifacts": observations,
            "native_tests_run": 0, "repository_edits": False,
            "old_315_outcomes_used": False, "qualification_inferred": False,
        }))
        inventory = [{"path": str(p.relative_to(out)), "bytes": p.stat().st_size,
                      "sha256": sha(p.read_bytes())} for p in sorted(out.rglob("*")) if p.is_file()]
        write_new(out, "packet-files.json", json_bytes(inventory))
        write_new(out, "SHA256SUMS", "".join(f"{r['sha256']}  {r['path']}\n" for r in inventory).encode())
        packet = out.with_suffix(".tar.xz")
        with packet.open("xb") as target:
            with tarfile.open(fileobj=target, mode="w:xz", preset=6) as archive:
                for p in sorted(out.rglob("*")):
                    if not p.is_file() or p.is_symlink():
                        continue
                    raw = p.read_bytes()
                    info = tarfile.TarInfo(str(p.relative_to(out)))
                    info.size, info.mode, info.mtime = len(raw), 0o644, 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    archive.addfile(info, io.BytesIO(raw))
        with packet.open("rb") as stream:
            packet_sha, packet_size = stream_hash(stream)
        result = {"packet": str(packet), "bytes": packet_size, "sha256": packet_sha,
                  "artifacts": observations, "native_tests_run": 0}
        with packet.with_suffix(packet.suffix + ".sha256").open("x") as stream:
            stream.write(f"{packet_sha}  {packet.name}\n")
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        write_new(out, "reader-failure.json", json_bytes({
            "error_type": type(error).__name__, "error": str(error),
            "native_tests_run": 0, "partial_output_is_not_a_complete_verification": True}))
        raise


if __name__ == "__main__":
    main()
