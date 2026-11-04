#!/usr/bin/env python3
"""Bounded read-only inspection of two frozen original Actions artifacts.

No archive member is extracted or executed. Download and ZIP/JSON validation
success is evidence-readback success, never native or business qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPOSITORY = "TrillionniumFoundation/Trillionnium-Chain"
REPOSITORY_ID = 1323087357
BRANCH = "refs/heads/research/chain-original-cpu-readback-20261103-gpt6"
COMPRESSED_BUDGET = 96 * 1024 * 1024
DECODED_BUDGET = 512 * 1024 * 1024
MEMBER_BUDGET = 256 * 1024 * 1024
JSON_MEMBER_BUDGET = 16 * 1024 * 1024
JSON_RETAINED_BUDGET = 64 * 1024 * 1024
PRINT_BUDGET = 2 * 1024 * 1024
CHUNK = 64 * 1024


class Rejected(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise Rejected(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def finite_float(value):
    number = float(value)
    require(math.isfinite(number), "NONFINITE_JSON_NUMBER")
    return number


def parse_json(data):
    def invalid_constant(_value):
        raise Rejected("NONFINITE_JSON_CONSTANT")
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_float=finite_float, parse_constant=invalid_constant)


def safe_url(url):
    parts = urllib.parse.urlsplit(url)
    require(parts.scheme == "https" and parts.hostname is not None
            and parts.username is None and parts.password is None
            and parts.port in (None, 443) and not parts.fragment,
            "ARCHIVE_URL_NOT_HTTPS")
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpsRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        safe_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def api_request(path, token):
    require(path.startswith("/repos/" + REPOSITORY + "/"), "API_REPOSITORY")
    return urllib.request.Request("https://api.github.com" + path, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "trnm-frozen-artifact-readback",
    })


def api_json(path, token):
    with urllib.request.build_opener(NoRedirect()).open(
            api_request(path, token), timeout=60) as response:
        payload = response.read(1024 * 1024 + 1)
    require(len(payload) <= 1024 * 1024, "API_JSON_BUDGET")
    return parse_json(payload)


def archive_location(artifact_id, token):
    request = api_request(
        f"/repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip", token)
    try:
        with urllib.request.build_opener(NoRedirect()).open(
                request, timeout=60) as response:
            raise Rejected("ARCHIVE_REDIRECT_REQUIRED")
    except urllib.error.HTTPError as error:
        try:
            require(error.code in (302, 303, 307), "ARCHIVE_REDIRECT_STATUS")
            location = error.headers.get("Location")
            require(isinstance(location, str), "ARCHIVE_REDIRECT_LOCATION")
            return safe_url(location)
        finally:
            error.close()


def check_metadata(spec, artifact, run, commit):
    require(artifact.get("id") == spec["artifact_id"]
            and artifact.get("name") == spec["artifact_name"]
            and artifact.get("size_in_bytes") == spec["bytes"]
            and artifact.get("digest") == "sha256:" + spec["sha256"]
            and artifact.get("expired") is False, "ARTIFACT_METADATA_CHANGED")
    workflow = artifact.get("workflow_run", {})
    require(workflow.get("id") == spec["run_id"]
            and workflow.get("head_sha") == spec["source"]
            and workflow.get("repository_id") == REPOSITORY_ID
            and workflow.get("head_repository_id") == REPOSITORY_ID,
            "ARTIFACT_WORKFLOW_SOURCE")
    require(run.get("id") == spec["run_id"]
            and run.get("head_sha") == spec["source"]
            and run.get("run_attempt") == 1
            and run.get("status") == "completed"
            and run.get("conclusion") == "failure", "ORIGINAL_FAILED_RUN_REQUIRED")
    require(commit.get("sha") == spec["source"]
            and commit.get("tree", {}).get("sha") == spec["tree"],
            "SOURCE_COMMIT_TREE")


def download(spec, token, path, budget):
    require(spec["bytes"] <= budget["compressed"], "COMPRESSED_TOTAL_BUDGET")
    location = archive_location(spec["artifact_id"], token)
    # The API Authorization header is deliberately absent from this new request.
    request = urllib.request.Request(location, headers={
        "User-Agent": "trnm-frozen-artifact-readback"})
    digest = hashlib.sha256()
    count = 0
    with urllib.request.build_opener(HttpsRedirect()).open(
            request, timeout=60) as response, path.open("xb") as output:
        while True:
            block = response.read(min(CHUNK, spec["bytes"] - count + 1))
            if not block:
                break
            count += len(block)
            budget["compressed"] -= len(block)
            require(count <= spec["bytes"] and budget["compressed"] >= 0,
                    "COMPRESSED_STREAM_BUDGET")
            digest.update(block)
            output.write(block)
    require(count == spec["bytes"] and digest.hexdigest() == spec["sha256"],
            "ARCHIVE_BYTES_OR_DIGEST")


def validate_members(infos, remaining):
    require(0 < len(infos) <= 10000, "MEMBER_COUNT")
    seen = set()
    total = 0
    for info in infos:
        name = info.filename
        require(isinstance(name, str) and name and "\\" not in name
                and not any(ord(c) < 32 or ord(c) == 127 for c in name),
                "MEMBER_PATH_ENCODING")
        bare = name[:-1] if info.is_dir() else name
        require(bare and not bare.startswith("/")
                and not re.match(r"^[A-Za-z]:", bare)
                and all(p not in ("", ".", "..") for p in bare.split("/")),
                "MEMBER_PATH")
        require(name not in seen, "DUPLICATE_MEMBER")
        seen.add(name)
        mode = info.external_attr >> 16
        require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR),
                "MEMBER_TYPE")
        require(not (info.flag_bits & 1), "ENCRYPTED_MEMBER")
        require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                "MEMBER_COMPRESSION")
        require(0 <= info.file_size <= MEMBER_BUDGET, "MEMBER_SIZE")
        total += info.file_size
        require(total <= remaining, "DECLARED_DECODED_TOTAL")
    return total


def wanted_json(name, spec):
    if name in spec["required_json"]:
        return True
    path = PurePosixPath(name)
    if not name.endswith(".json"):
        return False
    if path.name in ("controller-result.json", "child-result.json",
                     "phase-result.json"):
        return True
    return len(path.parts) <= 2 and path.name not in (
        "artifact-files.json", "log-files.json", "files.json")


def inspect_zip(path, spec, budget):
    files, documents = {}, {}
    retained = 0
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        declared = validate_members(infos, budget["decoded"])
        for info in infos:
            selected = not info.is_dir() and wanted_json(info.filename, spec)
            if selected:
                require(info.file_size <= JSON_MEMBER_BUDGET, "SELECTED_JSON_SIZE")
                retained += info.file_size
                require(retained <= JSON_RETAINED_BUDGET, "SELECTED_JSON_TOTAL")
            parts = [] if selected else None
            digest = hashlib.sha256()
            count = 0
            # Every member reaches EOF, so zipfile checks the original CRC.
            # No paths from the ZIP are used for writes or command execution.
            with archive.open(info) as member:
                while True:
                    block = member.read(min(CHUNK, budget["decoded"] + 1))
                    if not block:
                        break
                    count += len(block)
                    budget["decoded"] -= len(block)
                    require(count <= info.file_size and budget["decoded"] >= 0,
                            "RETURNED_DECODED_BUDGET")
                    digest.update(block)
                    if parts is not None:
                        parts.append(block)
            require(count == info.file_size, "MEMBER_SHORT_READ")
            files[info.filename] = {
                "bytes": count, "sha256": digest.hexdigest(),
                "crc32": f"{info.CRC:08x}", "directory": info.is_dir(),
            }
            if parts is not None:
                documents[info.filename] = parse_json(b"".join(parts))
    require(all(name in documents for name in spec["required_json"]),
            "REQUIRED_JSON_MISSING")
    for name in spec["source_json"]:
        source = documents[name]
        require(source.get("schema") == "trnm-ci-source-v1"
                and source.get("candidate") == spec["source"]
                and source.get("tested_commit") == spec["source"]
                and source.get("tested_tree") == spec["tree"]
                and source.get("tracked_worktree_verified") is True,
                "ORIGINAL_SOURCE_RECEIPT")
    if spec["kind"] == "campaign":
        result = documents["results.json"]
        require(result.get("schema") == "pon-original-native-campaign-ci-v1"
                and result.get("expected_head") == spec["source"]
                and result.get("expected_tree") == spec["tree"]
                and result.get("complete_success") is False
                and result.get("failure") == "ORIGINAL_THREE_RUN_CAMPAIGN_FAILED",
                "ORIGINAL_CAMPAIGN_RESULT")
        require(result.get("original_inputs") == {
            "attacker_processes": [0, 24, 24], "business_blocks": 21,
            "modes": ["baseline", "from-zero", "late-product"],
            "phase_seconds": 30, "seed_blocks": 4, "seed_transfers": 1024,
        }, "ORIGINAL_CAMPAIGN_INPUTS")
        binary = result["binary"]
        require(files["public_v3_multiprocess.bin"]["sha256"]
                == binary["sha256_before"] == binary["sha256_after"]
                and files["public_v3_multiprocess.bin"]["bytes"] == binary["bytes"],
                "ORIGINAL_NATIVE_BINARY")
        attempts = result["attempts"]
        require(len(attempts) == 3, "ORIGINAL_ATTEMPTS")
        for ordinal, attempt in enumerate(attempts, 1):
            report_name = f"run-{ordinal}-raw/report.json"
            require(attempt["number"] == ordinal
                    and attempt["report_sha256"] == files[report_name]["sha256"],
                    "ORIGINAL_REPORT_HASH")
    return files, documents, declared


BLOCKED = re.compile(
    r"header|packet|transaction|signature|private|secret|payload|state_rows|"
    r"proof|witness|seed$|business$|key_material|signed_request|raw_body",
    re.IGNORECASE)
STRING_FIELDS = {
    "schema", "mode", "kind", "state_backend", "status", "phase", "method",
    "profile", "source_kind", "tested_commit", "tested_tree", "candidate",
    "cpu_max", "memory_max", "memory_swap_max", "pids_max", "name",
}
ERROR_FIELDS = re.compile(r"error|failure|reason|refusal", re.IGNORECASE)
KNOWN_CODES = (
    "PUBLIC_REQUEST_DEADLINE", "CPU_BUDGET", "ROOT", "UNKNOWN_PARENT",
    "OwnerReorgTerminationCpuRequired", "FRESH_NATIVE_PROCESS_REQUIRED",
    "CONFIRMATION_TARGET", "WouldBlock", "TimedOut", "ConnectionRefused",
    "BROKEN_PIPE", "HOST_", "ARCHITECTURE_", "ORIGINAL_",
)



def aggregate_records(rows):
    groups = {}
    for row in rows:
        if not isinstance(row, dict):
            group_key = ("malformed", None)
        else:
            op = row.get("operation")
            dispatch = row.get("dispatch_started")
            group_key = (op if op is None or type(op) is int else "unknown",
                         dispatch if type(dispatch) is bool else None)
        group = groups.setdefault(group_key, {"rows": 0, "numeric": {}, "nulls": {}})
        group["rows"] += 1
        def visit(item, path="", depth=0):
            if depth > 8:
                return
            if item is None:
                group["nulls"][path] = group["nulls"].get(path, 0) + 1
            elif type(item) in (int, float):
                group["numeric"].setdefault(path, []).append(item)
            elif isinstance(item, dict):
                for name, child in item.items():
                    if (re.fullmatch(r"[A-Za-z0-9_]{1,80}", name)
                            and not BLOCKED.search(name)):
                        visit(child, f"{path}.{name}" if path else name, depth + 1)
        visit(row)
    result = []
    for (op, dispatch), group in groups.items():
        statistics = {}
        for name, values in group["numeric"].items():
            values.sort()
            statistics[name] = {
                "samples": len(values), "sum": sum(values),
                "min": values[0], "max": values[-1],
                "p50_nearest_rank": values[max(0, math.ceil(len(values) * .50) - 1)],
                "p95_nearest_rank": values[max(0, math.ceil(len(values) * .95) - 1)],
                "p99_nearest_rank": values[max(0, math.ceil(len(values) * .99) - 1)],
            }
        result.append({"operation": op, "dispatch_started": dispatch,
                       "recorded_rows": group["rows"], "statistics": statistics,
                       "null_counts": group["nulls"]})
    return {"recorded_rows": len(rows), "groups": result,
            "scope": "all recorded numeric fields per original operation; nested costs are not additive; no network latency or business acceptance claim"}

def projection(value, key="", depth=0):
    if depth > 16:
        return {"omitted_deeper_structure": True}
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if key in STRING_FIELDS and re.fullmatch(r"[A-Za-z0-9_./: +\-]{0,160}", value):
            return value
        if ERROR_FIELDS.search(key):
            return {"text_sha256": hashlib.sha256(value.encode()).hexdigest(),
                    "characters": len(value),
                    "known_codes": [code for code in KNOWN_CODES if code in value],
                    "literal_code": value if re.fullmatch(
                        r"[A-Z][A-Z0-9_]{0,100}", value) else None}
        return {"omitted_string_sha256": hashlib.sha256(value.encode()).hexdigest(),
                "characters": len(value)}
    if isinstance(value, list):
        if key == "records":
            return aggregate_records(value)
        if key == "budget_samples":
            return {"recorded_samples": len(value),
                    "first": projection(value[0], "", depth + 1) if value else None,
                    "last": projection(value[-1], "", depth + 1) if value else None,
                    "scope": "endpoint projection only; all original samples remain in the verified archive"}
        return [projection(item, key, depth + 1) for item in value]
    if isinstance(value, dict):
        return {name: projection(item, name, depth + 1)
                for name, item in value.items()
                if not BLOCKED.search(name)
                and name not in ("economics", "children", "preparation",
                                 "environment", "command", "cwd", "scope")}
    raise Rejected("JSON_VALUE_TYPE")


def phase_summary(report):
    phases = report.get("phases")
    if not isinstance(phases, list):
        return None
    output = []
    for phase in phases:
        require(isinstance(phase, dict), "PHASE_OBJECT")
        confirmations = phase.get("confirmations", [])
        require(isinstance(confirmations, list), "CONFIRMATION_ARRAY")
        output.append({
            "mode": phase.get("mode"),
            "duration_seconds": phase.get("duration_seconds"),
            "attacker_processes_requested": phase.get("attacker_processes_requested"),
            "attacker_processes_ready": phase.get("attacker_processes_ready"),
            "planned_signed_rounds": 3,
            "recorded_rounds": len(confirmations),
            "confirmed_rounds": sum(
                row.get("confirmed_inside_pressure_window") is True
                for row in confirmations if isinstance(row, dict)),
            "finite_phase_criteria_met": phase.get("finite_phase_criteria_met"),
            "all_signed_rounds_confirmed_in_window":
                phase.get("all_signed_rounds_confirmed_in_window"),
            "startup_or_campaign_error": projection(
                phase.get("startup_or_campaign_error"), "error"),
            "root_criteria": phase.get("root_supplement", {}).get("criteria_met"),
        })
    return output


def self_test():
    count = 0
    def rejects(function, code):
        nonlocal count
        try:
            function()
        except Rejected as error:
            require(str(error) == code, "SELF_TEST_WRONG_REJECTION")
        else:
            raise Rejected("SELF_TEST_ACCEPTED_NEGATIVE")
        count += 1
    valid = zipfile.ZipInfo("nested/report.json")
    valid.file_size = 2
    require(validate_members([valid], 2) == 2, "SELF_TEST_VALID_MEMBER")
    count += 1
    for name in ("../escape", "/absolute", "C:/escape", "nested//file"):
        bad = zipfile.ZipInfo(name)
        rejects(lambda bad=bad: validate_members([bad], 100), "MEMBER_PATH")
    bad = zipfile.ZipInfo("nested\\file")
    rejects(lambda: validate_members([bad], 100), "MEMBER_PATH_ENCODING")
    rejects(lambda: validate_members([valid, valid], 100), "DUPLICATE_MEMBER")
    link = zipfile.ZipInfo("link")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    rejects(lambda: validate_members([link], 100), "MEMBER_TYPE")
    rejects(lambda: validate_members([valid], 1), "DECLARED_DECODED_TOTAL")
    rejects(lambda: parse_json(b'{"a":1,"a":2}'), "DUPLICATE_JSON_KEY")
    rejects(lambda: parse_json(b'{"a":1e999}'), "NONFINITE_JSON_NUMBER")
    rejects(lambda: parse_json(b'{"a":NaN}'), "NONFINITE_JSON_CONSTANT")
    require(parse_json(b'{"a":1,"b":[true,null]}') == {"a": 1, "b": [True, None]},
            "SELF_TEST_VALID_JSON")
    count += 1
    sample = projection({"packet": "DO_NOT_PRINT", "cpu_ns": 42,
                         "error": "PUBLIC_REQUEST_DEADLINE",
                         "environment": {"TOKEN": "DO_NOT_PRINT"}})
    require(sample["cpu_ns"] == 42 and "packet" not in sample
            and "environment" not in sample
            and sample["error"]["literal_code"] == "PUBLIC_REQUEST_DEADLINE",
            "SELF_TEST_REDACTION")
    count += 1
    # Actual ZIP read and CRC validation, including a single-bit stored corruption.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("plain", b"abcdef")
    raw = bytearray(buffer.getvalue())
    offset = raw.index(b"abcdef")
    raw[offset] ^= 1
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            archive.read("plain")
    except zipfile.BadZipFile:
        count += 1
    else:
        raise Rejected("SELF_TEST_CRC_ACCEPTED")
    print(json.dumps({"self_tests_passed": count, "native_tests_executed": 0}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    require(args.out is not None, "OUTPUT_REQUIRED")
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == BRANCH, "READBACK_JOB_SCOPE")
    token = os.environ.get("GH_TOKEN")
    require(isinstance(token, str) and len(token) > 0, "READ_TOKEN_REQUIRED")
    specs = parse_json(Path(__file__).with_name("inputs.json").read_bytes())
    require(isinstance(specs, list) and len(specs) == 2, "TWO_FROZEN_ARTIFACTS")
    args.out.mkdir(parents=True, exist_ok=False)
    budget = {"compressed": COMPRESSED_BUDGET, "decoded": DECODED_BUDGET}
    printed = 0
    snapshots = []
    with tempfile.TemporaryDirectory(prefix="trnm-original-artifacts-") as scratch:
        for spec in specs:
            artifact = api_json(
                f"/repos/{REPOSITORY}/actions/artifacts/{spec['artifact_id']}", token)
            run = api_json(f"/repos/{REPOSITORY}/actions/runs/{spec['run_id']}", token)
            commit = api_json(
                f"/repos/{REPOSITORY}/git/commits/{spec['source']}", token)
            check_metadata(spec, artifact, run, commit)
            path = Path(scratch) / f"{spec['artifact_id']}.zip"
            download(spec, token, path, budget)
            files, documents, declared = inspect_zip(path, spec, budget)
            snapshot = {
                "artifact": spec, "archive_digest_and_size_verified": True,
                "members_crc_and_sha256_verified": len(files),
                "declared_decoded_bytes": declared,
                "source_receipts_verified": spec["source_json"],
                "original_binary_verified": spec["kind"] == "campaign",
                "phase_summaries": {
                    name: phase_summary(value) for name, value in documents.items()
                    if isinstance(value, dict) and "phases" in value},
                "qualification": {"readback_only": True, "native_executed": False,
                                  "performance_qualified": False,
                                  "production_activation": False},
            }
            prefix = str(spec["artifact_id"])
            (args.out / (prefix + "-members.json")).write_text(
                json.dumps(files, sort_keys=True, indent=2) + "\n")
            projected = {name: projection(value) for name, value in documents.items()
                         if name in spec["project_json"]}
            (args.out / (prefix + "-selected.json")).write_text(
                json.dumps(projected, sort_keys=True, indent=2, allow_nan=False) + "\n")
            (args.out / (prefix + "-readback.json")).write_text(
                json.dumps(snapshot, sort_keys=True, indent=2, allow_nan=False) + "\n")
            for kind, value in (("READBACK", snapshot), ("SELECTED", projected)):
                line = kind + " " + json.dumps(value, sort_keys=True, allow_nan=False)
                printed += len(line.encode()) + 1
                require(printed <= PRINT_BUDGET, "STDOUT_PROJECTION_BUDGET")
                print(line, flush=True)
            snapshots.append(snapshot)
            path.unlink()
    (args.out / "SUMMARY.json").write_text(json.dumps({
        "schema": "trnm-frozen-original-artifact-readback-v1",
        "source": os.environ["GITHUB_SHA"], "snapshots": snapshots,
        "remaining_budgets": budget, "archive_members_executed": 0,
        "scope": "integrity/source-bound diagnostic readback, not native qualification",
    }, sort_keys=True, indent=2, allow_nan=False) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Rejected as error:
        print(json.dumps({"readback_failed": str(error), "native_executed": False}))
        raise SystemExit(1) from None
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile,
            urllib.error.URLError, RecursionError) as error:
        # Do not print signed redirect URLs, request headers, or arbitrary bytes.
        print(json.dumps({"readback_failed": type(error).__name__,
                          "native_executed": False}))
        raise SystemExit(1) from None
