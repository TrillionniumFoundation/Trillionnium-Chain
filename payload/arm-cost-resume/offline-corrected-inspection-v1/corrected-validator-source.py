#!/usr/bin/env python3
"""Fixed arm64 artifact resume: preserve the failed original and verify a new full ZIP."""
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import stat
import subprocess
import sys
import time
import zipfile
import zlib

ROOT = Path("/private/tmp/chain-consolidation-20261114-root")
OUT = Path("/private/tmp/chain-R1-required-cross-arch-cost-arm-resume-20261114-v1")
SELF = ROOT / "resume_r1_arm64_cost_artifact_v1.py"
GH = "/opt/homebrew/bin/gh"
REPO = "TrillionniumFoundation/Trillionnium-Chain"
ARTIFACT = 14119000610
JOB = 132481412245
RUN = 43604217412
HEAD = "2a86462a1ab20c68151719ba4635e3c294391e64"
TREE = "5c26776f96f15fd131e85a5c2d7c5e895ad7fab4"
NAME = "cost-arm64-" + HEAD + "-1"
SIZE = 9927038
DIGEST = "8249d0279e12e95bb59da7644b3d62ca1243589f9488b26e3b2b95560c9735ff"
PARTIAL = Path("/private/tmp/chain-R1-required-cross-arch-cost-artifacts-20261114-v3/14119000610.zip")
START = 9142272
PARTIAL_SHA = "cacd3e2ae5db448ee3e9b0d4e8383be9b5764c5984991bd7cf5f23b3c5527ada"
TAIL = 784766
ORIGINAL = Path("/private/tmp/chain-R1-required-cross-arch-cost-artifacts-20261114-v3/14119000610.completion.json")
ORIGINAL_BYTES = 5026
ORIGINAL_SHA = "319dc40dd4626e4bf9e5eb13fe89ce2a00736f562a40c265245704cf538150b2"
SOURCE_LOG = Path("/private/tmp/chain-R1-required-cross-arch-cost-log-review-20261114-v2/job-132481412245-original-log.stdout")
SOURCE_BYTES = 184625
SOURCE_SHA = "2563aac4968c906fa6664d84be5ba069093d0dc3bbdc7a055b9f0f796098b170"
TEST_SHA = "c20a1d34bcb4ad9d0f37a9b65815aac3c9e50b267edb9a65e856b3acd954064f"
BUDGET = 300
METADATA_BUDGET = 90
SELECTORS = (
    "caller_cpu_clock_keeps_missing_overflow_and_wrong_owner_distinct",
    "from_zero_search_preserves_misses_exhaustion_and_full_replay_rejection",
    "four_from_zero_w1_traces_keep_native_state_and_chainwork_unchanged",
    "from_zero_service_shares_cpu_with_honest_work_and_reopened_owner",
    "from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline",
)
SAFE_HEADERS = {"content-range", "content-length", "content-type", "accept-ranges", "content-encoding"}

def need(ok, message):
    if not ok:
        raise ValueError(message)

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def fingerprint(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def stable_bytes(path, expected_size, expected_sha):
    need(path.is_absolute() and path.resolve(strict=True) == path, "SOURCE_PATH")
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == expected_size, "SOURCE_REGULAR_SIZE")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as f:
        need(fingerprint(os.fstat(f.fileno())) == fingerprint(before), "SOURCE_OPEN_IDENTITY")
        raw = f.read(expected_size + 1)
        need(fingerprint(os.fstat(f.fileno())) == fingerprint(before), "SOURCE_FD_CHANGED")
    need(fingerprint(path.lstat()) == fingerprint(before), "SOURCE_PATH_CHANGED")
    need(len(raw) == expected_size and hashlib.sha256(raw).hexdigest() == expected_sha, "SOURCE_SHA")
    return raw

def save(name, raw):
    path = OUT / name
    with path.open("xb") as f:
        f.write(raw)
    need(path.read_bytes() == raw, "OUTPUT_READBACK")
    return {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

def save_json(name, value):
    return save(name, (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode())

def pairs(items):
    out = {}
    for key, value in items:
        need(key not in out, "DUPLICATE_JSON_KEY")
        out[key] = value
    return out

def parse_json(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("NONFINITE_JSON")))

def parsed_headers(raw):
    """Keep only typed non-sensitive fields. Never persist the original headers."""
    lines = raw.replace(b"\r\n", b"\n").split(b"\n")
    need(len(lines) <= 128, "HEADER_COUNT")
    match = re.fullmatch(rb"HTTP/(?:1\.[01]|2(?:\.0)?|3(?:\.0)?) ([0-9]{3})(?: [\x20-\x7e]*)?", lines[0])
    need(match is not None, "GH_INCLUDE_STATUS_UNRECOGNIZED")
    status = int(match.group(1))
    safe = {}
    for line in lines[1:]:
        if not line:
            continue
        need(not line.startswith((b" ", b"\t")) and b":" in line, "HEADER_FRAMING")
        key, value = line.split(b":", 1)
        need(re.fullmatch(rb"[A-Za-z0-9-]+", key) is not None, "HEADER_KEY")
        key = key.decode("ascii").lower()
        if key not in SAFE_HEADERS:
            continue
        need(key not in safe, "DUPLICATE_SAFE_HEADER")
        value = value.strip()
        need(len(value) <= 128 and all(32 <= c < 127 for c in value), "SAFE_HEADER_VALUE")
        if key == "content-range":
            need(re.fullmatch(rb"bytes [0-9]+-[0-9]+/[0-9]+", value) is not None, "CONTENT_RANGE_FORMAT")
        elif key == "content-length":
            need(re.fullmatch(rb"[0-9]{1,12}", value) is not None, "CONTENT_LENGTH_FORMAT")
        elif key == "content-type":
            need(re.fullmatch(rb"[A-Za-z0-9.+_-]+/[A-Za-z0-9.+_-]+(?:; ?charset=[A-Za-z0-9_-]+)?", value) is not None, "CONTENT_TYPE_FORMAT")
        elif key == "accept-ranges":
            need(value in (b"bytes", b"none"), "ACCEPT_RANGES_FORMAT")
        elif key == "content-encoding":
            need(value in (b"identity", b"gzip", b"br", b"deflate"), "CONTENT_ENCODING_FORMAT")
        safe[key] = value.decode("ascii")
    return status, safe

def capture(label, endpoint, deadline, range_probe=False):
    argv = [GH, "api", "--hostname", "github.com", "--method", "GET"]
    if range_probe:
        argv += ["--include", "--header", f"Range: bytes={START}-{SIZE - 1}"]
    argv += [endpoint]
    env = os.environ.copy()
    env.pop("GH_DEBUG", None)
    env["GH_HOST"] = "github.com"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONOPTIMIZE"] = "0"
    rec = {"label": label, "argv": argv, "method": "GET", "cwd": "/private/tmp",
           "started_at": now(), "finished_at": None, "exit": None, "error": None,
           "overall_budget_seconds": BUDGET, "automatic_retry": False,
           "GH_DEBUG_removed": True, "GH_HOST": "github.com",
           "headers_raw_saved": False, "stderr_raw_saved": False,
           "stdout_consumed_bytes": 0, "stderr_consumed_bytes": 0,
           "stdout_eof": False, "stderr_eof": False,
           "http_status": None, "safe_response_headers": {},
           "raw_header_bytes": None, "raw_header_sha256": None}
    body = bytearray()
    headers = bytearray()
    hashes = {"stdout": hashlib.sha256(), "stderr": hashlib.sha256()}
    process = None
    started_clock = time.monotonic()
    next_progress = 30.0
    sel = selectors.DefaultSelector()
    try:
        need(time.monotonic() < deadline, "TOTAL_DEADLINE_BEFORE_REQUEST")
        process = subprocess.Popen(argv, cwd="/private/tmp", env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rec["pid"] = process.pid
        print(json.dumps({"event": "request-started", "label": label, "pid": process.pid,
                          "time": rec["started_at"], "automatic_retry": False}), flush=True)
        for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, name)
        got_headers = not range_probe
        while sel.get_map():
            elapsed = time.monotonic() - started_clock
            if elapsed >= next_progress:
                print(json.dumps({"event": "request-progress", "label": label, "pid": process.pid,
                                  "elapsed_seconds": elapsed, "accepted_body_bytes": len(body),
                                  "http_status": rec["http_status"]}), flush=True)
                next_progress += 30.0
            need(time.monotonic() < deadline, "TOTAL_NETWORK_DEADLINE")
            for key, _ in sel.select(min(0.1, max(0.0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 4096)
                name = key.data
                if not chunk:
                    rec[name + "_eof"] = True
                    sel.unregister(key.fileobj)
                    continue
                hashes[name].update(chunk)
                rec[name + "_consumed_bytes"] += len(chunk)
                if name == "stderr":
                    need(rec["stderr_consumed_bytes"] <= 65536, "STDERR_COUNT_BOUND")
                    continue
                if not got_headers:
                    headers.extend(chunk)
                    cuts = [(headers.find(x), x) for x in (b"\r\n\r\n", b"\n\n") if headers.find(x) >= 0]
                    if not cuts:
                        need(len(headers) <= 16384, "HEADER_BYTE_BOUND")
                        continue
                    cut, separator = min(cuts, key=lambda x: x[0])
                    need(cut + len(separator) <= 16384, "HEADER_BYTE_BOUND")
                    original = bytes(headers[:cut])
                    rec["raw_header_bytes"] = cut + len(separator)
                    rec["raw_header_sha256"] = hashlib.sha256(bytes(headers[:cut + len(separator)])).hexdigest()
                    status, safe = parsed_headers(original)
                    rec["http_status"], rec["safe_response_headers"] = status, safe
                    chunk = bytes(headers[cut + len(separator):])
                    headers.clear()
                    if status != 206:
                        raise ValueError("RANGE_UNSUPPORTED_HTTP_STATUS")
                    need(safe.get("content-range") == f"bytes {START}-{SIZE - 1}/{SIZE}", "EXACT_TAIL_CONTENT_RANGE_REQUIRED")
                    need("content-length" not in safe or safe["content-length"] == str(TAIL), "EXACT_TAIL_CONTENT_LENGTH")
                    need(safe.get("content-encoding", "identity") == "identity", "ENCODED_RANGE_REFUSED")
                    got_headers = True
                cap = TAIL if range_probe else 65536
                need(len(body) + len(chunk) <= cap, "BODY_BYTE_BOUND")
                body.extend(chunk)
        rec["exit"] = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        need(rec["exit"] == 0, "GH_GET_NONZERO")
        if range_probe:
            need(got_headers and rec["http_status"] == 206 and len(body) == TAIL, "COMPLETE_EXACT_TAIL_REQUIRED")
        rec["accepted_body_bytes"] = len(body)
    except Exception as error:
        # All ValueError messages above are fixed codes, never server strings.
        rec["error"] = str(error) if isinstance(error, ValueError) else type(error).__name__
    finally:
        sel.close()
        if process is not None:
            if process.poll() is None:
                rec["terminated_owned_request"] = True
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            rec["exit"] = process.returncode
            process.stdout.close()
            process.stderr.close()
        rec["finished_at"] = now()
        rec["elapsed_seconds"] = time.monotonic() - started_clock
        rec["stdout_consumed_sha256"] = hashes["stdout"].hexdigest()
        rec["stderr_consumed_sha256"] = hashes["stderr"].hexdigest()
        rec["complete_transport"] = (rec["error"] is None and rec["exit"] == 0
                                     and rec["stdout_eof"] and rec["stderr_eof"])
        rec["body_retained_bytes"] = len(body) if range_probe and rec["http_status"] == 206 else 0
        rec["step_receipt"] = save_json(label + ".step.json", rec)
    return rec, bytes(body)

def safe_member(name):
    need(isinstance(name, str) and name and "\\" not in name and ":" not in name
         and all(ord(c) >= 32 and ord(c) != 127 for c in name), "UNSAFE_MEMBER_PATH")
    normalized = name[:-1] if name.endswith("/") else name
    path = PurePosixPath(normalized)
    need(normalized and not path.is_absolute() and path.as_posix() == normalized
         and all(part not in ("", ".", "..") for part in path.parts), "NONCANONICAL_MEMBER")
    return path

def save_member(name, raw):
    path = safe_member(name)
    target = OUT / "members" / path
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    need(target.parent.resolve(strict=True) == target.parent, "MEMBER_OUTPUT_PARENT")
    return save(str(target.relative_to(OUT)), raw)

def inspect_complete_zip(path):
    stable_bytes(path, SIZE, DIGEST)
    rows, seen, total = [], set(), 0
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        need(0 < len(infos) <= 10000, "ZIP_MEMBER_COUNT")
        for info in infos:
            normalized = safe_member(info.filename).as_posix()
            need(normalized not in seen, "DUPLICATE_ZIP_MEMBER")
            seen.add(normalized)
            kind = stat.S_IFMT(info.external_attr >> 16)
            need(kind in (0, stat.S_IFREG, stat.S_IFDIR) and not info.flag_bits & 0x41,
                 "LINK_SPECIAL_ENCRYPTED_ZIP_MEMBER")
            need(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                 "UNSUPPORTED_ZIP_COMPRESSION")
            need(info.file_size <= 256 * 1024 * 1024, "ZIP_MEMBER_SIZE")
            if info.is_dir():
                need(info.file_size == 0, "DIRECTORY_BYTES")
                continue
            need(kind != stat.S_IFDIR, "DIRECTORY_NAME_MISMATCH")
            total += info.file_size
            need(total <= 512 * 1024 * 1024, "ZIP_TOTAL_SIZE")
            h, crc, count = hashlib.sha256(), 0, 0
            with archive.open(info) as stream:
                while True:
                    block = stream.read(65536)
                    if not block:
                        break
                    h.update(block)
                    crc = zlib.crc32(block, crc)
                    count += len(block)
                    need(count <= info.file_size, "EXPANDED_MEMBER_OVERRUN")
            need(count == info.file_size and (crc & 0xffffffff) == info.CRC,
                 "MEMBER_CRC_OR_SIZE")
            rows.append({"path": info.filename, "bytes": count, "sha256": h.hexdigest(),
                         "crc32": f"{info.CRC:08x}", "compressed_bytes": info.compress_size,
                         "mode": info.external_attr >> 16})
        stable_bytes(path, SIZE, DIGEST)
        index = {"schema": "trnm-original-artifact-full-member-index-v1",
                 "artifact_id": ARTIFACT, "zip": {"path": str(path), "bytes": SIZE, "sha256": DIGEST},
                 "member_count": len(infos), "file_count": len(rows),
                 "total_uncompressed_bytes": total, "all_members_CRC_SHA256_verified": True,
                 "files": rows, "no_inner_code_executed": True}
        index_pin = save_json("complete-zip-member-index.json", index)
        members = {row["path"]: row for row in rows}
        def read_member(name, cap):
            need(name in members and members[name]["bytes"] <= cap, "DECLARED_MEMBER_BOUND")
            data = archive.read(name)
            need(len(data) == members[name]["bytes"]
                 and hashlib.sha256(data).hexdigest() == members[name]["sha256"],
                 "MEMBER_READBACK_SHA")
            return data
        prefix = "from-zero-native/"
        manifest_raw = read_member(prefix + "manifest.json", 2 * 1024 * 1024)
        manifest = parse_json(manifest_raw)
        need(manifest.get("schema") == "trnm-from-zero-native-execution-v3", "NATIVE_MANIFEST_SCHEMA")
        filemap = manifest.get("files")
        need(isinstance(filemap, dict), "NATIVE_FILEMAP_TYPE")
        expected_members = set()
        for rel, digest in filemap.items():
            path_part = safe_member(rel)
            need(str(path_part) == rel and isinstance(digest, str)
                 and re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "NATIVE_FILEMAP_ROW")
            name = prefix + rel
            need(name in members and members[name]["sha256"] == digest,
                 "NATIVE_DECLARED_MEMBER_SHA")
            expected_members.add(name)
        actual_members = {name for name in members if name.startswith(prefix)} - {prefix + "manifest.json"}
        need(expected_members == actual_members, "NATIVE_EXACT_FILEMAP_CLOSURE")
        map_pin = save_json("native-manifest-filemap-verification.json",
                            {"declared_files": len(filemap), "actual_files": len(actual_members),
                             "all_declared_hashes_match": True, "exact_prefix_closure": True})
        before, after = manifest.get("source_before"), manifest.get("source_after")
        need(isinstance(before, dict) and before == after, "NATIVE_SOURCE_BEFORE_AFTER")
        need(before.get("commit") == HEAD and before.get("tree") == TREE
             and before.get("test_sha256") == TEST_SHA, "NATIVE_SOURCE_AND_TEST_IDENTITY")
        tracked = before.get("tracked_source_identity")
        need(isinstance(tracked, dict) and tracked.get("schema") == "trnm-ci-source-v1"
             and tracked.get("kind") == "head" and tracked.get("candidate") == HEAD
             and tracked.get("tested_commit") == HEAD and tracked.get("tested_tree") == TREE
             and tracked.get("base") is None and tracked.get("prospective_merge") is None
             and tracked.get("tracked_worktree_verified") is True
             and tracked.get("tests_executed_by_identity_check") is False,
             "TRACKED_SOURCE_IDENTITY")
        binary_before, binary_after = manifest.get("binary_sha256_before"), manifest.get("binary_sha256_after")
        need(isinstance(binary_before, str) and re.fullmatch(r"[0-9a-f]{64}", binary_before) is not None
             and binary_before == binary_after, "NATIVE_BINARY_BEFORE_AFTER")
        runs = manifest.get("runs")
        need(isinstance(runs, list) and [row.get("name") for row in runs] == list(SELECTORS),
             "EXACT_FIVE_NATIVE_SELECTOR_ROSTER")
        run_facts = []
        for row in runs:
            name = row["name"]
            log_pins, raw_streams = {}, {}
            for leaf in ("stdout", "stderr", "process.json"):
                member_name = prefix + name + "/" + leaf
                data = read_member(member_name, 2 * 1024 * 1024)
                raw_streams[leaf] = data
                log_pins[leaf] = save_member(member_name, data)
            process = parse_json(raw_streams["process.json"])
            need(process == row.get("process"), "ORIGINAL_PROCESS_MANIFEST_BINDING")
            need(process.get("stdout_sha256") == hashlib.sha256(raw_streams["stdout"]).hexdigest()
                 and process.get("stderr_sha256") == hashlib.sha256(raw_streams["stderr"]).hexdigest(),
                 "NATIVE_STREAM_PROCESS_SHA")
            run_facts.append({"name": name, "process": process, "passed": row.get("passed"),
                              "named_execution": row.get("named_execution"), "failure": row.get("failure"),
                              "failure_diagnostic": row.get("failure_diagnostic"),
                              "originals": log_pins})
        manifest_pin = save_member(prefix + "manifest.json", manifest_raw)
        source_pin = save_json("source-before-after-extracted.json",
                              {"source_before": before, "source_after": after,
                               "binary_sha256_before": binary_before, "binary_sha256_after": binary_after})
        report_name = prefix + "confirmation/report.json"
        report_facts = None
        if report_name in members:
            report = parse_json(read_member(report_name, 128 * 1024 * 1024))
            need(report.get("schema") == "public-v3-signed-confirmation-pressure-v1",
                 "CONFIRMATION_REPORT_SCHEMA")
            phases = report.get("phases")
            need(isinstance(phases, list) and len(phases) == 2, "CONFIRMATION_PHASE_COUNT")
            compact = []
            for i, phase in enumerate(phases):
                replays = phase.get("independent_history_page_replay")
                need(isinstance(replays, list) and len(replays) <= 64, "REPLAY_RECORD_BOUND")
                replay_facts = []
                for j, replay in enumerate(replays):
                    native = replay.get("native_import_observation")
                    replay_facts.append({
                        "json_pointer": f"/phases/{i}/independent_history_page_replay/{j}",
                        "replay": {k: v for k, v in replay.items() if k != "native_import_observation"},
                        "host_checks": native.get("host_checks") if isinstance(native, dict) else None,
                        "measurement_failures": native.get("measurement_failures") if isinstance(native, dict) else None})
                compact.append({"json_pointer": f"/phases/{i}",
                                "phase_scalars": {k: v for k, v in phase.items()
                                                  if v is None or isinstance(v, (bool, int, float, str))},
                                "honest_submissions_count": len(phase.get("honest_submissions", [])),
                                "honest_history_count": len(phase.get("honest_history", [])),
                                "verification_errors": phase.get("verification_errors"), "replays": replay_facts})
            report_facts = save_json("bounded-confirmation-report-facts.json",
                                    {"report_member": members[report_name],
                                     "top_scalar_values": {k: v for k, v in report.items()
                                                          if v is None or isinstance(v, (bool, int, float, str))},
                                     "phases": compact, "raw_report_only_in_verified_complete_ZIP": True,
                                     "nested_intervals_not_additive": True, "no_wall_minus_CPU_causal_inference": True})
        result = {"member_index": index_pin, "native_filemap": map_pin, "manifest": manifest_pin,
                  "source_identity": source_pin, "runs": run_facts, "confirmation_facts": report_facts,
                  "manifest_outcome": {key: manifest.get(key) for key in
                      ("source_recompiled", "all_named_tests_passed", "format_passed", "failures",
                       "passed", "execution_finished", "service_report", "sustained_report",
                       "confirmation_report", "independent_wan_accepted", "work_hardness_accepted",
                       "production_activation")}, "no_inner_code_or_test_executed": True}
        stable_bytes(path, SIZE, DIGEST)
        return result

def main():
    need(sys.flags.optimize == 0, "OPTIMIZATION_FORBIDDEN")
    need(Path(__file__).resolve(strict=True) == SELF, "EXACT_PRODUCER_PATH")
    need(OUT.parent.resolve(strict=True) == OUT.parent, "OUTPUT_PARENT")
    OUT.mkdir(mode=0o700)
    started = now()
    deadline = time.monotonic() + BUDGET
    source_inputs = ((PARTIAL, START, PARTIAL_SHA), (ORIGINAL, ORIGINAL_BYTES, ORIGINAL_SHA),
                     (SOURCE_LOG, SOURCE_BYTES, SOURCE_SHA))
    result = {"schema": "trnm-r1-arm64-artifact-explicit-range-resume-v1", "status": "HOLD",
              "started_at": started, "finished_at": None, "errors": [], "steps": [],
              "artifact_id": ARTIFACT, "job_id": JOB, "run_id": RUN, "run_attempt": 1,
              "head": HEAD, "tree": TREE, "expected_artifact_name": NAME,
              "expected_archive_bytes": SIZE, "expected_whole_archive_sha256": DIGEST,
              "requested_range": f"bytes={START}-{SIZE - 1}", "expected_range_body_bytes": TAIL,
              "maximum_GETs": 2, "network_methods": ["GET"], "network_budget_seconds": BUDGET,
              "metadata_budget_seconds": METADATA_BUDGET, "automatic_retry": False,
              "original_partial_modified": False, "original_failure_relabelled": False,
              "whole_artifact_sha256_verified": False, "all_member_crc_verified": False,
              "source_refs_config_CI_stage_modified": False, "qualification": False,
              "signed_URL_headers_auth_cookies_saved": False}
    source_validated = False
    try:
        need(SIZE - START == TAIL, "FIXED_RANGE_ARITHMETIC")
        partial = stable_bytes(PARTIAL, START, PARTIAL_SHA)
        original_raw = stable_bytes(ORIGINAL, ORIGINAL_BYTES, ORIGINAL_SHA)
        original = parse_json(original_raw)
        log = stable_bytes(SOURCE_LOG, SOURCE_BYTES, SOURCE_SHA)
        source_validated = True
        need(original["requested"]["id"] == ARTIFACT and original["requested"]["bytes"] == SIZE
             and original["requested"]["sha256"] == DIGEST
             and original["download"]["exit_code"] == 124
             and original["download"]["process_returncode"] == -9
             and original["download"]["timeout_seconds"] == 1200
             and original["download"]["timeout_reached"] is True
             and original["download"]["stdout"] == {"path": str(PARTIAL), "bytes": START, "sha256": PARTIAL_SHA}
             and original["member_index"] is None, "EXACT_ORIGINAL_FAILED_DOWNLOAD")
        need((f"Artifact ID is {ARTIFACT}").encode() in log and DIGEST.encode() in log
             and (f"Final size is {SIZE} bytes").encode() in log, "ORIGINAL_UPLOAD_ANCHOR")
        result["original_failure"] = {"path": str(ORIGINAL), "bytes": ORIGINAL_BYTES, "sha256": ORIGINAL_SHA}
        result["original_partial"] = {"path": str(PARTIAL), "bytes": START, "sha256": PARTIAL_SHA}
        result["original_upload_log"] = {"path": str(SOURCE_LOG), "bytes": SOURCE_BYTES, "sha256": SOURCE_SHA}
        result["retained_original_failure"] = save("original-failed-download.json", original_raw)
        endpoint = "repos/" + REPO + "/actions/artifacts/" + str(ARTIFACT)
        step, metadata_raw = capture("artifact-metadata", endpoint,
                                     min(deadline, time.monotonic() + METADATA_BUDGET))
        result["steps"].append(step)
        need(step["complete_transport"], "FRESH_METADATA_TRANSPORT")
        meta = parse_json(metadata_raw)
        run = meta.get("workflow_run") or {}
        need(type(meta.get("id")) is int and meta["id"] == ARTIFACT
             and type(meta.get("size_in_bytes")) is int and meta["size_in_bytes"] == SIZE
             and meta.get("name") == NAME and meta.get("digest") == "sha256:" + DIGEST
             and meta.get("expired") is False and run.get("id") == RUN
             and run.get("head_sha") == HEAD, "FRESH_ARTIFACT_IDENTITY")
        result["fresh_metadata"] = save("artifact-metadata.json", metadata_raw)
        result["metadata_identity_verified"] = True
        step, body = capture("remaining-range", endpoint + "/zip", deadline, range_probe=True)
        result["steps"].append(step)
        if step["http_status"] == 206 and body:
            result["tail_body"] = save("remaining-range.body" if step["complete_transport"]
                                       else "remaining-range.body.partial", body)
        if step["error"] == "RANGE_UNSUPPORTED_HTTP_STATUS":
            result["status"] = "RANGE_UNSUPPORTED"
        need(step["complete_transport"], "EXACT_206_RANGE_NOT_COMPLETE")
        need(len(body) == TAIL, "EXACT_REMAINING_BODY_SIZE")
        whole = partial + body
        need(len(whole) == SIZE and hashlib.sha256(whole).hexdigest() == DIGEST,
             "RECONSTRUCTED_FULL_ZIP_SHA")
        result["complete_zip"] = save(str(ARTIFACT) + ".complete.zip", whole)
        result["whole_artifact_sha256_verified"] = True
        result["inspection"] = inspect_complete_zip(Path(result["complete_zip"]["path"]))
        result["all_member_crc_verified"] = True
        result["status"] = "COMPLETE_ARM_ARTIFACT_VERIFIED"
    except Exception as error:
        result["errors"].append(str(error) if isinstance(error, ValueError) else type(error).__name__)
    finally:
        result["original_inputs_before_after_valid"] = False
        if source_validated:
            try:
                for path, size, digest in source_inputs:
                    stable_bytes(path, size, digest)
                result["original_inputs_before_after_valid"] = True
            except Exception as error:
                result["errors"].append(str(error) if isinstance(error, ValueError) else type(error).__name__)
                result["status"] = "HOLD"
        if result["errors"] and result["status"] == "COMPLETE_ARM_ARTIFACT_VERIFIED":
            result["status"] = "HOLD"
        result["finished_at"] = now()
        producer_raw = SELF.read_bytes()
        result["producer"] = {"path": str(SELF), "bytes": len(producer_raw),
                              "sha256": hashlib.sha256(producer_raw).hexdigest()}
        summary = save_json("summary.json", result)
        print(json.dumps({"status": result["status"], "summary": summary,
                          "whole_artifact_sha256_verified": result["whole_artifact_sha256_verified"],
                          "all_member_crc_verified": result["all_member_crc_verified"],
                          "original_inputs_before_after_valid": result["original_inputs_before_after_valid"],
                          "qualification": False}), flush=True)
    return 0 if result["status"] == "COMPLETE_ARM_ARTIFACT_VERIFIED" else 1

if __name__ == "__main__":
    raise SystemExit(main())
