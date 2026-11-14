#!/usr/bin/env python3
"""Read six fixed diagnostic members using four explicit ranges. Never execute members."""
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import stat
import struct
import subprocess
import sys
import time
import zlib

OUT = Path("/private/tmp/chain-prci-R1-history-artifact-selected-members-20261114-v1")
GH = "/opt/homebrew/bin/gh"
REPO = "TrillionniumFoundation/Trillionnium-Chain"
ARTIFACT = 14118769328
RUN = 43604217565
HEAD = "2a86462a1ab20c68151719ba4635e3c294391e64"
NAME = "priority-ubuntu-24.04-head-history-" + HEAD + "-1"
SIZE = 59887660
DIGEST = "cf934b39339e2039beb285ade75473b9bb1035b0a69441c13ce08d3b47e376dc"
DIRECTORY = Path("/private/tmp/chain-prci-R1-history-artifact-central-directory-20261114-v1/central-directory.json")
DIRECTORY_BYTES = 1733699
DIRECTORY_SHA = "0efa6871c0fb1b509d285bdaf54a9970aeeca7e18182be67eaacbcd0fa041e68"
MEMBERS = [
    {
        "path": "history-native/history-resources.txt",
        "index": 3,
        "offset": 10011,
        "end": 10624,
        "compressed": 531,
        "expanded": 972,
        "crc32": "5e13cf8a",
        "method": 8,
        "flags": 8,
        "version": 20,
        "output": "history-resources.txt"
    },
    {
        "path": "history-native/history.log",
        "index": 4,
        "offset": 10624,
        "end": 13254,
        "compressed": 2558,
        "expanded": 11359,
        "crc32": "7f9502ac",
        "method": 8,
        "flags": 8,
        "version": 20,
        "output": "history.log"
    },
    {
        "path": "history-native/long-history/source.json",
        "index": 4113,
        "offset": 36548239,
        "end": 36548644,
        "compressed": 320,
        "expanded": 514,
        "crc32": "d998eb9b",
        "method": 8,
        "flags": 8,
        "version": 20,
        "output": "long-history-source.json"
    },
    {
        "path": "history-native/long-history/summary.json",
        "index": 4114,
        "offset": 36548644,
        "end": 36548890,
        "compressed": 160,
        "expanded": 259,
        "crc32": "c3eab677",
        "method": 8,
        "flags": 8,
        "version": 20,
        "output": "long-history-summary.json"
    },
    {
        "path": "history-native/manifest.json",
        "index": 4117,
        "offset": 59498008,
        "end": 59499532,
        "compressed": 1450,
        "expanded": 4907,
        "crc32": "b859bbaf",
        "method": 8,
        "flags": 8,
        "version": 20,
        "output": "manifest.json"
    },
    {
        "path": "source.json",
        "index": 4139,
        "offset": 59510826,
        "end": 59511122,
        "compressed": 239,
        "expanded": 423,
        "crc32": "63111cae",
        "method": 8,
        "flags": 8,
        "version": 20,
        "output": "source.json"
    }
]
RANGES = [
    {
        "label": "resources-and-history-log",
        "start": 10011,
        "end": 13253,
        "members": [
            0,
            1
        ]
    },
    {
        "label": "long-history-source-and-summary",
        "start": 36548239,
        "end": 36548889,
        "members": [
            2,
            3
        ]
    },
    {
        "label": "native-manifest",
        "start": 59498008,
        "end": 59499531,
        "members": [
            4
        ]
    },
    {
        "label": "top-level-source",
        "start": 59510826,
        "end": 59511121,
        "members": [
            5
        ]
    }
]
SOURCE_LOG = Path("/private/tmp/chain-R1-native-priorities-history-log-review-20261114-v1/job-132475258347-original-log.stdout")
SOURCE_BYTES = 178249
SOURCE_SHA = "3ba328053189e7e8a25c8fb5cfc5780941dc21d96afba56808fe61bc1a7e536e"
BUDGET = 180
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

def capture(label, endpoint, deadline, exact_range=None):
    range_probe = exact_range is not None
    if range_probe:
        start, end = exact_range
        expected_bytes = end - start + 1
        need((start, end) in {(g["start"], g["end"]) for g in RANGES}, "UNAPPROVED_RANGE")
    argv = [GH, "api", "--hostname", "github.com", "--method", "GET"]
    if range_probe:
        argv += ["--include", "--header", f"Range: bytes={start}-{end}"]
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
    sel = selectors.DefaultSelector()
    try:
        need(time.monotonic() < deadline, "TOTAL_DEADLINE_BEFORE_REQUEST")
        process = subprocess.Popen(argv, cwd="/private/tmp", env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ, name)
        got_headers = not range_probe
        while sel.get_map():
            need(time.monotonic() < deadline, "TOTAL_180_SECOND_DEADLINE")
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
                    need(safe.get("content-range") == f"bytes {start}-{end}/{SIZE}", "EXACT_SELECTED_CONTENT_RANGE_REQUIRED")
                    need("content-length" not in safe or safe["content-length"] == str(expected_bytes), "EXACT_SELECTED_CONTENT_LENGTH")
                    need(safe.get("content-encoding", "identity") == "identity", "ENCODED_RANGE_REFUSED")
                    got_headers = True
                cap = expected_bytes if range_probe else 65536
                need(len(body) + len(chunk) <= cap, "BODY_BYTE_BOUND")
                body.extend(chunk)
        rec["exit"] = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        need(rec["exit"] == 0, "GH_GET_NONZERO")
        if range_probe:
            need(got_headers and rec["http_status"] == 206 and len(body) == expected_bytes, "COMPLETE_EXACT_SELECTED_RANGE_REQUIRED")
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
        rec["stdout_consumed_sha256"] = hashes["stdout"].hexdigest()
        rec["stderr_consumed_sha256"] = hashes["stderr"].hexdigest()
        rec["complete_transport"] = (rec["error"] is None and rec["exit"] == 0
                                     and rec["stdout_eof"] and rec["stderr_eof"])
        rec["body_retained_bytes"] = len(body) if range_probe and rec["http_status"] == 206 else 0
        rec["step_receipt"] = save_json(label + ".step.json", rec)
    return rec, bytes(body)

def validate_directory():
    raw = stable_bytes(DIRECTORY, DIRECTORY_BYTES, DIRECTORY_SHA)
    data = parse_json(raw)
    need(data.get("schema") == "trnm-r1-history-central-directory-observation-v1"
         and data.get("artifact_id") == ARTIFACT
         and data.get("entries") == 4140
         and data.get("central_directory_offset") == 59511122
         and data.get("central_directory_bytes") == 376516
         and data.get("complete_central_directory_observed") is True
         and data.get("existing_tail_overlap_verified") is True, "CLOSED_CD_IDENTITY")
    rows = data["members"]
    need(type(rows) is list and len(rows) == 4140, "CD_COUNT")
    need(len({r["path"] for r in rows}) == len(rows)
         and len({r["local_header_offset"] for r in rows}) == len(rows), "CD_DUPLICATE")
    ordered = sorted(rows, key=lambda r: r["local_header_offset"])
    ends = {r["path"]: (ordered[i + 1]["local_header_offset"] if i + 1 < len(ordered)
                        else 59511122) for i, r in enumerate(ordered)}
    for selected in MEMBERS:
        row = rows[selected["index"]]
        actual = {key: row[field] for key, field in (
            ("path", "path"), ("index", "index"), ("offset", "local_header_offset"),
            ("compressed", "compressed_bytes"), ("expanded", "uncompressed_bytes"),
            ("crc32", "crc32_declared_hex"), ("method", "compression_method"),
            ("flags", "flags"), ("version", "version_needed"))}
        expected = {key: selected[key] for key in actual}
        need(actual == expected and row["directory"] is False
             and ends[selected["path"]] == selected["end"], "EXACT_SELECTED_CD_RECORD")
        need(selected["end"] - selected["offset"] <= 4096
             and 0 <= selected["compressed"] <= 4096
             and 0 <= selected["expanded"] <= 16384, "FIXED_SMALL_MEMBER_BOUNDS")
    need(len(MEMBERS) == 6 and len(RANGES) == 4
         and sum(g["end"] - g["start"] + 1 for g in RANGES) == 5714
         and sum(r["expanded"] for r in MEMBERS) == 18434, "EXACT_SELECTION_TOTAL")
    seen = []
    for group in RANGES:
        selected = [MEMBERS[i] for i in group["members"]]
        need(selected[0]["offset"] == group["start"]
             and selected[-1]["end"] == group["end"] + 1, "GROUP_RANGE_BOUND")
        need(all(selected[i]["end"] == selected[i + 1]["offset"]
                 for i in range(len(selected) - 1)), "GROUP_GAP_REFUSED")
        seen.extend(group["members"])
    need(seen == list(range(6)), "EXACT_MEMBER_COVERAGE")
    return {"path": str(DIRECTORY), "bytes": DIRECTORY_BYTES, "sha256": DIRECTORY_SHA}

def decode_member(record, selected):
    """Decode an explicitly selected regular member, with exact framing/length/CRC."""
    need(len(record) == selected["end"] - selected["offset"]
         and len(record) >= 30, "EXACT_MEMBER_RECORD_LENGTH")
    fields = struct.unpack_from("<4s5H3I2H", record)
    sig, version, flags, method, mtime, mdate, crc, csize, usize, nlen, xlen = fields
    need(sig == b"PK\x03\x04" and version == selected["version"] == 20
         and flags == selected["flags"] == 8
         and method == selected["method"] == 8, "LOCAL_HEADER_CONTRACT")
    expected_name = selected["path"].encode("ascii")
    need(nlen == len(expected_name) and 0 <= xlen <= 1024
         and record[30:30 + nlen] == expected_name, "LOCAL_NAME_EXTRA_BOUND")
    expected_crc = int(selected["crc32"], 16)
    need(crc in (0, expected_crc) and csize in (0, selected["compressed"])
         and usize in (0, selected["expanded"]), "LOCAL_DEFERRED_SIZE_OR_CRC")
    data_start = 30 + nlen + xlen
    data_end = data_start + selected["compressed"]
    need(data_start <= len(record) and data_end <= len(record), "COMPRESSED_DATA_BOUND")
    extras = record[30 + nlen:data_start]
    cursor = 0
    while cursor < len(extras):
        need(cursor + 4 <= len(extras), "LOCAL_EXTRA_HEADER_BOUND")
        kind, length = struct.unpack_from("<HH", extras, cursor)
        need(kind != 1 and cursor + 4 + length <= len(extras), "ZIP64_OR_EXTRA_BOUND")
        cursor += 4 + length
    descriptor = record[data_end:]
    if len(descriptor) == 16:
        need(descriptor[:4] == b"PK\x07\x08", "DATA_DESCRIPTOR_SIGNATURE")
        values = struct.unpack("<3I", descriptor[4:])
    else:
        need(len(descriptor) == 12, "DATA_DESCRIPTOR_LENGTH")
        values = struct.unpack("<3I", descriptor)
    need(values == (expected_crc, selected["compressed"], selected["expanded"]),
         "DATA_DESCRIPTOR_CD_MISMATCH")
    decoder = zlib.decompressobj(-15)
    raw = decoder.decompress(record[data_start:data_end], selected["expanded"] + 1)
    need(len(raw) == selected["expanded"] and decoder.eof
         and not decoder.unused_data and not decoder.unconsumed_tail, "EXACT_DEFLATE_EOF")
    need(zlib.crc32(raw) & 0xffffffff == expected_crc, "SELECTED_MEMBER_CRC_MISMATCH")
    return raw

def main():
    need(sys.flags.optimize == 0, "OPTIMIZATION_FORBIDDEN")
    need(OUT.parent.resolve(strict=True) == OUT.parent, "OUTPUT_PARENT")
    OUT.mkdir(mode=0o700)
    started = now()
    deadline = time.monotonic() + BUDGET
    result = {"schema": "trnm-r1-history-artifact-selected-member-read-v1", "status": "HOLD",
              "started_at": started, "finished_at": None, "errors": [], "steps": [],
              "artifact_id": ARTIFACT, "run_id": RUN, "head": HEAD,
              "expected_artifact_name": NAME, "expected_archive_bytes": SIZE,
              "expected_whole_archive_sha256": DIGEST, "network_methods": ["GET"],
              "maximum_GETs": 5, "manual_redirect_following": False,
              "signed_URL_headers_auth_cookies_saved": False,
              "whole_artifact_sha256_verified": False, "all_member_crc_verified": False,
              "source_refs_config_CI_modified": False, "qualification": False,
              "automatic_other_ranges_or_retries": False, "members": [],
              "original_business_failure_preserved": True, "member_contents_executed": False}
    try:
        result["closed_directory"] = validate_directory()
        result["selected_member_records"] = MEMBERS
        result["explicit_range_groups"] = RANGES
        raw = stable_bytes(SOURCE_LOG, SOURCE_BYTES, SOURCE_SHA)
        need((f"Artifact ID is {ARTIFACT}").encode() in raw and DIGEST.encode() in raw
             and (f"Final size is {SIZE} bytes").encode() in raw, "ORIGINAL_UPLOAD_ANCHOR")
        result["original_upload_log"] = {"path": str(SOURCE_LOG), "bytes": SOURCE_BYTES, "sha256": SOURCE_SHA}
        endpoint = "repos/" + REPO + "/actions/artifacts/" + str(ARTIFACT)
        step, metadata_raw = capture("artifact-metadata", endpoint, deadline)
        result["steps"].append(step)
        need(step["complete_transport"], "FRESH_METADATA_TRANSPORT")
        meta = parse_json(metadata_raw)
        need(type(meta.get("id")) is int and meta["id"] == ARTIFACT
             and type(meta.get("size_in_bytes")) is int and meta["size_in_bytes"] == SIZE
             and meta.get("name") == NAME and meta.get("digest") == "sha256:" + DIGEST
             and meta.get("expired") is False, "FRESH_ARTIFACT_IDENTITY")
        run = meta.get("workflow_run", {})
        need(run.get("id") == RUN and run.get("head_sha") == HEAD, "FRESH_ARTIFACT_RUN_HEAD")
        # Preserve only the successfully validated API metadata body; no response headers.
        result["metadata"] = save("artifact-metadata.json", metadata_raw)
        result["metadata_identity_verified"] = True
        for group in RANGES:
            step, body = capture(group["label"], endpoint + "/zip", deadline,
                                 exact_range=(group["start"], group["end"]))
            result["steps"].append(step)
            if step["http_status"] == 206 and body:
                step["range_body"] = save(group["label"] + (".body" if step["complete_transport"] else ".body.partial"), body)
            if step["error"] == "RANGE_UNSUPPORTED_HTTP_STATUS":
                result["status"] = "RANGE_UNSUPPORTED"
            need(step["complete_transport"], "EXACT_206_SELECTED_RANGE_NOT_COMPLETE")
            for number in group["members"]:
                selected = MEMBERS[number]
                offset = selected["offset"] - group["start"]
                record = body[offset:offset + selected["end"] - selected["offset"]]
                raw = decode_member(record, selected)
                pin = save(selected["output"], raw)
                result["members"].append({"member": selected["path"], "zip_artifact_id": ARTIFACT,
                                          "range_label": group["label"], "raw": pin,
                                          "crc32_declared_hex": selected["crc32"],
                                          "crc32_verified": True, "exact_deflate_eof": True,
                                          "member_execution": False})
        need(len(result["members"]) == 6, "ALL_SELECTED_MEMBERS_REQUIRED")
        result["selected_member_crc_verified"] = True
        result["status"] = "SELECTED_MEMBERS_OBSERVED"
    except Exception as error:
        result["errors"].append(str(error) if isinstance(error, ValueError) else type(error).__name__)
    finally:
        result["finished_at"] = now()
        result["producer"] = {"path": str(Path(__file__).resolve()),
                              "bytes": len(Path(__file__).read_bytes()),
                              "sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
        summary = save_json("summary.json", result)
        print(json.dumps({"status": result["status"], "summary": summary,
                          "whole_artifact_sha256_verified": False, "qualification": False}), flush=True)
    return 0 if result["status"] == "SELECTED_MEMBERS_OBSERVED" else 1

if __name__ == "__main__":
    raise SystemExit(main())
