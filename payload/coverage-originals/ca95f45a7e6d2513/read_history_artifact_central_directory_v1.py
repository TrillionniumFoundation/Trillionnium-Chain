#!/usr/bin/env python3
"""Fixed read-only central-directory GET after the closed tail probe; no member GETs."""
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

OUT = Path("/private/tmp/chain-prci-R1-history-artifact-central-directory-20261114-v1")
GH = "/opt/homebrew/bin/gh"
REPO = "TrillionniumFoundation/Trillionnium-Chain"
ARTIFACT = 14118769328
RUN = 43604217565
HEAD = "2a86462a1ab20c68151719ba4635e3c294391e64"
NAME = "priority-ubuntu-24.04-head-history-" + HEAD + "-1"
SIZE = 59887660
DIGEST = "cf934b39339e2039beb285ade75473b9bb1035b0a69441c13ce08d3b47e376dc"
RANGE_BYTES = 376516
START = 59511122
END = 59887637
ENTRY_COUNT = 4140
EOCD_OFFSET = 59887638
EXISTING_TAIL = Path("/private/tmp/chain-prci-R1-history-artifact-explicit-tail-probe-20261114-v2/tail-range.body")
EXISTING_TAIL_BYTES = 65557
EXISTING_TAIL_START = 59822103
EXISTING_TAIL_SHA = "f140bd7c067a6448800914fbccc9ed06b982fbde5485f5b6d1249681df39f559"
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

def capture(label, endpoint, deadline, range_probe=False):
    argv = [GH, "api", "--hostname", "github.com", "--method", "GET"]
    if range_probe:
        argv += ["--include", "--header", f"Range: bytes={START}-{END}"]
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
                    need(safe.get("content-range") == f"bytes {START}-{END}/{SIZE}", "EXACT_CD_CONTENT_RANGE_REQUIRED")
                    need("content-length" not in safe or safe["content-length"] == str(RANGE_BYTES), "EXACT_CD_CONTENT_LENGTH")
                    need(safe.get("content-encoding", "identity") == "identity", "ENCODED_RANGE_REFUSED")
                    got_headers = True
                cap = RANGE_BYTES if range_probe else 65536
                need(len(body) + len(chunk) <= cap, "BODY_BYTE_BOUND")
                body.extend(chunk)
        rec["exit"] = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        need(rec["exit"] == 0, "GH_GET_NONZERO")
        if range_probe:
            need(got_headers and rec["http_status"] == 206 and len(body) == RANGE_BYTES, "COMPLETE_EXACT_CD_REQUIRED")
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

def validate_existing_tail():
    raw = stable_bytes(EXISTING_TAIL, EXISTING_TAIL_BYTES, EXISTING_TAIL_SHA)
    position = EOCD_OFFSET - EXISTING_TAIL_START
    need(len(raw) == position + 22, "FIXED_EOCD_TERMINAL_OFFSET")
    fields = struct.unpack_from("<4s4H2IH", raw, position)
    need(fields == (b"PK\x05\x06", 0, 0, ENTRY_COUNT, ENTRY_COUNT,
                    RANGE_BYTES, START, 0), "FIXED_ACTUAL_EOCD")
    need(raw[position - 20:position - 16] != b"PK\x06\x07", "UNEXPECTED_ZIP64_LOCATOR")
    need(START + RANGE_BYTES == END + 1 == EOCD_OFFSET
         and EOCD_OFFSET + 22 == SIZE, "EXACT_DIRECTORY_ARCHIVE_BOUND")
    return raw

def central_directory(body, existing_tail):
    """Inventory exactly the observed 4,140 entries; never fetch or execute members."""
    need(len(body) == RANGE_BYTES, "EXACT_CD_BYTES")
    overlap = EOCD_OFFSET - EXISTING_TAIL_START
    need(body[-overlap:] == existing_tail[:overlap], "EXISTING_TAIL_OVERLAP_MISMATCH")
    count, cd_size, cd_offset, comment_size = ENTRY_COUNT, RANGE_BYTES, START, 0
    cursor, end = 0, len(body)
    rows, seen = [], set()
    for number in range(count):
        need(cursor + 46 <= end, "CENTRAL_HEADER_BOUND")
        fields = struct.unpack_from("<4s6H3I5H2I", body, cursor)
        sig, made, version, flags, method, mtime, mdate, crc, compressed, expanded, nlen, xlen, clen, member_disk, iattr, eattr, local_offset = fields
        need(sig == b"PK\x01\x02" and member_disk == 0, "CENTRAL_ENTRY_FRAMING")
        need(0 < nlen <= 1024 and cursor + 46 + nlen + xlen + clen <= end, "CENTRAL_ENTRY_LENGTH")
        need(compressed != 0xffffffff and expanded != 0xffffffff and local_offset != 0xffffffff, "ZIP64_ENTRY_REFUSED")
        need(local_offset < cd_offset and not flags & 0x41, "LOCAL_OFFSET_OR_ENCRYPTION_REFUSED")
        name_bytes = body[cursor + 46:cursor + 46 + nlen]
        name = name_bytes.decode("utf-8" if flags & 0x800 else "cp437")
        need(not any(ord(c) < 32 or ord(c) == 127 for c in name), "CONTROL_CHARACTER_PATH")
        need("\\" not in name and ":" not in name and "\x00" not in name, "UNSAFE_MEMBER_PATH")
        normalized = name[:-1] if name.endswith("/") else name
        path = PurePosixPath(normalized)
        need(normalized and not path.is_absolute() and path.as_posix() == normalized
             and all(part not in ("", ".", "..") for part in path.parts), "TRAVERSAL_MEMBER_PATH")
        need(normalized not in seen, "DUPLICATE_MEMBER_PATH")
        seen.add(normalized)
        filetype = stat.S_IFMT(eattr >> 16)
        need(filetype in (0, stat.S_IFREG, stat.S_IFDIR), "LINK_OR_SPECIAL_MEMBER_REFUSED")
        is_directory = name.endswith("/") or filetype == stat.S_IFDIR
        rows.append({"index": number, "path": name, "compressed_bytes": compressed,
                     "uncompressed_bytes": expanded, "compression_method": method,
                     "crc32_declared_hex": f"{crc:08x}", "crc32_verified": False,
                     "local_header_offset": local_offset, "flags": flags,
                     "directory": is_directory, "version_needed": version,
                     "small_member_candidate_only": (not is_directory and expanded <= 32 * 1024 * 1024
                                                      and compressed <= 16 * 1024 * 1024 and method in (0, 8))})
        cursor += 46 + nlen + xlen + clen
    need(cursor == end, "CENTRAL_DIRECTORY_COUNT_OR_TRAILING_BYTES")
    return {"schema": "trnm-r1-history-central-directory-observation-v1",
            "artifact_id": ARTIFACT, "complete_central_directory_observed": True,
            "existing_tail_overlap_verified": True,
            "entries": count, "central_directory_offset": cd_offset,
            "central_directory_bytes": cd_size, "eocd_absolute_offset": EOCD_OFFSET,
            "zip_comment_bytes": comment_size, "members": rows,
            "whole_artifact_sha256_verified": False, "all_member_crc_verified": False,
            "member_contents_downloaded_or_executed": False}

def main():
    need(sys.flags.optimize == 0, "OPTIMIZATION_FORBIDDEN")
    need(OUT.parent.resolve(strict=True) == OUT.parent, "OUTPUT_PARENT")
    OUT.mkdir(mode=0o700)
    started = now()
    deadline = time.monotonic() + BUDGET
    result = {"schema": "trnm-r1-history-artifact-central-directory-read-v1", "status": "HOLD",
              "started_at": started, "finished_at": None, "errors": [], "steps": [],
              "artifact_id": ARTIFACT, "run_id": RUN, "head": HEAD,
              "expected_artifact_name": NAME, "expected_archive_bytes": SIZE,
              "expected_whole_archive_sha256": DIGEST, "network_methods": ["GET"],
              "maximum_GETs": 2, "manual_redirect_following": False,
              "signed_URL_headers_auth_cookies_saved": False,
              "whole_artifact_sha256_verified": False, "all_member_crc_verified": False,
              "source_refs_config_CI_modified": False, "qualification": False,
              "automatic_other_ranges_or_retries": False}
    try:
        existing_tail = validate_existing_tail()
        result["existing_tail"] = {"path": str(EXISTING_TAIL), "bytes": EXISTING_TAIL_BYTES,
                                   "sha256": EXISTING_TAIL_SHA}
        result["exact_directory_scope"] = {"start": START, "end": END, "bytes": RANGE_BYTES,
                                           "entries": ENTRY_COUNT, "zip64": False}
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
        step, body = capture("central-directory-range", endpoint + "/zip", deadline, range_probe=True)
        result["steps"].append(step)
        if step["http_status"] == 206 and body:
            result["central_directory_body"] = save("central-directory.body" if step["complete_transport"] else "central-directory.body.partial", body)
        if step["error"] == "RANGE_UNSUPPORTED_HTTP_STATUS":
            result["status"] = "RANGE_UNSUPPORTED"
        need(step["complete_transport"], "EXACT_206_CD_NOT_COMPLETE")
        result["central_directory"] = save_json("central-directory.json", central_directory(body, existing_tail))
        result["status"] = "CENTRAL_DIRECTORY_OBSERVED"
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
    return 0 if result["status"] == "CENTRAL_DIRECTORY_OBSERVED" else 1

if __name__ == "__main__":
    raise SystemExit(main())
