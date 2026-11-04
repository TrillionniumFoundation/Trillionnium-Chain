#!/usr/bin/env python3
"""Read four frozen 40a fetch failures; archive contents are data only."""
import hashlib, json, os, stat, urllib.error, urllib.parse, urllib.request, zipfile
from pathlib import Path
REPO = "TrillionniumFoundation/Trillionnium-Chain"
BRANCH = "fix/chain-retained-failure-readback-20261104"
BASE = "dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
TARGETS = json.loads(r'''[{"id":13302207260,"job":126429599723,"job_name":"rust-baseline shard (quality)","name":"rust-observations-head-40a5ba25e40fd5eda5b04fc1c3811320d438de11-1-quality","size":41663,"digest":"sha256:47237c5d9879f584617728d844534d9cd4ed86c972a1bfc69a200d004943b11b","kind":"head","fetch_member":"supply-chain/fetch-crates-1.log","run":41785836318,"attempt":1,"head":"40a5ba25e40fd5eda5b04fc1c3811320d438de11","tested":"40a5ba25e40fd5eda5b04fc1c3811320d438de11","tree":"75fe3367c4896a4f2d5f5dd561914613ec999343"},{"id":13301623824,"job":126429599917,"job_name":"prospective Rust shard (quality)","name":"rust-observations-prospective-merge-720606ee3ed65c943bda395c923e4d5b9bc0560c-1-quality","size":41773,"digest":"sha256:373446ee129ca43dece78d8e967f74b9b1ed93d1c669f1024278b86bb3241646","kind":"prospective-merge","fetch_member":"supply-chain/fetch-crates-1.log","run":41785836318,"attempt":1,"head":"40a5ba25e40fd5eda5b04fc1c3811320d438de11","tested":"720606ee3ed65c943bda395c923e4d5b9bc0560c","tree":"75fe3367c4896a4f2d5f5dd561914613ec999343"},{"id":13302016035,"job":126429599397,"job_name":"fuzz-smoke","name":"head-fuzz-smoke-40a5ba25e40fd5eda5b04fc1c3811320d438de11-1","size":4140,"digest":"sha256:f1191f55d4451b4cac3643eedd7ba67b16b2073a1105b7f13f8d2bad3a0fc4c8","kind":"head","fetch_member":"fuzz/fetch.log","run":41785836318,"attempt":1,"head":"40a5ba25e40fd5eda5b04fc1c3811320d438de11","tested":"40a5ba25e40fd5eda5b04fc1c3811320d438de11","tree":"75fe3367c4896a4f2d5f5dd561914613ec999343"},{"id":13302426232,"job":126429599964,"job_name":"prospective-merge (fuzz-smoke)","name":"merge-fuzz-smoke-720606ee3ed65c943bda395c923e4d5b9bc0560c-1","size":4189,"digest":"sha256:9a7228d240eb9f3992a00ccc656aa3c6ec65dd3ce46b0e379d221d10d758bcfa","kind":"prospective-merge","fetch_member":"fuzz/fetch.log","run":41785836318,"attempt":1,"head":"40a5ba25e40fd5eda5b04fc1c3811320d438de11","tested":"720606ee3ed65c943bda395c923e4d5b9bc0560c","tree":"75fe3367c4896a4f2d5f5dd561914613ec999343"}]''')

ROOT = Path(os.environ["READBACK_OUT"])
API = "https://api.github.com/repos/" + REPO
TOKEN = os.environ["GH_TOKEN"]
MAX_METADATA = 2 * 1024 * 1024
MAX_MEMBER = 32 * 1024 * 1024
MAX_SELECTED = 160 * 1024 * 1024
MAX_MEMBERS = 25000
MAX_STDOUT = 70000
SOURCE_MEMBERS = ("source.json", "source-before.json", "source-after.json")

class Refused(Exception):
    pass

def require(condition, label):
    if not condition:
        raise Refused(label)

require(os.environ["GITHUB_REPOSITORY"] == REPO, "REPOSITORY")
require(os.environ["GITHUB_REF"] == "refs/heads/" + BRANCH, "REF")
require(os.environ["GITHUB_EVENT_NAME"] == "push", "EVENT")
require(len(TARGETS) == len({x["id"] for x in TARGETS}) == 4, "TARGETS")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

AUTH = urllib.request.build_opener(NoRedirect())

def request_api(path):
    require(path.startswith("/actions/"), "API_PATH")
    req = urllib.request.Request(API + path, headers={
        "Authorization": "Bearer " + TOKEN,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "trnm-retained-failure-readback-v1",
    })
    return AUTH.open(req, timeout=60)

def read_json(path):
    with request_api(path) as response:
        raw = response.read(MAX_METADATA + 1)
    require(len(raw) <= MAX_METADATA, "METADATA_LIMIT")
    return json.loads(raw)

def write_json(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with path.open("xb") as stream:
        stream.write(raw)
    return hashlib.sha256(raw).hexdigest()

def archive(target, destination):
    # Only the GitHub API receives Authorization. The signed artifact URL is
    # fetched using a new request with no token and is never printed or saved.
    try:
        response = request_api("/actions/artifacts/" + str(target["id"]) + "/zip")
    except urllib.error.HTTPError as error:
        require(error.code in (301, 302, 303, 307, 308), "ARCHIVE_REDIRECT_STATUS")
        location = error.headers.get("Location")
        error.close()
        require(isinstance(location, str), "ARCHIVE_LOCATION")
        parsed = urllib.parse.urlsplit(location)
        require(parsed.scheme == "https" and parsed.hostname
                and parsed.username is None and parsed.password is None,
                "ARCHIVE_LOCATION_SCHEME")
        unsigned = urllib.request.Request(location, headers={
            "User-Agent": "trnm-retained-failure-readback-v1"})
        response = urllib.request.build_opener(NoRedirect()).open(unsigned, timeout=120)
    digest = hashlib.sha256()
    total = 0
    with response, destination.open("xb") as stream:
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            require(total <= target["size"], "ARCHIVE_SIZE_OVERRUN")
            digest.update(block)
            stream.write(block)
    require(total == target["size"], "ARCHIVE_SIZE")
    require("sha256:" + digest.hexdigest() == target["digest"], "ARCHIVE_DIGEST")
    return total


require(ROOT.is_absolute() and ROOT.parent == Path(os.environ["RUNNER_TEMP"])
        and ROOT.name == ("frozen-40a-fetch-failure-readback-"
                          + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]),
        "OUTPUT_LOCATION")

def source_observation(text, target):
    fields = ("schema", "kind", "candidate", "base", "prospective_merge",
              "tested_commit", "tested_tree", "tracked_entries", "tracked_bytes",
              "tracked_worktree_verified", "tests_executed_by_identity_check")
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return {"status": "invalid", "fields": dict.fromkeys(fields)}
    if not isinstance(value, dict):
        return {"status": "invalid", "fields": dict.fromkeys(fields)}
    original = {key: value.get(key) for key in fields}
    expected = {
        "schema": "trnm-ci-source-v1", "kind": target["kind"],
        "candidate": target["head"], "tested_commit": target["tested"],
        "tested_tree": target["tree"], "tracked_entries": 8113, "tracked_bytes": 932942579,
        "base": BASE if target["kind"] == "prospective-merge" else None,
        "prospective_merge": target["tested"] if target["kind"] == "prospective-merge" else None,
        "tracked_worktree_verified": True, "tests_executed_by_identity_check": False}
    missing = [key for key in fields if key not in value]
    mismatches = [key for key in fields if key in value
                  and (type(original[key]) is not type(expected[key])
                       or original[key] != expected[key])]
    return {"status": "mismatch" if mismatches else "unknown" if missing else "verified",
            "missing_fields": missing, "mismatching_fields": mismatches, "fields": original}

def validate_members(infos):
    require(len(infos) <= MAX_MEMBERS, "MEMBER_COUNT")
    require(len(infos) == len({info.filename for info in infos}), "DUPLICATE_MEMBER")
    for info in infos:
        name = info.filename
        directory = info.is_dir()
        parts = (name[:-1] if directory else name).split("/")
        require(name and name == info.orig_filename and "\0" not in name
                and "\\" not in name and not name.startswith("/")
                and all(part not in ("", ".", "..") for part in parts)
                and ":" not in parts[0], "MEMBER_PATH")
        kind = stat.S_IFMT(info.external_attr >> 16)
        # Type 0 is the ordinary ZIP/DOS representation without Unix type bits.
        # No archive path, permission, link or extra-field is extracted.
        require(kind in (0, stat.S_IFREG, stat.S_IFDIR)
                and (kind != stat.S_IFDIR or directory)
                and (not directory or kind != stat.S_IFREG)
                and (not (info.external_attr & 0x10) or directory), "MEMBER_NOT_REGULAR")
        require(not info.flag_bits & 1, "ENCRYPTED_MEMBER")

def read_member(bundle, info):
    require(0 <= info.file_size <= MAX_MEMBER, "MEMBER_SIZE_LIMIT")
    chunks, count = [], 0
    with bundle.open(info, "r") as stream:
        while True:
            block = stream.read(min(65536, MAX_MEMBER - count + 1))
            if not block:
                break
            count += len(block)
            require(count <= info.file_size and count <= MAX_MEMBER, "MEMBER_SIZE_OVERRUN")
            chunks.append(block)
    require(count == info.file_size, "MEMBER_SIZE")
    return b"".join(chunks)

def emit_record(record, allowance):
    projected = {key: record[key] for key in (
        "artifact", "member", "bytes", "sha256", "read_status", "original_text",
        "source_observation", "retained_file")}
    rendered = json.dumps(projected, sort_keys=True) + "\n"
    if len(rendered) > allowance:
        original = projected.pop("original_text")
        count = 8192
        while True:
            projected["console_truncated"] = True
            projected["complete_original_member_retained"] = True
            projected["text_prefix"] = original[:count // 2] if original is not None else None
            projected["text_suffix"] = original[-count:] if original is not None and count else None
            rendered = json.dumps(projected, sort_keys=True) + "\n"
            if len(rendered) <= allowance:
                break
            require(count > 0, "CONSOLE_METADATA_LIMIT")
            count //= 2
    # JSON escapes every embedded newline/control byte; archived text is never a command.
    print(rendered, end="", flush=True)
    return len(rendered)

results, had_error = [], False
for target in TARGETS:
    output = ROOT / str(target["id"])
    output.mkdir()
    stage, records, printed = "metadata", [], 0
    try:
        metadata = read_json("/actions/artifacts/" + str(target["id"]))
        run = read_json("/actions/runs/" + str(target["run"]))
        job = read_json("/actions/jobs/" + str(target["job"]))
        require(metadata["id"] == target["id"] and metadata["name"] == target["name"],
                "ARTIFACT_IDENTITY")
        require(metadata["size_in_bytes"] == target["size"]
                and metadata["digest"] == target["digest"] and metadata["expired"] is False,
                "ARTIFACT_METADATA")
        require(metadata["workflow_run"]["id"] == run["id"] == job["run_id"] == target["run"],
                "RUN_IDENTITY")
        require(metadata["workflow_run"]["head_sha"] == run["head_sha"] == job["head_sha"]
                == target["head"], "SOURCE_IDENTITY")
        require(run["run_attempt"] == target["attempt"] and run["event"] == "pull_request"
                and run["path"] == ".github/workflows/trnm-required-baseline.yml"
                and run["status"] in ("in_progress", "completed"), "ORIGINAL_RUN")
        require(job["id"] == target["job"] and job["name"] == target["job_name"]
                and job["status"] == "completed" and job["conclusion"] == "failure",
                "ORIGINAL_FAILED_JOB")
        write_json(output / "metadata.json", metadata)
        write_json(output / "run.json", run)
        write_json(output / "job.json", job)
        stage = "archive"
        received = archive(target, output / "original.zip")
        stage = "members"
        selected_bytes = 0
        with zipfile.ZipFile(output / "original.zip") as bundle:
            infos = bundle.infolist()
            validate_members(infos)
            index_sha = write_json(output / "members.json", [
                {"name": info.filename, "bytes": info.file_size,
                 "compressed_bytes": info.compress_size, "crc32": info.CRC,
                 "create_system": info.create_system, "external_attr": info.external_attr}
                for info in infos])
            allow = {target["fetch_member"], *SOURCE_MEMBERS}
            chosen = sorted((info for info in infos if info.filename in allow),
                            key=lambda info: (info.filename != target["fetch_member"], info.filename))
            for number, info in enumerate(chosen):
                require(not info.is_dir(), "SELECTED_DIRECTORY")
                require(selected_bytes + info.file_size <= MAX_SELECTED, "SELECTED_SIZE_LIMIT")
                raw = read_member(bundle, info)
                selected_bytes += len(raw)
                retained = f"member-{number:02}.raw"
                with (output / retained).open("xb") as stream:
                    stream.write(raw)
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    text = None
                record = {
                    "artifact": target["id"], "member": info.filename, "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(), "retained_file": retained,
                    "read_status": "read" if text is not None else "non_utf8_uninterpreted",
                    "original_text": text, "source_observation": (
                        (source_observation(text, target) if text is not None
                         else {"status": "invalid", "reason": "non_utf8_source", "fields": None})
                        if info.filename in SOURCE_MEMBERS else None)}
                records.append(record)
                limit = 24000 if info.filename == target["fetch_member"] else 12000
                printed += emit_record(record, min(limit, MAX_STDOUT - printed - 4096))
        fetch = next((row for row in records if row["member"] == target["fetch_member"]), None)
        sources = {name: next((row["source_observation"] for row in records
                               if row["member"] == name), None) for name in SOURCE_MEMBERS}
        source_mismatches = [name for name, value in sources.items()
                             if value is not None and value["status"] in ("invalid", "mismatch")]
        complete = fetch is not None and fetch["read_status"] == "read" and not source_mismatches
        had_error = had_error or not complete
        result = {
            "schema": "trnm-frozen-fetch-failure-readback-v1", "target": target,
            "reader_status": "completed" if complete else "failed",
            "original_run_status": run["status"], "original_run_conclusion": run.get("conclusion"),
            "original_job_conclusion": job["conclusion"], "original_fetch_exit_code": None,
            "downloaded_zip_bytes": received, "downloaded_zip_sha256": target["digest"][7:],
            "member_index_sha256": index_sha, "selected_text_bytes": selected_bytes,
            "fetch_member_present": fetch is not None,
            "source_observations": sources, "source_mismatches": source_mismatches,
            "absent_source_members": [name for name in SOURCE_MEMBERS
                                      if not any(row["member"] == name for row in records)],
            "records": records, "source_tests_executed": False, "acceptance_granted": False,
            "scope": "Original fetch and source text only. Missing source fields remain null; "
                     "the complete original ZIP and selected member bytes are retained. "
                     "No archived command is executed and no later fix is inherited."}
        write_json(output / "readback.json", result)
        summary = {key: value for key, value in result.items() if key not in ("records", "source_observations")}
        summary["records"] = len(records)
        summary["source_status"] = {name: value["status"] if value is not None else None
                                    for name, value in sources.items()}
        rendered = json.dumps(summary, sort_keys=True) + "\n"
        require(printed + len(rendered) <= MAX_STDOUT, "CONSOLE_LIMIT")
        print(rendered, end="", flush=True)
        results.append(summary)
    except Exception as error:
        had_error = True
        result = {"target": target, "reader_status": "failed", "stage": stage,
                  "error_type": type(error).__name__, "http_status": getattr(error, "code", None),
                  "reason": str(error) if isinstance(error, Refused) else None,
                  "records_retained": len(records), "source_tests_executed": False,
                  "acceptance_granted": False}
        write_json(output / "reader-failure.json", result)
        write_json(output / "partial-records.json", records)
        print(json.dumps(result, sort_keys=True), flush=True)
        results.append(result)
write_json(ROOT / "readback.json", {
    "schema": "trnm-frozen-fetch-failure-readback-cohort-v1",
    "planned_artifacts": len(TARGETS), "results": results,
    "source_tests_executed": False, "acceptance_granted": False})
raise SystemExit(1 if had_error else 0)
