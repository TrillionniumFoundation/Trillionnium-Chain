"""Prepare PR847 metadata from an original confirmed publication or separate actual resume proof.

This module is inert on import. Only main performs two read-only GitHub queries.
The original publication status/bytes/exit are never synthesized or rewritten.
No mutation, hosted qualification or activation is granted by this preparation.
"""
import argparse, datetime, hashlib, ipaddress, json, math, os, pathlib, re, stat, string, sys

ROOT = pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
SOURCE = pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
SELF = ROOT / "prepare_pr847_audit_update_v10.py"
FOLLOWUP = ROOT / "publish_followup_candidate_execution_archive_v2.py"
FOLLOWUP_BYTES = 73492
FOLLOWUP_SHA = "0d0a9153f6a0f8aed7201afc77ba52fd2e6ea36009b155ce24d2e59cf1caf0e2"
PUBLISHER = ROOT / "publish_candidate_and_archive_v4.py"
PUBLISHER_SHA = "4105cd1db2e5219deda83a881872c51ac5cf671f5caa367bc2ea8ae4d4495038"
TEMPLATE = ROOT / "pr847-audit-body-template-v3.md"
TEMPLATE_SHA = "0d37a8132e7d9b262eefdb02f1e2968f26b5f8ec17e59a2701343cc9d611073a"
REPO = "TrillionniumFoundation/Trillionnium-Chain"
URL = "https://github.com/" + REPO
BASE = "dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
HEAD_REF = "fix/chain-hepta-closure-candidate-20261109-481716"
TITLE = "Consolidate audited branch history and current runtime"
QUERY = "{number,state,draft,node_id,head:.head.sha,head_ref:.head.ref,base:.base.sha,base_ref:.base.ref,title,body,auto_merge}"
PR_FIELDS = {"number", "state", "draft", "node_id", "head", "head_ref", "base",
             "base_ref", "title", "body", "auto_merge"}
PLACEHOLDERS = {
    "url", "head", "tree", "base", "execution_evidence_url", "publication_manifest_url",
    "seven_source_status", "seven_source_receipt_url", "full_linux_status",
    "full_linux_receipt_url", "hosted_head_status", "hosted_head_checks_url",
    "hosted_merge_status", "hosted_merge_checks_url", "hosted_observed_at",
    "historical_collector_disposition", "archive_tag", "tag_oid", "archive_commit",
    "archive_candidate_head",
}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)

def read_regular(path, expected_sha=None, maximum=8 * 1024 * 1024):
    path = pathlib.Path(path)
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
            "canonical input path required")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= maximum, "regular bounded single-link file required")
    def fp(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        require(fp(os.fstat(stream.fileno())) == fp(before), "input changed before read")
        raw = stream.read(before.st_size + 1)
        require(fp(os.fstat(stream.fileno())) == fp(before), "input changed during read")
    require(fp(path.lstat()) == fp(before) and len(raw) == before.st_size,
            "input path or length changed during read")
    if expected_sha is not None:
        require(sha(raw) == expected_sha, "input SHA256 differs: " + str(path))
    return raw


def safe_environment(H):
    env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                "GIT_NAMESPACE", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        require(key not in env, "unexpected inherited Git repository/config override: " + key)
    for key in tuple(env):
        if key.startswith("GIT_TRACE") or key == "GIT_CURL_VERBOSE":
            del env[key]
    env.update(H["GATE_ENV"])
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_TRACE2="0", GIT_TRACE2_EVENT="0",
               GIT_TRACE2_PERF="0", PYTHONOPTIMIZE="0", PYTHONDONTWRITEBYTECODE="1")
    return env

def valid_pr_identity(value, node_id, head):
    require(isinstance(value, dict) and set(value) == PR_FIELDS, "PR field set differs")
    require(type(value["number"]) is int and value["number"] == 847
            and value["state"] == "open" and value["head"] == head
            and value["head_ref"] == HEAD_REF and value["base"] == BASE
            and value["base_ref"] == "main" and value["auto_merge"] is None,
            "PR number/state/head/base/auto_merge differs")
    require(isinstance(node_id, str) and bool(node_id) and value["node_id"] == node_id
            and type(value["draft"]) is bool and isinstance(value["title"], str)
            and (value["body"] is None or isinstance(value["body"], str)),
            "PR node/draft/metadata type differs")

def evidence_directory(value, prefix):
    path = pathlib.Path(value)
    require(path.parent == ROOT and ROOT.resolve(strict=True) == ROOT
            and re.fullmatch(re.escape(prefix) + r"(?:-[a-z0-9-]+)?", path.name),
            "unexpected create-only evidence directory")
    return path



PREVIOUS = ROOT / "prepare_pr847_audit_update_v5.py"
PREVIOUS_BYTES = 36663
PREVIOUS_SHA = "12776f0a436732589e46ef13548cb8f34180a532ab1ff63671560326c541cd6d"
RESUME = ROOT / "resume_followup_candidate_execution_archive_v3.py"
RESUME_BYTES = 78875
RESUME_SHA = "f4db0552a747f18525a4938510b5768e4852b0a787271762c6e80c204b829627"
RESUME_SESSION = "dpty-ab48705cce7d5c8fbd7f6ab139bb67b17e07a5c975b0d88f64db6a90bc3b6589"
RESUME_SPEC_PIN = {
    "path": str(ROOT / "resume-followup-spec-2a8646-parallel-hook-v1.json"),
    "bytes": 2428, "sha256": "7959ac71f53c52981a240832e2374e4ac49f08e536534a405a77d4e8b848b1ca",
}
MAX_META = 8 * 1024 * 1024

def load_previous():
    require(sys.flags.optimize == 0, "optimized interpreter forbidden")
    raw = read_regular(PREVIOUS, PREVIOUS_SHA)
    require(len(raw) == PREVIOUS_BYTES, "previous preparer length")
    P = {"__name__": "_fixed_pr847_v5", "__file__": str(PREVIOUS)}
    exec(compile(raw, str(PREVIOUS), "exec", optimize=0), P)
    require(P["ROOT"] == ROOT and P["SOURCE"] == SOURCE and P["BASE"] == BASE
            and P["REPO"] == REPO and P["HEAD_REF"] == HEAD_REF
            and P["TEMPLATE_SHA"] == TEMPLATE_SHA, "previous fixed scope differs")
    return P, raw

def pinned_raw(pin):
    require(type(pin) is dict and set(pin) == {"path", "bytes", "sha256"}
            and type(pin["path"]) is str and type(pin["bytes"]) is int
            and 0 <= pin["bytes"] <= MAX_META and type(pin["sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]), "strict pinned input")
    raw = read_regular(pin["path"], pin["sha256"])
    require(len(raw) == pin["bytes"], "pinned input length differs")
    return raw

def resume_terminal(raw, receipt, receipt_path):
    """Validate the independent actual closed PTY; never infer success from a live receipt."""
    value = strict_json(raw)
    require(type(value) is dict and set(value) == {
        "schema", "session_id", "archive_path", "terminal", "pages"}
        and value["schema"] == "trnm-actual-pty-pages-v1"
        and value["session_id"] == RESUME_SESSION, "actual resume terminal container")
    archive_path = value["archive_path"]
    require(type(archive_path) is str and pathlib.PurePosixPath(archive_path).is_absolute()
            and ".." not in pathlib.PurePosixPath(archive_path).parts, "terminal archive path")
    pages = value["pages"]
    require(type(pages) is list and 0 < len(pages) <= 512, "bounded complete terminal pages")
    def page_bytes(page):
        require(type(page) is dict and page.get("host") == "mac"
                and page.get("session_id") == RESUME_SESSION
                and page.get("archive_path") == archive_path, "actual resume session")
        require(type(page.get("offset")) is int and page["offset"] >= 0
                and page.get("truncated_before_offset") is False, "terminal cursor")
        encoded = page.get("bytes_hex")
        require(type(encoded) is str and len(encoded) % 2 == 0
                and re.fullmatch(r"[0-9a-f]*", encoded), "raw terminal encoding")
        chunk = bytes.fromhex(encoded)
        require(sha(chunk) == page.get("chunk_sha256")
                and type(page.get("next_offset")) is int
                and page["next_offset"] == page["offset"] + len(chunk), "terminal chunk identity")
        require(page.get("text_is_lossy") is False and page.get("utf8_pending") is False
                and type(page.get("text")) is str and page["text"].encode("utf-8") == chunk,
                "terminal original raw/text mismatch")
        return chunk
    chunks, cursor = [], 0
    for page in pages:
        chunk = page_bytes(page)
        require(page["offset"] == cursor, "terminal gap or overlap")
        cursor += len(chunk)
        require(cursor <= MAX_META, "terminal output bound")
        chunks.append(chunk)
    output = b"".join(chunks)
    terminal = value["terminal"]
    last = page_bytes(terminal)
    require(terminal["next_offset"] == cursor
            and output[terminal["offset"]:terminal["next_offset"]] == last,
            "terminal final observation differs")
    for page in pages + [terminal]:
        status = page.get("status")
        require(type(status) is dict and status.get("state") == "exited"
                and type(status.get("exit_code")) is int and status["exit_code"] == 0
                and status.get("output_complete") is True and page.get("output_complete") is True
                and status.get("capture_error") is None, "resume is not authoritatively complete")
        for end in (page.get("available_end"), status.get("bytes_seen"), status.get("bytes_stored")):
            require(type(end) is int and end == cursor, "terminal output incomplete")
    require(output.splitlines(), "terminal output empty")
    wanted = {k: receipt[k] for k in (
        "schema", "status", "head", "tree", "push_started", "push_exit",
        "source_after_valid", "exact_hook_verified", "original_hook_verified",
        "publication_observation_phase")}
    wanted["receipt"] = receipt_path
    require(strict_json(output.splitlines()[-1]) == wanted, "actual terminal/receipt binding")
    return {"session_id": RESUME_SESSION, "archive_path": archive_path,
            "exit_code": 0, "output_complete": True, "page_count": len(pages),
            "bytes": len(output), "sha256": sha(output)}

def validate_transport_trace(C, trace, pushed):
    """Bind the actual typed-only diagnostic originals; never reconstruct a raw trace."""
    if not pushed:
        require(trace is None, "already-confirmed path must not invent a new trace")
        return None
    F = C["F"]
    directory = C["evidence_directory"] / "atomic-publish-resume-redacted-curl"
    keys = {"schema", "complete", "raw_trace_written", "header_auth_cookie_URL_or_body_retained",
            "trace_fd", "NO_DATA", "REDACT", "input_bytes_seen", "lines_seen",
            "unrecognized_or_header_lines_discarded", "overlong_lines_discarded",
            "events_retained", "eof", "errors", "bounds", "events", "scope", "summary"}
    require(type(trace) is dict and set(trace) == keys
            and trace["schema"] == "trnm-redacted-git-curl-info-v1"
            and trace["complete"] is True and trace["eof"] is True and trace["errors"] == []
            and trace["raw_trace_written"] is False
            and trace["header_auth_cookie_URL_or_body_retained"] is False
            and trace["NO_DATA"] is True and trace["REDACT"] is True
            and type(trace["trace_fd"]) is int and 3 <= trace["trace_fd"] <= 9,
            "complete typed-only trace proof required")
    require(type(trace["bounds"]) is dict and all(type(item) is int for item in trace["bounds"].values())
            and trace["bounds"] == {"parsed_input": 16777216, "line": 8192, "events": 4096,
            "retained_bytes": 524288, "postprocess_EOF_seconds": 5}
            and trace["scope"] == "Strict typed connection/DNS/ALPN/TLS events; not a complete HTTP trace.",
            "original trace bounds/scope differ")
    for field in ("input_bytes_seen", "lines_seen", "unrecognized_or_header_lines_discarded",
                  "overlong_lines_discarded", "events_retained"):
        require(type(trace[field]) is int and trace[field] >= 0, "typed trace counter")
    require(0 < trace["input_bytes_seen"] <= 16777216
            and 0 < trace["events_retained"] <= 4096
            and trace["lines_seen"] == trace["events_retained"] + trace["unrecognized_or_header_lines_discarded"]
            and trace["overlong_lines_discarded"] <= trace["unrecognized_or_header_lines_discarded"],
            "complete trace counter consistency")
    def retain(field, name, maximum):
        pin = trace[field]
        require(type(pin) is dict and set(pin) == {"path", "bytes", "sha256"}
                and pin["path"] == str(directory / name)
                and type(pin["bytes"]) is int and 0 < pin["bytes"] <= maximum,
                "exact bounded typed trace original")
        raw, record = F["pinned_bytes"](pin)
        C["snapshots"].append(record)
        C["retained"].append(("resume-typed-trace-" + name, pin["path"], raw))
        return raw
    summary_raw = retain("summary", "summary.json", 16384)
    summary = {key: item for key, item in trace.items() if key != "summary"}
    require(strict_json(summary_raw) == summary
            and summary_raw == (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode(),
            "trace receipt/actual summary bytes differ")
    raw = retain("events", "events.jsonl", 524288)
    lines = raw.splitlines(keepends=True)
    require(len(lines) == trace["events_retained"], "actual typed trace event count")
    shapes = {
        "tcp_connect_attempt": [{"ip", "port"}], "target_resolved": [set()], "dns_cache_hit": [set()],
        "resolved_addresses": [{"family", "addresses"}],
        "tcp_connected": [{"ip", "port", "connection"}],
        "connection_reused": [set(), {"connection"}], "connection_kept": [{"connection"}],
        "cached_connection_dead": [{"connection"}], "connection_closed": [{"connection"}],
        "libcurl_fresh_connection_retry": [{"retry_count"}],
        "alpn_offered": [{"protocols"}], "alpn_accepted": [{"protocol"}],
        "http_version": [{"version"}], "tls_negotiated": [{"version"}],
        "tls_certificate_verified": [set()], "tcp_connect_failed": [{"ip", "port", "reason"}],
        "target_connect_failed": [{"elapsed_ms", "reason"}],
    }
    def public_ip(value):
        require(type(value) is str, "typed IP string")
        address = ipaddress.ip_address(value)
        require(address.is_global and str(address) == value, "canonical public typed IP")
    previous_time = 0
    for line in lines:
        require(len(line) <= 2048 and line.endswith(b"\n"), "bounded complete typed event")
        event = strict_json(line)
        require(type(event) is dict and type(event.get("event")) is str
                and event["event"] in shapes, "unknown typed event")
        kind = event["event"]
        require(set(event) - {"event", "since_capture_ms"} in shapes[kind]
                and {"event", "since_capture_ms"} <= set(event), "typed event fields differ")
        elapsed = event["since_capture_ms"]
        require(type(elapsed) in (int, float) and math.isfinite(elapsed)
                and elapsed >= previous_time, "typed monotonic observation time")
        previous_time = elapsed
        require(line == (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode(),
                "actual canonical typed event bytes differ")
        if "ip" in event:
            public_ip(event["ip"])
            require(type(event["port"]) is int and event["port"] == 443, "typed destination port")
        for key in ("connection", "retry_count", "elapsed_ms"):
            if key in event:
                require((kind == "tcp_connected" and key == "connection" and event[key] is None)
                        or (type(event[key]) is int and event[key] >= 0), "typed connection/count")
        if kind == "resolved_addresses":
            require(event["family"] in ("IPv4", "IPv6") and type(event["addresses"]) is list
                    and len(event["addresses"]) <= 8, "typed DNS result")
            for address in event["addresses"]:
                public_ip(address)
        if kind == "alpn_offered":
            require(event["protocols"] in (["h2", "http/1.1"], ["h2"], ["http/1.1"]), "typed ALPN offer")
        if kind == "alpn_accepted":
            require(event["protocol"] in ("h2", "http/1.1"), "typed ALPN selection")
        if kind == "http_version":
            require(event["version"] in ("2", "1.1"), "typed HTTP version")
        if kind == "tls_negotiated":
            require(event["version"] in ("TLSv1", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"), "typed TLS version")
        if kind == "tcp_connect_failed":
            require(event["reason"] in ("timeout", "refused", "unreachable", "no_route", "other"), "typed connect result")
        if kind == "target_connect_failed":
            require(event["elapsed_ms"] <= 9999999999
                    and event["reason"] in ("could_not_connect", "timeout", "other"), "typed target result")
    return trace

def validate_resume_outcome(C, recovery_spec, recovery_pin, receipt_pin, terminal_pin):
    """Pure validation of actual resume originals; the old publication is never rewritten."""
    F, H = C["F"], C["H"]
    ev = C["evidence_directory"]
    require(ev.resolve(strict=True) == ev, "closed canonical resume directory")
    require(receipt_pin["path"] == str(ev / "summary.json"), "resume receipt path differs")
    snapshots, retained = C["snapshots"], C["retained"]
    def keep(pin, name):
        data, record = F["pinned_bytes"](pin)
        snapshots.append(record)
        retained.append((name, pin["path"], data))
        return data
    receipt_raw = keep(receipt_pin, "resume-receipt.json")
    receipt = strict_json(receipt_raw)
    require(receipt["schema"] == "trnm-followup-candidate-execution-resume-receipt-v3"
            and receipt["status"] in ("confirmed", "already_confirmed")
            and receipt["errors"] == [] and receipt["source_after_valid"] is True
            and receipt["original_hook_verified"] is True, "complete separate resume proof required")
    require(receipt["driver"] == {"path": str(RESUME), "bytes": RESUME_BYTES, "sha256": RESUME_SHA}
            and receipt["resume_spec"] == recovery_pin
            and type(receipt["transport_timeout_seconds"]) is int
            and receipt["transport_timeout_seconds"] == 3600, "resume producer/spec/budget")
    require(receipt["head"] == C["head"] and receipt["tree"] == C["tree"]
            and receipt["previous_own_published_head"] == C["previous_own_published_head"]
            and receipt["expected_remote_head"] == C["expected_remote_head"]
            and receipt["archive"] == C["archive"] and receipt["archive_rebuilt"] is False,
            "resume changed source/archive identity")
    require(receipt["original_publication_spec"] == recovery_spec["original_publication_spec"]
            and receipt["original_publication_receipt"] == recovery_spec["original_publication_receipt"]
            and receipt["original_publication_status"] == C["original_publication"]["status"]
            and receipt["original_terminal_pages"] == recovery_spec["original_terminal_pages"]
            and receipt["original_terminal_proof"] == C["original_terminal_proof"]
            and receipt["original_launch_inputs"] == recovery_spec["original_launch_inputs"]
            and receipt["original_coverage"] == C["original_coverage"]
            and receipt["validated_inputs"] == C["validated_inputs"]
            and receipt["original_hook_receipt"] == C["original_publication"]["hook_receipt"],
            "original proof must remain separate and unchanged")
    require(receipt["previous_resume_attempts"] == recovery_spec["previous_resume_attempts"]
            and receipt["previous_resume_failures"] == C["previous_resume_failures"],
            "both previous actual failed attempts must remain separate and unchanged")
    require(receipt["effective_hook_plan"] == C["effective_hook_plan"],
            "exact reviewed parallel-capture hook plan differs")
    for key in ("automatic_retry_authorized", "rollback_authorized", "main_merged", "branches_deleted",
                "protection_changed", "pr_metadata_changed", "auto_merge_enabled",
                "hosted_ci_qualification", "qualification_granted",
                "untouched_refs_and_protection_atomically_locked", "HTTP_protocol_or_product_budget_changed"):
        require(receipt[key] is False, "unexpected recovery scope: " + key)
    require(receipt["required_head_and_prospective_ci_must_still_pass"] is True
            and receipt["archive_preserves_history_not_semantic_equivalence"] is True,
            "qualification boundary changed")
    for key in ("started_at", "finished_at"):
        require(type(receipt[key]) is str and bool(receipt[key]), "closed resume time missing")
        require(datetime.datetime.fromisoformat(receipt[key]).tzinfo is not None, "timezone missing")
    pushed = receipt["status"] == "confirmed"
    phase = "after" if pushed else "before"
    require(receipt["push_started"] is pushed and receipt["publication_observation_phase"] == phase
            and receipt["hook_evidence_origin"] == ("resume" if pushed else "original_publication"),
            "actual resume path differs")
    if pushed:
        require(type(receipt["push_exit"]) is int and receipt["exact_hook_verified"] is True
                and type(receipt["push_started_at"]) is str, "actual resumed push outcome missing")
        datetime.datetime.fromisoformat(receipt["push_started_at"])
    else:
        require(receipt["push_exit"] is None and receipt["exact_hook_verified"] is False
                and receipt["hook_receipt"] is None and receipt["remote_after"] is None
                and "push_started_at" not in receipt, "already-confirmed path must not push")
    trace = validate_transport_trace(C, receipt["transport_trace"], pushed)
    invocation = receipt["invocation"]
    require(type(invocation) is dict and set(invocation) == {"argv", "executable", "optimize"}
            and type(invocation["optimize"]) is int and invocation["optimize"] == 0
            and type(invocation["executable"]) is str
            and pathlib.PurePosixPath(invocation["executable"]).is_absolute(), "actual invocation")
    argv = invocation["argv"]
    require(type(argv) is list and len(argv) == 7 and argv[0] == str(RESUME)
            and len(set(argv[1::2])) == 3
            and dict(zip(argv[1::2], argv[2::2])) == {
                "--spec": recovery_pin["path"], "--spec-bytes": str(recovery_pin["bytes"]),
                "--spec-sha256": recovery_pin["sha256"]}, "actual resume CLI input binding")
    rows = receipt["steps"]
    require(type(rows) is list and 0 < len(rows) <= 128, "bounded resume steps")
    by_label = {}
    for row in rows:
        label = row["label"]
        require(type(label) is str and re.fullmatch(r"[a-z0-9-]+", label)
                and label not in by_label, "duplicate/invalid resume step")
        by_label[label] = row
    consumed = []
    def step(label, argv, timeout=180, expected_exit=0, maximum=F["MAX_META"]):
        row = by_label[label]
        require(row["argv"] == argv and row["cwd"] == str(SOURCE)
                and type(row["timeout_seconds"]) is int and row["timeout_seconds"] == timeout
                and type(row["exit"]) is int and row["exit"] == expected_exit,
                "resume exact command/cwd/budget/result differs: " + label)
        consumed.append(label)
        channels = []
        for channel in ("stdout", "stderr"):
            path = ev / (label + "." + channel)
            require(row[channel + "_path"] == str(path), "resume raw path differs")
            raw, record = F["stable_bytes"](path, row[channel + "_bytes"],
                                           row[channel + "_sha256"], maximum=maximum)
            snapshots.append(record)
            retained.append(("resume-" + label + "." + channel, str(path), raw))
            channels.append(raw)
        return channels[0], channels[1]
    def local(name, maximum=F["MAX_META"]):
        raw, record = F["stable_bytes"](ev / name, maximum=maximum)
        snapshots.append(record)
        return raw
    expected_retained = {
        "resume-spec.json": pinned_raw(recovery_pin),
        "original-publication-spec.json": C["original_spec_raw"],
        "original-publication-receipt.json": C["original_publication_raw"],
        "original-terminal-pages.json": C["original_terminal_record_raw"],
        "original-terminal-output.bin": C["original_terminal_output"],
        "original-terminal-proof.json": (json.dumps(C["original_terminal_proof"],
            indent=2, sort_keys=True) + "\n").encode(),
        "archive-local.json": (json.dumps(C["archive"], indent=2, sort_keys=True) + "\n").encode(),
        "archive-file-index.json": C["archive_index_raw"],
        "expected-reviewed-remote-heads.json": (json.dumps(C["expected_heads"],
            indent=2, sort_keys=True) + "\n").encode(),
        "expected-published-dc42-heads.json": (json.dumps(C["published_heads"],
            indent=2, sort_keys=True) + "\n").encode(),
    }
    for name, raw in expected_retained.items():
        require(local(name) == raw, "resume retained original differs: " + name)
    for label, argv in (
        ("origin-push-url", ["git", "remote", "get-url", "--push", "--all", "origin"]),
        ("origin-fetch-url", ["git", "remote", "get-url", "--all", "origin"])):
        require(step(label, argv, 60)[0].decode().splitlines() == [F["URL"]], "canonical origin")
    require(step("existing-hook-config", ["git", "config", "--get", "core.hooksPath"], 60, 1)
            == (b"", b""), "existing mandatory hook config")
    hook_path = step("default-hook-path", ["git", "--no-replace-objects", "rev-parse",
        "--path-format=absolute", "--git-path", "hooks/pre-push"], 60)[0].decode().strip()
    require(pathlib.PurePosixPath(hook_path).is_absolute(), "recorded default hook path")
    archive = C["archive"]
    tagref = "refs/tags/" + archive["tag"]
    for label, ref, wanted in (
        ("old-local-tag", F["OLD_TAG_REF"], F["OLD_TAG_OID"]),
        ("old-local-peel", F["OLD_TAG_REF"] + "^{}", F["OLD_ARCHIVE_COMMIT"]),
        ("same-local-tag", tagref, archive["tag_oid"]),
        ("same-local-peel", tagref + "^{}", archive["commit"])):
        require(step(label, ["git", "--no-replace-objects", "rev-parse", ref], 60)[0].decode().strip()
                == wanted, "existing archive ref identity")
    for label, kind, oid, maximum in (
        ("old-archive-commit-object", "commit", F["OLD_ARCHIVE_COMMIT"], 128 * 1024),
        ("old-archive-tag-object", "tag", F["OLD_TAG_OID"], 64 * 1024),
        ("same-archive-commit-object", "commit", archive["commit"], 128 * 1024),
        ("same-archive-tag-object", "tag", archive["tag_oid"], 64 * 1024)):
        size = step(label + "-size", ["git", "--no-replace-objects", "cat-file", "-s", oid], 60)[0].decode().strip()
        require(re.fullmatch(r"[1-9][0-9]*", size) and int(size) <= maximum, "bounded existing object")
        raw = step(label, ["git", "--no-replace-objects", "cat-file", kind, oid], 60, maximum=maximum)[0]
        require(len(raw) == int(size) and F["git_object_oid"](kind, raw) == oid, "object content address")
        if label == "old-archive-commit-object":
            F["check_commit_object"](raw, oid, F["OLD_ARCHIVE_TREE"], C["old_parents"])
        elif label == "old-archive-tag-object":
            F["check_tag_object"](raw, oid, F["OLD_TAG"], F["OLD_ARCHIVE_COMMIT"])
        elif kind == "commit":
            F["check_commit_object"](raw, oid, archive["tree"], [F["OLD_ARCHIVE_COMMIT"], C["head"]])
        else:
            F["check_tag_object"](raw, oid, archive["tag"], archive["commit"])
    require(step("same-archive-exact-tree-list", ["git", "ls-tree", "-r", "-z", archive["tree"]], 60)[0]
            == C["archive_tree_listing"], "same exact archived file roster")
    step("project-preflight", ["bash", "scripts/project-preflight.sh", "--audit"])
    before_raw = local("source-before.json")
    require(step("verify-source-before", [H["PYTHON"], "-B", "scripts/ci/verify_ci_source.py",
        "--kind", "head", "--expected-head", C["head"], "--output", str(ev / "source-before.json")])[0]
        == before_raw == C["source_before_raw"]
        and H["validate_source_identity"](before_raw, C["head"], C["tree"]) == C["gate_source"],
        "resume original/fresh source-before binding")
    for label, ancestor, descendant in (
        ("candidate-fast-forward", F["BASE_HEAD"], C["head"]),
        ("main-ancestry", F["MAIN_HEAD"], C["head"]),
        ("semantic-ledger-ancestry", "5c04c60e463462d9df8884786e0d5bb32af08a64", C["head"]),
        ("published-to-reviewed-remote", F["BASE_HEAD"], C["expected_remote_head"]),
        ("reviewed-remote-to-candidate", C["expected_remote_head"], C["head"]),
        ("published-to-rog-start", F["BASE_HEAD"], C["original_spec"]["rog_invocation"]["expected_start_head"]),
        ("rog-start-to-candidate", C["original_spec"]["rog_invocation"]["expected_start_head"], C["head"])):
        require(step(label, ["git", "--no-replace-objects", "merge-base", "--is-ancestor",
                            ancestor, descendant], 60)[0] == b"", "actual ancestry record")
    actor_argv = ["gh", "api", "user", "--jq", "{login,id}"]
    require(strict_json(step("actor", actor_argv)[0]) == C["actor"] == receipt["actor"], "resume actor")
    pr_argv = ["gh", "api", "repos/" + REPO + "/pulls/847", "--jq",
        "{number,state,draft,head:.head.sha,head_ref:.head.ref,base:.base.sha,base_ref:.base.ref,auto_merge}"]
    pr = strict_json(step("pr-before", pr_argv)[0])
    expected_pr = dict(C["publication_pr"])
    expected_pr["head"] = C["expected_remote_head"] if pushed else C["head"]
    require(pr == expected_pr == receipt["pr_before"], "resume exact PR/base/draft/auto_merge")
    def observation(phase, heads, tags, both_old, both_new):
        value = receipt["remote_" + phase]
        require(type(value) is dict and set(value) == {
            "observed_at", "heads", "tags", "errors", "both_old", "both_new"}
            and value["heads"] == heads and value["tags"] == tags and value["errors"] == []
            and value["both_old"] is both_old and value["both_new"] is both_new, "complete actual remote state")
        require(datetime.datetime.fromisoformat(value["observed_at"]).tzinfo is not None, "observation time")
        heads_raw = step("remote-" + phase + "-heads", ["git", "ls-remote", "--heads", "origin"])[0]
        tags_raw = step("remote-" + phase + "-tags", ["git", "ls-remote", "origin",
            *sorted(C["old_tags"]), tagref, tagref + "^{}"])[0]
        require(F["parse_refs"](heads_raw, heads=True) == heads
                and F["parse_refs"](tags_raw, allowed=set(C["wanted_tags"])) == tags,
                "actual complete remote raw data differs")
        return value
    observed_before = observation("before", C["expected_heads"] if pushed else C["wanted_heads"],
        C["old_tags"] if pushed else C["wanted_tags"], pushed, not pushed)
    if pushed:
        require(C["original_publication"]["status"] != "confirmed", "no retry of known confirmed original")
        step("prepush-preflight", ["bash", "scripts/project-preflight.sh", "--audit"])
        require(step("prepush-origin-push-url", ["git", "remote", "get-url", "--push", "--all", "origin"], 60)[0]
                .decode().splitlines() == [F["URL"]], "prepush origin")
        require(step("prepush-existing-hook-config", ["git", "config", "--get", "core.hooksPath"], 60, 1)
                == (b"", b""), "mandatory hook appeared")
        require(strict_json(step("pr-prepush", pr_argv)[0]) == pr, "prepush PR differs")
        require(strict_json(step("actor-prepush", actor_argv)[0]) == C["actor"], "prepush actor differs")
        require(local("hooks/expected.json") == C["expected_hook_raw"]
                and local("hooks/pre-push") == C["effective_hook_raw"], "exact reviewed effective hook")
        step("atomic-publish-resume", ["git", "-c", "core.hooksPath=" + str(ev / "hooks"),
            "push", "--verify", "--atomic", "--porcelain", "--verbose", "--progress", "origin",
            C["head"] + ":" + F["CANDIDATE_REF"], tagref + ":" + tagref], 3600,
            receipt["push_exit"], maximum=F["MAX_FILE"])
        effective = observation("after", C["wanted_heads"], C["wanted_tags"], False, True)
        require(receipt["hook_receipt"] == F["verify_hook_receipt"](
            ev / "hooks", C["expected_hook_raw"], C["effective_hook_raw"], C["expected_hook"]),
            "actual new hook invocation/readback differs")
    else:
        effective = observed_before
    after_raw = local("source-after.json")
    require(step("verify-source-after", [H["PYTHON"], "-B", "scripts/ci/verify_ci_source.py",
        "--kind", "head", "--expected-head", C["head"], "--output", str(ev / "source-after.json")])[0]
        == after_raw == before_raw == C["source_after_raw"]
        and H["validate_source_identity"](after_raw, C["head"], C["tree"]) == C["gate_source"],
        "resume source-after exact stdout/sidecar/gates")
    for field in ("source_before_identity", "source_after_identity"):
        require(receipt[field] == {"head": C["head"], "tree": C["tree"], "status": ""}, "source identity")
    require([r["label"] for r in rows] == consumed, "resume exact command order/roster differs")
    terminal_raw = keep(terminal_pin, "resume-actual-terminal-pages.json")
    terminal = resume_terminal(terminal_raw, receipt, receipt_pin["path"])
    completion = {"kind": "resume-executor", "receipt": receipt_pin,
        "original_receipt": C["original_publication_pin"], "resume_spec": recovery_pin,
        "actual_terminal": terminal_pin, "status": receipt["status"],
        "observation_phase": phase, "observation": effective,
        "transport_exit": receipt["push_exit"], "terminal_proof": terminal,
        "previous_resume_attempts": receipt["previous_resume_attempts"],
        "previous_resume_failures": receipt["previous_resume_failures"],
        "transport_trace": trace, "effective_hook_plan": receipt["effective_hook_plan"]}
    return receipt, completion

def complete_context(ctx, extra):
    F = ctx["F"]
    for name, path, raw in extra:
        data, record = F["stable_bytes"](path, len(raw), sha(raw))
        require(data == raw, "fixed adapter dependency changed")
        ctx["snapshots"].append(record)
        ctx["retained"].append((name, str(path), raw))
    by_path = {}
    for row in ctx["snapshots"]:
        require(by_path.setdefault(row["path"], row) == row, "dependency changed between reads")
    ctx["dependency_index"] = {"schema": "trnm-pr847-local-validated-dependencies-v1",
                             "files": [by_path[k] for k in sorted(by_path)]}
    names = set()
    for name, _, _ in ctx["retained"]:
        require(name not in names, "retained dependency name collision")
        names.add(name)
    F["check_versions"](ctx["snapshots"])
    return ctx

def render_resume_context(C, value, input_path, input_raw, receipt, completion):
    """Use the unchanged V3 body template and verified original archive; no terminal receipt is placed in it."""
    F, H = C["F"], C["H"]
    archive, payload, indexed = C["archive"], C["payload"], C["indexed"]
    snapshots, retained = C["snapshots"], C["retained"]
    head, tree, spec = C["head"], C["tree"], C["original_spec"]
    def archive_bytes(name, data):
        require(indexed[name] == {"path": name, "bytes": len(data), "sha256": sha(data),
            "git_blob": F["git_object_oid"]("blob", data), "mode": "100644"}, "public original archive bytes")
    collector = value["collector_disposition"]
    require(isinstance(collector, dict), "explicit collector disposition required")
    if collector == {"state": "pending"}:
        collector_text = ("A separate reviewed disposition is still pending. No repair, current-source "
                          "qualification or replay of historical results is asserted by this preparation.")
    else:
        require(set(collector) == {"state", "payload_path", "exact_excerpt"}
                and collector["state"] == "reviewed", "unsupported collector disposition")
        name = str(F["safe_relative"](collector["payload_path"]))
        require(re.fullmatch(r"[A-Za-z0-9._/-]+", name), "collector public-link path is not URL-safe")
        excerpt = collector["exact_excerpt"]
        require(type(excerpt) is str and 0 < len(excerpt.encode()) <= 1600
                and "\n" not in excerpt and "\r" not in excerpt
                and not any(ord(c) < 32 for c in excerpt), "bounded single-paragraph collector excerpt required")
        collector_raw = payload["payload"][name]
        require(excerpt.encode("utf-8") in collector_raw,
                "collector wording must be an exact excerpt of the retained reviewed evidence")
        archive_bytes("payload/" + name, collector_raw)
        escaped = excerpt.replace("\\", "\\\\")
        for char in (chr(96), "*", "_", "[", "]", "<", ">"):
            escaped = escaped.replace(char, "\\" + char)
        collector_text = escaped + " ([separate reviewed disposition](" + URL + "/blob/" + archive["commit"] + "/payload/" + name + "))."
        retained.append(("collector-disposition-original", str(pathlib.Path(
            payload["manifest"]["payload_root"]) / name), collector_raw))
    template_raw = read_regular(TEMPLATE, TEMPLATE_SHA)
    _, template_snapshot = F["stable_bytes"](TEMPLATE, len(template_raw), TEMPLATE_SHA)
    snapshots.append(template_snapshot)
    retained.append(("body-template-v3.md", str(TEMPLATE), template_raw))
    fields = []
    for _, field, format_spec, conversion in string.Formatter().parse(template_raw.decode("utf-8")):
        if field is not None:
            require(not format_spec and conversion is None, "unexpected template formatting operation")
            fields.append(field)
    require(set(fields) == PLACEHOLDERS, "closed template placeholder roster differs")
    archive_url = URL + "/blob/" + archive["commit"] + "/"
    render = {
        "url": URL, "head": head, "tree": tree, "base": BASE,
        "execution_evidence_url": archive_url + "metadata/execution-manifest.json",
        "publication_manifest_url": archive_url + "metadata/archive-file-index.json",
        "seven_source_status": "Passed on this exact candidate (seven original commands)",
        "seven_source_receipt_url": archive_url + "metadata/local-gates.json",
        "full_linux_status": "Passed on this exact candidate (original complete fail-fast lane)",
        "full_linux_receipt_url": archive_url + "metadata/rog-full-lane.json",
        "hosted_head_status": "Not established by this preparation; required checks remain mandatory",
        "hosted_head_checks_url": URL + "/pull/847/checks",
        "hosted_merge_status": "Not established by this preparation; required checks remain mandatory",
        "hosted_merge_checks_url": URL + "/pull/847/checks",
        "hosted_observed_at": "Not supplied for this final candidate/base; no hosted pass asserted",
        "historical_collector_disposition": collector_text,
        "archive_tag": archive["tag"], "tag_oid": archive["tag_oid"],
        "archive_commit": archive["commit"], "archive_candidate_head": archive["candidate_head"],
    }
    body_raw = template_raw.decode("utf-8").format(**render).encode("utf-8")
    require(len(body_raw) <= 16000, "reviewable PR body exceeds finite size bound")
    facts = {
        "head": head, "tree": tree, "base": BASE, "pr_number": 847, "head_ref": HEAD_REF,
        "previous_own_published_head": C["previous_own_published_head"],
        "expected_remote_head": C["expected_remote_head"],
        "publication_spec": value["publication_spec"], "publication_receipt": value["publication_receipt"],
        "publication_status": C["original_publication"]["status"],
        "publication_transport_exit": C["original_publication"]["push_exit"],
        "publication_observation_phase": "after",
        "publication_resume_spec": value["publication_resume_spec"],
        "publication_resume_receipt": value["publication_resume_receipt"],
        "publication_resume_terminal": value["publication_resume_terminal"],
        "publication_resume_status": receipt["status"],
        "publication_resume_transport_exit": receipt["push_exit"],
        "publication_completion": {k: v for k, v in completion.items() if k != "observation"},
        "archive": archive, "original_branch_names": 908, "original_distinct_tips": 892,
        "original_archive_direct_parents": 893, "execution_manifest": spec["execution_manifest"],
        "seven_gate_receipt": spec["local_gate_receipt"], "seven_gate_commands": 7,
        "full_linux_receipt": spec["rog_lane_receipt"], "original_linux_commands": 18,
        "hosted_checks": value["hosted_checks"], "collector_disposition": collector,
        "template": {"path": str(TEMPLATE), "bytes": len(template_raw), "sha256": TEMPLATE_SHA},
        "qualification_granted": False,
    }
    return {"F": F, "H": H, "head": head, "tree": tree, "gate_source": C["gate_source"],
        "body_raw": body_raw, "facts": facts, "snapshots": snapshots, "retained": retained,
        "input_pin": {"path": str(input_path), "bytes": len(input_raw), "sha256": sha(input_raw)},
        "publication_actor": C["actor"], "publication_completion": completion}

def validate_inputs(path, digest):
    """Two explicit evidence paths; no synthesized publication receipt or remote call."""
    require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest), "exact inputs SHA")
    P, previous_raw = load_previous()
    raw = read_regular(path, digest)
    value = strict_json(raw)
    require(type(value) is dict, "explicit input object required")
    if value.get("schema") == "trnm-pr847-final-audit-inputs-v1":
        # Preserve the complete prior successful-publication validator unmodified.
        ctx = P["validate_inputs"](path, digest)
        originals = [data for name, _, data in ctx["retained"] if name == "confirmed-publication.json"]
        require(len(originals) == 1, "normal original publication proof")
        publication = strict_json(originals[0])
        completion = {"kind": "original-publisher", "receipt": value["publication_receipt"],
            "original_receipt": value["publication_receipt"], "resume_spec": None,
            "actual_terminal": None, "status": publication["status"], "observation_phase": "after",
            "observation": publication["remote_after"], "transport_exit": publication["push_exit"],
            "terminal_proof": None}
        ctx["publication_completion"] = completion
        ctx["facts"] = dict(ctx["facts"], publication_completion={
            k: v for k, v in completion.items() if k != "observation"})
        return complete_context(ctx, [("preparer-v5.py", PREVIOUS, previous_raw)])
    require(set(value) == {"schema", "publication_spec", "publication_receipt",
        "publication_resume_spec", "publication_resume_receipt", "publication_resume_terminal",
        "hosted_checks", "collector_disposition"}
        and value["schema"] == "trnm-pr847-final-audit-inputs-v2", "explicit recovery input schema")
    require(value["hosted_checks"] == {"state": "not_observed_for_final_candidate"},
            "this preparer accepts no caller-supplied hosted success")
    require(value["publication_resume_spec"] == RESUME_SPEC_PIN, "exact actual parallel-hook resume spec required")
    recovery_raw = pinned_raw(value["publication_resume_spec"])
    recovery_spec = strict_json(recovery_raw)
    require(recovery_spec["original_publication_spec"] == value["publication_spec"]
            and recovery_spec["original_publication_receipt"] == value["publication_receipt"]
            and recovery_spec["resume_sha256"] == RESUME_SHA, "separate original/resume binding")
    resume_raw = read_regular(RESUME, RESUME_SHA)
    require(len(resume_raw) == RESUME_BYTES, "reviewed resume source length")
    R = {"__name__": "_reviewed_closed_resume_proof", "__file__": str(RESUME)}
    exec(compile(resume_raw, str(RESUME), "exec", optimize=0), R)
    require(R["ROOT"] == ROOT and R["SOURCE"] == SOURCE and R["SELF"] == RESUME
            and R["FOLLOWUP_SHA"] == FOLLOWUP_SHA and R["TRANSPORT_SECONDS"] == 3600,
            "reviewed resume helper scope differs")
    C = R["validate_closed_original_inputs"](recovery_spec)
    require(C["F"]["MAIN_HEAD"] == BASE and C["F"]["REPOSITORY"] == REPO
            and C["F"]["CANDIDATE_REF"] == "refs/heads/" + HEAD_REF, "fixed resumed publication scope")
    # Only rename the copied label. The original UNKNOWN bytes/status/exit stay exact.
    C["retained"] = [("original-publication.json" if name == "confirmed-publication.json" else name, origin, data)
                     for name, origin, data in C["retained"]]
    receipt, completion = validate_resume_outcome(C, recovery_spec, value["publication_resume_spec"],
        value["publication_resume_receipt"], value["publication_resume_terminal"])
    ctx = render_resume_context(C, value, path, raw, receipt, completion)
    extra = [("final-inputs.json", pathlib.Path(path), raw),
        ("preparer-v5.py", PREVIOUS, previous_raw), ("resume-producer-v3.py", RESUME, resume_raw),
        ("resume-spec.json", pathlib.Path(value["publication_resume_spec"]["path"]), recovery_raw)]
    retained_paths = {str(origin) for _, origin, _ in ctx["retained"] + extra}
    seen_reads = {}
    for pin, version in R["READS"]:
        require(seen_reads.setdefault(pin["path"], (pin, version)) == (pin, version),
                "original recovery pin changed between reads")
    external_coverage = {
        "path": "/private/tmp/chain-prci-final-execution-coverage-checker-20261114-v1/run-final-v1/summary.json",
        "bytes": 9614, "sha256": "49b43f68b433423cb5af57ce56db18c00d7aa0f320a325740946e6d86bdf8004",
    }
    for number, (source, (pin, version)) in enumerate(sorted(seen_reads.items())):
        if pin == C["original_coverage"]["receipt"]:
            # This one reviewed original is within R's explicit CHECKER_ROOT, not F's ROOT.
            # Do not widen F.stable_bytes or route this original through complete_context.extra.
            require(pin == external_coverage, "exact reviewed external coverage pin differs")
            data = R["read_pin"](pin)
            current = pathlib.Path(source).lstat()
            require(R["identity"](current) == version, "external coverage version changed")
            record = {"path": source, "bytes": len(data), "sha256": sha(data),
                      "version": C["F"]["fingerprint"](current)}
            ctx["snapshots"].append(record)
            if source not in retained_paths:
                ctx["retained"].append(("original-read-" + str(number) + ".raw", source, data))
                retained_paths.add(source)
            continue
        data, record = C["F"]["pinned_bytes"](pin)
        require(R["identity"](pathlib.Path(source).lstat()) == version, "original recovery dependency changed")
        ctx["snapshots"].append(record)
        if source not in retained_paths:
            extra.append(("original-read-" + str(number) + ".raw", pathlib.Path(source), data))
            retained_paths.add(source)
    return complete_context(ctx, extra)

def preparation_commands():
    return [("actor", ["gh", "api", "user", "--jq", "{login,id}"]),
            ("pr-before", ["gh", "api", "repos/" + REPO + "/pulls/847", "--jq", QUERY])]

def main():
    require(sys.flags.optimize == 0, "optimized interpreter is not allowed")
    require(pathlib.Path(__file__).resolve(strict=True) == SELF, "unexpected preparer location")
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--evidence-dir", required=True)
    args = parser.parse_args()
    ev = evidence_directory(args.evidence_dir, "prepare-pr847-audit-update-v10")
    ctx = validate_inputs(args.inputs, args.inputs_sha256)
    H, F = ctx["H"], ctx["F"]
    env = safe_environment(H)
    os.umask(0o077)
    ev.mkdir(mode=0o700, exist_ok=False)
    inputs = ev / "inputs"
    inputs.mkdir(mode=0o700)
    retained, steps = [], []
    for name, original_path, data in ctx["retained"]:
        target = inputs / name
        with target.open("xb") as stream:
            stream.write(data)
        require(read_regular(target) == data, "retained fixed input differs")
        retained.append({"source_path": original_path, "retained_path": str(target),
                         "bytes": len(data), "sha256": sha(data)})
    dependency_raw = (json.dumps(ctx["dependency_index"], sort_keys=True, indent=2) + "\n").encode()
    with (ev / "dependencies.json").open("xb") as stream:
        stream.write(dependency_raw)
    result = {"schema": "prepared-pr847-audit-update-v10", "status": "HOLD", "remote_writes": False,
        "started_at": now(), "driver": {"path": str(SELF), "sha256": sha(read_regular(SELF))},
        "inputs": ctx["input_pin"], "validated_facts": ctx["facts"],
        "dependencies": {"path": str(ev / "dependencies.json"), "bytes": len(dependency_raw),
                         "sha256": sha(dependency_raw)}, "retained_inputs": retained,
        "steps": steps, "errors": []}
    def save():
        (ev / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
        (ev / "steps.json").write_text(json.dumps(steps, indent=2) + "\n")
    def run(label, argv):
        began = now()
        q = H["capture"](argv, env, timeout=180)
        row = {"label": label, "argv": argv, "cwd": str(SOURCE), "exit": q.returncode,
               "timeout_seconds": 180, "started_at": began, "finished_at": now()}
        for channel in ("stdout", "stderr"):
            data = getattr(q, channel)
            path = ev / (label + "." + channel)
            with path.open("xb") as stream:
                stream.write(data)
            row.update({channel + "_path": str(path), channel + "_bytes": len(data),
                        channel + "_sha256": sha(data)})
        steps.append(row)
        save()
        require(q.returncode == 0, "read failed: " + label)
        return q.stdout
    save()
    try:
        F["check_versions"](ctx["snapshots"])
        actor_raw = run(*preparation_commands()[0])
        actor = strict_json(actor_raw)
        require(actor == ctx["publication_actor"], "authenticated actor differs from confirmed publication")
        before_raw = run(*preparation_commands()[1])
        before = strict_json(before_raw)
        valid_pr_identity(before, before["node_id"], ctx["head"])
        F["check_versions"](ctx["snapshots"])
        body_raw = ctx["body_raw"]
        with (ev / "pr-body.md").open("xb") as stream:
            stream.write(body_raw)
        desired = {"title": TITLE, "body": body_raw.decode("utf-8"), "head": ctx["head"],
            "tree": ctx["tree"], "base": BASE, "base_ref": "main", "pr_number": 847,
            "pr_node_id": before["node_id"], "mark_ready_after_metadata_verified": True}
        desired_raw = (json.dumps(desired, indent=2) + "\n").encode()
        with (ev / "desired.json").open("xb") as stream:
            stream.write(desired_raw)
        result.update(status="prepared", before_raw_sha256=sha(before_raw),
            before_title=before["title"], before_draft=before["draft"],
            before_body_bytes=len((before["body"] or "").encode("utf-8")),
            desired_title=TITLE, desired_body_path=str(ev / "pr-body.md"),
            desired_body_bytes=len(body_raw), desired_body_sha256=sha(body_raw),
            desired_path=str(ev / "desired.json"), desired_sha256=sha(desired_raw))
    except Exception as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        result["finished_at"] = now()
        save()
    print(json.dumps({"status": result["status"], "summary": str(ev / "summary.json"),
                      "remote_writes": False}), flush=True)
    return 0 if result["status"] == "prepared" else 1

if __name__ == "__main__":
    sys.exit(main())
