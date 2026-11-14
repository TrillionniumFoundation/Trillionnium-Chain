"""Prepared-only R1 recovery executor. Execute only after review of this file and actual closed-input spec.
One ordinary atomic retry may follow a verified both-old state. Existing archive objects are reused.
"""
import argparse, datetime, hashlib, ipaddress, json, math, os, pathlib, re, selectors, signal, stat
import subprocess, sys, threading, time

ROOT = pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
SOURCE = pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
SELF = ROOT / "resume_followup_candidate_execution_archive_v3.py"
FOLLOWUP = ROOT / "publish_followup_candidate_execution_archive_v2.py"
FOLLOWUP_BYTES = 73492
FOLLOWUP_SHA = "0d0a9153f6a0f8aed7201afc77ba52fd2e6ea36009b155ce24d2e59cf1caf0e2"
CHECKER_ROOT = pathlib.Path("/private/tmp/chain-prci-final-execution-coverage-checker-20261114-v1")
HEAD = "2a86462a1ab20c68151719ba4635e3c294391e64"
TREE = "5c26776f96f15fd131e85a5c2d7c5e895ad7fab4"
REMOTE_HEAD = "096c6b5f9b952c49389fd975515744074ba61317"
ORIGINAL_SESSION = "dpty-9ebb8b96cf53f9abfa81965182f0c2a0856b2870f0268b09fe36b1e912dc2f06"
ORIGINAL_LAUNCHER_SHA = "2b611845764a6830e47ad05a897961db5c409958e8d2cc06d3165ca30e798376"
TRANSPORT_SECONDS = 3600
MAX_META = 8 * 1024 * 1024
READS = []

def require(value, message):
    if not value:
        raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, "duplicate JSON key")
            out[key] = value
        return out
    def finite(value):
        number = float(value)
        require(math.isfinite(number), "nonfinite JSON number")
        return number
    def invalid(value):
        raise ValueError("nonfinite JSON constant")
    return json.loads(raw, object_pairs_hook=pairs, parse_float=finite, parse_constant=invalid)

def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

def read_pin(pin):
    require(type(pin) is dict and set(pin) == {"path", "bytes", "sha256"}, "pin fields")
    require(type(pin["path"]) is str and "\\" not in pin["path"]
            and all(ord(c) >= 32 and ord(c) != 127 for c in pin["path"]), "pin path")
    p = pathlib.Path(pin["path"])
    require(p.is_absolute() and str(p) == pin["path"] and ".." not in p.parts
            and p.resolve(strict=True) == p
            and (p.is_relative_to(ROOT) or p.is_relative_to(CHECKER_ROOT)), "canonical pin scope")
    require(type(pin["bytes"]) is int and 0 <= pin["bytes"] <= MAX_META
            and type(pin["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]), "pin values")
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_size == pin["bytes"], "regular single-link pinned file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(pin["bytes"] + 1)
        require(identity(before) == identity(os.fstat(fd)), "pin changed during read")
    finally:
        os.close(fd)
    require(identity(p.lstat()) == identity(before) and len(raw) == pin["bytes"]
            and sha(raw) == pin["sha256"], "pin digest or identity mismatch")
    READS.append((dict(pin), identity(before)))
    return raw

def final_pin_fence():
    old = list(READS)
    for pin, version in old:
        raw = read_pin(pin)
        require(identity(pathlib.Path(pin["path"]).lstat()) == version, "original pinned input changed")

def load_helpers():
    raw = read_pin({"path": str(FOLLOWUP), "bytes": FOLLOWUP_BYTES, "sha256": FOLLOWUP_SHA})
    namespace = {"__name__": "_reviewed_followup_helpers", "__file__": str(FOLLOWUP)}
    exec(compile(raw, str(FOLLOWUP), "exec", optimize=0), namespace)
    H = namespace["bootstrap_helpers"]()
    require(namespace["SOURCE"] == SOURCE and namespace["ROOT"] == ROOT, "fixed helper scope")
    return namespace, H, raw

def original_terminal(record, prior, receipt_path, *, session_id=ORIGINAL_SESSION,
                      printed_fields=("schema", "status", "head", "tree", "push_exit",
                                      "source_after_valid", "exact_hook_verified")):
    require(type(record) is dict and set(record) == {
        "schema", "session_id", "archive_path", "terminal", "pages"}
        and record["schema"] == "trnm-actual-pty-pages-v1"
        and record["session_id"] == session_id, "actual original terminal container")
    archive_path = record["archive_path"]
    require(type(archive_path) is str and pathlib.PurePosixPath(archive_path).is_absolute()
            and ".." not in pathlib.PurePosixPath(archive_path).parts, "actual terminal archive path")
    pages = record["pages"]
    require(type(pages) is list and 0 < len(pages) <= 512, "complete actual terminal pages required")
    def page_bytes(page):
        require(type(page) is dict and page.get("host") == "mac"
                and page.get("session_id") == session_id
                and page.get("archive_path") == archive_path, "original terminal session/archive")
        require(type(page.get("offset")) is int and page["offset"] >= 0
                and page.get("truncated_before_offset") is False, "terminal cursor")
        encoded = page.get("bytes_hex")
        require(type(encoded) is str and len(encoded) % 2 == 0
                and re.fullmatch(r"[0-9a-f]*", encoded), "raw terminal bytes")
        raw = bytes.fromhex(encoded)
        require(sha(raw) == page.get("chunk_sha256")
                and type(page.get("next_offset")) is int
                and page["next_offset"] == page["offset"] + len(raw), "terminal chunk identity")
        require(page.get("text_is_lossy") is False and page.get("utf8_pending") is False
                and type(page.get("text")) is str and page["text"].encode("utf-8") == raw,
                "actual terminal raw/text differs")
        return raw
    chunks, cursor = [], 0
    for page in pages:
        raw = page_bytes(page)
        require(page["offset"] == cursor, "terminal cursor gap or overlap")
        cursor += len(raw)
        require(cursor <= MAX_META, "original terminal bound")
        chunks.append(raw)
    output = b"".join(chunks)
    terminal = record["terminal"]
    terminal_raw = page_bytes(terminal)
    require(terminal["next_offset"] == cursor
            and output[terminal["offset"]:terminal["next_offset"]] == terminal_raw,
            "actual terminal final observation not contained in complete pages")
    for page in pages + [terminal]:
        status = page.get("status")
        require(type(status) is dict and status.get("state") == "exited"
                and type(status.get("exit_code")) is int
                and status.get("output_complete") is True and page.get("output_complete") is True
                and status.get("capture_error") is None, "original process not authoritatively closed")
        for value in (page.get("available_end"), status.get("bytes_seen"), status.get("bytes_stored")):
            require(type(value) is int and value == cursor, "original complete output missing")
        require(status["exit_code"] == terminal["status"]["exit_code"], "terminal pages outcome differs")
    require(prior["status"] in ("confirmed", "UNKNOWN")
            and prior["push_started"] is True and type(prior["push_exit"]) is int
            and type(prior["finished_at"]) is str, "original final publication receipt incomplete")
    datetime.datetime.fromisoformat(prior["finished_at"])
    expected_exit = 0 if prior["status"] == "confirmed" else 1
    require(terminal["status"]["exit_code"] == expected_exit, "original receipt/terminal outcome differs")
    require(output.splitlines(), "original output empty")
    printed = strict_json(output.splitlines()[-1])
    wanted = {key: prior[key] for key in printed_fields}
    wanted["receipt"] = receipt_path
    require(printed == wanted, "original terminal final receipt identity differs")
    return output, {"session_id": session_id, "archive_path": archive_path,
                    "exit_code": expected_exit, "output_complete": True,
                    "page_count": len(pages), "bytes": len(output), "sha256": sha(output)}

def validate_coverage(inputs, spec):
    require(type(inputs) is dict and set(inputs) == {
        "publication_spec", "coverage_receipt", "coverage_terminal"}, "original launcher input fields")
    require(inputs["publication_spec"] == spec, "original coverage/spec binding")
    coverage = strict_json(read_pin(inputs["coverage_receipt"]))
    require(coverage["schema"] == "trnm-final-execution-payload-coverage-check-v1"
            and coverage["status"] == "COVERAGE_CONFIRMED" and coverage["coverage_confirmed"] is True
            and coverage["final_manifest"] == spec["execution_manifest"]
            and coverage["checks"] and all(v is True for v in coverage["checks"].values()),
            "actual final coverage closure")
    require(coverage["pattern_source_sha256"] == "5c292f6554bbf1345d6e58a3c64cf9099230223fc9c70f217a575f6f20ee7368"
            and coverage["checker"] == {"path": str(CHECKER_ROOT / "check_final_execution_coverage_v2.py"),
                "bytes": 23687, "sha256": "9f3a1370fdf50adccf6cecf2b33b5fe15e6b32d007a7bc7b87fb997ee11db21e"},
            "coverage producer/pattern source")
    ct = strict_json(read_pin(inputs["coverage_terminal"]))
    require(ct["host"] == "mac" and ct["status"]["state"] == "exited"
            and type(ct["status"]["exit_code"]) is int and ct["status"]["exit_code"] == 0
            and ct["output_complete"] is True and ct["status"]["output_complete"] is True
            and ct["status"]["capture_error"] is None, "actual coverage terminal")
    raw = bytes.fromhex(ct["bytes_hex"])
    require(sha(raw) == ct["chunk_sha256"] and ct["text"].encode() == raw
            and type(ct["offset"]) is int and ct["offset"] == 0
            and ct["next_offset"] == ct["available_end"] == ct["status"]["bytes_seen"]
            == ct["status"]["bytes_stored"] == len(raw)
            and ct["truncated_before_offset"] is False and ct["text_is_lossy"] is False
            and ct["utf8_pending"] is False, "coverage raw terminal completeness")
    require(strict_json(raw) == {"schema": coverage["schema"], "status": "COVERAGE_CONFIRMED",
                                "summary": inputs["coverage_receipt"]}, "coverage terminal summary binding")
    return {"receipt": inputs["coverage_receipt"], "terminal": inputs["coverage_terminal"],
            "final_manifest": coverage["final_manifest"]}

def validate_previous_resume_failures(recovery_spec, original, archive, expected_heads, old_tags):
    """Only the two actual closed failed resumes; never a replacement success receipt."""
    rows = recovery_spec["previous_resume_attempts"]
    require(type(rows) is list and len(rows) == 2, "two closed previous resume attempts required")
    expected_sessions = (
        "dpty-1e071a3c6223500afaf12efd6647610752be79f4dd5520dcd77ca0a02a6883a7",
        "dpty-e4cfa015148b54e6302e6fb59a77d16a17b96869bbd25678db7ad4eb6915cd8c",
    )
    previous_driver = {"path": str(ROOT / "resume_followup_candidate_execution_archive_v1.py"),
                       "bytes": 58300,
                       "sha256": "0da42495c82b668047cfcc2115f7cda75b3b78520688119aa654ed99cd631a2e"}
    proofs, retained = [], []
    for number, (row, session) in enumerate(zip(rows, expected_sessions), 1):
        require(type(row) is dict and set(row) == {"receipt", "terminal_pages"}, "previous attempt pins")
        raw = read_pin(row["receipt"])
        prior = strict_json(raw)
        require(prior["schema"] == "trnm-followup-candidate-execution-resume-receipt-v1"
                and prior["status"] == "UNKNOWN" and prior["push_started"] is True
                and type(prior["push_exit"]) is int and prior["push_exit"] != 0
                and prior["driver"] == previous_driver
                and prior["head"] == HEAD and prior["tree"] == TREE
                and prior["expected_remote_head"] == REMOTE_HEAD
                and prior["archive"] == archive and prior["archive_rebuilt"] is False
                and prior["original_publication_receipt"] == recovery_spec["original_publication_receipt"]
                and prior["original_publication_spec"] == recovery_spec["original_publication_spec"]
                and prior["original_terminal_pages"] == recovery_spec["original_terminal_pages"]
                and prior["original_publication_status"] == original["status"]
                and prior["source_after_valid"] is True and prior["exact_hook_verified"] is True
                and prior["source_after_identity"] == {"head": HEAD, "tree": TREE, "status": ""}
                and prior["transport_timeout_seconds"] == TRANSPORT_SECONDS
                and type(prior["remote_after"]) is dict
                and prior["remote_after"]["both_old"] is True and prior["remote_after"]["both_new"] is False
                and prior["remote_after"]["errors"] == []
                and prior["remote_after"]["heads"] == expected_heads and prior["remote_after"]["tags"] == old_tags,
                "previous failed attempt does not bind this exact publication/both-old state")
        terminal_raw = read_pin(row["terminal_pages"])
        _, proof = original_terminal(
            strict_json(terminal_raw), prior, row["receipt"]["path"], session_id=session,
            printed_fields=("schema", "status", "head", "tree", "push_started", "push_exit",
                            "source_after_valid", "exact_hook_verified", "original_hook_verified",
                            "publication_observation_phase"))
        require(proof["exit_code"] == 1 and proof["output_complete"] is True,
                "previous attempt is not authoritatively failed and closed")
        matches = [x for x in prior["steps"] if x.get("label") == "atomic-publish-resume"]
        require(len(matches) == 1, "one previous transport invocation required")
        step = matches[0]
        require(step["exit"] == prior["push_exit"] and step["timeout_seconds"] == TRANSPORT_SECONDS,
                "previous transport result/budget differs")
        stderr_pin = {key: step["stderr_" + key] for key in ("path", "bytes", "sha256")}
        require(stderr_pin["path"] == str(pathlib.Path(row["receipt"]["path"]).parent / "atomic-publish-resume.stderr"),
                "previous stderr path differs")
        err = read_pin(stderr_pin)
        require(len(err) == 13318
                and sha(err) == "d1f31190e22e217374cbba9b2fa0f2ebe85cddaf66524c3fc8bfdeb92e39df8a",
                "previous actual transport failure differs from reviewed connect timeout")
        proofs.append({"number": number, "receipt": row["receipt"], "terminal_pages": row["terminal_pages"],
                       "terminal_proof": proof, "status": prior["status"],
                       "push_exit": prior["push_exit"], "transport_stderr": stderr_pin})
        retained.extend(((f"previous-resume-{number}-receipt.json", row["receipt"]["path"], raw),
                         (f"previous-resume-{number}-terminal-pages.json", row["terminal_pages"]["path"], terminal_raw)))
    return proofs, retained


def typed_curl_info(line):
    """No raw text survives. Request/response headers and all unknown info are discarded."""
    framing = re.fullmatch(rb"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6} http\.c:[0-9]+[ \t]+== Info: (.*)", line)
    if framing is None:
        return None
    raw = framing[1]
    try:
        message = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    def address(value):
        try:
            ip = ipaddress.ip_address(value.strip("[]"))
        except ValueError:
            return None
        return str(ip) if ip.is_global else None
    match = re.fullmatch(r"Trying (\[[0-9A-Fa-f:]+\]|[0-9.]+):443\.\.\.", message)
    if match and (ip := address(match[1])):
        return {"event": "tcp_connect_attempt", "ip": ip, "port": 443}
    if message in ("Host github.com:443 was resolved.", "Hostname github.com was found in DNS cache"):
        return {"event": "target_resolved" if message.startswith("Host ") else "dns_cache_hit"}
    match = re.fullmatch(r"(IPv4|IPv6): (.*)", message)
    if match:
        if match[2] == "(none)":
            return {"event": "resolved_addresses", "family": match[1], "addresses": []}
        pieces = match[2].split(", ")
        if 0 < len(pieces) <= 8:
            addresses = [address(x) for x in pieces]
            if all(addresses):
                return {"event": "resolved_addresses", "family": match[1], "addresses": addresses}
        return None
    match = re.fullmatch(r"Connected to github\.com \(([0-9A-Fa-f:.]+)\) port 443(?: \(#([0-9]+)\))?", message)
    if match and (ip := address(match[1])):
        return {"event": "tcp_connected", "ip": ip, "port": 443,
                "connection": int(match[2]) if match[2] is not None else None}
    if message in ("Re-using existing connection with host github.com",
                   "Re-using existing connection! (#0) with host github.com"):
        return {"event": "connection_reused"}
    match = re.fullmatch(r"Re-using existing connection! \(#([0-9]+)\) with host github\.com", message)
    if match:
        return {"event": "connection_reused", "connection": int(match[1])}
    match = re.fullmatch(r"Connection #([0-9]+) to host github\.com left intact", message)
    if match:
        return {"event": "connection_kept", "connection": int(match[1])}
    match = re.fullmatch(r"Connection ([0-9]+) seems to be dead", message)
    if match:
        return {"event": "cached_connection_dead", "connection": int(match[1])}
    match = re.fullmatch(r"Closing connection ([0-9]+)", message)
    if match:
        return {"event": "connection_closed", "connection": int(match[1])}
    match = re.fullmatch(r"Connection died, retrying a fresh connect \(retry count: ([0-9]+)\)", message)
    if match:
        return {"event": "libcurl_fresh_connection_retry", "retry_count": int(match[1])}
    match = re.fullmatch(r"ALPN: curl offers (h2,http/1\.1|h2|http/1\.1)", message)
    if match:
        return {"event": "alpn_offered", "protocols": match[1].split(",")}
    match = re.fullmatch(r"ALPN: server accepted (h2|http/1\.1)", message)
    if match:
        return {"event": "alpn_accepted", "protocol": match[1]}
    match = re.fullmatch(r"using HTTP/(2|1\.1)", message)
    if match:
        return {"event": "http_version", "version": match[1]}
    match = re.match(r"SSL connection using (TLSv1(?:\.[0-3])?) /", message)
    if match:
        return {"event": "tls_negotiated", "version": match[1]}
    if message in ("SSL certificate verify ok.", "SSL certificate verified via OpenSSL."):
        return {"event": "tls_certificate_verified"}
    match = re.fullmatch(r"connect to (\[[0-9A-Fa-f:]+\]|[0-9A-Fa-f:.]+) port 443(?: from .*?)? failed: (.*)", message)
    if match and (ip := address(match[1])):
        reason = {"Operation timed out": "timeout", "Connection refused": "refused",
                  "Network is unreachable": "unreachable", "No route to host": "no_route"}.get(match[2], "other")
        return {"event": "tcp_connect_failed", "ip": ip, "port": 443, "reason": reason}
    match = re.fullmatch(r"Failed to connect to github\.com port 443 after ([0-9]{1,10}) ms: (.*)", message)
    if match:
        reason = {"Couldn't connect to server": "could_not_connect",
                  "Timeout was reached": "timeout"}.get(match[2], "other")
        return {"event": "target_connect_failed", "elapsed_ms": int(match[1]), "reason": reason}
    return None


class RedactedCurlInfo:
    """Bounded live pipe filter. No full trace, header, auth field, URL or body is written."""
    MAX_LINE = 8192
    MAX_INPUT_PARSED = 16 * 1024 * 1024
    MAX_EVENTS = 4096
    MAX_OUTPUT = 512 * 1024

    def __init__(self, directory):
        directory.mkdir(mode=0o700, exist_ok=False)
        self.directory = directory
        self.events_path = directory / "events.jsonl"
        self.started = time.monotonic()
        self.stop = threading.Event()
        self.read_fd, self.write_fd = os.pipe()
        # GIT_TRACE_CURL only recognizes numeric inherited descriptors in 3..9 here.
        # Never overwrite a descriptor and never use preexec_fn in this threaded program.
        if not (3 <= self.write_fd <= 9):
            os.close(self.read_fd)
            os.close(self.write_fd)
            raise ValueError("no supported trace pipe descriptor in 3..9; transport not launched")
        os.set_blocking(self.read_fd, False)
        self.trace_fd = self.write_fd
        self.input_bytes = self.output_bytes = self.events = self.lines = self.dropped = 0
        self.overlong_lines = 0
        self.eof = False
        self.errors = []
        self.thread = None

    def close_parent_writer(self):
        if self.write_fd is not None:
            os.close(self.write_fd)
            self.write_fd = None

    def start(self):
        self.thread = threading.Thread(target=self.consume, name="redacted-curl-info", daemon=True)
        self.thread.start()

    def consume(self):
        pending = bytearray()
        discard_line = False
        parsing_disabled = False
        closing_at = None
        try:
            with self.events_path.open("xb") as stream, selectors.DefaultSelector() as selector:
                selector.register(self.read_fd, selectors.EVENT_READ)
                while True:
                    if self.stop.is_set() and closing_at is None:
                        closing_at = time.monotonic() + 5.0
                    if closing_at is not None and time.monotonic() >= closing_at:
                        self.errors.append("TraceEOFDrainDeadline")
                        break
                    ready = selector.select(0.2)
                    if not ready:
                        continue
                    try:
                        chunk = os.read(self.read_fd, 8192)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        self.eof = True
                        if pending or discard_line:
                            self.errors.append("IncompleteTraceLine")
                        break
                    self.input_bytes += len(chunk)
                    if self.input_bytes > self.MAX_INPUT_PARSED:
                        if not parsing_disabled:
                            self.errors.append("TraceInputBound")
                        parsing_disabled = True
                        pending.clear()
                    if parsing_disabled:
                        continue  # Drain without retaining or parsing; original transport budget is unchanged.
                    for byte in chunk:
                        if byte != 10:
                            if not discard_line:
                                pending.append(byte)
                                if len(pending) > self.MAX_LINE:
                                    pending.clear()
                                    discard_line = True
                                    self.overlong_lines += 1
                            continue
                        self.lines += 1
                        if discard_line:
                            discard_line = False
                            self.dropped += 1
                            continue
                        event = typed_curl_info(bytes(pending).rstrip(b"\r"))
                        pending.clear()
                        if event is None:
                            self.dropped += 1
                            continue
                        event["since_capture_ms"] = round((time.monotonic() - self.started) * 1000, 3)
                        raw = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
                        if len(raw) > 2048 or self.events >= self.MAX_EVENTS or self.output_bytes + len(raw) > self.MAX_OUTPUT:
                            self.errors.append("TraceOutputBound")
                            parsing_disabled = True
                            break
                        try:
                            stream.write(raw)
                            stream.flush()
                        except OSError:
                            self.errors.append("TraceEventWriteError")
                            parsing_disabled = True
                            break
                        self.events += 1
                        self.output_bytes += len(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception as error:
            self.errors.append("TraceReader:" + type(error).__name__)
        finally:
            os.close(self.read_fd)

    def finish(self):
        self.close_parent_writer()
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=7)
            if self.thread.is_alive():
                return {"schema": "trnm-redacted-git-curl-info-v1", "complete": False,
                        "errors": ["TraceReaderDidNotClose"], "raw_trace_written": False}
        if not self.input_bytes or not self.events:
            self.errors.append("NoRecognizedTransportEvents")
        raw = self.events_path.read_bytes() if self.events_path.exists() else b""
        require(len(raw) == self.output_bytes and len(raw) <= self.MAX_OUTPUT, "typed trace readback")
        record = {"schema": "trnm-redacted-git-curl-info-v1", "complete": self.eof and not self.errors,
                  "raw_trace_written": False, "header_auth_cookie_URL_or_body_retained": False,
                  "trace_fd": self.trace_fd, "NO_DATA": True, "REDACT": True,
                  "input_bytes_seen": self.input_bytes, "lines_seen": self.lines,
                  "unrecognized_or_header_lines_discarded": self.dropped,
                  "overlong_lines_discarded": self.overlong_lines, "events_retained": self.events,
                  "eof": self.eof, "errors": list(self.errors),
                  "bounds": {"parsed_input": self.MAX_INPUT_PARSED, "line": self.MAX_LINE,
                             "events": self.MAX_EVENTS, "retained_bytes": self.MAX_OUTPUT,
                             "postprocess_EOF_seconds": 5},
                  "events": {"path": str(self.events_path), "bytes": len(raw), "sha256": sha(raw)},
                  "scope": "Strict typed connection/DNS/ALPN/TLS events; not a complete HTTP trace."}
        encoded = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
        path = self.directory / "summary.json"
        with path.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        require(path.read_bytes() == encoded, "typed trace summary readback")
        return {**record, "summary": {"path": str(path), "bytes": len(encoded), "sha256": sha(encoded)}}

def sample_owned(pid, phase, env):
    """Retain only the owned tree; ps never requests arguments or environment."""
    q = subprocess.run(
        ["/bin/ps", "-axo", "pid=,ppid=,pgid=,pcpu=,etime=,comm="],
        env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=5, check=False)
    if q.returncode != 0:
        raise RuntimeError("owned process metadata sampling failed")
    parsed = []
    for line in q.stdout.decode("utf-8", errors="replace").splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6:
            raise RuntimeError("process metadata shape differs")
        parsed.append((int(fields[0]), int(fields[1]), int(fields[2]),
                       fields[3], fields[4], fields[5]))
    selected = {pid}
    selected.update(p for p, _, group, _, _, _ in parsed if group == pid)
    while True:
        extended = selected | {p for p, parent, _, _, _, _ in parsed if parent in selected}
        if extended == selected:
            break
        selected = extended
    rows = [{"pid": p, "ppid": parent, "comm": comm, "cpu_percent": cpu, "elapsed": elapsed}
            for p, parent, _, cpu, elapsed, comm in parsed if p in selected]
    return {"observed_at": now(), "phase": phase, "owned_root_pid": pid,
            "processes": sorted(rows, key=lambda row: row["pid"])}

def capture_sampled(argv, env, sample_path):
    """The reviewed capture lifecycle, with metadata only at 0/15s/terminal."""
    sampling_errors = []
    trace = RedactedCurlInfo(sample_path.with_name("atomic-publish-resume-redacted-curl"))
    trace_env = env.copy()
    trace_env.update(GIT_TRACE_CURL=str(trace.trace_fd), GIT_TRACE_CURL_NO_DATA="1", GIT_TRACE_REDACT="1")
    trace.start()
    try:
        process = subprocess.Popen(argv, cwd=SOURCE, env=trace_env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
            close_fds=True, pass_fds=(trace.trace_fd,))
    except OSError as error:
        trace.close_parent_writer()
        proof = trace.finish()
        return subprocess.CompletedProcess(argv, 127, b"", str(error).encode()), sampling_errors, proof
    trace.close_parent_writer()
    stop = threading.Event()
    def sampler():
        with sample_path.open("x", encoding="utf-8") as stream:
            def record(phase):
                try:
                    row = sample_owned(process.pid, phase, env)
                except Exception as error:
                    row = {"observed_at": now(), "phase": phase,
                           "owned_root_pid": process.pid, "error_type": type(error).__name__}
                    sampling_errors.append(row)
                stream.write(json.dumps(row, sort_keys=True) + "\n")
                stream.flush()
            record("start")
            while not stop.wait(15):
                record("periodic")
            record("terminal")
    thread = threading.Thread(target=sampler, name="owned-process-metadata", daemon=True)
    thread.start()
    try:
        try:
            stdout, stderr = process.communicate(timeout=3600)
            result = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired as expired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired as remaining:
                stdout, stderr = remaining.stdout or expired.stdout or b"", remaining.stderr or expired.stderr or b""
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
                stderr += b"\nOwned process capture did not close after timeout; outcome UNKNOWN.\n"
            result = subprocess.CompletedProcess(argv, 124, stdout, stderr)
    finally:
        stop.set()
        thread.join(timeout=12)
        if thread.is_alive():
            sampling_errors.append({"error_type": "SamplerDidNotClose"})
    return result, sampling_errors, trace.finish()


def derive_effective_hook(original_hook_raw):
    """Derive only concurrent heads/tags capture; archived original proof stays unchanged."""
    require(type(original_hook_raw) is bytes, "original hook must be verified bytes")
    changes = (
        (b'''import datetime, hashlib, json, os, pathlib, re, stat, subprocess, sys
''', b'''import concurrent.futures, datetime, hashlib, json, os, pathlib, re, stat, subprocess, sys
'''),
        (b'''def command(label, argv):
''', b'''def capture_command(argv):
'''),
        (b'''    row = {"label": label, "argv": argv, "exit": q.returncode, "timeout_seconds": 90}
''', b'''    return q

def record_command(label, argv, q):
    row = {"label": label, "argv": argv, "exit": q.returncode, "timeout_seconds": 90}
'''),
        (b'''def advertised(raw, prefix=None, allowed=None):
''', b'''def command(label, argv):
    return record_command(label, argv, capture_command(argv))

def advertised(raw, prefix=None, allowed=None):
'''),
        (b'''    heads = command("heads", ["git", "ls-remote", "--heads", "origin"])
    refs = sorted(spec["old_archive_tags"]) + [spec["new_tag_ref"], spec["new_tag_ref"] + "^{}"]
    tags = command("tags", ["git", "ls-remote", "origin", *refs])
''', b'''    heads_argv = ["git", "ls-remote", "--heads", "origin"]
    refs = sorted(spec["old_archive_tags"]) + [spec["new_tag_ref"], spec["new_tag_ref"] + "^{}"]
    tags_argv = ["git", "ls-remote", "origin", *refs]
    # Only the two independent read-only captures overlap. No shared receipt
    # or file is written by a worker; persist both actual results in old order.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        heads_future = pool.submit(capture_command, heads_argv)
        tags_future = pool.submit(capture_command, tags_argv)
        heads_result = heads_future.result()
        tags_result = tags_future.result()
    heads = record_command("heads", heads_argv, heads_result)
    tags = record_command("tags", tags_argv, tags_result)
'''),
    )
    effective = original_hook_raw
    for before, after in changes:
        require(effective.count(before) == 1, "effective hook derivation exact span differs")
        effective = effective.replace(before, after, 1)
    return effective

def validate_closed_original_inputs(recovery_spec):
    """Pure read-only closure validation. No Git/API/subprocess or producer main runs here."""
    require(type(recovery_spec) is dict and set(recovery_spec) == {
        "schema", "resume_sha256", "evidence_dir", "transport_timeout_seconds",
        "original_publication_spec", "original_publication_receipt",
        "original_terminal_pages", "original_launch_inputs", "previous_resume_attempts"}, "resume spec fields")
    require(recovery_spec["schema"] == "trnm-followup-candidate-execution-resume-spec-v3"
            and type(recovery_spec["resume_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", recovery_spec["resume_sha256"])
            and type(recovery_spec["transport_timeout_seconds"]) is int
            and recovery_spec["transport_timeout_seconds"] == TRANSPORT_SECONDS, "resume spec identity/budget")
    ev = pathlib.Path(recovery_spec["evidence_dir"])
    require(ev.parent == ROOT and re.fullmatch(
        r"resume-followup-candidate-execution-2a8646-[a-z0-9-]+", ev.name),
        "dedicated recovery evidence directory")
    require(type(recovery_spec["original_terminal_pages"]) is dict, "actual terminal container pin")
    F, H, followup_raw = load_helpers()
    value = {"publication_spec": recovery_spec["original_publication_spec"],
             "publication_receipt": recovery_spec["original_publication_receipt"]}
    snapshots, retained = [], []
    BASE = F["MAIN_HEAD"]
    HEAD_REF = F["CANDIDATE_REF"][11:]
    URL = "https://github.com/" + F["REPOSITORY"]
    REPO = F["REPOSITORY"]
    def pinned(pin, name):
        raw = read_pin(pin)
        _, record = F["pinned_bytes"](pin)
        snapshots.append(record)
        retained.append((name, pin["path"], raw))
        return raw
    spec_raw = pinned(value["publication_spec"], "publication-spec.json")
    spec = strict_json(spec_raw)
    pubdir = F["validate_spec"](spec)
    require(spec["publisher_sha256"] == FOLLOWUP_SHA, "unreviewed follow-up producer")
    head, tree = spec["candidate_head"], spec["candidate_tree"]
    expected_remote_head = spec["expected_remote_head"]
    pub_raw = pinned(value["publication_receipt"], "confirmed-publication.json")
    pub = strict_json(pub_raw)
    require(value["publication_receipt"]["path"] == str(pubdir / "summary.json"),
            "terminal publication receipt path differs from reviewed spec")
    require(pub["schema"] == "trnm-followup-candidate-execution-publication-receipt-v2"
            and pub["status"] in ("confirmed", "UNKNOWN") and pub["push_started"] is True
            and pub["source_after_valid"] is True and pub["exact_hook_verified"] is True
            and pub["head"] == head and pub["tree"] == tree
            and pub["previous_own_published_head"] == F["BASE_HEAD"]
            and pub["expected_remote_head"] == expected_remote_head and type(pub["errors"]) is list,
            "complete original publication source/hook closure required")
    require(pub["driver"] == {"path": str(FOLLOWUP), "bytes": FOLLOWUP_BYTES, "sha256": FOLLOWUP_SHA}
            and pub["spec"] == value["publication_spec"], "publication producer/spec binding differs")
    require(type(pub["push_exit"]) is int, "publication transport outcome missing")
    for field in ("started_at", "push_started_at", "finished_at"):
        require(type(pub[field]) is str and bool(pub[field]), "publication terminal time missing")
        datetime.datetime.fromisoformat(pub[field])
    for field in ("automatic_retry_authorized", "rollback_authorized", "main_merged",
                  "branches_deleted", "protection_changed", "pr_metadata_changed",
                  "auto_merge_enabled", "hosted_ci_qualification", "qualification_granted",
                  "untouched_refs_and_protection_atomically_locked"):
        require(pub[field] is False, "unexpected publication scope flag: " + field)
    require(pub["required_head_and_prospective_ci_must_still_pass"] is True
            and pub["archive_preserves_history_not_semantic_equivalence"] is True,
            "publication qualification/history boundary differs")
    require(head == HEAD and tree == TREE and expected_remote_head == REMOTE_HEAD,
            "fixed R1/N2 original publication required")
    terminal_record_raw = read_pin(recovery_spec["original_terminal_pages"])
    terminal_raw, terminal_proof = original_terminal(
        strict_json(terminal_record_raw), pub, value["publication_receipt"]["path"])
    require(recovery_spec["original_launch_inputs"]["path"] ==
            str(ROOT / "R1-publication-launch-inputs-v1/inputs.json"), "original launcher inputs path")
    launch = strict_json(read_pin(recovery_spec["original_launch_inputs"]))
    launcher_raw = read_pin({"path": str(ROOT / "R1-publication-launch-inputs-v1/producer.py"),
                            "bytes": 5488, "sha256": ORIGINAL_LAUNCHER_SHA})
    coverage = validate_coverage(launch, spec)
    published_heads, old_parents, frozen_raw, old_originals, old_snapshots = F["original_frozen_state"]()
    expected = F["bind_expected_remote_heads"](published_heads, expected_remote_head)
    published_heads_raw = (json.dumps(published_heads, indent=2, sort_keys=True) + "\n").encode()
    expected_remote_heads_raw = (json.dumps(expected, indent=2, sort_keys=True) + "\n").encode()
    snapshots.extend(old_snapshots)
    payload = F["load_manifest"](spec["execution_manifest"])
    snapshots.extend(payload["snapshots"])
    gate, gate_raw, gate_source, gate_snapshots, gate_producer = F["validate_gate_payload"](
        H, spec["local_gate_receipt"], head, tree, payload)
    rog, rog_raw, rog_snapshots, rog_producer = F["validate_rog_payload"](
        H, spec["rog_lane_receipt"], spec["rog_invocation"], head, tree, gate_source, payload)
    snapshots.extend(gate_snapshots + rog_snapshots)
    require(pub["validated_inputs"] == {
        "gate_receipt": spec["local_gate_receipt"], "rog_receipt": spec["rog_lane_receipt"],
        "rog_invocation": spec["rog_invocation"], "execution_manifest": spec["execution_manifest"],
        "payload_files": payload["manifest"]["file_count"],
        "payload_bytes": payload["manifest"]["total_bytes"],
        "rog_producer_sha256": sha(rog_producer),
        "exact_gate_commands": len(gate["steps"]), "exact_rog_commands": len(rog["steps"])},
        "publication validated-input closure differs")
    retained.extend([
        ("execution-manifest.json", spec["execution_manifest"]["path"], payload["raw"]),
        ("seven-local-gates.json", spec["local_gate_receipt"]["path"], gate_raw),
        ("full-linux-lane.json", spec["rog_lane_receipt"]["path"], rog_raw),
    ])

    def local(name, maximum=F["MAX_META"]):
        data, record = F["stable_bytes"](pubdir / name, maximum=maximum)
        snapshots.append(record)
        return data

    require(local("spec.json") == spec_raw
            and local("validated-execution-manifest.json") == payload["raw"]
            and local("validated-local-gate-receipt.json") == gate_raw
            and local("validated-rog-lane-receipt.json") == rog_raw
            and local("expected-published-dc42-heads.json") == published_heads_raw
            and local("expected-reviewed-remote-heads.json") == expected_remote_heads_raw,
            "publisher retained inputs differ")
    steps = pub["steps"]
    require(isinstance(steps, list) and 0 < len(steps) <= F["MAX_FILES"] * 3,
            "publication step roster is missing or unbounded")
    by_label = {}
    for row in steps:
        label = row["label"]
        require(type(label) is str and re.fullmatch(r"[a-z0-9-]+", label)
                and label not in by_label, "duplicate/invalid publication step")
        by_label[label] = row

    def step(label, argv, timeout, expected_exit=0, maximum=F["MAX_META"]):
        row = by_label[label]
        require(row["argv"] == argv and row["cwd"] == str(SOURCE)
                and type(row["timeout_seconds"]) is int and row["timeout_seconds"] == timeout
                and type(row["exit"]) is int and row["exit"] == expected_exit,
                "publication command/cwd/budget/result differs: " + label)
        data = {}
        for channel in ("stdout", "stderr"):
            path = pubdir / (label + "." + channel)
            require(row[channel + "_path"] == str(path), "publication raw-output path differs")
            raw, record = F["stable_bytes"](path, row[channel + "_bytes"],
                                          row[channel + "_sha256"], maximum=maximum)
            snapshots.append(record)
            data[channel] = raw
        return data["stdout"]

    # The reviewed remote advance and the independently tested ROG start have
    # separate C0 lineages; the remote advance need not precede the ROG start.
    for label, ancestor, descendant in (
        ("published-to-reviewed-remote", F["BASE_HEAD"], expected_remote_head),
        ("reviewed-remote-to-candidate", expected_remote_head, head),
        ("published-to-rog-start", F["BASE_HEAD"], spec["rog_invocation"]["expected_start_head"]),
        ("rog-start-to-candidate", spec["rog_invocation"]["expected_start_head"], head),
    ):
        require(step(label, ["git", "--no-replace-objects", "merge-base",
                "--is-ancestor", ancestor, descendant], 60) == b"",
                "recorded ancestry proof differs: " + label)
    publication_pr_query = "{number,state,draft,head:.head.sha,head_ref:.head.ref,base:.base.sha,base_ref:.base.ref,auto_merge}"
    publication_pr_argv = ["gh", "api", "repos/" + REPO + "/pulls/847", "--jq", publication_pr_query]
    publication_pr = strict_json(step("pr-before", publication_pr_argv, 180))
    require(isinstance(publication_pr, dict) and set(publication_pr) == {
            "number", "state", "draft", "head", "head_ref", "base", "base_ref", "auto_merge"}
            and type(publication_pr["number"]) is int and publication_pr["number"] == 847
            and publication_pr["state"] == "open" and type(publication_pr["draft"]) is bool
            and publication_pr["head"] == expected_remote_head
            and publication_pr["head_ref"] == HEAD_REF and publication_pr["base"] == BASE
            and publication_pr["base_ref"] == "main" and publication_pr["auto_merge"] is None
            and pub["pr_before"] == publication_pr,
            "publication original PR does not bind the reviewed remote head")
    require(strict_json(step("pr-prepush", publication_pr_argv, 180)) == publication_pr,
            "publication prepush PR changed from its exact original")

    archive = pub["archive"]
    require(isinstance(archive, dict) and set(archive) == {
        "tag", "tag_oid", "commit", "tree", "direct_parents", "candidate_head",
        "payload_manifest_sha256", "archive_files", "archive_bytes", "file_index_sha256"},
        "archive field set differs")
    for field in ("tag_oid", "commit", "tree"):
        require(type(archive[field]) is str and re.fullmatch(r"[0-9a-f]{40}", archive[field]),
                "archive object identity invalid")
    require(archive["tag"] == spec["archive_tag"]
            and archive["direct_parents"] == [F["OLD_ARCHIVE_COMMIT"], head]
            and archive["candidate_head"] == head
            and archive["payload_manifest_sha256"] == sha(payload["raw"]),
            "archive source/ordered parents/payload differs")
    require(strict_json(local("archive-local.json")) == archive, "archive retained metadata differs")
    tagref = "refs/tags/" + archive["tag"]
    old_tags = {F["OLD_TAG_REF"]: F["OLD_TAG_OID"],
                F["OLD_TAG_REF"] + "^{}": F["OLD_ARCHIVE_COMMIT"]}
    expected_new = dict(expected)
    expected_new[HEAD_REF] = head
    wanted_tags = dict(old_tags)
    wanted_tags.update({tagref: archive["tag_oid"], tagref + "^{}": archive["commit"]})
    for phase, wanted_heads, tags in (("before", expected, old_tags),):
        observed = pub["remote_" + phase]
        require(isinstance(observed, dict) and set(observed) == {
            "observed_at", "heads", "tags", "errors", "both_old", "both_new"}
            and observed["heads"] == wanted_heads and observed["tags"] == tags
            and observed["errors"] == [] and observed["both_old"] is (phase == "before")
            and observed["both_new"] is (phase == "after"), "complete remote observation differs")
        datetime.datetime.fromisoformat(observed["observed_at"])
        heads_raw = step("remote-" + phase + "-heads", ["git", "ls-remote", "--heads", "origin"], 180)
        tags_raw = step("remote-" + phase + "-tags",
            ["git", "ls-remote", "origin", *sorted(old_tags), tagref, tagref + "^{}"], 180)
        require(F["parse_refs"](heads_raw, heads=True) == wanted_heads
                and F["parse_refs"](tags_raw, allowed=set(wanted_tags)) == tags,
                "original complete ref readbacks differ")
    # Preserve the original after-observation raw results without treating them as success.
    for label, argv in (
        ("remote-after-heads", ["git", "ls-remote", "--heads", "origin"]),
        ("remote-after-tags", ["git", "ls-remote", "origin", *sorted(old_tags), tagref, tagref + "^{}"]),
    ):
        row = by_label[label]
        require(type(row["exit"]) is int, "original after-read actual result missing")
        step(label, argv, 180, row["exit"])
    expected_hook = {"origin": URL + ".git", "remote_heads": expected, "old_archive_tags": old_tags,
        "new_tag_ref": tagref, "updates": {
            "refs/heads/" + HEAD_REF: {"local_ref": head, "new": head, "old": expected_remote_head},
            tagref: {"local_ref": tagref, "new": archive["tag_oid"], "old": F["ZERO"]}}}
    hook_expected_raw = local("hooks/expected.json")
    require(strict_json(hook_expected_raw) == expected_hook, "actual exact hook scope differs")
    hook_raw = F["HOOK_TEMPLATE"].replace("__EXPECTED_SHA__", sha(hook_expected_raw)).replace(
        "__EXPECTED_BYTES__", str(len(hook_expected_raw))).encode()
    require(local("hooks/pre-push") == hook_raw, "actual hook differs from reviewed producer")
    require(pub["hook_receipt"] == F["verify_hook_receipt"](
        pubdir / "hooks", hook_expected_raw, hook_raw, expected_hook), "actual hook receipt differs")
    step("atomic-publish", ["git", "-c", "core.hooksPath=" + str(pubdir / "hooks"),
        "push", "--verify", "--atomic", "--porcelain", "--verbose", "--progress", "origin",
        head + ":refs/heads/" + HEAD_REF, tagref + ":" + tagref], 1800, pub["push_exit"],
        maximum=F["MAX_FILE"])
    actor_raw = step("actor", ["gh", "api", "user", "--jq", "{login,id}"], 180)
    actor = strict_json(actor_raw)
    require(set(actor) == {"login", "id"} and actor["login"] == "ProfHepta"
            and type(actor["id"]) is int and actor["id"] > 0 and pub["actor"] == actor,
            "publication authenticated actor differs")
    require(strict_json(step("actor-prepush", ["gh", "api", "user", "--jq", "{login,id}"], 180)) == actor,
            "publication prepush actor differs")
    source_pair = {}
    for phase in ("before", "after"):
        sidecar = local("source-" + phase + ".json")
        stdout = step("verify-source-" + phase, [H["PYTHON"], "-B", "scripts/ci/verify_ci_source.py",
            "--kind", "head", "--expected-head", head,
            "--output", str(pubdir / ("source-" + phase + ".json"))], 180)
        require(stdout == sidecar and H["validate_source_identity"](sidecar, head, tree) == gate_source,
                "publication source/stdout/sidecar differs from exact passed gates")
        source_pair[phase] = sidecar
        require(pub["source_" + phase + "_identity"] == {"head": head, "tree": tree, "status": ""},
                "publication HEAD/tree/clean status differs")
    require(source_pair["before"] == source_pair["after"], "publication source pair differs")
    for label, kind, oid, maximum in (
        ("old-archive-commit-object", "commit", F["OLD_ARCHIVE_COMMIT"], 128 * 1024),
        ("old-archive-tag-object", "tag", F["OLD_TAG_OID"], 64 * 1024),
        ("new-archive-commit-object", "commit", archive["commit"], 128 * 1024),
        ("new-archive-tag-object", "tag", archive["tag_oid"], 64 * 1024),
    ):
        data = step(label, ["git", "--no-replace-objects", "cat-file", kind, oid], 60, maximum=maximum)
        if label == "old-archive-commit-object":
            F["check_commit_object"](data, oid, F["OLD_ARCHIVE_TREE"], old_parents)
        elif label == "old-archive-tag-object":
            F["check_tag_object"](data, oid, F["OLD_TAG"], F["OLD_ARCHIVE_COMMIT"])
        elif kind == "commit":
            F["check_commit_object"](data, oid, archive["tree"], [F["OLD_ARCHIVE_COMMIT"], head])
        else:
            F["check_tag_object"](data, oid, archive["tag"], archive["commit"])

    # Validate original exact ls-tree output and byte-indexed public destinations.
    # This is data validation, not a Git command, publication or extra archive.
    index_raw = local("archive-file-index.json")
    require(sha(index_raw) == archive["file_index_sha256"], "archive index SHA differs")
    index = strict_json(index_raw)
    require(isinstance(index, dict) and set(index) == {"schema", "self_excluded", "files"}
            and index["schema"] == "trnm-execution-archive-file-index-v1"
            and index["self_excluded"] == "metadata/archive-file-index.json"
            and isinstance(index["files"], list), "archive index schema differs")
    indexed = {}
    for row in index["files"]:
        require(isinstance(row, dict) and set(row) == {"path", "bytes", "sha256", "git_blob", "mode"}
                and row["mode"] == "100644" and type(row["bytes"]) is int and row["bytes"] >= 0
                and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                and re.fullmatch(r"[0-9a-f]{40}", row["git_blob"]), "invalid archive index row")
        name = str(F["safe_relative"](row["path"]))
        require(name not in indexed and name != index["self_excluded"], "duplicate archive path")
        indexed[name] = row
    require(type(archive["archive_files"]) is int and archive["archive_files"] == len(indexed) + 1
            and type(archive["archive_bytes"]) is int
            and archive["archive_bytes"] == sum(row["bytes"] for row in indexed.values()) + len(index_raw),
            "archive exact count/bytes differs")
    listing = step("archive-exact-tree-list", ["git", "ls-tree", "-r", "-z", archive["tree"]], 60)
    actual = {}
    for record in listing.split(b"\0"):
        if not record:
            continue
        metadata, name_raw = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        name = name_raw.decode("utf-8")
        require(mode == "100644" and kind == "blob" and name not in actual,
                "unexpected actual archive mode/type/duplicate")
        actual[name] = oid
    wanted_files = {name: row["git_blob"] for name, row in indexed.items()}
    wanted_files[index["self_excluded"]] = F["git_object_oid"]("blob", index_raw)
    require(actual == wanted_files, "archive exact tree path/blob roster differs")

    def archive_bytes(name, data):
        row = indexed[name]
        require(row == {"path": name, "bytes": len(data), "sha256": sha(data),
                        "git_blob": F["git_object_oid"]("blob", data), "mode": "100644"},
                "public archive evidence bytes differ: " + name)

    for name, data in payload["payload"].items():
        archive_bytes("payload/" + name, data)
    for name, data in {
        "metadata/publication-spec.json": spec_raw,
        "metadata/execution-manifest.json": payload["raw"],
        "metadata/local-gates.json": gate_raw,
        "metadata/rog-full-lane.json": rog_raw,
        "metadata/frozen-0170-branches.json": frozen_raw,
        "metadata/published-dc42-expected-heads.json": published_heads_raw,
        "metadata/reviewed-remote-expected-heads.json": expected_remote_heads_raw,
        "metadata/live-source-before.json": source_pair["before"],
    }.items():
        archive_bytes(name, data)
    archive_scope = {
        "schema": "trnm-followup-execution-archive-scope-v2",
        "candidate_head": head, "candidate_tree": tree,
        "previous_own_published_head": F["BASE_HEAD"],
        "expected_remote_head": expected_remote_head,
        "old_history_archive": pub["old_archive_verified"],
        "exact_ordered_parents": [F["OLD_ARCHIVE_COMMIT"], head],
        "frozen_remote_branch_names": 908, "original_distinct_tips": 892,
        "payload_manifest_sha256": sha(payload["raw"]),
        "payload_files": len(payload["payload"]),
        "payload_bytes": payload["manifest"]["total_bytes"],
        "local_gate_receipt_sha256": sha(gate_raw), "rog_lane_receipt_sha256": sha(rog_raw),
        "original_rog_producer_sha256": sha(rog_producer),
        "main_merged": False, "branches_deleted": False, "protection_changed": False,
        "hosted_ci_qualification": False, "qualification_granted": False,
        "archive_preserves_history_not_semantic_equivalence": True,
        "current_publication_outcome_included": False,
        "new_full_fsck_performed": False,
    }
    archive_bytes("metadata/archive-scope.json",
                  (json.dumps(archive_scope, indent=2, sort_keys=True) + "\n").encode())
    retained.append(("archive-file-index.json", str(pubdir / "archive-file-index.json"), index_raw))
    previous_failures, previous_retained = validate_previous_resume_failures(recovery_spec, pub, archive, expected, old_tags)
    retained.extend(previous_retained)
    effective_hook_raw = derive_effective_hook(hook_raw)
    F["check_versions"](snapshots)
    final_pin_fence()
    return {
        "previous_resume_failures": previous_failures,
        "F": F, "H": H, "head": head, "tree": tree, "gate_source": gate_source,
        "archive": archive, "payload": payload, "indexed": indexed, "actor": actor,
        "original_spec": spec, "original_spec_raw": spec_raw,
        "original_spec_pin": value["publication_spec"],
        "original_publication": pub, "original_publication_raw": pub_raw,
        "original_publication_pin": value["publication_receipt"],
        "original_publication_directory": pubdir,
        "original_terminal_proof": terminal_proof, "original_terminal_output": terminal_raw,
        "original_terminal_record_raw": terminal_record_raw,
        "original_coverage": coverage, "original_launcher_raw": launcher_raw,
        "gate": gate, "gate_raw": gate_raw, "rog": rog, "rog_raw": rog_raw,
        "expected_heads": expected, "published_heads": published_heads,
        "old_parents": old_parents, "old_tags": old_tags,
        "wanted_heads": expected_new, "wanted_tags": wanted_tags,
        "old_history_originals": old_originals, "frozen_raw": frozen_raw,
        "source_before_raw": source_pair["before"], "source_after_raw": source_pair["after"],
        "archive_index_raw": index_raw, "archive_tree_listing": listing,
        "expected_hook": expected_hook, "expected_hook_raw": hook_expected_raw, "hook_raw": hook_raw,
        "effective_hook_raw": effective_hook_raw,
        "effective_hook_plan": {
            "schema": "trnm-followup-parallel-hook-read-plan-v1",
            "original_hook_sha256": sha(hook_raw),
            "effective_hook_sha256": sha(effective_hook_raw),
            "effective_hook_bytes": len(effective_hook_raw),
            "parallel_capture_labels": ["heads", "tags"],
            "receipt_command_order": ["push-url", "fetch-url", "heads", "tags"]},
        "snapshots": snapshots, "retained": retained,
        "publication_pr": publication_pr, "validated_inputs": pub["validated_inputs"],
        "previous_own_published_head": F["BASE_HEAD"], "expected_remote_head": expected_remote_head,
        "followup_producer_raw": followup_raw, "evidence_directory": ev,
        "original_validation_scope": "Archive/source/gates/raw proof; original status is retained unchanged.",
    }


def main():
    require(__debug__ and sys.flags.optimize == 0, "optimized Python forbidden")
    require(pathlib.Path(__file__).resolve(strict=True) == SELF, "fixed recovery driver path")
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--spec-bytes", required=True, type=int)
    parser.add_argument("--spec-sha256", required=True)
    args = parser.parse_args()
    spec_pin = {"path": args.spec, "bytes": args.spec_bytes, "sha256": args.spec_sha256}
    recovery_raw = read_pin(spec_pin)
    recovery_spec = strict_json(recovery_raw)
    self_raw = read_pin({"path": str(SELF), "bytes": SELF.stat().st_size,
                         "sha256": recovery_spec["resume_sha256"]})
    # This pure closure includes the actual original terminal. No Git/API call precedes it.
    C = validate_closed_original_inputs(recovery_spec)
    F, H = C["F"], C["H"]
    ev = C["evidence_directory"]
    ev.mkdir(mode=0o700, exist_ok=False)
    require(ev.resolve(strict=True) == ev, "canonical new recovery directory")
    os.umask(0o077)
    env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                "GIT_NAMESPACE", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        require(key not in env, "unexpected inherited Git override")
    for key in tuple(env):
        if key.startswith("GIT_TRACE") or key == "GIT_CURL_VERBOSE":
            del env[key]
    env.update(H["GATE_ENV"])
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_TRACE2="0", GIT_TRACE2_EVENT="0", GIT_TRACE2_PERF="0")
    original = C["original_publication"]
    original_spec = C["original_spec"]
    archive = C["archive"]
    tagref = "refs/tags/" + archive["tag"]
    expected = C["expected_heads"]
    old_tags, wanted_tags = C["old_tags"], C["wanted_tags"]
    allowed_tags = set(wanted_tags)
    steps = []
    state = {
        "schema": "trnm-followup-candidate-execution-resume-receipt-v3",
        "status": "HOLD", "started_at": now(), "head": HEAD, "tree": TREE,
        "driver": {"path": str(SELF), "bytes": len(self_raw), "sha256": sha(self_raw)},
        "invocation": {"argv": list(sys.argv), "executable": sys.executable, "optimize": sys.flags.optimize},
        "resume_spec": spec_pin, "transport_timeout_seconds": TRANSPORT_SECONDS,
        "previous_resume_attempts": recovery_spec["previous_resume_attempts"],
        "previous_resume_failures": C["previous_resume_failures"],
        "transport_trace": None,
        "effective_hook_plan": C["effective_hook_plan"],
        "original_publication_spec": recovery_spec["original_publication_spec"],
        "original_publication_receipt": recovery_spec["original_publication_receipt"],
        "original_publication_status": original["status"],
        "original_terminal_pages": recovery_spec["original_terminal_pages"],
        "original_terminal_proof": C["original_terminal_proof"],
        "original_launch_inputs": recovery_spec["original_launch_inputs"],
        "original_coverage": C["original_coverage"],
        "previous_own_published_head": F["BASE_HEAD"], "expected_remote_head": REMOTE_HEAD,
        "archive": archive, "archive_rebuilt": False,
        "validated_inputs": C["validated_inputs"],
        "original_hook_verified": True, "original_hook_receipt": original["hook_receipt"],
        "push_started": False, "push_exit": None, "exact_hook_verified": False, "hook_receipt": None,
        "remote_before": None, "remote_after": None, "source_after_valid": False,
        "publication_observation_phase": None, "hook_evidence_origin": None,
        "steps": steps, "errors": [], "automatic_retry_authorized": False,
        "rollback_authorized": False, "main_merged": False, "branches_deleted": False,
        "protection_changed": False, "pr_metadata_changed": False, "auto_merge_enabled": False,
        "hosted_ci_qualification": False, "qualification_granted": False,
        "required_head_and_prospective_ci_must_still_pass": True,
        "archive_preserves_history_not_semantic_equivalence": True,
        "untouched_refs_and_protection_atomically_locked": False,
        "HTTP_protocol_or_product_budget_changed": False,
    }
    def encode(value):
        return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    def emit(name, raw):
        path = ev / name
        with path.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}
    def save():
        temporary = ev / "summary.next"
        with temporary.open("xb") as stream:
            stream.write(encode(state))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, ev / "summary.json")
    def run(label, argv, timeout=180, require_zero=True, sampled=False):
        require(re.fullmatch(r"[a-z0-9-]+", label) and not any(r["label"] == label for r in steps),
                "duplicate/invalid recovery command")
        began = now()
        if sampled:
            require(timeout == TRANSPORT_SECONDS, "only transport budget may be 3600")
            q, errors, trace_proof = capture_sampled(argv, env, ev / (label + "-process-samples.jsonl"))
            state["transport_sampling_errors"] = errors
            state["transport_trace"] = trace_proof
            if not trace_proof["complete"]:
                state["errors"].append({"phase": "typed-transport-trace", "type": "IncompleteTrace",
                                        "message": "Typed-only diagnostic capture incomplete; real push/readback facts retained."})
        else:
            q = H["capture"](argv, env, timeout=timeout)
        row = {"label": label, "argv": argv, "cwd": str(SOURCE), "exit": q.returncode,
               "timeout_seconds": timeout, "started_at": began, "finished_at": now()}
        for channel in ("stdout", "stderr"):
            value = emit(label + "." + channel, getattr(q, channel))
            for key, item in value.items():
                row[channel + "_" + key] = item
        steps.append(row)
        save()
        print(json.dumps({"label": label, "exit": q.returncode}), flush=True)
        require(not require_zero or q.returncode == 0, label + " failed; actual output retained")
        return q
    def git_value(label, *argv):
        return run(label, ["git", "--no-replace-objects", *argv], timeout=60).stdout.decode().strip()
    def object_bytes(label, kind, oid, maximum):
        size = git_value(label + "-size", "cat-file", "-s", oid)
        require(re.fullmatch(r"[1-9][0-9]*", size) and int(size) <= maximum, "bounded existing object")
        raw = run(label, ["git", "--no-replace-objects", "cat-file", kind, oid], timeout=60).stdout
        require(len(raw) == int(size) and F["git_object_oid"](kind, raw) == oid, "existing object address")
        return raw
    def observe(phase):
        a = run("remote-" + phase + "-heads", ["git", "ls-remote", "--heads", "origin"],
                require_zero=False)
        b = run("remote-" + phase + "-tags", ["git", "ls-remote", "origin",
                *sorted(old_tags), tagref, tagref + "^{}"], require_zero=False)
        value = {"observed_at": now(), "heads": None, "tags": None,
                 "errors": [], "both_old": False, "both_new": False}
        for name, response in (("heads", a), ("tags", b)):
            if response.returncode != 0:
                value["errors"].append(name + " read exit " + str(response.returncode))
            else:
                try:
                    value[name] = F["parse_refs"](response.stdout, heads=name == "heads",
                                                  allowed=allowed_tags if name == "tags" else None)
                except Exception as error:
                    value["errors"].append(name + " parse " + type(error).__name__)
        value["both_old"] = not value["errors"] and value["heads"] == expected and value["tags"] == old_tags
        value["both_new"] = (not value["errors"] and value["heads"] == C["wanted_heads"]
                             and value["tags"] == wanted_tags)
        return value
    emit("resume-spec.json", recovery_raw)
    emit("original-publication-spec.json", C["original_spec_raw"])
    emit("original-publication-receipt.json", C["original_publication_raw"])
    emit("original-terminal-pages.json", C["original_terminal_record_raw"])
    emit("original-terminal-output.bin", C["original_terminal_output"])
    emit("original-terminal-proof.json", encode(C["original_terminal_proof"]))
    emit("archive-local.json", encode(archive))
    emit("archive-file-index.json", C["archive_index_raw"])
    emit("expected-reviewed-remote-heads.json", encode(expected))
    emit("expected-published-dc42-heads.json", encode(C["published_heads"]))
    save()
    source_before_raw = None
    hook_dir = None
    try:
        require(H["identity_snapshot"](env) == {"head": HEAD, "tree": TREE, "status": ""},
                "local candidate HEAD/tree/status")
        for label, argv in (
            ("origin-push-url", ["git", "remote", "get-url", "--push", "--all", "origin"]),
            ("origin-fetch-url", ["git", "remote", "get-url", "--all", "origin"]),
        ):
            require(run(label, argv, timeout=60).stdout.decode().splitlines() == [F["URL"]],
                    "unique canonical origin")
        config = run("existing-hook-config", ["git", "config", "--get", "core.hooksPath"],
                     timeout=60, require_zero=False)
        require(config.returncode == 1 and not config.stdout and not config.stderr, "existing required hook")
        default_hook = pathlib.Path(git_value("default-hook-path", "rev-parse",
                                              "--path-format=absolute", "--git-path", "hooks/pre-push"))
        require(not default_hook.exists() and not default_hook.is_symlink(), "default hook must not be overridden")
        # Existing archive only: read refs/objects/tree roster; no object or ref construction.
        require(git_value("old-local-tag", "rev-parse", F["OLD_TAG_REF"]) == F["OLD_TAG_OID"]
                and git_value("old-local-peel", "rev-parse", F["OLD_TAG_REF"] + "^{}") == F["OLD_ARCHIVE_COMMIT"],
                "old local archive changed")
        require(git_value("same-local-tag", "rev-parse", tagref) == archive["tag_oid"]
                and git_value("same-local-peel", "rev-parse", tagref + "^{}") == archive["commit"],
                "same existing local archive required")
        for label, kind, oid, maximum in (
            ("old-archive-commit-object", "commit", F["OLD_ARCHIVE_COMMIT"], 128 * 1024),
            ("old-archive-tag-object", "tag", F["OLD_TAG_OID"], 64 * 1024),
            ("same-archive-commit-object", "commit", archive["commit"], 128 * 1024),
            ("same-archive-tag-object", "tag", archive["tag_oid"], 64 * 1024),
        ):
            raw = object_bytes(label, kind, oid, maximum)
            if label == "old-archive-commit-object":
                F["check_commit_object"](raw, oid, F["OLD_ARCHIVE_TREE"], C["old_parents"])
            elif label == "old-archive-tag-object":
                F["check_tag_object"](raw, oid, F["OLD_TAG"], F["OLD_ARCHIVE_COMMIT"])
            elif kind == "commit":
                F["check_commit_object"](raw, oid, archive["tree"], [F["OLD_ARCHIVE_COMMIT"], HEAD])
            else:
                F["check_tag_object"](raw, oid, archive["tag"], archive["commit"])
        require(run("same-archive-exact-tree-list",
                    ["git", "ls-tree", "-r", "-z", archive["tree"]], timeout=60).stdout == C["archive_tree_listing"],
                "same existing archive tree/blob roster")
        run("project-preflight", ["bash", "scripts/project-preflight.sh", "--audit"])
        before = run("verify-source-before", [H["PYTHON"], "-B", "scripts/ci/verify_ci_source.py",
            "--kind", "head", "--expected-head", HEAD, "--output", str(ev / "source-before.json")])
        source_before_raw, _ = F["stable_bytes"](ev / "source-before.json")
        require(before.stdout == source_before_raw == C["source_before_raw"]
                and H["validate_source_identity"](source_before_raw, HEAD, TREE) == C["gate_source"],
                "fresh source/gates/ROG/original source differ")
        state["source_before_identity"] = H["identity_snapshot"](env)
        require(state["source_before_identity"] == {"head": HEAD, "tree": TREE, "status": ""}, "fresh source identity")
        for label, ancestor, descendant in (
            ("candidate-fast-forward", F["BASE_HEAD"], HEAD),
            ("main-ancestry", F["MAIN_HEAD"], HEAD),
            ("semantic-ledger-ancestry", "5c04c60e463462d9df8884786e0d5bb32af08a64", HEAD),
            ("published-to-reviewed-remote", F["BASE_HEAD"], REMOTE_HEAD),
            ("reviewed-remote-to-candidate", REMOTE_HEAD, HEAD),
            ("published-to-rog-start", F["BASE_HEAD"], original_spec["rog_invocation"]["expected_start_head"]),
            ("rog-start-to-candidate", original_spec["rog_invocation"]["expected_start_head"], HEAD),
        ):
            run(label, ["git", "--no-replace-objects", "merge-base", "--is-ancestor", ancestor, descendant],
                timeout=60)
        actor_argv = ["gh", "api", "user", "--jq", "{login,id}"]
        actor = strict_json(run("actor", actor_argv).stdout)
        require(actor == C["actor"] and actor["login"] == "ProfHepta", "fresh original actor")
        pr_argv = ["gh", "api", "repos/" + F["REPOSITORY"] + "/pulls/847", "--jq",
                  "{number,state,draft,head:.head.sha,head_ref:.head.ref,base:.base.sha,base_ref:.base.ref,auto_merge}"]
        pr = strict_json(run("pr-before", pr_argv).stdout)
        require(type(pr) is dict and set(pr) == set(C["publication_pr"])
                and type(pr["number"]) is int and pr["number"] == 847 and pr["state"] == "open"
                and pr["head_ref"] == F["CANDIDATE_REF"][11:] and pr["base_ref"] == "main"
                and pr["base"] == F["MAIN_HEAD"] and pr["auto_merge"] is None
                and type(pr["draft"]) is bool and pr["draft"] == C["publication_pr"]["draft"],
                "fresh PR/base/draft/auto-merge guard")
        state["actor"], state["pr_before"] = actor, pr
        state["remote_before"] = observe("before")
        save()
        obs = state["remote_before"]
        require(obs["both_old"] or obs["both_new"], "mixed/drift/unknown complete remote state: HOLD")
        require(pr["head"] == (HEAD if obs["both_new"] else REMOTE_HEAD), "fresh PR and refs disagree")
        if obs["both_new"]:
            state["publication_observation_phase"] = "before"
            state["hook_evidence_origin"] = "original_publication"
        else:
            require(original["status"] != "confirmed", "previous confirmed publication rolled back: HOLD")
            hook_dir = ev / "hooks"
            hook_dir.mkdir(mode=0o700)
            hook_expected_raw = C["expected_hook_raw"]
            hook_raw = C["effective_hook_raw"]
            for name, raw in (("expected.json", hook_expected_raw), ("pre-push", hook_raw)):
                with (hook_dir / name).open("xb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            hook_path = hook_dir / "pre-push"
            hook_path.chmod(0o700)
            require(stat.S_ISREG(hook_path.lstat().st_mode) and hook_path.lstat().st_mode & 0o111
                    and hook_path.lstat().st_nlink == 1 and hook_path.resolve(strict=True) == hook_path,
                    "new owned regular executable hook")
            run("prepush-preflight", ["bash", "scripts/project-preflight.sh", "--audit"])
            require(H["identity_snapshot"](env) == {"head": HEAD, "tree": TREE, "status": ""},
                    "source changed before resume push")
            require(run("prepush-origin-push-url", ["git", "remote", "get-url", "--push", "--all", "origin"],
                        timeout=60).stdout.decode().splitlines() == [F["URL"]], "prepush origin")
            config = run("prepush-existing-hook-config", ["git", "config", "--get", "core.hooksPath"],
                         timeout=60, require_zero=False)
            require(config.returncode == 1 and not config.stdout and not config.stderr
                    and not default_hook.exists() and not default_hook.is_symlink(), "required hook appeared")
            require(strict_json(run("pr-prepush", pr_argv).stdout) == pr, "PR changed before retry")
            require(strict_json(run("actor-prepush", actor_argv).stdout) == actor, "actor changed before retry")
            F["check_versions"](C["snapshots"])
            final_pin_fence()
            require(F["stable_bytes"](hook_dir / "expected.json")[0] == hook_expected_raw
                    and F["stable_bytes"](hook_path)[0] == hook_raw, "new hook bytes changed")
            state["push_started"], state["status"], state["push_started_at"] = True, "UNKNOWN", now()
            save()
            q = run("atomic-publish-resume", [
                "git", "-c", "core.hooksPath=" + str(hook_dir), "push", "--verify", "--atomic",
                "--porcelain", "--verbose", "--progress", "origin",
                HEAD + ":" + F["CANDIDATE_REF"], tagref + ":" + tagref],
                timeout=TRANSPORT_SECONDS, require_zero=False, sampled=True)
            state["push_exit"] = q.returncode
            save()
    except Exception as error:
        state["errors"].append({"phase": "fresh-guard-or-push", "type": type(error).__name__,
                                "message": str(error)})
    finally:
        if state["push_started"]:
            try:
                state["remote_after"] = observe("after")
            except Exception as error:
                state["errors"].append({"phase": "remote-after", "type": type(error).__name__,
                                        "message": str(error)})
            try:
                state["hook_receipt"] = F["verify_hook_receipt"](
                    hook_dir, C["expected_hook_raw"], C["effective_hook_raw"], C["expected_hook"])
                state["exact_hook_verified"] = True
            except Exception as error:
                state["errors"].append({"phase": "new-hook-readback", "type": type(error).__name__,
                                        "message": str(error)})
        try:
            q = run("verify-source-after", [H["PYTHON"], "-B", "scripts/ci/verify_ci_source.py",
                "--kind", "head", "--expected-head", HEAD, "--output", str(ev / "source-after.json")],
                require_zero=False)
            after, _ = F["stable_bytes"](ev / "source-after.json")
            require(q.returncode == 0 and after == q.stdout == source_before_raw == C["source_after_raw"]
                    and H["validate_source_identity"](after, HEAD, TREE) == C["gate_source"],
                    "fresh source-after stdout/sidecar/closure")
            state["source_after_identity"] = H["identity_snapshot"](env)
            require(state["source_after_identity"] == {"head": HEAD, "tree": TREE, "status": ""},
                    "source-after head/tree/status")
            F["check_versions"](C["snapshots"])
            final_pin_fence()
            state["source_after_valid"] = True
        except Exception as error:
            state["errors"].append({"phase": "source-after", "type": type(error).__name__,
                                    "message": str(error)})
        after = state["remote_after"]
        before = state["remote_before"]
        if (not state["errors"] and state["push_started"] and isinstance(after, dict)
                and after["both_new"] and state["source_after_valid"] and state["exact_hook_verified"]):
            state["status"] = "confirmed"
            state["publication_observation_phase"] = "after"
            state["hook_evidence_origin"] = "resume"
        elif (not state["errors"] and not state["push_started"] and isinstance(before, dict)
              and before["both_new"] and state["source_after_valid"] and state["original_hook_verified"]):
            state["status"] = "already_confirmed"
        else:
            state["status"] = "UNKNOWN" if state["push_started"] else "HOLD"
        state["finished_at"] = now()
        save()
    print(json.dumps({"schema": state["schema"], "status": state["status"],
        "head": HEAD, "tree": TREE, "push_started": state["push_started"], "push_exit": state["push_exit"],
        "source_after_valid": state["source_after_valid"], "exact_hook_verified": state["exact_hook_verified"],
        "original_hook_verified": state["original_hook_verified"],
        "publication_observation_phase": state["publication_observation_phase"],
        "receipt": str(ev / "summary.json")}), flush=True)
    return 0 if state["status"] in ("confirmed", "already_confirmed") else 1

if __name__ == "__main__":
    sys.exit(main())
