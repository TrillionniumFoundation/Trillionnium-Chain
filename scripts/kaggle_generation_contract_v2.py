"""Unexecuted candidate adapter for the reviewed hepta-kaggle-job-v1 contract.

The object passed as adapter is the existing authenticated KaggleAdapter; this
module does not change that adapter, select accounts or read credentials.
Only a NEW committed M12 generation intent may call dispatch. Every replay calls
the adapter's observation-only resume on the original request ID. The separate
target fence protects one NativeTask across generation journals at that target.
Provider receipts and fixture receipts are not cryptographic proof of W1.
"""
import hashlib
import json
import os
import contextlib
from pathlib import Path, PurePosixPath
import re
import sqlite3
import subprocess
import time

NAMESPACE = "trnm-w1-kaggle-generation-target-v2"
TERMINAL = frozenset({"COMPLETE", "ERROR", "CANCEL_ACKNOWLEDGED"})
STATES = TERMINAL | {"QUEUED", "RUNNING", "CANCEL_REQUESTED", "NEW_SCRIPT", "UNKNOWN"}
INTENT_KEYS = {"source_sha256", "timeout_seconds", "accelerator", "internet", "kernel_type",
               "language", "is_private", "dataset_sources", "kernel_sources", "model_sources", "competition_sources"}
TARGET_DDL = "CREATE TABLE generation_targets(operation TEXT PRIMARY KEY,task_scope TEXT UNIQUE NOT NULL,request_id TEXT UNIQUE NOT NULL,binding BLOB NOT NULL,cancel INTEGER NOT NULL CHECK(cancel IN (0,1)),identity BLOB,last_receipt BLOB) STRICT"
OBSERVATION_DDL = "CREATE TABLE target_observations(sequence INTEGER PRIMARY KEY,operation TEXT NOT NULL,receipt BLOB NOT NULL CHECK(length(receipt)<=262144)) STRICT"


def check(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def hex32(value):
    check(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "expected 32-byte digest")
    return value


def positive_int(value):
    # bool is an int subclass and must never become a provider session/version.
    check(type(value) is int and value > 0, "positive provider integer required")
    return value


def expected_binding(binding):
    check(binding["schema"] == NAMESPACE, "binding namespace")
    check(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", binding["request_id"]), "request_id")
    for name in ("task_scope", "statement", "journal_identity", "operation", "provider_namespace", "input_digest"):
        hex32(binding[name])
    intent = binding["intent"]
    check(set(intent) == INTENT_KEYS and digest(intent) == binding["input_digest"], "immutable input digest")
    hex32(intent["source_sha256"])
    check(type(intent["timeout_seconds"]) is int and 1 <= intent["timeout_seconds"] <= 43200, "provider timeout")
    check(intent["language"] == "python" and intent["is_private"] is True
          and intent["kernel_type"] in {"script", "notebook"} and type(intent["internet"]) is bool, "provider settings")
    check(re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", intent["accelerator"]), "accelerator")
    for key in ("dataset_sources", "kernel_sources", "model_sources", "competition_sources"):
        check(isinstance(intent[key], list) and len(intent[key]) <= 50
              and all(isinstance(v, str) and len(v) <= 512 and "\n" not in v for v in intent[key]), "input references")
    check(isinstance(binding["account_username"], str) and re.fullmatch(r"[A-Za-z0-9_-]+", binding["account_username"]), "account identity")
    # Original controller deadline is retained, but never subtracted from a
    # Kaggle monotonic timestamp or extended to its remote hard timeout.
    deadline = binding["original_controller_deadline"]
    hex32(deadline["clock_domain"])
    check(type(deadline["winner_ns"]) is int and type(deadline["deadline_ns"]) is int
          and 0 <= deadline["winner_ns"] < deadline["deadline_ns"], "original controller deadline")
    return binding


def normalized_source(path, kernel_type):
    path = Path(path)
    check(not path.is_symlink() and path.is_file() and path.stat().st_size <= 2 * 1024 * 1024, "source file bound")
    raw = path.read_bytes()
    check(len(raw) <= 2 * 1024 * 1024, "source file grew")
    code = raw.decode("utf-8")
    if kernel_type == "notebook":
        notebook = json.loads(code)
        check(isinstance(notebook.get("cells"), list), "notebook cells")
        for cell in notebook["cells"]:
            if cell.get("cell_type") == "code":
                cell["outputs"] = []
            if isinstance(cell.get("source"), list):
                cell["source"] = "".join(cell["source"])
        code = canonical(notebook).decode("utf-8")
    return code.encode("utf-8")


def receipt_identity(binding, receipt, prior_identity=None):
    expected_binding(binding)
    check(receipt.get("schema") == "hepta-kaggle-job-v1", "provider receipt schema")
    check(receipt.get("remote_submission_replayed", False) is False,
          "provider receipt reports a replayed or unproven submission")
    check(receipt.get("request_id") == binding["request_id"]
          and receipt.get("input_digest") == binding["input_digest"]
          and receipt.get("intent") == binding["intent"], "provider immutable request mismatch")
    check(receipt.get("account", {}).get("username") == binding["account_username"], "provider account changed")
    state = receipt.get("remote_state", "UNKNOWN")
    check(state in STATES, "unknown provider state spelling")
    ref = receipt.get("notebook_ref")
    check(isinstance(ref, str) and re.fullmatch(r"[A-Za-z0-9_-]+/[a-z0-9-]+", ref)
          and ref.split("/", 1)[0] == binding["account_username"], "notebook owner/ref")
    version, kernel = receipt.get("notebook_version"), receipt.get("kernel_id")
    acknowledged = receipt.get("submission_state") == "ACCEPTED" and receipt.get("remote_submission_state") == "ACKNOWLEDGED"
    identity = None
    if acknowledged:
        identity = {"request_id": binding["request_id"], "input_digest": binding["input_digest"],
                    "account_username": binding["account_username"], "notebook_ref": ref,
                    "notebook_version": positive_int(version), "kernel_id": positive_int(kernel)}
        if prior_identity is not None:
            check(identity == prior_identity, "provider job repinned")
    elif prior_identity is not None:
        # An observation may become unavailable, but never silently lose or
        # replace the original concrete version/kernel identity.
        check(ref == prior_identity["notebook_ref"] and version == prior_identity["notebook_version"]
              and kernel == prior_identity["kernel_id"], "provider retained identity changed")
    session = receipt.get("kernel_session_id")
    cancel_session_proven = False
    if session is not None:
        positive_int(session)
        session_binding = receipt.get("session_binding") or {}
        cancel_session_proven = (session_binding.get("notebook_ref") == ref
                                 and session_binding.get("notebook_version") == version)
        if cancel_session_proven:
            hex32(session_binding.get("response_sha256"))
    verified = receipt.get("identity_verified") is True
    unknown = receipt.get("remote_effect_unknown") is not False
    invalid = receipt.get("submission_state") == "ACCEPTED_WITH_INVALID_INPUTS" or bool(receipt.get("invalid_inputs"))
    return {"identity": identity, "provider_job_id": digest(identity) if identity else None,
            "state": state, "acknowledged": acknowledged, "identity_verified": verified,
            "remote_terminal_observed": acknowledged and verified and not unknown and not invalid and state in TERMINAL,
            "artifact_candidate": acknowledged and verified and not unknown and not invalid and state == "COMPLETE",
            "cancel_session_proven": cancel_session_proven,
            "cancel_blocker": None if cancel_session_proven else "SESSION_IDENTITY_UNPROVEN",
            "remote_effect_unknown": unknown, "remote_submission_replayed": False,
            "may_dispatch_again": False, "may_release_resources": False, "can_authorize_payment": False}


def check_download(binding, provider_receipt, download, artifact_root, manifest_name, prior_identity=None):
    observation = receipt_identity(binding, provider_receipt, prior_identity)
    check(observation["artifact_candidate"], "remote execution not a verified COMPLETE")
    identity = observation["identity"]
    for k in ("request_id", "input_digest", "notebook_ref", "notebook_version"):
        check(download.get(k) == identity[k], "download identity")
    check(download.get("schema") == "hepta-kaggle-download-v1"
          and download.get("remote_manifest_verified") is True
          and download.get("remote_manifest_name") == manifest_name
          and download.get("verification_policy") == "manifest-and-http-v1", "worker manifest required")
    files = download.get("files")
    check(isinstance(files, list) and download.get("files_manifest_sha256") == digest(files), "file list digest")
    root = Path(artifact_root)
    check(root.is_dir() and not root.is_symlink(), "artifact root")
    check(str(root) == download.get("directory"), "artifact directory identity")
    seen, actual, total = set(), {}, 0
    for item in files:
        name = item["path"]
        check(isinstance(name, str) and name and not PurePosixPath(name).is_absolute()
              and "\\" not in name and ":" not in name and "\x00" not in name
              and all(part not in {"", ".", ".."} for part in name.split("/")), "artifact path")
        check(name not in seen, "duplicate artifact path")
        seen.add(name)
        path = root / name
        check(not any(p.is_symlink() for p in path.parents) and not path.is_symlink() and path.is_file(), "artifact symlink/type")
        check(type(item.get("bytes")) is int and item["bytes"] >= 0
              and type(item.get("http_content_length")) is int
              and item["http_content_length"] == item["bytes"]
              and item.get("http_content_length_verified") is True, "HTTP length binding")
        h = hashlib.sha256()
        size = 0
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                size += len(chunk)
                check(size <= item["bytes"], "artifact length overrun")
                h.update(chunk)
        check(size == item["bytes"] and h.hexdigest() == hex32(item["sha256"]), "artifact bytes/hash")
        total += size
        actual[name] = {"bytes": size, "sha256": h.hexdigest()}
    check(total == download.get("total_bytes") and manifest_name in actual, "artifact total/manifest")
    manifest = json.loads((root / manifest_name).read_bytes())
    check(manifest.get("schema") == "hepta-artifact-manifest-v1" and manifest.get("request_id") == binding["request_id"], "worker manifest identity")
    entries = manifest.get("files")
    check(isinstance(entries, list), "worker manifest entries")
    declared = {x["path"]: {"bytes": x["bytes"], "sha256": x["sha256"]} for x in entries}
    check(len(declared) == len(entries) and declared == {k: v for k, v in actual.items() if k != manifest_name}, "worker complete closure")
    return {**observation, "worker_artifacts_verified": True, "next_gate": "INDEPENDENT_FULL_W1_V2_VERIFIER",
            "can_authorize_payment": False, "may_release_resources": False}


class KaggleGenerationTargetV2:
    """Concrete durable wrapper around the existing KaggleAdapter methods.

    This local target DB must be shared by all journals of this service. It is
    never restored from native chain snapshots. None of its methods pays money.
    submit is reachable once after the new outer target intent has committed;
    every uncertain/failed/accepted/rejected retry only observes resume.
    """
    def __init__(self, adapter, fence_path, clock_checkpoint):
        self.adapter = adapter
        self.clock_checkpoint = clock_checkpoint
        path = Path(fence_path)
        check(not path.is_symlink(), "target fence symlink")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), isolation_level=None, timeout=5)
        self.source_root = path.with_name(path.name + ".sources")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA trusted_schema=OFF")
        app = self.db.execute("PRAGMA application_id").fetchone()[0]
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        ddl = TARGET_DDL
        observations_ddl = OBSERVATION_DDL
        if app == 0 and version == 0:
            self.db.execute("BEGIN IMMEDIATE")
            check(self.db.execute("SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").fetchone()[0] == 0, "foreign target fence")
            self.db.execute(ddl)
            self.db.execute(observations_ddl)
            self.db.execute("PRAGMA application_id=1464551218")
            self.db.execute("PRAGMA user_version=2")
            self.db.execute("COMMIT")
        check(self.db.execute("PRAGMA application_id").fetchone()[0] == 1464551218
              and self.db.execute("PRAGMA user_version").fetchone()[0] == 2, "target fence namespace")
        check(self.db.execute("SELECT sql FROM sqlite_master WHERE name='generation_targets'").fetchone() == (ddl,), "target fence schema")
        check(self.db.execute("SELECT sql FROM sqlite_master WHERE name='target_observations'").fetchone() == (observations_ddl,), "target observation schema")
        check(self.db.execute("SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").fetchone()[0] == 2, "target fence schema")
        self.db.execute("PRAGMA journal_mode=WAL")

    def _schema(self):
        check(self.db.execute("PRAGMA application_id").fetchone() == (1464551218,)
              and self.db.execute("PRAGMA user_version").fetchone() == (2,), "target live namespace")
        for name, ddl in (("generation_targets", TARGET_DDL), ("target_observations", OBSERVATION_DDL)):
            check(self.db.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone() == (ddl,),
                  "target live schema")
        check(self.db.execute("SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").fetchone() == (2,),
              "target live schema")

    @contextlib.contextmanager
    def _write(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            self._schema()
            yield
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        else:
            self.db.execute("COMMIT")

    def _check_original_deadline(self, binding):
        checkpoint = self.clock_checkpoint()
        original = binding["original_controller_deadline"]
        check(checkpoint["clock_domain"] == original["clock_domain"], "controller clock continuity UNKNOWN")
        check(original["winner_ns"] <= checkpoint["now_ns"] < original["deadline_ns"], "original controller deadline")

    def _freeze_source(self, binding, source):
        raw = normalized_source(source, binding["intent"]["kernel_type"])
        check(hashlib.sha256(raw).hexdigest() == binding["intent"]["source_sha256"], "frozen source digest")
        self.source_root.mkdir(parents=True, exist_ok=True)
        check(not self.source_root.is_symlink(), "source custody directory")
        path = self.source_root / (binding["operation"] + ".source")
        if path.exists():
            check(not path.is_symlink() and path.read_bytes() == raw, "frozen source replaced")
        else:
            with path.open("xb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            path.chmod(0o400)
            fd = os.open(self.source_root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        return path

    def _row(self, operation):
        self._schema()
        row = self.db.execute("SELECT binding,cancel,identity,last_receipt,task_scope,request_id FROM generation_targets WHERE operation=?", (operation,)).fetchone()
        check(row is not None, "original target intent missing: UNKNOWN")
        binding = expected_binding(json.loads(row[0]))
        check(canonical(binding) == row[0] and binding["operation"] == operation
              and binding["task_scope"] == row[4] and binding["request_id"] == row[5], "target binding damaged")
        return {"binding": binding, "cancel": bool(row[1]),
                "identity": json.loads(row[2]) if row[2] else None,
                "last_receipt": json.loads(row[3]) if row[3] else None}

    def _record(self, operation, receipt):
        raw = canonical(receipt)
        check(len(raw) <= 262144, "provider receipt size; original adapter ledger retains the original")
        # Retain even a rejected identity response before validating it. This is
        # an audit observation, not an upgrade of its authority or result state.
        with self._write():
            self._row(operation)
            self.db.execute("INSERT INTO target_observations(operation,receipt) VALUES(?,?)", (operation, raw))
        with self._write():
            row = self._row(operation)
            observed = receipt_identity(row["binding"], receipt, row["identity"])
            identity = observed["identity"] or row["identity"]
            self.db.execute("UPDATE generation_targets SET identity=?,last_receipt=? WHERE operation=?",
                            (canonical(identity) if identity else None, raw, operation))
        check(self._row(operation)["last_receipt"] == receipt, "target observation committed readback")
        return {**observed, "sticky_cancel": row["cancel"], "provider_receipt": receipt,
                "may_dispatch_again": False, "may_release_resources": False, "can_authorize_payment": False}

    def dispatch(self, binding, source, *, m12_new_intent):
        # This flag is a trusted service call boundary, not a remotely supplied
        # capability. The provider itself cannot turn an ACK into M12 New.
        check(m12_new_intent is True, "M12 New required; Pending only reconciles")
        expected_binding(binding)
        raw = canonical(binding)
        with self._write():
            old = self.db.execute("SELECT binding FROM generation_targets WHERE operation=?", (binding["operation"],)).fetchone()
            if old:
                check(old[0] == raw, "target binding replay mismatch")
            else:
                self._check_original_deadline(binding)
                self.db.execute("INSERT INTO generation_targets VALUES(?,?,?,?,0,NULL,NULL)",
                                (binding["operation"], binding["task_scope"], binding["request_id"], raw))
        if old:
            return self.reconcile(binding["operation"])
        check(self._row(binding["operation"])["binding"] == binding, "target intent committed readback")
        # A crash here permanently leaves this intent for observation only. It
        # cannot be repaired by inventing a different request_id or new version.
        intent = binding["intent"]
        frozen_source = self._freeze_source(binding, source)
        if isinstance(self.adapter, AccountGuardedCliAdapter):
            # The normal account wrapper performs its existing live identity
            # guard. This only checks the caller-pinned wrapper/prefix; returned
            # receipt identity is checked independently below, never synthesized.
            self.adapter.verify_account_guard(binding["account_username"])
        else:
            check(self.adapter.transport.account().get("username") == binding["account_username"], "authenticated account changed")
        self._check_original_deadline(binding)
        check(not self._row(binding["operation"])["cancel"], "sticky cancel before provider submit")
        receipt = self.adapter.submit(request_id=binding["request_id"], source=str(frozen_source),
            timeout=intent["timeout_seconds"], accelerator=intent["accelerator"], internet=intent["internet"],
            kernel_type=intent["kernel_type"], dataset_sources=intent["dataset_sources"],
            kernel_sources=intent["kernel_sources"], model_sources=intent["model_sources"],
            competition_sources=intent["competition_sources"])
        return self._record(binding["operation"], receipt)

    def reconcile(self, operation):
        row = self._row(operation)
        # Actual reviewed adapter resume is observation-only, including UNKNOWN.
        return self._record(operation, self.adapter.resume(row["binding"]["request_id"]))

    def cancel(self, operation, wait_seconds=0):
        with self._write():
            row = self._row(operation)
            self.db.execute("UPDATE generation_targets SET cancel=1 WHERE operation=?", (operation,))
        check(self._row(operation)["cancel"], "cancel veto committed readback")
        # Existing adapter alone decides whether a genuine kernel_session_id is
        # proven. Its SESSION_IDENTITY_UNPROVEN error preserves this local veto.
        receipt = self.adapter.cancel(row["binding"]["request_id"], wait_seconds=wait_seconds)
        return self._record(operation, receipt)


class AccountGuardedCliAdapter:
    """Actual existing provider CLI, on the host where its account wrapper lives.

    No SSH, credential read, alternate account, or direct low-level transport is
    introduced. ``prefix`` is caller-supplied, pinned, and must end in the exact
    reviewed normal account and ``batch``. Raw failed outputs survive; a submit
    timeout remains Unknown in the outer target journal and is never retried.
    This adapter does not claim that an expected username is live authentication.
    Authentication stays in the existing account wrapper and original receipt.
    """
    def __init__(self, prefix, wrapper_sha256, account_label, expected_username,
                 evidence_directory, original_deadline_ns, original_boot_id):
        check(isinstance(prefix, list) and len(prefix) == 3
              and all(isinstance(x, str) and x and "\x00" not in x for x in prefix), "provider command prefix")
        check(prefix[1:] == [account_label, "batch"] and account_label == "qiqian", "normal provider account wrapper required")
        self.prefix = prefix
        self.wrapper_sha256 = hex32(wrapper_sha256)
        self.expected_username = expected_username
        self.directory = Path(evidence_directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        check(not self.directory.is_symlink(), "provider evidence symlink")
        self.deadline_ns = original_deadline_ns
        self.boot = original_boot_id
        self.verify_account_guard(expected_username)

    def verify_account_guard(self, expected_username):
        check(expected_username == self.expected_username, "expected provider account changed")
        path = Path(self.prefix[0])
        check(path.is_absolute() and path.is_file(), "existing account wrapper unavailable on this host")
        check(hashlib.sha256(path.read_bytes()).hexdigest() == self.wrapper_sha256, "account wrapper changed")

    def _call(self, command, arguments, *, submission=False):
        self.verify_account_guard(self.expected_username)
        check(Path("/proc/sys/kernel/random/boot_id").read_text().strip() == self.boot,
              "provider controller boot changed; original deadline not rebased")
        started = time.monotonic_ns()
        if submission:
            check(started < self.deadline_ns, "original submission deadline exhausted")
        # Observation/cleanup after a deadline is allowed, but it never restores
        # proof eligibility or permission to dispatch another physical request.
        timeout = min(60., max(.001, (self.deadline_ns - started) / 1e9)) if submission else 60.
        stem = self.directory / (str(started) + "-" + command)
        intent = {"argv": [*self.prefix, command, *arguments], "started_monotonic_ns": started,
                  "original_deadline_ns": self.deadline_ns, "original_boot_id": self.boot,
                  "submission": submission, "normal_account_guard_owner": str(self.prefix[0])}
        with stem.with_suffix(".intent.json").open("xb") as f:
            f.write(canonical(intent) + b"\n"); f.flush(); os.fsync(f.fileno())
        try:
            with stem.with_suffix(".stdout").open("xb") as out, stem.with_suffix(".stderr").open("xb") as err:
                completed = subprocess.run(intent["argv"], stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                           check=False, timeout=timeout)
            result = {**intent, "returncode": completed.returncode, "finished_monotonic_ns": time.monotonic_ns()}
            with stem.with_suffix(".result.json").open("xb") as f:
                f.write(canonical(result) + b"\n"); f.flush(); os.fsync(f.fileno())
            raw = stem.with_suffix(".stdout").read_bytes()
            check(len(raw) <= 262144, "bounded provider receipt")
            receipt = json.loads(raw)
            check(isinstance(receipt, dict), "provider object receipt")
            # Some original adapters preserve an Unknown receipt with failure
            # transport status. Retain and validate that receipt, not exit 0.
            return receipt
        except BaseException as exc:
            with stem.with_suffix(".failure.json").open("xb") as f:
                f.write(canonical({**intent, "error": f"{type(exc).__name__}: {exc}",
                                   "remote_effect_unknown": submission, "may_dispatch_again": False}) + b"\n")
                f.flush(); os.fsync(f.fileno())
            raise

    def submit(self, **kw):
        check(kw["kernel_type"] == "script" and not any(kw[k] for k in
              ("dataset_sources", "kernel_sources", "model_sources", "competition_sources")),
              "only reviewed fixed-source script CLI settings supported")
        args = ["--request-id", kw["request_id"], "--source", str(kw["source"]),
                "--timeout", str(kw["timeout"]), "--accelerator", kw["accelerator"]]
        if kw["internet"]:
            args.append("--internet")
        return self._call("submit", args, submission=True)

    def resume(self, request_id):
        return self._call("resume", ["--request-id", request_id])

    def cancel(self, request_id, wait_seconds=0):
        check(wait_seconds == 0, "unreviewed CLI cancellation wait option refused")
        return self._call("cancel", ["--request-id", request_id])

    def artifacts(self, request_id, manifest_name, max_bytes):
        check(type(max_bytes) is int and max_bytes > 0 and manifest_name == "w1-result-manifest.json",
              "explicit bounded full-W1 artifact contract required")
        return self._call("artifacts", ["--request-id", request_id, "--manifest-name", manifest_name,
                                       "--max-bytes", str(max_bytes)])
