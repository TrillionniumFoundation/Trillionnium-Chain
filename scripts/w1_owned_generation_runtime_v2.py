#!/usr/bin/env python3
"""Explicit research owner runtime for the funded full-W1 integration test.

This helper does no funding or payment. The Rust Node/M12 owner commits its
generation intent before calling ``generate``. It executes a real POSIX target,
then a separate pinned full verifier of raw succinct.bin. Unknown GPU accounting
is retained as null; a valid proof does not manufacture a payable resource record.
The whole helper and every generated child stay inside the caller's original
Hepta job cgroup. Linux clock readings never come from a remote provider.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tarfile
import time
from types import SimpleNamespace

SCHEMA = "TRNM-W1-OWNED-GENERATION-RUNTIME2"
FORBIDDEN = {"RISC0_DEV_MODE", "RISC0_PROVER", "BONSAI_API_KEY", "BONSAI_API_URL"}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def obj(path, maximum=8 * 1024 * 1024):
    with Path(path).open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, "bounded JSON")
    result = json.loads(raw, object_pairs_hook=strict_pairs,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    require(type(result) is dict, "JSON object required")
    return result


def strict_pairs(items):
    value = {}
    for key, item in items:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def write_new(path, value):
    path = Path(path)
    with path.open("xb") as stream:
        stream.write(canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def complete_controller(controller):
    require(controller.get("schema") == "TRNM-W1-COMPLETE-STAGED-RUN3"
            and controller.get("complete_proof_claim") is True and controller.get("error") is None,
            "complete raw controller result required")
    stages = controller.get("stages")
    require(type(stages) is list and stages and controller.get("stage_dispatch_attempts") == [x.get("stage") for x in stages]
            and controller.get("unretained_stage_labels") == []
            and controller.get("controller_canceled_signal") is None
            and controller.get("controller_cancellation_event") is None
            and controller.get("deadline_exhausted_at_snapshot") is False,
            "controller stage retention/cancellation/deadline failure")
    labels = [x["stage"] for x in stages]
    require(labels[0] == "prepare-full-execution" and len(labels) == len(set(labels))
            and "complete-recursive-compression" in labels
            and "fresh-process-strict-verification" in labels,
            "complete fresh pipeline stages required")
    for item in stages:
        stage = item.get("result")
        require(type(stage) is dict and stage.get("schema") == "TRNM-W1-STAGE-MEASUREMENT3"
                and stage.get("returncode") == 0 and stage.get("stage_process_complete") is True
                and stage.get("error") is None and stage.get("termination_reasons") == []
                and stage.get("canceled_signal") is None and stage.get("cancellation_event") is None
                and stage.get("completion_observed_before_deadline") is True
                and stage.get("timed_out") is False and stage.get("deadline_exhausted_at_snapshot") is False
                and stage.get("owned_session_observation_complete") is True
                and stage.get("final_owned_session_members") == []
                and type(stage.get("final_known_group_probes")) is list
                and all(x.get("state") == "ABSENT" for x in stage["final_known_group_probes"])
                and stage.get("process_group_remaining_after_child_exit") is False,
                "raw stage has no complete uncancelled process observation: " + item["stage"])


def archive_object(archive, name, expected_sha256, maximum=8 * 1024 * 1024):
    require(isinstance(name, str) and name and not Path(name).is_absolute()
            and all(x not in {"", ".", ".."} for x in name.split("/")) and "\\" not in name,
            "raw archive member path")
    require(archive.is_file() and not archive.is_symlink() and archive.stat().st_size <= 256 * 1024 * 1024,
            "bounded raw archive required")
    # Read only exact bounded regular members; never extract archive paths into
    # the filesystem. Reject duplicate member names and link/directory stand-ins.
    raw = None
    seen = set()
    total_declared = 0
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            require(len(seen) < 10000 and member.name not in seen, "raw archive member count/duplicate")
            total_declared += max(0, member.size)
            require(0 <= member.size <= 512 * 1024 * 1024 and total_declared <= 512 * 1024 * 1024,
                    "raw archive decompressed byte bound")
            seen.add(member.name)
            if member.name == name:
                require(member.isfile() and 0 <= member.size <= maximum, "raw JSON member type/size")
                stream = tar.extractfile(member)
                require(stream is not None, "raw archive member stream")
                raw = stream.read(maximum + 1)
                require(len(raw) == member.size, "raw archive member length")
    require(raw is not None and hashlib.sha256(raw).hexdigest() == expected_sha256, "raw archive member digest")
    result = json.loads(raw, object_pairs_hook=strict_pairs,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    require(type(result) is dict, "raw archive JSON object")
    return result


def complete_worker_archive(worker):
    require(worker.get("outcome") == "verified" and worker.get("raw_archive_name") == "w1-raw-logs.tar.gz"
            and type(worker.get("raw_archive")) is dict and worker["raw_archive"].get("complete") is True,
            "fixed worker raw archive closure is not complete")
    return worker["raw_archive_name"]


def boot():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def identity(pid):
    data = Path(f"/proc/{pid}/stat").read_text()
    tail = data[data.rfind(")") + 2:].split()
    return {"pid": pid, "start_ticks": int(tail[19]), "parent": int(tail[1]), "boot_id": boot()}


def original(c):
    require(boot() == c["original_boot_id"], "original controller boot changed; no deadline rebasing")
    now = time.monotonic_ns()
    require(now < c["original_deadline_ns"], "original deadline exhausted")
    return now


def pinned(pin):
    path = Path(pin["path"])
    require(path.is_absolute() and path.is_file() and not path.is_symlink(), "absolute regular pinned file")
    require(sha(path) == pin["sha256"], "pinned file changed: " + str(path))
    return path


def source(c):
    root = Path(c["repo"])
    remote = c.get("provider", {}).get("kind") == "kaggle-cli"
    for key in ("native_winner", "material", "expected_artifacts", "header_template",
                "verifier", "guest", "python", "runtime") + (() if remote else ("runner", "r0vm", "target")):
        pinned(c[key])
    if remote:
        provider = c["provider"]
        for path, digest in provider["source_builder_file_pins"].items():
            pinned({"path": path, "sha256": digest})
        require(provider["source_builder_argv"] and provider["source_builder_argv"][0] in provider["source_builder_file_pins"],
                "source builder executable pin required")
        pinned({"path": provider["command_prefix"][0], "sha256": provider["wrapper_sha256"]})
    require(Path(c["runtime"]["path"]).resolve() == Path(__file__).resolve(), "runtime source path")
    for name, digest in c["source_files"].items():
        path = root / name
        require(not Path(name).is_absolute() and ".." not in Path(name).parts, "relative source pin")
        require(sha(path) == digest, "source file changed: " + name)
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    def git(*args):
        return subprocess.run(["/usr/bin/git", "-C", str(root), *args], check=True,
                              capture_output=True, env=env).stdout
    require(git("rev-parse", "HEAD").strip().decode() == c["expected_commit"], "source commit changed")
    require(git("rev-parse", "HEAD^{tree}").strip().decode() == c["expected_tree"], "source tree changed")
    require(git("status", "--porcelain=v1", "--untracked-files=all") == b"", "clean source required")
    require(not any(key in os.environ for key in FORBIDDEN), "unexpected proof environment")
    return {"commit": c["expected_commit"], "tree": c["expected_tree"],
            "source_files": c["source_files"], "raw_file_pins_checked": True}


class Scope:
    """Actual owned parent job scope, including all descendant sub-cgroups.

    The baseline may contain only this helper and its living ancestors. CPU is
    measured from cgroup usage counters; memory.peak is the parent's cumulative
    scope high-water mark, a conservative upper bound, not child peak RSS.
    """
    def __init__(self, c):
        self.c = c
        membership = Path("/proc/self/cgroup").read_text()
        lines = membership.splitlines()
        require(len(lines) == 1 and lines[0].startswith("0::/"), "unambiguous cgroup v2 membership required")
        self.relative = lines[0][3:]
        require("/hepta-runtime-job-" in self.relative and self.relative.endswith(".service"),
                "explicit isolated Hepta job scope required")
        mount = [line.split() for line in Path("/proc/self/mountinfo").read_text().splitlines()
                 if " - cgroup2 " in line]
        require(len(mount) == 1 and mount[0][3] == "/" and mount[0][4] == "/sys/fs/cgroup",
                "complete original cgroup mount required")
        self.path = Path("/sys/fs/cgroup") / self.relative.lstrip("/")
        self.ancestors = {}
        current = os.getpid()
        while current > 0:
            who = identity(current)
            self.ancestors[current] = who
            current = who["parent"]
        self.baseline = self.members()
        require(set(self.baseline) <= set(self.ancestors), "foreign process already occupies owner job scope")
        self.before = self.snapshot()
        require(self.before["memory_max"] != "max", "bounded owner memory cgroup required")
        require(self.before["cpu_max"].split()[0] != "max", "bounded owner CPU cgroup required")

    def groups(self):
        found = [self.path]
        for path in found:
            found.extend(child for child in path.iterdir() if child.is_dir())
            require(len(found) <= 128, "owned cgroup directory bound")
        return found

    def members(self):
        result = {}
        for group in self.groups():
            for value in (group / "cgroup.procs").read_text().split():
                pid = int(value)
                try:
                    who = identity(pid)
                    member = Path(f"/proc/{pid}/cgroup").read_text().strip()
                    require(member == "0::" + self.relative or member.startswith("0::" + self.relative + "/"),
                            "process moved outside owned cgroup")
                    result[pid] = who
                except FileNotFoundError:
                    pass
        return result

    def remaining(self):
        result = self.members()
        for pid in list(result):
            if pid in self.baseline:
                require(result[pid] == self.baseline[pid], "original scope process identity changed")
                del result[pid]
        return result

    def snapshot(self):
        counters = dict(line.split() for line in (self.path / "cpu.stat").read_text().splitlines())
        return {"cgroup": self.relative, "monotonic_ns": time.monotonic_ns(), "boot_id": boot(),
                "cpu_usage_ns": int(counters["usage_usec"]) * 1000,
                "cpu_max": (self.path / "cpu.max").read_text().strip(),
                "memory_max": (self.path / "memory.max").read_text().strip(),
                "memory_peak_upper_bound_bytes": int((self.path / "memory.peak").read_text()),
                "members": list(self.members().values())}

    def wait_empty(self, until_ns):
        while True:
            remaining = self.remaining()
            if not remaining:
                return True
            if time.monotonic_ns() >= until_ns:
                return False
            time.sleep(.05)

    def cleanup(self):
        # Cleanup never extends proof eligibility; original() is not used here.
        until = time.monotonic_ns() + 5_000_000_000
        while True:
            remaining = self.remaining()
            if not remaining:
                return True
            for pid, who in remaining.items():
                try:
                    fd = os.pidfd_open(pid)
                    try:
                        if identity(pid) == who:
                            signal.pidfd_send_signal(fd, signal.SIGKILL)
                    finally:
                        os.close(fd)
                except ProcessLookupError:
                    pass
            if time.monotonic_ns() >= until:
                return False
            time.sleep(.05)

    def costs(self, receipt_bytes=0):
        after = self.snapshot()
        require(after["boot_id"] == self.before["boot_id"] and after["cpu_usage_ns"] >= self.before["cpu_usage_ns"],
                "scope counters/clock changed")
        return {"before": self.before, "after": after,
                "cpu_ns": after["cpu_usage_ns"] - self.before["cpu_usage_ns"],
                "memory_peak_upper_bound_bytes": after["memory_peak_upper_bound_bytes"],
                "gpu_ns": None, "receipt_bytes": receipt_bytes,
                "scope_complete_for_local_processes": not self.remaining(),
                "gpu_accounting_qualified": False,
                "memory_scope": "cumulative owned job cgroup peak; conservative upper bound, not simultaneous child RSS"}


def command(c, scope, executable, args, directory):
    """Execute the already-open pinned inode, retain raw logs and deadline.

    Using /proc/self/fd with pass_fds binds exec to the verified opened inode.
    Both its bytes and metadata are rechecked after process join. This does not
    claim protection from a malicious owner modifying its own executable inode.
    """
    directory = Path(directory)
    directory.mkdir(exist_ok=False)
    path = pinned(executable)
    original(c)
    fd = os.open(path, os.O_RDONLY)
    start = time.monotonic_ns()
    initial = os.fstat(fd)
    intent = {"executable": executable, "argv": [str(path), *map(str, args)],
              "original_deadline_ns": c["original_deadline_ns"], "boot_id": boot(),
              "started_monotonic_ns": start, "cgroup": scope.relative,
              "exec_binding": "retained verified inode via inherited file descriptor",
              "device": initial.st_dev, "inode": initial.st_ino}
    write_new(directory / "intent.json", intent)
    child = None
    try:
        env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}
        with (directory / "stdout.log").open("xb") as out, (directory / "stderr.log").open("xb") as err:
            child = subprocess.Popen([f"/proc/self/fd/{fd}", *map(str, args)], executable=f"/proc/self/fd/{fd}",
                                     pass_fds=(fd,), stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                     cwd=c["repo"], env=env, start_new_session=True)
            while child.poll() is None:
                original(c)
                time.sleep(.05)
            code = child.wait()
        require(scope.wait_empty(c["original_deadline_ns"]), "owned command descendants not terminal")
        require(code == 0, "owned command failed: " + str(code))
        original(c)
        final = os.fstat(fd)
        require((initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns)
                == (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns),
                "executed inode metadata changed")
        require(sha(f"/proc/self/fd/{fd}") == executable["sha256"], "executed inode changed")
        result = {**intent, "pid": child.pid, "returncode": code, "completed_monotonic_ns": time.monotonic_ns(),
                  "all_owned_descendants_terminal": True, "stage_process_complete": True,
                  "stdout_sha256": sha(directory / "stdout.log"), "stderr_sha256": sha(directory / "stderr.log")}
        write_new(directory / "result.json", result)
        return result
    except BaseException as exc:
        clean = scope.cleanup()
        if child is not None:
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                clean = False
        write_new(directory / "failure.json", {**intent, "error": f"{type(exc).__name__}: {exc}",
                  "cleanup_complete": clean, "complete_proof_claim": False,
                  "observed_monotonic_ns": time.monotonic_ns()})
        raise
    finally:
        os.close(fd)


def winner(c, scope):
    out = Path(c["out"])
    d = out / "native-winner"
    command(c, scope, c["native_winner"], [c["material"]["path"], c["expected_artifacts"]["path"],
            c["header_template"]["path"], d, c["original_deadline_ns"], c["original_boot_id"], c["max_attempts"]],
            out / "native-winner-process")
    report = obj(d / "result.json")
    require(report["schema"] == "TRNM-W1-NATIVE-WINNER2" and report["winner_observed"] is True
            and report["native_replay_verified"] is True and report["native_ticket_before_deadline"] is True
            and report["winner_saved_before_deadline"] is True, "actual complete native winner required")
    require(report["original_deadline_monotonic_ns"] == c["original_deadline_ns"]
            and report["original_deadline_boot_id"] == boot(), "winner original deadline changed")
    require(report["native_winner_monotonic_ns"] <= report["winner_saved_monotonic_ns"] < original(c), "winner event ordering")
    for name, key in (("input.bin", "input_sha256"), ("header.bin", "header_sha256"),
                      ("expected-artifacts.bin", "expected_artifacts_sha256")):
        require(sha(d / name) == report[key], "winner asset changed")
    require(report["expected_artifacts_sha256"] == c["expected_artifacts"]["sha256"], "independent artifacts changed")
    command(c, scope, c["verifier"], ["--native-once", d / "input.bin", d / "header.bin", d / "expected-artifacts.bin"],
            out / "native-independent-process")
    native = obj(out / "native-independent-process/stdout.log", 16384)
    require(native["schema"] == "TRNM-W1-V2-NATIVE-ONCE1" and native["iterations"] == 1
            and native["full_replay_calls"] == 1 and native["profile_id"] == c["profile_id"], "one complete native replay required")
    for key in ("input_sha256", "header_sha256", "expected_artifacts_sha256"):
        require(native[key] == report[key], "native independent statement mismatch")
    result = {"winner": report, "native": native}
    if c.get("provider", {}).get("kind") == "kaggle-cli":
        provider = c["provider"]
        source_path = out / "kaggle-worker-source.py"
        require(not source_path.exists(), "new immutable provider source required")
        argv = provider["source_builder_argv"]
        executable = {"path": argv[0], "sha256": provider["source_builder_file_pins"][argv[0]]}
        # Fixed positional builder contract, executed BEFORE statement lock:
        # [*prefix, WINNER_DIR, OUT_NEW_SOURCE, ORIGINAL_REQUEST_ID]. No submit.
        command(c, scope, executable, [*argv[1:], d, source_path, provider["request_id"]], out / "source-builder")
        contract = load_contract(c)
        raw = contract.normalized_source(source_path, "script")
        require(raw == source_path.read_bytes(), "builder must emit its exact fixed script bytes")
        intent = {"source_sha256": hashlib.sha256(raw).hexdigest(),
                  "timeout_seconds": provider["timeout_seconds"], "accelerator": provider["accelerator"],
                  "internet": provider["internet"], "kernel_type": "script", "language": "python",
                  "is_private": True, "dataset_sources": [], "kernel_sources": [],
                  "model_sources": [], "competition_sources": []}
        result["provider_selection"] = {"source": str(source_path), "intent": intent,
                                        "input_digest": contract.digest(intent), "request_id": provider["request_id"],
                                        "source_builder_process_result_sha256": sha(out / "source-builder/result.json")}
    result["scope"] = scope.costs()
    return result


def load_contract(c):
    path = Path(c["repo"]) / "scripts/kaggle_generation_contract_v2.py"
    require(c["source_files"].get("scripts/kaggle_generation_contract_v2.py") == sha(path), "provider contract source pin")
    spec = importlib.util.spec_from_file_location("owned_kaggle_contract_v2", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generate_kaggle(c, scope, request_path):
    """Execute the real normal-account CLI in the owner's actual host scope.

    Only controller clock readings enter the winner latency. Remote hard timeout
    is retained separately. Provider COMPLETE/artifact closure cannot qualify
    resources or authorize payment; the owner verifies raw receipt bytes later.
    """
    contract = load_contract(c)
    provider = c["provider"]
    out = Path(c["out"])
    request = obj(request_path, 131072)
    binding = request["binding"]
    chosen = obj(out / "winner-runtime-result.json")["provider_selection"]
    require(binding["intent"] == chosen["intent"] and binding["input_digest"] == chosen["input_digest"]
            and binding["request_id"] == chosen["request_id"] == provider["request_id"]
            and request["source"] == chosen["source"], "provider selection changed after statement lock")
    original_deadline = binding["original_controller_deadline"]
    require(original_deadline["deadline_ns"] == c["original_deadline_ns"], "owner original deadline changed")
    adapter = contract.AccountGuardedCliAdapter(provider["command_prefix"], provider["wrapper_sha256"],
        "qiqian", provider["account_username"], out / "provider-cli", c["original_deadline_ns"], c["original_boot_id"])
    target = contract.KaggleGenerationTargetV2(adapter, Path(c["target_root"]) / "kaggle-generation-v2.sqlite",
        lambda: {"clock_domain": load_target_clock(c), "now_ns": time.monotonic_ns()})
    # Existing outer target intents are reconciliation-only, even when their
    # upstream transport result was lost. This heavy entry never starts a retry.
    require(target.db.execute("SELECT count(*) FROM generation_targets WHERE operation=? OR task_scope=? OR request_id=?",
        (binding["operation"], binding["task_scope"], binding["request_id"])).fetchone() == (0,),
        "original funded provider operation already exists; observation-only recovery required")
    observed = None
    try:
        try:
            observed = target.dispatch(binding, request["source"], m12_new_intent=True)
            write_new(out / "provider-dispatch.json", observed)
        except Exception as exc:
            # Original adapter ledger and outer durable target preserve whether
            # submit may have happened. No second submit is permitted below.
            write_new(out / "provider-dispatch-unknown.json", {"error": f"{type(exc).__name__}: {exc}",
                "request_id": provider["request_id"], "may_dispatch_again": False})
        while observed is None or not observed["remote_terminal_observed"]:
            original(c)
            try:
                observed = target.reconcile(binding["operation"])
                write_new(out / ("provider-observation-" + str(time.monotonic_ns()) + ".json"), observed)
            except Exception as exc:
                write_new(out / ("provider-observation-unknown-" + str(time.monotonic_ns()) + ".json"),
                          {"error": f"{type(exc).__name__}: {exc}", "request_id": provider["request_id"],
                           "may_dispatch_again": False, "can_authorize_payment": False})
            if observed is None or not observed["remote_terminal_observed"]:
                time.sleep(min(5., max(0., (c["original_deadline_ns"] - time.monotonic_ns()) / 1e9)))
        require(observed["artifact_candidate"] and not observed["sticky_cancel"], "provider has no eligible COMPLETE artifacts")
        downloaded = adapter.artifacts(provider["request_id"], "w1-result-manifest.json", provider["artifacts_max_bytes"])
        write_new(out / "provider-download.json", downloaded)
        closure = contract.check_download(binding, observed["provider_receipt"], downloaded,
            downloaded["directory"], "w1-result-manifest.json", observed["identity"])
        write_new(out / "provider-artifact-closure.json", closure)
        artifact_root = Path(downloaded["directory"])
        worker = obj(artifact_root / "w1-result.json", 256 * 1024)
        require(worker["schema"] == provider["worker_report_schema"] and worker["request_id"] == provider["request_id"],
                "actual fixed worker report identity")
        native = obj(out / "native-winner/result.json")
        for key in ("input_sha256", "header_sha256", "expected_artifacts_sha256"):
            require(worker[key] == native[key], "worker executed a different native statement")
        require(worker["source_commit"] == c["expected_commit"] and worker["guest_sha256"] == c["guest"]["sha256"]
                and worker["image_id"] == c["image_id"], "worker source or guest changed")
        # The trusted fixed worker source must publish this actual raw full
        # controller result separately, covered by the provider manifest/HTTP
        # closure; a provider transport success string is insufficient.
        archive = artifact_root / complete_worker_archive(worker)
        controller = archive_object(archive, worker["controller_result_archive_member"], worker["controller_result_sha256"])
        complete_controller(controller)
        manifest = archive_object(archive, worker["prepare_manifest_archive_member"], worker["prepare_manifest_sha256"], 1024 * 1024)
        require(manifest["schema"] == "TRNM-W1-STAGED-PROOF2"
                and manifest["source_commit"] == c["expected_commit"]
                and manifest["input_sha256"] == native["input_sha256"]
                and manifest["guest_sha256"] == c["guest"]["sha256"] and manifest["image_id"] == c["image_id"],
                "worker actual complete execution manifest binding")
        receipt = artifact_root / "succinct.bin"
        require(worker["receipt_sha256"] == sha(receipt), "downloaded receipt bytes changed")
        cp = out / "proof/checkpoint"
        cp.mkdir(parents=True, exist_ok=False)
        # Copy bounded owned bytes to the final independent-verifier input. No
        # reused execution/segment archive is adopted by this owner pipeline.
        with receipt.open("rb") as src, (cp / "succinct.bin").open("xb") as dst:
            total = 0
            for block in iter(lambda: src.read(1024 * 1024), b""):
                total += len(block)
                require(total <= 64 * 1024 * 1024, "full receipt byte bound")
                dst.write(block)
            dst.flush(); os.fsync(dst.fileno())
        require(sha(cp / "succinct.bin") == worker["receipt_sha256"], "owner receipt custody hash")
        original(c)
        require(scope.wait_empty(c["original_deadline_ns"]), "local provider CLI descendants not terminal")
        identity = observed["identity"]
        job = {"job_id": f"{identity['notebook_ref']}@{identity['notebook_version']}/kernel/{identity['kernel_id']}/request/{identity['request_id']}",
               "identity": identity, "kernel_session_id": observed["provider_receipt"].get("kernel_session_id"),
               "provider_receipt": observed["provider_receipt"]}
        write_new(out / "target-original-job.json", job)
        return {"target_job": job, "target_terminal": observed, "manifest": manifest,
                "receipt_sha256": sha(cp / "succinct.bin"), "receipt_bytes": total,
                "fresh_trial_count": 1, "reused_segments": False,
                "freshness_authority": "original provider source/ref/version identity, fixed worker source, manifest and complete controller evidence",
                "remote_resource_scope_complete": False, "full_independent_verifier_still_required": True,
                "scope": scope.costs(total)}
    except BaseException:
        # Local durable veto is not a remote cancellation acknowledgement or a
        # release. The normal wrapper alone decides whether session is proven.
        try:
            cancelled = target.cancel(binding["operation"])
            write_new(out / "provider-cancel-observation.json", cancelled)
        except Exception as exc:
            write_new(out / "provider-cancel-unknown.json", {"error": f"{type(exc).__name__}: {exc}",
                "request_id": provider["request_id"], "may_release_resources": False,
                "can_authorize_payment": False, "may_dispatch_again": False})
        raise
    finally:
        target.db.close()


def load_target_clock(c):
    return hashlib.sha256(canonical({"schema": "trnm-w1-generation-posix-target-v2",
        "target_instance": c["target_instance"], "linux_boot_id": c["original_boot_id"]})).hexdigest()


def load_target(c):
    path = pinned(c["target"])
    spec = importlib.util.spec_from_file_location("owned_generation_target_v2", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generate(c, scope, request_path):
    target = load_target(c)
    request = target.load_request(request_path, c["target_instance"])
    require(request["cgroup_parent"] == str(scope.path) and request["containment"] == "cgroup-v2",
            "generation must enter the actual owned sub-cgroup")
    require(request["deadline_monotonic_ns"] == c["original_deadline_ns"], "target original deadline changed")
    cp = Path(c["out"]) / "proof/checkpoint"
    require(not cp.exists() and not cp.parent.exists(), "fresh proof output must not exist")
    args = SimpleNamespace(root=c["target_root"], target=c["target_instance"], request=str(request_path), operation=request["operation"])
    out = Path(c["out"])
    # Rust committed the M12 intent first; this second, target-wide fence is
    # shared across generation journals. A previous target intent is NEVER New.
    db, _ = target.open_db(args.root, args.target, True)
    require(db.execute("SELECT count(*) FROM operations WHERE operation=? OR task_scope=?",
                       (request["operation"], request["task_scope"])).fetchone() == (0,),
            "original target operation already exists; reconcile only, no redispatch")
    db.close()
    initial = target.dispatch(args)
    write_new(out / "target-dispatch.json", initial)
    db, _ = target.open_db(args.root, args.target, False)
    last_job = None
    try:
        while True:
            original(c)
            row = target.read_operation(db, request["operation"])
            if row["worker"] is not None and last_job is None:
                last_job = row["worker"]
                write_new(out / "target-original-job.json", last_job)
            if row["result"] is not None:
                break
            time.sleep(.2)
        require(scope.wait_empty(c["original_deadline_ns"]), "target worker/descendants still occupy owner scope")
        final = target.public_readback(db, request["operation"], args.target)
        write_new(out / "target-terminal-readback.json", final)
        result = final["result"]
        require(final["state"] == "terminal" and not final["sticky_cancel"]
                and result["all_owned_processes_terminal"] is True and result["command_success"] is True
                and result["exit_code"] == 0 and result["cause"] is None and result["error"] is None,
                "actual target has no terminal successful generation")
        require(last_job == final["worker"] and last_job == result["provider_job"], "provider job identity changed")
        controller = obj(out / "proof/controller/result.json")
        complete_controller(controller)
        require(controller["end_to_end_observation_complete"] is True, "local postwin receiver did not finish")
        manifest = obj(cp / "manifest.json")
        native = obj(out / "native-winner/result.json")
        require(manifest["schema"] == "TRNM-W1-STAGED-PROOF2" and manifest["source_commit"] == c["expected_commit"]
                and manifest["input_sha256"] == native["input_sha256"]
                and manifest["runner_sha256"] == c["runner"]["sha256"]
                and manifest["r0vm_sha256"] == c["r0vm"]["sha256"]
                and manifest["guest_sha256"] == c["guest"]["sha256"] and manifest["image_id"] == c["image_id"],
                "fresh execution manifest binding")
        segments = manifest["segments"]
        require(type(segments) is list and segments and [x["index"] for x in segments] == list(range(len(segments))),
                "ordered complete segment manifest")
        receipt = cp / "succinct.bin"
        require(receipt.is_file() and not receipt.is_symlink(), "fresh full receipt absent")
        original(c)
        return {"target_job": last_job, "target_terminal": final, "manifest": manifest,
                "receipt_sha256": sha(receipt), "receipt_bytes": receipt.stat().st_size,
                "fresh_trial_count": 1, "reused_segments": False,
                "full_independent_verifier_still_required": True, "scope": scope.costs(receipt.stat().st_size)}
    except BaseException:
        # Sticky local cancellation and original target identity survive errors.
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE operations SET cancel=1 WHERE operation=?", (request["operation"],))
            db.execute("COMMIT")
        finally:
            scope.cleanup()
        raise
    finally:
        db.close()


def verify(c, scope):
    out = Path(c["out"])
    receipt = out / "proof/checkpoint/succinct.bin"
    native = out / "native-winner"
    process = command(c, scope, c["verifier"], [receipt, native / "header.bin", native / "expected-artifacts.bin"],
                      out / "node-independent-verifier")
    report = obj(out / "node-independent-verifier/stdout.log", 16384)
    n = obj(out / "native-independent-process/stdout.log", 16384)
    require(report["schema"] == "TRNM-W1-V2-FULL-VERIFY1" and report["profile_id"] == c["profile_id"]
            and report["sdk"] == "3.0.6" and report["iterations"] == 1
            and report["image_id"] == c["image_id"] and report["receipt_sha256"] == sha(receipt)
            and report["receipt_bytes"] == receipt.stat().st_size
            and report["parent_eligibility_checked"] is False and report["admission_authorized"] is False,
            "actual fixed full verifier rejected its profile")
    for key in ("header_sha256", "expected_artifacts_sha256", "journal_sha256", "work_id"):
        require(report[key] == n[key], "actual full verifier binding differs from native statement")
    generation = obj(out / "generate-runtime-result.json")
    require(generation["receipt_sha256"] == report["receipt_sha256"], "receipt changed since fresh generation")
    return {"process": process, "verifier": report, "scope": scope.costs(),
            "full_proof_verified": True, "verified_monotonic_ns": time.monotonic_ns(),
            "can_authorize_payment": False, "reason": "GPU resource accounting remains unknown"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("phase", choices=("winner", "generate", "verify"))
    p.add_argument("--config", required=True)
    p.add_argument("--request")
    args = p.parse_args()
    c = obj(args.config, 131072)
    require(c["schema"] == "TRNM-W1-FUNDED-HEAVY-CONFIG2", "explicit heavy declaration required")
    original(c)
    before_source = source(c)
    scope = Scope(c)
    out = Path(c["out"])
    write_new(out / (args.phase + "-runtime-intent.json"),
              {"schema": SCHEMA, "phase": args.phase, "config_sha256": sha(args.config),
               "original_deadline_ns": c["original_deadline_ns"], "boot_id": boot(), "scope": scope.before,
               "source": before_source, "started_monotonic_ns": time.monotonic_ns()})
    try:
        if args.phase == "winner":
            result = winner(c, scope)
        elif args.phase == "generate":
            require(args.request is not None, "target request required")
            result = (generate_kaggle(c, scope, args.request)
                      if c.get("provider", {}).get("kind") == "kaggle-cli" else generate(c, scope, args.request))
        else:
            result = verify(c, scope)
        require(source(c) == before_source, "source changed during owned operation")
        original(c)
        result.update(schema=SCHEMA, phase=args.phase, operation_complete=True,
                      config_sha256=sha(args.config), completed_monotonic_ns=time.monotonic_ns(),
                      original_deadline_ns=c["original_deadline_ns"], boot_id=boot(),
                      can_authorize_payment=False)
        write_new(out / (args.phase + "-runtime-result.json"), result)
        print(json.dumps({"schema": SCHEMA, "phase": args.phase, "operation_complete": True,
                          "can_authorize_payment": False}))
    except BaseException as exc:
        clean = scope.cleanup()
        write_new(out / (args.phase + "-runtime-failure.json"),
                  {"schema": SCHEMA, "phase": args.phase, "operation_complete": False,
                   "original_deadline_ns": c["original_deadline_ns"], "boot_id": boot(),
                   "error": f"{type(exc).__name__}: {exc}", "cleanup_complete": clean,
                   "can_authorize_payment": False, "may_dispatch_again": False})
        raise


if __name__ == "__main__":
    main()
