#!/usr/bin/env python3
"""Fixed CPU-profile W1 research worker; the source builder supplies main(config).

This file deliberately has no automatic entry point. A provider result is an
observation, not a Node payment, consensus admission, GPU measurement or deadline
translation. The owner must verify the returned receipt and its original fence.
"""

import base64
import ctypes
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback
import urllib.request
import uuid

CONFIG_SCHEMA = "TRNM-W1-KAGGLE-WORKER-CONFIG1"
RESULT_SCHEMA = "TRNM-W1-KAGGLE-WORKER-RESULT1"
REPO_URL = "https://github.com/TrillionniumFoundation/Trillionnium-Chain.git"
GUEST_SHA = "25718312ec3c6f5219d832e3516adfb5f82983156f669c5e7daa15bd22d1798f"
IMAGE_ID = [1958252411, 3287394615, 1805488136, 1516578702,
            78549041, 790278610, 301018785, 4279049364]
BUNDLE_URL = "https://github.com/risc0/risc0/releases/download/v3.0.3/cargo-risczero-x86_64-unknown-linux-gnu.tgz"
BUNDLE_SHA = "71a0adaa64235be13e9b8471bea5c4ded64bf97c6bd1eb9c2285b966c0b62fee"
R0VM_SHA = "2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6"
MAX_PROOF = 16 * 1024 * 1024
MAX_REPORT = 256 * 1024
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_RAW_TOTAL = 512 * 1024 * 1024
MAX_RAW_FILE = 64 * 1024 * 1024
TEMPLATE_PATH = "scripts/w1_kaggle_worker_template.py"
OWNER_TIME_KEYS = {"original_deadline_monotonic_ns", "original_deadline_boot_id",
                   "native_winner_monotonic_ns", "winner_saved_monotonic_ns"}
CONFIG_KEYS = {"schema", "request_id", "repo_url", "source_commit", "source_tree", "template_sha256",
               "input_b64", "input_sha256", "header_b64", "header_sha256", "expected_artifacts_b64",
               "expected_artifacts_sha256", "guest_sha256", "image_id", "r0vm_bundle_url",
               "r0vm_bundle_sha256", "r0vm_sha256", "segment_workers", "compression_mode",
               "compression_workers", "rayon_threads", "worker_wall_seconds", "owner_deadline_provenance",
               "prover_profile", "cuda_required"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def strict_json(data):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result

    def invalid(value):
        raise ValueError("nonfinite JSON: " + value)

    def finite(value):
        number = float(value)
        require(math.isfinite(number), "nonfinite JSON number")
        return number

    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid, parse_float=finite)


def checked_hex(value, length):
    require(type(value) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None,
            "noncanonical hexadecimal identity")
    return value


def validate_config(config):
    require(type(config) is dict and set(config) == CONFIG_KEYS, "unexpected worker configuration keys")
    require(config["schema"] == CONFIG_SCHEMA, "wrong worker configuration schema")
    require(type(config["request_id"]) is str and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,95}", config["request_id"]),
            "invalid provider request identity")
    require(config["repo_url"] == REPO_URL, "repository is outside the fixed research profile")
    for key in ("source_commit", "source_tree"):
        checked_hex(config[key], 40)
    for key in ("template_sha256", "input_sha256", "header_sha256", "expected_artifacts_sha256",
                "guest_sha256", "r0vm_bundle_sha256", "r0vm_sha256"):
        checked_hex(config[key], 64)
    require(config["guest_sha256"] == GUEST_SHA, "retained guest identity differs")
    require(type(config["image_id"]) is list and len(config["image_id"]) == 8
            and all(type(value) is int for value in config["image_id"]) and config["image_id"] == IMAGE_ID,
            "independent v2 image identity differs")
    require(config["r0vm_bundle_url"] == BUNDLE_URL and config["r0vm_bundle_sha256"] == BUNDLE_SHA
            and config["r0vm_sha256"] == R0VM_SHA, "fixed CPU prover supply identity differs")
    require(config["prover_profile"] == "cpu-fixed-v3.0.3" and config["cuda_required"] is False,
            "this template implements only the explicitly declared CPU profile")
    for key in ("segment_workers", "compression_workers", "rayon_threads"):
        require(type(config[key]) is int and 1 <= config[key] <= 4, "invalid four-CPU resource plan")
    require(max(config["segment_workers"], config["compression_workers"]) * config["rayon_threads"] <= 4,
            "worker plan exceeds the four-CPU study declaration")
    require(config["compression_mode"] in ("sequential", "balanced"), "unknown compression schedule")
    require(config["compression_mode"] != "sequential" or config["compression_workers"] == 1,
            "sequential compression has exactly one worker")
    require(type(config["worker_wall_seconds"]) is int and 60 <= config["worker_wall_seconds"] <= 7200,
            "worker wall budget must be an integer in [60,7200]")
    provenance = config["owner_deadline_provenance"]
    require(type(provenance) is dict and set(provenance) == OWNER_TIME_KEYS, "wrong opaque owner-time schema")
    for key in OWNER_TIME_KEYS - {"original_deadline_boot_id"}:
        require(type(provenance[key]) is int and 0 <= provenance[key] < 2**64, "invalid original owner integer clock")
    boot = provenance["original_deadline_boot_id"]
    require(type(boot) is str and str(uuid.UUID(boot)) == boot, "invalid original owner boot identity")
    decoded = {}
    for name, length in (("input", 49506), ("header", 318), ("expected_artifacts", 64)):
        value = config[name + "_b64"]
        require(type(value) is str and len(value) <= 70000, "invalid bounded base64 input")
        raw = base64.b64decode(value, validate=True)
        require(base64.b64encode(raw).decode() == value and len(raw) == length, "noncanonical input or wrong byte length")
        require(hashlib.sha256(raw).hexdigest() == config[name + "_sha256"], "input digest differs: " + name)
        decoded[name] = raw
    require(decoded["input"][:318] == decoded["header"], "winner header and complete input differ")
    return decoded


def same_file_stat(before, after):
    return (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)


def file_info(path, limit=MAX_RAW_TOTAL):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_size <= limit, "not a bounded ordinary file: " + str(path))
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        require(same_file_stat(before, os.fstat(stream.fileno())), "file identity changed before read")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
        require(same_file_stat(before, os.fstat(stream.fileno())), "file changed during read")
    require(same_file_stat(before, path.lstat()), "file path changed during read")
    return {"bytes": before.st_size, "sha256": digest.hexdigest()}


def read_json_file(path, limit=4 * 1024 * 1024):
    before = file_info(path, limit)
    value = strict_json(path.read_bytes())
    require(file_info(path, limit) == before, "JSON changed during parsing")
    return value


def write_new(path, data):
    raw = data if isinstance(data, bytes) else canonical(data)
    with path.open("xb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    require(file_info(path)["sha256"] == hashlib.sha256(raw).hexdigest(), "new file readback differs")


def resources():
    result = {"affinity": sorted(os.sched_getaffinity(0)), "resource_completeness_established": False,
              "gpu_ns": None, "aggregate_process_tree_peak_rss_bytes": None}
    for name in ("/proc/self/cgroup", "/sys/fs/cgroup/cpu.max", "/sys/fs/cgroup/memory.max",
                 "/sys/fs/cgroup/memory.peak", "/sys/fs/cgroup/cpu.stat"):
        try:
            result[name] = Path(name).read_text()[:16384]
        except OSError as error:
            result[name] = {"unknown": type(error).__name__ + ": " + str(error)}
    return result


def proc_rows():
    # This supervisor uses /proc numeric identities for kill(2). A procfs mounted
    # from a different PID namespace is not silently interpreted as local PIDs.
    own_stat = Path("/proc/self/stat").read_text()
    require(int(own_stat.split("(", 1)[0].strip()) == os.getpid(),
            "procfs and worker PID namespaces differ; descendant control is unknown")
    rows, errors = {}, []
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            text = (path / "stat").read_text()
            fields = text[text.rindex(")") + 2:].split()
            rows[int(path.name)] = {"pid": int(path.name), "parent": int(fields[1]), "state": fields[0],
                                    "birth": int(fields[19]), "group": int(fields[2]), "session": int(fields[3])}
        except (FileNotFoundError, ProcessLookupError):
            pass
        except Exception as error:
            errors.append({"pid": int(path.name), "error": type(error).__name__ + ": " + str(error)})
    return rows, errors


class Budget:
    def __init__(self, seconds):
        self.started_ns = time.monotonic_ns()
        self.deadline_ns = self.started_ns + seconds * 1_000_000_000
        self.cancellation = None

    def signal(self, signum, _frame):
        if self.cancellation is None:
            self.cancellation = {"signal": int(signum), "monotonic_ns": time.monotonic_ns()}

    def check(self):
        require(self.cancellation is None, "worker cancellation observed")
        require(time.monotonic_ns() < self.deadline_ns, "worker deadline exhausted")


class Commands:
    """Reap this worker's own descendants; observations do not certify all resource use."""

    def __init__(self, logs, budget, env):
        self.logs, self.budget, self.env, self.rows = logs, budget, env, []
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.old_subreaper = ctypes.c_int()
        require(self.libc.prctl(37, ctypes.byref(self.old_subreaper), 0, 0, 0) == 0, "cannot observe child-subreaper state")
        require(self.libc.prctl(36, 1, 0, 0, 0) == 0, "cannot own orphaned task descendants")
        before, errors = proc_rows()
        require(not errors, "initial process membership is unknown")
        self.preexisting = {(pid, row["birth"]) for pid, row in before.items() if row["parent"] == os.getpid()}

    def close(self):
        require(self.libc.prctl(36, self.old_subreaper.value, 0, 0, 0) == 0, "cannot restore child-subreaper state")

    def run(self, label, argv, cwd, allow_failure=False):
        self.budget.check()
        require(re.fullmatch(r"[a-z0-9-]+", label) is not None, "invalid command label")
        argv = list(map(str, argv))
        write_new(self.logs / (label + ".command.json"), {"argv": argv, "cwd": str(cwd)})
        row = {"label": label, "argv": argv, "started_monotonic_ns": time.monotonic_ns(), "returncode": None,
               "cleanup_complete": False, "process_scan_errors": [], "signal_attempts": [], "adopted_reaped": [],
               "termination_reasons": [], "result_is_pre_handoff_snapshot": True}
        self.rows.append(row)
        owned = {}

        def observe(root_pid):
            table, errors = proc_rows()
            row["process_scan_errors"].extend(errors)
            found = {root_pid}
            changed = True
            while changed:
                changed = False
                for pid, current in table.items():
                    key = (pid, current["birth"])
                    if key in self.preexisting:
                        continue
                    if current["parent"] in found or current["parent"] == os.getpid() or key in owned:
                        if pid not in found:
                            found.add(pid); changed = True
                        owned[key] = current
            return [table[pid] for pid, birth in owned if pid in table and table[pid]["birth"] == birth]

        def send(members, signum):
            current, errors = proc_rows()
            row["process_scan_errors"].extend(errors)
            for member in members:
                pid = member["pid"]
                if pid not in current or current[pid]["birth"] != member["birth"]:
                    continue
                try:
                    os.kill(pid, signum)
                    outcome = "SENT"
                except ProcessLookupError:
                    outcome = "ALREADY_ABSENT"
                except OSError as error:
                    outcome = "UNKNOWN:" + type(error).__name__
                row["signal_attempts"].append({"pid": pid, "birth": member["birth"], "signal": int(signum), "outcome": outcome})

        print(json.dumps({"starting": label}), flush=True)
        with (self.logs / (label + ".stdout")).open("xb") as stdout, (self.logs / (label + ".stderr")).open("xb") as stderr:
            process = subprocess.Popen(argv, cwd=cwd, env=self.env, stdin=subprocess.DEVNULL, stdout=stdout,
                                       stderr=stderr, start_new_session=True)
            row["pid"] = process.pid
            try:
                while process.poll() is None:
                    members = observe(process.pid)
                    stopped = self.budget.cancellation is not None or time.monotonic_ns() >= self.budget.deadline_ns
                    oversized = max(os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size) > MAX_RAW_FILE
                    if stopped or oversized or row["process_scan_errors"]:
                        row["termination_reasons"].append("CANCELLED_OR_DEADLINE" if stopped else "OUTPUT_OR_PROCESS_STATE_UNKNOWN")
                        roots = [member for member in members if member["pid"] == process.pid]
                        send(roots or members, signal.SIGTERM)
                        settlement = time.monotonic() + 15
                        while process.poll() is None and time.monotonic() < settlement:
                            observe(process.pid); time.sleep(0.05)
                        break
                    time.sleep(0.1)
            finally:
                members = observe(process.pid)
                live = [member for member in members if member["state"] != "Z"]
                if process.poll() is None or live:
                    row["termination_reasons"].append("OWNED_DESCENDANTS_REQUIRED_CLEANUP")
                    send(live, signal.SIGKILL)
                if process.poll() is None:
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        row["termination_reasons"].append("UNREAPED_DIRECT_CHILD")
                row["returncode"] = process.returncode
                settle = time.monotonic() + 2
                while time.monotonic() < settle:
                    if process.returncode is not None:
                        current, errors = proc_rows()
                        row["process_scan_errors"].extend(errors)
                        for owned_pid, birth in list(owned):
                            if owned_pid == process.pid or owned_pid not in current or current[owned_pid]["birth"] != birth:
                                continue
                            try:
                                pid, status, usage = os.wait4(owned_pid, os.WNOHANG)
                            except ChildProcessError:
                                continue
                            if pid:
                                row["adopted_reaped"].append({"pid": pid, "status": status,
                                                             "user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime})
                    remaining = observe(process.pid)
                    if not remaining:
                        break
                    send([member for member in remaining if member["state"] != "Z"], signal.SIGKILL)
                    time.sleep(0.05)
                row["final_owned_members"] = observe(process.pid)
                row["cleanup_complete"] = process.returncode is not None and not row["final_owned_members"] and not row["process_scan_errors"]
                row["finished_monotonic_ns"] = time.monotonic_ns()
                row["cancellation"] = self.budget.cancellation
                stdout.flush(); stderr.flush(); os.fsync(stdout.fileno()); os.fsync(stderr.fileno())
        for kind in ("stdout", "stderr"):
            path = self.logs / (label + "." + kind)
            row[kind] = {"path": path.name, **file_info(path)}
        write_new(self.logs / (label + ".result.json"), row)
        self.budget.check()
        require(row["cleanup_complete"] and not row["termination_reasons"], "command settlement incomplete: " + label)
        require(allow_failure or row["returncode"] == 0, "command failed: " + label + ", exit=" + str(row["returncode"]))
        return (self.logs / (label + ".stdout")).read_text(errors="strict")


def download(url, destination, digest, limit, budget):
    budget.check()
    accepted = ("https://static.rust-lang.org/", BUNDLE_URL)
    require(url.startswith(accepted), "download outside fixed public tool sources")
    count, hasher = 0, hashlib.sha256()
    with urllib.request.urlopen(url, timeout=30) as response, destination.open("xb") as stream:
        while True:
            budget.check()
            block = response.read(1024 * 1024)
            if not block:
                break
            count += len(block); require(count <= limit, "download exceeds bound")
            stream.write(block); hasher.update(block)
        stream.flush(); os.fsync(stream.fileno())
    require(digest is None or hasher.hexdigest() == digest, "fixed download digest differs")
    return {"url": url, "final_url": response.geturl(), "bytes": count, "sha256": hasher.hexdigest()}


def setup_rust(task, commands):
    url = "https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init"
    checksum = task / "rustup-init.sha256"
    declaration = download(url + ".sha256", checksum, None, 4096, commands.budget)
    digest = checked_hex(checksum.read_text().split()[0], 64)
    installer = task / "rustup-init"
    declaration["installer"] = download(url, installer, digest, 32 * 1024 * 1024, commands.budget)
    write_new(commands.logs / "rust-installer.json", declaration)
    installer.chmod(0o700)
    commands.run("install-rust-195", [installer, "-y", "--no-modify-path", "--profile", "minimal", "--default-toolchain", "1.95.0"], task)
    binaries = task / "rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin"
    commands.env["RUSTC"] = str(binaries / "rustc")
    commands.env["RUSTDOC"] = str(binaries / "rustdoc")
    commands.env["PATH"] = str(binaries) + ":" + commands.env["PATH"]
    version = commands.run("rustc-version", [binaries / "rustc", "--version", "--verbose"], task)
    require(version.startswith("rustc 1.95.0 "), "toolchain version differs")
    commands.run("cargo-version", [binaries / "cargo", "--version", "--verbose"], task)
    return binaries / "cargo"


def extract_fixed_r0vm(bundle, destination):
    require(file_info(bundle, 100 * 1024 * 1024)["sha256"] == BUNDLE_SHA, "official bundle hash differs")
    seen = set()
    with tarfile.open(bundle, "r:gz") as archive:
        for member in archive:
            require(member.name in ("r0vm", "cargo-risczero") and member.name not in seen and member.isfile(),
                    "unexpected official bundle member")
            require(0 < member.size <= MAX_RAW_TOTAL, "official executable size exceeds bound")
            seen.add(member.name)
            if member.name == "r0vm":
                with archive.extractfile(member) as source, destination.open("xb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
                    output.flush(); os.fsync(output.fileno())
    require(seen == {"r0vm", "cargo-risczero"}, "incomplete official release bundle")
    require(file_info(destination)["sha256"] == R0VM_SHA, "actual r0vm does not match the original fixed CPU pin")
    destination.chmod(0o500)


def validate_controller(row):
    require(type(row) is dict and row.get("schema") == "TRNM-W1-COMPLETE-STAGED-RUN3", "wrong complete controller schema")
    require(row.get("complete_proof_claim") is True and row.get("end_to_end_observation_complete") is True,
            "controller did not complete proof and operation")
    require(row.get("error") is None and row.get("controller_canceled_signal") is None
            and row.get("controller_cancellation_event") is None and row.get("deadline_exhausted_at_snapshot") is False,
            "controller cancellation, error or expiry veto")
    require(row.get("fresh_preparation_included") is True and row.get("prior_runs") == []
            and row.get("prior_bounded_wall_seconds") == 0 and row.get("unretained_stage_labels") == [],
            "fresh execution or retained dispatch closure is missing")
    stages = row.get("stages")
    require(type(stages) is list and stages and stages[0].get("stage") == "prepare-full-execution", "fresh prepare is not first")
    labels = [entry.get("stage") for entry in stages]
    require(all(type(label) is str for label in labels) and len(labels) == len(set(labels))
            and row.get("stage_dispatch_attempts") == labels, "stage ordering or retained dispatch differs")
    for needed in ("reverify-existing-prefix", "complete-recursive-compression", "fresh-process-strict-verification"):
        require(needed in labels, "required full pipeline stage missing: " + needed)
    for entry in stages:
        result = entry.get("result")
        require(type(result) is dict and result.get("schema") == "TRNM-W1-STAGE-MEASUREMENT3", "wrong actual stage schema")
        require(result.get("stage_process_complete") is True and type(result.get("returncode")) is int
                and result["returncode"] == 0 and result.get("completion_observed_before_deadline") is True,
                "actual stage failed or was late")
        require(result.get("error") is None and result.get("canceled_signal") is None
                and result.get("cancellation_event") is None and result.get("deadline_exhausted_at_snapshot") is False,
                "stage cancellation/error/expiry veto")
        require(result.get("termination_reasons") == [] and result.get("cleanup_errors") == []
                and result.get("proc_scan_errors") == [] and result.get("group_probe_errors") == []
                and result.get("owned_session_observation_complete") is True
                and result.get("final_owned_session_members") == [], "stage cleanup is incomplete or unknown")
    return labels


def validate_prepared(manifest, config, runner_sha):
    fields = {"schema", "source_commit", "runner_sha256", "guest_sha256", "image_id", "r0vm_sha256",
              "input_sha256", "journal_sha256", "full_claim_digest", "segment_limit_po2", "segments"}
    require(type(manifest) is dict and set(manifest) == fields and manifest["schema"] == "TRNM-W1-STAGED-PROOF2",
            "wrong exact prepared v2 manifest")
    for field in ("source_commit", "input_sha256", "guest_sha256", "image_id", "r0vm_sha256"):
        require(manifest[field] == config[field], "prepared identity differs: " + field)
    require(manifest["runner_sha256"] == runner_sha and type(manifest["segment_limit_po2"]) is int
            and manifest["segment_limit_po2"] == 18, "prepared runner or segment limit differs")
    segments = manifest["segments"]
    require(type(segments) is list and len(segments) == 43, "this study requires all 43 complete-execution segments")
    for index, segment in enumerate(segments):
        require(type(segment) is dict and set(segment) == {"index", "po2", "cycles", "bytes", "sha256"}, "wrong segment asset schema")
        require(type(segment["index"]) is int and segment["index"] == index, "noncanonical full segment order")
        require(all(type(segment[key]) is int and segment[key] > 0 for key in ("po2", "cycles", "bytes"))
                and segment["po2"] <= 18 and segment["bytes"] <= MAX_RAW_FILE, "invalid complete segment asset bounds")
        checked_hex(segment["sha256"], 64)


class HashReader:
    def __init__(self, stream):
        self.stream, self.digest, self.count = stream, hashlib.sha256(), 0

    def read(self, amount):
        block = self.stream.read(amount); self.digest.update(block); self.count += len(block)
        return block


def archive_raw(roots, destination):
    """Explicit roots only. Never follow links, import receipts or archive a build tree."""
    require(not destination.exists(), "refusing archive overwrite")
    entries = []
    for prefix, root in roots:
        require(re.fullmatch(r"[a-z][a-z0-9-]*", prefix) is not None, "invalid archive prefix")
        require(root.is_dir() and not root.is_symlink(), "invalid archive root")
        require(not destination.resolve().is_relative_to(root.resolve()), "archive output is inside an input root")
        for path in sorted(root.rglob("*")):
            if path.is_dir() and not path.is_symlink():
                continue
            before = path.lstat()
            require(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_RAW_TOTAL, "nonordinary or oversized raw observation")
            entries.append((prefix + "/" + path.relative_to(root).as_posix(), path, before))
    require(len(entries) <= 4096 and len({name for name, _, _ in entries}) == len(entries), "raw archive member bound or collision")
    require(sum(before.st_size for _, _, before in entries) <= MAX_RAW_TOTAL, "raw archive logical bound exceeded")
    index = []
    with destination.open("xb") as output:
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                for name, path, before in sorted(entries):
                    info = tarfile.TarInfo(name); info.size = before.st_size; info.mode = 0o444; info.mtime = 0
                    info.uid = info.gid = 0; info.uname = info.gname = ""
                    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                    with os.fdopen(descriptor, "rb") as stream:
                        require(same_file_stat(before, os.fstat(stream.fileno())), "raw file changed before archive read")
                        reader = HashReader(stream); archive.addfile(info, reader)
                        require(reader.count == before.st_size and same_file_stat(before, os.fstat(stream.fileno())),
                                "raw file changed during archive read")
                    require(same_file_stat(before, path.lstat()), "raw pathname changed during archive read")
                    index.append({"path": name, "bytes": before.st_size, "sha256": reader.digest.hexdigest()})
                encoded_index = canonical(index)
                info = tarfile.TarInfo("member-index.json"); info.size = len(encoded_index); info.mode = 0o444; info.mtime = 0
                info.uid = info.gid = 0; info.uname = info.gname = ""
                archive.addfile(info, io.BytesIO(encoded_index))
        output.flush(); os.fsync(output.fileno())
    require(destination.stat().st_size <= MAX_ARCHIVE, "compressed raw archive bound exceeded")
    return index


def main(config):
    decoded = validate_config(config)
    budget = Budget(config["worker_wall_seconds"])
    task = Path(tempfile.mkdtemp(prefix="trnm-w1-" + config["request_id"] + "-", dir="/tmp"))
    logs = task / "worker"; logs.mkdir()
    inputs = task / "inputs"; inputs.mkdir()
    copied_checkpoint = task / "checkpoint-observations"; copied_checkpoint.mkdir()
    working = Path("/kaggle/working"); working.mkdir(parents=True, exist_ok=True)
    for name in ("succinct.bin", "w1-result.json", "w1-raw-logs.tar.gz", "w1-result-manifest.json"):
        require(not os.path.lexists(working / name), "refusing existing output: " + name)
    saved_signals = {signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    for signum in saved_signals:
        signal.signal(signum, budget.signal)
    report = {"schema": RESULT_SCHEMA, "request_id": config["request_id"], "source_commit": config["source_commit"],
              "source_tree": config["source_tree"], "input_sha256": config["input_sha256"],
              "header_sha256": config["header_sha256"], "expected_artifacts_sha256": config["expected_artifacts_sha256"],
              "guest_sha256": GUEST_SHA, "image_id": IMAGE_ID, "receipt_sha256": None, "outcome": "failed",
              "template_sha256": config["template_sha256"], "config_sha256": hashlib.sha256(canonical(config)).hexdigest(),
              "prover_profile": "cpu-fixed-v3.0.3", "cuda_required": False, "gpu_acceleration_claimed": False,
              "gpu_usage_observed": None, "gpu_ns": None, "resource_completeness_established": False,
              "owner_deadline_provenance": config["owner_deadline_provenance"],
              "owner_clock_translation_performed": False, "worker_started_monotonic_ns": budget.started_ns,
              "worker_deadline_monotonic_ns": budget.deadline_ns, "worker_wall_seconds": config["worker_wall_seconds"],
              "raw_archive_name": "w1-raw-logs.tar.gz", "controller_result_archive_member": None,
              "controller_result_sha256": None, "prepare_manifest_archive_member": None, "prepare_manifest_sha256": None,
              "complete_proof_claim": False, "fresh_generation_observed": False, "error": None, "publication_errors": [],
              "result_is_pre_handoff_snapshot": True, "provider_successful_process_exit_required": True,
              "payment_authorized": False, "consensus_admission": False, "production_qualification": False,
              "guest_compilation_performed": False, "resource_before": resources(), "commands": []}
    env = os.environ.copy()
    forbidden = [key for key in env if key in ("RISC0_DEV_MODE", "RISC0_SKIP_BUILD", "RISC0_SKIP_BUILD_KERNELS",
                                               "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS")]
    env.update({"RUSTUP_HOME": str(task / "rustup"), "CARGO_HOME": str(task / "cargo"), "RISC0_HOME": str(task / "risc0"),
                "XDG_CACHE_HOME": str(task / "cache"), "RUSTUP_TOOLCHAIN": "1.95.0", "CARGO_TARGET_DIR": str(task / "target"),
                "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0", "PYTHONDONTWRITEBYTECODE": "1",
                "RAYON_NUM_THREADS": str(config["rayon_threads"])})
    commands = None
    controller_out, checkpoint = task / "controller", task / "fresh-checkpoint"
    try:
        require(not forbidden, "unexpected proof/build override keys: " + ",".join(forbidden))
        require(len(os.sched_getaffinity(0)) <= 4, "provider affinity exceeds the four-CPU study declaration")
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        require(str(uuid.UUID(boot)) == boot, "worker local boot identity unavailable")
        report["worker_boot_id"] = boot
        write_new(logs / "config.json", config)
        for name, raw in decoded.items():
            write_new(inputs / (name + ".bin"), raw)
        commands = Commands(logs, budget, env); report["commands"] = commands.rows
        repo = task / "repo"; repo.mkdir()
        commands.run("git-init", ["git", "init", "--quiet"], repo)
        commands.run("git-origin", ["git", "remote", "add", "origin", REPO_URL], repo)
        commands.run("git-fetch-fixed", ["git", "-c", "protocol.version=2", "fetch", "--depth=1", "--no-tags", "origin", config["source_commit"]], repo)
        branch = "fix/w1-kaggle-" + hashlib.sha256(config["request_id"].encode()).hexdigest()[:16]
        commands.run("git-checkout-fixed", ["git", "checkout", "-b", branch, config["source_commit"]], repo)
        require(commands.run("source-head", ["git", "rev-parse", "HEAD"], repo).strip() == config["source_commit"], "checked-out commit differs")
        require(commands.run("source-tree", ["git", "rev-parse", "HEAD^{tree}"], repo).strip() == config["source_tree"], "checked-out tree differs")
        require(file_info(repo / TEMPLATE_PATH, 1024 * 1024)["sha256"] == config["template_sha256"], "committed template differs")
        source_check = [sys.executable, "scripts/ci/verify_ci_source.py", "--kind", "head", "--expected-head", config["source_commit"]]
        commands.run("source-exact-before", [*source_check, "--output", logs / "source-before.json"], repo)
        require(read_json_file(logs / "source-before.json")["tested_tree"] == config["source_tree"], "raw verified tree differs")
        commands.run("project-preflight", ["bash", "scripts/project-preflight.sh", "--dev"], repo)
        retained = repo / "evidence/pon-w1-full-v2-20261105/guest.bin"
        require(file_info(retained) == {"bytes": 375928, "sha256": GUEST_SHA}, "original retained guest bytes differ")
        cargo = setup_rust(task, commands)
        bundle = task / "r0vm-official.tgz"
        report["r0vm_bundle"] = download(BUNDLE_URL, bundle, BUNDLE_SHA, 100 * 1024 * 1024, budget)
        r0vm = task / "r0vm"; extract_fixed_r0vm(bundle, r0vm)
        report["r0vm"] = {**file_info(r0vm), "version_output": commands.run("r0vm-version", [r0vm, "--version"], task),
                          "build_feature_declaration": "official v3.0.3 release uses the default CPU build; no CUDA feature enabled",
                          "gpu_runtime_measurement": None}
        manifest_path = "formal/pon-nakamoto-v1/w1_zkvm/Cargo.toml"
        commands.run("host-locked-metadata", [cargo, "metadata", "--manifest-path", manifest_path, "--locked", "--format-version", "1", "--features", "trnm-w1-zk-host-v2/retained-v2-guest"], repo)
        commands.run("host-retained-build", [cargo, "build", "--release", "--locked", "--manifest-path", manifest_path,
                                             "-p", "trnm-w1-zk-host-v2", "--bin", "w1-staged-prover-v2", "--features", "retained-v2-guest"], repo)
        commands.run("strict-verifier-build", [cargo, "build", "--release", "--locked", "--manifest-path",
                                               "formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.toml", "--bin", "w1-verify-v2"], repo)
        runner, verifier = task / "target/release/w1-staged-prover-v2", task / "target/release/w1-verify-v2"
        report["runner"] = file_info(runner); report["independent_verifier"] = file_info(verifier)
        require(not checkpoint.exists() and not controller_out.exists(), "fresh task namespace was reused")
        local_deadline = math.nextafter(budget.deadline_ns / 1e9, -math.inf)
        command = [sys.executable, "formal/pon-nakamoto-v1/experiments/w1_full_staged_run.py",
                   "--runner", runner, "--r0vm", r0vm, "--checkpoint", checkpoint, "--out", controller_out,
                   "--prepare-input", inputs / "input.bin", "--statement-version", "2", "--fresh-verifier", verifier,
                   "--native-verifier", verifier, "--expected-artifacts", inputs / "expected_artifacts.bin",
                   "--total-wall-seconds", str(config["worker_wall_seconds"]), "--deadline-monotonic", repr(local_deadline),
                   "--deadline-boot-id", boot, "--segment-workers", str(config["segment_workers"]),
                   "--compression-mode", config["compression_mode"], "--compression-workers", str(config["compression_workers"]),
                   "--rayon-threads", str(config["rayon_threads"])]
        commands.run("full-fresh-controller", command, repo)
        controller = read_json_file(controller_out / "result.json")
        report["completed_stage_labels"] = validate_controller(controller)
        require(not list(controller_out.rglob("cancellation.json")), "post-snapshot cancellation sidecar veto")
        prepared = read_json_file(checkpoint / "manifest.json")
        validate_prepared(prepared, config, report["runner"]["sha256"])
        require(all((checkpoint / ("receipt-" + str(index).zfill(4) + ".bin")).is_file() for index in range(43)),
                "complete canonical segment receipts missing")
        require(file_info(checkpoint / "input.bin")["sha256"] == config["input_sha256"]
                and file_info(checkpoint / "header.bin")["sha256"] == config["header_sha256"], "prepared winner bytes differ")
        receipt = checkpoint / "succinct.bin"
        info = file_info(receipt, MAX_PROOF); require(info["bytes"] > 0, "empty complete receipt")
        require(controller.get("identity", {}).get("receipt_sha256") == info["sha256"], "controller receipt identity differs")
        require(controller.get("expected_artifacts_sha256") == config["expected_artifacts_sha256"], "controller independent commitments differ")
        commands.run("source-exact-after", [*source_check, "--output", logs / "source-after.json"], repo)
        require(read_json_file(logs / "source-after.json")["tested_tree"] == config["source_tree"], "post-build verified source tree differs")
        budget.check()
        report["complete_proof_claim"] = True
        report["fresh_generation_observed"] = True
        report["segment_count"] = 43
        report["receipt_sha256"] = info["sha256"]
        report["outcome"] = "verified"
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "message": str(error), "traceback": traceback.format_exc()}
        report["outcome"] = "cancelled" if budget.cancellation else ("timed_out" if time.monotonic_ns() >= budget.deadline_ns else "failed")
    finally:
        if commands is not None:
            try:
                commands.close()
            except BaseException as error:
                report["supervisor_restore_error"] = type(error).__name__ + ": " + str(error)
                report["outcome"] = "unknown"
        report["resource_after"] = resources()
        report["cancellation"] = budget.cancellation
        def publication_failure(error):
            report["publication_errors"].append({"type": type(error).__name__, "message": str(error)})
            report["outcome"] = "unknown"

        for name in ("manifest.json", "stages.jsonl"):
            try:
                source = checkpoint / name
                if os.path.lexists(source):
                    original = file_info(source, MAX_RAW_FILE)
                    write_new(copied_checkpoint / name, source.read_bytes())
                    require(file_info(copied_checkpoint / name) == original and file_info(source) == original,
                            "checkpoint observation changed while retaining raw bytes")
            except Exception as error:
                publication_failure(error)
        if (copied_checkpoint / "manifest.json").is_file():
            report["prepare_manifest_archive_member"] = "checkpoint/manifest.json"
            report["prepare_manifest_sha256"] = file_info(copied_checkpoint / "manifest.json")["sha256"]
        if (controller_out / "result.json").is_file():
            report["controller_result_archive_member"] = "controller/result.json"
            report["controller_result_sha256"] = file_info(controller_out / "result.json")["sha256"]
        try:
            receipt = checkpoint / "succinct.bin"
            if os.path.lexists(receipt):
                proof = file_info(receipt, MAX_PROOF)
                require(proof["bytes"] > 0, "empty observed receipt")
                write_new(working / "succinct.bin", receipt.read_bytes())
                require(file_info(working / "succinct.bin") == proof, "receipt publication bytes differ")
                report["receipt_sha256"] = proof["sha256"]
                report["receipt_bytes"] = proof["bytes"]
        except Exception as error:
            publication_failure(error)
        write_new(logs / "worker-observation-before-packaging.json", report)
        roots = [("worker", logs), ("inputs", inputs), ("checkpoint", copied_checkpoint)]
        if controller_out.is_dir():
            roots.append(("controller", controller_out))
        raw_archive = working / "w1-raw-logs.tar.gz"
        try:
            members = archive_raw(roots, raw_archive)
            report["raw_archive"] = {**file_info(raw_archive, MAX_ARCHIVE), "path": raw_archive.name, "complete": True,
                                     "indexed_data_members": len(members), "member_index_archive_member": "member-index.json",
                                     "member_index_sha256": hashlib.sha256(canonical(members)).hexdigest()}
        except Exception as error:
            publication_failure(error)
            report["raw_archive"] = {"path": raw_archive.name, "complete": False}
        report["worker_snapshot_monotonic_ns"] = time.monotonic_ns()
        report["deadline_exhausted_at_report"] = report["worker_snapshot_monotonic_ns"] >= budget.deadline_ns
        if budget.cancellation or report["deadline_exhausted_at_report"]:
            report["outcome"] = "cancelled" if budget.cancellation else "timed_out"
        data = canonical(report); require(len(data) <= MAX_REPORT, "worker report exceeds bound")
        write_new(working / "w1-result.json", data)
        files = [{"path": name, **file_info(working / name)} for name in ("succinct.bin", "w1-result.json", "w1-raw-logs.tar.gz")
                 if (working / name).is_file()]
        write_new(working / "w1-result-manifest.json", {"schema": "hepta-artifact-manifest-v1", "request_id": config["request_id"], "files": files})
        descriptor = os.open(working, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        for signum, handler in saved_signals.items():
            signal.signal(signum, handler)
    # The immutable report is a pre-handoff observation. A late fsync or signal
    # cannot change that historical observation into a successful live operation.
    return 0 if report["outcome"] == "verified" and budget.cancellation is None and time.monotonic_ns() < budget.deadline_ns else 1
