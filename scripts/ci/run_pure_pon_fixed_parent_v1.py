#!/usr/bin/env python3
"""Owned, runtime-only fixed-parent observation on a disposable GitHub runner.

This opt-in fixture never adopts an existing unit/cgroup, changes ancestor
permissions, replaces a public service, or qualifies the old pressure campaign.
Only an intended root-opened target-leaf descriptor crosses into the trusted,
unprivileged phase controller; no root/common-ancestor permission is delegated.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "formal/pon-nakamoto-v1"), str(ROOT / "scripts/ci")]
from bounded_process import _wait_without_reaping
import pure_pon_binary_archive_v1 as files

PARENT = Path("/sys/fs/cgroup/trnmponpublic.slice")
UNIT = "trnmponpublic.slice"
PHASES = ("baseline", "from-zero", "correct-product-false-trace")
LIMITS = {"cpu.max": "25000 100000", "cpu.max.burst": "0",
          "memory.max": "2147483648", "memory.swap.max": "0", "pids.max": "256"}
SCHEMA = "pon-fixed-parent-fixture-v1"
CONTEXT_SCHEMA = "pon-fixed-parent-fixture-context-v1"
RESULT_SCHEMA = "pon-fixed-parent-fixture-result-v1"
FILE_LIMIT = 64 * 1024 * 1024
CAPTURE_LIMIT = 256 * 1024 * 1024
BUILD_STEPS = ("rustc-version", "cargo-version", "locked-graph", "format", "strict-pressure", "build-pressure",
               "descriptor-negative", "ready-deadline")
CONTROL_SELECTORS = {"descriptor-negative": "fixed_parent::native_fixed_parent_descriptor_rejects_ordinary_files",
                     "ready-deadline": "receiver_owner::native_receiver_ready_deadline_retains_partial_prefix_and_body"}
BUILD_FILES = ("source-before.json", "source-after.json", "native-binary.json", "results.json",
               "toolchain-observation.json", "resources-before.json", "resources-after.json", "ready-control.json",
               *(name + suffix for name in BUILD_STEPS for suffix in (".stdout.log", ".stderr.log", ".step.json")),
               *(name + ".native-verdict.json" for name in CONTROL_SELECTORS))
ROOT_FIELDS = tuple(LIMITS) + ("cpu.stat", "memory.current", "memory.events",
        "pids.current", "cgroup.procs", "cgroup.threads", "cgroup.events",
        "cgroup.type", "cgroup.subtree_control")
LEAF_FIELDS = ("cpu.stat", "memory.current", "memory.events", "pids.current",
        "cgroup.procs", "cgroup.threads", "cgroup.events", "cgroup.type",
        "cgroup.max.descendants")
NATIVE_SIDE_FILES = ("fixed-parent-placement-v1.json", "fixed-parent-after-exec-v1.json",
                    "fixed-parent-receiver-entry-v1.json", "fixed-parent-actors-ready-v1.json",
                    "receiver-ready-exchange-v1.json", "receiver-owner-binding-v1.json",
                    "receiver-child-ownership-binding-v1.json", "attacker-cost-binding-v1.json",
                    "attacker-process-cost-v1.json", "attacker-child-ownership-binding-v1.json")
PRIOR_FAILURE = {"head": "504ccfe6bc4aa504f4a67f73c16040fca5b8e10e",
                 "run_id": 40825729556, "job_id": 123288212503, "artifact_id": 12877105840,
                 "artifact_sha256": "1987270515950cc1e8fc108f9998ec63ad2fe5a6f7b847866e8a937aed833564",
                 "supplement_from_zero_paid_depletion_qualified": False,
                 "scope": "Preserved historical exact-B failure; this fixture cannot supersede it."}
require = files.require
strict_json = files.strict_json


def natural(value):
    return type(value) is int and value >= 0


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(value):
    return {"device": value.st_dev, "inode": value.st_ino, "uid": value.st_uid,
            "gid": value.st_gid, "mode": value.st_mode}


def write_new(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    require(len(raw) <= FILE_LIMIT, "FIXTURE_OUTPUT_BOUND")
    with path.open("xb") as stream:
        stream.write(raw)
    return {"bytes": len(raw), "sha256": sha(raw)}


def read_at(directory, name, limit=65536):
    require(name and "/" not in name and name not in (".", ".."), "FIXTURE_BASENAME")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        value = bytearray()
        while True:
            chunk = os.read(fd, min(8192, limit + 1 - len(value)))
            if not chunk:
                break
            value.extend(chunk)
            require(len(value) <= limit, "FIXTURE_KERNEL_READ_BOUND")
        return bytes(value).decode()
    finally:
        os.close(fd)


def write_at(directory, name, text):
    require(name in ("cgroup.subtree_control", "cgroup.max.descendants"), "FIXTURE_WRITE_SCOPE")
    fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    try:
        raw = text.encode()
        require(os.write(fd, raw) == len(raw), "FIXTURE_KERNEL_SHORT_WRITE")
    finally:
        os.close(fd)


def parse_fields(raw):
    values = {}
    for line in raw.splitlines():
        key, separator, value = line.partition("=")
        require(separator and key and key not in values, "FIXTURE_MANAGER_FIELDS")
        values[key] = value
    return values


def kernel_pairs(raw):
    values = {}
    for line in raw.splitlines():
        fields = line.split()
        require(len(fields) == 2 and fields[0] not in values
                and fields[1].isdigit(), "FIXTURE_KERNEL_FIELDS")
        values[fields[0]] = int(fields[1])
    return values


def empty(snapshot):
    if snapshot.get("complete") is not True:
        return False
    for name in ("parent", "leaf"):
        values = snapshot[name]["values"]
        if (values["cgroup.procs"].strip() or values["cgroup.threads"].strip()
                or values["pids.current"].strip() != "0"
                or kernel_pairs(values["cgroup.events"]).get("populated") != 0):
            return False
    return True


def host_capability():
    value = {"schema": "pon-fixed-parent-host-capability-v1", "platform": platform.platform(),
             "uname": list(platform.uname()), "euid": os.geteuid(),
             "github_actions": os.environ.get("GITHUB_ACTIONS"),
             "runner_environment": os.environ.get("RUNNER_ENVIRONMENT"),
             "physical_authentication": False}
    for name, path in (("self_cgroup", "/proc/self/cgroup"),
                       ("controllers", "/sys/fs/cgroup/cgroup.controllers"),
                       ("status", "/proc/self/status"), ("mountinfo", "/proc/self/mountinfo")):
        try:
            raw = Path(path).read_bytes()
            require(len(raw) <= 256 * 1024, "FIXTURE_HOST_PROBE_BOUND")
            value[name] = raw.decode()
        except (OSError, ValueError) as error:
            value[name] = None
            value[name + "_error"] = str(error)
    value["systemd_present"] = Path("/run/systemd/system").is_dir()
    value["cgroup_root_writable"] = os.access("/sys/fs/cgroup", os.W_OK)
    value["fixed_parent_exists"] = os.path.lexists(PARENT)
    return value


def transient_unit_command(description):
    properties = [("Description", "s", description), ("StopWhenUnneeded", "b", "false"),
                  ("CPUAccounting", "b", "true"), ("CPUQuotaPerSecUSec", "t", "250000"),
                  ("CPUQuotaPeriodUSec", "t", "100000"), ("MemoryAccounting", "b", "true"),
                  ("MemoryMax", "t", "2147483648"), ("MemorySwapMax", "t", "0"),
                  ("TasksAccounting", "b", "true"), ("TasksMax", "t", "256")]
    command = ["/usr/bin/busctl", "--system", "call", "org.freedesktop.systemd1",
               "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager",
               "StartTransientUnit", "ssa(sv)a(sa(sv))", UNIT, "fail", str(len(properties))]
    for row in properties:
        command.extend(row)
    return [*command, "0"]


class Owner:
    def __init__(self, output):
        self.output = output
        self.nonce = uuid.uuid4().hex
        self.description = "Owned PoN finite fixed-parent CI fixture " + self.nonce
        self.parent_fd = self.leaf_fd = None
        self.parent_identity = self.leaf_identity = None
        self.manager_identity = None
        self.leaf = PARENT / ("owned-" + self.nonce + ".group")
        self.started_by_fixture = False
        self.creation_attempted = False
        self.commands = []
        self.cleanup_observation = None

    def command(self, label, argv):
        start = time.monotonic_ns()
        row = {"label": label, "command": argv, "started_monotonic_ns": start,
               "returncode": None, "error": None}
        try:
            captured = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      timeout=30, check=False)
            row.update(returncode=captured.returncode, stdout=captured.stdout.decode(errors="replace"),
                       stderr=captured.stderr.decode(errors="replace"))
            require(len(captured.stdout) <= 131072 and len(captured.stderr) <= 131072,
                    "FIXTURE_MANAGER_OUTPUT_BOUND")
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            row["error"] = str(error)
        finally:
            row["ended_monotonic_ns"] = time.monotonic_ns()
            self.commands.append(row)
            write_new(self.output / ("manager-command-%02d.json" % len(self.commands)), row)
        require(row["returncode"] == 0 and row["error"] is None, "FIXTURE_MANAGER_COMMAND")
        return row["stdout"]

    def manager(self, active_required=True):
        raw = self.command("inspect-owned-unit", [
            "/usr/bin/systemctl", "show", UNIT, "--no-pager",
            "--property=Description,Transient,ControlGroup,ActiveState,InvocationID"])
        result = parse_fields(raw)
        require(result.get("Description") == self.description
                and result.get("Transient") == "yes"
                and result.get("ControlGroup") in ("", "/trnmponpublic.slice")
                and re.fullmatch("[0-9a-f]{32}", result.get("InvocationID", "")),
                "FIXTURE_UNIT_IDENTITY")
        if active_required:
            require(result.get("ControlGroup") == "/trnmponpublic.slice"
                    and result.get("ActiveState") == "active", "FIXTURE_UNIT_NOT_ACTIVE")
        if self.manager_identity is not None:
            require(all(result[key] == self.manager_identity[key]
                        for key in ("Description", "Transient", "InvocationID")),
                    "FIXTURE_UNIT_REPLACED")
        return result

    def create(self):
        capability = host_capability()
        write_new(self.output / "host-capability.json", capability)
        require(capability["euid"] == 0 and capability["github_actions"] == "true"
                and capability["runner_environment"] == "github-hosted"
                and capability["systemd_present"] and capability["cgroup_root_writable"],
                "FIXTURE_DISPOSABLE_PRIVILEGED_HOST_REQUIRED")
        require(not capability["fixed_parent_exists"], "FIXTURE_EXISTING_PARENT_REFUSED")
        for location in ("/run/systemd/system", "/etc/systemd/system", "/usr/lib/systemd/system",
                         "/lib/systemd/system"):
            require(not os.path.lexists(Path(location) / UNIT)
                    and not os.path.lexists(Path(location) / (UNIT + ".d")),
                    "FIXTURE_EXISTING_UNIT_FILE_REFUSED")
        for operation in ("list-units", "list-unit-files"):
            raw = self.command("absence-" + operation, [
                "/usr/bin/systemctl", operation, "--all", "--plain", "--full",
                "--no-legend", "--no-pager", UNIT])
            require(not raw.strip(), "FIXTURE_EXISTING_MANAGER_UNIT_REFUSED")
        self.creation_attempted = True
        self.command("create-owned-runtime-unit", transient_unit_command(self.description))
        self.started_by_fixture = True
        # StartTransientUnit returns a queued job path. Wait for that same
        # newly created unit's activation without restarting/resetting it.
        self.command("wait-owned-start-job", ["/usr/bin/systemctl", "start", UNIT])
        self.manager_identity = self.manager()
        self.parent_fd = files.directory(PARENT)
        self.parent_identity = identity(os.fstat(self.parent_fd))
        require(self.parent_identity["uid"] == 0 and self.parent_identity["mode"] & 0o022 == 0,
                "FIXTURE_ROOT_PARENT_REQUIRED")
        require(read_at(self.parent_fd, "cgroup.type") == "domain\n"
                and not read_at(self.parent_fd, "cgroup.procs").strip(), "FIXTURE_PARENT_NOT_EMPTY_DOMAIN")
        for name, expected in LIMITS.items():
            require(read_at(self.parent_fd, name).strip() == expected, "FIXTURE_ORIGINAL_LIMIT_REQUIRED")
        controllers = set(read_at(self.parent_fd, "cgroup.controllers").split())
        require({"cpu", "memory", "pids"} <= controllers, "FIXTURE_CONTROLLERS_REQUIRED")
        # Only this newly owned empty parent is changed. No ancestor controller,
        # permission or limit is ever written or delegated.
        write_at(self.parent_fd, "cgroup.subtree_control", "+cpu +memory +pids\n")
        os.mkdir(self.leaf.name, 0o755, dir_fd=self.parent_fd)
        self.leaf_fd = os.open(self.leaf.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=self.parent_fd)
        self.leaf_identity = identity(os.fstat(self.leaf_fd))
        write_at(self.leaf_fd, "cgroup.max.descendants", "0\n")
        require(self.leaf_identity["uid"] == 0 and self.leaf_identity["mode"] & 0o022 == 0,
                "FIXTURE_ROOT_LEAF_REQUIRED")
        require(empty(self.snapshot()), "FIXTURE_INITIAL_EMPTY_REQUIRED")

    def verify(self):
        require(self.parent_fd is not None and self.leaf_fd is not None, "FIXTURE_NOT_CREATED")
        require(identity(os.stat(PARENT, follow_symlinks=False)) == self.parent_identity
                and identity(os.fstat(self.parent_fd)) == self.parent_identity,
                "FIXTURE_PARENT_REPLACED")
        require(identity(os.stat(self.leaf.name, dir_fd=self.parent_fd, follow_symlinks=False)) == self.leaf_identity
                and identity(os.fstat(self.leaf_fd)) == self.leaf_identity, "FIXTURE_LEAF_REPLACED")
        require({p.name for p in os.scandir(self.parent_fd) if p.is_dir(follow_symlinks=False)}
                == {self.leaf.name}, "FIXTURE_FOREIGN_PARENT_SUBGROUP")
        require(not any(p.is_dir(follow_symlinks=False) for p in os.scandir(self.leaf_fd)),
                "FIXTURE_FOREIGN_LEAF_SUBGROUP")
        for name, expected in LIMITS.items():
            require(read_at(self.parent_fd, name).strip() == expected, "FIXTURE_LIMIT_CHANGED")
        require(read_at(self.parent_fd, "cgroup.type") == read_at(self.leaf_fd, "cgroup.type") == "domain\n"
                and read_at(self.leaf_fd, "cgroup.max.descendants").strip() == "0",
                "FIXTURE_TOPOLOGY_CHANGED")

    def snapshot(self):
        result = {"schema": "pon-fixed-parent-kernel-snapshot-v1",
                  "started_monotonic_ns": time.monotonic_ns(), "complete": False, "errors": [],
                  "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}
        try:
            self.verify()
            for name, fd, fields in (("parent", self.parent_fd, ROOT_FIELDS),
                                    ("leaf", self.leaf_fd, LEAF_FIELDS)):
                result[name] = {"identity": identity(os.fstat(fd)),
                                "values": {key: read_at(fd, key) for key in fields}}
            self.verify()
            result["complete"] = True
        except (OSError, ValueError) as error:
            result["errors"].append(str(error))
        result["ended_monotonic_ns"] = time.monotonic_ns()
        return result

    def migration_fd(self):
        self.verify()
        fd = os.open("cgroup.procs", os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.leaf_fd)
        return fd, {"identity": identity(os.fstat(fd)),
                    "open_flags": fcntl.fcntl(fd, fcntl.F_GETFL),
                    "descriptor_flags": fcntl.fcntl(fd, fcntl.F_GETFD),
                    "opening_euid": os.geteuid(),
                    "scope": "Intentionally granted target-leaf migration descriptor; trusted harness writes only zero.",
                    "kernel_enforced_write_zero_only": False}

    def cleanup(self):
        result = {"schema": "pon-fixed-parent-cleanup-v1", "attempted": False,
                  "complete": False, "error": None, "forced_kernel_kill": False,
                  "foreign_or_replaced_objects_touched": False}
        try:
            if not self.creation_attempted:
                result.update(complete=True, scope="No fixture unit was created; no host cleanup action.")
                return result
            result["attempted"] = True
            listed = self.command("cleanup-inspect-loaded-name", ["/usr/bin/systemctl", "list-units",
                "--all", "--plain", "--full", "--no-legend", "--no-pager", UNIT])
            if not listed.strip() and not os.path.lexists(PARENT):
                require(self.manager_identity is None and self.parent_identity is None,
                        "FIXTURE_OWNED_ASSET_DISAPPEARED")
                result.update(complete=True, scope="Failed create left no loaded unit or fixed parent; no stop/removal performed.")
                return result
            observed_manager = self.manager(active_required=False)
            result["manager_before"] = observed_manager
            if self.manager_identity is None:
                # A successful or ambiguously returned create has an exact
                # nonce and mode=fail. Only that newly owned empty transient
                # unit can be cleaned; unrelated/replaced names are refused.
                self.manager_identity = observed_manager
            if os.path.lexists(PARENT):
                current = identity(os.stat(PARENT, follow_symlinks=False))
                if self.parent_identity is None:
                    require(current["uid"] == 0 and current["mode"] & 0o022 == 0,
                            "FIXTURE_PARTIAL_PARENT_OWNER")
                    self.parent_identity = current
                require(current == self.parent_identity, "FIXTURE_CLEANUP_PARENT_CHANGED")
                if self.parent_fd is None:
                    self.parent_fd = files.directory(PARENT)
                require(identity(os.fstat(self.parent_fd)) == self.parent_identity,
                        "FIXTURE_CLEANUP_PARENT_CHANGED")
                children = {p.name for p in os.scandir(self.parent_fd) if p.is_dir(follow_symlinks=False)}
                if self.leaf_identity is not None:
                    require(children == {self.leaf.name}, "FIXTURE_FOREIGN_PARENT_SUBGROUP")
                    if self.leaf_fd is None:
                        self.leaf_fd = os.open(self.leaf.name, os.O_RDONLY | os.O_DIRECTORY
                            | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.parent_fd)
                    snapshot = self.snapshot()
                    result["before"] = snapshot
                    require(empty(snapshot), "FIXTURE_CLEANUP_REFUSED_POPULATED_OR_UNKNOWN")
                    self.verify()
                    os.rmdir(self.leaf.name, dir_fd=self.parent_fd)
                    os.close(self.leaf_fd)
                    self.leaf_fd = None
                else:
                    require(not children, "FIXTURE_PARTIAL_CLEANUP_REFUSED_UNKNOWN_CHILD")
                    partial = {name: read_at(self.parent_fd, name) for name in
                               ("cgroup.procs", "cgroup.threads", "cgroup.events", "pids.current")}
                    result["partial_parent_before"] = partial
                    require(not partial["cgroup.procs"].strip() and not partial["cgroup.threads"].strip()
                            and partial["pids.current"].strip() == "0"
                            and kernel_pairs(partial["cgroup.events"]).get("populated") == 0,
                            "FIXTURE_PARTIAL_CLEANUP_REFUSED_POPULATED")
                require(identity(os.stat(PARENT, follow_symlinks=False)) == self.parent_identity
                        and not read_at(self.parent_fd, "cgroup.procs").strip()
                        and not any(p.is_dir(follow_symlinks=False) for p in os.scandir(self.parent_fd)),
                        "FIXTURE_CLEANUP_PARENT_CHANGED")
            else:
                require(self.parent_identity is None, "FIXTURE_OWNED_PARENT_DISAPPEARED")
            self.command("stop-only-owned-runtime-unit", ["/usr/bin/systemctl", "stop", UNIT])
            require(not os.path.lexists(PARENT), "FIXTURE_PARENT_REMOVAL_UNCONFIRMED")
            result["complete"] = True
            result["scope"] = "Owned empty runtime unit/leaf removed; memory counters were point samples, not zero-charge proof."
        except (OSError, ValueError) as error:
            result["error"] = str(error)
        finally:
            for fd in (self.leaf_fd, self.parent_fd):
                if fd is not None:
                    os.close(fd)
            self.leaf_fd = self.parent_fd = None
            self.cleanup_observation = result
        return result


def phase_process(owner, output, binary, uid, gid, context, context_path, phase, preparation_hash):
    fd, fd_record = owner.migration_fd()
    require(fd_record["identity"] == context["migration_file_identity"], "FIXTURE_DESCRIPTOR_REPLACED")
    before = owner.snapshot()
    require(empty(before), "FIXTURE_PHASE_START_NOT_EMPTY")
    write_new(output / (phase + "-kernel-before.json"), before)
    command = ["/usr/bin/setpriv", "--reuid", str(uid), "--regid", str(gid), "--clear-groups",
               "--no-new-privs", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all",
               "--", binary["path"], "--exact", "fixed_parent::fixed_parent_receiver_phase_v1",
               "--ignored", "--nocapture", "--test-threads=1"]
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "RUST_BACKTRACE": "1",
                   "TRNM_FIXED_PARENT_FD": str(fd), "TRNM_FIXED_PARENT_CONTEXT": str(context_path),
                   "TRNM_FIXED_PARENT_OUT": str(output / "native"), "TRNM_FIXED_PARENT_PHASE": phase}
    if preparation_hash is not None:
        environment["TRNM_FIXED_PARENT_PREPARATION_SHA256"] = preparation_hash
    row = {"schema": "pon-fixed-parent-controller-process-v1", "phase": phase,
           "command": command, "inherited_descriptor": fd_record, "pid": None,
           "started_monotonic_ns": time.monotonic_ns(), "returncode": None, "error": None,
           "stdout_truncated": False, "stderr_truncated": False, "forced_controller_group_cleanup": False,
           "owned_group_cleanup_attempted": False, "owned_group_cleanup_error": None,
           "original_phase_window_ns": 30_000_000_000, "original_call_deadline_ns": 2_000_000_000,
           "outer_controller_limit_seconds": 600}
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": 4 * 1024 * 1024, "stderr": 1024 * 1024}
    child = selector = None
    deadline = time.monotonic() + 600
    terminal = False
    try:
        child = subprocess.Popen(command, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 pass_fds=(fd,), start_new_session=True, umask=0o077)
        row["pid"] = child.pid
        # The root controller does not retain an extra migration capability
        # during native service. A fresh root-open occurs only for the next phase.
        os.close(fd)
        fd = None
        selector = selectors.DefaultSelector()
        for name in ("stdout", "stderr"):
            stream = getattr(child, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            left = deadline - time.monotonic()
            require(left > 0, "FIXTURE_CONTROLLER_TIMEOUT")
            for key, _ in selector.select(min(left, 0.05)):
                name = key.data
                chunk = os.read(key.fileobj.fileno(), min(65536, limits[name] + 1 - len(buffers[name])))
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                buffers[name].extend(chunk)
                require(len(buffers[name]) <= limits[name], "FIXTURE_CONTROLLER_STREAM_BOUND")
        row["returncode"] = _wait_without_reaping(child, deadline)
        terminal = True
        row["before_parent_reap"] = owner.snapshot()
        # This empty observation precedes any possible error cleanup signal.
        require(empty(row["before_parent_reap"]), "FIXTURE_RECEIVER_FAMILY_STILL_POPULATED")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        row["error"] = str(error)
    finally:
        if fd is not None:
            os.close(fd)
        if selector is not None:
            selector.close()
        if child is not None:
            try:
                row["forced_controller_group_cleanup"] = (row["error"] is not None
                    or not terminal or row["returncode"] != 0)
                # Same POSIX group ownership rule as bounded_process: retain
                # the unreaped leader's PID/PGID through the final own-group
                # cleanup, including a zero-exit parent. The receiver's empty
                # cgroup observation above precedes this signal; actors and
                # honest-controller descendants outside that leaf also close.
                row["owned_group_cleanup_attempted"] = True
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as error:
                    row["owned_group_cleanup_error"] = str(error)
                row["actual_reaped_returncode"] = child.wait(timeout=10)
            except (OSError, subprocess.SubprocessError) as error:
                row["reap_error"] = str(error)
            finally:
                for name in ("stdout", "stderr"):
                    stream = getattr(child, name)
                    if stream is not None and not stream.closed:
                        stream.close()
        for name, raw in buffers.items():
            row[name + "_truncated"] = len(raw) > limits[name]
            raw = bytes(raw[:limits[name]])
            with (output / (phase + "." + name + ".log")).open("xb") as stream:
                stream.write(raw)
            row[name + "_bytes"], row[name + "_sha256"] = len(raw), sha(raw)
        row["ended_monotonic_ns"] = time.monotonic_ns()
        row["after"] = owner.snapshot()
        write_new(output / (phase + "-kernel-after.json"), row["after"])
        write_new(output / (phase + "-process.json"), row)
    return row


def process_complete(row):
    return (type(row.get("returncode")) is int and row["returncode"] == 0
            and type(row.get("actual_reaped_returncode")) is int and row["actual_reaped_returncode"] == 0
            and row.get("error") is None and row.get("reap_error") is None
            and row.get("owned_group_cleanup_attempted") is True
            and row.get("owned_group_cleanup_error") is None
            and row.get("forced_controller_group_cleanup") is False
            and row.get("stdout_truncated") is False and row.get("stderr_truncated") is False)


def source_record(uid, gid, expected):
    command = [sys.executable, "-B", str(ROOT / "scripts/ci/verify_ci_source.py"),
               "--kind", "head", "--expected-head", expected]
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            user=uid, group=gid, extra_groups=[], timeout=180, check=False)
    require(result.returncode == 0, "FIXTURE_SOURCE_IDENTITY: " + result.stderr.decode(errors="replace")[:2048])
    require(len(result.stdout) < 131072, "FIXTURE_SOURCE_OUTPUT_BOUND")
    return strict_json(result.stdout)


def prepare_native(args):
    """Build and run only the two new short controls; never provision resources."""
    import run_pure_pon_admission_daa_v2 as native
    from verify_ci_source import verify
    out, target = args.output.resolve(), args.target.resolve()
    require(not out.is_relative_to(ROOT) and not target.is_relative_to(ROOT)
            and not out.is_relative_to(target) and not target.is_relative_to(out), "FIXTURE_BUILD_PATHS")
    native.validate_build_environment(os.environ)
    native.validate_cargo_configuration(os.environ)
    out.mkdir(parents=False, exist_ok=False)
    result = {"schema": "pon-fixed-parent-build-v1", "expected_head": args.expected_head,
              "steps": [], "native_verdicts": [], "source_before": None, "source_after": None,
              "binary": None, "failure": None, "finalization_failures": [], "complete_success": False,
              "automatic_retries": 0, "target": str(target), "toolchain": native.TOOLCHAIN,
              "physical_authentication": False, "original_campaign_qualification": False,
              "public_fairness_qualified": False, "production_qualified": False}
    environment = {key: value for key, value in os.environ.items() if not key.startswith("TRNM_")}
    environment.update(CARGO_TARGET_DIR=str(target), CARGO_BUILD_JOBS="2", CARGO_NET_OFFLINE="true",
                       CARGO_INCREMENTAL="0", RUSTUP_TOOLCHAIN=native.TOOLCHAIN, RUST_TEST_THREADS="1",
                       PYTHONDONTWRITEBYTECODE="1")
    cargo = [str(args.cargo), "+" + native.TOOLCHAIN]

    def step(name, command, timeout, env=None):
        row = native.bounds.run_step(out, name, command, env or environment, timeout=timeout)
        result["steps"].append(row)
        require(row["complete_success"] is True, "FIXTURE_BUILD_STEP_FAILED:" + name)
        return row

    try:
        result["source_before"] = verify("head", args.expected_head, root=ROOT)
        write_new(out / "source-before.json", result["source_before"])
        resources = native.bounds.resource_observation()
        write_new(out / "resources-before.json", resources)
        native.bounds.validate_resources(resources, 10)
        rustc = step("rustc-version", [str(args.cargo.parent / "rustup"), "run", native.TOOLCHAIN, "rustc", "-Vv"], 30)
        version = step("cargo-version", [*cargo, "-Vv"], 30)
        compiler = native.toolchain_identity((out / rustc["stdout"]).read_text(),
                    (out / version["stdout"]).read_text(), platform.machine())
        write_new(out / "toolchain-observation.json", compiler)
        step("locked-graph", [*cargo, "metadata", "--locked", "--offline", "--format-version", "1",
                              "--manifest-path", "trillionnium/Cargo.toml"], 120)
        step("format", [*cargo, "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"], 180)
        step("strict-pressure", [*cargo, "clippy", "--release", "--locked", "--offline", "--manifest-path",
                "trillionnium/Cargo.toml", "--all-features", "-p", "trnm-pon-node", "--test",
                "pure_pon_pressure_v2", "--", "-D", "warnings"], 1800)
        build = step("build-pressure", [*cargo, "test", "--release", "--locked", "--offline", "--manifest-path",
                "trillionnium/Cargo.toml", "--all-features", "--no-run", "--message-format=json", "-p",
                "trnm-pon-node", "--test", "pure_pon_pressure_v2"], 1800)
        binary = native.test_artifacts(out / build["stdout"], target)["pure_pon_pressure_v2"]
        result["binary"] = binary
        write_new(out / "native-binary.json", {"expected_head": args.expected_head,
                  "expected_tree": result["source_before"]["tested_tree"], "binary": binary})
        for name, selector in CONTROL_SELECTORS.items():
            require(native.bounds.sha(binary["path"]) == binary["sha256"], "FIXTURE_BUILD_BINARY_CHANGED")
            env = dict(environment, TRNM_RECEIVER_READY_CONTROL_OUT=str(out / "ready-control.json"))
            row = step(name, [binary["path"], "--exact", selector, "--nocapture", "--test-threads=1"], 60, env)
            verdict = native.native_verdict(name, row, (out / row["stdout"]).read_text())
            result["native_verdicts"].append(verdict)
            write_new(out / (name + ".native-verdict.json"), verdict)
            require(verdict["qualified"] is True and verdict["terminal_summary"]["passed"] == 1,
                    "FIXTURE_NATIVE_CONTROL_FAILED")
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result["failure"] = str(error)
    finally:
        try:
            result["source_after"] = verify("head", args.expected_head, root=ROOT)
            write_new(out / "source-after.json", result["source_after"])
            require(result["source_after"] == result["source_before"], "FIXTURE_BUILD_SOURCE_CHANGED")
            resources = native.bounds.resource_observation()
            write_new(out / "resources-after.json", resources)
            native.bounds.validate_resources(resources, 10)
            if result["binary"] is not None:
                require(native.bounds.sha(result["binary"]["path"]) == result["binary"]["sha256"],
                        "FIXTURE_BUILD_BINARY_CHANGED")
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            result["finalization_failures"].append(str(error))
        result["complete_success"] = (result["failure"] is None and not result["finalization_failures"]
            and tuple(row["name"] for row in result["steps"]) == BUILD_STEPS
            and len(result["native_verdicts"]) == 2)
        write_new(out / "results.json", result)
    return 0 if result["complete_success"] else 1


def retain_build(output, source):
    held = files.directory(source)
    target = output / "build"
    target.mkdir(mode=0o755)
    total = 0
    try:
        for name in BUILD_FILES:
            fd = files.held_file(held, (name,))
            try:
                before = os.fstat(fd)
                require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= FILE_LIMIT,
                        "FIXTURE_BUILD_FILE_BOUND")
                total += before.st_size
                require(total <= CAPTURE_LIMIT, "FIXTURE_BUILD_TOTAL_BOUND")
                raw = bytearray()
                while True:
                    chunk = os.read(fd, min(65536, FILE_LIMIT + 1 - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
                    require(len(raw) <= FILE_LIMIT, "FIXTURE_BUILD_FILE_GREW")
                require(len(raw) == before.st_size and files.identity(before) == files.identity(os.fstat(fd)),
                        "FIXTURE_BUILD_FILE_CHANGED")
                with (target / name).open("xb") as stream:
                    stream.write(raw)
            finally:
                os.close(fd)
    finally:
        os.close(held)


def core_binding_paths(phase_names=PHASES):
    names = ["context.json", "source-before.json", "source-after.json", "native-binary.json",
             "results.json", "native/preparation.json", "host-capability.json"]
    names += ["build/" + name for name in BUILD_FILES]
    for phase in phase_names:
        names += [phase + suffix for suffix in ("-kernel-before.json", "-kernel-after.json",
                                                "-process.json", ".stdout.log", ".stderr.log")]
        names += ["native/" + phase + ".json", "native/" + phase + "-controller-v1.json"]
        names += ["native/" + phase + "/" + name for name in NATIVE_SIDE_FILES]
    return names


def bind_files(output, phase_names):
    names = core_binding_paths(phase_names)
    manager = sorted(p.name for p in output.glob("manager-command-*.json"))
    require(len(manager) <= 32, "FIXTURE_MANAGER_COMMAND_COUNT")
    names += manager
    rows, total = [], 0
    held = files.directory(output)
    try:
        for name in names:
            item = {"path": name, "bytes": None, "sha256": None, "error": None}
            try:
                fd = files.held_file(held, tuple(name.split("/")))
                try:
                    before = os.fstat(fd)
                    require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= FILE_LIMIT,
                            "FIXTURE_BINDING_FILE_BOUND")
                    total += before.st_size
                    require(total <= CAPTURE_LIMIT, "FIXTURE_BINDING_TOTAL_BOUND")
                    raw = bytearray()
                    while True:
                        chunk = os.read(fd, min(65536, FILE_LIMIT + 1 - len(raw)))
                        if not chunk:
                            break
                        raw.extend(chunk)
                        require(len(raw) <= FILE_LIMIT, "FIXTURE_BINDING_FILE_GREW")
                    require(len(raw) == before.st_size
                            and files.identity(before) == files.identity(os.fstat(fd)),
                            "FIXTURE_BINDING_FILE_CHANGED")
                    item.update(bytes=len(raw), sha256=sha(raw))
                finally:
                    os.close(fd)
            except (OSError, ValueError) as error:
                item["error"] = str(error)
            rows.append(item)
    finally:
        os.close(held)
    value = {"schema": "pon-fixed-parent-parent-binding-v1", "files": rows,
             "complete": all(r["error"] is None for r in rows),
             "physical_authentication": False,
             "scope": "Root fixture exact-byte capture after native exits and owned-unit cleanup; not hostile-host authentication."}
    write_new(output / "fixed-parent-binding-v1.json", value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary-description", type=Path)
    parser.add_argument("--runner-uid", type=int)
    parser.add_argument("--runner-gid", type=int)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--probe-only", action="store_true")
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--target", type=Path)
    parser.add_argument("--cargo", type=Path)
    args = parser.parse_args()
    require(re.fullmatch("[0-9a-f]{40}", args.expected_head), "FIXTURE_HEAD_ARGUMENT")
    if args.prepare:
        require(not args.probe_only and args.target is not None and args.cargo is not None,
                "FIXTURE_BUILD_ARGUMENTS")
        return prepare_native(args)
    output = args.output.absolute()
    require(str(output) == os.path.abspath(output) and not output.is_relative_to(ROOT),
            "FIXTURE_OUTPUT_OUTSIDE_SOURCE")
    output.mkdir(mode=0o755, parents=False, exist_ok=False)
    if args.probe_only:
        write_new(output / "host-capability.json", host_capability())
        return 0
    require(type(args.runner_uid) is int and args.runner_uid > 0
            and type(args.runner_gid) is int and args.runner_gid > 0
            and args.binary_description is not None, "FIXTURE_NATIVE_ARGUMENTS")
    owner = Owner(output)
    result = {"schema": RESULT_SCHEMA, "expected_head": args.expected_head,
              "started_utc": datetime.now(timezone.utc).isoformat(), "phases": [],
              "failure": None, "finalization_failures": [], "cleanup": None,
              "original_campaign_qualification": False, "physical_authentication": False,
              "public_fairness_qualified": False, "production_qualified": False,
              "work_hardness_qualified": False, "prior_failure": PRIOR_FAILURE,
              "qualification_scope": "Owned fixed-parent lifecycle and observations only; unchanged honest-service and paid-depletion predicates are independent results.",
              "topology": "Three fresh unprivileged phase controllers outside the one shared fixed parent; same owned leaf reused without counter reset."}
    binary = None
    try:
        require(os.geteuid() == 0, "FIXTURE_ROOT_OWNER_REQUIRED")
        before = source_record(args.runner_uid, args.runner_gid, args.expected_head)
        write_new(output / "source-before.json", before)
        retain_build(output, args.binary_description.parent)
        description = strict_json(args.binary_description.read_bytes())
        require(description == strict_json((output / "build/native-binary.json").read_bytes()),
                "FIXTURE_BUILD_DESCRIPTION_CHANGED")
        built = strict_json((output / "build/results.json").read_bytes())
        require(built["schema"] == "pon-fixed-parent-build-v1" and built["complete_success"] is True
                and built["expected_head"] == args.expected_head and built["failure"] is None
                and built["finalization_failures"] == [] and built["source_before"] == built["source_after"] == before,
                "FIXTURE_EXACT_BUILD_REQUIRED")
        binary = description["binary"]
        require(description["expected_head"] == args.expected_head and description["expected_tree"] == before["tested_tree"]
                and binary["profile"]["opt_level"] == "3" and binary["profile"]["debug_assertions"] is False
                and binary["test_harness"] is True and binary["profile"]["test"] is True,
                "FIXTURE_NATIVE_BUILD_IDENTITY")
        binary_path = Path(binary["path"])
        meta = binary_path.lstat()
        require(binary_path.is_absolute() and stat.S_ISREG(meta.st_mode)
                and meta.st_uid == args.runner_uid and not meta.st_mode & 0o6000
                and 0 < meta.st_size == binary["bytes"] <= FILE_LIMIT
                and sha(binary_path.read_bytes()) == binary["sha256"], "FIXTURE_ACTUAL_BINARY")
        write_new(output / "native-binary.json", description)
        owner.create()
        native = output / "native"
        native.mkdir(mode=0o700)
        os.chown(native, args.runner_uid, args.runner_gid)
        fd, opened = owner.migration_fd()
        os.close(fd)
        context = {"schema": CONTEXT_SCHEMA, "root_fixture_pid": os.getpid(),
                   "runner_uid": args.runner_uid, "runner_gid": args.runner_gid,
                   "expected_head": args.expected_head, "expected_tree": before["tested_tree"],
                   "parent_path": str(PARENT), "leaf_path": str(owner.leaf),
                   "parent_identity": owner.parent_identity, "leaf_identity": owner.leaf_identity,
                   "migration_file_identity": opened["identity"], "initial_root_open": opened,
                   "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                   "limits": LIMITS, "outer_cgroup": Path("/proc/self/cgroup").read_text(),
                   "manager_identity": owner.manager_identity, "owner_nonce": owner.nonce,
                   "physical_authentication": False, "production_qualified": False,
                   "kernel_enforced_write_zero_only": False}
        write_new(output / "context.json", context)
        preparation_hash = None
        for phase in PHASES:
            row = phase_process(owner, output, binary, args.runner_uid, args.runner_gid,
                                context, output / "context.json", phase, preparation_hash)
            result["phases"].append(row)
            path = native / "preparation.json"
            if path.is_file():
                actual = sha(path.read_bytes())
                if preparation_hash is None:
                    preparation_hash = actual
                require(actual == preparation_hash, "FIXTURE_COMMON_INPUT_CHANGED")
            require(process_complete(row) and empty(row["after"]), "FIXTURE_PHASE_LIFECYCLE_FAILED")
        result["common_preparation_sha256"] = preparation_hash
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result["failure"] = str(error)
    finally:
        result["cleanup"] = owner.cleanup()
        try:
            after = source_record(args.runner_uid, args.runner_gid, args.expected_head)
            write_new(output / "source-after.json", after)
            require(after == strict_json((output / "source-before.json").read_bytes()), "FIXTURE_SOURCE_CHANGED")
            if binary is not None:
                raw = Path(binary["path"]).read_bytes()
                require(0 < len(raw) == binary["bytes"] <= FILE_LIMIT and sha(raw) == binary["sha256"],
                        "FIXTURE_BINARY_CHANGED")
                retained = output / "retained-binary"
                with retained.open("xb") as stream:
                    stream.write(raw)
                require(sha(retained.read_bytes()) == binary["sha256"], "FIXTURE_RETAINED_BINARY")
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            result["finalization_failures"].append(str(error))
        result["completed_utc"] = datetime.now(timezone.utc).isoformat()
        result["manager_command_files"] = ["manager-command-%02d.json" % index
                                            for index in range(1, len(owner.commands) + 1)]
        write_new(output / "results.json", result)
        binding = bind_files(output, PHASES)
        print(json.dumps({"schema": RESULT_SCHEMA, "failure": result["failure"],
                          "cleanup_complete": result["cleanup"]["complete"],
                          "binding_complete": binding["complete"], "original_campaign_qualification": False}))
    return 0 if (result["failure"] is None and not result["finalization_failures"]
                 and result["cleanup"]["complete"] and binding["complete"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
