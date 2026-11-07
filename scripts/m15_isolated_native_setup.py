#!/usr/bin/env python3
"""Inner setup for one reviewed rootless M15 native fixture.

Called only by m15_isolated_native_run.py inside NEW user/mount/PID namespaces.
The pinned chroot utility starts the real static test ELF. Its actual product
launcher still performs its own sealed-FD exec; this helper grants no authority.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location(
    "m15_exact_isolated_support", Path(__file__).with_name("m15_isolated_native_support.py"))
isolated = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(isolated)
support = isolated.support


def bounded_kernel(path, maximum):
    with open(path, "rb") as source:
        raw = source.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("kernel observation exceeds bound")
    return raw


def check_mapping(path, outside, subordinate):
    rows = [tuple(map(int, line.split()))
            for line in bounded_kernel(path, 16384).decode("ascii").splitlines()]
    expected = {(0, outside, 1), (1, subordinate, 2000)}
    if len(rows) != 2 or set(rows) != expected:
        raise ValueError("actual independent UID/GID map differs from the reviewed plan")
    return rows


def input_plan(path, digest):
    plan, _ = isolated.json_input(path, digest, 32 * 1024**2)
    expected = {"schema", "host", "source", "tools", "tool_observations",
                "runtime_files", "artifacts", "control_scripts", "root", "evidence",
                "test_selector", "tmpfs_bytes"}
    if set(plan) != expected or plan["schema"] != "trnm-m15-isolated-native-plan-v1":
        raise ValueError("complete exact namespace plan required")
    if os.geteuid() != 0 or plan["host"]["uid"] == 0 or plan["host"]["gid"] == 0:
        raise ValueError("requires namespace root mapped from a non-root host principal")
    uid_map = check_mapping("/proc/self/uid_map", plan["host"]["uid"], plan["tools"]["subuid"]["start"])
    gid_map = check_mapping("/proc/self/gid_map", plan["host"]["gid"], plan["tools"]["subgid"]["start"])
    actual = isolated.namespaces()
    if any(actual[name] == plan["host"]["namespaces"][name] for name in isolated.NAMESPACES):
        raise ValueError("new user/mount/PID namespaces are mandatory before any mount")
    if plan["test_selector"] != isolated.CASE:
        raise ValueError("the original isolated-native selector cannot be changed")
    for record in plan["control_scripts"]:
        isolated.namespace_view(record, 1024**2)
    if not any(Path(record["path"]) == Path(__file__) for record in plan["control_scripts"]):
        raise ValueError("this exact inner runner was not bound by the outer process")
    for record in plan["tool_observations"].values():
        isolated.namespace_view(record, 256 * 1024**2)
    for item in plan["runtime_files"]:
        isolated.namespace_view(item["record"], 256 * 1024**2)
    for name, bound in (("node", 512 * 1024**2), ("tests", 4 * 1024**3), ("build_input", 4 * 1024**2)):
        isolated.namespace_view(plan["artifacts"][name], bound)
    root, evidence = Path(plan["root"]), Path(plan["evidence"])
    for directory in (root, evidence):
        info = os.stat(directory, follow_symlinks=False)
        if not directory.is_absolute() or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
            raise ValueError("fresh owned absolute namespace/evidence directories required")
    if any(root.iterdir()) or root.parent != evidence.parent or root.name != "root" or evidence.name != "evidence":
        raise ValueError("root must be the exact fresh sibling of retained evidence")
    if root.resolve() != root or evidence.resolve() != evidence:
        raise ValueError("namespace mount destinations may not traverse a symlink")
    mounts = bounded_kernel("/proc/self/mountinfo", 4 * 1024**2).decode()
    if any(any(flag in line.split(" - ", 1)[0] for flag in ("shared:", "master:", "propagate_from:"))
           for line in mounts.splitlines()):
        raise ValueError("mount propagation must already be private")
    return plan, {"uid_map": uid_map, "gid_map": gid_map, "namespaces": actual}


class Setup:
    def __init__(self, plan):
        self.plan = plan
        self.root = Path(plan["root"])
        self.evidence = Path(plan["evidence"])
        self.operations = []

    def mount(self, *arguments):
        record = self.plan["tool_observations"]["mount"]
        isolated.namespace_view(record, 256 * 1024**2)
        argv = [record["path"], "--no-mtab", "--internal-only", *map(str, arguments)]
        started = time.monotonic_ns()
        result, failure, out, err = None, None, b"", b""
        try:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, timeout=15)
            out, err = result.stdout, result.stderr
        except Exception as error:
            failure = {"type": type(error).__name__, "message": str(error)}
            if isinstance(error, subprocess.TimeoutExpired):
                out, err = error.stdout or b"", error.stderr or b""
        number = len(self.operations) + 1
        support.create(self.evidence / f"mount-{number:02}.stdout", out)
        support.create(self.evidence / f"mount-{number:02}.stderr", err)
        item = {"argv": argv, "exit_code": None if result is None else result.returncode,
                "failure": failure, "started_monotonic_ns": started,
                "ended_monotonic_ns": time.monotonic_ns(),
                "stdout_sha256": support.sha(out), "stderr_sha256": support.sha(err)}
        self.operations.append(item)
        support.create(self.evidence / f"mount-{number:02}.json", support.canonical(item))
        if failure is not None or result.returncode:
            raise RuntimeError("owned namespace mount failed; original streams retained; no fallback")

    def directory(self, name, mode=0o755):
        path = self.root / name.removeprefix("/")
        path.mkdir(mode=mode, parents=True, exist_ok=False)
        os.chmod(path, mode)
        return path

    def copied(self, source, target, maximum):
        destination = self.root / target.removeprefix("/")
        destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        isolated.namespace_view(source, maximum)
        result = support.copy_exact(source["path"], destination, maximum, source["sha256"])
        os.chmod(destination, 0o555)
        if os.stat(destination, follow_symlinks=False).st_uid != 0:
            raise ValueError("namespace executable copy is not held by namespace root")
        return support.fingerprint(destination, maximum)

    def prepare(self):
        size = self.plan["tmpfs_bytes"]
        if type(size) is not int or not 256 * 1024**2 <= size <= 8 * 1024**3:
            raise ValueError("explicit bounded tmpfs allocation required")
        self.mount("-t", "tmpfs", "-o", f"nodev,nosuid,mode=0755,size={size}", "m15-isolated-native", self.root)
        for path in ("/etc", "/m15", "/m15/bin", "/m15/evidence", "/proc", "/dev", "/usr", "/usr/bin"):
            self.directory(path)
        self.directory("/tmp", 0o1777)
        self.mount("-t", "proc", "-o", "nodev,nosuid,noexec", "proc", self.root / "proc")
        self.mount("--bind", self.evidence, self.root / "m15/evidence")
        null = os.stat("/dev/null", follow_symlinks=False)
        if not stat.S_ISCHR(null.st_mode) or (os.major(null.st_rdev), os.minor(null.st_rdev)) != (1, 3):
            raise ValueError("actual /dev/null character device required")
        support.create(self.root / "dev/null", b"")
        self.mount("--bind", "/dev/null", self.root / "dev/null")
        copies = []
        for name, target, bound in (("node", "/m15/bin/node", 512 * 1024**2),
                                   ("tests", "/m15/bin/tests", 4 * 1024**3)):
            copies.append(self.copied(self.plan["artifacts"][name], target, bound))
        copies.append(self.copied(self.plan["tool_observations"]["setpriv"], "/usr/bin/setpriv", 256 * 1024**2))
        for entry in self.plan["runtime_files"]:
            copies.append(self.copied(entry["record"], entry["destination"], 256 * 1024**2))
        raw = support.read(self.plan["artifacts"]["build_input"]["path"], 4 * 1024**2)
        if support.sha(raw) != self.plan["artifacts"]["build_input"]["sha256"]:
            raise ValueError("actual build input changed before fixture provisioning")
        support.create(self.root / "m15/build-input.json", raw, 0o400)
        marker = {"schema": "trnm-m15-isolated-native-fixture-v1",
                  "host_user_namespace": self.plan["host"]["namespaces"]["user"],
                  "host_mount_namespace": self.plan["host"]["namespaces"]["mnt"],
                  "host_pid_namespace": self.plan["host"]["namespaces"]["pid"],
                  "build_input_sha256": self.plan["artifacts"]["build_input"]["sha256"],
                  "node_sha256": self.plan["artifacts"]["node"]["sha256"],
                  "test_elf_sha256": self.plan["artifacts"]["tests"]["sha256"]}
        support.create(self.root / "m15/isolated-suite.json", support.canonical(marker), 0o400)
        if (self.root / "etc/trillionnium").exists():
            raise ValueError("production fixed root must be absent before the real fixture")
        return copies


def retain_state(root, evidence):
    """Retain remaining real test state after the owned child exits, including failures.
    No socket/device is opened. Roots and their parents must be real directories;
    nested symbolic links remain observations, never followed.
    """
    if not stat.S_ISDIR(os.stat(root, follow_symlinks=False).st_mode):
        raise ValueError("retained native state roots must be real directories")
    target = evidence / "retained-state"
    target.mkdir(mode=0o700)
    rows, total = [], 0
    for base in ("etc/trillionnium", "m15/runtime", "m15/frontier", "tmp"):
        source = root
        try:
            for component in Path(base).parts:
                source = source / component
                if not stat.S_ISDIR(os.stat(source, follow_symlinks=False).st_mode):
                    raise ValueError("retained native state roots must be real directories")
        except FileNotFoundError:
            rows.append({"path": base, "absent": True})
            continue
        for current, directories, files in os.walk(source, followlinks=False):
            relative = Path(current).relative_to(root)
            out = target / relative
            out.mkdir(mode=0o700, parents=True, exist_ok=True)
            entries = sorted(set(directories + files))
            for name in entries:
                path = Path(current) / name
                info = os.stat(path, follow_symlinks=False)
                row = {"path": path.relative_to(root).as_posix(), "identity": list(support.identity(info))}
                if stat.S_ISREG(info.st_mode):
                    record = support.fingerprint(path, 512 * 1024**2)
                    total += record["bytes"]
                    if total > 2 * 1024**3:
                        raise ValueError("retained native state exceeds the explicit evidence bound")
                    support.copy_exact(path, out / name, 512 * 1024**2, record["sha256"])
                    os.chmod(out / name, 0o600)
                    row.update({"kind": "regular", "sha256": record["sha256"], "bytes": record["bytes"]})
                elif stat.S_ISDIR(info.st_mode):
                    row["kind"] = "directory"
                elif stat.S_ISLNK(info.st_mode):
                    row.update({"kind": "symlink", "target": os.readlink(path)})
                    if name in directories:
                        directories.remove(name)
                else:
                    row["kind"] = "unopened-special"
                rows.append(row)
                if len(rows) > 100000:
                    raise ValueError("retained native state file count exceeded")
    support.create(evidence / "retained-state.json", support.canonical({"files": rows, "regular_bytes": total}))
    return {"entries": len(rows), "regular_bytes": total}


def execute(plan, isolation):
    setup = Setup(plan)
    process, status, failure, state_error = None, None, None, None
    unexpected_group = False
    try:
        copies = setup.prepare()
        support.create(setup.evidence / "namespace-prepared.json", support.canonical({
            "schema": "trnm-m15-real-namespace-setup-v1", "isolation": isolation, "copies": copies,
            "product_deployment_override": False, "independent_deployment_qualified": False}))
        chroot = plan["tool_observations"]["chroot"]
        isolated.namespace_view(chroot, 256 * 1024**2)
        argv = [chroot["path"], str(setup.root), "/m15/bin/tests", "--exact",
                isolated.CASE, "--ignored", "--nocapture", "--test-threads=1"]
        with (setup.evidence / "native.stdout").open("xb") as out, (setup.evidence / "native.stderr").open("xb") as err:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                env={"LANG": "C", "LC_ALL": "C", "TZ": "UTC", "TRNM_M15_ISOLATED_SUITE": "isolated-native-v1"},
                start_new_session=True)
            try:
                # The Rust case retains its own original 180-second limit.
                # This separate ceiling only bounds cleanup of a stuck fixture.
                status = process.wait(timeout=195)
            finally:
                try:
                    os.killpg(process.pid, 0)
                    unexpected_group = True
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                out.flush()
                err.flush()
                os.fsync(out.fileno())
                os.fsync(err.fileno())
        if status != 0 or unexpected_group:
            raise RuntimeError("actual isolated native child failed or retained a live process group")
    except Exception as error:
        failure = {"type": type(error).__name__, "message": str(error)}
    finally:
        try:
            state = retain_state(setup.root, setup.evidence)
        except Exception as error:
            state = None
            state_error = {"type": type(error).__name__, "message": str(error)}
        support.create(setup.evidence / "namespace-result.json", support.canonical({
            "schema": "trnm-m15-isolated-native-namespace-result-v1", "exit_code": status,
            "failure": failure, "unexpected_owned_process_group": unexpected_group,
            "retained_state": state, "state_error": state_error,
            "original_case_seconds": 180, "original_steps": 32, "service_rpc_seconds": 2,
            "independent_deployment_qualified": False}))
    return 0 if failure is None and state_error is None else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    args = parser.parse_args()
    plan, isolation = input_plan(args.plan, args.plan_sha256)
    raise SystemExit(execute(plan, isolation))


if __name__ == "__main__":
    main()
