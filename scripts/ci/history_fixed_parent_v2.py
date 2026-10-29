#!/usr/bin/env python3
"""Create and remove only this run's source-pinned, separately limited CI slice.

An unconfigured systemd slice may have LoadState=loaded. That is not proof that
somebody owns it, nor permission to replace a configured or active slice. The
root-only lease, actual manager state, on-disk unit paths and inode all matter.
Receipts on stdout are evidence copies, never cleanup authority by themselves.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import sys
import time

SOURCE_SHA256 = "74eb36a63559bf8603c15ddd3753a1db143684a2cefd84cce5aff10a76bbd622"
FIXED_UNIT = "trnmponpublic.slice"
ROOT = Path("/run/trnm-history-parent-ci-v2")
UNIT_ROOT = Path("/run/systemd/system")
CGROUP_ROOT = Path("/sys/fs/cgroup")
PROPERTIES = (
    "Id", "Names", "LoadState", "FragmentPath", "DropInPaths", "ActiveState",
    "SubState", "ControlGroup", "Transient", "Job", "CPUQuotaPerSecUSec",
    "CPUQuotaPeriodUSec", "MemoryMax", "MemorySwapMax", "TasksMax",
)


def require(value: bool, message: str) -> None:
    if not value:
        raise RuntimeError(message)


def owner(value: str) -> str:
    require(re.fullmatch(r"[1-9][0-9]{0,19}\.[1-9][0-9]{0,9}", value) is not None,
            "numeric workflow run and attempt required")
    return value


def probe_unit(value: str) -> str:
    run, attempt = owner(value).split(".")
    return f"trnmponprobe{run}a{attempt}.slice"


def validate_fresh(unit: str, state: dict, existing: list, cgroup_exists: bool) -> None:
    require(state.get("Id") == unit and state.get("Names", "").split() == [unit],
            "unexpected unit identity or alias")
    require(state.get("LoadState") in ("loaded", "not-found"),
            "unexpected load state")
    require(state.get("FragmentPath") == "" and state.get("DropInPaths") == "",
            "refuse an existing configured unit or drop-in")
    require(state.get("ActiveState") == "inactive" and state.get("SubState") == "dead",
            "refuse an active, failed or transitioning unit")
    require(state.get("Transient") == "no" and state.get("Job") in ("", "0"),
            "refuse transient or queued unit")
    require(state.get("ControlGroup") == "" and not cgroup_exists,
            "refuse an existing kernel parent")
    require(not existing, "refuse an existing unit file, alias, dependency or drop-in")


def validate_copy(actual: dict, evidence: dict, expected_owner: str, unit: str) -> None:
    require(actual.get("schema") == "history-fixed-parent-root-lease-v2"
            and actual.get("owner") == owner(expected_owner)
            and actual.get("unit") == unit
            and actual.get("path") == str(UNIT_ROOT / unit)
            and actual.get("sha256") == SOURCE_SHA256
            and actual.get("uid") == 0
            and re.fullmatch(r"[0-9a-f]{64}", actual.get("token", "")) is not None,
            "unexpected root lease authority")
    require(evidence == actual, "receipt differs from root-only lease")


class Manager:
    def __init__(self, expected_owner: str, events: list, lifetime: float = 90):
        self.owner = owner(expected_owner)
        self.events = events
        self.deadline = time.monotonic() + lifetime

    def command(self, *args: str) -> str:
        left = self.deadline - time.monotonic()
        require(left > 0, "finite fixture lifetime exhausted")
        proc = subprocess.run(args, capture_output=True, text=True,
                              timeout=min(left, 15), check=False)
        self.events.append({"argv": list(args), "exit_code": proc.returncode,
                            "stdout": proc.stdout, "stderr": proc.stderr})
        require(proc.returncode == 0, "fixture command failed")
        return proc.stdout.strip()

    def state(self, unit: str) -> dict:
        output = self.command("systemctl", "show", unit,
                              "--property=" + ",".join(PROPERTIES))
        state = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        require(set(state) == set(PROPERTIES), "incomplete actual systemd properties")
        return state

    def disk_paths(self, unit: str) -> tuple[list, list]:
        paths = shlex.split(self.command("systemctl", "show", "--property=UnitPath", "--value"))
        require(paths and str(UNIT_ROOT) in paths and len(paths) <= 64
                and all(Path(p).is_absolute() for p in paths), "unexpected manager unit path")
        existing = []
        for raw in paths:
            parent = Path(raw)
            for name in (unit, unit + ".d", unit + ".wants", unit + ".requires", "slice.d"):
                item = parent / name
                if os.path.lexists(item):
                    existing.append(str(item))
            if parent.is_dir():
                children = list(parent.iterdir())
                require(len(children) <= 8192, "unexpectedly large unit directory")
                for item in children:
                    if item.name.endswith((".wants", ".requires")) and os.path.lexists(item / unit):
                        existing.append(str(item / unit))
        return paths, sorted(set(existing))

    def lease_directory(self, unit: str, create: bool) -> Path:
        require(unit in (FIXED_UNIT, probe_unit(self.owner)), "unit outside fixed fixture scope")
        if create:
            try:
                ROOT.mkdir(mode=0o700)
            except FileExistsError:
                pass
        metadata = ROOT.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
                and stat.S_IMODE(metadata.st_mode) == 0o700, "unsafe root lease directory")
        path = ROOT / unit
        if create:
            path.mkdir(mode=0o700)
        metadata = path.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
                and stat.S_IMODE(metadata.st_mode) == 0o700, "unsafe unit lease directory")
        return path

    def root_lease(self, unit: str) -> dict:
        path = self.lease_directory(unit, False) / "lease.json"
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                    and stat.S_IMODE(metadata.st_mode) == 0o600
                    and metadata.st_size <= 8192, "unsafe root lease file")
            return json.load(stream)

    def file_matches(self, record: dict) -> None:
        path = UNIT_ROOT / record["unit"]
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                    and stat.S_IMODE(metadata.st_mode) == 0o644
                    and (metadata.st_dev, metadata.st_ino) == (record["device"], record["inode"])
                    and metadata.st_size <= 8192
                    and hashlib.sha256(stream.read()).hexdigest() == SOURCE_SHA256,
                    "refuse a replaced fixed parent file")

    def loaded_matches(self, record: dict) -> dict:
        self.file_matches(record)
        state = self.state(record["unit"])
        require(state["Id"] == record["unit"]
                and state["Names"].split() == [record["unit"]]
                and state["LoadState"] == "loaded"
                and state["FragmentPath"] == record["path"]
                and state["DropInPaths"] == ""
                and state["Transient"] == "no", "refuse changed manager configuration")
        return state

    def provision(self, source: Path, unit: str) -> dict:
        require(unit in (FIXED_UNIT, probe_unit(self.owner)), "unexpected unit")
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= 8192,
                    "source-pinned regular slice file required")
            raw = stream.read()
        require(hashlib.sha256(raw).hexdigest() == SOURCE_SHA256,
                "original fixed 25 percent CPU, 2 GiB, 256 task limits changed")
        state = self.state(unit)
        paths, existing = self.disk_paths(unit)
        cgroup_exists = os.path.lexists(CGROUP_ROOT / unit)
        self.events.append({"phase": "before-exclusive-creation", "unit": unit,
                            "state": state, "manager_unit_paths": paths,
                            "existing_paths": existing, "kernel_parent_exists": cgroup_exists})
        validate_fresh(unit, state, existing, cgroup_exists)
        lease = self.lease_directory(unit, True)
        destination = UNIT_ROOT / unit
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            created = os.fstat(stream.fileno())
        record = {"schema": "history-fixed-parent-root-lease-v2", "owner": self.owner,
                  "unit": unit, "path": str(destination), "device": created.st_dev,
                  "inode": created.st_ino, "uid": created.st_uid,
                  "sha256": SOURCE_SHA256, "token": secrets.token_hex(32),
                  "exclusive_creation": True}
        fd = os.open(lease / "lease.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(record, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        self.command("systemctl", "daemon-reload")
        self.loaded_matches(record)
        self.command("systemctl", "start", unit)
        active = self.loaded_matches(record)
        require(active["ActiveState"] == "active" and active["SubState"] == "active"
                and active["ControlGroup"] == "/" + unit, "owned slice did not become active")
        root = CGROUP_ROOT / unit
        limits = {name: (root / name).read_text().strip()
                  for name in ("cpu.max", "memory.max", "memory.swap.max", "pids.max")}
        require(limits == {"cpu.max": "25000 100000", "memory.max": "2147483648",
                           "memory.swap.max": "0", "pids.max": "256"},
                "actual original fixed parent limits differ")
        self.events.append({"phase": "owned-active-parent", "state": active, "limits": limits})
        return record

    def cleanup(self, unit: str, evidence: dict | None = None) -> dict:
        actual = self.root_lease(unit)
        validate_copy(actual, actual if evidence is None else evidence, self.owner, unit)
        before = self.loaded_matches(actual)
        root = CGROUP_ROOT / unit
        counters = {name: (root / name).read_text().strip()
                    for name in ("pids.current", "cpu.stat", "memory.current", "cgroup.events")
                    if (root / name).is_file()}
        self.command("systemctl", "stop", unit)
        self.file_matches(actual)
        after = self.state(unit)
        require(after["ActiveState"] == "inactive" and after["SubState"] == "dead"
                and not os.path.lexists(root), "owned parent failed to stop completely")
        (UNIT_ROOT / unit).unlink()
        self.command("systemctl", "daemon-reload")
        lease = self.lease_directory(unit, False)
        require(self.root_lease(unit) == actual, "lease changed before removal")
        (lease / "lease.json").unlink()
        lease.rmdir()
        return {"unit": unit, "owned_runtime_unit_removed": True,
                "pre_cleanup_state": before, "post_stop_state": after,
                "pre_cleanup_counters": counters,
                "cleanup_does_not_change_native_completion_or_failed_run": True}

    def probe(self, source: Path) -> dict:
        rows = Path("/proc/self/cgroup").read_text().splitlines()
        require(len(rows) == 1 and rows[0].startswith("0::/"), "one actual cgroup v2 membership required")
        membership = rows[0][3:]
        require(".." not in Path(membership).parts, "unexpected probe cgroup path")
        parent = CGROUP_ROOT / membership.lstrip("/")
        actual = {name: (parent / name).read_text().strip()
                  for name in ("cpu.max", "memory.max")}
        actual["nice"] = os.getpriority(os.PRIO_PROCESS, 0)
        self.events.append({"phase": "actual-probe-outer-resources", "cgroup": membership,
                            "pid": os.getpid(), "resources": actual})
        require(actual == {"cpu.max": "400000 100000", "memory.max": "17179869184", "nice": 10},
                "original four CPU, 16 GiB, nice 10 probe ceiling required")
        unit = probe_unit(self.owner)
        record = self.provision(source, unit)
        observations = []
        try:
            try:
                self.provision(source, unit)
            except (RuntimeError, FileExistsError) as error:
                observations.append({"control": "duplicate-live-creation-refused", "error": str(error)})
            else:
                raise RuntimeError("duplicate provisioning unexpectedly accepted")
            wrong = copy.deepcopy(record)
            wrong["sha256"] = "0" * 64
            try:
                self.cleanup(unit, wrong)
            except RuntimeError as error:
                require(str(error) == "receipt differs from root-only lease",
                        "wrong-copy refusal must happen before manager mutation")
                observations.append({"control": "forged-evidence-copy-refused", "error": str(error)})
            else:
                raise RuntimeError("forged evidence copy unexpectedly accepted")
            state = self.loaded_matches(record)
            require(state["ActiveState"] == "active" and self.root_lease(unit) == record,
                    "negative controls mutated the original live parent or lease")
        finally:
            cleaned = self.cleanup(unit, record)
        return {"probe_unit": unit, "negative_controls": observations, "cleanup": cleaned}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("probe", "provision", "cleanup", "cleanup-probe"))
    parser.add_argument("--owner", required=True)
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    events = []
    result = {"schema": "history-fixed-parent-fixture-v2", "action": args.action,
              "events": events, "complete_success": False,
              "root_only_lease_is_authority": True, "outer_four_cpu_budget_unchanged": True,
              "fixed_parent_is_a_ceiling_not_physical_reservation": True}
    try:
        require(os.geteuid() == 0, "root needed for exclusive systemd fixture lease")
        manager = Manager(args.owner, events)
        if args.action in ("cleanup", "cleanup-probe"):
            unit = FIXED_UNIT if args.action == "cleanup" else probe_unit(args.owner)
            if not os.path.lexists(ROOT / unit):
                result["cleanup"] = {"no_owned_lease": True, "no_unit_mutated": True}
            else:
                result["cleanup"] = manager.cleanup(unit)
        else:
            require(args.source is not None, "source-pinned slice file required")
            if args.action == "probe":
                result["probe"] = manager.probe(args.source)
            else:
                result["lease"] = manager.provision(args.source, FIXED_UNIT)
        result["complete_success"] = True
    except Exception as error:
        result["failure"] = {"type": type(error).__name__, "message": str(error)}
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["complete_success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
