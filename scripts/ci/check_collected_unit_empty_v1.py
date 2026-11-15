#!/usr/bin/env python3
"""Observe collection of an exact finite CI service; never stop or remove it.

The systemd service owner retains RuntimeMaxSec, TimeoutStopSec and KillMode.
An EXIT trap has no creation/InvocationID authority: a failed create may have
collided with somebody else's unit. This observer therefore grants no cleanup
authority, including after cancellation. UNKNOWN/error is never EMPTY.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "formal/pon-nakamoto-v1"))
from bounded_process import ProcessFailure, run_bounded

CGROUP_ROOT = Path("/sys/fs/cgroup")
SYSTEMD_ROOT = Path("/run/systemd")
QUERY_SECONDS = 3.0
OBSERVATION_SECONDS = 15.0
STDOUT_LIMIT = 65536
STDERR_LIMIT = 8192
MAX_OBSERVATIONS = 4
# No inherited remote/user bus, pager, credential, or executable overrides.
COMMAND_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
               "SYSTEMD_PAGER": "cat", "SYSTEMD_PAGERSECURE": "1",
               "SYSTEMD_COLORS": "0", "SYSTEMD_URLIFY": "0"}


class Residual(ValueError):
    """A successful observation of something still present, not a read error."""


def unit_name(value: str) -> str:
    ordinary = r"trnm-(?:native-campaign|native-history-lifeline|history-graph-v1)"
    identity = r"[1-9][0-9]{0,19}-[1-9][0-9]{0,9}"
    pattern = rf"(?:{ordinary}-{identity}|trnm-pure-admission-daa-{identity}-(?:x64|arm64))\.service"
    if re.fullmatch(pattern, value) is None:
        raise ValueError("exact supported run/attempt service name required")
    return value


def loaded_command(unit: str) -> list[str]:
    return ["/usr/bin/systemctl", "--system", "--no-ask-password", "list-units",
            "--all", "--full", "--no-legend", "--no-pager", "--output=json", unit]


def files_command(unit: str) -> list[str]:
    # A successful typed empty array, unlike list-unit-files' ambiguous exit 1.
    return ["/usr/bin/busctl", "--system", "--no-pager", "--timeout=3s", "call",
            "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager", "ListUnitFilesByPatterns",
            "asas", "0", "1", unit]


def identity(value: os.stat_result) -> dict:
    return {"device": value.st_dev, "inode": value.st_ino, "mode": value.st_mode,
            "uid": value.st_uid, "gid": value.st_gid}


def open_directory(path: Path) -> int:
    """Resolve every component without following a symlink; caller closes FD."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute fixed directory required")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


class Observer:
    def __init__(self, unit: str):
        self.unit = unit_name(unit)
        self.deadline = time.monotonic() + OBSERVATION_SECONDS
        self.report = {"schema": "pon-collected-unit-empty-v1", "unit": self.unit,
                       "read_only": True, "complete": False, "state": "UNRESOLVED",
                       "started_monotonic_ns": time.monotonic_ns(), "commands": [],
                       "paths": [], "observations": [], "failure": None,
                       "scope": "Fresh local-system absence only; no authority to mutate a unit or revise a native result."}

    def query(self, label: str, argv: list[str]) -> str:
        row = {"label": label, "argv": argv, "returncode": None, "stdout": "",
               "stderr": "", "error": None, "stdout_truncated": False,
               "stderr_truncated": False, "started_monotonic_ns": time.monotonic_ns()}
        self.report["commands"].append(row)
        try:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise ValueError("observation deadline exhausted")
            result = run_bounded(argv, b"", timeout=min(QUERY_SECONDS, left),
                                 stdout_limit=STDOUT_LIMIT, stderr_limit=STDERR_LIMIT,
                                 env=COMMAND_ENV.copy())
            row.update(returncode=result.returncode,
                       stdout=result.stdout.decode("utf-8", "backslashreplace"),
                       stderr=result.stderr.decode("utf-8", "backslashreplace"))
            # Invalid UTF-8, diagnostics, and every nonzero exit are unknown.
            result.stdout.decode("utf-8")
            result.stderr.decode("utf-8")
            if type(result.returncode) is not int or result.returncode != 0 or result.stderr:
                raise ValueError("query did not succeed without diagnostics")
            return row["stdout"]
        except ProcessFailure as error:
            row.update(returncode=error.returncode,
                       stdout=error.stdout.decode("utf-8", "backslashreplace"),
                       stderr=error.stderr.decode("utf-8", "backslashreplace"),
                       stdout_truncated=error.stdout_truncated,
                       stderr_truncated=error.stderr_truncated, error=str(error))
            raise ValueError(f"{label}: {error}") from error
        except (ValueError, OSError) as error:
            row["error"] = f"{type(error).__name__}: {error}"
            raise ValueError(f"{label}: {error}") from error
        finally:
            row["ended_monotonic_ns"] = time.monotonic_ns()

    def loaded_absent(self, label: str) -> None:
        raw = self.query(label, loaded_command(self.unit))
        try:
            rows = json.loads(raw)
        except (ValueError, RecursionError) as error:
            raise ValueError("invalid manager JSON") from error
        if type(rows) is not list:
            raise ValueError("manager response is not an array")
        if rows:
            # Only a complete, successful presence observation may be polled.
            required = ("unit", "load", "active", "sub", "description")
            if any(type(row) is not dict or row.get("unit") != self.unit
                   or any(type(row.get(key)) is not str for key in required) for row in rows):
                raise ValueError("malformed or foreign manager rows")
            raise Residual("manager still has this exact unit")

    def path_absent(self, base: Path, parts: tuple[str, ...]) -> None:
        row = {"path": str(base.joinpath(*parts)), "absent": False,
               "error": None, "parents": [], "started_monotonic_ns": time.monotonic_ns()}
        self.report["paths"].append(row)
        fd = None
        try:
            fd = open_directory(base)
            current = base
            for index, name in enumerate(parts):
                row["parents"].append({"path": str(current), **identity(os.fstat(fd))})
                try:
                    found = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError as error:
                    # No lexists()/exists(): EACCES, EIO, ENOTDIR, etc. must fail.
                    if error.errno != errno.ENOENT:
                        raise
                    row.update(absent=True, absent_at=str(current / name), errno=error.errno)
                    return
                if index == len(parts) - 1:
                    row["present_identity"] = identity(found)
                    raise Residual("kernel or runtime unit path still exists")
                if not stat.S_ISDIR(found.st_mode):
                    raise ValueError("path parent is not a real directory")
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                dir_fd=fd)
                if identity(os.fstat(child)) != identity(found):
                    os.close(child)
                    raise ValueError("path parent changed during observation")
                os.close(fd)
                fd = child
                current /= name
        except (OSError, ValueError) as error:
            row["error"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            if fd is not None:
                os.close(fd)
            row["ended_monotonic_ns"] = time.monotonic_ns()

    def observe(self) -> None:
        self.loaded_absent("manager-before")
        magic = self.query("cgroup-filesystem", ["/usr/bin/stat", "--file-system", "--format=%t",
                                                 "--", str(CGROUP_ROOT)])
        if magic.strip() != "63677270":  # Linux CGROUP2_SUPER_MAGIC.
            raise ValueError("expected actual cgroup v2 filesystem")
        # These six callers use the existing default system.slice, with no
        # alternate Slice=, scope, delegation, or changed runtime limits.
        self.path_absent(CGROUP_ROOT, ("system.slice", self.unit))
        for directory in ("transient", "system", "system.control"):
            for name in (self.unit, self.unit + ".d"):
                self.path_absent(SYSTEMD_ROOT, (directory, name))
        raw = self.query("unit-files", files_command(self.unit))
        if raw.strip() != "a(ss) 0":
            raise ValueError("unit files are not a successful typed empty array")
        self.loaded_absent("manager-after")

    def run(self) -> dict:
        try:
            for number in range(1, MAX_OBSERVATIONS + 1):
                observation = {"number": number, "started_monotonic_ns": time.monotonic_ns()}
                self.report["observations"].append(observation)
                try:
                    self.observe()
                except Residual as error:
                    observation["residual"] = str(error)
                    if number == MAX_OBSERVATIONS or self.deadline - time.monotonic() <= 0.1:
                        raise
                    # --wait may return just before --collect finishes. Retry
                    # only known presence, never a failed/unknown observation.
                    time.sleep(0.1)
                else:
                    self.report.update(complete=True, state="EMPTY")
                    break
                finally:
                    observation["ended_monotonic_ns"] = time.monotonic_ns()
        except (OSError, ValueError) as error:
            self.report["failure"] = f"{type(error).__name__}: {error}"
        finally:
            self.report["ended_monotonic_ns"] = time.monotonic_ns()
        return self.report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", required=True)
    args = parser.parse_args()
    try:
        report = Observer(args.unit).run()
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(report, sort_keys=True))
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
