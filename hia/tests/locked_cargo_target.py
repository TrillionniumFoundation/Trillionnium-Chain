"""Process-local build storage for the two exact General C Rust oracles.

No result, compiler event, adapter executable or test data is reused. Cargo
validates every current invocation; this additionally fences the shared output.
"""
from __future__ import annotations

import atexit
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import threading


PACKAGES = frozenset({"trnm-service-settlement", "trnm-sqlite-io-boundary"})
_LOCAL = threading.local()


def _identity(path):
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Expected a regular Cargo input")
        sha = hashlib.file_digest(stream, "sha256").hexdigest()
        stamp = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
        if stamp(before) != stamp(os.fstat(stream.fileno())) or stamp(before) != stamp(path.stat()):
            raise ValueError("Cargo identity changed while reading")
    return before.st_size, sha


def _context(root, rustc, cargo, env):
    cwd = Path.cwd().resolve(strict=True)
    git = lambda *args: subprocess.run(["git", *args], cwd=root, check=True, capture_output=True,
                                       timeout=10).stdout
    git("diff", "--quiet", "HEAD", "--", "trillionnium", "rust-toolchain.toml", ".cargo")
    inputs = [root / "trillionnium" / p for p in ("Cargo.toml", "Cargo.lock")]
    inputs.append(root / "rust-toolchain.toml")
    cargo_home = Path(env.get("CARGO_HOME") or (Path.home() / ".cargo")).absolute()
    config_roots = [cargo_home, *(d / ".cargo" for d in (cwd, *cwd.parents))]
    inputs += [d / name for d in config_roots for name in ("config", "config.toml")
               if (d / name).exists()]
    for command in (rustc, cargo):
        resolved = shutil.which(command, path=env.get("PATH"))
        if not resolved:
            raise ValueError("Missing selected original Cargo tool")
        inputs.append(Path(resolved).resolve(strict=True))
    env_digest = hashlib.sha256(json.dumps(env, sort_keys=True, separators=(",", ":")).encode()).digest()
    return (root, cwd, git("rev-parse", "HEAD", "HEAD^{tree}"),
            tuple((p, _identity(p)) for p in inputs), env_digest)


def _artifact(target, value):
    path = Path(value)
    if not path.is_absolute() or not path.is_relative_to(target) or path.resolve(strict=True) != path:
        raise ValueError("Cargo emitted artifact outside the exact private target")
    return path


def _snapshot(target, events):
    files = set()
    for event in events:
        if event.get("reason") == "compiler-artifact":
            files.update(_artifact(target, name) for name in event["filenames"])
        if (event.get("reason") == "build-script-executed"
                and event["package_id"].endswith("libsqlite3-sys@0.39.1")):
            [linked_path] = event["linked_paths"]
            if event["linked_libs"] != ["static=sqlite3"] or not linked_path.startswith("native="):
                raise ValueError("Original Cargo output lacks the fixed bundled SQLite")
            files.add(_artifact(target, Path(linked_path[7:]) / "libsqlite3.a"))
    if not files:
        raise ValueError("No current Cargo artifact output")
    return {p: _identity(p) for p in sorted(files)}


class _Target:
    def __init__(self, package, context):
        self.context = context
        self.output = None
        self.usable = True
        self.path = Path(tempfile.mkdtemp(prefix="trnm-general-c-" + package + "-")).resolve(strict=True)
        pid = os.getpid()

        def remove():
            if os.getpid() == pid:
                shutil.rmtree(self.path)

        atexit.register(remove)


def locked_cargo_build(root, *, rustc, cargo, package, execute):
    """Return this successful Cargo invocation's target and JSON, never a cache hit."""
    if package not in PACKAGES:
        raise ValueError("Unregistered original Cargo package")
    root = Path(root).resolve(strict=True)
    env = {**os.environ, "RUSTC": rustc, "CARGO_BUILD_JOBS": "2"}
    context = _context(root, rustc, cargo, env)
    pid = os.getpid()
    if getattr(_LOCAL, "pid", None) != pid:
        _LOCAL.pid, _LOCAL.targets = pid, {}
    target = _LOCAL.targets.get(package)
    if target is None:
        target = _LOCAL.targets[package] = _Target(package, context)
    if not target.usable or target.context != context:
        raise ValueError("Original Cargo private target context changed or failed")
    target.usable = False
    if target.output is not None and any(_identity(p) != wanted for p, wanted in target.output.items()):
        raise ValueError("Private original Cargo artifacts changed")
    answer = execute([cargo, "build", "--locked", "--offline", "--manifest-path",
                      str(root / "trillionnium/Cargo.toml"), "--target-dir", str(target.path),
                      "-p", package, "--message-format=json"], timeout=160, env=env)
    events = [json.loads(line) for line in answer.stdout.splitlines()]
    if _context(root, rustc, cargo, env) != context:
        raise ValueError("Original Cargo inputs changed during build")
    before = target.output
    target.output = _snapshot(target.path, events)
    if before is not None and before != target.output:
        raise ValueError("Current Cargo artifact census differs from the exact prior build")
    target.usable = True
    return target.path, events
