#!/usr/bin/env python3
"""Reviewed, fail-closed publisher for one frozen Chain native validation.

This program is a review artifact until explicitly invoked with --publish.
It never changes a test threshold, repairs source, reruns an uncertain
supplement, forces a branch, merges, approves, or activates a deployment.
"""
from __future__ import annotations

import argparse
import ast
import copy
import codecs
import fcntl
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import time

ROOT = Path("/home/qian-qi/work/chain-root-operation-recovered-20261112-df05")
OUT = None  # Required reviewed invocation input; never silently select a failed run.
STATE = Path("/home/qian-qi/work/chain-root-publication-20261112-df05-v1")
PREFIX = "evidence/root-execution-v6-20261112-df05"
CORPUS = "config/pon/pq-cross-branch-corpus-v1.json"
REPO = "TrillionniumFoundation/Trillionnium-Chain"
ORIGIN = "https://github.com/" + REPO + ".git"
BRANCH = "fix/chain-root-operation-recovered-20261112-df05"
BASE_BRANCH = "fix/pq-root-v5-copied-lease-integration-20261112-8970e2c"
BASE = "8970e2c81abbf48e2a4d3f0802d79624ab20fadd"
TREE = "b1882c2e46827abfd1db5f8744be043d5776df6d"
CLOUD = "87bf6bb07c4ccdd75741cfb79c7447d8d8c54758"
DRIVER_SHA = None
RUN_KEY = None
PUB_KEY = "root-operation-20261112-df05-native-publication-v1"
CAP = 4 * 1024 * 1024
TOOLCHAIN = Path("/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin")
PROVIDER = Path("/home/qian-qi/credit-envelope-f7e62-provider2/runner/trnm-pq-provider-3.5.9.5yXdk2mN/install")
PROVIDER_HASHES = {
    "bin/openssl": "41d5b79f937beed7f94d9623be504db72c5048fcd952965fc0e13305d2802a33",
    "include/openssl/opensslv.h": "9647fc99758cf83e3bcf11ae310894fd4911ad62bff22d8213a614df89cfedda",
    "include/openssl/configuration.h": "406c26f93511299b264062f9f3faf0760e7a0506e91a61717c491f3c92e1a996",
    "lib/libcrypto.a": "005a0f7d9f6a073e6530cc556c90b3c415df7c6bc2475e333d29aa9bfa409bfb",
    "lib/libssl.a": "f355167951857505b5b0305fd2e8ea8f224fa29d780211175d32767b07234727",
}
PRIOR_PATH = Path("/home/qian-qi/work/chain-root-prior-evidence-20261112-df05-v2/root-prior-evidence-selected-v2.tar.gz")
PRIOR_SHA = "44afa64b3e222914e7301ddb4e1a7178fa651069bfad9076615af0e1439f1024"
PRIOR_BYTES = 73802
FAILED_V1 = Path("/home/qian-qi/work/chain-root-validation-20261112-df05-v1")
FAILED_V1_DRIVER = "65addcbeb56eff0214b46eaaca02ba3389698f6e29c9ff54de85033254abff6f"
SOCKET_NAMES = (
    "rejected_nonprivate_socket_parent_does_not_unlink_existing_listener",
    "different_admitted_journal_cannot_replace_a_live_checkpoint_endpoint",
    "copied_lease_record_cannot_replace_a_live_checkpoint_endpoint",
)
SUITES = {
    "root-v5-v6": ("run_pq_root_witness_v5.py", (
        ("fresh-witness", "WITNESS", "", 17),
        ("durable-witness", "DURABLE", "", 12),
        ("provider-readback", "PROVIDER_READBACK", "", 14),
        ("retained-receipts", "RECEIPTS", "", 7))),
    "root-v4": ("run_pq_root_continuation_v4.py", (
        ("recovery-floor", "FLOOR", "", 9),
        ("provider-readback", "PROVIDER", "", 14),
        ("callback-budget", "CALLBACK_BUDGET", "", 6))),
    "root-v3": ("run_pq_root_native_v3.py", (
        ("crypto-structure", "CRYPTO_STRUCTURE", "pq_root_v3::tests::", 10),
        ("crypto-native", "CRYPTO_NATIVE", "", 8),
        ("root-kernel", "KERNEL", "root_recovery_v3::tests::", 12),
        ("root-owner", "OWNER", "", 20))),
}
BASE_ARTIFACTS = {
    "driver.py", "invocation.json", "source-reconstruction.json",
    "environment.json", "source-before.json", "plan.json", "commands.json",
    "source-after.json", "SUMMARY.json",
}
FALSE_CLAIMS = (
    "production_activation", "whole_chain_pq_qualified", "independent_custody_verified",
    "actual_external_effects_verified", "native_m15_production_integration_complete",
    "publication_performed",
)
SECRETS = [
    re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    re.compile(rb"(?i)\bauthorization\s*[:=]\s*[\"']?(?:bearer|basic)\s+[A-Za-z0-9_+/=.-]{20,}"),
    re.compile(rb"(?i)\b(?:GH_TOKEN|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*[\"']?[A-Za-z0-9_+/=.-]{20,}"),
]


class Refuse(RuntimeError):
    pass


def need(value, message):
    if not value:
        raise Refuse(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def h256(value):
    return hashlib.sha256(value).hexdigest()


def digest_ok(value, length=64):
    return type(value) is str and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None


def strict_json(raw):
    def pairs(items):
        answer = {}
        for key, value in items:
            need(key not in answer, "duplicate JSON key")
            answer[key] = value
        return answer
    def bad(value):
        raise Refuse("nonfinite JSON number")
    def floating(value):
        number = float(value)
        need(math.isfinite(number), "nonfinite JSON number")
        return number
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=bad, parse_float=floating)


def relative(name):
    need(type(name) is str and name and len(name) <= 4096, "invalid artifact path")
    need("\\" not in name and not any(ord(c) < 32 for c in name), "ambiguous artifact path")
    path = PurePosixPath(name)
    need(not path.is_absolute() and str(path) == name, "noncanonical artifact path")
    need(all(p not in ("", ".", "..") for p in path.parts), "path traversal")
    need(not any(p.lower() in ("tmp", "pycache", "__pycache__", ".git", ".ssh", ".aws")
                 or re.search(r"(?i)(credential|password|passwd|secret|token|id_rsa|id_ed25519)", p)
                 for p in path.parts), "forbidden artifact path")
    return path


def ensure_dirs(path):
    need(path.is_absolute(), "absolute directory required")
    here = Path(path.anchor)
    for part in path.parts[1:]:
        here /= part
        try:
            info = here.lstat()
        except FileNotFoundError:
            here.mkdir(mode=0o700)
            info = here.lstat()
        need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
             "non-directory or symlink in directory chain")


def directory_fd(path):
    need(path.is_absolute(), "absolute parent directory required")
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            need(part not in (".", ".."), "noncanonical directory component")
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_regular(path, allow_hardlinks=False):
    path = Path(path)
    need(path.is_absolute(), "absolute file required")
    fd = directory_fd(path.parent)
    stream = None
    try:
        name = path.name
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode), "nonregular file: " + str(path))
        need(allow_hardlinks or before.st_nlink == 1, "hardlinked artifact")
        stream = os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                  dir_fd=fd), "rb")
        need(fingerprint(os.fstat(stream.fileno())) == fingerprint(before), "file admission race")
        return fd, name, before, stream
    except BaseException:
        if stream is not None:
            stream.close()
        os.close(fd)
        raise


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def chunks(path, allow_hardlinks=False):
    fd, name, before, stream = open_regular(path, allow_hardlinks)
    try:
        with stream:
            for block in iter(lambda: stream.read(CAP), b""):
                yield block
            need(fingerprint(os.fstat(stream.fileno())) == fingerprint(before), "file changed during read")
        need(fingerprint(os.stat(name, dir_fd=fd, follow_symlinks=False)) == fingerprint(before),
             "file name changed during read")
    finally:
        os.close(fd)


def file_identity(path, allow_hardlinks=False, scan=False):
    digest, size, tail = hashlib.sha256(), 0, b""
    for block in chunks(path, allow_hardlinks):
        if scan:
            inspect_credentials(tail + block)
            tail = block[-1024:]
        size += len(block)
        digest.update(block)
    return {"bytes": size, "sha256": digest.hexdigest()}


def read_small(path, cap=CAP, scan=False):
    result = bytearray()
    for block in chunks(path):
        need(len(result) + len(block) <= cap, "oversized metadata")
        result.extend(block)
    value = bytes(result)
    if scan:
        inspect_credentials(value)
    return value


def jread(path):
    return strict_json(read_small(path))


def inspect_credentials(value):
    need(not any(pattern.search(value) for pattern in SECRETS), "recognized credential material")


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create_exact(path, value):
    """Create once; an identical already-complete file is a reconciled write."""
    ensure_dirs(path.parent)
    parent = directory_fd(path.parent)
    try:
        try:
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
        except FileExistsError:
            need(read_small(path, max(CAP, len(value))) == value,
                 "existing immutable file differs: " + str(path))
            return
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def archive_mode(path):
    parent, name, before, stream = open_regular(path)
    try:
        os.fchmod(stream.fileno(), 0o644)
        os.fsync(stream.fileno())
    finally:
        stream.close()
        os.close(parent)


def create_json(path, value):
    create_exact(path, canonical(value))


def clean_env(selected=None):
    env = dict(os.environ)
    for key in list(env):
        if (key.startswith("GIT_") or key.startswith("CARGO_PROFILE_")
                or key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                           "RUSTC_WORKSPACE_WRAPPER", "PYTHONPATH", "PYTHONSTARTUP")):
            env.pop(key, None)
    if selected:
        env.update(selected)
    # Preserve the native administrator's ordinary author/signing configuration.
    # Process-level Git injection is removed above; no local/global config is edited.
    env.update(GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0",
               PYTHONDONTWRITEBYTECODE="1", GH_HOST="github.com",
               GH_PROMPT_DISABLED="1", GH_PAGER="cat")
    return env


def command(argv, *, env=None, timeout=180, check=True, stdin=None):
    result = subprocess.run(argv, cwd=ROOT, env=env or clean_env(),
                            input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
    if check and result.returncode != 0:
        raise Refuse("command failed (" + str(result.returncode) + "): " + str(argv[0]))
    return result


def git(*args, check=True):
    return command(["git", "--no-replace-objects", *args], check=check)


def gtext(*args):
    return git(*args).stdout.decode("utf-8").strip()


def entries(commit):
    answer = {}
    for row in git("ls-tree", "-r", "-l", "-z", "--full-tree", commit).stdout.split(b"\0"):
        if row:
            meta, name = row.split(b"\t", 1)
            mode, kind, blob, size = meta.split()
            need(kind == b"blob" and size.isdigit() and mode in (b"100644", b"100755", b"120000"),
                 "unsupported tracked source entry")
            answer[name.decode("utf-8")] = (mode.decode(), blob.decode(), int(size))
    return answer


def blob_id(value):
    return hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value,
                        usedforsecurity=False).hexdigest()


def symlink_blob(path, size):
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = following
        before = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISLNK(before.st_mode), "tracked symlink type changed")
        value = os.fsencode(os.readlink(path.name, dir_fd=fd))
        need(len(value) == size and
             fingerprint(os.stat(path.name, dir_fd=fd, follow_symlinks=False)) == fingerprint(before),
             "tracked symlink changed while reading")
        return blob_id(value)
    finally:
        os.close(fd)


def physical_tree(commit, *, dirty_evidence=False, overrides=None, evidence_paths=None):
    """Independent full Git mode/blob read, followed by the repository verifier later."""
    need(digest_ok(commit, 40), "noncanonical source commit")
    need(Path(gtext("rev-parse", "--show-toplevel")) == ROOT, "wrong worktree root")
    need(gtext("rev-parse", "HEAD") == commit, "unexpected checked-out commit")
    need(not gtext("for-each-ref", "--format=%(refname)", "refs/replace/"), "replacement refs")
    graft = Path(gtext("rev-parse", "--git-path", "info/grafts"))
    if not graft.is_absolute():
        graft = ROOT / graft
    need(not os.path.lexists(graft), "grafted history")
    flags = git("ls-files", "-v", "-z").stdout.split(b"\0")
    need(not any(x and (x[:1].islower() or x[:1] == b"S") for x in flags),
         "hidden index flags")
    for name, (mode, expected, size) in entries(commit).items():
        path = ROOT / name
        if overrides and name in overrides:
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode) and not bool(info.st_mode & 0o111),
                 "archival metadata mode changed")
            value = read_small(path)
            need(value in overrides[name], "unauthorized archival metadata content")
            continue
        if mode == "120000":
            need(symlink_blob(path, size) == expected, "tracked symlink differs")
            continue
        info = path.lstat()
        need(bool(info.st_mode & 0o111) == (mode == "100755"), "tracked mode changed")
        digest = hashlib.sha1(b"blob " + str(size).encode() + b"\0", usedforsecurity=False)
        observed = 0
        for part in chunks(path, allow_hardlinks=True):
            observed += len(part)
            digest.update(part)
        need(observed == size and digest.hexdigest() == expected, "tracked source bytes differ: " + name)
    if dirty_evidence:
        changed = set(git("diff", "--name-only", "-z", commit).stdout.decode().split("\0")) - {""}
        untracked = set(git("ls-files", "--others", "--exclude-standard", "-z").stdout.decode().split("\0")) - {""}
        need(evidence_paths is not None and
             changed | untracked <= set(evidence_paths) | {CORPUS},
             "unrelated local changes")
    else:
        need(not git("status", "--porcelain", "--untracked-files=all",
                     "--ignore-submodules=none").stdout, "source is not completely clean")
    need(gtext("rev-parse", "HEAD") == commit, "HEAD changed while reading")
    return {"commit": commit, "tree": gtext("rev-parse", commit + "^{tree}"),
            "tracked_entries": len(entries(commit)), "physical_bytes_checked": True}


def repository_identity():
    need(gtext("branch", "--show-current") == BRANCH, "wrong development branch")
    need(re.fullmatch(r"(feature|fix|chore|docs|test)/chain-[a-z0-9][a-z0-9._-]*", BRANCH),
         "invalid development branch")
    need(gtext("remote", "get-url", "--all", "origin") == ORIGIN, "wrong canonical origin")
    need(gtext("remote", "get-url", "--push", "--all", "origin") == ORIGIN, "wrong push origin")


def planned_commands(env):
    cargo = str(TOOLCHAIN / "cargo")
    metadata = [cargo, "metadata", "--locked", "--offline", "--format-version", "1"]
    py = ["/usr/bin/python3", "-B"]
    return [
        ("preflight", ["bash", "scripts/project-preflight.sh"], 120),
        ("rustc-version", [str(TOOLCHAIN / "rustc"), "-Vv"], 120),
        ("cargo-version", [cargo, "-V"], 120),
        ("openssl-version", [str(PROVIDER / "bin/openssl"), "version", "-a"], 120),
        ("metadata-default", metadata + ["--manifest-path", "trillionnium/Cargo.toml"], 300),
        ("metadata-all-features", metadata + ["--all-features", "--manifest-path", "trillionnium/Cargo.toml"], 300),
        ("metadata-fuzz", metadata + ["--manifest-path", "tests/fuzz/Cargo.toml"], 300),
        ("format", [cargo, "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"], 300),
        ("source-integrity-controls", py + ["-m", "unittest", "discover", "-s", "scripts/ci", "-p", "test_ci_source_integrity.py", "-v"], 600),
        ("root-gate-controls", py + ["-m", "unittest", "discover", "-s", "scripts/ci", "-p", "test_pq_root_dependency_register.py", "-v"], 600),
        ("root-runner-controls", py + ["-m", "unittest", "discover", "-s", "scripts/ci", "-p", "test_run_pq_root_witness_v5.py", "-v"], 600),
        ("repository-links", py + ["scripts/ci/check_repository.py"], 600),
        ("research-corpus", py + ["scripts/ci/check_pq_research_integration.py"], 600),
        ("root-dependency-register", py + ["scripts/ci/pq_root_dependency_register.py"], 600),
        ("source-inventory", py + ["scripts/refresh_distributed_source_inventory.py", "--check"], 300),
        ("root-v5-v6", py + ["scripts/ci/run_pq_root_witness_v5.py", "--out", str(OUT / "root-v5-v6")], 5400),
        ("root-v4", py + ["scripts/ci/run_pq_root_continuation_v4.py", "--out", str(OUT / "root-v4")], 4200),
        ("root-v3", py + ["scripts/ci/run_pq_root_native_v3.py", "--out", str(OUT / "root-v3")], 5400),
        ("strict-workspace-clippy", [cargo, "clippy", "--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml",
                                   "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"], 3600),
    ]


def checked_environment(source):
    document = jread(OUT / "environment.json")
    need(document["source"] == source and document["tree"] == TREE, "environment source mismatch")
    env = document["environment"]
    target = env.get("CARGO_TARGET_DIR")
    version = OUT.name.rsplit("-", 1)[1]
    target_name = "chain-root-operation-v6-df05-target-" + version
    need(target in ("/data/" + target_name, "/home/qian-qi/work/" + target_name),
         "wrong target isolation")
    expected = {
        "PATH": str(TOOLCHAIN) + ":/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin",
        "CARGO_HOME": "/home/qian-qi/.cargo", "CARGO_TARGET_DIR": target,
        "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0", "CARGO_TERM_COLOR": "never",
        "CARGO_NET_OFFLINE": "true", "RUSTUP_TOOLCHAIN": "1.95.0",
        "RUSTC": str(TOOLCHAIN / "rustc"), "RUSTDOC": str(TOOLCHAIN / "rustdoc"),
        "OPENSSL_DIR": str(PROVIDER), "OPENSSL_STATIC": "1", "OPENSSL_NO_VENDOR": "1",
        "OPENSSL_LIB_DIR": str(PROVIDER / "lib"), "OPENSSL_INCLUDE_DIR": str(PROVIDER / "include"),
        "TRNM_PQ_OPENSSL": str(PROVIDER / "bin/openssl"),
        "TRNM_PQ_OPENSSL_SHA256": PROVIDER_HASHES["bin/openssl"], "TRNM_PQ_OPENSSL_VERSION": "3.5.9",
        "OPENSSL_CONF": "/dev/null", "OPENSSL_MODULES": str(PROVIDER / "lib/ossl-modules"),
        "TMPDIR": str(OUT / "tmp"), "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPYCACHEPREFIX": str(OUT / "pycache"), "GIT_TERMINAL_PROMPT": "0",
    }
    need(env == expected and document["optimization_or_debug_profile_overrides"] is False
         and document["isolated_new_target"] is True, "changed native environment")
    rows = document["provider"]
    need(type(rows) is list and len(rows) == len(PROVIDER_HASHES), "provider inventory")
    observed = {}
    for row in rows:
        need(set(row) == {"path", "bytes", "sha256"} and type(row["bytes"]) is int, "provider row schema")
        path = Path(row["path"])
        rel = str(path.relative_to(PROVIDER))
        need(rel in PROVIDER_HASHES and rel not in observed, "provider path substitution")
        need(row["sha256"] == PROVIDER_HASHES[rel], "provider identity changed")
        need(file_identity(path, allow_hardlinks=True) == {"bytes": row["bytes"], "sha256": row["sha256"]},
             "provider actual bytes changed")
        observed[rel] = row
    need(set(observed) == set(PROVIDER_HASHES), "incomplete provider inventory")
    return env, rows


def wait_finished():
    deadline = time.monotonic() + 21600
    while True:
        need(not os.path.lexists(OUT / "FAILED.json"), "validation FAILED; no publication permitted")
        if os.path.lexists(OUT / "VALIDATION_FINISHED.json"):
            return jread(OUT / "VALIDATION_FINISHED.json")
        need(time.monotonic() < deadline, "validation still UNKNOWN after publisher wait bound")
        time.sleep(min(5, max(0, deadline - time.monotonic())))


def inventories():
    result, commands = {}, {}
    for suite, (script, definitions) in SUITES.items():
        tree = ast.parse(read_small(ROOT / "scripts/ci" / script).decode())
        literals = {n.targets[0].id: ast.literal_eval(n.value)
                    for n in tree.body if isinstance(n, ast.Assign)
                    and isinstance(n.targets[0], ast.Name)
                    and n.targets[0].id in {d[1] for d in definitions}}
        result[suite] = {}
        for name, symbol, prefix, count in definitions:
            values = literals[symbol]
            need(type(values) is tuple and all(type(v) is str for v in values), "test roster type")
            names = tuple(prefix + n for n in values)
            need(len(names) == count and len(set(names)) == count, "test roster incomplete")
            result[suite][name] = names
        # Evaluate only the original static suites definition and its roster constants.
        # No original module top-level imports, subprocess calls, or main are executed.
        selected = [n for n in tree.body if (
            isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
            and n.targets[0].id in literals) or (
            isinstance(n, ast.FunctionDef) and n.name == "suites")]
        namespace = {"__builtins__": {"len": len, "set": set, "tuple": tuple,
                     "any": any, "ValueError": ValueError}}
        exec(compile(ast.Module(body=selected, type_ignores=[]), script, "exec"), namespace)
        exact = namespace["suites"]()
        need([name for name, _, _ in exact] == list(result[suite]), "original suite order changed")
        commands[suite] = {}
        for name, argv, names in exact:
            need(tuple(names) == result[suite][name] and type(argv) is list
                 and all(type(x) is str for x in argv), "original suite definition differs")
            commands[suite][name] = argv
    return result, commands


def libtest(raw, names, code, require_no_filter):
    """Stream observations only; raw bytes are retained separately without truncation."""
    result = {"required": len(names), "observed_counts": None, "complete_success": False}
    summaries, lines, discovery = [], [], []
    patterns = (
        re.compile(r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
                   r"(\d+) measured; (\d+) filtered out; finished in .+$"),
        re.compile(r"^test ([A-Za-z0-9_:]+) \.\.\. (.+)$"),
        re.compile(r"^running (\d+) tests?$"),
    )
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    pending, oversized, invalid = "", False, False

    def observe(line):
        for pattern, output, limit in zip(patterns, (summaries, lines, discovery),
                                          (2, len(names) + 1, 2)):
            match = pattern.fullmatch(line)
            if match and len(output) < limit:
                output.append(match.groups())

    blocks = (raw,) if isinstance(raw, bytes) else raw
    for block in blocks:
        if invalid:
            continue  # Exhaust the regular-file reader so its final race checks run.
        try:
            text = decoder.decode(block)
        except UnicodeError:
            invalid = True
            continue
        for index, part in enumerate(text.split("\n")):
            if index:
                if not oversized:
                    observe(pending)
                pending, oversized = "", False
            if not oversized:
                pending += part
                # An unrelated arbitrary-length compiler line need not consume RAM.
                # A too-long test observation yields no complete success, never truncation.
                if len(pending) > 65536:
                    if pending.startswith(("test ", "running ")):
                        invalid = True
                    pending, oversized = "", True
    if not invalid:
        try:
            pending += decoder.decode(b"", final=True)
        except UnicodeError:
            invalid = True
    if invalid:
        return result
    if pending and not oversized:
        observe(pending)
    discovery = [value[0] for value in discovery]
    if len(summaries) != 1 or discovery != [str(len(names))]:
        return result
    status, passed, failed, ignored, measured, filtered = summaries[0]
    values = list(map(int, (passed, failed, ignored, measured, filtered)))
    seen = [name for name, _ in lines]
    if len(seen) != len(names) or len(set(seen)) != len(seen) or set(seen) != set(names):
        return result
    if any(outcome not in ("ok", "FAILED", "ignored") for _, outcome in lines):
        return result
    if [sum(outcome == label for _, outcome in lines) for label in ("ok", "FAILED", "ignored")] != values[:3]:
        return result
    if sum(values[:4]) != len(names):
        return result
    result["observed_counts"] = dict(zip(("passed", "failed", "ignored", "measured", "filtered_out"), values))
    result["complete_success"] = (code == 0 and status == "ok" and values[:4] == [len(names), 0, 0, 0]
                                  and (not require_no_filter or values[4] == 0))
    return result


def validate_native(finished):
    need(set(finished) == {"source", "tree", "manifest_sha256", "summary_sha256",
                          "all_commands_passed", "status", "publication_performed"}, "FINISHED schema")
    source = finished["source"]
    need(digest_ok(source, 40) and finished["tree"] == TREE, "wrong native source identity")
    need(finished["status"] == "HOLD" and finished["publication_performed"] is False, "FINISHED overclaim")
    manifest_raw, summary_raw = read_small(OUT / "ARTIFACT_MANIFEST.json"), read_small(OUT / "SUMMARY.json")
    need(h256(manifest_raw) == finished["manifest_sha256"] and h256(summary_raw) == finished["summary_sha256"],
         "FINISHED does not bind native metadata")
    manifest, summary = strict_json(manifest_raw), strict_json(summary_raw)
    need(set(manifest) == {"source", "tree", "artifacts"} and manifest["source"] == source
         and manifest["tree"] == TREE, "manifest source/schema")
    need(summary["schema"] == "root-v6-native-validation-v1" and summary["operation_key"] == RUN_KEY
         and summary["source"] == source and summary["tree"] == TREE
         and summary["cloud_source_with_same_tree"] == CLOUD, "native summary identity")
    need(summary["status"] == "HOLD" and summary["source_consistent"] is True
         and summary["provider_unchanged"] is True, "native integrity was not established")
    need(all(summary[k] is False for k in FALSE_CLAIMS), "native summary overclaims")
    roster, original_argv = inventories()
    env, provider = checked_environment(source)
    plan = planned_commands(env)
    actual_plan = jread(OUT / "plan.json")
    need(actual_plan["source"] == source and actual_plan["tree"] == TREE
         and actual_plan["original_inner_runner_limits_unchanged"] is True
         and actual_plan["commands"] == [
             {"name": name, "argv": argv, "outer_timeout_seconds": timeout} for name, argv, timeout in plan],
         "original command plan changed")
    allowed = set(BASE_ARTIFACTS)
    required = set(BASE_ARTIFACTS)
    for name, _, _ in plan:
        allowed.update((name + ".log", name + ".receipt.json"))
        required.update((name + ".log", name + ".receipt.json"))
    for suite, targets in roster.items():
        allowed.update(suite + "/" + name for name in ("source-before.json", "source-after.json", "commands.json", "summary.json"))
        allowed.update(suite + "/" + name + ".log" for name in targets)
    art = {}
    need(type(manifest["artifacts"]) is list, "artifact inventory type")
    for row in manifest["artifacts"]:
        need(type(row) is dict and set(row) == {"path", "bytes", "sha256"}, "artifact row schema")
        name = str(relative(row["path"]))
        need(name in allowed and name not in art and type(row["bytes"]) is int and row["bytes"] >= 0
             and digest_ok(row["sha256"]), "unexpected, duplicate or malformed artifact")
        need(file_identity(OUT / name, scan=True) == {"bytes": row["bytes"], "sha256": row["sha256"]},
             "artifact bytes differ: " + name)
        art[name] = row
    need(required <= set(art), "missing original native artifacts")
    found = set()
    for directory, dirs, files in os.walk(OUT, followlinks=False):
        dirs[:] = [d for d in dirs if d not in ("tmp", "pycache", "__pycache__")]
        for d in dirs:
            need(not (Path(directory) / d).is_symlink(), "symlinked artifact directory")
        for name in files:
            path = Path(directory) / name
            rel = str(path.relative_to(OUT))
            need(not path.is_symlink(), "symlinked artifact")
            if rel not in ("ARTIFACT_MANIFEST.json", "VALIDATION_FINISHED.json"):
                found.add(rel)
    need(found == set(art), "unlisted native artifact or stray temporary")
    need(art["driver.py"]["sha256"] == DRIVER_SHA, "unreviewed native driver")
    invocation = jread(OUT / "invocation.json")
    need(invocation["operation_key"] == RUN_KEY and invocation["driver_sha256"] == DRIVER_SHA
         and invocation["expected_tree"] == TREE and invocation["cloud_source"] == CLOUD
         and invocation["base"] == BASE, "native invocation changed")
    reconstruction = jread(OUT / "source-reconstruction.json")
    need(reconstruction["head"] == source and reconstruction["tree"] == TREE
         and reconstruction["worktree"] == str(ROOT) and reconstruction["branch"] == BRANCH
         and reconstruction["same_full_tree"] is True and reconstruction["expected_cloud_source"] == CLOUD,
         "native reconstruction identity differs")
    before, after = jread(OUT / "source-before.json"), jread(OUT / "source-after.json")
    need(before == after and before["tested_commit"] == source and before["tested_tree"] == TREE
         and before["candidate"] == source and before["kind"] == "head"
         and before["tracked_worktree_verified"] is True, "native source receipts disagree")
    rows = jread(OUT / "commands.json")
    need(rows == summary["commands"] and type(rows) is list and len(rows) == len(plan), "command receipt inventory")
    for row, (name, argv, _) in zip(rows, plan):
        need(row["name"] == name and row["command"] == argv and row["cwd"] == str(ROOT)
             and row["source"] == source and row["expected_source"] == source
             and row["source_verified"] is True and row["source_before_verified"] is True
             and row["source_after_verified"] is True and row["executed"] is True,
             "command/source binding mismatch")
        need(type(row["exit_code"]) is int and type(row["timed_out"]) is bool
             and type(row["process_exit_code"]) is int and type(row["elapsed_ns"]) is int
             and row["elapsed_ns"] >= 0 and row["log"] == name + ".log",
             "command outcome type/path")
        need(row["exit_code"] == (124 if row["timed_out"] else row["process_exit_code"]),
             "original process outcome was relabelled")
        need(row == jread(OUT / (name + ".receipt.json")), "standalone command receipt mismatch")
        need(art[row["log"]]["bytes"] == row["bytes"] and art[row["log"]]["sha256"] == row["sha256"],
             "command log identity mismatch")
    passed = all(row["exit_code"] == 0 for row in rows)
    need(type(summary["all_commands_passed"]) is bool and summary["all_commands_passed"] == passed
         and finished["all_commands_passed"] is passed, "native pass flag inconsistent")
    need(set(summary["suites"]) == set(roster), "suite summary inventory changed")
    observations = {}
    for suite, targets in roster.items():
        declared = summary["suites"][suite]
        path = suite + "/summary.json"
        if path not in art:
            need(declared == {"source": source, "component_execution_passed": False, "summary_missing": True},
                 "missing suite summary was relabelled")
            need(next(r for r in rows if r["name"] == suite)["exit_code"] != 0,
                 "successful runner has no original summary")
            observations[suite] = {"summary_missing": True}
            continue
        actual = jread(OUT / path)
        need(actual == declared and actual["source"] == source and actual["status"] == "HOLD",
             "suite summary identity mismatch")
        commands = actual["commands"]
        need(commands == jread(OUT / suite / "commands.json"), "inner command receipt mismatch")
        need([r["name"] for r in commands] == list(targets), "suite command roster changed")
        observations[suite] = {}
        for row in commands:
            log = suite + "/" + row["log"]
            need(row["source"] == source and row["argv"] == original_argv[suite][row["name"]]
                 and log == suite + "/" + row["name"] + ".log" and log in art
                 and type(row["exit_code"]) is int,
                 "suite log path/source")
            need(row["bytes"] == art[log]["bytes"] and row["sha256"] == art[log]["sha256"],
                 "suite log digest mismatch")
            observation = libtest(chunks(OUT / log), targets[row["name"]], row["exit_code"],
                                  suite == "root-v5-v6")
            observations[suite][row["name"]] = observation
            need((row["error"] is None) == observation["complete_success"],
                 "original suite result contradicts its actual log")
            if observation["complete_success"]:
                need(row["observation"] == {"tests": sorted(targets[row["name"]]),
                     "passed": len(targets[row["name"]]),
                     "filtered_out": observation["observed_counts"]["filtered_out"]},
                     "original suite count was relabelled")
            else:
                need(row["observation"] is None and type(row["error"]) is str,
                     "failed inner observation was relabelled")
            if suite == "root-v5-v6" and row["execution"] is not None:
                execution = row["execution"]
                need(execution["command"] == row["argv"] and execution["cwd"] == str(ROOT)
                     and execution["log"] == row["log"] and execution["executed"] is True
                     and execution["exit_code"] == row["exit_code"],
                     "V5 original process-owner receipt mismatch")
        inner_before = jread(OUT / suite / "source-before.json")
        inner_after = jread(OUT / suite / "source-after.json")
        need(inner_before == inner_after == before, "suite source evidence mismatch")
        need(actual["component_execution_passed"] is all(r["error"] is None for r in commands),
             "suite component status inconsistent")
    return source, manifest, summary, env, provider, observations


def repo_verify(source):
    # Import only after the independent physical mode/blob check admitted the fixed tree.
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(ROOT / "scripts/ci"))
    from verify_ci_source import verify
    return verify("head", source, root=ROOT)


def provider_unchanged(rows):
    for row in rows:
        need(file_identity(Path(row["path"]), allow_hardlinks=True) ==
             {"bytes": row["bytes"], "sha256": row["sha256"]}, "provider changed before publication")


def supplement(source, env, provider):
    directory = STATE / "socket-ownership"
    done = directory / "FINISHED.json"
    argv = ["/home/qian-qi/.cargo/bin/cargo", "+1.95.0", "test", "--locked",
            "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-checkpoint-store",
            "--test", "socket_ownership", "--", "--show-output", "--test-threads=1"]
    binding = {"source": source, "tree": TREE, "operation_key": PUB_KEY + "-socket-ownership",
               "argv": argv, "required_tests": list(SOCKET_NAMES),
               "native_environment_sha256": h256(read_small(OUT / "environment.json")),
               "outer_timeout_seconds": 1200,
               "timeout_scope": "new supplemental outer bound; original tests unchanged"}
    if done.exists():
        receipt = jread(done)
        need(receipt["binding"] == binding, "supplement identity changed")
        expected_names = {"STARTED.json", "cargo-version.log", "cargo-version.receipt.json",
                          "socket-ownership.log", "socket-ownership.receipt.json", "source-after.json"}
        need(set(receipt["files"]) == expected_names and
             {p.name for p in directory.iterdir()} == expected_names | {"FINISHED.json"},
             "supplement file inventory differs")
        need(receipt["status"] == "HOLD" and all(receipt[name] is False for name in (
             "production_activation", "arm_verified", "prospective_merge_verified",
             "original_three_30s_campaigns_verified")), "supplement overclaim")
        for name, identity in receipt["files"].items():
            need(file_identity(directory / str(relative(name))) == identity, "supplement file changed")
        row = jread(directory / "socket-ownership.receipt.json")
        need(receipt["execution"] == row, "supplement execution receipt differs")
        need(jread(directory / "STARTED.json") == binding and
             jread(directory / "source-after.json") == jread(OUT / "source-after.json"),
             "supplement source/binding receipt differs")
        version = jread(directory / "cargo-version.receipt.json")
        need(version["exit_code"] == 0 and version["source_verified"] is True
             and version["expected_source"] == source
             and version["command"] == ["/home/qian-qi/.cargo/bin/cargo", "+1.95.0", "-V"]
             and read_small(directory / "cargo-version.log").strip() == read_small(OUT / "cargo-version.log").strip(),
             "supplement tool identity changed")
        observation = libtest(chunks(directory / "socket-ownership.log"),
                              SOCKET_NAMES, row["exit_code"], True)
        need(row["source_verified"] is True and row["expected_source"] == source
             and row["executed"] is True and row["source_before_verified"] is True
             and row["source_after_verified"] is True and type(row["exit_code"]) is int
             and type(row["timed_out"]) is bool and type(row["process_exit_code"]) is int
             and row["exit_code"] == (124 if row["timed_out"] else row["process_exit_code"])
             and row["command"] == argv and row["cwd"] == str(ROOT)
             and receipt["observation"] == observation, "supplement outcome/source changed")
        return directory, receipt
    need(not (directory / "STARTED.json").exists(),
         "supplement previously admitted but outcome UNKNOWN; reconcile original, never rerun")
    physical_tree(source)
    need(gtext("rev-parse", source + "^{tree}") == TREE, "supplement source tree")
    repo_verify(source)
    provider_unchanged(provider)
    ensure_dirs(directory)
    create_json(directory / "STARTED.json", binding)
    from ci_observation import run
    selected = clean_env(env)
    version = run(["/home/qian-qi/.cargo/bin/cargo", "+1.95.0", "-V"],
                  directory / "cargo-version.log", timeout=120, env=selected,
                  cwd=ROOT, expected_source=source)
    create_json(directory / "cargo-version.receipt.json", version)
    need(version["exit_code"] == 0 and version["source_verified"] is True
         and read_small(directory / "cargo-version.log").strip() == read_small(OUT / "cargo-version.log").strip(),
         "supplement cargo shim differs from native toolchain")
    row = run(argv, directory / "socket-ownership.log", timeout=1200, env=selected,
              cwd=ROOT, expected_source=source)
    create_json(directory / "socket-ownership.receipt.json", row)
    need(row["source_verified"] is True, "supplement source integrity failed")
    provider_unchanged(provider)
    after = repo_verify(source)
    create_json(directory / "source-after.json", after)
    observation = libtest(chunks(directory / "socket-ownership.log"),
                          SOCKET_NAMES, row["exit_code"], True)
    files = {p.name: file_identity(p, scan=True) for p in sorted(directory.iterdir()) if p.is_file()}
    receipt = {"binding": binding, "observation": observation, "execution": row, "files": files,
               "status": "HOLD", "production_activation": False,
               "arm_verified": False, "prospective_merge_verified": False,
               "original_three_30s_campaigns_verified": False}
    create_json(done, receipt)
    return directory, receipt


def own_program():
    argv = getattr(sys, "orig_argv", [])
    if "-c" in argv:
        return argv[argv.index("-c") + 1].encode("utf-8")
    return read_small(Path(__file__).absolute())


def verify_prior():
    value = read_small(PRIOR_PATH)
    need(len(value) == PRIOR_BYTES and h256(value) == PRIOR_SHA, "pinned prior-evidence archive unavailable/changed")
    total = 0
    with tarfile.open(fileobj=io.BytesIO(value), mode="r:gz") as archive:
        seen = set()
        for member in archive:
            name = str(relative(member.name.rstrip("/") if member.isdir() else member.name))
            need(name not in seen, "duplicate prior archive member")
            seen.add(name)
            if member.isdir():
                continue
            need(member.isfile(), "prior archive has nonregular member")
            total += member.size
            need(total <= 64 * CAP and member.size <= CAP, "prior archive exceeds reviewed bounds")
            stream = archive.extractfile(member)
            need(stream is not None, "prior archive member unreadable")
            inspect_credentials(stream.read(CAP + 1))
    return value


def prior_failed_validation():
    """Keep the observed pre-execution v1 failure separate from v2 test outcomes."""
    need(OUT != FAILED_V1 and not os.path.lexists(FAILED_V1 / "VALIDATION_FINISHED.json"),
         "failed historical run cannot be a successful validation")
    failure = jread(FAILED_V1 / "FAILED.json")
    need(failure["operation_key"] == "root-operation-20261112-df05-native-validation-v1"
         and failure["stage"] == "await-source" and failure["records_completed"] == 0
         and failure["no_success_inferred"] is True, "historical v1 failure differs")
    invocation = jread(FAILED_V1 / "invocation.json")
    need(invocation["operation_key"] == failure["operation_key"]
         and invocation["driver_sha256"] == FAILED_V1_DRIVER
         and invocation["expected_tree"] == TREE and invocation["base"] == BASE,
         "historical v1 invocation differs")
    result = []
    for name in ("driver.py", "invocation.json", "FAILED.json"):
        path = FAILED_V1 / name
        identity = file_identity(path, scan=True)
        if name == "driver.py":
            need(identity["sha256"] == FAILED_V1_DRIVER, "historical driver changed")
        result.append((path, "prior/validation-v1-failed/" + name, identity))
    return result


def checked_sealed(binding=None):
    sealed = jread(STATE / "SEALED.json")
    need(type(sealed) is dict and set(sealed) == {"binding", "files"}, "sealed manifest schema")
    if binding is not None:
        need(sealed["binding"] == binding, "sealed publication intent differs")
    files = sealed["files"]
    need(type(files) is dict and files, "empty sealed evidence")
    found = set()
    folder = STATE / "sealed"
    for directory, dirs, names in os.walk(folder, followlinks=False):
        for name in dirs:
            need(not (Path(directory) / name).is_symlink(), "symlinked sealed directory")
        for name in names:
            path = Path(directory) / name
            rel = str(relative(path.relative_to(folder).as_posix()))
            need(rel in files and type(files[rel]) is dict
                 and set(files[rel]) == {"bytes", "sha256"}
                 and type(files[rel]["bytes"]) is int and 0 <= files[rel]["bytes"] <= CAP
                 and digest_ok(files[rel]["sha256"])
                 and file_identity(path) == files[rel], "sealed artifact changed")
            found.add(rel)
    need(found == set(files), "extra or missing sealed artifact")
    return sealed


def publication_binding(source, finished, program):
    return {"operation_key": PUB_KEY, "source": source, "source_tree": TREE,
               "validation_directory": str(OUT), "validation_operation_key": RUN_KEY,
               "validation_driver_sha256": DRIVER_SHA,
               "cloud_same_tree_history_only": CLOUD, "native_manifest_sha256": finished["manifest_sha256"],
               "native_summary_sha256": finished["summary_sha256"], "publisher_sha256": h256(program),
               "branch": BRANCH, "base": BASE, "base_branch": BASE_BRANCH, "repository": REPO}


def seal(source, finished, manifest, summary, observations, supp_dir, supp, program):
    folder = STATE / "sealed"
    marker = STATE / "SEALED.json"
    binding = publication_binding(source, finished, program)
    create_json(STATE / "PUBLICATION_INTENT.json", binding)
    if marker.exists():
        return checked_sealed(binding)
    physical_tree(source)
    repo_verify(source)
    ensure_dirs(folder)
    originals = []
    need(not os.path.lexists(OUT / "FAILED.json"), "validation failed after its FINISHED marker")
    need(jread(OUT / "VALIDATION_FINISHED.json") == finished
         and jread(supp_dir / "FINISHED.json") == supp, "terminal metadata changed before sealing")
    candidates = [(OUT / row["path"], "native/" + row["path"],
                   {"bytes": row["bytes"], "sha256": row["sha256"]}) for row in manifest["artifacts"]]
    manifest_identity = file_identity(OUT / "ARTIFACT_MANIFEST.json")
    need(manifest_identity["sha256"] == finished["manifest_sha256"], "manifest changed before sealing")
    candidates += [(OUT / "ARTIFACT_MANIFEST.json", "native/ARTIFACT_MANIFEST.json", manifest_identity),
                   (OUT / "VALIDATION_FINISHED.json", "native/VALIDATION_FINISHED.json",
                    file_identity(OUT / "VALIDATION_FINISHED.json"))]
    candidates += [(supp_dir / name, "supplemental/" + name, identity)
                   for name, identity in supp["files"].items()]
    candidates += [(supp_dir / "FINISHED.json", "supplemental/FINISHED.json",
                    file_identity(supp_dir / "FINISHED.json"))]
    candidates += prior_failed_validation()
    for index, (path, name, expected_identity) in enumerate(candidates):
        relative(name)
        identity = file_identity(path, scan=True)
        need(identity == expected_identity, "original artifact changed after validation")
        parts, overall, count = [], hashlib.sha256(), 0
        for number, block in enumerate(chunks(path)):
            destination = name if identity["bytes"] <= CAP else f"chunks/{index:05d}/{number:06d}.bin"
            need(len(block) <= CAP, "chunk cap")
            create_exact(folder / destination, block)
            parts.append({"path": destination, "bytes": len(block), "sha256": h256(block)})
            count += len(block)
            overall.update(block)
        if identity["bytes"] == 0:
            create_exact(folder / name, b"")
            parts = [{"path": name, "bytes": 0, "sha256": h256(b"")}]
        need(count == identity["bytes"] and overall.hexdigest() == identity["sha256"], "artifact changed while sealing")
        originals.append({"original_path": name, **identity, "parts": parts})
    create_exact(folder / "publisher.py", program)
    prior = verify_prior()
    create_exact(folder / "prior/root-prior-evidence-selected-v2.tar.gz", prior)
    report = {"schema": "root-v6-publication-package-v1", "binding": binding,
              "native_commands": summary["commands"], "native_suite_observations": observations,
              "supplement": supp, "originals": originals,
              "chunk_byte_cap": CAP, "raw_original_bytes_preserved": True,
              "prior_evidence": {"sha256": PRIOR_SHA, "bytes": PRIOR_BYTES, "complete": False,
                                 "cloud_originals_missing": True,
                                 "note": "Retained prior native failures and explicit gaps; not all original cloud logs."},
              "prior_validation_v1": {"status": "FAILED_BEFORE_EXECUTION",
                                      "stage": "await-source", "rust_tests_executed": False,
                                      "not_a_failure_bearing_FINISHED_run": True},
              "status": "HOLD", "production_activation": False,
              "arm_verified": False, "prospective_merge_verified": False,
              "original_three_30s_campaigns_verified": False}
    create_json(folder / "PUBLICATION_PACKAGE.json", report)
    readme = (
        "# Root V6 native execution evidence — HOLD\n\n"
        f"Tested native source: {source}\n\nSource tree: {TREE}\n\n"
        f"Cloud source {CLOUD} is same-tree history only; these executions retain their native source identity.\n\n"
        "The evidence commit is an archival child. It is not a new test execution.\n\n"
        "[Native summary](native/SUMMARY.json), [command receipts](native/commands.json), "
        "[ordered original-byte and chunk manifest](PUBLICATION_PACKAGE.json), "
        "[copied-Lease supplementary receipt](supplemental/FINISHED.json).\n\n"
        "All native command failures, timeouts and incomplete results remain visible. "
        "Formatting, Python controls and source checks do not substitute for native tests.\n\n"
        "The supplementary complete socket_ownership target uses a new 1200-second outer bound. "
        "Its three original tests and internal bounds are unchanged. A timeout is a failed execution.\n\n"
        "Prior retained native failures and selected reconstruction receipts are in "
        "prior/root-prior-evidence-selected-v2.tar.gz. "
        "That historical archive is explicitly incomplete: original cloud logs remain missing.\n\n"
        "The failed validation-v1 invocation, original driver and FAILED marker are retained under "
        "prior/validation-v1-failed. That attempt stopped while awaiting source and executed no Rust tests.\n\n"
        "ARM, prospective-merge validation, the original three 30-second campaigns, distributed witness "
        "independence, actual external effects and production activation remain unqualified.\n"
    ).encode()
    create_exact(folder / "README.md", readme)
    files = {}
    for path in sorted(folder.rglob("*")):
        if path.is_file():
            name = str(relative(path.relative_to(folder).as_posix()))
            identity = file_identity(path, scan=path.suffix != ".gz")
            need(identity["bytes"] <= CAP, "published file exceeds unchanged corpus cap")
            files[name] = identity
    sealed = {"binding": binding, "files": files}
    create_json(marker, sealed)
    return checked_sealed(binding)


def git_blob(commit, name):
    return git("show", commit + ":" + name).stdout


def expected_corpus(source, sealed):
    original = strict_json(git_blob(source, CORPUS))
    changed = copy.deepcopy(original)
    need(type(original["pinned_blobs"]) is dict and type(original["required_paths"]) is list,
         "corpus grammar changed")
    need(len(set(original["required_paths"])) == len(original["required_paths"]), "duplicate original corpus path")
    for name in sorted(sealed["files"]):
        path = PREFIX + "/" + name
        need(path not in changed["pinned_blobs"] and path not in changed["required_paths"],
             "archive path already has a corpus identity")
        value = read_small(STATE / "sealed" / name)
        changed["pinned_blobs"][path] = blob_id(value)
        changed["required_paths"].append(path)
    # Only these additions are authorized; preserve every other old value.
    check = copy.deepcopy(changed)
    for name in sealed["files"]:
        del check["pinned_blobs"][PREFIX + "/" + name]
    check["required_paths"] = check["required_paths"][:len(original["required_paths"])]
    need(check == original, "corpus unrelated values changed")
    value = canonical(changed)
    need(len(value) <= CAP, "corpus cap exceeded")
    return value


def permitted_delta(source, evidence, sealed, corpus):
    before, after = entries(source), entries(evidence)
    new_paths = {PREFIX + "/" + name for name in sealed["files"]}
    need(not (new_paths & set(before)), "evidence path existed in tested source")
    need(set(after) == set(before) | new_paths, "unexpected added/deleted path")
    for name, entry in before.items():
        expected = ("100644", blob_id(corpus), len(corpus)) if name == CORPUS else entry
        need(after[name] == expected, "existing source/mode changed in evidence child: " + name)
    for name in sealed["files"]:
        value = read_small(STATE / "sealed" / name)
        need(after[PREFIX + "/" + name] == ("100644", blob_id(value), len(value)), "evidence blob/mode changed")
    need(gtext("show", "-s", "--format=%P", evidence) == source, "evidence must be one child of tested source")


def archive_commit(source, sealed, selected):
    corpus = expected_corpus(source, sealed)
    current = gtext("rev-parse", "HEAD")
    if current != source:
        permitted_delta(source, current, sealed, corpus)
        physical_tree(current)
        create_json(STATE / "EVIDENCE_COMMIT.json", {"source": source, "evidence": current, "tree": gtext("rev-parse", current + "^{tree}")})
        return current
    original_corpus = git_blob(source, CORPUS)
    physical_tree(source, dirty_evidence=True, overrides={CORPUS: (original_corpus, corpus)},
                  evidence_paths={PREFIX + "/" + name for name in sealed["files"]})
    command(["bash", "scripts/project-preflight.sh"], env=selected)
    for name, identity in sealed["files"].items():
        value = read_small(STATE / "sealed" / name)
        need({"bytes": len(value), "sha256": h256(value)} == identity, "sealed file changed before copy")
        create_exact(ROOT / PREFIX / name, value)
        archive_mode(ROOT / PREFIX / name)
    existing = read_small(ROOT / CORPUS)
    need(existing in (original_corpus, corpus), "corpus concurrent edit")
    if existing != corpus:
        temp = ROOT / (CORPUS + ".publication-v1.tmp")
        create_exact(temp, corpus)
        need(read_small(ROOT / CORPUS) == original_corpus, "corpus changed before replacement")
        os.replace(temp, ROOT / CORPUS)
        archive_mode(ROOT / CORPUS)
        fsync_directory((ROOT / CORPUS).parent)
    paths = [CORPUS] + [PREFIX + "/" + name for name in sorted(sealed["files"])]
    index_options = ("-c", "core.sparseCheckout=false", "-c", "core.sparseCheckoutCone=false",
                     "-c", "core.ignorestat=false")
    for start in range(0, len(paths), 100):
        git(*index_options, "add", "--", *paths[start:start + 100])
    staged = set(git("diff", "--cached", "--name-only", "-z", source).stdout.decode().split("\0")) - {""}
    need(staged == set(paths), "staged path allowlist differs")
    repository_identity()
    command(["bash", "scripts/project-preflight.sh", "--staged"], env=selected)
    marker = STATE / "EVIDENCE_COMMIT_STARTED.json"
    need(not marker.exists(), "earlier commit outcome UNKNOWN at source HEAD; reconcile, do not recommit")
    create_json(marker, {"source": source, "corpus_sha256": h256(corpus),
                        "sealed_manifest_sha256": h256(read_small(STATE / "SEALED.json"))})
    git(*index_options, "commit", "-m", "test(root): retain exact native V6 validation evidence with HOLD")
    evidence = gtext("rev-parse", "HEAD")
    permitted_delta(source, evidence, sealed, corpus)
    physical_tree(evidence)
    create_json(STATE / "EVIDENCE_COMMIT.json", {"source": source, "evidence": evidence, "tree": gtext("rev-parse", evidence + "^{tree}")})
    return evidence


def final_checks(evidence, selected):
    directory = STATE / "final-source-checks"
    ensure_dirs(directory)
    sys.path.insert(0, str(ROOT / "scripts/ci"))
    from ci_observation import run
    checks = [
        ("preflight", ["bash", "scripts/project-preflight.sh"], 120),
        ("corpus", ["/usr/bin/python3", "-B", "scripts/ci/check_pq_research_integration.py"], 600),
        ("links", ["/usr/bin/python3", "-B", "scripts/ci/check_repository.py"], 600),
        ("root-map", ["/usr/bin/python3", "-B", "scripts/ci/pq_root_dependency_register.py"], 600),
        ("inventory", ["/usr/bin/python3", "-B", "scripts/refresh_distributed_source_inventory.py", "--check"], 300),
    ]
    for name, argv, timeout in checks:
        done = directory / (name + ".receipt.json")
        if done.exists():
            row = jread(done)
            need(row["command"] == argv and row["expected_source"] == evidence
                 and row["exit_code"] == 0 and row["source_verified"] is True
                 and row["log_identity"] == file_identity(directory / (name + ".log")), "final gate receipt mismatch")
            continue
        need(not (directory / (name + ".log")).exists(), "final gate outcome UNKNOWN; do not rerun silently")
        row = run(argv, directory / (name + ".log"), timeout=timeout, env=selected,
                  cwd=ROOT, expected_source=evidence)
        row["log_identity"] = file_identity(directory / (name + ".log"))
        create_json(done, row)
        need(row["exit_code"] == 0 and row["source_verified"] is True, "evidence-child publication gate failed: " + name)
    physical_tree(evidence)
    repo_verify(evidence)


def gh_command(*args, check=True):
    return command(["gh", *args], env=clean_env(), timeout=180, check=check)


def actor():
    observed = gh_command("api", "--hostname", "github.com", "user", "--jq", ".login").stdout.decode().strip()
    need(observed == "ProfHepta", "wrong GitHub actor")


def publication_preflight(source, current):
    actor()
    repository_identity()
    # An old HTTP Authorization header would bypass the deliberately selected gh helper.
    headers = git("config", "--get-regexp", r"^http\..*extraheader$", check=False)
    need(headers.returncode == 1 and not headers.stdout, "Git HTTP extraHeader needs explicit operator reconciliation")
    parent = strict_json(gh_command("pr", "view", "940", "--repo", REPO, "--json",
                                   "state,isDraft,headRefName,headRefOid").stdout)
    need(parent == {"state": "OPEN", "isDraft": True, "headRefName": BASE_BRANCH, "headRefOid": BASE},
         "parent Draft #940 moved or changed state")
    need(remote_head(BASE_BRANCH) == BASE, "integration base moved")
    remote = remote_head(BRANCH)
    if remote is not None:
        need(remote == current or (git("cat-file", "-e", remote + "^{commit}", check=False).returncode == 0
             and git("merge-base", "--is-ancestor", remote, source, check=False).returncode == 0),
             "unexpected remote continuation head")
    existing = locate_pr()
    if existing:
        need(existing["state"] == "OPEN" and existing["isDraft"] is True
             and existing["headRefName"] == BRANCH and existing["baseRefName"] == BASE_BRANCH
             and existing["author"]["login"] == "ProfHepta" and existing["headRefOid"] == remote,
             "existing exact branch/base PR is not the authorized open Draft")


def remote_head(branch):
    # Clear all older helpers; this helper resolves the same gh credentials checked above.
    helper = "!" + shlex.quote(shutil.which("gh") or "gh") + " auth git-credential"
    result = command(["git", "--no-replace-objects", "-c", "credential.helper=",
                      "-c", "credential.helper=" + helper,
                      "ls-remote", "--exit-code", "origin", "refs/heads/" + branch],
                     check=False)
    if result.returncode == 2 and not result.stdout:
        return None
    need(result.returncode == 0, "remote readback unavailable")
    rows = result.stdout.decode().strip().splitlines()
    need(len(rows) == 1, "ambiguous remote head")
    head, ref = rows[0].split()
    need(digest_ok(head, 40) and ref == "refs/heads/" + branch, "remote identity malformed")
    return head


def push(source, evidence, selected):
    actor()
    repository_identity()
    need(remote_head(BASE_BRANCH) == BASE, "base branch moved; requires reconciliation")
    observed = remote_head(BRANCH)
    if observed == evidence:
        create_json(STATE / "PUSH_RECEIPT.json", {"source": source, "evidence": evidence, "remote_head": observed, "repository": REPO})
        return
    attempt = STATE / "PUSH_ATTEMPT.json"
    need(not attempt.exists(), "prior push response/outcome unresolved; readback only")
    if observed is not None:
        need(git("cat-file", "-e", observed + "^{commit}", check=False).returncode == 0
             and git("merge-base", "--is-ancestor", observed, evidence, check=False).returncode == 0,
             "remote branch is neither absent nor a known normal ancestor")
    physical_tree(evidence)
    command(["bash", "scripts/project-preflight.sh"], env=selected)
    update = f"refs/heads/{BRANCH} {evidence} refs/heads/{BRANCH} {observed or '0' * 40}\n".encode()
    command(["bash", "scripts/project-preflight.sh", "--push", "origin", ORIGIN],
            env=selected, stdin=update)
    create_json(attempt, {"source": source, "evidence": evidence, "observed_old": observed,
                          "branch": BRANCH, "repository": REPO, "no_force": True})
    helper = "!" + shlex.quote(shutil.which("gh") or "gh") + " auth git-credential"
    try:
        result = command(["git", "--no-replace-objects", "-c", "credential.helper=",
                          "-c", "credential.helper=" + helper, "push", "origin",
                          evidence + ":refs/heads/" + BRANCH], check=False, timeout=300)
        create_json(STATE / "PUSH_COMMAND.json", {"exit_code": result.returncode,
                    "stdout_sha256": h256(result.stdout), "stderr_sha256": h256(result.stderr)})
    except subprocess.TimeoutExpired:
        create_json(STATE / "PUSH_COMMAND.json", {"response": "UNKNOWN", "no_success_inferred": True})
    # No second push is issued, regardless of command response.
    actual = remote_head(BRANCH)
    need(actual == evidence, "push has not been independently reconciled to exact evidence child")
    create_json(STATE / "PUSH_RECEIPT.json", {"source": source, "evidence": evidence, "remote_head": actual, "repository": REPO})


def pr_body(source, evidence, summary, observations, supp):
    lines = [
        "## HOLD: exact native evidence",
        "",
        f"Native tested source: {source}. Tree: {TREE}. Evidence-only child: {evidence}.",
        f"Cloud commit {CLOUD} is same-tree history only; native receipts retain their actual source.",
        "",
        "This continues the open Draft #940 on its existing integration base. "
        "It does not approve, merge, activate, migrate production state, or qualify independent custody.",
        "",
        "### Native command outcomes", "",
        "| Command | Exit | Timeout |", "| --- | ---: | --- |",
    ]
    lines += [f"| {r['name']} | {r['exit_code']} | {str(r['timed_out']).lower()} |" for r in summary["commands"]]
    lines += ["", "### Original suite observations", "",
              "| Suite / target | Actual complete counts | Complete success |", "| --- | --- | --- |"]
    for suite, targets in observations.items():
        if targets.get("summary_missing"):
            lines.append(f"| {suite} | Original summary missing; no success inferred | false |")
            continue
        for name, row in targets.items():
            counts = row["observed_counts"]
            text = (", ".join(f"{k}={v}" for k, v in counts.items())
                    if counts is not None else "Incomplete/absent libtest result; count not established")
            lines.append(f"| {suite} / {name} | {text} | {str(row['complete_success']).lower()} |")
    lines += ["", "### Copied-Lease supplementary control", "",
              "The complete socket_ownership target preserves all three original named tests, no filter or ignore, "
              "and unchanged test-internal limits. This run adds a 1200-second outer bound; its timeout is a failed execution.",
              "", "Actual exit: " + str(supp["execution"]["exit_code"]) +
              "; timeout: " + str(supp["execution"]["timed_out"]).lower() + ".",
              "", json.dumps(supp["observation"], sort_keys=True), "",
              "ARM, prospective-merge validation and the original three 30-second campaigns remain open. "
              "Native failures and incomplete observations remain failures/unknown observations; source and format checks do not replace execution.",
              "",
              f"[Complete retained evidence](https://github.com/{REPO}/blob/{evidence}/{PREFIX}/README.md)",
              "",
              "The pinned prior-native archive retains original failures and explicit gaps; "
              "complete original cloud logs are unavailable. No complete-history claim is made.",
              "", "Production activation, whole-chain PQ qualification, actual external-effect verification, "
              "independent freshness custody and M15 production integration remain unqualified.", ""]
    return "\n".join(lines).encode()


def locate_pr():
    result = gh_command("pr", "list", "--repo", REPO, "--state", "all", "--head", BRANCH,
                        "--base", BASE_BRANCH, "--limit", "100",
                        "--json", "number,url,state,isDraft,headRefName,headRefOid,baseRefName,author")
    rows = strict_json(result.stdout)
    need(type(rows) is list and len(rows) <= 1, "ambiguous existing PR")
    return rows[0] if rows else None


def validate_pr(pr, evidence):
    need(pr["state"] == "OPEN" and pr["isDraft"] is True and pr["headRefName"] == BRANCH
         and pr["headRefOid"] == evidence and pr["baseRefName"] == BASE_BRANCH
         and pr["author"]["login"] == "ProfHepta", "existing PR scope/actor/state differs")


def publish_pr(source, evidence, summary, observations, supp):
    actor()
    need(remote_head(BRANCH) == evidence and remote_head(BASE_BRANCH) == BASE, "remote branch/base changed")
    body = pr_body(source, evidence, summary, observations, supp)
    path = STATE / "PR_BODY.md"
    create_exact(path, body)
    title = "[HOLD] Root V6 original receipts and provider history floors"
    current = locate_pr()
    if current:
        validate_pr(current, evidence)
        detail = strict_json(gh_command("pr", "view", str(current["number"]), "--repo", REPO,
                                       "--json", "body,title").stdout)
        if detail == {"body": body.decode().rstrip("\n"), "title": title} or detail == {"body": body.decode(), "title": title}:
            create_json(STATE / "PR_RECEIPT.json", {"source": source, "evidence": evidence, "url": current["url"],
                        "number": current["number"], "draft": True, "status": "HOLD", "body_sha256": h256(body)})
            return current
        marker = STATE / "PR_EDIT_ATTEMPT.json"
        need(not marker.exists() and not (STATE / "PR_CREATE_ATTEMPT.json").exists(),
             "previous PR write outcome unresolved; readback only")
        create_json(marker, {"number": current["number"], "evidence": evidence, "body_sha256": h256(body)})
        argv = ("pr", "edit", str(current["number"]), "--repo", REPO, "--title", title, "--body-file", str(path))
    else:
        marker = STATE / "PR_CREATE_ATTEMPT.json"
        need(not marker.exists() and not (STATE / "PR_EDIT_ATTEMPT.json").exists(),
             "previous PR write outcome UNKNOWN; reconcile exact branch, never recreate")
        create_json(marker, {"head": BRANCH, "base": BASE_BRANCH, "evidence": evidence, "body_sha256": h256(body)})
        argv = ("pr", "create", "--repo", REPO, "--head", BRANCH, "--base", BASE_BRANCH,
                "--draft", "--title", title, "--body-file", str(path))
    try:
        result = gh_command(*argv, check=False)
        create_json(STATE / "PR_COMMAND.json", {"exit_code": result.returncode,
                    "stdout_sha256": h256(result.stdout), "stderr_sha256": h256(result.stderr)})
    except subprocess.TimeoutExpired:
        create_json(STATE / "PR_COMMAND.json", {"response": "UNKNOWN", "no_success_inferred": True})
    current = locate_pr()
    need(current is not None, "PR response remains UNKNOWN; no second creation")
    validate_pr(current, evidence)
    detail = strict_json(gh_command("pr", "view", str(current["number"]), "--repo", REPO,
                                   "--json", "body,title").stdout)
    need(detail["title"] == title and detail["body"].rstrip("\n") == body.decode().rstrip("\n"),
         "PR body response not reconciled")
    create_json(STATE / "PR_RECEIPT.json", {"source": source, "evidence": evidence, "url": current["url"],
                "number": current["number"], "draft": True, "status": "HOLD", "body_sha256": h256(body)})
    return current


def main():
    global OUT, DRIVER_SHA, RUN_KEY
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish", action="store_true", help="Explicitly execute the already-reviewed native publication")
    parser.add_argument("--validation-dir", required=True, type=Path)
    parser.add_argument("--expected-driver-sha256", required=True)
    parser.add_argument("--validation-operation-key", required=True)
    args = parser.parse_args()
    need(args.publish, "review artifact only; explicit --publish is required")
    OUT, DRIVER_SHA, RUN_KEY = args.validation_dir, args.expected_driver_sha256, args.validation_operation_key
    need(OUT.is_absolute() and str(OUT.parent) == "/home/qian-qi/work"
         and re.fullmatch(r"chain-root-validation-20261112-df05-v[1-9][0-9]*", OUT.name)
         and digest_ok(DRIVER_SHA), "unreviewed validation directory or driver digest")
    version = OUT.name.rsplit("-", 1)[1]
    need(RUN_KEY == "root-operation-20261112-df05-native-validation-" + version,
         "validation key/directory mismatch")
    os.umask(0o077)
    sys.dont_write_bytecode = True
    initial_environment = clean_env()
    os.environ.clear()
    os.environ.update(initial_environment)
    finished = wait_finished()
    source = finished["source"]
    repository_identity()
    need(gtext("rev-parse", source + "^{tree}") == TREE and gtext("show", "-s", "--format=%P", source) == BASE,
         "native source is not the exact permitted continuation")
    ensure_dirs(STATE)
    lock_path = STATE / "publisher.lock"
    create_exact(lock_path, b"")
    lock_parent, lock_name, lock_before, lock_stream = open_regular(lock_path)
    try:
        fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        lock_stream.close()
        os.close(lock_parent)
        raise Refuse("another publisher owns this immutable publication identity")
    # Retain both descriptors until main exits, including a lost external response.
    # The kernel releases this cooperative owner lock when the process ends.
    globals()["_publisher_owner_lock"] = (lock_parent, lock_stream)
    bytecode = STATE / "bytecode-must-remain-absent"
    need(not os.path.lexists(bytecode), "unreviewed publisher bytecode cache")
    sys.pycache_prefix = str(bytecode)
    program = own_program()
    # Before importing a repository verifier or runner, admit physical bytes independently.
    current = gtext("rev-parse", "HEAD")
    marker_exists = (STATE / "SEALED.json").exists()
    if current == source and not marker_exists:
        physical_tree(source)
    else:
        need(marker_exists, "unexpected evidence child without sealed intent")
        resume_sealed = checked_sealed(publication_binding(source, finished, program))
        resume_corpus = expected_corpus(source, resume_sealed)
        if current == source:
            physical_tree(source, dirty_evidence=True,
                          overrides={CORPUS: (git_blob(source, CORPUS), resume_corpus)},
                          evidence_paths={PREFIX + "/" + name for name in resume_sealed["files"]})
        else:
            permitted_delta(source, current, resume_sealed, resume_corpus)
            physical_tree(current)
    source, manifest, summary, env, provider, observations = validate_native(finished)
    selected = clean_env(env)
    os.environ.clear()
    os.environ.update(selected)
    publication_preflight(source, current)
    if current == source and not marker_exists:
        physical_tree(source)
        repo_verify(source)
        command(["bash", "scripts/project-preflight.sh"], env=selected)
    supp_dir, supp = supplement(source, env, provider)
    sealed = seal(source, finished, manifest, summary, observations, supp_dir, supp, program)
    evidence = archive_commit(source, sealed, selected)
    final_checks(evidence, selected)
    provider_unchanged(provider)
    need(not os.path.lexists(OUT / "FAILED.json"), "validation has a later failure marker")
    push(source, evidence, selected)
    pr = publish_pr(source, evidence, summary, observations, supp)
    receipt = {"operation_key": PUB_KEY, "native_source": source, "native_tree": TREE,
               "evidence_commit": evidence, "pr": pr["url"], "draft": True, "status": "HOLD",
               "publication_complete": True, "native_all_commands_passed": summary["all_commands_passed"],
               "supplement_complete_success": supp["observation"]["complete_success"],
               "production_activation": False, "tests_relabelled_to_evidence_commit": False}
    create_json(STATE / "PUBLICATION_RECEIPT.json", receipt)
    print(json.dumps(receipt, sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # No cleanup, source repair, command rerun, or alternate publication identity.
        message = {"operation_key": PUB_KEY, "publication_complete": False, "status": "REFUSE_OR_UNKNOWN",
                   "error_type": type(error).__name__, "reason": str(error),
                   "no_success_inferred": True}
        try:
            ensure_dirs(STATE)
            name = "refusal-" + str(time.time_ns()) + ".json"
            create_json(STATE / name, message)
        except BaseException:
            pass
        print(json.dumps(message, sort_keys=True), file=sys.stderr, flush=True)
        raise
