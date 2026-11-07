#!/usr/bin/env python3
"""Unexecuted candidate: durable POSIX target for W1 generation operations.

This is a real subprocess backend, not a Kaggle/Colab API implementation. The
state root must be persistent on the provider controller, shared by all service
journals addressing that target. Ephemeral notebook storage is insufficient.
The request is immutable, including its original LOCAL monotonic clock domain.
A remote clock cannot be substituted for it. Success never authorizes payment.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import stat
import subprocess
import sys
import time

NAMESPACE = "trnm-w1-generation-posix-target-v2"
APPLICATION_ID = 0x57475432
MAX_REQUEST = 65536
MAX_RESULT = 65536
FORBIDDEN_ENV = {"RISC0_DEV_MODE", "RISC0_PROVER", "BONSAI_API_URL", "BONSAI_API_KEY"}
ENV_KEYS = {"PATH", "LANG", "LC_ALL", "TMPDIR", "RAYON_NUM_THREADS", "RUSTUP_HOME", "CARGO_HOME", "PYTHONDONTWRITEBYTECODE"}
META_SQL = "CREATE TABLE target_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),namespace TEXT NOT NULL,target TEXT NOT NULL) STRICT"
OPS_SQL = "CREATE TABLE operations(operation TEXT PRIMARY KEY,task_scope TEXT UNIQUE NOT NULL,statement TEXT NOT NULL,request BLOB NOT NULL,request_sha256 TEXT NOT NULL,state TEXT NOT NULL,cancel INTEGER NOT NULL CHECK(cancel IN (0,1)),worker BLOB,result BLOB) STRICT"


def check(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def hex32(value):
    check(isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value), "invalid digest")
    return value


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def clock_domain(target):
    return sha(canonical({"schema": NAMESPACE, "target_instance": target, "linux_boot_id": boot_id()}))


def process_identity(pid):
    # starttime follows the final ')' because a comm may contain spaces or ')'.
    raw = Path(f"/proc/{pid}/stat").read_text()
    rest = raw[raw.rfind(")") + 2:].split()
    return {"boot_id": boot_id(), "pid": pid, "start_ticks": int(rest[19])}


def same_process(identity):
    try:
        return process_identity(identity["pid"]) == identity
    except (OSError, ValueError, KeyError):
        return False


def open_db(root, target, create):
    root = Path(root).resolve()
    if create:
        root.mkdir(parents=True, exist_ok=True)
    check(root.is_dir(), "persistent target root absent")
    path = root / "target-v2.sqlite"
    check(not path.is_symlink(), "target database symlink")
    check(create or path.is_file(), "target database absent; UNKNOWN, not permission to dispatch")
    c = sqlite3.connect(str(path), isolation_level=None, timeout=5)
    c.execute("PRAGMA trusted_schema=OFF")
    c.execute("PRAGMA synchronous=FULL")
    app = c.execute("PRAGMA application_id").fetchone()[0]
    version = c.execute("PRAGMA user_version").fetchone()[0]
    if app == 0 and version == 0:
        check(create, "target namespace absent")
        c.execute("BEGIN IMMEDIATE")
        check(c.execute("SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").fetchone()[0] == 0, "foreign database")
        c.execute(META_SQL)
        c.execute(OPS_SQL)
        c.execute("INSERT INTO target_meta VALUES(1,?,?)", (NAMESPACE, target))
        c.execute(f"PRAGMA application_id={APPLICATION_ID}")
        c.execute("PRAGMA user_version=2")
        c.execute("COMMIT")
    check(c.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID, "foreign target namespace")
    check(c.execute("PRAGMA user_version").fetchone()[0] == 2, "foreign target version")
    for name, expected in (("target_meta", META_SQL), ("operations", OPS_SQL)):
        check(c.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone() == (expected,), "target schema changed")
    check(c.execute("SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").fetchone()[0] == 2, "target schema changed")
    check(c.execute("SELECT namespace,target FROM target_meta WHERE singleton=1").fetchone() == (NAMESPACE, target), "target instance changed")
    c.execute("PRAGMA journal_mode=WAL")
    return c, root


def read_operation(c, operation):
    check(c.execute("PRAGMA application_id").fetchone() == (APPLICATION_ID,)
          and c.execute("PRAGMA user_version").fetchone() == (2,), "live target namespace changed")
    for name, expected in (("target_meta", META_SQL), ("operations", OPS_SQL)):
        check(c.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone() == (expected,),
              "live target schema changed")
    check(c.execute("SELECT count(*) FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'").fetchone() == (2,),
          "live target schema changed")
    meta = c.execute("SELECT namespace,target FROM target_meta WHERE singleton=1").fetchone()
    check(meta and meta[0] == NAMESPACE, "live target namespace changed")
    row = c.execute("SELECT task_scope,statement,request,request_sha256,state,cancel,worker,result FROM operations WHERE operation=?", (operation,)).fetchone()
    check(row is not None, "operation absent: UNKNOWN, not retry permission")
    check(sha(row[2]) == row[3], "retained request damaged")
    request = json.loads(row[2])
    check(request["target_instance"] == meta[1], "live target instance changed")
    check(canonical(request) == row[2], "noncanonical request")
    check(request["operation"] == operation and request["task_scope"] == row[0] and request["statement"] == row[1], "request binding damaged")
    return {"request": request, "request_sha256": row[3], "state": row[4], "cancel": bool(row[5]),
            "worker": json.loads(row[6]) if row[6] else None, "result": json.loads(row[7]) if row[7] else None}


def request_check(r, target, check_clock=True):
    check(r.get("schema") == NAMESPACE and r.get("target_instance") == target, "request namespace/target")
    for name in ("operation", "task_scope", "statement", "provider_namespace", "execution_source_commitment"):
        hex32(r[name])
    check(r["target_backend_sha256"] == file_sha(Path(__file__).resolve()), "target backend source pin")
    check(r["clock_domain"] == clock_domain(target), "cross-host or reboot clock continuity UNKNOWN")
    check(isinstance(r["winner_monotonic_ns"], int) and isinstance(r["deadline_monotonic_ns"], int)
          and 0 <= r["winner_monotonic_ns"] < r["deadline_monotonic_ns"], "original deadline")
    if check_clock:
        check(r["winner_monotonic_ns"] <= time.monotonic_ns() < r["deadline_monotonic_ns"], "original deadline expired")
    argv = r["argv"]
    check(isinstance(argv, list) and argv and len(argv) <= 128 and all(isinstance(x, str) and "\x00" not in x for x in argv), "argv")
    check(Path(argv[0]).is_absolute(), "executable must be absolute")
    check(Path(r["cwd"]).is_absolute() and Path(r["cwd"]).is_dir(), "cwd")
    pins = r["file_pins"]
    check(isinstance(pins, dict) and str(Path(argv[0]).resolve()) in pins, "executable pin required")
    for path, digest in pins.items():
        check(Path(path).is_absolute() and file_sha(path) == hex32(digest), "pinned file changed")
    env = r["environment"]
    check(isinstance(env, dict) and set(env) <= ENV_KEYS and not set(env) & FORBIDDEN_ENV, "environment keys")
    check(all(isinstance(v, str) and "\x00" not in v for v in env.values()), "environment values")
    check(not any(os.environ.get(k) is not None for k in FORBIDDEN_ENV), "forbidden proof environment")
    cpus = r["cpus"]
    check(isinstance(cpus, list) and cpus and len(set(cpus)) == len(cpus) and all(type(v) is int and v >= 0 for v in cpus), "CPU affinity")
    check(set(cpus) <= os.sched_getaffinity(0), "requested affinity unavailable")
    check(type(r["total_threads"]) is int and 1 <= r["total_threads"] <= len(cpus), "total thread budget")
    check(env.get("RAYON_NUM_THREADS") == str(r["total_threads"]), "Rayon budget binding")
    check(r["containment"] in ("cgroup-v2", "process-group-research"), "containment mode")
    if r["containment"] == "cgroup-v2":
        parent = Path(r["cgroup_parent"]).resolve()
        check(parent.is_absolute() and (parent / "cgroup.controllers").is_file(), "delegated cgroup-v2 parent unavailable")
    check(0 < r.get("cleanup_grace_ns", 0) <= 10_000_000_000, "cleanup grace limit")
    return r


def public_readback(c, operation, target):
    row = read_operation(c, operation)
    worker = row["worker"]
    return {"schema": NAMESPACE + "/readback", "operation": operation,
            "target_instance": target, "request_sha256": row["request_sha256"],
            "statement": row["request"]["statement"], "task_scope": row["request"]["task_scope"],
            "state": row["state"], "sticky_cancel": row["cancel"], "worker": worker,
            "worker_alive_same_identity": same_process(worker["identity"]) if worker else None,
            "result": row["result"], "may_dispatch_again": False, "can_authorize_payment": False,
            "original_deadline_monotonic_ns": row["request"]["deadline_monotonic_ns"]}


def dispatch(args):
    raw = Path(args.request).read_bytes()
    check(len(raw) <= MAX_REQUEST, "request size")
    r = request_check(json.loads(raw), args.target)
    raw = canonical(r)
    c, root = open_db(args.root, args.target, True)
    c.execute("BEGIN IMMEDIATE")
    previous = c.execute("SELECT request FROM operations WHERE operation=?", (r["operation"],)).fetchone()
    if previous:
        check(previous[0] == raw, "operation replay mismatch")
        c.execute("COMMIT")
        return public_readback(c, r["operation"], args.target)
    # UNIQUE task_scope is shared by ALL callers/journal identities at this target.
    c.execute("INSERT INTO operations VALUES(?,?,?,?,?,'intent',0,NULL,NULL)",
              (r["operation"], r["task_scope"], r["statement"], raw, sha(raw)))
    c.execute("COMMIT")
    check(read_operation(c, r["operation"])["request_sha256"] == sha(raw), "committed intent readback")
    # A crash from this point is Pending/UNKNOWN and NEVER triggers redispatch.
    job = root / r["operation"]
    job.mkdir(exist_ok=False)
    with (job / "supervisor.stdout").open("xb") as out, (job / "supervisor.stderr").open("xb") as err:
        subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "_worker", "--root", str(root),
                          "--target", args.target, "--operation", r["operation"]],
                         stdin=subprocess.DEVNULL, stdout=out, stderr=err, start_new_session=True,
                         close_fds=True)
    return public_readback(c, r["operation"], args.target)


def cgroup_identity(path):
    value = Path(path).lstat()
    check(stat.S_ISDIR(value.st_mode), "original child cgroup is not a directory")
    return {"device": value.st_dev, "inode": value.st_ino}


def cgroup_observation(path, expected_identity=None):
    """Observe the whole child subtree; a direct procs list is insufficient.

    Missing files, a changed tree or a replaced original cgroup are errors, not
    empty observations. This establishes a bounded current no-live-task fact;
    it does not establish that every orphaned descendant has been wait/reaped.
    """
    if path is None:
        return None
    path = Path(path)
    original = cgroup_identity(path)
    check(expected_identity is None or original == expected_identity, "original child cgroup identity changed")

    def tree():
        groups = [path]
        for group in groups:
            groups.extend(sorted((p for p in group.iterdir() if stat.S_ISDIR(p.lstat().st_mode)), key=str))
            check(len(groups) <= 128, "child cgroup subtree bound")
        return {str(p): cgroup_identity(p) for p in groups}

    before = tree()
    members = []
    for group in before:
        rows = [int(x) for x in (Path(group) / "cgroup.procs").read_text().split()]
        check(all(pid > 0 for pid in rows) and len(rows) <= 4096, "child cgroup process bound")
        members.extend(rows)
    check(len(members) == len(set(members)), "child cgroup membership changed during observation")
    events = {}
    for line in (path / "cgroup.events").read_text().splitlines():
        key, value = line.split()
        check(key not in events, "duplicate cgroup event counter")
        events[key] = int(value)
    check(events.get("populated") in (0, 1), "hierarchical cgroup population unknown")
    check(before == tree() and cgroup_identity(path) == original, "child cgroup tree changed during observation")
    return {"schema": "TRNM-W1-OWNED-CGROUP-OBSERVATION1", "path": str(path), "identity": original, "groups": before,
            "members": sorted(members), "events": events, "observation_complete": True,
            "recursive_empty": not members and events["populated"] == 0,
            "all_descendants_reaped": None}


def cgroup_members(path):
    observed = cgroup_observation(path)
    return None if observed is None else observed["members"]


def worker(args):
    c, root = open_db(args.root, args.target, False)
    row = read_operation(c, args.operation)
    r = row["request"]
    identity = process_identity(os.getpid())
    actual_job = {"identity": identity, "provider_namespace": r["provider_namespace"],
                  "operation": args.operation, "request_sha256": row["request_sha256"],
                  "job_id": sha(canonical({"target": args.target, "operation": args.operation, "identity": identity}))}
    c.execute("BEGIN IMMEDIATE")
    check(c.execute("UPDATE operations SET worker=?,state='supervising' WHERE operation=? AND worker IS NULL AND state='intent'",
                    (canonical(actual_job), args.operation)).rowcount == 1, "worker already claimed; no second execution")
    c.execute("COMMIT")
    check(read_operation(c, args.operation)["worker"] == actual_job, "worker identity committed readback")
    job = root / args.operation
    child = None
    group = None
    group_identity = None
    direct_child_reaped = False
    child_identity = None
    cause = None
    error = None
    started = time.monotonic_ns()
    deadline = r["deadline_monotonic_ns"]
    cleanup_until = None
    try:
        request_check(r, args.target)
        check(not read_operation(c, args.operation)["cancel"], "cancelled before launch")
        if r["containment"] == "cgroup-v2":
            group = Path(r["cgroup_parent"]).resolve() / ("trnm-w1-generation-" + args.operation)
            group.mkdir(exist_ok=False)
            group_identity = cgroup_identity(group)
            if r.get("memory_max_bytes") is not None:
                check(type(r["memory_max_bytes"]) is int and r["memory_max_bytes"] > 0, "memory limit")
                (group / "memory.max").write_text(str(r["memory_max_bytes"]))
            if r.get("cpu_max") is not None:
                check(isinstance(r["cpu_max"], str) and len(r["cpu_max"].split()) == 2, "cpu.max")
                (group / "cpu.max").write_text(r["cpu_max"])
        request_check(r, args.target)
        check(not read_operation(c, args.operation)["cancel"], "cancelled before exec intent")
        c.execute("BEGIN IMMEDIATE")
        check(c.execute("UPDATE operations SET state='child-intent' WHERE operation=? AND state='supervising' AND cancel=0",
                        (args.operation,)).rowcount == 1, "cancelled before exec intent")
        c.execute("COMMIT")
        with (job / "child.stdout").open("xb") as out, (job / "child.stderr").open("xb") as err:
            child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "_exec", "--root", str(root),
                                      "--target", args.target, "--operation", args.operation],
                                     stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                     start_new_session=True, close_fds=True)
            try:
                child_identity = process_identity(child.pid)
            except OSError:
                child_identity = None
            while True:
                now = time.monotonic_ns()
                cancelled = read_operation(c, args.operation)["cancel"]
                if (cancelled or now >= deadline) and cause is None:
                    cause = "cancelled" if cancelled else "original-deadline"
                    cleanup_until = now + r["cleanup_grace_ns"]
                if cause is not None:
                    if group is not None and (group / "cgroup.kill").is_file():
                        check(cgroup_identity(group) == group_identity, "refuse kill of replaced child cgroup")
                        (group / "cgroup.kill").write_text("1")
                    elif child.poll() is None and child_identity and same_process(child_identity):
                        os.killpg(child.pid, signal.SIGKILL)
                code = child.poll()
                observed_group = cgroup_observation(group, group_identity)
                if code is not None and (group is None or observed_group["recursive_empty"]):
                    break
                if cleanup_until is not None and now >= cleanup_until:
                    cause = "termination-unknown"
                    break
                # A leader exiting with live cgroup descendants is NOT terminal.
                time.sleep(0.05)
            if child.poll() is not None:
                child.wait()
                direct_child_reaped = True
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        cause = cause or "supervisor-error"
        # Never hide descendants behind an error-path success. cgroup.kill is
        # bounded by the same cleanup grace; the result below retains UNKNOWN.
        if group is not None and (group / "cgroup.kill").is_file():
            try:
                check(cgroup_identity(group) == group_identity, "refuse kill of replaced child cgroup")
                (group / "cgroup.kill").write_text("1")
            except (OSError, ValueError):
                pass
        if child is not None and child.poll() is None and child_identity and same_process(child_identity):
            try:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=r["cleanup_grace_ns"] / 1e9)
                direct_child_reaped = True
            except (OSError, subprocess.TimeoutExpired):
                cause = "termination-unknown"
    finished = time.monotonic_ns()
    try:
        observed_group = cgroup_observation(group, group_identity)
    except (OSError, ValueError):
        observed_group = None
    members = None if observed_group is None else observed_group["members"]
    resources = {"cpu_stat": None, "memory_peak_bytes": None, "gpu_ns": None}
    if group is not None:
        try:
            resources["cpu_stat"] = dict(line.split() for line in (group / "cpu.stat").read_text().splitlines())
            resources["memory_peak_bytes"] = int((group / "memory.peak").read_text())
        except (OSError, ValueError):
            pass
    exit_code = None if child is None else child.poll()
    cancellation = read_operation(c, args.operation)["cancel"]
    if child is not None and exit_code is not None and not direct_child_reaped:
        child.wait()
        direct_child_reaped = True
    owned_terminal = (observed_group is not None and observed_group["recursive_empty"]
                      and exit_code is not None and direct_child_reaped)
    ok = cause is None and not cancellation and exit_code == 0 and finished < deadline
    result = {"schema": NAMESPACE + "/result", "operation": args.operation,
              "provider_job": actual_job, "child_identity": child_identity, "request_sha256": row["request_sha256"],
              "original_deadline_monotonic_ns": deadline, "clock_domain": r["clock_domain"],
              "started_monotonic_ns": started, "finished_monotonic_ns": finished,
              "exit_code": exit_code, "cause": cause, "error": error,
              "sticky_cancel": cancellation, "process_containment": r["containment"],
              "cgroup_members_after_cleanup": members, "all_owned_processes_terminal": owned_terminal,
              "child_cgroup_observation": observed_group, "direct_child_reaped": direct_child_reaped,
              "all_descendants_reaped": None,
              "resources": resources, "command_success": ok,
              "generation_qualification": "requires-full-independent-verifier-and-fresh-pipeline-closure",
              "resource_qualification": "unknown" if resources["gpu_ns"] is None else "requires-owner-validation",
              "can_authorize_payment": False, "may_dispatch_again": False}
    encoded = canonical(result)
    check(len(encoded) <= MAX_RESULT, "result bound")
    c.execute("BEGIN IMMEDIATE")
    terminal_state = "terminal" if owned_terminal else "termination-unknown"
    check(c.execute("UPDATE operations SET state=?,result=? WHERE operation=? AND result IS NULL",
                    (terminal_state, encoded, args.operation)).rowcount == 1, "terminal overwrite refused")
    c.execute("COMMIT")
    check(read_operation(c, args.operation)["result"] == result, "terminal committed readback")
    return result


def exec_child(args):
    c, _ = open_db(args.root, args.target, False)
    row = read_operation(c, args.operation)
    r = request_check(row["request"], args.target)
    check(row["state"] == "child-intent" and not row["cancel"], "exec cancelled or not intended")
    if r["containment"] == "cgroup-v2":
        group = Path(r["cgroup_parent"]).resolve() / ("trnm-w1-generation-" + args.operation)
        (group / "cgroup.procs").write_text(str(os.getpid()))
        check(os.getpid() in cgroup_members(group), "cgroup membership readback")
    os.sched_setaffinity(0, set(r["cpus"]))
    check(os.sched_getaffinity(0) == set(r["cpus"]), "affinity readback")
    # No arbitrary inherited credentials/prover API settings in a job environment.
    env = {k: v for k, v in os.environ.items() if k in {"PATH", "LANG", "LC_ALL", "TMPDIR"}}
    env.update(r["environment"])
    request_check(r, args.target)
    check(not read_operation(c, args.operation)["cancel"], "cancelled at exec boundary")
    c.close()
    os.chdir(r["cwd"])
    os.execve(r["argv"][0], r["argv"], env)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=["preflight", "dispatch", "reconcile", "cancel", "_worker", "_exec"])
    p.add_argument("--root", required=True)
    p.add_argument("--target", required=True)
    p.add_argument("--request")
    p.add_argument("--operation")
    args = p.parse_args()
    check(args.target and len(args.target) <= 256, "target identity")
    if args.command == "preflight":
        result = {"schema": NAMESPACE + "/preflight", "clock_domain": clock_domain(args.target),
                  "monotonic_ns": time.monotonic_ns(), "available_cpus": sorted(os.sched_getaffinity(0)),
                  "target_backend_sha256": file_sha(Path(__file__).resolve()), "dispatch_performed": False,
                  "requires_persistent_target_root": True, "cross_host_deadline_bridge": "not-implemented"}
        if args.request:
            raw = Path(args.request).read_bytes()
            check(len(raw) <= MAX_REQUEST, "request size")
            request_check(json.loads(raw), args.target)
            result["request_valid_now"] = True
    elif args.command == "dispatch":
        check(args.request is not None, "request required")
        result = dispatch(args)
    elif args.command == "_worker":
        result = worker(args)
    elif args.command == "_exec":
        exec_child(args)
        raise AssertionError("exec returned")
    else:
        hex32(args.operation)
        c, _ = open_db(args.root, args.target, False)
        if args.command == "cancel":
            c.execute("BEGIN IMMEDIATE")
            read_operation(c, args.operation)
            c.execute("UPDATE operations SET cancel=1 WHERE operation=?", (args.operation,))
            c.execute("COMMIT")
        result = public_readback(c, args.operation, args.target)
        if args.command == "cancel":
            result["cancel_ack_scope"] = "durable-veto-only; process termination requires terminal reconciliation"
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(json.dumps({"schema": NAMESPACE + "/error", "error": f"{type(exc).__name__}: {exc}",
                          "may_dispatch_again": False, "can_authorize_payment": False}), file=sys.stderr)
        raise SystemExit(1)
