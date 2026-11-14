"""Diagnose only the previously reviewed candidate/tag push with Git --dry-run.

No remote update, archive construction, ref update, fetch, retry or qualification.
The original 300-second limit and all original pre-push assertions are retained.
Execute only after the operator reviews this external driver.
"""
import argparse, datetime, hashlib, json, os, pathlib, re, signal, stat
import subprocess, sys, threading, time

ROOT = pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
SOURCE = pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
SELF = ROOT / "diagnose_candidate_archive_push_dry_run_v1.py"
PUBLISHER = ROOT / "publish_candidate_and_archive_v4.py"
PUBLISHER_SHA = "4105cd1db2e5219deda83a881872c51ac5cf671f5caa367bc2ea8ae4d4495038"
ORIGINAL = ROOT / "publish-candidate-and-archive-dc42ce-v2"
HEAD = "dc42ce4df5cff79cc61c5addbaf01074b56b06ca"
TREE = "9fda17fed2542b2baccaa34585bb00afd699e12b"
OLD_HEAD = "e40d7071c4724e6600deef8a2820bf35c1982289"
MAIN_HEAD = "dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
CANDIDATE_REF = "refs/heads/fix/chain-hepta-closure-candidate-20261109-481716"
TAG = "archive/branches-before-consolidation-20261114-dc42ce4df5cf-v2"
TAGREF = "refs/tags/" + TAG
TAG_OID = "9dafd9192e4040fab530958ef71598aaec9265b9"
ARCHIVE_COMMIT = "5f57c4e1e2b7ae95a7b0651d7674979d3f44b90b"
ARCHIVE_TREE = "b91f68e70a05e5475b850159033baffb0824c6ba"
REPOSITORY = "TrillionniumFoundation/Trillionnium-Chain"
URL = "https://github.com/" + REPOSITORY + ".git"
PINS = {
    "spec.json": (1008, "c63009a5e7d99af7e60f66cfd43fcf036a6cf4d5b002a98cd4500c3d76b07c2a"),
    "archive-local.json": (43199, "7a5ead74ce076c3e8fd56cac61c22a380b660b7da4875a9259018e37e4c21aa6"),
    "hooks/pre-push": (933, "f0df66af0e6d360386f72475c79a38d2e40567396b00aca492d175195d503730"),
    "hooks/expected.json": (83072, "ee1e1fca066b62525016cd60803cadb3a2183cb8f9a5f367872341bd0ec2ca1a"),
    "summary.json": (211557, "7f1821d9779f68d8a05c392b65b78a7ca248abe6dc81f0a7faffd3043d2e0bd2"),
}
MARKERS = (
    (b"import json,pathlib,subprocess,sys\n",
     b'sys.stderr.write("hook-enter\\n"); sys.stderr.flush()\n'),
    (b'assert seen==spec["updates"],"unexpected push update"\n',
     b'sys.stderr.write("advertised-input-pass\\n"); sys.stderr.flush()\n'),
    (b'assert actual==spec["remote_heads"],"remote set changed after review"\n',
     b'sys.stderr.write("full-head-map-pass\\n"); sys.stderr.flush()\n'),
)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def bootstrap_helpers():
    if sys.flags.optimize != 0:
        raise RuntimeError("optimized Python disables diagnostic guards")
    before = PUBLISHER.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("publisher dependency is not a regular file")
    def fingerprint(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)
    fd = os.open(PUBLISHER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if fingerprint(os.fstat(stream.fileno())) != fingerprint(before):
            raise ValueError("publisher changed before read")
        raw = stream.read()
        if fingerprint(os.fstat(stream.fileno())) != fingerprint(before):
            raise ValueError("publisher changed during read")
    if fingerprint(PUBLISHER.lstat()) != fingerprint(before) or sha(raw) != PUBLISHER_SHA:
        raise ValueError("reviewed publisher dependency differs")
    namespace = {"__name__": "_reviewed_publisher_helpers", "__file__": str(PUBLISHER)}
    exec(compile(raw, str(PUBLISHER), "exec"), namespace)
    return namespace

def instrument_hook(original):
    result = original
    for anchor, marker in MARKERS:
        if result.count(anchor) != 1 or marker in result:
            raise ValueError("original hook insertion anchor differs")
        result = result.replace(anchor, anchor + marker, 1)
    restored = result
    for _, marker in MARKERS:
        if restored.count(marker) != 1:
            raise ValueError("diagnostic hook marker differs")
        restored = restored.replace(marker, b"", 1)
    if restored != original:
        raise ValueError("original hook assertions changed")
    return result

def sample_owned(pid, phase, env):
    """Retain only the owned tree; ps never requests arguments or environment."""
    q = subprocess.run(
        ["/bin/ps", "-axo", "pid=,ppid=,pgid=,pcpu=,etime=,comm="],
        env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=5, check=False)
    if q.returncode != 0:
        raise RuntimeError("owned process metadata sampling failed")
    parsed = []
    for line in q.stdout.decode("utf-8", errors="replace").splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6:
            raise RuntimeError("process metadata shape differs")
        parsed.append((int(fields[0]), int(fields[1]), int(fields[2]),
                       fields[3], fields[4], fields[5]))
    selected = {pid}
    selected.update(p for p, _, group, _, _, _ in parsed if group == pid)
    while True:
        extended = selected | {p for p, parent, _, _, _, _ in parsed if parent in selected}
        if extended == selected:
            break
        selected = extended
    rows = [{"pid": p, "ppid": parent, "comm": comm, "cpu_percent": cpu, "elapsed": elapsed}
            for p, parent, _, cpu, elapsed, comm in parsed if p in selected]
    return {"observed_at": now(), "phase": phase, "owned_root_pid": pid,
            "processes": sorted(rows, key=lambda row: row["pid"])}

def capture_sampled(argv, env, sample_path):
    """The reviewed capture lifecycle, with metadata only at 0/15s/terminal."""
    sampling_errors = []
    try:
        process = subprocess.Popen(argv, cwd=SOURCE, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    except OSError as error:
        return subprocess.CompletedProcess(argv, 127, b"", str(error).encode()), sampling_errors
    stop = threading.Event()
    def sampler():
        with sample_path.open("x", encoding="utf-8") as stream:
            def record(phase):
                try:
                    row = sample_owned(process.pid, phase, env)
                except Exception as error:
                    row = {"observed_at": now(), "phase": phase,
                           "owned_root_pid": process.pid, "error_type": type(error).__name__}
                    sampling_errors.append(row)
                stream.write(json.dumps(row, sort_keys=True) + "\n")
                stream.flush()
            record("start")
            while not stop.wait(15):
                record("periodic")
            record("terminal")
    thread = threading.Thread(target=sampler, name="owned-process-metadata", daemon=True)
    thread.start()
    try:
        try:
            stdout, stderr = process.communicate(timeout=300)
            result = subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired as expired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired as remaining:
                stdout, stderr = remaining.stdout or expired.stdout or b"", remaining.stderr or expired.stderr or b""
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
                stderr += b"\nOwned process capture did not close after timeout; outcome UNKNOWN.\n"
            result = subprocess.CompletedProcess(argv, 124, stdout, stderr)
    finally:
        stop.set()
        thread.join(timeout=12)
        if thread.is_alive():
            sampling_errors.append({"error_type": "SamplerDidNotClose"})
    return result, sampling_errors

def main():
    helpers = bootstrap_helpers()
    require = helpers["require"]
    regular_bytes = helpers["regular_bytes"]
    strict_json = helpers["strict_json"]
    capture = helpers["capture"]
    require(pathlib.Path(__file__).resolve(strict=True) == SELF, "unexpected driver path")
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True)
    args = parser.parse_args()
    ev = pathlib.Path(args.evidence_dir)
    require(ev.parent == ROOT and ROOT.resolve(strict=True) == ROOT
            and re.fullmatch(r"diagnose-candidate-archive-dry-run-[a-z0-9-]+", ev.name),
            "unexpected evidence directory")
    os.umask(0o077)
    ev.mkdir(mode=0o700, exist_ok=False)
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("GIT_TRACE") or key == "GIT_CURL_VERBOSE":
            del env[key]
    env.update(helpers["GATE_ENV"])
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_TRACE2="0",
               GIT_TRACE2_EVENT="0", GIT_TRACE2_PERF="0")
    steps, errors = [], []
    state = {"schema": "trnm-candidate-archive-push-dry-run-v1", "status": "HOLD",
             "started_at": now(), "head": HEAD, "tree": TREE,
             "archive_tag": TAG, "archive_tag_oid": TAG_OID,
             "archive_commit": ARCHIVE_COMMIT, "dry_run_started": False,
             "dry_run_exit": None, "source_after_valid": False,
             "remote_write_authorized": False, "automatic_retry_authorized": False,
             "qualification_granted": False, "errors": errors, "steps": steps,
             "driver": {"path": str(SELF), "sha256": sha(regular_bytes(SELF))},
             "reviewed_helpers": {"path": str(PUBLISHER), "sha256": PUBLISHER_SHA},
             "trace_enabled": False, "sampling_interval_seconds": 15,
             "sampling_limitations": "Metadata samples may miss short-lived children; no argv or environment is sampled."}
    def save():
        (ev / "summary.json").write_text(json.dumps(state, indent=2) + "\n")
        (ev / "steps.json").write_text(json.dumps(steps, indent=2) + "\n")
    def run(label, argv, timeout=60, require_zero=True, sampled=False):
        started = now()
        if sampled:
            q, sample_errors = capture_sampled(argv, env, ev / "owned-process-samples.jsonl")
            state["sampling_errors"] = sample_errors
        else:
            q = capture(argv, env, timeout=timeout)
        row = {"label": label, "cwd": str(SOURCE), "argv": argv, "exit": q.returncode,
               "started_at": started, "finished_at": now(),
               "timeout_seconds": 300 if sampled else timeout}
        for suffix, raw in (("stdout", q.stdout), ("stderr", q.stderr)):
            path = ev / (label + "." + suffix)
            with path.open("xb") as stream:
                stream.write(raw)
            row.update({suffix + "_path": str(path), suffix + "_bytes": len(raw),
                        suffix + "_sha256": sha(raw)})
        steps.append(row)
        save()
        print(json.dumps({"label": label, "exit": q.returncode}), flush=True)
        require(not require_zero or q.returncode == 0, label + ": see retained private outputs")
        return q
    def pin(name):
        raw = regular_bytes(ORIGINAL / name)
        length, digest = PINS[name]
        require(len(raw) == length and sha(raw) == digest, "original input differs: " + name)
        return raw
    def parse_refs(raw, heads=False):
        result = {}
        for line in raw.decode("ascii").splitlines():
            oid, ref = line.split()
            require(re.fullmatch(r"[0-9a-f]{40}", oid) is not None, "invalid advertised object")
            if heads:
                require(ref.startswith("refs/heads/"), "unexpected head advertisement")
                ref = ref[11:]
            else:
                require(ref in (TAGREF, TAGREF + "^{}"), "unexpected tag advertisement")
            require(ref not in result, "duplicate advertised ref")
            result[ref] = oid
        return result
    def observe(phase):
        h = run("refs-" + phase, ["git", "ls-remote", "--heads", "origin"],
                timeout=90, require_zero=False)
        t = run("tag-" + phase, ["git", "ls-remote", "origin", TAGREF, TAGREF + "^{}"],
                timeout=90, require_zero=False)
        result = {"heads": None, "tags": None, "errors": []}
        for key, q, is_heads in (("heads", h, True), ("tags", t, False)):
            if q.returncode != 0:
                result["errors"].append(key + " read failed")
            else:
                try:
                    result[key] = parse_refs(q.stdout, heads=is_heads)
                except Exception:
                    result["errors"].append(key + " parse failed")
        state["remote_" + phase] = result
        save()
        return result
    expected = wanted = gate_source = source_before = None
    def classify(observation):
        if observation["errors"]:
            return "HOLD"
        if observation["heads"] == wanted and observation["tags"] == {
                TAGREF: TAG_OID, TAGREF + "^{}": ARCHIVE_COMMIT}:
            return "both_new"
        if observation["heads"] == expected and observation["tags"] == {}:
            return "all_old_tag_absent"
        return "HOLD"
    try:
        original = {name: pin(name) for name in PINS}
        spec = strict_json(original["spec.json"])
        archive = strict_json(original["archive-local.json"])
        hook_spec = strict_json(original["hooks/expected.json"])
        previous = strict_json(original["summary.json"])
        require(spec["candidate_head"] == HEAD and spec["candidate_tree"] == TREE
                and spec["archive_tag"] == TAG and spec["evidence_dir"] == str(ORIGINAL),
                "original publication identity differs")
        require(previous["status"] == "UNKNOWN" and previous["push_exit"] == 124
                and previous["readback_errors"] == [] and previous["remote_archive_tags"] == {}
                and previous["postpublication_source_valid"] is True,
                "original retained timeout receipt differs")
        expected_raw = regular_bytes(spec["expected_remote_manifest"])
        frozen_raw = regular_bytes(spec["frozen_remote_manifest"])
        require(sha(expected_raw) == spec["expected_remote_sha256"]
                and sha(frozen_raw) == spec["frozen_remote_sha256"],
                "remote manifest bytes differ")
        expected = strict_json(expected_raw)
        frozen = strict_json(frozen_raw)
        require(expected == {row["name"]: row["sha"] for row in frozen}
                and len(frozen) == len(expected) == 908 and len(set(expected.values())) == 892
                and expected["main"] == MAIN_HEAD and expected[CANDIDATE_REF[11:]] == OLD_HEAD,
                "frozen remote scope differs")
        wanted = dict(expected)
        wanted[CANDIDATE_REF[11:]] = HEAD
        parents = sorted(set(expected.values()) | {HEAD})
        require(archive == {"tag": TAG, "tag_oid": TAG_OID, "commit": ARCHIVE_COMMIT,
                            "tree": ARCHIVE_TREE, "direct_parents": parents, "candidate_head": HEAD}
                and len(parents) == 893, "original archive differs")
        require(hook_spec == {"remote_heads": expected, "origin": URL, "updates": {
                    CANDIDATE_REF: {"new": HEAD, "old": OLD_HEAD},
                    TAGREF: {"new": TAG_OID, "old": "0" * 40}}},
                "original two-ref hook specification differs")
        require(previous["remote_heads"] == expected, "original timeout observation differs")
        _, _, gate_source = helpers["validate_gate_receipt"](
            spec["local_gate_receipt"], spec["local_gate_receipt_sha256"], HEAD, TREE)
        state["retained_gate_receipt"] = {"path": spec["local_gate_receipt"],
                                         "sha256": spec["local_gate_receipt_sha256"],
                                         "commands_rerun": False}
        state["git_version"] = run("git-version", ["git", "--version"]).stdout.decode().strip()
        for name, argv in (
                ("origin-push-url", ["git", "remote", "get-url", "--push", "--all", "origin"]),
                ("origin-fetch-url", ["git", "remote", "get-url", "--all", "origin"])):
            q = run(name, argv)
            require(q.stdout.decode().splitlines() == [URL],
                    "origin URL must be the unique exact authorized HTTPS URL")
        hook_config = run("original-hook-config", ["git", "config", "--get", "core.hooksPath"],
                          require_zero=False)
        require(hook_config.returncode == 1 and hook_config.stdout == b"" and hook_config.stderr == b"",
                "existing hooksPath configuration must not be overridden")
        hp = run("default-hook-path", ["git", "rev-parse", "--path-format=absolute",
                                       "--git-path", "hooks/pre-push"])
        default_hook = pathlib.Path(hp.stdout.decode().strip())
        require(not default_hook.exists() and not default_hook.is_symlink(),
                "existing default pre-push hook must not be overridden")
        for name, ref, oid in (("local-tag", TAGREF, TAG_OID),
                               ("local-archive", TAGREF + "^{}", ARCHIVE_COMMIT)):
            require(run(name, ["git", "rev-parse", "--verify", ref]).stdout.decode().strip() == oid,
                    "local archive reference differs")
        for kind, oid, maximum in (("tag", TAG_OID, 64 * 1024),
                                   ("commit", ARCHIVE_COMMIT, 128 * 1024)):
            size = run("archive-" + kind + "-size", ["git", "cat-file", "-s", oid]).stdout.decode().strip()
            require(re.fullmatch(r"[1-9][0-9]*", size) is not None and int(size) <= maximum,
                    "archive object exceeds fixed size bound")
            raw = run("archive-" + kind + "-object", ["git", "cat-file", kind, oid]).stdout
            require(len(raw) == int(size)
                    and hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == oid,
                    "archive raw object address differs")
            header, separator, _ = raw.partition(b"\n\n")
            require(separator == b"\n\n", "archive header terminator missing")
            lines = header.split(b"\n")
            if kind == "tag":
                require(lines[:3] == [b"object " + ARCHIVE_COMMIT.encode(), b"type commit",
                                     b"tag " + TAG.encode()], "archive tag headers differ")
            else:
                plines = [line for line in lines if line.startswith(b"parent ")]
                require(lines[0] == b"tree " + ARCHIVE_TREE.encode()
                        and lines[1:1 + len(parents)] == plines
                        and [line[7:].decode("ascii") for line in plines] == parents,
                        "archive commit tree/parent headers differ")
        run("project-preflight", ["bash", "scripts/project-preflight.sh", "--audit"], timeout=180)
        source_before = run("verify-source-before", [
            helpers["PYTHON"], "-B", "scripts/ci/verify_ci_source.py", "--kind", "head",
            "--expected-head", HEAD, "--output", str(ev / "source-before.json")], timeout=180).stdout
        require(regular_bytes(ev / "source-before.json") == source_before
                and helpers["validate_source_identity"](source_before, HEAD, TREE) == gate_source,
                "source-before stdout/sidecar/identity differs")
        state["identity_before"] = helpers["identity_snapshot"](env)
        require(state["identity_before"] == {"head": HEAD, "tree": TREE, "status": ""},
                "source-before HEAD/tree/status differs")
        for label, ancestor in (("candidate-fast-forward", OLD_HEAD), ("main-ancestry", MAIN_HEAD),
                                ("semantic-ledger-ancestry", "5c04c60e463462d9df8884786e0d5bb32af08a64")):
            run(label, ["git", "merge-base", "--is-ancestor", ancestor, HEAD])
        actor = strict_json(run("actor", ["gh", "api", "user", "--jq", "{login,id}"],
                                timeout=90).stdout)
        require(actor["login"] == "ProfHepta", "unexpected authenticated actor")
        pr = strict_json(run("pr-before", ["gh", "api", "repos/" + REPOSITORY + "/pulls/847",
            "--jq", "{number,state,draft,head:.head.sha,head_ref:.head.ref,base:.base.sha,base_ref:.base.ref,auto_merge}"],
            timeout=90).stdout)
        require(pr["number"] == 847 and pr["state"] == "open"
                and pr["head_ref"] == CANDIDATE_REF[11:] and pr["base_ref"] == "main"
                and pr["base"] == MAIN_HEAD and pr["auto_merge"] is None,
                "PR identity/base/state differs")
        before = observe("before")
        state["remote_before_classification"] = classify(before)
        require(state["remote_before_classification"] != "HOLD", "fresh remote state requires HOLD")
        expected_pr_head = HEAD if state["remote_before_classification"] == "both_new" else OLD_HEAD
        require(pr["head"] == expected_pr_head, "PR and remote head observation differ")
        if state["remote_before_classification"] == "both_new":
            state["status"] = "already_confirmed"
        else:
            hooks = ev / "hooks"
            hooks.mkdir(mode=0o700)
            with (hooks / "expected.json").open("xb") as stream:
                stream.write(original["hooks/expected.json"])
            with (ev / "original-pre-push").open("xb") as stream:
                stream.write(original["hooks/pre-push"])
            diagnostic_hook = instrument_hook(original["hooks/pre-push"])
            with (hooks / "pre-push").open("xb") as stream:
                stream.write(diagnostic_hook)
            (hooks / "pre-push").chmod(0o700)
            require(regular_bytes(hooks / "expected.json") == original["hooks/expected.json"]
                    and regular_bytes(hooks / "pre-push") == diagnostic_hook,
                    "diagnostic hook copy differs")
            state["hook"] = {"original_sha256": sha(original["hooks/pre-push"]),
                             "diagnostic_sha256": sha(diagnostic_hook),
                             "expected_sha256": sha(original["hooks/expected.json"]),
                             "only_fixed_markers_added": True}
            state["dry_run_started"] = True
            save()
            q = run("atomic-push-dry-run", [
                "git", "-c", "core.hooksPath=" + str(hooks), "push", "--dry-run", "--atomic",
                "--porcelain", "--verbose", "--progress", "origin",
                HEAD + ":" + CANDIDATE_REF, TAGREF + ":" + TAGREF],
                timeout=300, require_zero=False, sampled=True)
            state["dry_run_exit"] = q.returncode
            after = observe("after")
            state["remote_after_classification"] = classify(after)
            if q.returncode == 0 and state["remote_after_classification"] == "all_old_tag_absent" \
                    and not state.get("sampling_errors"):
                state["status"] = "diagnostic_complete"
            else:
                errors.append("Dry-run result requires review; no actual push or retry is authorized.")
    except Exception as error:
        errors.append(type(error).__name__ + ": " + str(error))
        state["status"] = "HOLD"
    finally:
        try:
            q = run("verify-source-after", [
                helpers["PYTHON"], "-B", "scripts/ci/verify_ci_source.py", "--kind", "head",
                "--expected-head", HEAD, "--output", str(ev / "source-after.json")],
                timeout=180, require_zero=False)
            after_source = regular_bytes(ev / "source-after.json")
            require(q.returncode == 0 and after_source == q.stdout
                    and helpers["validate_source_identity"](after_source, HEAD, TREE) == gate_source,
                    "source-after stdout/sidecar/identity differs")
            require(source_before == after_source, "source-before/after bytes differ")
            state["identity_after"] = helpers["identity_snapshot"](env)
            require(state["identity_after"] == {"head": HEAD, "tree": TREE, "status": ""},
                    "source-after HEAD/tree/status differs")
            state["source_after_valid"] = True
        except Exception as error:
            errors.append("source-after: " + type(error).__name__ + ": " + str(error))
            state["status"] = "HOLD"
        state["finished_at"] = now()
        state["diagnostic_does_not_validate_pack_transfer_or_server_write"] = True
        save()
    print(json.dumps({"status": state["status"], "summary": str(ev / "summary.json"),
                      "dry_run_exit": state["dry_run_exit"],
                      "source_after_valid": state["source_after_valid"]}), flush=True)
    return 0 if state["status"] in ("diagnostic_complete", "already_confirmed") else 1

if __name__ == "__main__":
    sys.exit(main())
