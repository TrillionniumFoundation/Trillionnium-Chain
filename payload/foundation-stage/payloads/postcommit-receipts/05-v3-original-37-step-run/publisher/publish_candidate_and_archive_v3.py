"""Publish the audited candidate and an immutable full-history tag atomically.

This script never merges main, deletes refs, changes protection, cancels CI,
approves a PR, or qualifies a protocol. A fixed JSON spec and passing local
source-gate receipt are mandatory. Execute only from the authorized Mac.
"""
import argparse, datetime, hashlib, json, os, pathlib, re, signal, stat, subprocess, sys
ROOT = pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
SOURCE = pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
REPOSITORY = "TrillionniumFoundation/Trillionnium-Chain"
URL = "https://github.com/" + REPOSITORY + ".git"
CANDIDATE_REF = "refs/heads/fix/chain-hepta-closure-candidate-20261109-481716"
ZERO = "0" * 40
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def load_pinned(path, expected):
    p = pathlib.Path(path)
    assert p.is_file() and not p.is_symlink()
    raw = p.read_bytes()
    assert sha(raw) == expected, str(p)
    return json.loads(raw), raw

PYTHON = "/opt/homebrew/bin/python3"
GATE_ENV = {
    "PATH": "/Users/qianqi/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    "PYTHONDONTWRITEBYTECODE": "1", "PYTHONOPTIMIZE": "0",
    "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
    "GIT_TERMINAL_PROMPT": "0", "GH_PROMPT_DISABLED": "1",
}
def require(condition, message):
    if not condition:
        raise ValueError(message)
def require_unoptimized():
    if sys.flags.optimize != 0:
        raise RuntimeError("optimized Python disables publication guards")
def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)
def regular_bytes(path):
    path = pathlib.Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), "expected regular file: " + str(path))
    def fingerprint(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before),
                "file changed before read: " + str(path))
        raw = stream.read()
        require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before),
                "file changed during read: " + str(path))
    require(fingerprint(path.lstat()) == fingerprint(before),
            "file path changed during read: " + str(path))
    return raw
def gate_commands(head, evidence):
    evidence = pathlib.Path(evidence)
    def source(label):
        return [PYTHON, "-B", "scripts/ci/verify_ci_source.py", "--kind", "head",
                "--expected-head", head, "--output", str(evidence / ("source-" + label + ".json"))]
    return [
        ("preflight-audit", ["bash", "scripts/project-preflight.sh", "--audit"]),
        ("verify-source-before", source("before")),
        ("repository-check", [PYTHON, "-B", "scripts/ci/check_repository.py"]),
        ("distributed-inventory-check", [PYTHON, "-B", "scripts/refresh_distributed_source_inventory.py", "--check"]),
        ("ci-contract", [PYTHON, "-B", "scripts/ci/check_ci_contract.py"]),
        ("pq-corpus", [PYTHON, "-B", "scripts/ci/check_pq_research_integration.py"]),
        ("verify-source-after", source("after")),
    ]
def validate_source_identity(raw, head, tree):
    value = strict_json(raw)
    expected = {
        "schema": "trnm-ci-source-v1", "kind": "head",
        "tested_commit": head, "tested_tree": tree, "candidate": head,
        "base": None, "prospective_merge": None,
        "tracked_worktree_verified": True, "tests_executed_by_identity_check": False,
    }
    require(isinstance(value, dict) and set(value) == set(expected) | {"tracked_entries", "tracked_bytes"},
            "source receipt field set differs")
    for key, wanted in expected.items():
        require(type(value[key]) is type(wanted) and value[key] == wanted,
                "source receipt identity differs: " + key)
    for key in ("tracked_entries", "tracked_bytes"):
        require(type(value[key]) is int and value[key] > 0, "empty or invalid source count: " + key)
    return value
def capture(argv, env, data=None, timeout=180):
    """Capture one owned process group; never retry a timed-out command."""
    try:
        process = subprocess.Popen(argv, cwd=SOURCE, env=env,
            stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    except OSError as error:
        return subprocess.CompletedProcess(argv, 127, b"", str(error).encode())
    try:
        stdout, stderr = process.communicate(data, timeout=timeout)
        return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)
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
        return subprocess.CompletedProcess(argv, 124, stdout, stderr)
def identity_snapshot(env):
    values = {}
    for name, args in (("head", ["rev-parse", "HEAD"]),
                       ("tree", ["rev-parse", "HEAD^{tree}"]),
                       ("status", ["status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"])):
        result = capture(["git", "--no-replace-objects", *args], env, timeout=60)
        require(result.returncode == 0, "identity read failed: " + name + ": " + result.stderr.decode(errors="replace"))
        values[name] = result.stdout.decode().strip()
    return values

GATE_PRODUCER_SHA256 = "e7bc466fcf570a20745954c8627b8af9227582484b251dfcf7900e7942fa7496"
def validate_gate_receipt(path, expected_sha, head, tree):
    path = pathlib.Path(path)
    evidence = path.parent
    require(path.name == "receipt.json" and evidence.parent == ROOT
            and evidence.resolve(strict=True) == evidence and not evidence.is_symlink(),
            "gate receipt must use its canonical original evidence directory")
    raw = regular_bytes(path)
    require(sha(raw) == expected_sha, "gate receipt SHA differs")
    gate = strict_json(raw)
    require(gate["schema"] == "root-final-prepublication-source-gates-v1"
            and gate["head"] == head and gate["tree"] == tree
            and gate["status"] == "passed" and gate["errors"] == [], "gate identity/status differs")
    require(gate["source"] == str(SOURCE) and gate["evidence_dir"] == str(evidence),
            "gate source/evidence cwd differs")
    require(gate["environment"] == GATE_ENV and gate["hosted_ci_qualification"] is False,
            "gate environment/scope differs")
    producer = ROOT / "run_final_prepublication_gates_v1.py"
    require(gate["producer"] == {"path": str(producer), "sha256": GATE_PRODUCER_SHA256}
            and sha(regular_bytes(producer)) == GATE_PRODUCER_SHA256, "gate producer differs")
    wanted_identity = {"head": head, "tree": tree, "status": ""}
    require(gate["identities"] == {"before": wanted_identity, "after": wanted_identity},
            "gate HEAD/tree/status snapshots differ")
    commands = gate_commands(head, evidence)
    steps = gate["steps"]
    require(isinstance(steps, list) and len(steps) == len(commands)
            and [step["label"] for step in steps] == [label for label, _ in commands],
            "gate must contain exactly the seven ordered original commands")
    outputs = {}
    for step, (label, argv) in zip(steps, commands):
        require(step["cwd"] == str(SOURCE) and step["argv"] == argv
                and type(step["exit"]) is int and step["exit"] == 0, "gate command/cwd/exit differs: " + label)
        for channel in ("stdout", "stderr"):
            expected_path = evidence / (label + "." + channel)
            require(step[channel + "_path"] == str(expected_path), "gate output path differs: " + label)
            data = regular_bytes(expected_path)
            require(type(step[channel + "_bytes"]) is int
                    and len(data) == step[channel + "_bytes"]
                    and sha(data) == step[channel + "_sha256"], "gate output bytes differ: " + label)
            outputs[(label, channel)] = data
    require(set(gate["source_observations"]) == {"before", "after"}, "source observation pair missing")
    sources = {}
    for phase in ("before", "after"):
        source_path = evidence / ("source-" + phase + ".json")
        entry = gate["source_observations"][phase]
        data = regular_bytes(source_path)
        require(entry["path"] == str(source_path) and type(entry["bytes"]) is int
                and len(data) == entry["bytes"] and sha(data) == entry["sha256"],
                "source sidecar bytes differ: " + phase)
        require(data == outputs[("verify-source-" + phase, "stdout")],
                "source stdout and sidecar differ: " + phase)
        value = validate_source_identity(data, head, tree)
        require(entry["identity"] == value, "embedded source identity differs")
        sources[phase] = value
    require(sources["before"] == sources["after"], "source before/after content differs")
    return gate, raw, sources["before"]

def main():
    require_unoptimized()
    publisher_path = ROOT / "publish_candidate_and_archive_v3.py"
    require(pathlib.Path(__file__).resolve(strict=True) == publisher_path, "unexpected publisher path")
    publisher_source = regular_bytes(publisher_path)
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True)
    parser.add_argument("--spec-sha256", required=True)
    args = parser.parse_args()
    spec, spec_raw = load_pinned(args.spec, args.spec_sha256)
    ev = pathlib.Path(spec["evidence_dir"])
    assert ev.parent == ROOT and re.fullmatch(r"publish-candidate-and-archive-[a-z0-9-]+", ev.name)
    ev.mkdir(exist_ok=False)
    (ev / "spec.json").write_bytes(spec_raw)
    env = os.environ.copy()
    env.update(PATH="/Users/qianqi/.rustup/toolchains/1.95.0-aarch64-apple-darwin/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
               GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0",
               GH_PROMPT_DISABLED="1", PYTHONDONTWRITEBYTECODE="1")
    env.update(GATE_ENV)
    steps = []
    def run(label, argv, data=None, require_zero=True, timeout=180):
        q = capture(argv, env, data=data, timeout=timeout)
        for suffix, raw in [("stdout", q.stdout), ("stderr", q.stderr)]:
            with (ev / (label + "." + suffix)).open("xb") as f:
                f.write(raw)
        row = {"label": label, "argv": argv, "exit": q.returncode,
               "stdout_sha256": sha(q.stdout), "stderr_sha256": sha(q.stderr),
               "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        steps.append(row)
        (ev / "steps.json").write_text(json.dumps(steps, indent=2) + "\n")
        print(json.dumps({"label": label, "exit": q.returncode}), flush=True)
        if require_zero:
            assert q.returncode == 0, (label, "see retained stdout/stderr")
        return q
    def git(*argv):
        return subprocess.check_output(["git", *argv], cwd=SOURCE, env=env).decode().strip()
    def heads(raw):
        result = {}
        for line in raw.decode().splitlines():
            oid, ref = line.split()
            assert re.fullmatch(r"[0-9a-f]{40}", oid) and ref.startswith("refs/heads/")
            assert ref[11:] not in result
            result[ref[11:]] = oid
        return dict(sorted(result.items()))
    expected, expected_raw = load_pinned(spec["expected_remote_manifest"], spec["expected_remote_sha256"])
    frozen, frozen_raw = load_pinned(spec["frozen_remote_manifest"], spec["frozen_remote_sha256"])
    assert spec["frozen_remote_sha256"] == "e52bb1c8c0963b2ddd303761ffe7ba949c080b3a0f72983f508978f8971e7734"
    assert expected == {x["name"]: x["sha"] for x in frozen}
    assert len(expected) == 908 and len(set(expected.values())) == 892
    assert expected["main"] == "dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
    assert expected[CANDIDATE_REF[11:]] == "e40d7071c4724e6600deef8a2820bf35c1982289"
    head, tree = spec["candidate_head"], spec["candidate_tree"]
    assert re.fullmatch(r"[0-9a-f]{40}", head) and re.fullmatch(r"[0-9a-f]{40}", tree)
    assert git("rev-parse", "HEAD") == head and git("rev-parse", "HEAD^{tree}") == tree
    assert git("status", "--porcelain") == ""
    assert git("remote", "get-url", "origin") in {URL, URL[:-4], "git@github.com:" + REPOSITORY + ".git"}
    gate, gate_raw, gate_source = validate_gate_receipt(
        spec["local_gate_receipt"], spec["local_gate_receipt_sha256"], head, tree)
    (ev / "local-gate-receipt.json").write_bytes(gate_raw)
    run("project-preflight", ["bash", "scripts/project-preflight.sh", "--audit"])
    run("verify-source-before", ["python3", "-B", "scripts/ci/verify_ci_source.py",
        "--kind", "head", "--expected-head", head, "--output", str(ev / "source-before.json")])
    fresh_source_raw = regular_bytes(ev / "source-before.json")
    require(fresh_source_raw == regular_bytes(ev / "verify-source-before.stdout"),
            "live source stdout/sidecar differs")
    require(validate_source_identity(fresh_source_raw, head, tree) == gate_source,
            "live source identity differs from the gate receipt")
    for label, before in [("candidate-fast-forward", expected[CANDIDATE_REF[11:]]),
                          ("main-ancestry", expected["main"]),
                          ("semantic-ledger-ancestry", "5c04c60e463462d9df8884786e0d5bb32af08a64")]:
        run(label, ["git", "merge-base", "--is-ancestor", before, head])
    actor = json.loads(run("actor", ["gh", "api", "user", "--jq", "{login,id}"]).stdout)
    assert actor["login"] == "ProfHepta"
    pr = json.loads(run("pr-before", ["gh", "api", "repos/" + REPOSITORY + "/pulls/847",
        "--jq", "{number,state,draft,head:.head.sha,head_ref:.head.ref,base:.base.sha,base_ref:.base.ref,auto_merge}"]).stdout)
    assert pr["state"] == "open" and pr["head"] == expected[CANDIDATE_REF[11:]]
    assert pr["head_ref"] == CANDIDATE_REF[11:] and pr["base_ref"] == "main" and pr["base"] == expected["main"]
    assert pr["auto_merge"] is None
    live = heads(run("refs-before", ["git", "ls-remote", "--heads", "origin"]).stdout)
    assert live == expected, "remote changes require a fresh review before publication"
    tag = spec["archive_tag"]
    assert tag == "archive/branches-before-consolidation-20261114-" + head[:12]
    tagref = "refs/tags/" + tag
    run("archive-ref-format", ["git", "check-ref-format", tagref])
    assert run("archive-remote-absence", ["git", "ls-remote", "origin", tagref, tagref + "^{}"]).stdout == b""
    assert subprocess.run(["git", "show-ref", "--verify", "--quiet", tagref], cwd=SOURCE, env=env).returncode == 1
    # No existing hook is overridden. The per-command hook only adds strict checks.
    hook_config = subprocess.run(["git", "config", "--get", "core.hooksPath"], cwd=SOURCE, env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert hook_config.returncode == 1 and not hook_config.stdout
    default_hook = pathlib.Path(git("rev-parse", "--path-format=absolute", "--git-path", "hooks/pre-push"))
    assert not default_hook.exists() and not default_hook.is_symlink()
    archive_record = {"schema": "trnm-pre-consolidation-history-archive-v1",
        "frozen_manifest_sha256": sha(frozen_raw), "observed_remote_manifest_sha256": sha(expected_raw),
        "branch_names": 908, "distinct_remote_tips": 892, "candidate_head": head, "candidate_tree": tree,
        "archive_preserves_history_not_semantic_equivalence": True,
        "main_merge_performed": False, "branches_deleted": False,
        "required_head_and_prospective_ci_qualification": False}
    files = {
        "branches-frozen-0170.json": frozen_raw,
        "branches-before-publication.json": expected_raw,
        "candidate-and-scope.json": (json.dumps(archive_record, indent=2) + "\n").encode(),
        "prepublication-source-gates.json": gate_raw,
        "README.md": ("# Pre-consolidation branch history\n\nThis immutable tag retains every recorded remote branch tip as a direct parent, "
            "plus the reviewed candidate. It is a historical archive, not a declaration that old implementations are active or equivalent. "
            "No main merge, branch deletion, production activation, or hosted qualification is represented by this tag. "
            "The candidate's committed audit report contains the complete disposition ledger and evidence index.\n").encode()
    }
    # Retain the already-validated gate's original bytes, not only paths into /tmp.
    require(regular_bytes(pathlib.Path(spec["local_gate_receipt"])) == gate_raw
            and sha(gate_raw) == spec["local_gate_receipt_sha256"],
            "gate receipt changed before archiving")
    archived_gate_artifacts = []
    def archive_gate_file(name, path, expected_bytes, expected_sha):
        require(name not in files and "/" not in name, "duplicate/non-flat gate archive name")
        raw = regular_bytes(pathlib.Path(path))
        require(len(raw) == expected_bytes and sha(raw) == expected_sha,
                "gate artifact changed before archiving: " + name)
        files[name] = raw
        archived_gate_artifacts.append({"archive_name": name, "original_path": str(path),
                                        "bytes": len(raw), "sha256": sha(raw)})
    for step in gate["steps"]:
        for channel in ("stdout", "stderr"):
            archive_gate_file("gate-" + step["label"] + "." + channel,
                              step[channel + "_path"], step[channel + "_bytes"],
                              step[channel + "_sha256"])
    for phase in ("before", "after"):
        entry = gate["source_observations"][phase]
        archive_gate_file("gate-source-" + phase + ".json", entry["path"],
                          entry["bytes"], entry["sha256"])
    producer_path = ROOT / "run_final_prepublication_gates_v1.py"
    producer_source = regular_bytes(producer_path)
    require(sha(producer_source) == GATE_PRODUCER_SHA256 == gate["producer"]["sha256"],
            "gate producer changed before archiving")
    archive_gate_file("gate-producer.py", producer_path, len(producer_source), GATE_PRODUCER_SHA256)
    require(regular_bytes(publisher_path) == publisher_source,
            "publisher source changed before archiving")
    archive_gate_file("publisher-script.py", publisher_path, len(publisher_source), sha(publisher_source))
    files["gate-evidence-index.json"] = (json.dumps({
        "schema": "trnm-archived-source-gate-artifacts-v1",
        "gate_receipt_sha256": sha(gate_raw),
        "artifacts": archived_gate_artifacts,
        "qualification_granted": False,
    }, indent=2) + "\n").encode()
    tree_lines = []
    for name, raw in sorted(files.items()):
        oid = run("archive-blob-" + name.replace(".", "-"), ["git", "hash-object", "-w", "--stdin"], data=raw).stdout.decode().strip()
        assert re.fullmatch(r"[0-9a-f]{40}", oid)
        tree_lines.append("100644 blob " + oid + "\t" + name + "\n")
    archive_tree = run("archive-tree", ["git", "mktree"], data="".join(tree_lines).encode()).stdout.decode().strip()
    parents = sorted(set(expected.values()) | {head})
    argv = ["git", "commit-tree", archive_tree]
    for oid in parents:
        argv += ["-p", oid]
    archive_commit = run("archive-commit", argv, data=("Preserve all 908 pre-consolidation branch names and audited candidate " + head + "\n").encode()).stdout.decode().strip()
    run("archive-annotated-tag", ["git", "tag", "-a", tag, archive_commit, "-m",
        "Immutable full branch history archive; 908 names, 892 remote tips, plus candidate " + head +
        ". Original manifest SHA256 " + sha(frozen_raw) + ". No main merge or protocol qualification granted."])
    tag_oid = git("rev-parse", tagref)
    assert git("rev-parse", tagref + "^{}") == archive_commit
    recorded_parents = git("show", "-s", "--format=%P", archive_commit).split()
    assert recorded_parents == parents and set(expected.values()) <= set(recorded_parents)
    reachable = set(run("archive-reachability", ["git", "rev-list", archive_commit]).stdout.decode().splitlines())
    assert set(expected.values()) | {head} <= reachable
    run("archive-connectivity", ["git", "fsck", "--connectivity-only", "--no-reflogs", archive_commit], timeout=300)
    hook_dir = ev / "hooks"
    hook_dir.mkdir()
    hook_spec = {"remote_heads": expected, "origin": URL,
                 "updates": {CANDIDATE_REF: {"new": head, "old": expected[CANDIDATE_REF[11:]]},
                             tagref: {"new": tag_oid, "old": ZERO}}}
    (hook_dir / "expected.json").write_text(json.dumps(hook_spec, sort_keys=True) + "\n")
    hook = """#!/opt/homebrew/bin/python3
import json,pathlib,subprocess,sys
if sys.flags.optimize != 0:
 raise RuntimeError("optimized Python disables pre-push guards")
spec=json.loads(pathlib.Path(__file__).with_name("expected.json").read_text())
assert len(sys.argv)==3 and sys.argv[1]=="origin"
assert sys.argv[2] in {spec["origin"],spec["origin"][:-4],"git@github.com:TrillionniumFoundation/Trillionnium-Chain.git"}
seen={}
for line in sys.stdin.read().splitlines():
 local_ref,new,remote_ref,old=line.split()
 assert remote_ref not in seen
 seen[remote_ref]={"new":new,"old":old}
assert seen==spec["updates"],"unexpected push update"
raw=subprocess.check_output(["git","ls-remote","--heads","origin"],timeout=90)
actual={}
for line in raw.decode().splitlines():
 oid,ref=line.split()
 assert ref.startswith("refs/heads/") and ref[11:] not in actual
 actual[ref[11:]]=oid
assert actual==spec["remote_heads"],"remote set changed after review"
"""
    hp = hook_dir / "pre-push"
    hp.write_text(hook)
    hp.chmod(0o700)
    archive_info = {"tag": tag, "tag_oid": tag_oid, "commit": archive_commit,
                    "tree": archive_tree, "direct_parents": parents, "candidate_head": head}
    (ev / "archive-local.json").write_text(json.dumps(archive_info, indent=2) + "\n")
    run("prepush-preflight", ["bash", "scripts/project-preflight.sh", "--audit"])
    push = run("atomic-publish", ["git", "-c", "core.hooksPath=" + str(hook_dir),
        "push", "--atomic", "--porcelain", "origin", head + ":" + CANDIDATE_REF, tagref + ":" + tagref],
        require_zero=False, timeout=300)
    # Always read both destinations, even after a timeout or failed heads read.
    # No old/partial observation authorizes a retry or rollback.
    after_run = run("refs-after", ["git", "ls-remote", "--heads", "origin"], require_zero=False)
    tag_run = run("archive-remote-readback",
                  ["git", "ls-remote", "origin", tagref, tagref + "^{}"], require_zero=False)
    wanted = dict(expected)
    wanted[CANDIDATE_REF[11:]] = head
    after, remote_tags, reconciliation_errors = None, None, []
    if after_run.returncode == 0:
        try:
            after = heads(after_run.stdout)
        except Exception as error:
            reconciliation_errors.append("heads parse: " + repr(error))
    else:
        reconciliation_errors.append("heads read failed: " + str(after_run.returncode))
    if tag_run.returncode == 0:
        try:
            remote_tags = {}
            for line in tag_run.stdout.decode().splitlines():
                oid, ref = line.split()
                require(re.fullmatch(r"[0-9a-f]{40}", oid) is not None
                        and ref in (tagref, tagref + "^{}") and ref not in remote_tags,
                        "unexpected/duplicate archive tag advertisement")
                remote_tags[ref] = oid
        except Exception as error:
            remote_tags = None
            reconciliation_errors.append("tag parse: " + repr(error))
    else:
        reconciliation_errors.append("tag read failed: " + str(tag_run.returncode))
    confirmed = (after == wanted and remote_tags == {tagref: tag_oid, tagref + "^{}": archive_commit})
    result = {
        "schema": "trnm-candidate-and-archive-publication-receipt-v2",
        "status": "confirmed" if confirmed else "UNKNOWN",
        "head": head, "tree": tree, "archive": archive_info,
        "remote_branches": len(after) if after is not None else None,
        "remote_heads": after, "remote_archive_tags": remote_tags,
        "archive_remote_verified": remote_tags == {tagref: tag_oid, tagref + "^{}": archive_commit},
        "push_exit": push.returncode, "readback_errors": reconciliation_errors,
        "automatic_retry_authorized": False, "required_ci_must_still_pass": True,
        "main_merged": False, "branches_deleted": False, "protection_changed": False,
        "qualification_granted": False, "postpublication_source_valid": None, "steps": steps,
    }
    # Persist the actual remote observation before any subsequent local check.
    (ev / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    source_after = run("verify-source-after", [PYTHON, "-B", "scripts/ci/verify_ci_source.py",
        "--kind", "head", "--expected-head", head, "--output", str(ev / "source-after.json")],
        require_zero=False)
    try:
        require(source_after.returncode == 0, "postpublication source check failed")
        raw = regular_bytes(ev / "source-after.json")
        require(raw == source_after.stdout and validate_source_identity(raw, head, tree) == gate_source,
                "postpublication source stdout/sidecar/identity differs")
        require(identity_snapshot(env) == {"head": head, "tree": tree, "status": ""},
                "postpublication HEAD/tree/status differs")
        result["postpublication_source_valid"] = True
    except Exception as error:
        result["postpublication_source_valid"] = False
        result["postpublication_source_error"] = repr(error)
    (ev / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items()
                     if k not in {"steps", "archive", "remote_heads"}}), flush=True)
    return 0 if confirmed and result["postpublication_source_valid"] else 1
if __name__ == "__main__":
    sys.exit(main())
