#!/usr/bin/env python3
"""Prepare one isolated socket continuation from a caller-pinned actual E1; no native tests or publication."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import traceback
import types

KEY = "chain-checkpoint-probe-source-prep-20261112-df05-v1"
ROOT = Path("/data/chain-checkpoint-probe-20261112-df05")
CONTROL = Path("/data/chain-checkpoint-probe-source-20261112-df05")
OLD_ROOT = Path("/data/chain-root-operation-owned-20261112-df05-v4")
BRANCH = "fix/chain-checkpoint-probe-20261112-df05"
PARENT_BRANCH = "fix/chain-root-operation-owned-20261112-df05-v4"
PRIOR_SOURCE = "87943f6229d8785c3f431ede5eadba62b634ab8c"
PRIOR_TREE = "5d2538f404e32319ea1084a6c79f37c52503546f"
PRIOR_PREFIX = "evidence/root-execution-v6-20261112-df05-v3/"
REPOSITORY = "TrillionniumFoundation/Trillionnium-Chain"
ORIGIN = "https://github.com/" + REPOSITORY + ".git"
CORPUS = "config/pon/pq-cross-branch-corpus-v1.json"
PLAN = "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
SOURCES = ("trillionnium/crates/trnm-checkpoint-store/src/lib.rs",
           "trillionnium/crates/trnm-checkpoint-store/tests/socket_ownership.rs")
PATHS = (*SOURCES, PLAN, CORPUS)
ORIGINALS = {
    SOURCES[0]: ("246eeb548a5b0736b023381bbf04d0a960ed3126", "e23dbefc7bb7f772413ce73526ff87c0483ab058c95183040c3e332e7a6dce6c"),
    SOURCES[1]: ("6e66fc4d007993acef6e48bdd611bd75c2eb2baa", "9265268c33a625c8793fca97d42807f77cfa35b383fb45132f42d811657a99c4"),
}
POST_SHA = {
    SOURCES[0]: "8ad6d9b14300c2df5d674604e4a0107e242c40d6a1e0f1a56d83763015b6f880",
    SOURCES[1]: "6c0482cab4ce234e32ebd388a856f1754aeaa48f299b1996f721420b0bac088f",
}
PLAN_ENTRY_SHA = "0458acbd35eed7528b2334643b0c19ed01bd960384d53321220809c16875e179"
VERIFIER_SHA = "0ddfd07719eae98913348c82b06d3e4522d721c353d9b01d6deac0dfda619946"
INDEX = ("-c", "core.sparseCheckout=false", "-c", "core.sparseCheckoutCone=false", "-c", "core.ignorestat=false")
ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
ENV.update(GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0",
           PYTHONDONTWRITEBYTECODE="1", PYTHONPYCACHEPREFIX=str(CONTROL / "pycache"),
           GH_HOST="github.com", GH_PROMPT_DISABLED="1", GH_PAGER="cat")
stage = "admission"
counter = 0


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(value):
    return hashlib.sha256(value).hexdigest()


def blob(value):
    return hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest()


def fingerprint(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def stable(path, cap=4 * 1024 * 1024):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap,
         "not a bounded single-link regular file: " + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        need(fingerprint(os.fstat(stream.fileno())) == fingerprint(before), "file admission race")
        raw = stream.read(cap + 1)
        need(fingerprint(os.fstat(stream.fileno())) == fingerprint(before), "file changed")
    need(len(raw) <= cap and fingerprint(path.lstat()) == fingerprint(before), "path changed")
    return raw


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def put(path, value):
    raw = value if isinstance(value, bytes) else (
        json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    need(not os.path.lexists(path), "refuse to overwrite retained artifact: " + str(path))
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fsync_dir(path.parent)


def command(name, argv, cwd, stdin=None, timeout=300, allowed=(0,)):
    global counter
    counter += 1
    prefix = CONTROL / "commands" / f"{counter:03d}-{name}"
    prefix.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    put(Path(str(prefix) + ".argv.json"), {"argv": argv, "cwd": str(cwd),
        "timeout_seconds": timeout, "stdin_bytes": len(stdin) if stdin is not None else 0,
        "stdin_sha256": sha(stdin) if stdin is not None else None})
    if stdin is not None:
        put(Path(str(prefix) + ".stdin"), stdin)
    with Path(str(prefix) + ".stdout").open("xb") as out, Path(str(prefix) + ".stderr").open("xb") as err:
        started = time.monotonic_ns()
        process = subprocess.Popen(argv, cwd=cwd, env=ENV, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                   stdout=out, stderr=err, start_new_session=True)
        timed_out = False
        try:
            process.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, 9)
            process.wait()
        out.flush()
        err.flush()
        os.fsync(out.fileno())
        os.fsync(err.fileno())
    row = {"exit_code": process.returncode, "timed_out": timed_out,
           "elapsed_ns": time.monotonic_ns() - started}
    put(Path(str(prefix) + ".result.json"), row)
    need(not timed_out and process.returncode in allowed, "command failed: " + name)
    return Path(str(prefix) + ".stdout").read_bytes()


def git(name, *args, cwd=ROOT, stdin=None, timeout=300):
    return command(name, ["git", "--no-replace-objects", *args], cwd, stdin, timeout)


def textgit(name, *args, cwd=ROOT):
    return git(name, *args, cwd=cwd).decode().strip()


def entries(commit, cwd=ROOT):
    result = {}
    raw = git("tree-" + commit[:8], "ls-tree", "-r", "-l", "-z", "--full-tree", commit, cwd=cwd)
    for row in raw.split(b"\0"):
        if row:
            meta, path = row.split(b"\t", 1)
            mode, kind, identity, length = meta.split()
            need(kind == b"blob" and mode in (b"100644", b"100755", b"120000"), "unsupported tree entry")
            result[path.decode()] = (mode.decode(), identity.decode(), int(length))
    return result


def physical(expected, label):
    flags = git(label + "-flags", "ls-files", "-v", "-z")
    need(not any(row and (row[:1].islower() or row[:1] == b"S") for row in flags.split(b"\0")),
         "hidden index flags")
    total = 0
    for name, (mode, identity, length) in expected.items():
        path = ROOT / name
        before = path.lstat()
        if mode == "120000":
            need(stat.S_ISLNK(before.st_mode), "symlink mode differs: " + name)
            raw = os.fsencode(os.readlink(path))
            need(len(raw) == length and blob(raw) == identity, "symlink differs: " + name)
        else:
            need(stat.S_ISREG(before.st_mode) and bool(before.st_mode & 0o111) == (mode == "100755"),
                 "regular mode differs: " + name)
            digest = hashlib.sha1(b"blob " + str(length).encode() + b"\0")
            count = 0
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                need(fingerprint(os.fstat(stream.fileno())) == fingerprint(before), "physical admission race")
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    count += len(block)
                    digest.update(block)
                need(fingerprint(os.fstat(stream.fileno())) == fingerprint(before), "physical file changed")
            need(count == length and digest.hexdigest() == identity, "physical content differs: " + name)
        need(fingerprint(path.lstat()) == fingerprint(before), "physical path changed")
        total += length
    put(CONTROL / (label + ".json"), {"tracked_entries": len(expected), "bytes": total,
                                     "all_modes_and_blobs_match": True, "hidden_index_flags": 0})


def original_preflight(label, *args):
    global counter
    output = command("preflight-" + label.lower(), ["bash", "scripts/project-preflight.sh", *args], ROOT, timeout=120)
    stem = CONTROL / "commands" / f"{counter:03d}-preflight-{label.lower()}"
    put(CONTROL / ("PREFLIGHT_" + label + ".stdout"), output)
    put(CONTROL / ("PREFLIGHT_" + label + ".stderr"), stable(Path(str(stem) + ".stderr")))
    result = json.loads(stable(Path(str(stem) + ".result.json")))
    argv = json.loads(stable(Path(str(stem) + ".argv.json")))
    put(CONTROL / ("PREFLIGHT_" + label + ".receipt.json"), {**result, **argv,
        "stdout_sha256": sha(output), "stderr_sha256": sha(stable(Path(str(stem) + ".stderr")))})


def validate_evidence_parent(source, tree):
    need(textgit("e1-tree", "rev-parse", source + "^{tree}", cwd=OLD_ROOT) == tree,
         "actual E1 tree differs")
    need(textgit("e1-parent", "show", "-s", "--format=%P", source, cwd=OLD_ROOT) == PRIOR_SOURCE,
         "E1 is not the sole evidence child of the prior tested source")
    need(textgit("prior-tree", "rev-parse", PRIOR_SOURCE + "^{tree}", cwd=OLD_ROOT) == PRIOR_TREE,
         "prior tested source identity differs")
    before, after = entries(PRIOR_SOURCE, cwd=OLD_ROOT), entries(source, cwd=OLD_ROOT)
    need(set(before) < set(after), "E1 did not add retained evidence")
    added = set(after) - set(before)
    need(all(name.startswith(PRIOR_PREFIX) and after[name][0] == "100644" for name in added),
         "unexpected E1 additions")
    need(all(after[name] == item for name, item in before.items() if name != CORPUS),
         "E1 changed product, tests, plans or modes")
    old = json.loads(git("prior-corpus", "show", PRIOR_SOURCE + ":" + CORPUS, cwd=OLD_ROOT))
    new = json.loads(git("e1-corpus", "show", source + ":" + CORPUS, cwd=OLD_ROOT))
    need(type(new.get("pinned_blobs")) is dict and type(new.get("required_paths")) is list,
         "corpus grammar differs")
    need(len(new["required_paths"]) == len(set(new["required_paths"])), "duplicate E1 required path")
    need(set(new["pinned_blobs"]) == set(old["pinned_blobs"]) | added,
         "E1 pin set is not exactly old plus evidence")
    need(new["required_paths"][:len(old["required_paths"])] == old["required_paths"]
         and set(new["required_paths"][len(old["required_paths"]):]) == added,
         "E1 required paths differ outside appended evidence")
    for name in added:
        need(new["pinned_blobs"][name] == after[name][1], "E1 archive pin mismatch")
        del new["pinned_blobs"][name]
    new["required_paths"] = new["required_paths"][:len(old["required_paths"])]
    need(new == old, "E1 changed unrelated corpus values")
    return after


def main():
    global stage
    os.umask(0o077)
    sys.dont_write_bytecode = True
    need(len(sys.argv) == 3 and sys.argv[1] == "--input-sha256"
         and re.fullmatch(r"[0-9a-f]{64}", sys.argv[2]), "reviewed exact input hash required")
    raw = sys.stdin.buffer.read(512 * 1024 + 1)
    need(len(raw) <= 512 * 1024 and sha(raw) == sys.argv[2], "reviewed input bytes differ")
    data = json.loads(raw)
    need(set(data) == {"schema", "operation_key", "base_evidence", "base_tree", "parent_pr",
                      "postimages", "plan_prepend", "program_sha256"}, "unreviewed input fields")
    source, tree = data["base_evidence"], data["base_tree"]
    need(re.fullmatch(r"[0-9a-f]{40}", source) and re.fullmatch(r"[0-9a-f]{40}", tree),
         "actual E1 identity remains UNBOUND")
    need(data["schema"] == "checkpoint-probe-source-input-v1" and data["operation_key"] == KEY
         and set(data["postimages"]) == set(SOURCES), "wrong source preparation input")
    program = (sys.orig_argv[sys.orig_argv.index("-c") + 1].encode()
               if "-c" in sys.orig_argv else Path(__file__).read_bytes())
    need(sha(program) == data["program_sha256"], "unreviewed program bytes")
    need(sha(data["plan_prepend"].encode()) == PLAN_ENTRY_SHA, "plan entry differs")
    need(not os.path.lexists(ROOT) and not os.path.lexists(CONTROL), "isolated path already exists; reconcile original operation")
    need(ROOT.parent == Path("/data") and CONTROL.parent == ROOT.parent
         and ROOT.parent.is_dir() and not ROOT.parent.is_symlink(), "unexpected storage root")
    CONTROL.mkdir(mode=0o700)
    put(CONTROL / "INPUT.json", raw)
    put(CONTROL / "driver.py", program)
    put(CONTROL / "INTENT.json", {"operation_key": KEY, "input_sha256": sha(raw), "program_sha256": sha(program),
        "parent_evidence": source, "parent_tree": tree, "worktree": str(ROOT), "branch": BRANCH,
        "allowed_paths": list(PATHS), "allowed_corpus_pin_paths": [*SOURCES, PLAN],
        "prior_source": PRIOR_SOURCE, "no_native_tests_or_publication": True})
    stage = "admit-actual-evidence-parent"
    need(textgit("old-head-before", "rev-parse", "HEAD", cwd=OLD_ROOT) == source, "old worktree is not actual E1")
    need(textgit("origin", "remote", "get-url", "--all", "origin", cwd=OLD_ROOT) == ORIGIN
         and textgit("push-origin", "remote", "get-url", "--push", "--all", "origin", cwd=OLD_ROOT) == ORIGIN,
         "wrong canonical repository")
    need(textgit("parent-branch", "branch", "--show-current", cwd=OLD_ROOT) == PARENT_BRANCH,
         "wrong parent branch")
    need(not git("old-clean", "status", "--porcelain", "--untracked-files=all", cwd=OLD_ROOT), "old E1 is dirty")
    parent = data["parent_pr"]
    need(type(parent) is dict and type(parent.get("number")) is int and parent["number"] > 0
         and parent.get("headRefName") == PARENT_BRANCH and parent.get("headRefOid") == source
         and parent.get("state") == "OPEN" and parent.get("isDraft") is True
         and parent.get("author_login") == "ProfHepta", "actual parent Draft input differs")
    actor = command("github-actor", ["gh", "api", "--hostname", "github.com", "user", "--jq", ".login"], OLD_ROOT).decode().strip()
    need(actor == "ProfHepta", "wrong native GitHub actor")
    actual_pr = json.loads(command("parent-draft", ["gh", "pr", "view", str(parent["number"]), "--repo", REPOSITORY,
        "--json", "number,url,state,isDraft,headRefName,headRefOid,baseRefName,author"], OLD_ROOT))
    projection = {name: actual_pr[name] for name in ("number", "url", "state", "isDraft", "headRefName", "headRefOid", "baseRefName")}
    projection["author_login"] = actual_pr["author"]["login"]
    need(projection == parent, "parent Draft moved or changed identity/state")
    baseline = validate_evidence_parent(source, tree)
    common = Path(textgit("common-dir", "rev-parse", "--git-common-dir", cwd=OLD_ROOT))
    if not common.is_absolute():
        common = (OLD_ROOT / common).resolve()
    config_before = stable(common / "config")
    put(CONTROL / "SHARED_CONFIG_IDENTITY.json", {"bytes": len(config_before), "sha256": sha(config_before)})
    usage = shutil.disk_usage(ROOT.parent)
    tracked_bytes = sum(row[2] for row in baseline.values())
    required = tracked_bytes + 1024 ** 3
    put(CONTROL / "STORAGE_ADMISSION.json", {"storage_root": str(ROOT.parent), "free_bytes": usage.free,
        "tracked_bytes": tracked_bytes, "tracked_entries": len(baseline), "required_free_bytes": required,
        "control_files_written_and_fsynced": True, "before_worktree_add": True})
    need(usage.free >= required, "insufficient space for complete source materialization")
    stage = "materialize-isolated-parent"
    # Use the ordinary checkout path so the repository's post-checkout hook runs.
    # Per-process sparse options affect only this operation; common config is retained.
    git("worktree-add", *INDEX, "worktree", "add", "-b", BRANCH, str(ROOT), source, cwd=OLD_ROOT, timeout=900)
    need(textgit("hook-index-tree", "write-tree") == tree,
         "post-checkout hook changed the admitted index; preserve and refuse")
    names = b"".join(name.encode() + b"\0" for name in baseline)
    for flag in ("--no-skip-worktree", "--no-assume-unchanged"):
        git("clear-before-" + flag[5:], *INDEX, "update-index", flag, "-z", "--stdin", stdin=names)
    missing = [name for name in baseline if not os.path.lexists(ROOT / name)]
    put(CONTROL / "MATERIALIZED_MISSING_PATHS.json", {"paths": missing,
        "existing_paths_not_overwritten": True, "post_checkout_hook_run_by_git": True})
    if missing:
        missing_names = b"".join(name.encode() + b"\0" for name in missing)
        git("materialize-missing-e1", *INDEX, "checkout-index", "-z", "--stdin", stdin=missing_names, timeout=900)
    git("refresh-source-index", *INDEX, "update-index", "--really-refresh")
    for flag in ("--no-skip-worktree", "--no-assume-unchanged"):
        git("clear-after-" + flag[5:], *INDEX, "update-index", flag, "-z", "--stdin", stdin=names)
    need(textgit("base-index-tree", "write-tree") == tree, "materialized index differs from E1")
    physical(baseline, "BASE_PHYSICAL")
    need(not git("base-clean", "status", "--porcelain", "--untracked-files=all"), "base dirty")
    original_preflight("BEFORE_EDIT")
    stage = "apply-four-reviewed-paths"
    originals = {name: git("preimage-" + str(index), "show", source + ":" + name)
                 for index, name in enumerate(PATHS)}
    posts = {name: data["postimages"][name].encode() for name in SOURCES}
    for name in SOURCES:
        need((blob(originals[name]), sha(originals[name])) == ORIGINALS[name], "reviewed original differs: " + name)
        need(sha(posts[name]) == POST_SHA[name], "reviewed postimage differs: " + name)
    entry = data["plan_prepend"].rstrip().encode() + b"\n\n"
    posts[PLAN] = entry + originals[PLAN]
    before = json.loads(originals[CORPUS])
    after = json.loads(originals[CORPUS])
    corpus_text = originals[CORPUS].decode()
    for name in (*SOURCES, PLAN):
        old_blob, new_blob = blob(originals[name]), blob(posts[name])
        need(before["pinned_blobs"][name] == old_blob and name in before["required_paths"], "old corpus identity differs")
        old_pair = json.dumps(name) + ": " + json.dumps(old_blob)
        new_pair = json.dumps(name) + ": " + json.dumps(new_blob)
        need(corpus_text.count(old_pair) == 1, "ambiguous pin span")
        corpus_text = corpus_text.replace(old_pair, new_pair, 1)
        after["pinned_blobs"][name] = new_blob
    posts[CORPUS] = corpus_text.encode()
    need(json.loads(posts[CORPUS]) == after and len(posts[CORPUS]) == len(originals[CORPUS]),
         "corpus differs outside exactly three existing equal-length pins")
    expected = dict(baseline)
    delta = []
    for name in PATHS:
        mode, old_blob, old_bytes = baseline[name]
        need(mode == "100644" and stable(ROOT / name) == originals[name], "preimage/mode mismatch")
        value = posts[name]
        temporary = ROOT / (name + ".checkpoint-probe.tmp")
        with temporary.open("xb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, ROOT / name)
        fsync_dir((ROOT / name).parent)
        expected[name] = (mode, blob(value), len(value))
        delta.append({"path": name, "old_mode": mode, "new_mode": mode,
            "old_blob": old_blob, "new_blob": blob(value), "old_bytes": old_bytes, "new_bytes": len(value),
            "old_sha256": sha(originals[name]), "new_sha256": sha(value)})
    put(CONTROL / "FOUR_PATH_DELTA.json", delta)
    git("stage-four-paths", *INDEX, "add", "--", *PATHS)
    staged = set(git("staged-paths", "diff", "--cached", "--name-only", "-z", source).decode().split("\0")) - {""}
    need(staged == set(PATHS), "unexpected staged path")
    candidate = textgit("candidate-tree", "write-tree")
    need(entries(candidate) == expected, "candidate tree differs outside four paths")
    physical(expected, "CANDIDATE_PHYSICAL")
    original_preflight("STAGED", "--staged")
    stage = "commit-new-source"
    put(CONTROL / "COMMIT_INTENT.json", {"parent": source, "candidate_tree": candidate,
        "branch": BRANCH, "four_path_delta": delta, "unknown_requires_read_only_reconciliation": True})
    git("commit", *INDEX, "commit", "-m", "fix(checkpoint): fence complete requests after connect-only probes", timeout=300)
    head = textgit("new-head", "rev-parse", "HEAD")
    actual_tree = textgit("new-tree", "rev-parse", head + "^{tree}")
    need(actual_tree == candidate and textgit("new-parent", "show", "-s", "--format=%P", head) == source
         and textgit("new-branch", "branch", "--show-current") == BRANCH, "new source identity differs")
    need(entries(head) == expected, "committed tree differs")
    physical(expected, "COMMITTED_PHYSICAL")
    need(not git("committed-clean", "status", "--porcelain", "--untracked-files=all"), "committed source dirty")
    stage = "original-source-verifier"
    verifier = ROOT / "scripts/ci/verify_ci_source.py"
    verifier_bytes = stable(verifier)
    need(sha(verifier_bytes) == VERIFIER_SHA, "original verifier differs")
    sys.path.insert(0, str(ROOT / "scripts/ci"))
    module = types.ModuleType("verify_ci_source")
    module.__file__ = str(verifier)
    module.__package__ = ""
    sys.modules[module.__name__] = module
    exec(compile(verifier_bytes, str(verifier), "exec"), module.__dict__)
    verification = module.verify("head", head, root=ROOT)
    put(CONTROL / "VERIFIED_PHYSICAL_SOURCE.json", verification)
    original_preflight("COMMITTED")
    need(textgit("old-head-after", "rev-parse", "HEAD", cwd=OLD_ROOT) == source
         and stable(common / "config") == config_before, "old head or shared config changed")
    safe_names = ["driver.py", "FOUR_PATH_DELTA.json", "BASE_PHYSICAL.json", "COMMITTED_PHYSICAL.json",
        "VERIFIED_PHYSICAL_SOURCE.json", "STORAGE_ADMISSION.json", "SHARED_CONFIG_IDENTITY.json"]
    safe_names += ["PREFLIGHT_" + label + suffix for label in ("BEFORE_EDIT", "STAGED", "COMMITTED")
                   for suffix in (".receipt.json", ".stdout", ".stderr")]
    safe_files = []
    for name in safe_names:
        value = stable(CONTROL / name)
        safe_files.append({"path": name, "bytes": len(value), "sha256": sha(value)})
    put(CONTROL / "SAFE_MANIFEST.json", {"schema": "checkpoint-probe-source-safe-manifest-v1",
        "source": head, "tree": actual_tree, "parent_evidence": source, "files": safe_files,
        "scope": "fixed sixteen safe source-preparation artifacts only; excludes INPUT and private command transcripts"})
    frozen = {"schema": "checkpoint-probe-source-v1", "operation_key": KEY,
        "head": head, "tree": actual_tree, "parent": source, "parent_tree": tree,
        "worktree": str(ROOT), "branch": BRANCH, "parent_pr": parent,
        "four_path_delta": delta, "allowed_corpus_pin_paths": [*SOURCES, PLAN],
        "unchanged_outside_four_paths": True, "source_clean": True, "shared_config_unchanged": True,
        "old_source_head_unchanged": True, "prior_root_source": PRIOR_SOURCE,
        "old_failures_reused_as_new_pass": False, "program_sha256": sha(program), "input_sha256": sha(raw),
        "safe_manifest_sha256": sha(stable(CONTROL / "SAFE_MANIFEST.json")),
        "native_tests_executed": False, "publication_performed": False, "production_activation": False, "status": "HOLD"}
    put(CONTROL / "FROZEN.json", frozen)
    print(json.dumps(frozen, sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        if CONTROL.is_dir() and not (CONTROL / "FROZEN.json").exists() and not (CONTROL / "FAILED.json").exists():
            put(CONTROL / "FAILED.json", {"operation_key": KEY, "stage": stage,
                "error_type": type(error).__name__, "error": str(error),
                "traceback": traceback.format_exc(), "no_success_inferred": True})
        raise
