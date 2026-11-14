"""Apply the exact dynamic PR847 preparation and mark ready after readback.

Importing this module performs no work. The operator supplies the pinned final
input manifest and exact prepared-summary/desired digests. Each edit/ready
mutation is attempted at most once, with unconditional readback after a nonzero
or timeout result. There is no automatic retry, rollback, merge or Git push.
"""
import argparse, datetime, hashlib, json, os, pathlib, re, stat, sys

ROOT = pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
SOURCE = pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
SELF = ROOT / "apply_pr847_audit_update_and_ready_v3.py"
PREPARER = ROOT / "prepare_pr847_audit_update_v5.py"
PREPARER_SHA = "12776f0a436732589e46ef13548cb8f34180a532ab1ff63671560326c541cd6d"
PUBLISHER = ROOT / "publish_candidate_and_archive_v4.py"
PUBLISHER_SHA = "4105cd1db2e5219deda83a881872c51ac5cf671f5caa367bc2ea8ae4d4495038"
BASE = "dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
HEAD_REF = "fix/chain-hepta-closure-candidate-20261109-481716"
REPO = "TrillionniumFoundation/Trillionnium-Chain"
TITLE = "Consolidate audited branch history and current runtime"
QUERY = "{number,state,draft,node_id,head:.head.sha,head_ref:.head.ref,base:.base.sha,base_ref:.base.ref,title,body,auto_merge}"
PR_FIELDS = {"number", "state", "draft", "node_id", "head", "head_ref", "base",
             "base_ref", "title", "body", "auto_merge"}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)

def read_regular(path, expected_sha=None, maximum=8 * 1024 * 1024):
    path = pathlib.Path(path)
    require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent,
            "canonical input path required")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_size <= maximum, "regular bounded single-link file required")
    def fp(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        require(fp(os.fstat(stream.fileno())) == fp(before), "input changed before read")
        raw = stream.read(before.st_size + 1)
        require(fp(os.fstat(stream.fileno())) == fp(before), "input changed during read")
    require(fp(path.lstat()) == fp(before) and len(raw) == before.st_size,
            "input path or length changed during read")
    if expected_sha is not None:
        require(sha(raw) == expected_sha, "input SHA256 differs: " + str(path))
    return raw

def load_helpers():
    require(sys.flags.optimize == 0, "optimized interpreter is not allowed")
    raw = read_regular(PUBLISHER, PUBLISHER_SHA)
    namespace = {"__name__": "_reviewed_publication_capture_helpers", "__file__": str(PUBLISHER)}
    exec(compile(raw, str(PUBLISHER), "exec"), namespace)
    return namespace

def valid_pr_identity(value, node_id, head):
    require(isinstance(value, dict) and set(value) == PR_FIELDS, "PR field set differs")
    require(type(value["number"]) is int and value["number"] == 847
            and value["state"] == "open" and value["head"] == head
            and value["head_ref"] == HEAD_REF and value["base"] == BASE
            and value["base_ref"] == "main" and value["auto_merge"] is None,
            "PR number/state/head/base/auto_merge differs")
    require(isinstance(node_id, str) and bool(node_id) and value["node_id"] == node_id
            and type(value["draft"]) is bool and isinstance(value["title"], str)
            and (value["body"] is None or isinstance(value["body"], str)),
            "PR node/draft/metadata type differs")

def load_preparer():
    raw = read_regular(PREPARER, PREPARER_SHA)
    namespace = {"__name__": "_reviewed_dynamic_pr847_validator", "__file__": str(PREPARER)}
    exec(compile(raw, str(PREPARER), "exec"), namespace)
    require(namespace["ROOT"] == ROOT and namespace["SOURCE"] == SOURCE
            and namespace["BASE"] == BASE and namespace["REPO"] == REPO
            and namespace["HEAD_REF"] == HEAD_REF and namespace["QUERY"] == QUERY
            and namespace["TITLE"] == TITLE, "reviewed preparer scope differs")
    return namespace

def main():
    helpers = load_helpers()
    preparer = load_preparer()
    require(pathlib.Path(__file__).resolve(strict=True) == SELF, "unexpected driver path")
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--prepared-directory", required=True)
    parser.add_argument("--prepared-summary-sha256", required=True)
    parser.add_argument("--desired-sha256", required=True)
    parser.add_argument("--evidence-dir", required=True)
    args = parser.parse_args()
    for digest in (args.inputs_sha256, args.prepared_summary_sha256, args.desired_sha256):
        require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "exact operator SHA256 required")
    PREPARED = preparer["evidence_directory"](args.prepared_directory, "prepare-pr847-audit-update-v5")
    ev = preparer["evidence_directory"](args.evidence_dir, "apply-pr847-audit-update-and-ready-v3")
    ctx = preparer["validate_inputs"](args.inputs, args.inputs_sha256)
    HEAD, TREE = ctx["head"], ctx["tree"]
    os.umask(0o077)
    ev.mkdir(mode=0o700, exist_ok=False)
    inputs = ev / "inputs"
    inputs.mkdir(mode=0o700)
    env = preparer["safe_environment"](helpers)
    steps, errors, retained = [], [], []
    result = {
        "schema": "trnm-pr847-audit-metadata-ready-v3", "status": "HOLD",
        "started_at": now(), "head": HEAD, "tree": TREE, "base": BASE, "pr_number": 847,
        "driver": {"path": str(SELF), "sha256": sha(read_regular(SELF))},
        "inputs": ctx["input_pin"], "validated_facts": ctx["facts"],
        "prepared_summary_sha256": args.prepared_summary_sha256,
        "desired_sha256": args.desired_sha256, "prepared_directory": str(PREPARED),
        "metadata_attempted": False, "metadata_exit": None, "metadata_verified": False,
        "ready_attempted": False, "ready_exit": None, "ready_skipped_already_nondraft": False,
        "final_pr_verified": False, "source_before_after_valid": False,
        "automatic_retry_authorized": False, "rollback_authorized": False,
        "approval_or_reviewer_or_comment_or_merge_performed": False,
        "git_push_or_protection_change_performed": False, "hosted_qualification_granted": False,
        "steps": steps, "errors": errors, "retained_inputs": retained,
    }
    def save():
        (ev / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
        (ev / "steps.json").write_text(json.dumps(steps, indent=2) + "\n")
    def retain(name, path, expected_sha=None):
        raw = read_regular(path, expected_sha)
        target = inputs / name
        with target.open("xb") as stream:
            stream.write(raw)
        require(read_regular(target) == raw, "retained input differs")
        retained.append({"source_path": str(path), "retained_path": str(target),
                         "bytes": len(raw), "sha256": sha(raw)})
        return raw
    def run(label, argv, timeout=180, require_zero=True):
        started = now()
        q = helpers["capture"](argv, env, timeout=timeout)
        row = {"label": label, "argv": argv, "cwd": str(SOURCE), "exit": q.returncode,
               "timeout_seconds": timeout, "started_at": started, "finished_at": now()}
        for channel, raw in (("stdout", q.stdout), ("stderr", q.stderr)):
            path = ev / (label + "." + channel)
            with path.open("xb") as stream:
                stream.write(raw)
            row.update({channel + "_path": str(path), channel + "_bytes": len(raw),
                        channel + "_sha256": sha(raw)})
        steps.append(row)
        save()
        print(json.dumps({"label": label, "exit": q.returncode}), flush=True)
        require(not require_zero or q.returncode == 0, label + " failed; see retained outputs")
        return q
    def snapshot(phase):
        identity = {}
        for key, argv in (
                ("head", ["rev-parse", "HEAD"]), ("tree", ["rev-parse", "HEAD^{tree}"]),
                ("status", ["status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"])):
            q = run("identity-" + phase + "-" + key, ["git", "--no-replace-objects", *argv], timeout=60)
            identity[key] = q.stdout.decode().strip()
        require(identity == {"head": HEAD, "tree": TREE, "status": ""}, "source HEAD/tree/status differs")
        result["identity_" + phase] = identity
        return identity
    gate_source = source_before_raw = None
    def source_check(phase):
        q = run("verify-source-" + phase, [
            helpers["PYTHON"], "-B", "scripts/ci/verify_ci_source.py", "--kind", "head",
            "--expected-head", HEAD, "--output", str(ev / ("source-" + phase + ".json"))],
            require_zero=False)
        raw = read_regular(ev / ("source-" + phase + ".json"))
        require(q.returncode == 0 and q.stdout == raw, "source stdout/sidecar differs")
        require(helpers["validate_source_identity"](raw, HEAD, TREE) == gate_source,
                "source identity differs from the original exact gates")
        snapshot(phase)
        return raw
    def read_pr(label):
        q = run(label, ["gh", "api", "repos/" + REPO + "/pulls/847", "--jq", QUERY],
                require_zero=False)
        require(q.returncode == 0, label + " readback unavailable; HOLD")
        value = strict_json(q.stdout)
        result[label.replace("-", "_")] = value
        save()
        return value
    save()
    try:
        retain("preparer-v5.py", PREPARER, PREPARER_SHA)
        summary_raw = retain("prepared-summary.json", PREPARED / "summary.json", args.prepared_summary_sha256)
        prepared = strict_json(summary_raw)
        required_summary_fields = {
            "schema", "status", "remote_writes", "started_at", "finished_at", "driver",
            "inputs", "validated_facts", "dependencies", "retained_inputs", "steps", "errors",
            "before_raw_sha256", "before_title", "before_draft", "before_body_bytes",
            "desired_title", "desired_body_path", "desired_body_bytes", "desired_body_sha256",
            "desired_path", "desired_sha256",
        }
        require(isinstance(prepared, dict) and set(prepared) == required_summary_fields,
                "prepared summary field set differs")
        require(prepared["schema"] == "prepared-pr847-audit-update-v5"
                and prepared["status"] == "prepared" and prepared["remote_writes"] is False
                and prepared["errors"] == [] and prepared["inputs"] == ctx["input_pin"]
                and prepared["validated_facts"] == ctx["facts"]
                and prepared["driver"] == {"path": str(PREPARER), "sha256": PREPARER_SHA},
                "prepared exact final inputs/identity/scope differs")
        for key in ("started_at", "finished_at"):
            require(type(prepared[key]) is str and bool(prepared[key]), "prepared terminal time missing")
            datetime.datetime.fromisoformat(prepared[key])
        require(prepared["desired_path"] == str(PREPARED / "desired.json")
                and prepared["desired_body_path"] == str(PREPARED / "pr-body.md"),
                "prepared output path differs")
        dependencies = prepared["dependencies"]
        require(isinstance(dependencies, dict) and set(dependencies) == {"path", "bytes", "sha256"}
                and dependencies["path"] == str(PREPARED / "dependencies.json"),
                "prepared dependency index identity differs")
        dependency_raw = retain("prepared-dependencies.json", dependencies["path"], dependencies["sha256"])
        require(type(dependencies["bytes"]) is int and dependencies["bytes"] == len(dependency_raw)
                and strict_json(dependency_raw) == ctx["dependency_index"],
                "prepared dependencies differ from independently revalidated inputs")
        expected_retained = []
        for index, (name, source_path, original_raw) in enumerate(ctx["retained"]):
            target = PREPARED / "inputs" / name
            data = retain("prepared-input-" + str(index) + ".raw", target, sha(original_raw))
            require(data == original_raw, "prepared retained original differs")
            expected_retained.append({"source_path": source_path, "retained_path": str(target),
                                      "bytes": len(data), "sha256": sha(data)})
        require(prepared["retained_inputs"] == expected_retained,
                "prepared retained-input roster differs")
        desired_raw = retain("desired.json", PREPARED / "desired.json", args.desired_sha256)
        require(prepared["desired_sha256"] == args.desired_sha256, "prepared/desired SHA differs")
        desired = strict_json(desired_raw)
        body_raw = retain("pr-body.md", PREPARED / "pr-body.md", prepared["desired_body_sha256"])
        body = ctx["body_raw"].decode("utf-8")
        require(body_raw == ctx["body_raw"] and prepared["desired_title"] == TITLE
                and type(prepared["desired_body_bytes"]) is int
                and prepared["desired_body_bytes"] == len(body_raw), "exact reviewed body/title differs")
        original_steps_raw = retain("prepared-steps.json", PREPARED / "steps.json")
        original_steps = strict_json(original_steps_raw)
        require(original_steps == prepared["steps"] and len(original_steps) == 2,
                "prepared step closure differs")
        original_outputs = {}
        for step, (label, argv) in zip(original_steps, preparer["preparation_commands"]()):
            require(set(step) == {"label", "argv", "cwd", "exit", "timeout_seconds", "started_at",
                    "finished_at", "stdout_path", "stdout_bytes", "stdout_sha256",
                    "stderr_path", "stderr_bytes", "stderr_sha256"}
                    and step["label"] == label and step["argv"] == argv
                    and step["cwd"] == str(SOURCE)
                    and type(step["timeout_seconds"]) is int and step["timeout_seconds"] == 180
                    and type(step["exit"]) is int and step["exit"] == 0,
                    "prepared original command/cwd/budget/exit differs")
            for field in ("started_at", "finished_at"):
                require(type(step[field]) is str and bool(step[field]), "prepared step time missing")
                datetime.datetime.fromisoformat(step[field])
            for channel in ("stdout", "stderr"):
                name = label + "." + channel
                require(step[channel + "_path"] == str(PREPARED / name),
                        "prepared original stream path differs")
                data = retain("prepared-" + name, PREPARED / name, step[channel + "_sha256"])
                require(type(step[channel + "_bytes"]) is int and step[channel + "_bytes"] == len(data),
                        "prepared original stream bytes differ")
                original_outputs[name] = data
        original_actor = strict_json(original_outputs["actor.stdout"])
        require(original_actor == ctx["publication_actor"] and original_actor["login"] == "ProfHepta",
                "prepared actor differs from confirmed publication")
        before_raw = original_outputs["pr-before.stdout"]
        require(sha(before_raw) == prepared["before_raw_sha256"], "original PR snapshot SHA differs")
        before = strict_json(before_raw)
        valid_pr_identity(before, before["node_id"], HEAD)
        require(prepared["before_title"] == before["title"]
                and type(prepared["before_draft"]) is bool and prepared["before_draft"] == before["draft"]
                and type(prepared["before_body_bytes"]) is int
                and prepared["before_body_bytes"] == len((before["body"] or "").encode("utf-8")),
                "original PR summary binding differs")
        require(desired == {"title": TITLE, "body": body, "head": HEAD, "tree": TREE,
                            "base": BASE, "base_ref": "main", "pr_number": 847,
                            "pr_node_id": before["node_id"], "mark_ready_after_metadata_verified": True},
                "desired document differs from the exact reviewed rendering")
        require(type(desired["pr_number"]) is int
                and desired["mark_ready_after_metadata_verified"] is True, "desired operation type differs")
        gate_source = ctx["gate_source"]
        result["publication_receipt"] = {
            **ctx["facts"]["publication_receipt"], "status": "confirmed", "observation_phase": "after"}
        result["desired_title"] = TITLE
        result["desired_body_sha256"] = sha(body_raw)
        result["pr_node_id"] = before["node_id"]
        run("project-preflight", ["bash", "scripts/project-preflight.sh", "--audit"])
        source_before_raw = source_check("before")
        actor = strict_json(run("actor-fresh", ["gh", "api", "user", "--jq", "{login,id}"]).stdout)
        require(actor == original_actor and actor["login"] == "ProfHepta", "fresh authenticated actor differs")
        fresh = read_pr("pr-fresh-before")
        valid_pr_identity(fresh, before["node_id"], HEAD)
        require(fresh == before, "fresh PR differs from the prepared original; do not overwrite concurrent changes")
        ctx["F"]["check_versions"](ctx["snapshots"])
        exact_body_path = inputs / "pr-body.md"
        require(read_regular(exact_body_path) == body_raw, "body file changed before metadata mutation")
        result["metadata_attempted"] = True
        save()
        edit = run("metadata-edit-once", ["gh", "pr", "edit", "847", "--repo", REPO,
            "--title", TITLE, "--body-file", str(exact_body_path)], require_zero=False)
        result["metadata_exit"] = edit.returncode
        after_edit = read_pr("pr-after-edit")
        valid_pr_identity(after_edit, before["node_id"], HEAD)
        require(after_edit["title"] == TITLE and after_edit["body"] == body,
                "metadata mutation not confirmed by exact readback; ready is forbidden")
        result["metadata_verified"] = True
        if after_edit["draft"] is True:
            result["ready_attempted"] = True
            save()
            ready = run("mark-ready-once", ["gh", "pr", "ready", "847", "--repo", REPO],
                        require_zero=False)
            result["ready_exit"] = ready.returncode
        else:
            result["ready_skipped_already_nondraft"] = True
            save()
        final = read_pr("pr-final")
        valid_pr_identity(final, before["node_id"], HEAD)
        require(final["title"] == TITLE and final["body"] == body and final["draft"] is False,
                "final exact PR metadata/ready state is not confirmed")
        result["final_pr_verified"] = True
        result["status"] = "confirmed"
    except Exception as error:
        errors.append(type(error).__name__ + ": " + str(error))
        result["status"] = "HOLD"
    finally:
        try:
            after_raw = source_check("after")
            require(source_before_raw is not None and after_raw == source_before_raw,
                    "full source before/after differs")
            result["source_before_after_valid"] = True
        except Exception as error:
            errors.append("source-after: " + type(error).__name__ + ": " + str(error))
            result["status"] = "HOLD"
        result["finished_at"] = now()
        save()
    print(json.dumps({"status": result["status"], "summary": str(ev / "summary.json"),
                      "metadata_exit": result["metadata_exit"], "ready_exit": result["ready_exit"],
                      "final_pr_verified": result["final_pr_verified"],
                      "source_before_after_valid": result["source_before_after_valid"]}), flush=True)
    return 0 if result["status"] == "confirmed" else 1

if __name__ == "__main__":
    sys.exit(main())
