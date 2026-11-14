"""Prepare PR847's exact reviewed metadata after the fixed follow-up publisher.

This module is inert on import. Only main performs two read-only GitHub queries.
Final source/publication/receipt facts come from one operator-pinned manifest.
No PR mutation, Git write, Host operation, hosted pass or activation is granted.
"""
import argparse, datetime, hashlib, json, os, pathlib, re, stat, string, sys

ROOT = pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
SOURCE = pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
SELF = ROOT / "prepare_pr847_audit_update_v4.py"
FOLLOWUP = ROOT / "publish_followup_candidate_execution_archive_v1.py"
FOLLOWUP_BYTES = 71594
FOLLOWUP_SHA = "8510653d14ac5e9870e624137197c0f7d2fd193a37dc4c57a5f65b127a45398d"
PUBLISHER = ROOT / "publish_candidate_and_archive_v4.py"
PUBLISHER_SHA = "4105cd1db2e5219deda83a881872c51ac5cf671f5caa367bc2ea8ae4d4495038"
TEMPLATE = ROOT / "pr847-audit-body-template-v3.md"
TEMPLATE_SHA = "0d37a8132e7d9b262eefdb02f1e2968f26b5f8ec17e59a2701343cc9d611073a"
REPO = "TrillionniumFoundation/Trillionnium-Chain"
URL = "https://github.com/" + REPO
BASE = "dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
HEAD_REF = "fix/chain-hepta-closure-candidate-20261109-481716"
TITLE = "Consolidate audited branch history and current runtime"
QUERY = "{number,state,draft,node_id,head:.head.sha,head_ref:.head.ref,base:.base.sha,base_ref:.base.ref,title,body,auto_merge}"
PR_FIELDS = {"number", "state", "draft", "node_id", "head", "head_ref", "base",
             "base_ref", "title", "body", "auto_merge"}
PLACEHOLDERS = {
    "url", "head", "tree", "base", "execution_evidence_url", "publication_manifest_url",
    "seven_source_status", "seven_source_receipt_url", "full_linux_status",
    "full_linux_receipt_url", "hosted_head_status", "hosted_head_checks_url",
    "hosted_merge_status", "hosted_merge_checks_url", "hosted_observed_at",
    "historical_collector_disposition", "archive_tag", "tag_oid", "archive_commit",
    "archive_candidate_head",
}

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

def load_fixed_helpers():
    require(sys.flags.optimize == 0, "optimized interpreter is not allowed")
    raw = read_regular(FOLLOWUP, FOLLOWUP_SHA)
    require(len(raw) == FOLLOWUP_BYTES, "reviewed follow-up producer length differs")
    F = {"__name__": "_reviewed_followup_validation_helpers", "__file__": str(FOLLOWUP)}
    exec(compile(raw, str(FOLLOWUP), "exec"), F)
    require(F["ROOT"] == ROOT and F["SOURCE"] == SOURCE and F["REPOSITORY"] == REPO
            and F["MAIN_HEAD"] == BASE and F["CANDIDATE_REF"] == "refs/heads/" + HEAD_REF,
            "fixed follow-up helper scope differs")
    H = F["bootstrap_helpers"]()
    require(H["ROOT"] == ROOT and H["SOURCE"] == SOURCE
            and H["URL"] == URL + ".git" and F["PUBLISHER_SHA"] == PUBLISHER_SHA,
            "reviewed original capture helper scope differs")
    return F, H

def safe_environment(H):
    env = os.environ.copy()
    for key in ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE",
                "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
                "GIT_NAMESPACE", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        require(key not in env, "unexpected inherited Git repository/config override: " + key)
    for key in tuple(env):
        if key.startswith("GIT_TRACE") or key == "GIT_CURL_VERBOSE":
            del env[key]
    env.update(H["GATE_ENV"])
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_TRACE2="0", GIT_TRACE2_EVENT="0",
               GIT_TRACE2_PERF="0", PYTHONOPTIMIZE="0", PYTHONDONTWRITEBYTECODE="1")
    return env

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

def evidence_directory(value, prefix):
    path = pathlib.Path(value)
    require(path.parent == ROOT and ROOT.resolve(strict=True) == ROOT
            and re.fullmatch(re.escape(prefix) + r"(?:-[a-z0-9-]+)?", path.name),
            "unexpected create-only evidence directory")
    return path

def validate_inputs(path, digest):
    """Read-only local validation. Never calls a producer main or any command."""
    require(re.fullmatch(r"[0-9a-f]{64}", digest) is not None, "exact input SHA256 required")
    F, H = load_fixed_helpers()
    raw = read_regular(path, digest)
    manifest, snapshot = F["stable_bytes"](path, len(raw), digest)
    require(manifest == raw, "input changed during independent stable read")
    value = strict_json(raw)
    require(isinstance(value, dict) and set(value) == {
        "schema", "publication_spec", "publication_receipt", "hosted_checks", "collector_disposition"},
        "final PR input field set differs")
    require(value["schema"] == "trnm-pr847-final-audit-inputs-v1", "unexpected final PR input schema")
    require(value["hosted_checks"] == {"state": "not_observed_for_final_candidate"},
            "this narrow adapter accepts no caller-supplied hosted result")
    snapshots = [snapshot]
    retained = [("final-inputs.json", str(path), raw)]

    def pinned(pin, name):
        data, record = F["pinned_bytes"](pin)
        snapshots.append(record)
        retained.append((name, pin["path"], data))
        return data

    spec_raw = pinned(value["publication_spec"], "publication-spec.json")
    spec = strict_json(spec_raw)
    pubdir = F["validate_spec"](spec)
    require(spec["publisher_sha256"] == FOLLOWUP_SHA, "unreviewed follow-up producer")
    head, tree = spec["candidate_head"], spec["candidate_tree"]
    pub_raw = pinned(value["publication_receipt"], "confirmed-publication.json")
    pub = strict_json(pub_raw)
    require(value["publication_receipt"]["path"] == str(pubdir / "summary.json"),
            "terminal publication receipt path differs from reviewed spec")
    require(pub["schema"] == "trnm-followup-candidate-execution-publication-receipt-v1"
            and pub["status"] == "confirmed" and pub["push_started"] is True
            and pub["source_after_valid"] is True and pub["exact_hook_verified"] is True
            and pub["head"] == head and pub["tree"] == tree
            and pub["expected_previous_head"] == F["BASE_HEAD"] and pub["errors"] == [],
            "complete confirmed follow-up publication required")
    require(pub["driver"] == {"path": str(FOLLOWUP), "bytes": FOLLOWUP_BYTES, "sha256": FOLLOWUP_SHA}
            and pub["spec"] == value["publication_spec"], "publication producer/spec binding differs")
    require(type(pub["push_exit"]) is int, "publication transport outcome missing")
    for field in ("started_at", "push_started_at", "finished_at"):
        require(type(pub[field]) is str and bool(pub[field]), "publication terminal time missing")
        datetime.datetime.fromisoformat(pub[field])
    for field in ("automatic_retry_authorized", "rollback_authorized", "main_merged",
                  "branches_deleted", "protection_changed", "pr_metadata_changed",
                  "auto_merge_enabled", "hosted_ci_qualification", "qualification_granted",
                  "untouched_refs_and_protection_atomically_locked"):
        require(pub[field] is False, "unexpected publication scope flag: " + field)
    require(pub["required_head_and_prospective_ci_must_still_pass"] is True
            and pub["archive_preserves_history_not_semantic_equivalence"] is True,
            "publication qualification/history boundary differs")
    expected, old_parents, frozen_raw, old_originals, old_snapshots = F["original_frozen_state"]()
    snapshots.extend(old_snapshots)
    payload = F["load_manifest"](spec["execution_manifest"])
    snapshots.extend(payload["snapshots"])
    gate, gate_raw, gate_source, gate_snapshots, gate_producer = F["validate_gate_payload"](
        H, spec["local_gate_receipt"], head, tree, payload)
    rog, rog_raw, rog_snapshots, rog_producer = F["validate_rog_payload"](
        H, spec["rog_lane_receipt"], spec["rog_invocation"], head, tree, gate_source, payload)
    snapshots.extend(gate_snapshots + rog_snapshots)
    require(pub["validated_inputs"] == {
        "gate_receipt": spec["local_gate_receipt"], "rog_receipt": spec["rog_lane_receipt"],
        "rog_invocation": spec["rog_invocation"], "execution_manifest": spec["execution_manifest"],
        "payload_files": payload["manifest"]["file_count"],
        "payload_bytes": payload["manifest"]["total_bytes"],
        "rog_producer_sha256": sha(rog_producer),
        "exact_gate_commands": len(gate["steps"]), "exact_rog_commands": len(rog["steps"])},
        "publication validated-input closure differs")
    retained.extend([
        ("execution-manifest.json", spec["execution_manifest"]["path"], payload["raw"]),
        ("seven-local-gates.json", spec["local_gate_receipt"]["path"], gate_raw),
        ("full-linux-lane.json", spec["rog_lane_receipt"]["path"], rog_raw),
    ])

    def local(name, maximum=F["MAX_META"]):
        data, record = F["stable_bytes"](pubdir / name, maximum=maximum)
        snapshots.append(record)
        return data

    require(local("spec.json") == spec_raw
            and local("validated-execution-manifest.json") == payload["raw"]
            and local("validated-local-gate-receipt.json") == gate_raw
            and local("validated-rog-lane-receipt.json") == rog_raw,
            "publisher retained inputs differ")
    steps = pub["steps"]
    require(isinstance(steps, list) and 0 < len(steps) <= F["MAX_FILES"] * 3,
            "publication step roster is missing or unbounded")
    by_label = {}
    for row in steps:
        label = row["label"]
        require(type(label) is str and re.fullmatch(r"[a-z0-9-]+", label)
                and label not in by_label, "duplicate/invalid publication step")
        by_label[label] = row

    def step(label, argv, timeout, expected_exit=0, maximum=F["MAX_META"]):
        row = by_label[label]
        require(row["argv"] == argv and row["cwd"] == str(SOURCE)
                and type(row["timeout_seconds"]) is int and row["timeout_seconds"] == timeout
                and type(row["exit"]) is int and row["exit"] == expected_exit,
                "publication command/cwd/budget/result differs: " + label)
        data = {}
        for channel in ("stdout", "stderr"):
            path = pubdir / (label + "." + channel)
            require(row[channel + "_path"] == str(path), "publication raw-output path differs")
            raw, record = F["stable_bytes"](path, row[channel + "_bytes"],
                                          row[channel + "_sha256"], maximum=maximum)
            snapshots.append(record)
            data[channel] = raw
        return data["stdout"]

    archive = pub["archive"]
    require(isinstance(archive, dict) and set(archive) == {
        "tag", "tag_oid", "commit", "tree", "direct_parents", "candidate_head",
        "payload_manifest_sha256", "archive_files", "archive_bytes", "file_index_sha256"},
        "archive field set differs")
    for field in ("tag_oid", "commit", "tree"):
        require(type(archive[field]) is str and re.fullmatch(r"[0-9a-f]{40}", archive[field]),
                "archive object identity invalid")
    require(archive["tag"] == spec["archive_tag"]
            and archive["direct_parents"] == [F["OLD_ARCHIVE_COMMIT"], head]
            and archive["candidate_head"] == head
            and archive["payload_manifest_sha256"] == sha(payload["raw"]),
            "archive source/ordered parents/payload differs")
    require(strict_json(local("archive-local.json")) == archive, "archive retained metadata differs")
    tagref = "refs/tags/" + archive["tag"]
    old_tags = {F["OLD_TAG_REF"]: F["OLD_TAG_OID"],
                F["OLD_TAG_REF"] + "^{}": F["OLD_ARCHIVE_COMMIT"]}
    expected_new = dict(expected)
    expected_new[HEAD_REF] = head
    wanted_tags = dict(old_tags)
    wanted_tags.update({tagref: archive["tag_oid"], tagref + "^{}": archive["commit"]})
    for phase, wanted_heads, tags in (("before", expected, old_tags), ("after", expected_new, wanted_tags)):
        observed = pub["remote_" + phase]
        require(isinstance(observed, dict) and set(observed) == {
            "observed_at", "heads", "tags", "errors", "both_old", "both_new"}
            and observed["heads"] == wanted_heads and observed["tags"] == tags
            and observed["errors"] == [] and observed["both_old"] is (phase == "before")
            and observed["both_new"] is (phase == "after"), "complete remote observation differs")
        datetime.datetime.fromisoformat(observed["observed_at"])
        heads_raw = step("remote-" + phase + "-heads", ["git", "ls-remote", "--heads", "origin"], 180)
        tags_raw = step("remote-" + phase + "-tags",
            ["git", "ls-remote", "origin", *sorted(old_tags), tagref, tagref + "^{}"], 180)
        require(F["parse_refs"](heads_raw, heads=True) == wanted_heads
                and F["parse_refs"](tags_raw, allowed=set(wanted_tags)) == tags,
                "original complete ref readbacks differ")
    expected_hook = {"origin": URL + ".git", "remote_heads": expected, "old_archive_tags": old_tags,
        "new_tag_ref": tagref, "updates": {
            "refs/heads/" + HEAD_REF: {"local_ref": head, "new": head, "old": F["BASE_HEAD"]},
            tagref: {"local_ref": tagref, "new": archive["tag_oid"], "old": F["ZERO"]}}}
    hook_expected_raw = local("hooks/expected.json")
    require(strict_json(hook_expected_raw) == expected_hook, "actual exact hook scope differs")
    hook_raw = F["HOOK_TEMPLATE"].replace("__EXPECTED_SHA__", sha(hook_expected_raw)).replace(
        "__EXPECTED_BYTES__", str(len(hook_expected_raw))).encode()
    require(local("hooks/pre-push") == hook_raw, "actual hook differs from reviewed producer")
    require(pub["hook_receipt"] == F["verify_hook_receipt"](
        pubdir / "hooks", hook_expected_raw, hook_raw, expected_hook), "actual hook receipt differs")
    step("atomic-publish", ["git", "-c", "core.hooksPath=" + str(pubdir / "hooks"),
        "push", "--verify", "--atomic", "--porcelain", "--verbose", "--progress", "origin",
        head + ":refs/heads/" + HEAD_REF, tagref + ":" + tagref], 1800, pub["push_exit"],
        maximum=F["MAX_FILE"])
    actor_raw = step("actor", ["gh", "api", "user", "--jq", "{login,id}"], 180)
    actor = strict_json(actor_raw)
    require(set(actor) == {"login", "id"} and actor["login"] == "ProfHepta"
            and type(actor["id"]) is int and actor["id"] > 0 and pub["actor"] == actor,
            "publication authenticated actor differs")
    require(strict_json(step("actor-prepush", ["gh", "api", "user", "--jq", "{login,id}"], 180)) == actor,
            "publication prepush actor differs")
    source_pair = {}
    for phase in ("before", "after"):
        sidecar = local("source-" + phase + ".json")
        stdout = step("verify-source-" + phase, [H["PYTHON"], "-B", "scripts/ci/verify_ci_source.py",
            "--kind", "head", "--expected-head", head,
            "--output", str(pubdir / ("source-" + phase + ".json"))], 180)
        require(stdout == sidecar and H["validate_source_identity"](sidecar, head, tree) == gate_source,
                "publication source/stdout/sidecar differs from exact passed gates")
        source_pair[phase] = sidecar
        require(pub["source_" + phase + "_identity"] == {"head": head, "tree": tree, "status": ""},
                "publication HEAD/tree/clean status differs")
    require(source_pair["before"] == source_pair["after"], "publication source pair differs")
    for label, kind, oid, maximum in (
        ("old-archive-commit-object", "commit", F["OLD_ARCHIVE_COMMIT"], 128 * 1024),
        ("old-archive-tag-object", "tag", F["OLD_TAG_OID"], 64 * 1024),
        ("new-archive-commit-object", "commit", archive["commit"], 128 * 1024),
        ("new-archive-tag-object", "tag", archive["tag_oid"], 64 * 1024),
    ):
        data = step(label, ["git", "--no-replace-objects", "cat-file", kind, oid], 60, maximum=maximum)
        if label == "old-archive-commit-object":
            F["check_commit_object"](data, oid, F["OLD_ARCHIVE_TREE"], old_parents)
        elif label == "old-archive-tag-object":
            F["check_tag_object"](data, oid, F["OLD_TAG"], F["OLD_ARCHIVE_COMMIT"])
        elif kind == "commit":
            F["check_commit_object"](data, oid, archive["tree"], [F["OLD_ARCHIVE_COMMIT"], head])
        else:
            F["check_tag_object"](data, oid, archive["tag"], archive["commit"])

    # Validate original exact ls-tree output and byte-indexed public destinations.
    # This is data validation, not a Git command, publication or extra archive.
    index_raw = local("archive-file-index.json")
    require(sha(index_raw) == archive["file_index_sha256"], "archive index SHA differs")
    index = strict_json(index_raw)
    require(isinstance(index, dict) and set(index) == {"schema", "self_excluded", "files"}
            and index["schema"] == "trnm-execution-archive-file-index-v1"
            and index["self_excluded"] == "metadata/archive-file-index.json"
            and isinstance(index["files"], list), "archive index schema differs")
    indexed = {}
    for row in index["files"]:
        require(isinstance(row, dict) and set(row) == {"path", "bytes", "sha256", "git_blob", "mode"}
                and row["mode"] == "100644" and type(row["bytes"]) is int and row["bytes"] >= 0
                and re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                and re.fullmatch(r"[0-9a-f]{40}", row["git_blob"]), "invalid archive index row")
        name = str(F["safe_relative"](row["path"]))
        require(name not in indexed and name != index["self_excluded"], "duplicate archive path")
        indexed[name] = row
    require(type(archive["archive_files"]) is int and archive["archive_files"] == len(indexed) + 1
            and type(archive["archive_bytes"]) is int
            and archive["archive_bytes"] == sum(row["bytes"] for row in indexed.values()) + len(index_raw),
            "archive exact count/bytes differs")
    listing = step("archive-exact-tree-list", ["git", "ls-tree", "-r", "-z", archive["tree"]], 60)
    actual = {}
    for record in listing.split(b"\0"):
        if not record:
            continue
        metadata, name_raw = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        name = name_raw.decode("utf-8")
        require(mode == "100644" and kind == "blob" and name not in actual,
                "unexpected actual archive mode/type/duplicate")
        actual[name] = oid
    wanted_files = {name: row["git_blob"] for name, row in indexed.items()}
    wanted_files[index["self_excluded"]] = F["git_object_oid"]("blob", index_raw)
    require(actual == wanted_files, "archive exact tree path/blob roster differs")

    def archive_bytes(name, data):
        row = indexed[name]
        require(row == {"path": name, "bytes": len(data), "sha256": sha(data),
                        "git_blob": F["git_object_oid"]("blob", data), "mode": "100644"},
                "public archive evidence bytes differ: " + name)

    for name, data in payload["payload"].items():
        archive_bytes("payload/" + name, data)
    for name, data in {
        "metadata/publication-spec.json": spec_raw,
        "metadata/execution-manifest.json": payload["raw"],
        "metadata/local-gates.json": gate_raw,
        "metadata/rog-full-lane.json": rog_raw,
        "metadata/frozen-0170-branches.json": frozen_raw,
        "metadata/live-source-before.json": source_pair["before"],
    }.items():
        archive_bytes(name, data)
    retained.append(("archive-file-index.json", str(pubdir / "archive-file-index.json"), index_raw))
    collector = value["collector_disposition"]
    require(isinstance(collector, dict), "explicit collector disposition required")
    if collector == {"state": "pending"}:
        collector_text = ("A separate reviewed disposition is still pending. No repair, current-source "
                          "qualification or replay of historical results is asserted by this preparation.")
    else:
        require(set(collector) == {"state", "payload_path", "exact_excerpt"}
                and collector["state"] == "reviewed", "unsupported collector disposition")
        name = str(F["safe_relative"](collector["payload_path"]))
        require(re.fullmatch(r"[A-Za-z0-9._/-]+", name), "collector public-link path is not URL-safe")
        excerpt = collector["exact_excerpt"]
        require(type(excerpt) is str and 0 < len(excerpt.encode()) <= 1600
                and "\n" not in excerpt and "\r" not in excerpt
                and not any(ord(c) < 32 for c in excerpt), "bounded single-paragraph collector excerpt required")
        collector_raw = payload["payload"][name]
        require(excerpt.encode("utf-8") in collector_raw,
                "collector wording must be an exact excerpt of the retained reviewed evidence")
        archive_bytes("payload/" + name, collector_raw)
        escaped = excerpt.replace("\\", "\\\\")
        for char in (chr(96), "*", "_", "[", "]", "<", ">"):
            escaped = escaped.replace(char, "\\" + char)
        collector_text = escaped + " ([separate reviewed disposition](" + URL + "/blob/" + archive["commit"] + "/payload/" + name + "))."
        retained.append(("collector-disposition-original", str(pathlib.Path(
            payload["manifest"]["payload_root"]) / name), collector_raw))
    template_raw = read_regular(TEMPLATE, TEMPLATE_SHA)
    _, template_snapshot = F["stable_bytes"](TEMPLATE, len(template_raw), TEMPLATE_SHA)
    snapshots.append(template_snapshot)
    retained.append(("body-template-v3.md", str(TEMPLATE), template_raw))
    fields = []
    for _, field, format_spec, conversion in string.Formatter().parse(template_raw.decode("utf-8")):
        if field is not None:
            require(not format_spec and conversion is None, "unexpected template formatting operation")
            fields.append(field)
    require(set(fields) == PLACEHOLDERS, "closed template placeholder roster differs")
    archive_url = URL + "/blob/" + archive["commit"] + "/"
    render = {
        "url": URL, "head": head, "tree": tree, "base": BASE,
        "execution_evidence_url": archive_url + "metadata/execution-manifest.json",
        "publication_manifest_url": archive_url + "metadata/archive-file-index.json",
        "seven_source_status": "Passed on this exact candidate (seven original commands)",
        "seven_source_receipt_url": archive_url + "metadata/local-gates.json",
        "full_linux_status": "Passed on this exact candidate (original complete fail-fast lane)",
        "full_linux_receipt_url": archive_url + "metadata/rog-full-lane.json",
        "hosted_head_status": "Not established by this preparation; required checks remain mandatory",
        "hosted_head_checks_url": URL + "/pull/847/checks",
        "hosted_merge_status": "Not established by this preparation; required checks remain mandatory",
        "hosted_merge_checks_url": URL + "/pull/847/checks",
        "hosted_observed_at": "Not supplied for this final candidate/base; no hosted pass asserted",
        "historical_collector_disposition": collector_text,
        "archive_tag": archive["tag"], "tag_oid": archive["tag_oid"],
        "archive_commit": archive["commit"], "archive_candidate_head": archive["candidate_head"],
    }
    body_raw = template_raw.decode("utf-8").format(**render).encode("utf-8")
    require(len(body_raw) <= 16000, "reviewable PR body exceeds finite size bound")
    for fixed_path, expected_sha in ((FOLLOWUP, FOLLOWUP_SHA), (PUBLISHER, PUBLISHER_SHA)):
        fixed_raw = read_regular(fixed_path, expected_sha)
        _, fixed_snapshot = F["stable_bytes"](fixed_path, len(fixed_raw), expected_sha)
        snapshots.append(fixed_snapshot)
        retained.append((fixed_path.name, str(fixed_path), fixed_raw))
    facts = {
        "head": head, "tree": tree, "base": BASE, "pr_number": 847, "head_ref": HEAD_REF,
        "publication_spec": value["publication_spec"], "publication_receipt": value["publication_receipt"],
        "publication_status": "confirmed", "publication_transport_exit": pub["push_exit"],
        "publication_observation_phase": "after", "archive": archive,
        "original_branch_names": 908, "original_distinct_tips": 892,
        "original_archive_direct_parents": 893,
        "execution_manifest": spec["execution_manifest"],
        "seven_gate_receipt": spec["local_gate_receipt"], "seven_gate_commands": 7,
        "full_linux_receipt": spec["rog_lane_receipt"], "original_linux_commands": 18,
        "hosted_checks": value["hosted_checks"], "collector_disposition": collector,
        "template": {"path": str(TEMPLATE), "bytes": len(template_raw), "sha256": TEMPLATE_SHA},
        "qualification_granted": False,
    }
    by_path = {}
    for item in snapshots:
        old = by_path.setdefault(item["path"], item)
        require(old == item, "a fixed dependency changed between reads")
    dependency_index = {"schema": "trnm-pr847-local-validated-dependencies-v1",
                        "files": [by_path[name] for name in sorted(by_path)]}
    F["check_versions"](snapshots)
    return {"F": F, "H": H, "head": head, "tree": tree, "gate_source": gate_source,
            "body_raw": body_raw, "facts": facts, "snapshots": snapshots,
            "dependency_index": dependency_index, "retained": retained,
            "input_pin": {"path": str(path), "bytes": len(raw), "sha256": digest},
            "publication_actor": actor}

def preparation_commands():
    return [("actor", ["gh", "api", "user", "--jq", "{login,id}"]),
            ("pr-before", ["gh", "api", "repos/" + REPO + "/pulls/847", "--jq", QUERY])]

def main():
    require(sys.flags.optimize == 0, "optimized interpreter is not allowed")
    require(pathlib.Path(__file__).resolve(strict=True) == SELF, "unexpected preparer location")
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--inputs-sha256", required=True)
    parser.add_argument("--evidence-dir", required=True)
    args = parser.parse_args()
    ev = evidence_directory(args.evidence_dir, "prepare-pr847-audit-update-v4")
    ctx = validate_inputs(args.inputs, args.inputs_sha256)
    H, F = ctx["H"], ctx["F"]
    env = safe_environment(H)
    os.umask(0o077)
    ev.mkdir(mode=0o700, exist_ok=False)
    inputs = ev / "inputs"
    inputs.mkdir(mode=0o700)
    retained, steps = [], []
    for name, original_path, data in ctx["retained"]:
        target = inputs / name
        with target.open("xb") as stream:
            stream.write(data)
        require(read_regular(target) == data, "retained fixed input differs")
        retained.append({"source_path": original_path, "retained_path": str(target),
                         "bytes": len(data), "sha256": sha(data)})
    dependency_raw = (json.dumps(ctx["dependency_index"], sort_keys=True, indent=2) + "\n").encode()
    with (ev / "dependencies.json").open("xb") as stream:
        stream.write(dependency_raw)
    result = {"schema": "prepared-pr847-audit-update-v4", "status": "HOLD", "remote_writes": False,
        "started_at": now(), "driver": {"path": str(SELF), "sha256": sha(read_regular(SELF))},
        "inputs": ctx["input_pin"], "validated_facts": ctx["facts"],
        "dependencies": {"path": str(ev / "dependencies.json"), "bytes": len(dependency_raw),
                         "sha256": sha(dependency_raw)}, "retained_inputs": retained,
        "steps": steps, "errors": []}
    def save():
        (ev / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
        (ev / "steps.json").write_text(json.dumps(steps, indent=2) + "\n")
    def run(label, argv):
        began = now()
        q = H["capture"](argv, env, timeout=180)
        row = {"label": label, "argv": argv, "cwd": str(SOURCE), "exit": q.returncode,
               "timeout_seconds": 180, "started_at": began, "finished_at": now()}
        for channel in ("stdout", "stderr"):
            data = getattr(q, channel)
            path = ev / (label + "." + channel)
            with path.open("xb") as stream:
                stream.write(data)
            row.update({channel + "_path": str(path), channel + "_bytes": len(data),
                        channel + "_sha256": sha(data)})
        steps.append(row)
        save()
        require(q.returncode == 0, "read failed: " + label)
        return q.stdout
    save()
    try:
        F["check_versions"](ctx["snapshots"])
        actor_raw = run(*preparation_commands()[0])
        actor = strict_json(actor_raw)
        require(actor == ctx["publication_actor"], "authenticated actor differs from confirmed publication")
        before_raw = run(*preparation_commands()[1])
        before = strict_json(before_raw)
        valid_pr_identity(before, before["node_id"], ctx["head"])
        F["check_versions"](ctx["snapshots"])
        body_raw = ctx["body_raw"]
        with (ev / "pr-body.md").open("xb") as stream:
            stream.write(body_raw)
        desired = {"title": TITLE, "body": body_raw.decode("utf-8"), "head": ctx["head"],
            "tree": ctx["tree"], "base": BASE, "base_ref": "main", "pr_number": 847,
            "pr_node_id": before["node_id"], "mark_ready_after_metadata_verified": True}
        desired_raw = (json.dumps(desired, indent=2) + "\n").encode()
        with (ev / "desired.json").open("xb") as stream:
            stream.write(desired_raw)
        result.update(status="prepared", before_raw_sha256=sha(before_raw),
            before_title=before["title"], before_draft=before["draft"],
            before_body_bytes=len((before["body"] or "").encode("utf-8")),
            desired_title=TITLE, desired_body_path=str(ev / "pr-body.md"),
            desired_body_bytes=len(body_raw), desired_body_sha256=sha(body_raw),
            desired_path=str(ev / "desired.json"), desired_sha256=sha(desired_raw))
    except Exception as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        result["finished_at"] = now()
        save()
    print(json.dumps({"status": result["status"], "summary": str(ev / "summary.json"),
                      "remote_writes": False}), flush=True)
    return 0 if result["status"] == "prepared" else 1

if __name__ == "__main__":
    sys.exit(main())
