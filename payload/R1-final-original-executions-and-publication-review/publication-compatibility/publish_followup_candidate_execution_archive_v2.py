"""Publish a reviewed follow-up candidate and a frozen execution archive once.

The caller supplies a separately reviewed pinned spec. This never merges main,
deletes branches, changes protection, enables auto-merge, retries a push, or
turns local receipts into hosted/protocol qualification. Preparation is static;
execute only after explicit operator review of this exact driver and spec.
"""
import argparse, datetime, hashlib, json, os, pathlib, re, signal, stat
import subprocess, sys, threading, time

ROOT = pathlib.Path("/private/tmp/chain-consolidation-20261114-root")
SOURCE = pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
SELF = ROOT / "publish_followup_candidate_execution_archive_v2.py"
PUBLISHER = ROOT / "publish_candidate_and_archive_v4.py"
PUBLISHER_SHA = "4105cd1db2e5219deda83a881872c51ac5cf671f5caa367bc2ea8ae4d4495038"
RESUME = ROOT / "resume_candidate_archive_publish_v2.py"
RESUME_SHA = "d89b6f7b651d0422cd17fbd97ff6782996c9e3cdab163306f729109146560853"
REPOSITORY = "TrillionniumFoundation/Trillionnium-Chain"
URL = "https://github.com/" + REPOSITORY + ".git"
CANDIDATE_REF = "refs/heads/fix/chain-hepta-closure-candidate-20261109-481716"
BASE_HEAD = "dc42ce4df5cff79cc61c5addbaf01074b56b06ca"
BASE_TREE = "9fda17fed2542b2baccaa34585bb00afd699e12b"
MAIN_HEAD = "dd6e1c3cbeacbdc532b0679297835b3a0aac78f0"
OLD_CANDIDATE = "e40d7071c4724e6600deef8a2820bf35c1982289"
OLD_TAG = "archive/branches-before-consolidation-20261114-dc42ce4df5cf-v2"
OLD_TAG_REF = "refs/tags/" + OLD_TAG
OLD_TAG_OID = "9dafd9192e4040fab530958ef71598aaec9265b9"
OLD_ARCHIVE_COMMIT = "5f57c4e1e2b7ae95a7b0651d7674979d3f44b90b"
OLD_ARCHIVE_TREE = "b91f68e70a05e5475b850159033baffb0824c6ba"
ZERO = "0" * 40
OLD_ORIGINAL = ROOT / "publish-candidate-and-archive-dc42ce-v2"
ORIGINAL_PINS = {
    "spec.json": (1008, "c63009a5e7d99af7e60f66cfd43fcf036a6cf4d5b002a98cd4500c3d76b07c2a"),
    "archive-local.json": (43199, "7a5ead74ce076c3e8fd56cac61c22a380b660b7da4875a9259018e37e4c21aa6"),
    "hooks/expected.json": (83072, "ee1e1fca066b62525016cd60803cadb3a2183cb8f9a5f367872341bd0ec2ca1a"),
}
FROZEN_SHA = "e52bb1c8c0963b2ddd303761ffe7ba949c080b3a0f72983f508978f8971e7734"
ROG_BASE = pathlib.PurePosixPath("/home/qian-qi/chain-final-consolidation-20261114-root")
ROG_SOURCE = ROG_BASE / "source"
ROG_CONFORMANCE = ROG_BASE / "final-python312-env/bin/python"
ROG_RUNTIME = ROG_BASE / "final-runtime-release-env/bin/python"
ROG_TOOLCHAIN = pathlib.PurePosixPath("/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin")
ROG_PRODUCER_BYTES = 15187
ROG_PRODUCER_SHA = "bbc62032fcb58443ee36cd59408c49d2d9694c5f709c48a30b6daf714a5ddd38"
MAX_META = 8 * 1024 * 1024
MAX_FILE = 256 * 1024 * 1024
MAX_PAYLOAD = 512 * 1024 * 1024
MAX_FILES = 10000

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def require(condition, message):
    if not condition:
        raise ValueError(message)

def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)

def fingerprint(info):
    return {"device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode,
            "links": info.st_nlink, "bytes": info.st_size,
            "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns}

def safe_relative(value):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= 4096,
            "invalid relative path length")
    path = pathlib.PurePosixPath(value)
    require(not path.is_absolute() and str(path) == value and len(path.parts) <= 32,
            "relative path is not normalized")
    require(all(part not in ("", ".", "..") and part.casefold() != ".git"
                for part in path.parts)
            and "\\" not in value and all(ord(c) >= 32 and ord(c) != 127 for c in value),
            "unsafe relative path")
    return path

def canonical_original_path(value):
    require(type(value) is str and "\\" not in value
            and all(ord(c) >= 32 and ord(c) != 127 for c in value),
            "invalid original path")
    path = pathlib.PurePosixPath(value)
    require(path.is_absolute() and str(path) == value
            and ".." not in path.parts and ".git" not in path.parts,
            "original path must be absolute and normalized")
    return path

def stable_bytes(path, expected_bytes=None, expected_sha=None, maximum=MAX_META):
    path = pathlib.Path(path)
    require(path.is_absolute() and path.is_relative_to(ROOT)
            and path.resolve(strict=True) == path,
            "canonical file below the authorized Mac root required")
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum,
            "bounded regular file required")
    if expected_bytes is not None:
        require(type(expected_bytes) is int and 0 <= expected_bytes <= maximum
                and before.st_size == expected_bytes, "pinned file size differs")
    if expected_sha is not None:
        require(type(expected_sha) is str
                and re.fullmatch(r"[0-9a-f]{64}", expected_sha), "invalid SHA256 pin")
    version = fingerprint(before)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        require(fingerprint(os.fstat(stream.fileno())) == version,
                "file changed before held-descriptor read")
        raw = stream.read(before.st_size + 1)
        require(fingerprint(os.fstat(stream.fileno())) == version,
                "file changed during held-descriptor read")
    require(fingerprint(path.lstat()) == version and len(raw) == before.st_size,
            "file path/version changed during read")
    digest = sha(raw)
    require(expected_sha is None or digest == expected_sha, "pinned SHA256 differs")
    return raw, {"path": str(path), "bytes": len(raw), "sha256": digest, "version": version}

def pinned_bytes(pin, maximum=MAX_META):
    require(isinstance(pin, dict) and set(pin) == {"path", "bytes", "sha256"},
            "pin must contain exactly path, bytes, sha256")
    return stable_bytes(pin["path"], pin["bytes"], pin["sha256"], maximum=maximum)

def check_versions(snapshots):
    for snapshot in snapshots:
        path = pathlib.Path(snapshot["path"])
        require(path.resolve(strict=True) == path
                and fingerprint(path.lstat()) == snapshot["version"],
                "frozen input filesystem version changed: " + str(path))

def load_manifest(pin):
    raw, own_snapshot = pinned_bytes(pin)
    manifest = strict_json(raw)
    require(isinstance(manifest, dict) and set(manifest) ==
            {"schema", "payload_root", "file_count", "total_bytes", "files"}
            and manifest["schema"] == "trnm-frozen-execution-payload-manifest-v1",
            "execution manifest schema/field set differs")
    root = pathlib.Path(manifest["payload_root"])
    require(root.parent == ROOT and re.fullmatch(r"execution-receipts-[A-Za-z0-9._-]+", root.name)
            and root.resolve(strict=True) == root and root.is_dir(),
            "frozen payload root must be a canonical dedicated direct child")
    entries = manifest["files"]
    require(type(manifest["file_count"]) is int and isinstance(entries, list)
            and len(entries) == manifest["file_count"] and 0 < len(entries) <= MAX_FILES,
            "manifest file count differs")
    require(type(manifest["total_bytes"]) is int
            and 0 <= manifest["total_bytes"] <= MAX_PAYLOAD, "manifest byte bound differs")
    payload, origins, snapshots, rows, total = {}, {}, [own_snapshot], [], 0
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {"path", "bytes", "sha256", "origin"},
                "manifest entry fields differ")
        relative = safe_relative(entry["path"])
        require(entry["path"] not in payload, "duplicate payload path")
        origin = entry["origin"]
        require(isinstance(origin, dict) and set(origin) == {"host", "path"}
                and origin["host"] in ("mac", "rog"), "invalid original source identity")
        canonical_original_path(origin["path"])
        data, snapshot = stable_bytes(root.joinpath(*relative.parts), entry["bytes"],
                                      entry["sha256"], maximum=MAX_FILE)
        total += len(data)
        require(total <= MAX_PAYLOAD, "total payload exceeds fixed bound")
        payload[entry["path"]] = data
        origins.setdefault((origin["host"], origin["path"]), []).append(entry)
        snapshots.append(snapshot)
        rows.append(entry)
    require(total == manifest["total_bytes"], "manifest total byte count differs")
    paths = set(payload)
    for name in paths:
        require(not any(str(parent) in paths for parent in pathlib.PurePosixPath(name).parents
                        if str(parent) != "."), "payload file/directory prefix collision")
    def original(host, path, expected_bytes=None, expected_sha=None, expected_raw=None):
        matches = origins.get((host, str(path)), [])
        require(matches, "required original artifact missing from frozen manifest: " + str(path))
        values = [payload[row["path"]] for row in matches]
        require(all(value == values[0] for value in values), "ambiguous original artifact copies")
        value = values[0]
        require(expected_bytes is None or len(value) == expected_bytes,
                "original artifact bytes differ")
        require(expected_sha is None or sha(value) == expected_sha,
                "original artifact SHA256 differs")
        require(expected_raw is None or value == expected_raw,
                "original artifact raw bytes differ")
        return value
    return {"raw": raw, "manifest": manifest, "payload": payload, "snapshots": snapshots,
            "original": original, "rows": rows}

def validate_spec(spec):
    fields = {"schema", "publisher_sha256", "candidate_head", "candidate_tree", "evidence_dir",
              "archive_tag", "local_gate_receipt", "rog_lane_receipt", "rog_invocation",
              "execution_manifest", "expected_remote_head"}
    require(isinstance(spec, dict) and set(spec) == fields
            and spec["schema"] == "trnm-followup-candidate-execution-publication-spec-v2",
            "follow-up spec schema/field set differs")
    for key in ("candidate_head", "candidate_tree", "expected_remote_head"):
        require(type(spec[key]) is str and re.fullmatch(r"[0-9a-f]{40}", spec[key]),
                "exact candidate or expected remote object required")
    require(spec["candidate_head"] != BASE_HEAD, "follow-up candidate must be new")
    require(spec["candidate_head"] != spec["expected_remote_head"],
            "candidate update must advance the exact reviewed remote head")
    require(type(spec["publisher_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", spec["publisher_sha256"]),
            "reviewed publisher SHA256 required")
    ev = pathlib.Path(spec["evidence_dir"])
    require(ev.parent == ROOT and re.fullmatch(r"publish-followup-candidate-execution-[a-z0-9-]+", ev.name),
            "dedicated create-only evidence directory required")
    require(spec["archive_tag"] ==
            "archive/execution-receipts-20261114-" + spec["candidate_head"][:12] + "-v1",
            "new execution archive tag must bind the new candidate")
    invocation = spec["rog_invocation"]
    require(isinstance(invocation, dict)
            and set(invocation) == {"original_receipt_path", "driver_path", "executable", "expected_start_head"},
            "explicit original ROG invocation identity required")
    require(type(invocation["expected_start_head"]) is str
            and re.fullmatch(r"[0-9a-f]{40}", invocation["expected_start_head"]),
            "explicit reviewed ROG start commit required")
    original_receipt = canonical_original_path(invocation["original_receipt_path"])
    require(original_receipt.name == "summary.json" and original_receipt.parent.parent == ROG_BASE
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", original_receipt.parent.name),
            "unexpected original ROG receipt directory")
    driver = canonical_original_path(invocation["driver_path"])
    require(driver.parent == ROG_BASE and driver.name == "run_final_rog_repository_truth_offline_v4.py",
            "unexpected original ROG producer path")
    canonical_original_path(invocation["executable"])
    return ev

def original_frozen_state():
    originals, snapshots = {}, []
    for name, (length, digest) in ORIGINAL_PINS.items():
        raw, snapshot = stable_bytes(OLD_ORIGINAL / name, length, digest)
        originals[name] = raw
        snapshots.append(snapshot)
    oldspec = strict_json(originals["spec.json"])
    require(oldspec["candidate_head"] == BASE_HEAD and oldspec["candidate_tree"] == BASE_TREE
            and oldspec["archive_tag"] == OLD_TAG
            and oldspec["frozen_remote_sha256"] == FROZEN_SHA, "original fixed publication differs")
    frozen_raw, snapshot = stable_bytes(oldspec["frozen_remote_manifest"], expected_sha=FROZEN_SHA)
    snapshots.append(snapshot)
    frozen = strict_json(frozen_raw)
    require(isinstance(frozen, list) and len(frozen) == 908, "original branch inventory count differs")
    old_heads = {}
    for row in frozen:
        require(type(row["name"]) is str and row["name"] not in old_heads
                and re.fullmatch(r"[0-9a-f]{40}", row["sha"]), "invalid/duplicate frozen branch")
        old_heads[row["name"]] = row["sha"]
    require(len(old_heads) == 908 and len(set(old_heads.values())) == 892
            and old_heads["main"] == MAIN_HEAD
            and old_heads[CANDIDATE_REF[11:]] == OLD_CANDIDATE, "original frozen map differs")
    old_hook = strict_json(originals["hooks/expected.json"])
    require(old_hook == {"remote_heads": old_heads, "origin": URL, "updates": {
        CANDIDATE_REF: {"new": BASE_HEAD, "old": OLD_CANDIDATE},
        OLD_TAG_REF: {"new": OLD_TAG_OID, "old": ZERO}}}, "original exact two-ref scope differs")
    parents = sorted(set(old_heads.values()) | {BASE_HEAD})
    old_archive = strict_json(originals["archive-local.json"])
    require(old_archive == {"tag": OLD_TAG, "tag_oid": OLD_TAG_OID,
        "commit": OLD_ARCHIVE_COMMIT, "tree": OLD_ARCHIVE_TREE,
        "direct_parents": parents, "candidate_head": BASE_HEAD}
        and len(parents) == 893, "original immutable archive metadata differs")
    expected = dict(old_heads)
    expected[CANDIDATE_REF[11:]] = BASE_HEAD
    require(len(expected) == 908 and len(set(expected.values())) == 892, "published baseline map differs")
    return expected, parents, frozen_raw, originals, snapshots

def bind_expected_remote_heads(published_heads, expected_remote_head):
    """Bind only the candidate ref to the separately reviewed remote identity."""
    require(type(expected_remote_head) is str
            and re.fullmatch(r"[0-9a-f]{40}", expected_remote_head),
            "exact reviewed remote head required")
    require(isinstance(published_heads, dict) and len(published_heads) == 908
            and len(set(published_heads.values())) == 892
            and published_heads["main"] == MAIN_HEAD
            and published_heads[CANDIDATE_REF[11:]] == BASE_HEAD,
            "original published C0 map differs")
    expected = dict(published_heads)
    expected[CANDIDATE_REF[11:]] = expected_remote_head
    require(len(expected) == 908 and len(set(expected.values())) == 892,
            "reviewed remote map count differs")
    return expected

def validate_gate_payload(H, pin, head, tree, manifest):
    raw, snapshot = pinned_bytes(pin)
    gate, helper_raw, source = H["validate_gate_receipt"](pin["path"], pin["sha256"], head, tree)
    require(raw == helper_raw, "gate changed between pinned and complete validation")
    original = manifest["original"]
    original("mac", pin["path"], len(raw), sha(raw), raw)
    for step in gate["steps"]:
        for channel in ("stdout", "stderr"):
            original("mac", step[channel + "_path"], step[channel + "_bytes"],
                     step[channel + "_sha256"])
    for phase in ("before", "after"):
        entry = gate["source_observations"][phase]
        original("mac", entry["path"], entry["bytes"], entry["sha256"])
    producer = gate["producer"]
    producer_raw, producer_snapshot = stable_bytes(producer["path"], expected_sha=producer["sha256"])
    original("mac", producer["path"], len(producer_raw), producer["sha256"], producer_raw)
    return gate, raw, source, [snapshot, producer_snapshot], producer_raw

def rog_commands(head, start, bundle, evidence):
    def git(*args):
        return ["git", "--no-replace-objects", *args]
    program_rows = []
    for label, python, wanted in (
        ("conformance", ROG_CONFORMANCE, {"numpy": "1.26.4", "cryptography": "50.0.2"}),
        ("runtime", ROG_RUNTIME, {"packaging": "26.3"}),
    ):
        program = ("import importlib.metadata as m,json,sys; expected=" + repr(wanted)
                   + "; actual={k:m.version(k) for k in expected}; "
                   + "assert actual==expected and sys.version_info[:2]==(3,12); "
                   + "print(json.dumps({'actual':actual,'python':sys.version,'executable':sys.executable}))")
        program_rows.append((label + "-environment", [str(python), "-B", "-c", program], 300))
    source = lambda phase: [str(ROG_CONFORMANCE), "-B", "scripts/ci/verify_ci_source.py",
        "--kind", "head", "--expected-head", head, "--output", str(evidence / ("source-" + phase + ".json"))]
    return [
        ("initial-head", git("rev-parse", "HEAD"), 300),
        ("initial-status", git("status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"), 300),
        ("pre-update-preflight", ["bash", "scripts/project-preflight.sh", "--audit"], 300),
        ("local-bundle-verify", git("bundle", "verify", bundle), 300),
        ("local-bundle-list-heads", git("bundle", "list-heads", bundle), 300),
        ("fetch-exact-local-bundle", git("fetch", "--no-tags", "--no-recurse-submodules",
             "--no-write-fetch-head", "--no-auto-maintenance", bundle, "HEAD"), 300),
        ("fetched-commit", git("rev-parse", head + "^{commit}"), 300),
        ("fetched-tree", git("rev-parse", head + "^{tree}"), 300),
        ("fast-forward-ancestry", git("merge-base", "--is-ancestor", start, head), 300),
        ("fast-forward", git("merge", "--ff-only", "--no-edit", head), 300),
        ("preflight-audit", ["bash", "scripts/project-preflight.sh", "--audit"], 300),
        ("rust-version", [str(ROG_TOOLCHAIN / "rustc"), "--version"], 300),
        ("cargo-version", [str(ROG_TOOLCHAIN / "cargo"), "--version"], 300),
        *program_rows,
        ("verify-source-before", source("before"), 300),
        ("repository-truth", ["bash", "scripts/ci/ci_job.sh", "repository-truth"], 2700),
        ("verify-source-after", source("after"), 300),
    ]

def validate_rog_payload(H, pin, inv_pin, head, tree, gate_source, manifest):
    raw, snapshot = pinned_bytes(pin)
    receipt = strict_json(raw)
    start = inv_pin["expected_start_head"]
    require(receipt["schema"] == "trnm-final-linux-repository-truth-offline-source-v4"
            and receipt["head"] == head and receipt["tree"] == tree
            and receipt["expected_start_head"] == start
            and receipt["source"] == str(ROG_SOURCE)
            and receipt["status"] == "passed" and receipt["errors"] == []
            and type(receipt["lane_exit"]) is int and receipt["lane_exit"] == 0
            and receipt["source_before_after_verified"] is True,
            "completed exact ROG lane required")
    for key, expected in (("hosted_ci_qualification", False), ("host_provisioning_performed", False),
                          ("remote_mutations_performed", False), ("local_bundle_source", True),
                          ("remote_publication_verified", False)):
        require(type(receipt[key]) is bool and receipt[key] is expected,
                "ROG scope flag differs: " + key)
    require(receipt["source_acquisition"] == "fixed-local-bundle"
            and "local_unpublished_source" not in receipt, "ROG source namespace differs")
    for key in ("started_at", "finished_at"):
        require(type(receipt[key]) is str and receipt[key], "ROG terminal time missing")
        datetime.datetime.fromisoformat(receipt[key])
    require(receipt["driver"] == {"path": inv_pin["driver_path"], "sha256": ROG_PRODUCER_SHA},
            "ROG actual producer identity differs")
    invocation = receipt["invocation"]
    require(isinstance(invocation, dict) and set(invocation) == {"argv", "executable", "optimize"}
            and invocation["executable"] == inv_pin["executable"]
            and type(invocation["optimize"]) is int and invocation["optimize"] == 0,
            "ROG actual interpreter identity differs")
    evidence = pathlib.PurePosixPath(inv_pin["original_receipt_path"]).parent
    bundle = receipt["bundle_input"]
    require(isinstance(bundle, dict) and set(bundle) == {"path", "bytes", "sha256"},
            "ROG bundle input differs")
    bundle_path = canonical_original_path(bundle["path"])
    require(bundle_path.parent == ROG_BASE / "offline-source-bundles-v3"
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.bundle", bundle_path.name)
            and type(bundle["bytes"]) is int and bundle["bytes"] > 0
            and re.fullmatch(r"[0-9a-f]{64}", bundle["sha256"]), "ROG bundle pins invalid")
    wanted_args = {"--head": head, "--tree": tree, "--expected-start-head": start,
                   "--evidence-dir": str(evidence), "--bundle-path": bundle["path"],
                   "--bundle-bytes": str(bundle["bytes"]), "--bundle-sha256": bundle["sha256"]}
    argv = invocation["argv"]
    require(isinstance(argv, list) and len(argv) == 15
            and all(type(value) is str for value in argv)
            and argv[0] == inv_pin["driver_path"], "ROG actual argv shape differs")
    supplied = {}
    for flag, value in zip(argv[1::2], argv[2::2]):
        require(flag in wanted_args and flag not in supplied, "ROG argv unknown/duplicate option")
        supplied[flag] = value
    require(supplied == wanted_args, "ROG actual argv differs from reviewed source pins")
    before = receipt["bundle_before"]
    require(before == receipt["bundle_after_fetch"]
            and set(before) == {"path", "bytes", "sha256", "version"}
            and {k: before[k] for k in ("path", "bytes", "sha256")} == bundle,
            "ROG stable bundle observations differ")
    version = before["version"]
    require(isinstance(version, dict) and set(version) ==
            {"device", "inode", "mode", "links", "bytes", "mtime_ns", "ctime_ns"}
            and all(type(v) is int and v >= 0 for v in version.values())
            and stat.S_ISREG(version["mode"]) and version["links"] == 1
            and version["bytes"] == bundle["bytes"], "ROG bundle version fields invalid")
    expected_env = {
        "PATH": str(ROG_CONFORMANCE.parent) + ":" + str(ROG_TOOLCHAIN)
             + ":/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        "TRNM_RUNTIME_RELEASE_PYTHON": str(ROG_RUNTIME),
        "TRNM_CI_RECEIPT_DIR": str(evidence / "ci-observations"),
        "TMPDIR": str(evidence / "tmp"), "CARGO_TARGET_DIR": str(ROG_BASE / "target"),
        "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0", "RUST_TEST_THREADS": "1",
        "CARGO_TERM_COLOR": "never", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONOPTIMIZE": "0",
        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0",
    }
    require(receipt["environment"] == expected_env, "ROG original lane environment differs")
    original = manifest["original"]
    original("rog", inv_pin["original_receipt_path"], len(raw), sha(raw), raw)
    producer_raw = original("rog", inv_pin["driver_path"], ROG_PRODUCER_BYTES, ROG_PRODUCER_SHA)
    commands = rog_commands(head, start, bundle["path"], evidence)
    steps = receipt["steps"]
    require(isinstance(steps, list) and len(steps) == len(commands) == 18
            and [x["label"] for x in steps] == [x[0] for x in commands],
            "ROG complete ordered original 18-step roster differs")
    outputs = {}
    for step, (label, command, timeout) in zip(steps, commands):
        require(step["cwd"] == str(ROG_SOURCE) and step["argv"] == command
                and type(step["exit"]) is int and step["exit"] == 0
                and type(step["timeout_seconds"]) is int and step["timeout_seconds"] == timeout,
                "ROG command/cwd/terminal/budget differs: " + label)
        for channel in ("stdout", "stderr"):
            path = str(evidence / (label + "." + channel))
            require(step[channel + "_path"] == path
                    and type(step[channel + "_bytes"]) is int
                    and step[channel + "_bytes"] >= 0
                    and re.fullmatch(r"[0-9a-f]{64}", step[channel + "_sha256"]),
                    "ROG raw output binding differs: " + label)
            outputs[(label, channel)] = original("rog", path, step[channel + "_bytes"],
                                                step[channel + "_sha256"])
    require(outputs[("initial-head", "stdout")].decode().strip() == start
            and not outputs[("initial-status", "stdout")].strip(), "ROG initial source differs")
    require(outputs[("fetched-commit", "stdout")].decode().strip() == head
            and outputs[("fetched-tree", "stdout")].decode().strip() == tree,
            "ROG fetched identity differs")
    require([line.split() for line in outputs[("local-bundle-list-heads", "stdout")].decode("ascii").splitlines()]
            == [[head, "HEAD"]], "ROG bundle advertised extra/different refs")
    sources = {}
    for phase in ("before", "after"):
        data = original("rog", str(evidence / ("source-" + phase + ".json")),
                        expected_raw=outputs[("verify-source-" + phase, "stdout")])
        sources[phase] = H["validate_source_identity"](data, head, tree)
        require(sources[phase] == gate_source, "ROG/Mac exact source identities differ")
    require(sources["before"] == sources["after"], "ROG source pair differs")
    return receipt, raw, [snapshot], producer_raw


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
            stdout, stderr = process.communicate(timeout=1800)
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



HOOK_TEMPLATE = r'''#!/opt/homebrew/bin/python3
"""Exact two-ref guard; an omitted, duplicate, no-op, or stale update fails."""
import datetime, hashlib, json, os, pathlib, re, stat, subprocess, sys
EXPECTED_SHA = "__EXPECTED_SHA__"
EXPECTED_BYTES = __EXPECTED_BYTES__
HERE = pathlib.Path(__file__).parent
SOURCE = pathlib.Path("/private/tmp/chain-consolidation-20261114-mainline")
def need(ok, message):
    if not ok:
        raise ValueError(message)
def sha(raw):
    return hashlib.sha256(raw).hexdigest()
def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()
def read_fixed(path, maximum):
    need(path.resolve(strict=True) == path, "noncanonical hook input")
    old = path.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink,
                          s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(stat.S_ISREG(old.st_mode) and old.st_size <= maximum, "invalid hook input")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        need(identity(os.fstat(stream.fileno())) == identity(old), "hook input replaced")
        raw = stream.read(old.st_size + 1)
        need(identity(os.fstat(stream.fileno())) == identity(old), "hook input changed")
    need(identity(path.lstat()) == identity(old) and len(raw) == old.st_size,
         "hook input path changed")
    return raw
def pairs(items):
    value = {}
    for key, item in items:
        need(key not in value, "duplicate JSON field")
        value[key] = item
    return value
receipt_path = HERE / "receipt.json"
receipt = {"schema": "trnm-followup-publication-exact-prepush-v1",
           "status": "HOLD", "started_at": now(), "argv": list(sys.argv),
           "commands": [], "errors": [], "updates": None}
with receipt_path.open("xb") as stream:
    stream.write((json.dumps(receipt, sort_keys=True) + "\n").encode())
def save():
    temporary = HERE / "receipt.next"
    with temporary.open("xb") as stream:
        stream.write((json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode())
    os.replace(temporary, receipt_path)
def command(label, argv):
    try:
        q = subprocess.run(argv, cwd=SOURCE, stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=90, check=False)
    except subprocess.TimeoutExpired as error:
        q = subprocess.CompletedProcess(argv, 124, error.stdout or b"", error.stderr or b"")
    except OSError as error:
        q = subprocess.CompletedProcess(argv, 127, b"", str(error).encode())
    row = {"label": label, "argv": argv, "exit": q.returncode, "timeout_seconds": 90}
    for channel in ("stdout", "stderr"):
        raw = getattr(q, channel)
        path = HERE / (label + "." + channel)
        with path.open("xb") as stream:
            stream.write(raw)
        row[channel + "_path"] = str(path)
        row[channel + "_bytes"] = len(raw)
        row[channel + "_sha256"] = sha(raw)
    receipt["commands"].append(row)
    save()
    return q
def advertised(raw, prefix=None, allowed=None):
    result = {}
    for line in raw.decode("ascii").splitlines():
        values = line.split()
        need(len(values) == 2, "malformed advertised ref")
        oid, ref = values
        need(re.fullmatch(r"[0-9a-f]{40}", oid) and ref not in result,
             "invalid or duplicate advertised ref")
        if prefix is not None:
            need(ref.startswith(prefix), "unexpected ref namespace")
        if allowed is not None:
            need(ref in allowed, "unexpected tag advertisement")
        result[ref] = oid
    return result
try:
    need(sys.flags.optimize == 0, "optimized Python is forbidden")
    need(pathlib.Path.cwd().resolve(strict=True) == SOURCE, "unexpected hook cwd")
    raw = read_fixed(HERE / "expected.json", 256 * 1024)
    need(len(raw) == EXPECTED_BYTES and sha(raw) == EXPECTED_SHA, "hook expectation differs")
    spec = json.loads(raw, object_pairs_hook=pairs)
    need(set(spec) == {"origin", "remote_heads", "old_archive_tags", "new_tag_ref", "updates"},
         "hook expectation field set differs")
    self_raw = read_fixed(pathlib.Path(__file__), 64 * 1024)
    receipt["hook_sha256"] = sha(self_raw)
    receipt["expected_sha256"] = EXPECTED_SHA
    need(len(sys.argv) == 3 and sys.argv[1:] == ["origin", spec["origin"]],
         "unexpected actual remote name or URL")
    incoming = sys.stdin.buffer.read(65537)
    need(len(incoming) <= 65536, "too much pre-push input")
    rows = incoming.decode("ascii").splitlines()
    need(len(rows) == 2, "hook requires exactly two actual wire updates")
    seen = {}
    for line in rows:
        values = line.split()
        need(len(values) == 4, "malformed pre-push tuple")
        local_ref, new, remote_ref, old = values
        need(remote_ref not in seen
             and re.fullmatch(r"[0-9a-f]{40}", new)
             and re.fullmatch(r"[0-9a-f]{40}", old), "duplicate or malformed update")
        seen[remote_ref] = {"local_ref": local_ref, "new": new, "old": old}
    receipt["updates"] = seen
    need(seen == spec["updates"], "actual advertised old/new/local ref set differs")
    push_url = command("push-url", ["git", "remote", "get-url", "--push", "--all", "origin"])
    fetch_url = command("fetch-url", ["git", "remote", "get-url", "--all", "origin"])
    # Both ref observations execute independently. They are observations, not
    # locks on main/old archive/other refs that this transaction does not update.
    heads = command("heads", ["git", "ls-remote", "--heads", "origin"])
    refs = sorted(spec["old_archive_tags"]) + [spec["new_tag_ref"], spec["new_tag_ref"] + "^{}"]
    tags = command("tags", ["git", "ls-remote", "origin", *refs])
    need(push_url.returncode == fetch_url.returncode == heads.returncode == tags.returncode == 0,
         "fresh hook remote observation failed")
    need(push_url.stdout.decode().splitlines() == [spec["origin"]]
         and fetch_url.stdout.decode().splitlines() == [spec["origin"]],
         "origin must resolve to exactly one fixed fetch and push URL")
    wanted_heads = {"refs/heads/" + name: oid for name, oid in spec["remote_heads"].items()}
    need(advertised(heads.stdout, prefix="refs/heads/") == wanted_heads,
         "complete remote heads changed")
    need(advertised(tags.stdout, allowed=set(refs)) == spec["old_archive_tags"],
         "old archive changed or new tag appeared")
    receipt["status"] = "passed"
except Exception as error:
    receipt["errors"].append({"type": type(error).__name__, "message": str(error)})
finally:
    receipt["finished_at"] = now()
    save()
sys.stderr.write("followup-prepush-" + receipt["status"] + "\n")
sys.stderr.flush()
sys.exit(0 if receipt["status"] == "passed" else 1)
'''

def parse_refs(raw, *, heads=False, allowed=None):
    result = {}
    for line in raw.decode("ascii").splitlines():
        parts = line.split()
        require(len(parts) == 2, "malformed advertised ref")
        oid, ref = parts
        require(re.fullmatch(r"[0-9a-f]{40}", oid), "invalid advertised OID")
        if heads:
            require(ref.startswith("refs/heads/"), "unexpected head namespace")
            ref = ref[11:]
        if allowed is not None:
            require(ref in allowed, "unexpected tag advertisement")
        require(ref not in result, "duplicate advertised ref")
        result[ref] = oid
    return dict(sorted(result.items()))

def git_object_oid(kind, raw):
    return hashlib.sha1(kind.encode("ascii") + b" " + str(len(raw)).encode("ascii")
                        + b"\0" + raw).hexdigest()

def check_commit_object(raw, oid, tree, parents):
    require(git_object_oid("commit", raw) == oid, "raw commit Git object identity differs")
    header, separator, _ = raw.partition(b"\n\n")
    require(separator == b"\n\n", "commit header terminator missing")
    lines = header.split(b"\n")
    require(lines[0] == b"tree " + tree.encode("ascii"), "commit tree header differs")
    actual = [line for line in lines if line.startswith(b"parent ")]
    wanted = [b"parent " + parent.encode("ascii") for parent in parents]
    require(actual == wanted and lines[1:1 + len(wanted)] == wanted,
            "commit exact ordered parent list differs")

def check_tag_object(raw, oid, tag, commit):
    require(git_object_oid("tag", raw) == oid, "raw annotated tag Git object identity differs")
    header, separator, _ = raw.partition(b"\n\n")
    require(separator == b"\n\n", "annotated tag header terminator missing")
    lines = header.split(b"\n")
    require(lines[:3] == [b"object " + commit.encode("ascii"), b"type commit",
                           b"tag " + tag.encode("utf-8")],
            "annotated tag target/type/name differs")
    require(sum(line.startswith(b"object ") for line in lines) == 1
            and sum(line.startswith(b"type ") for line in lines) == 1
            and sum(line.startswith(b"tag ") for line in lines) == 1,
            "duplicate annotated tag identity fields")

def verify_hook_receipt(hook_dir, expected_raw, hook_raw, expected):
    raw, _ = stable_bytes(hook_dir / "receipt.json", maximum=MAX_META)
    receipt = strict_json(raw)
    require(receipt["schema"] == "trnm-followup-publication-exact-prepush-v1"
            and receipt["status"] == "passed" and receipt["errors"] == []
            and receipt["argv"] == [str(hook_dir / "pre-push"), "origin", URL]
            and receipt["hook_sha256"] == sha(hook_raw)
            and receipt["expected_sha256"] == sha(expected_raw)
            and receipt["updates"] == expected["updates"],
            "actual exact hook invocation did not pass")
    wanted = [
        ("push-url", ["git", "remote", "get-url", "--push", "--all", "origin"]),
        ("fetch-url", ["git", "remote", "get-url", "--all", "origin"]),
        ("heads", ["git", "ls-remote", "--heads", "origin"]),
        ("tags", ["git", "ls-remote", "origin", *sorted(expected["old_archive_tags"]),
                  expected["new_tag_ref"], expected["new_tag_ref"] + "^{}"]),
    ]
    require(len(receipt["commands"]) == len(wanted), "hook complete observation roster differs")
    outputs = {}
    for row, (label, argv) in zip(receipt["commands"], wanted):
        require(row["label"] == label and row["argv"] == argv
                and type(row["exit"]) is int and row["exit"] == 0
                and row["timeout_seconds"] == 90, "hook command result differs")
        for channel in ("stdout", "stderr"):
            path = hook_dir / (label + "." + channel)
            require(row[channel + "_path"] == str(path), "hook raw output path differs")
            value, _ = stable_bytes(path, row[channel + "_bytes"],
                                    row[channel + "_sha256"], maximum=MAX_META)
            outputs[(label, channel)] = value
    require(outputs[("push-url", "stdout")].decode().splitlines() == [URL]
            and outputs[("fetch-url", "stdout")].decode().splitlines() == [URL],
            "actual hook origin observations differ")
    require(parse_refs(outputs[("heads", "stdout")], heads=True) == expected["remote_heads"],
            "actual hook full heads observation differs")
    allowed = set(expected["old_archive_tags"]) | {expected["new_tag_ref"], expected["new_tag_ref"] + "^{}"}
    require(parse_refs(outputs[("tags", "stdout")], allowed=allowed) == expected["old_archive_tags"],
            "actual hook old/new tag observation differs")
    require(stable_bytes(hook_dir / "expected.json")[0] == expected_raw
            and stable_bytes(hook_dir / "pre-push")[0] == hook_raw,
            "hook/expectation changed during push")
    return {"path": str(hook_dir / "receipt.json"), "bytes": len(raw), "sha256": sha(raw),
            "status": receipt["status"]}



def main():
    require(sys.flags.optimize == 0, "optimized Python disables required guards")
    require(pathlib.Path(__file__).resolve(strict=True) == SELF, "unexpected publisher location")
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True)
    parser.add_argument("--spec-sha256", required=True)
    args = parser.parse_args()
    spec_raw, spec_snapshot = stable_bytes(args.spec, expected_sha=args.spec_sha256)
    spec = strict_json(spec_raw)
    ev = validate_spec(spec)
    self_raw, self_snapshot = stable_bytes(SELF, expected_sha=spec["publisher_sha256"])
    publisher_raw, publisher_snapshot = stable_bytes(PUBLISHER, expected_sha=PUBLISHER_SHA)
    resume_raw, resume_snapshot = stable_bytes(RESUME, expected_sha=RESUME_SHA)
    H = bootstrap_helpers()
    require(H["ROOT"] == ROOT and H["SOURCE"] == SOURCE and H["URL"] == URL,
            "reviewed helper fixed scope differs")
    ev.mkdir(mode=0o700, exist_ok=False)
    require(ev.resolve(strict=True) == ev, "noncanonical evidence directory")
    head, tree = spec["candidate_head"], spec["candidate_tree"]
    expected_remote_head = spec["expected_remote_head"]
    tag, tagref = spec["archive_tag"], "refs/tags/" + spec["archive_tag"]
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
               GIT_TRACE2_PERF="0")
    steps = []
    state = {
        "schema": "trnm-followup-candidate-execution-publication-receipt-v2",
        "status": "HOLD", "started_at": now(),
        "driver": {"path": str(SELF), "bytes": len(self_raw), "sha256": sha(self_raw)},
        "invocation": {"argv": list(sys.argv), "executable": sys.executable,
                       "optimize": sys.flags.optimize},
        "spec": {"path": str(args.spec), "bytes": len(spec_raw), "sha256": sha(spec_raw)},
        "head": head, "tree": tree, "previous_own_published_head": BASE_HEAD,
        "expected_remote_head": expected_remote_head,
        "archive": None, "push_started": False, "push_exit": None,
        "remote_before": None, "remote_after": None, "source_after_valid": False,
        "exact_hook_verified": False, "steps": steps, "errors": [],
        "automatic_retry_authorized": False, "rollback_authorized": False,
        "main_merged": False, "branches_deleted": False, "protection_changed": False,
        "pr_metadata_changed": False, "auto_merge_enabled": False,
        "hosted_ci_qualification": False, "qualification_granted": False,
        "required_head_and_prospective_ci_must_still_pass": True,
        "archive_preserves_history_not_semantic_equivalence": True,
        "untouched_refs_and_protection_atomically_locked": False,
    }
    def save():
        temporary = ev / "summary.next"
        with temporary.open("xb") as stream:
            stream.write((json.dumps(state, indent=2, sort_keys=True) + "\n").encode())
        os.replace(temporary, ev / "summary.json")
    def emit(name, raw):
        path = ev / name
        with path.open("xb") as stream:
            stream.write(raw)
        return {"path": str(path), "bytes": len(raw), "sha256": sha(raw)}
    def encode(value):
        return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    emit("spec.json", spec_raw)
    save()
    def run(label, argv, data=None, timeout=180, require_zero=True, sampled=False):
        require(re.fullmatch(r"[a-z0-9-]+", label) and not any(row["label"] == label for row in steps),
                "duplicate/invalid command label")
        began = time.monotonic()
        if sampled:
            require(timeout == 1800 and data is None, "sampled push budget/input differs")
            q, sampling_errors = capture_sampled(argv, env, ev / (label + "-process-samples.jsonl"))
            state["transport_sampling_errors"] = sampling_errors
        else:
            q = H["capture"](argv, env, data=data, timeout=timeout)
        row = {"label": label, "argv": argv, "cwd": str(SOURCE),
               "exit": q.returncode, "timeout_seconds": timeout,
               "elapsed_seconds": time.monotonic() - began, "finished_at": now()}
        if data is not None:
            row["stdin_bytes"], row["stdin_sha256"] = len(data), sha(data)
        for channel in ("stdout", "stderr"):
            identity = emit(label + "." + channel, getattr(q, channel))
            for key, value in identity.items():
                row[channel + "_" + key] = value
        steps.append(row)
        save()
        print(json.dumps({"label": label, "exit": q.returncode}), flush=True)
        if require_zero:
            require(q.returncode == 0, label + " failed; original stdout/stderr retained")
        return q
    def git_value(label, *argv):
        q = run(label, ["git", "--no-replace-objects", *argv], timeout=60)
        return q.stdout.decode("utf-8").strip()
    def object_bytes(label, kind, oid, maximum):
        size = git_value(label + "-size", "cat-file", "-s", oid)
        require(re.fullmatch(r"[1-9][0-9]*", size) and int(size) <= maximum,
                label + " object exceeds bound")
        raw = run(label, ["git", "--no-replace-objects", "cat-file", kind, oid], timeout=60).stdout
        require(len(raw) == int(size) and git_object_oid(kind, raw) == oid,
                label + " raw size/object identity differs")
        return raw
    old_tags = {OLD_TAG_REF: OLD_TAG_OID, OLD_TAG_REF + "^{}": OLD_ARCHIVE_COMMIT}
    allowed_tags = set(old_tags) | {tagref, tagref + "^{}"}
    def observe_remote(phase, expected, archive=None):
        # Execute both independently even when the first read fails.
        heads_run = run("remote-" + phase + "-heads", ["git", "ls-remote", "--heads", "origin"],
                        timeout=180, require_zero=False)
        tags_run = run("remote-" + phase + "-tags", ["git", "ls-remote", "origin",
                       *sorted(old_tags), tagref, tagref + "^{}"], timeout=180, require_zero=False)
        observation = {"observed_at": now(), "heads": None, "tags": None, "errors": [],
                       "both_old": False, "both_new": False}
        for name, q in (("heads", heads_run), ("tags", tags_run)):
            if q.returncode != 0:
                observation["errors"].append(name + " read exit " + str(q.returncode))
                continue
            try:
                observation[name] = parse_refs(q.stdout, heads=name == "heads",
                                               allowed=allowed_tags if name == "tags" else None)
            except Exception as error:
                observation["errors"].append(name + " parse " + type(error).__name__ + ": " + str(error))
        observation["both_old"] = observation["heads"] == expected and observation["tags"] == old_tags
        if archive is not None:
            wanted_heads = dict(expected)
            wanted_heads[CANDIDATE_REF[11:]] = head
            wanted_tags = dict(old_tags)
            wanted_tags.update({tagref: archive["tag_oid"], tagref + "^{}": archive["commit"]})
            observation["both_new"] = (observation["heads"] == wanted_heads
                                       and observation["tags"] == wanted_tags)
        return observation

    snapshots = [spec_snapshot, self_snapshot, publisher_snapshot, resume_snapshot]
    expected = None
    gate_source = None
    fresh_source_raw = None
    hook_dir = None
    hook_raw = expected_hook_raw = expected_hook = None
    try:
        published_heads, old_parents, frozen_raw, old_originals, original_snapshots = original_frozen_state()
        expected = bind_expected_remote_heads(published_heads, expected_remote_head)
        snapshots.extend(original_snapshots)
        manifest = load_manifest(spec["execution_manifest"])
        snapshots.extend(manifest["snapshots"])
        gate, gate_raw, gate_source, gate_snapshots, gate_producer = validate_gate_payload(
            H, spec["local_gate_receipt"], head, tree, manifest)
        snapshots.extend(gate_snapshots)
        rog, rog_raw, rog_snapshots, rog_producer = validate_rog_payload(
            H, spec["rog_lane_receipt"], spec["rog_invocation"], head, tree, gate_source, manifest)
        snapshots.extend(rog_snapshots)
        state["validated_inputs"] = {
            "gate_receipt": spec["local_gate_receipt"],
            "rog_receipt": spec["rog_lane_receipt"],
            "rog_invocation": spec["rog_invocation"],
            "execution_manifest": spec["execution_manifest"],
            "payload_files": manifest["manifest"]["file_count"],
            "payload_bytes": manifest["manifest"]["total_bytes"],
            "rog_producer_sha256": sha(rog_producer),
            "exact_gate_commands": len(gate["steps"]), "exact_rog_commands": len(rog["steps"]),
        }
        emit("validated-execution-manifest.json", manifest["raw"])
        emit("validated-local-gate-receipt.json", gate_raw)
        emit("validated-rog-lane-receipt.json", rog_raw)
        emit("expected-published-dc42-heads.json", encode(published_heads))
        emit("expected-reviewed-remote-heads.json", encode(expected))
        require(H["identity_snapshot"](env) == {"head": head, "tree": tree, "status": ""},
                "local candidate HEAD/tree/status differs")
        state["source_before_identity"] = {"head": head, "tree": tree, "status": ""}
        for label, argv in (
            ("origin-push-url", ["git", "remote", "get-url", "--push", "--all", "origin"]),
            ("origin-fetch-url", ["git", "remote", "get-url", "--all", "origin"]),
        ):
            require(run(label, argv, timeout=60).stdout.decode().splitlines() == [URL],
                    "exactly one fixed origin URL required")
        configured = run("existing-hook-config", ["git", "config", "--get", "core.hooksPath"],
                         timeout=60, require_zero=False)
        require(configured.returncode == 1 and not configured.stdout and not configured.stderr,
                "existing configured hook must not be overridden")
        default_hook = pathlib.Path(git_value("default-hook-path", "rev-parse",
                                   "--path-format=absolute", "--git-path", "hooks/pre-push"))
        require(not default_hook.exists() and not default_hook.is_symlink(),
                "existing default pre-push hook must not be overridden")
        run("project-preflight", ["bash", "scripts/project-preflight.sh", "--audit"])
        source_before = run("verify-source-before", [H["PYTHON"], "-B", "scripts/ci/verify_ci_source.py",
             "--kind", "head", "--expected-head", head, "--output", str(ev / "source-before.json")])
        fresh_source_raw, fresh_source_snapshot = stable_bytes(ev / "source-before.json")
        require(fresh_source_raw == source_before.stdout
                and H["validate_source_identity"](fresh_source_raw, head, tree) == gate_source,
                "fresh source identity differs from completed gate/ROG receipts")
        snapshots.append(fresh_source_snapshot)
        for label, ancestor in (("candidate-fast-forward", BASE_HEAD),
                                ("main-ancestry", MAIN_HEAD),
                                ("semantic-ledger-ancestry", "5c04c60e463462d9df8884786e0d5bb32af08a64")):
            run(label, ["git", "--no-replace-objects", "merge-base", "--is-ancestor", ancestor, head],
                timeout=60)
        run("published-to-reviewed-remote", ["git", "--no-replace-objects", "merge-base",
            "--is-ancestor", BASE_HEAD, expected_remote_head], timeout=60)
        run("reviewed-remote-to-candidate", ["git", "--no-replace-objects", "merge-base",
            "--is-ancestor", expected_remote_head, head], timeout=60)
        rog_start = spec["rog_invocation"]["expected_start_head"]
        run("published-to-rog-start", ["git", "--no-replace-objects", "merge-base",
            "--is-ancestor", BASE_HEAD, rog_start], timeout=60)
        run("rog-start-to-candidate", ["git", "--no-replace-objects", "merge-base",
            "--is-ancestor", rog_start, head], timeout=60)
        actor = strict_json(run("actor", ["gh", "api", "user", "--jq", "{login,id}"]).stdout)
        require(actor["login"] == "ProfHepta", "unexpected authenticated actor")
        pr = strict_json(run("pr-before", ["gh", "api", "repos/" + REPOSITORY + "/pulls/847",
            "--jq", "{number,state,draft,head:.head.sha,head_ref:.head.ref,base:.base.sha,base_ref:.base.ref,auto_merge}"]).stdout)
        require(pr["number"] == 847 and pr["state"] == "open" and pr["head"] == expected_remote_head
                and pr["head_ref"] == CANDIDATE_REF[11:] and pr["base_ref"] == "main"
                and pr["base"] == MAIN_HEAD and pr["auto_merge"] is None
                and type(pr["draft"]) is bool, "PR/base/head/auto-merge guard differs")
        state["actor"], state["pr_before"] = actor, pr
        state["remote_before"] = observe_remote("before", expected)
        save()
        require(state["remote_before"]["both_old"],
                "fresh complete heads/old archive/new-tag absence differ; new review required")
        run("archive-ref-format", ["git", "check-ref-format", tagref], timeout=60)
        absent = run("new-local-tag-absence", ["git", "show-ref", "--verify", "--quiet", tagref],
                     timeout=60, require_zero=False)
        require(absent.returncode == 1 and not absent.stdout and not absent.stderr,
                "new local tag already exists or absence check failed")
        require(git_value("old-local-tag", "rev-parse", OLD_TAG_REF) == OLD_TAG_OID
                and git_value("old-local-peel", "rev-parse", OLD_TAG_REF + "^{}") == OLD_ARCHIVE_COMMIT,
                "local original archive tag changed")
        old_tag_raw = object_bytes("old-archive-tag-object", "tag", OLD_TAG_OID, 64 * 1024)
        check_tag_object(old_tag_raw, OLD_TAG_OID, OLD_TAG, OLD_ARCHIVE_COMMIT)
        old_commit_raw = object_bytes("old-archive-commit-object", "commit", OLD_ARCHIVE_COMMIT, 128 * 1024)
        check_commit_object(old_commit_raw, OLD_ARCHIVE_COMMIT, OLD_ARCHIVE_TREE, old_parents)
        state["old_archive_verified"] = {
            "tag": OLD_TAG, "tag_oid": OLD_TAG_OID, "commit": OLD_ARCHIVE_COMMIT,
            "tree": OLD_ARCHIVE_TREE, "exact_direct_parents": len(old_parents),
            "commit_raw_sha256": sha(old_commit_raw), "tag_raw_sha256": sha(old_tag_raw),
            "historical_manifest_sha256": sha(frozen_raw),
            "new_full_fsck_performed": False, "preservation_is_not_semantic_absorption": True,
        }

        archive_scope = {
            "schema": "trnm-followup-execution-archive-scope-v2",
            "candidate_head": head, "candidate_tree": tree,
            "previous_own_published_head": BASE_HEAD,
            "expected_remote_head": expected_remote_head,
            "old_history_archive": state["old_archive_verified"],
            "exact_ordered_parents": [OLD_ARCHIVE_COMMIT, head],
            "frozen_remote_branch_names": 908, "original_distinct_tips": 892,
            "payload_manifest_sha256": sha(manifest["raw"]),
            "payload_files": len(manifest["payload"]),
            "payload_bytes": manifest["manifest"]["total_bytes"],
            "local_gate_receipt_sha256": sha(gate_raw), "rog_lane_receipt_sha256": sha(rog_raw),
            "original_rog_producer_sha256": sha(rog_producer),
            "main_merged": False, "branches_deleted": False, "protection_changed": False,
            "hosted_ci_qualification": False, "qualification_granted": False,
            "archive_preserves_history_not_semantic_equivalence": True,
            "current_publication_outcome_included": False,
            "new_full_fsck_performed": False,
        }
        files = {"payload/" + name: raw for name, raw in manifest["payload"].items()}
        files.update({
            "metadata/publication-spec.json": spec_raw,
            "metadata/execution-manifest.json": manifest["raw"],
            "metadata/frozen-0170-branches.json": frozen_raw,
            "metadata/published-dc42-expected-heads.json": encode(published_heads),
            "metadata/reviewed-remote-expected-heads.json": encode(expected),
            "metadata/archive-scope.json": encode(archive_scope),
            "metadata/local-gates.json": gate_raw,
            "metadata/rog-full-lane.json": rog_raw,
            "metadata/live-source-before.json": fresh_source_raw,
            "metadata/original-archive-commit.raw": old_commit_raw,
            "metadata/original-archive-tag.raw": old_tag_raw,
            "producers/followup-publisher.py": self_raw,
            "producers/original-publisher-v4.py": publisher_raw,
            "producers/original-resume-v2.py": resume_raw,
            "producers/seven-source-gates.py": gate_producer,
            "producers/rog-offline-v4.py": rog_producer,
            "README.md": (
                "# Frozen execution receipts and follow-up candidate\n\n"
                "This archive has exactly two ordered parents: the immutable original history archive, "
                "then the reviewed follow-up candidate. The first parent retains the original 893-parent "
                "history record; the second retains the candidate. Payload files are exact frozen bytes "
                "with explicit original paths, lengths and SHA256 values. Failed and UNKNOWN receipts "
                "remain failed and UNKNOWN. Historical preservation does not establish semantic equivalence.\n\n"
                "The selected local seven-gate receipt and original ROG repository-truth lane passed on "
                "the exact candidate. These local receipts do not confer hosted head/prospective CI, "
                "protocol, performance, production or activation qualification. Main was not merged, "
                "no branch was deleted, and no protection was changed by this archive operation.\n\n"
                "The outcome of the current publication is recorded externally after the push and is "
                "not self-referentially included. The archive index covers every other file, explicitly "
                "excluding itself. No new full object fsck is claimed here.\n"
            ).encode(),
        })
        for name, raw in old_originals.items():
            files["metadata/original-publication/" + name] = raw
        for name in files:
            safe_relative(name)
        archive_index = {"schema": "trnm-execution-archive-file-index-v1",
                         "self_excluded": "metadata/archive-file-index.json",
                         "files": [{"path": name, "bytes": len(raw), "sha256": sha(raw),
                                    "git_blob": git_object_oid("blob", raw), "mode": "100644"}
                                   for name, raw in sorted(files.items())]}
        files["metadata/archive-file-index.json"] = encode(archive_index)
        check_versions(snapshots)
        root_node, file_oids = {}, {}
        for index, (name, raw) in enumerate(sorted(files.items()), 1):
            parts = safe_relative(name).parts
            node = root_node
            for part in parts[:-1]:
                require(part not in node or isinstance(node[part], dict), "archive path collision")
                node = node.setdefault(part, {})
            require(parts[-1] not in node, "duplicate archive file")
            oid = run("archive-blob-" + str(index), ["git", "hash-object", "-w", "--stdin"],
                      data=raw, timeout=60).stdout.decode("ascii").strip()
            require(oid == git_object_oid("blob", raw), "written Git blob differs from held payload")
            node[parts[-1]] = oid
            file_oids[name] = oid
        tree_counter = [0]
        def write_tree(node):
            entries = []
            for name, value in sorted(node.items()):
                if isinstance(value, dict):
                    oid, mode, kind = write_tree(value), "040000", "tree"
                else:
                    oid, mode, kind = value, "100644", "blob"
                entries.append((mode + " " + kind + " " + oid + "\t" + name).encode("utf-8") + b"\0")
            tree_counter[0] += 1
            result = run("archive-tree-" + str(tree_counter[0]), ["git", "mktree", "-z"],
                         data=b"".join(entries), timeout=60).stdout.decode("ascii").strip()
            require(re.fullmatch(r"[0-9a-f]{40}", result), "invalid generated tree OID")
            return result
        archive_tree = write_tree(root_node)
        listing = run("archive-exact-tree-list", ["git", "ls-tree", "-r", "-z", archive_tree],
                      timeout=60).stdout
        actual_files = {}
        for record in listing.split(b"\0"):
            if not record:
                continue
            metadata, name = record.split(b"\t", 1)
            mode, kind, oid = metadata.decode("ascii").split()
            name = name.decode("utf-8")
            require(mode == "100644" and kind == "blob" and name not in actual_files,
                    "generated archive contains unexpected mode/type/duplicate")
            actual_files[name] = oid
        require(actual_files == file_oids, "generated archive tree path/blob roster differs")
        archive_commit = run("archive-commit", ["git", "commit-tree", archive_tree,
            "-p", OLD_ARCHIVE_COMMIT, "-p", head],
            data=("Preserve frozen follow-up execution receipts and candidate " + head + "\n").encode(),
            timeout=60).stdout.decode("ascii").strip()
        require(re.fullmatch(r"[0-9a-f]{40}", archive_commit), "invalid generated archive commit")
        new_commit_raw = object_bytes("new-archive-commit-object", "commit", archive_commit, 128 * 1024)
        check_commit_object(new_commit_raw, archive_commit, archive_tree, [OLD_ARCHIVE_COMMIT, head])
        run("archive-annotated-tag", ["git", "tag", "-a", tag, archive_commit, "-m",
            "Frozen follow-up execution receipts; original history archive " + OLD_ARCHIVE_COMMIT +
            "; candidate " + head + ". No main merge, deletion, hosted or protocol qualification."],
            timeout=60)
        tag_oid = git_value("new-local-tag", "rev-parse", tagref)
        require(git_value("new-local-peel", "rev-parse", tagref + "^{}") == archive_commit,
                "new annotated archive peel differs")
        new_tag_raw = object_bytes("new-archive-tag-object", "tag", tag_oid, 64 * 1024)
        check_tag_object(new_tag_raw, tag_oid, tag, archive_commit)
        state["archive"] = {
            "tag": tag, "tag_oid": tag_oid, "commit": archive_commit, "tree": archive_tree,
            "direct_parents": [OLD_ARCHIVE_COMMIT, head], "candidate_head": head,
            "payload_manifest_sha256": sha(manifest["raw"]), "archive_files": len(files),
            "archive_bytes": sum(map(len, files.values())),
            "file_index_sha256": sha(files["metadata/archive-file-index.json"]),
        }
        emit("archive-local.json", encode(state["archive"]))
        emit("archive-file-index.json", files["metadata/archive-file-index.json"])
        hook_dir = ev / "hooks"
        hook_dir.mkdir(mode=0o700)
        expected_hook = {
            "origin": URL, "remote_heads": expected, "old_archive_tags": old_tags,
            "new_tag_ref": tagref, "updates": {
                CANDIDATE_REF: {"local_ref": head, "new": head, "old": expected_remote_head},
                tagref: {"local_ref": tagref, "new": tag_oid, "old": ZERO},
            },
        }
        expected_hook_raw = encode(expected_hook)
        with (hook_dir / "expected.json").open("xb") as stream:
            stream.write(expected_hook_raw)
        hook_raw = HOOK_TEMPLATE.replace("__EXPECTED_SHA__", sha(expected_hook_raw)).replace(
            "__EXPECTED_BYTES__", str(len(expected_hook_raw))).encode()
        hook_path = hook_dir / "pre-push"
        with hook_path.open("xb") as stream:
            stream.write(hook_raw)
        hook_path.chmod(0o700)
        require(stat.S_ISREG(hook_path.lstat().st_mode)
                and hook_path.lstat().st_mode & 0o111
                and hook_path.resolve(strict=True) == hook_path, "actual executable hook missing")
        run("prepush-preflight", ["bash", "scripts/project-preflight.sh", "--audit"])
        require(H["identity_snapshot"](env) == {"head": head, "tree": tree, "status": ""},
                "candidate source changed before push")
        require(run("prepush-origin-push-url", ["git", "remote", "get-url", "--push", "--all", "origin"],
                    timeout=60).stdout.decode().splitlines() == [URL], "push URL changed")
        # These stable held-input identities are rechecked after archive creation.
        # The actual send transaction still uses the normal server old-OID check.
        current_hook_config = run("prepush-existing-hook-config",
            ["git", "config", "--get", "core.hooksPath"], timeout=60, require_zero=False)
        require(current_hook_config.returncode == 1 and not current_hook_config.stdout
                and not current_hook_config.stderr
                and not default_hook.exists() and not default_hook.is_symlink(),
                "another required pre-push hook appeared")
        current_pr = strict_json(run("pr-prepush", ["gh", "api", "repos/" + REPOSITORY + "/pulls/847",
            "--jq", "{number,state,draft,head:.head.sha,head_ref:.head.ref,base:.base.sha,base_ref:.base.ref,auto_merge}"]).stdout)
        require(current_pr == pr, "PR changed during archive preparation")
        current_actor = strict_json(run("actor-prepush", ["gh", "api", "user", "--jq", "{login,id}"]).stdout)
        require(current_actor == actor, "authenticated actor changed during archive preparation")
        check_versions(snapshots)
        require(stable_bytes(hook_path)[0] == hook_raw
                and stable_bytes(hook_dir / "expected.json")[0] == expected_hook_raw,
                "hook inputs changed before push")
        state["push_started"], state["status"] = True, "UNKNOWN"
        state["push_started_at"] = now()
        save()
        push = run("atomic-publish", ["git", "-c", "core.hooksPath=" + str(hook_dir),
                    "push", "--verify", "--atomic", "--porcelain", "--verbose", "--progress",
                    "origin", head + ":" + CANDIDATE_REF, tagref + ":" + tagref],
                   timeout=1800, require_zero=False, sampled=True)
        state["push_exit"] = push.returncode
        save()
    except Exception as error:
        state["errors"].append({"phase": "prepare-or-push", "type": type(error).__name__,
                                "message": str(error)})
    finally:
        # No retry follows any transport status. Both destinations are always
        # observed independently once a push was attempted, even after failure.
        if state["push_started"]:
            try:
                state["remote_after"] = observe_remote("after", expected, state["archive"])
            except Exception as error:
                state["errors"].append({"phase": "remote-after", "type": type(error).__name__,
                                        "message": str(error)})
            try:
                state["hook_receipt"] = verify_hook_receipt(
                    hook_dir, expected_hook_raw, hook_raw, expected_hook)
                state["exact_hook_verified"] = True
            except Exception as error:
                state["errors"].append({"phase": "hook-readback", "type": type(error).__name__,
                                        "message": str(error)})
        if gate_source is not None:
            try:
                source_after = run("verify-source-after", [H["PYTHON"], "-B",
                    "scripts/ci/verify_ci_source.py", "--kind", "head", "--expected-head", head,
                    "--output", str(ev / "source-after.json")], require_zero=False)
                require(source_after.returncode == 0, "final source check failed")
                after_raw, _ = stable_bytes(ev / "source-after.json")
                require(after_raw == source_after.stdout
                        and H["validate_source_identity"](after_raw, head, tree) == gate_source,
                        "final source stdout/sidecar/receipt differs")
                if fresh_source_raw is not None:
                    require(after_raw == fresh_source_raw, "live before/after source bytes differ")
                state["source_after_identity"] = H["identity_snapshot"](env)
                require(state["source_after_identity"] == {"head": head, "tree": tree, "status": ""},
                        "final HEAD/tree/status differs")
                state["source_after_valid"] = True
            except Exception as error:
                state["errors"].append({"phase": "source-after", "type": type(error).__name__,
                                        "message": str(error)})
        after = state["remote_after"]
        confirmed = (state["push_started"] and isinstance(after, dict) and after["both_new"]
                     and state["source_after_valid"] and state["exact_hook_verified"])
        state["status"] = "confirmed" if confirmed else ("UNKNOWN" if state["push_started"] else "HOLD")
        state["finished_at"] = now()
        save()
    print(json.dumps({"schema": state["schema"], "status": state["status"],
                      "head": head, "tree": tree, "push_exit": state["push_exit"],
                      "source_after_valid": state["source_after_valid"],
                      "exact_hook_verified": state["exact_hook_verified"],
                      "receipt": str(ev / "summary.json")}), flush=True)
    return 0 if state["status"] == "confirmed" else 1

if __name__ == "__main__":
    sys.exit(main())
