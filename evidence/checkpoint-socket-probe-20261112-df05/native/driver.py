#!/usr/bin/env python3
"""Run only the reviewed checkpoint follow-up gates on one caller-pinned new source."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time
import traceback
import types

KEY = "chain-checkpoint-probe-native-validation-20261112-df05-v2"
PREP_KEY = "chain-checkpoint-probe-source-prep-20261112-df05-v1"
ROOT = Path("/data/chain-checkpoint-probe-20261112-df05")
CONTROL = Path("/data/chain-checkpoint-probe-source-20261112-df05")
OUT = Path("/data/chain-checkpoint-probe-validation-20261112-df05-v2")
BRANCH = "fix/chain-checkpoint-probe-20261112-df05"
PARENT_EVIDENCE = "09e4801308366fac01e55bcbdcf8bdfd4e6d2810"
PARENT_TREE = "f322d45faaa204b641ed2565feca662ef096b161"
PARENT_PR = 945
OLD_SOURCE = "87943f6229d8785c3f431ede5eadba62b634ab8c"
OLD_TREE = "5d2538f404e32319ea1084a6c79f37c52503546f"
OLD_PREFIX = "evidence/root-execution-v6-20261112-df05-v3"
OLD_OUT = Path("/data/chain-root-validation-20261112-df05-v3")
OLD_STATE = Path("/data/chain-root-publication-20261112-df05-v2")
TARGET = Path("/data/chain-checkpoint-probe-target-20261112-df05-v2")
HELPER = Path("/data/chain-root-publication-bootstrap-20261112-df05-v2/root-native-publisher-v2-df05.py")
HELPER_SHA = "6b42ffccdd9ff216d1ec786813ba3059e0c89550ffbc8c6af6304f415884c40c"
VERIFIER_SHA = "0ddfd07719eae98913348c82b06d3e4522d721c353d9b01d6deac0dfda619946"
OWNER_SHA = "389154c792fd3c734621278fb4188e9863ff599efb0c9b863316f540a94eab4a"
TOOLCHAIN = Path("/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin")
PROVIDER = Path("/home/qian-qi/credit-envelope-f7e62-provider2/runner/trnm-pq-provider-3.5.9.5yXdk2mN/install")
PROVIDER_HASHES = {
    "bin/openssl": "41d5b79f937beed7f94d9623be504db72c5048fcd952965fc0e13305d2802a33",
    "include/openssl/opensslv.h": "9647fc99758cf83e3bcf11ae310894fd4911ad62bff22d8213a614df89cfedda",
    "include/openssl/configuration.h": "406c26f93511299b264062f9f3faf0760e7a0506e91a61717c491f3c92e1a996",
    "lib/libcrypto.a": "005a0f7d9f6a073e6530cc556c90b3c415df7c6bc2475e333d29aa9bfa409bfb",
    "lib/libssl.a": "f355167951857505b5b0305fd2e8ea8f224fa29d780211175d32767b07234727",
}
CORPUS = "config/pon/pq-cross-branch-corpus-v1.json"
PLAN = "docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md"
POST_SHA = {
    "trillionnium/crates/trnm-checkpoint-store/src/lib.rs": "8ad6d9b14300c2df5d674604e4a0107e242c40d6a1e0f1a56d83763015b6f880",
    "trillionnium/crates/trnm-checkpoint-store/tests/socket_ownership.rs": "6c0482cab4ce234e32ebd388a856f1754aeaa48f299b1996f721420b0bac088f",
}
PLAN_ENTRY_SHA = "0458acbd35eed7528b2334643b0c19ed01bd960384d53321220809c16875e179"
EXPECTED_SOURCE_PATHS = {*POST_SHA, PLAN, CORPUS}
stage = "admission"
records = []


def need(value, message):
    if not value:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stable(path, cap=4 * 1024 * 1024):
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= cap,
         "not a bounded single-link regular file: " + str(path))
    fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
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


def put(path, value, replace=False):
    raw = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    need(replace or not os.path.lexists(path), "retained artifact exists: " + str(path))
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fsync_dir(path.parent)


def planned_commands():
    cargo = str(TOOLCHAIN / "cargo")
    metadata = [cargo, "metadata", "--locked", "--offline", "--format-version", "1"]
    return [
        ("preflight", ["bash", "scripts/project-preflight.sh"], 120),
        ("rustc-version", [str(TOOLCHAIN / "rustc"), "-Vv"], 120),
        ("cargo-version", [cargo, "-V"], 120),
        ("openssl-version", [str(PROVIDER / "bin/openssl"), "version", "-a"], 120),
        ("metadata-default", metadata + ["--manifest-path", "trillionnium/Cargo.toml"], 300),
        ("metadata-all-features", metadata + ["--all-features", "--manifest-path", "trillionnium/Cargo.toml"], 300),
        ("metadata-fuzz", metadata + ["--manifest-path", "tests/fuzz/Cargo.toml"], 300),
        ("format", [cargo, "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"], 300),
        ("source-integrity-controls", ["/usr/bin/python3", "-B", "-m", "unittest", "discover", "-s", "scripts/ci", "-p", "test_ci_source_integrity.py", "-v"], 600),
        ("repository-links", ["/usr/bin/python3", "-B", "scripts/ci/check_repository.py"], 600),
        ("research-corpus", ["/usr/bin/python3", "-B", "scripts/ci/check_pq_research_integration.py"], 600),
        ("source-inventory", ["/usr/bin/python3", "-B", "scripts/refresh_distributed_source_inventory.py", "--check"], 300),
        ("checkpoint-package", [cargo, "test", "--locked", "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-checkpoint-store", "--", "--show-output", "--test-threads=1"], 1200),
        ("strict-workspace-clippy", [cargo, "clippy", "--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"], 3600),
    ]


def selected_environment():
    return {
        "PATH": str(TOOLCHAIN) + ":/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin",
        "CARGO_HOME": "/home/qian-qi/.cargo", "CARGO_TARGET_DIR": str(TARGET),
        "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0", "CARGO_TERM_COLOR": "never", "CARGO_NET_OFFLINE": "true",
        "RUSTUP_TOOLCHAIN": "1.95.0", "RUSTC": str(TOOLCHAIN / "rustc"), "RUSTDOC": str(TOOLCHAIN / "rustdoc"),
        "OPENSSL_DIR": str(PROVIDER), "OPENSSL_STATIC": "1", "OPENSSL_NO_VENDOR": "1",
        "OPENSSL_LIB_DIR": str(PROVIDER / "lib"), "OPENSSL_INCLUDE_DIR": str(PROVIDER / "include"),
        "TRNM_PQ_OPENSSL": str(PROVIDER / "bin/openssl"), "TRNM_PQ_OPENSSL_SHA256": PROVIDER_HASHES["bin/openssl"], "TRNM_PQ_OPENSSL_VERSION": "3.5.9",
        "OPENSSL_CONF": "/dev/null", "OPENSSL_MODULES": str(PROVIDER / "lib/ossl-modules"),
        "TMPDIR": str(OUT / "tmp"), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPYCACHEPREFIX": str(OUT / "pycache"), "GIT_TERMINAL_PROMPT": "0",
    }


def no_explicit_hold():
    for directory in (ROOT, CONTROL, OUT,
            Path("/data/chain-checkpoint-probe-validation-20261112-df05"),
            Path("/data/chain-checkpoint-probe-publication-20261112-df05"),
            Path("/data/chain-checkpoint-probe-publication-20261112-df05-v2")):
        need(not os.path.lexists(directory / "PUBLICATION_HOLD"), "explicit retained HOLD marker: " + str(directory))


def target_identity():
    info = TARGET.lstat()
    need(stat.S_ISDIR(info.st_mode), "target pathname is not a directory")
    return {"device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode),
            "uid": info.st_uid, "gid": info.st_gid}


def import_verified(name, path, expected_sha):
    raw = stable(path)
    need(sha(raw) == expected_sha, "reviewed executable snapshot differs: " + str(path))
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module


def import_helper():
    module = import_verified("checkpoint_probe_reviewed_helpers", HELPER, HELPER_SHA)
    module.ROOT = ROOT
    module.BRANCH = BRANCH
    return module


def admit_source(helper, data):
    source, tree = data["source"], data["tree"]
    need(helper.gtext("rev-parse", "HEAD") == source
         and helper.gtext("rev-parse", "HEAD^{tree}") == tree
         and helper.gtext("show", "-s", "--format=%P", source) == PARENT_EVIDENCE,
         "new source identity/parent differs")
    helper.repository_identity()
    frozen_bytes = stable(CONTROL / "FROZEN.json")
    expected = data["source_preparation"]
    need(set(expected) == {"frozen_bytes", "frozen_sha256", "program_sha256", "input_sha256", "safe_manifest_sha256"},
         "source preparation identity fields differ")
    need(len(frozen_bytes) == expected["frozen_bytes"] and sha(frozen_bytes) == expected["frozen_sha256"],
         "frozen source receipt differs")
    frozen = json.loads(frozen_bytes)
    need(frozen["schema"] == "checkpoint-probe-source-v1" and frozen["operation_key"] == PREP_KEY
         and frozen["head"] == source and frozen["tree"] == tree
         and frozen["parent"] == PARENT_EVIDENCE and frozen["parent_tree"] == PARENT_TREE
         and frozen["worktree"] == str(ROOT) and frozen["branch"] == BRANCH
         and frozen["unchanged_outside_four_paths"] is True and frozen["source_clean"] is True
         and frozen["old_failures_reused_as_new_pass"] is False, "frozen source scope differs")
    need(all(frozen[name] == expected[name] for name in ("program_sha256", "input_sha256", "safe_manifest_sha256")),
         "source preparation input/program identity differs")
    need(sha(stable(CONTROL / "driver.py")) == expected["program_sha256"]
         and sha(stable(CONTROL / "SAFE_MANIFEST.json")) == expected["safe_manifest_sha256"], "source preparation artifacts differ")
    parent = helper.entries(PARENT_EVIDENCE)
    actual = helper.entries(source)
    need(set(parent) == set(actual), "source path set differs")
    changed = {name for name in parent if parent[name] != actual[name]}
    need(changed == EXPECTED_SOURCE_PATHS, "source delta is not exact four paths")
    for name in POST_SHA:
        need(actual[name][0] == parent[name][0] == "100644" and sha(stable(ROOT / name)) == POST_SHA[name], "source postimage differs")
    old_plan = helper.git("show", PARENT_EVIDENCE + ":" + PLAN).stdout
    new_plan = stable(ROOT / PLAN)
    need(new_plan.endswith(old_plan) and len(new_plan) > len(old_plan), "sole-plan suffix differs")
    entry = new_plan[:-len(old_plan)]
    need(entry.endswith(b"\n\n") and sha(entry[:-1]) == PLAN_ENTRY_SHA, "plan prepend differs")
    old_corpus = json.loads(helper.git("show", PARENT_EVIDENCE + ":" + CORPUS).stdout)
    actual_corpus = json.loads(stable(ROOT / CORPUS))
    expected_corpus = json.loads(json.dumps(old_corpus))
    for name in (*POST_SHA, PLAN):
        need(old_corpus["pinned_blobs"][name] == parent[name][1], "parent corpus pin differs")
        expected_corpus["pinned_blobs"][name] = actual[name][1]
    need(actual_corpus == expected_corpus, "corpus changed outside three existing pins")
    need(all(actual[name][0] == parent[name][0] for name in changed), "changed tracked mode")
    put(OUT / "source-preparation.json", frozen_bytes)
    return frozen


def admit_previous_owners(helper, projection):
    need(set(projection) == {"schema", "validation", "publication", "publication_receipt"}
         and projection["schema"] == "checkpoint-probe-prior-owner-closure-v1", "prior closure fields differ")
    for name, job, key, runtime_key in (
        ("validation", "1a1cf53f912-2564-19f0", "root-operation-20261112-df05-native-validation-v3", "root-operation-20261112-df05-native-validation-v3"),
        ("publication", "1a1cfcc92d8-2564-1aba", "root-operation-20261112-df05-native-publication-v2", "root-operation-20261112-df05-native-publication-v2-resume1"),
    ):
        item = projection[name]
        need(set(item) == {"job_id", "operation_key", "runtime_idempotency_key", "state", "exit_code", "output_complete", "output_durable", "terminal_publication_confirmed"}
             and item["job_id"] == job and item["operation_key"] == key
             and item["runtime_idempotency_key"] == runtime_key
             and item["state"] == "succeeded" and item["exit_code"] == 0
             and item["output_complete"] is True and item["output_durable"] is True
             and item["terminal_publication_confirmed"] is True,
             "prior native owner terminal is unconfirmed; target reuse denied")
    expected = projection["publication_receipt"]
    need(set(expected) == {"bytes", "sha256"} and type(expected["bytes"]) is int
         and re.fullmatch(r"[0-9a-f]{64}", expected["sha256"]), "prior publication receipt remains unbound")
    raw = stable(OLD_STATE / "PUBLICATION_RECEIPT.json")
    need(len(raw) == expected["bytes"] and sha(raw) == expected["sha256"], "prior publication receipt changed")
    receipt = json.loads(raw)
    expected_receipt = {"operation_key": "root-operation-20261112-df05-native-publication-v2",
        "native_source": OLD_SOURCE, "native_tree": OLD_TREE, "evidence_commit": PARENT_EVIDENCE,
        "pr": "https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/945",
        "draft": True, "publication_complete": True, "native_all_commands_passed": False,
        "supplement_complete_success": False, "status": "HOLD", "production_activation": False,
        "tests_relabelled_to_evidence_commit": False}
    need(receipt == expected_receipt and raw == helper.canonical(expected_receipt),
         "prior publication exact object/canonical bytes differ")
    put(OUT / "prior-owner-closure.json", projection)
    put(OUT / "prior-publication-receipt.json", raw)
    retained = {}
    for native, archived, output in (
        (OLD_OUT / "environment.json", "native/environment.json", "prior-environment.json"),
        (OLD_OUT / "VALIDATION_FINISHED.json", "native/VALIDATION_FINISHED.json", "prior-validation-finished.json"),
        (OLD_STATE / "socket-ownership/FINISHED.json", "supplemental/FINISHED.json", "prior-socket-finished.json"),
    ):
        actual = stable(native)
        need(actual == helper.git("show", PARENT_EVIDENCE + ":" + OLD_PREFIX + "/" + archived).stdout,
             "prior native owner receipt differs from already-published E1")
        put(OUT / output, actual)
        retained[output] = json.loads(actual)
    previous_env = retained["prior-environment.json"]
    need(previous_env["source"] == OLD_SOURCE and previous_env["tree"] == OLD_TREE,
         "prior environment source differs")
    old_finished = retained["prior-validation-finished.json"]
    need(old_finished["source"] == OLD_SOURCE and old_finished["tree"] == OLD_TREE
         and old_finished["all_commands_passed"] is False, "prior Root HOLD differs")
    socket = retained["prior-socket-finished.json"]
    need(socket["binding"]["source"] == OLD_SOURCE and socket["execution"]["source_verified"] is True
         and socket["execution"]["exit_code"] == 101 and socket["execution"]["timed_out"] is False
         and socket["observation"]["complete_success"] is False, "prior socket failure/owner closure differs")
    return previous_env


def main():
    global stage
    os.umask(0o077)
    sys.dont_write_bytecode = True
    need(len(sys.argv) == 3 and sys.argv[1] == "--input-sha256"
         and re.fullmatch(r"[0-9a-f]{64}", sys.argv[2]), "exact reviewed input hash required")
    raw_input = sys.stdin.buffer.read(256 * 1024 + 1)
    need(len(raw_input) <= 256 * 1024 and sha(raw_input) == sys.argv[2], "reviewed input differs")
    data = json.loads(raw_input)
    need(set(data) == {"schema", "operation_key", "source", "tree", "parent_evidence", "parent_tree",
                      "program_sha256", "source_preparation", "prior_owner_closure"}, "unreviewed input fields")
    need(data["schema"] == "checkpoint-probe-native-input-v1" and data["operation_key"] == KEY
         and data["parent_evidence"] == PARENT_EVIDENCE and data["parent_tree"] == PARENT_TREE,
         "wrong native invocation scope")
    source, tree = data["source"], data["tree"]
    need(re.fullmatch(r"[0-9a-f]{40}", source) and re.fullmatch(r"[0-9a-f]{40}", tree), "new source remains UNBOUND")
    program = (sys.orig_argv[sys.orig_argv.index("-c") + 1].encode()
               if "-c" in sys.orig_argv else Path(__file__).read_bytes())
    need(sha(program) == data["program_sha256"], "driver differs")
    no_explicit_hold()
    need(not os.path.lexists(OUT), "native output already exists; reconcile original operation, never rerun")
    OUT.mkdir(mode=0o700)
    started = time.monotonic()
    put(OUT / "driver.py", program)
    put(OUT / "invocation.json", {"operation_key": KEY, "source": source, "tree": tree,
        "parent_evidence": PARENT_EVIDENCE, "parent_tree": PARENT_TREE,
        "driver_sha256": sha(program), "input_sha256": sha(raw_input),
        "scope": "four-path checkpoint follow-up only; no Root V3/V4/V5 suite rerun or publication"})
    helper = import_helper()
    stage = "admit-frozen-new-source"
    admit_source(helper, data)
    physical_before = helper.physical_tree(source)
    put(OUT / "physical-before.json", physical_before)
    stage = "admit-prior-owner-history"
    previous_env = admit_previous_owners(helper, data["prior_owner_closure"])
    stage = "admit-new-empty-target"
    parent_before = TARGET.parent.lstat()
    need(stat.S_ISDIR(parent_before.st_mode), "target parent is not a direct directory")
    need(not os.path.lexists(TARGET), "new isolated target already exists; do not reuse or rerun")
    target_free_before_creation = shutil.disk_usage(TARGET.parent).free
    output_free_before_creation = shutil.disk_usage(OUT).free
    need(target_free_before_creation >= 10 * 1024 ** 3
         and output_free_before_creation >= 1024 ** 3, "original disk reserve unavailable before target creation")
    TARGET.mkdir(mode=0o700)
    fsync_dir(TARGET.parent)
    retained_target = target_identity()
    parent_after = TARGET.parent.lstat()
    parent_fields = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)
    need(parent_fields(parent_before) == parent_fields(parent_after), "target parent identity changed during creation")
    need(retained_target["mode"] == 0o700 and retained_target["uid"] == os.geteuid()
         and not any(TARGET.iterdir()), "new target is not empty private owned storage")
    target_admission = {"path": str(TARGET), "created_new_empty": True,
        "absent_before_creation": True, "identity": retained_target,
        "requested_mode": 0o700, "creating_euid": os.geteuid(),
        "free_bytes_before_creation": target_free_before_creation, "required_free_bytes": 10 * 1024 ** 3,
        "output_free_bytes_before_creation": output_free_before_creation, "output_required_free_bytes": 1024 ** 3,
        "parent_device": parent_before.st_dev, "parent_inode": parent_before.st_ino,
        "parent_identity_unchanged_during_creation": True,
        "old_target_reused": False, "old_target_recreated": False,
        "prior_environment_target": previous_env["environment"]["CARGO_TARGET_DIR"]}
    (OUT / "tmp").mkdir()
    (OUT / "pycache").mkdir()
    selected = selected_environment()
    old_selected = previous_env["environment"]
    need(set(selected) == set(old_selected)
         and all(selected[name] == old_selected[name] for name in selected if name not in ("CARGO_TARGET_DIR", "TMPDIR", "PYTHONPYCACHEPREFIX")),
         "compiler/provider/resource environment differs beyond explicit new storage paths")
    env = helper.clean_env(selected)
    os.environ.clear()
    os.environ.update(env)
    sys.pycache_prefix = str(OUT / "pycache")
    stage = "verify-original-tools"
    for path, expected in ((ROOT / "scripts/ci/verify_ci_source.py", VERIFIER_SHA),
                           (ROOT / "scripts/ci/ci_observation.py", OWNER_SHA)):
        need(sha(stable(path)) == expected, "original verifier/process owner differs")
    provider = []
    for name, expected in PROVIDER_HASHES.items():
        path = PROVIDER / name
        identity = helper.file_identity(path, allow_hardlinks=True)
        need(identity["sha256"] == expected, "fixed provider input changed")
        provider.append({"path": str(path), **identity})
    need((TOOLCHAIN / "cargo").is_file() and (TOOLCHAIN / "rustc").is_file(), "fixed toolchain missing")
    put(OUT / "environment.json", {"source": source, "tree": tree, "parent_evidence": PARENT_EVIDENCE,
        "host": "desktop", "environment": selected, "provider": provider,
        "optimization_or_debug_profile_overrides": False, "isolated_new_target": True,
        "reused_target_after_verified_prior_owner_terminal": False,
        "target_admission": target_admission,
        "target_identity": retained_target, "target_identity_rechecked_per_command": True,
        "target_identity_scope": "new empty owned directory created by this invocation; not a reused or recovered prior target",
        "prior_terminal_basis": "caller-pinned authoritative H runtime terminal projection plus exact native/E1 receipt readback",
        "minimum_free_bytes_before_command": 10 * 1024 ** 3,
        "before_target_disk": shutil.disk_usage(TARGET)._asdict(), "before_output_disk": shutil.disk_usage(OUT)._asdict()})
    sys.path.insert(0, str(ROOT / "scripts/ci"))
    verify = import_verified("verify_ci_source", ROOT / "scripts/ci/verify_ci_source.py", VERIFIER_SHA).verify
    run = import_verified("ci_observation", ROOT / "scripts/ci/ci_observation.py", OWNER_SHA).run
    stage = "verify-before"
    before = verify("head", source, root=ROOT)
    put(OUT / "source-before.json", before)
    cmds = planned_commands()
    put(OUT / "plan.json", {"source": source, "tree": tree, "parent_evidence": PARENT_EVIDENCE,
        "commands": [{"name": name, "argv": argv, "outer_timeout_seconds": timeout} for name, argv, timeout in cmds],
        "outer_owner": "unchanged scripts/ci/ci_observation.py::run with process-group cleanup",
        "original_test_and_internal_transport_timeouts_unchanged": True,
        "root_s879_native_qualification_reused": False})
    for name, argv, timeout in cmds:
        stage = name
        no_explicit_hold()
        need(shutil.disk_usage(TARGET).free >= 10 * 1024 ** 3 and shutil.disk_usage(OUT).free >= 1024 ** 3,
             "original retained disk reserve reached before " + name)
        target_before = target_identity()
        need(target_before == retained_target, "target directory incarnation changed before " + name)
        log = OUT / (name + ".log")
        receipt_path = OUT / (name + ".receipt.json")
        need(not os.path.lexists(log) and not os.path.lexists(receipt_path), "existing command observation; do not rerun")
        print(json.dumps({"stage": name, "status": "START", "source": source}), flush=True)
        row = run(argv, log, timeout=timeout, env=env, cwd=ROOT, expected_source=source)
        identity = helper.file_identity(log)
        target_error = None
        try:
            target_after = target_identity()
        except (OSError, RuntimeError) as error:
            target_after, target_error = None, str(error)
        row.update(name=name, source=source, target_before_identity=target_before,
                   target_after_identity=target_after, target_identity_error=target_error, **identity)
        records.append(row)
        put(receipt_path, row)
        put(OUT / "commands.json", records, replace=True)
        print(json.dumps({"stage": name, "exit_code": row["exit_code"], "timed_out": row["timed_out"],
            "source_verified": row.get("source_verified")}), flush=True)
        need(row.get("source_verified") is True, "physical source integrity failed at " + name)
        need(target_error is None and target_after == retained_target, "target directory incarnation changed during " + name)
    stage = "verify-after"
    no_explicit_hold()
    after = verify("head", source, root=ROOT)
    need(before == after, "source changed across native gates")
    put(OUT / "source-after.json", after)
    physical_after = helper.physical_tree(source)
    need(physical_before == physical_after, "physical source changed across native gates")
    put(OUT / "physical-after.json", physical_after)
    need(target_identity() == retained_target, "target directory incarnation changed before native finish")
    for item in provider:
        need(helper.file_identity(Path(item["path"]), allow_hardlinks=True) == {"bytes": item["bytes"], "sha256": item["sha256"]},
             "provider input changed")
    report = {"schema": "checkpoint-probe-native-validation-v1", "operation_key": KEY,
        "source": source, "tree": tree, "parent_evidence": PARENT_EVIDENCE, "parent_tree": PARENT_TREE,
        "source_consistent": True, "provider_unchanged": True, "commands": records,
        "target_identity_consistent": True,
        "all_commands_passed": all(row["exit_code"] == 0 and not row["timed_out"] for row in records),
        "status": "HOLD", "root_s879_native_qualification_reused": False,
        "production_activation": False, "publication_performed": False, "elapsed_seconds": time.monotonic() - started}
    put(OUT / "SUMMARY.json", report)
    artifacts = []
    for path in sorted(OUT.rglob("*")):
        name = path.relative_to(OUT)
        if name.parts[0] in ("tmp", "pycache"):
            continue
        if path.is_file() and name.name not in ("ARTIFACT_MANIFEST.json", "VALIDATION_FINISHED.json"):
            artifacts.append({"path": str(name), **helper.file_identity(path)})
    put(OUT / "ARTIFACT_MANIFEST.json", {"source": source, "tree": tree,
        "parent_evidence": PARENT_EVIDENCE, "artifacts": artifacts})
    for item in artifacts:
        need(helper.file_identity(OUT / item["path"]) == {"bytes": item["bytes"], "sha256": item["sha256"]},
             "retained artifact changed after cleanup")
    finished = {"schema": "checkpoint-probe-native-finished-v1", "operation_key": KEY,
        "source": source, "tree": tree, "parent_evidence": PARENT_EVIDENCE,
        "manifest_sha256": sha(stable(OUT / "ARTIFACT_MANIFEST.json")),
        "summary_sha256": sha(stable(OUT / "SUMMARY.json")),
        "all_commands_passed": report["all_commands_passed"], "status": "HOLD", "publication_performed": False}
    put(OUT / "VALIDATION_FINISHED.json", finished)
    print(json.dumps({"stage": "VALIDATION_FINISHED", "source": source,
        "all_commands_passed": report["all_commands_passed"], "out": str(OUT)}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        if OUT.is_dir() and not os.path.lexists(OUT / "FAILED.json"):
            put(OUT / "FAILED.json", {"operation_key": KEY, "stage": stage,
                "error_type": type(error).__name__, "error": str(error),
                "records_completed": len(records), "no_success_inferred": True,
                "traceback": traceback.format_exc()})
        raise
