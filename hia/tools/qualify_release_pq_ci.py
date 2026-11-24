#!/usr/bin/env python3
"""Host the real Release PQ shadow qualifiers; retain only bounded evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PIN = "87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"
STAGES = ("observation", "quorum", "callback")
MAX_LEAF = 1 << 20
MAX_ARTIFACT = 8 << 20
LIMIT = 300
LIBRARIES = {"trnm_release_bundle", "trnm_crypto_primitives", "trnm_protocol", "zeroize"}
CASES = {
    "observation": (
        ("valid_first", 0), ("valid_second", 0),
        *((f"descriptor_byte_{n}", 4) for n in (0, 1, 32, 33, 40, 41, 48, 49, 56, 57, 88, 122, 153, 154)),
        ("none_is_not_some_zero", 4), ("altered_domain", 4), ("short_signature", 4),
        ("altered_signature", 4), ("replacement_public_key", 4),
        ("wrong_pin_precedes_short_signature", 3), ("malformed_spki_precedes_pin", 1),
        ("same_verifier_positive_after_refusal", 0)),
    "quorum": (
        ("two_signers", 0), ("two_in_reverse_order", 0), ("three_above_threshold", 0), ("maximum_16", 0),
        ("zero_signature", 105), ("below_threshold", 105), ("above_16", 105),
        ("duplicate_then_width", 107), ("first_width_then_duplicate", 106),
        ("unknown_before_duplicate", 108), ("duplicate_before_unknown", 107),
        ("unknown_mathematically_valid_cross_role", 108), ("width_before_later_unknown", 106),
        ("late_unknown_precedes_earlier_math", 108), ("late_duplicate_precedes_earlier_math", 107),
        ("late_invalid_pin_precedes_earlier_math", 109), ("check_all_past_threshold", 106),
        ("der_before_signature_width", 109), ("wrong_pin_before_width", 109),
        ("declared_width_outside_slot", 106), ("all_sixteen_at_max_threshold", 0),
        ("max_threshold_not_met", 105), ("wrong_exact_message_checkpoint", 106)),
    "callback": (
        ("valid", 0, "state", 0), ("valid_signature_wrong_generation", 204, "state", 204),
        ("valid_signature_wrong_network", 204, "state", 204),
        ("bad_signature_before_wrong_generation", 2, "quorum", 106),
        ("bad_locator_before_checkpoint", 2, "locator_mismatch", 0),
        ("invalid_unsigned_before_bad_signature", 2, "unsigned", 101),
        ("invalid_role_before_invalid_unsigned", 1, "outer", 1),
        ("declared_content_mismatch_before_invalid_unsigned", 1, "outer", 1),
        ("valid_signature_stale_candidate_checkpoint", 205, "state", 205),
        ("bad_signature_before_checkpoint", 2, "quorum", 106),
        ("valid_signature_expiry_before_wrong_generation", 203, "state", 203),
        ("identity_before_locator_and_math", 2, "identity_mismatch", 0),
        ("duplicate_locator_before_quorum_and_checkpoint", 2, "locator", 107),
        ("valid_cross_role_signature_refused", 2, "quorum", 108)),
}
PRIVATE = (
    *((name, 100) for name in ("empty_private_frame", "truncated_frame", "appended_byte",
        "duplicate_trusted_pins", "unsorted_trusted_pins", "trusted_zero_threshold", "reserved_byte",
        "invalid_transcript_domain", "invalid_transcript_optional_encoding")),
    ("source_role_mismatch", 110), ("source_network_mismatch", 110),
    ("source_generation_mismatch", 110), ("scratch_too_short", 102),
    ("count_precedes_scratch", 105), ("valid_exact_scratch", 0),
)
BACKENDS = ("direct", "selfhost")
COMMON = ("qualification.json", "rust-build.stdout.jsonl", "rust-build.stderr.raw")
RAW = ("process.json", "stdout.raw", "stderr.raw")
CALLBACK_PHASES = {"unsigned", "identity", "locator", "message", "quorum", "strict", "state"}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def valid_hash(value, width=64):
    return type(value) is str and re.fullmatch(rf"[0-9a-f]{{{width}}}", value) is not None


def exact_json(raw):
    def unique(rows):
        out = {}
        for key, value in rows:
            require(key not in out, "duplicate evidence JSON key")
            out[key] = value
        return out

    def invalid(_):
        raise ValueError("non-finite evidence JSON")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def read(path, bound=MAX_LEAF):
    require(not any(p.is_symlink() for p in (path, *path.parents)) and path.is_file(),
            "expected unlinked regular evidence " + path.name)
    with path.open("rb") as file:
        data = file.read(bound + 1)
    require(len(data) <= bound, "evidence extent exceeded: " + path.name)
    return data


def obj(path):
    value = exact_json(read(path))
    require(type(value) is dict, "expected JSON object: " + path.name)
    return value


def save(path, data):
    path.write_text(json.dumps(data, sort_keys=True, allow_nan=False) + "\n")


def lineage():
    sha_env, run, attempt = [os.environ.get(k, "") for k in (
        "TRNM_EXPECTED_SOURCE_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")]
    require(valid_hash(sha_env, 40), "expected exact source SHA")
    for value in (run, attempt):
        require(re.fullmatch(r"[1-9][0-9]*", value) is not None, "expected exact Actions run/attempt")
    return {"head": sha_env, "run_id": run, "attempt": int(attempt)}


def source(path, line):
    value = obj(path)
    require(value.get("schema") == "trnm-ci-source-v1" and value.get("kind") == "head"
            and value.get("candidate") == value.get("tested_commit") == line["head"]
            and valid_hash(value.get("tested_tree"), 40)
            and value.get("tracked_worktree_verified") is True
            and value.get("tests_executed_by_identity_check") is False
            and all(type(value.get(k)) is int and value[k] > 0
                    for k in ("tracked_bytes", "tracked_entries")), "invalid full source identity")
    return value


def bootstrap(path, env_file, out):
    value = obj(path)
    compiler = Path(value.get("compiler") or "")
    require(value.get("status") == "PASS" and value.get("compiler_sha256") == PIN
            and compiler.is_absolute() and "\n" not in str(compiler) and "\r" not in str(compiler)
            and sha(read(compiler, 16 << 20)) == PIN, "unbound HIA bootstrap compiler")
    require(os.access(compiler, os.X_OK), "bootstrap compiler not executable")
    save(out / "bootstrap.json", {"status": "PASS", "compiler_sha256": PIN,
                                 "raw_bootstrap_sha256": sha(read(path))})
    with env_file.open("a") as f:
        f.write(f"HIA_NATIVE_COMPILER={compiler}\nHIA_NATIVE_COMPILER_SHA256={PIN}\n")


def stage_files(stage):
    if stage == "observation":
        return (*COMMON, "owned-verifier.json")
    if stage == "callback":
        return (*COMMON, *(f"{b}-{kind}-native-build.json" for b in BACKENDS
                           for kind in sorted(CALLBACK_PHASES)))
    return (*COMMON, *(f"{b}-{kind}-native-build.json" for b in BACKENDS
                       for kind in ("quorum", "transcript")))


def script(stage):
    return f"hia/tests/qualify_release_pq_{stage}.py"


def run(work, out):
    line = lineage()
    before = source(out / "source-before.json", line)
    require(os.environ.get("HIA_NATIVE_COMPILER_SHA256") == PIN, "unbound native compiler")
    actual_source = subprocess.check_output(["git", "show", "-s", "--format=%H %T"], cwd=ROOT, timeout=15)
    require(actual_source.decode().split() == [line["head"], before["tested_tree"]],
            "wrong real process checkout")
    run_stages(work, out, line, before["tested_tree"])


def run_stages(work, out, line, tree):
    work.mkdir(mode=0o700)
    failed = False
    retained = 0

    def retain(path, data):
        nonlocal retained
        if len(data) > MAX_ARTIFACT - MAX_LEAF - retained:
            return False
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(data)
        retained += len(data)
        return True

    for stage in STAGES:
        dest = out / stage
        dest.mkdir(mode=0o700)
        relative = script(stage)
        exe = [sys.executable, "-I", "-S", "-B", relative, "--output"]
        status, timed_out = None, False
        with tempfile.TemporaryDirectory(dir=work, prefix=stage + "-") as temp:
            original = Path(temp) / "original"
            try:
                completed = subprocess.run(exe + [str(original)], cwd=ROOT,
                    check=False, capture_output=True, timeout=LIMIT)
                status = completed.returncode
                stdout, stderr = completed.stdout, completed.stderr
            except subprocess.TimeoutExpired as error:
                timed_out = True
                stdout, stderr = error.stdout or b"", error.stderr or b""
            overflow = len(stdout) > MAX_LEAF or len(stderr) > MAX_LEAF
            for label, data in (("stdout.raw", stdout), ("stderr.raw", stderr)):
                if not retain(dest / label, data[:MAX_LEAF]):
                    overflow = True
            missing = []
            for rel in stage_files(stage):
                filename = "owned/build.json" if rel == "owned-verifier.json" else rel
                if not (original / filename).is_file():
                    missing.append(rel)
                    continue
                try:
                    raw = read(original / filename)
                    if rel == "owned-verifier.json":
                        # Keep the actual image binding, not the build driver's
                        # process environment or unneeded raw compiler requests.
                        build = exact_json(raw)
                        raw = (json.dumps({"status": build.get("status"),
                            "final_image": build.get("final_image"),
                            "full_build_receipt_sha256": sha(raw)}, sort_keys=True,
                            allow_nan=False) + "\n").encode()
                except ValueError:
                    missing.append(rel)
                    continue
                if not retain(dest / rel, raw):
                    missing.append(rel)
            error = status != 0 or timed_out or overflow or bool(missing)
            save(dest / "process.json", {"stage": stage, **line, "source_tree": tree,
                "argv": exe[1:], "returncode": status, "timed_out": timed_out,
                "deadline_seconds": LIMIT, "overflow": overflow, "missing": missing})
            failed |= error
    require(not failed, "at least one actual Release PQ qualifier did not produce complete evidence")


def roster(rows, name_key, status_key, expected, digest_keys):
    require(type(rows) is list and len(rows) == len(expected), "incomplete actual case roster")
    for row, (name, status) in zip(rows, expected, strict=True):
        require(type(row) is dict and row.get(name_key) == name and
                type(row.get(status_key)) is int and row[status_key] == status
                and all(valid_hash(row.get(k)) for k in digest_keys), "case identity or status differs")


def callback_transition(row, code):
    # A success marker alone does not establish the genuine final Rust output.
    require("transition_checkpoint" in row, "missing callback checkpoint comparison")
    transition = row["transition_checkpoint"]
    if code:
        require(transition is None, "callback produced a checkpoint on refusal")
    else:
        require(type(transition) is dict and set(transition) ==
                {"original", "native", "borrowed_snapshot_sha256"}
                and all(valid_hash(x) and x != "0" * 64 for x in transition.values())
                and transition["original"] == transition["native"],
                "callback checkpoint differs from the Rust owner")
    return transition


def validate_stage(root, stage, line, tree, lock):
    process = obj(root / "process.json")
    require(process.get("stage") == stage and all(process.get(k) == v and type(process[k]) is type(v)
            for k, v in line.items()) and process.get("source_tree") == tree
            and process.get("argv") == ["-I", "-S", "-B", script(stage), "--output"]
            and type(process.get("returncode")) is int and process["returncode"] == 0
            and process.get("timed_out") is False and process.get("overflow") is False
            and process.get("deadline_seconds") == LIMIT and process.get("missing") == [],
            "actual qualifier execution failed or has wrong lineage")
    actual = obj(root / "stdout.raw")
    require(actual.get("status") == "PASS" and actual.get("source_head") == line["head"]
            and read(root / "stderr.raw") == b"", "unexpected actual qualifier terminal stream")
    report = obj(root / "qualification.json")
    require(report.get("status") == "PASS" and report.get("source_state") == "committed-clean"
            and report.get("source_head") == line["head"] and report.get("source_tree") == tree,
            "wrong qualifier source provenance")
    original = report.get("locked_original" if stage == "callback" else "rust", {})
    require(original.get("rust_pin") == "1.95.0" and original.get("workspace_lock_sha256") == lock
            and valid_hash(original.get("original_binary_sha256"))
            and valid_hash(original.get("public_adapter_sha256"))
            and set(original.get("libraries", {})) == LIBRARIES
            and all(valid_hash(x) for x in original["libraries"].values()), "missing locked original Rust artifacts")
    commands = [exact_json(raw) for raw in read(root / "rust-build.stdout.jsonl").splitlines()]
    libs = {c.get("target", {}).get("name") for c in commands if c.get("reason") == "compiler-artifact"
            and any(p.endswith(".rlib") for p in c.get("filenames", []))}
    require(LIBRARIES <= libs and commands and commands[-1].get("reason") == "build-finished"
            and commands[-1].get("success") is True and bool(read(root / "rust-build.stderr.raw")),
            "missing real Cargo compiler event roster")
    require(set(report.get("backends", {})) == set(BACKENDS), "both actual native emitters required")
    hashes = {}
    for backend in BACKENDS:
        current = report["backends"][backend]
        if stage == "observation":
            require(report.get("release_authorized") is False and report.get("quorum_verified") is False
                    and report.get("secret_material_retained") is False
                    and report.get("qualification_only") is True
                    and current.get("valid_identities") == current.get("role_identity_refusals") == 8,
                    "incorrect single-signature scope")
            roster(current.get("observations"), "name", "status", CASES[stage],
                   ("message_sha256", "public_observation_sha256"))
            build = obj(root / "owned-verifier.json")
            image = report.get("owned_verifier_image", {})
            require(build.get("status") == "PASS" and build.get("final_image") == image
                    and valid_hash(image.get("sha256"))
                    and valid_hash(build.get("full_build_receipt_sha256")),
                    "missing actual owned verifier build")
            hashes[backend] = {"identity": current.get("role_identity_image_sha256"),
                               "transcript": current.get("transcript_image_sha256")}
        elif stage == "quorum":
            require(report.get("release_authorized") is False
                    and report.get("trusted_snapshot_is_current_proved") is False
                    and report.get("ephemeral_secret_input_or_output") is False
                    and current.get("original_owner_synthetic_accept_reached") is True,
                    "incorrect quorum scope")
            roster(current.get("differential"), "case", "status", CASES[stage], ("public_request_sha256",))
            roster(current.get("private_boundary"), "case", "status", PRIVATE, ("public_request_sha256",))
            hashes[backend] = {k: current.get(f"native_{k}_sha256") for k in ("quorum", "transcript")}
        else:
            require(report.get("production_authority") is False and report.get("native_same_call_token") is False
                    and report.get("test_only_composition") is True and report.get("native_shadow_checkpoint") is True,
                    "incorrect callback scope")
            rows = current.get("rows")
            roster(rows, "case", "native", tuple(row[:2] for row in CASES[stage]), ("public_fixture_sha256",))
            for row, (_, code, phase, subcode) in zip(rows, CASES[stage], strict=True):
                trace = row.get("native_phases")
                require(type(row.get("actual_original")) is int and row["actual_original"] == code
                        and type(trace) is list and trace and trace[-1] == [phase, subcode],
                        "callback stage or original outcome differs")
                transition = callback_transition(row, code)
                if backend == "selfhost":
                    counterpart = next(other for other in report["backends"]["direct"]["rows"]
                                       if other["case"] == row["case"])
                    require(transition == counterpart["transition_checkpoint"]
                            and row["public_fixture_sha256"] == counterpart["public_fixture_sha256"],
                            "callback emitters disagree on the exact public fixture or checkpoint")
            hashes[backend] = current.get("images", {})
            require(set(hashes[backend]) == CALLBACK_PHASES, "missing callback phase image")
        require(all(valid_hash(x) for x in hashes[backend].values()), "missing emitted machine identity")
        if stage != "observation":
            for kind, digest in hashes[backend].items():
                receipt = obj(root / f"{backend}-{kind}-native-build.json")
                claims = receipt.get("claims", {})
                require(receipt.get("artifact_sha256") == digest and receipt.get("ok") is True
                        and claims.get("fallback_used") is False
                        and claims.get("direct_machine_code") is True
                        and claims.get("self_hosted") is (backend == "selfhost")
                        and (backend != "selfhost" or (receipt.get("compiler_sha256") == PIN
                             and claims.get("python_emitter_used") is False)),
                        "unbound or fallback emitted machine")
    require(hashes["direct"].keys() == hashes["selfhost"].keys()
            and all(hashes["direct"][k] != hashes["selfhost"][k] for k in hashes["direct"]),
            "distinct real machine emitters required")


def validate(out):
    line = lineage()
    before = source(out / "source-before.json", line)
    after = source(out / "source-after.json", line)
    require(before == after, "full source changed during Release PQ qualification")
    bound = obj(out / "bootstrap.json")
    require(bound.get("status") == "PASS" and bound.get("compiler_sha256") == PIN
            and valid_hash(bound.get("raw_bootstrap_sha256")), "missing compiler bootstrap")
    lock = sha(read(ROOT / "trillionnium/Cargo.lock"))
    files = {}
    for name in ("source-before.json", "source-after.json", "bootstrap.json"):
        files[name] = sha(read(out / name))
    for stage in STAGES:
        validate_stage(out / stage, stage, line, before["tested_tree"], lock)
        for leaf in (*stage_files(stage), *RAW):
            name = stage + "/" + leaf
            files[name] = sha(read(out / name))
    actual = {p.relative_to(out).as_posix() for p in out.rglob("*")
              if p.is_symlink() or not p.is_dir()}
    report = {"schema": "trnm.hia.release-pq-hosted-evidence.v1", "status": "PASS",
              **line, "source_tree": before["tested_tree"], "case_counts_per_emitter":
              {k: len(v) for k, v in CASES.items()}, "files": files,
              "production_authority": False, "native_same_call_token": False}
    if "readback.json" in actual:
        require(obj(out / "readback.json") == report, "retained readback does not match actual evidence")
        actual.remove("readback.json")
    require(actual == set(files), "unexpected or missing bounded Release PQ evidence members")
    require(sum((out / name).stat().st_size for name in files) <= MAX_ARTIFACT,
            "total Release PQ evidence extent exceeded")
    return report


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("action", choices=("bootstrap", "run", "verify"))
    cli.add_argument("--output", required=True, type=Path)
    cli.add_argument("--work", type=Path)
    cli.add_argument("--bootstrap", type=Path)
    cli.add_argument("--github-env", type=Path)
    args = cli.parse_args()
    if args.action == "bootstrap":
        bootstrap(args.bootstrap, args.github_env, args.output)
    elif args.action == "run":
        run(args.work, args.output)
    else:
        try:
            report = validate(args.output)
        except (ValueError, OSError, TypeError, KeyError) as error:
            save(args.output / "readback.json", {"status": "FAIL", "error": str(error),
                                                  "production_authority": False})
            raise
        save(args.output / "readback.json", report)
        print(json.dumps({"status": "PASS", "source_head": report["head"],
                          "case_counts_per_emitter": report["case_counts_per_emitter"]},
                         sort_keys=True))


if __name__ == "__main__":
    main()
