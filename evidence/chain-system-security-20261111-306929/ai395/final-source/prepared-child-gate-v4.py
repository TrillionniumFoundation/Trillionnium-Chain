#!/usr/bin/env python3
"""Run evidence-child gates while retaining the original F parser refusal and its raw-only qualification."""
from __future__ import annotations
import argparse, datetime, hashlib, json, os, pathlib, re, subprocess, sys, time, traceback

REPO = pathlib.Path("/home/qq/chain-system-security-20261112-306929")
NATIVE = "bac6b7659bd7e2d633e25c2da0add60f6a10c7fb"
TOOLCHAIN = pathlib.Path("/home/qq/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu")
PROVIDER = pathlib.Path("/home/qq/chain-system-security-root-provider-20261112-306929/provider.env")
PROTECTED = ("trillionnium", "formal", "scripts/ci")
TASK_EVIDENCE = "evidence/chain-system-security-20261111-306929/"
CORPUS = "config/pon/pq-cross-branch-corpus-v1.json"

def require(condition, message):
    if not condition: raise ValueError(message)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("evidence-child",), required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--parent")
    parser.add_argument("--full-receipt", type=pathlib.Path)
    parser.add_argument("--full-qualification-receipt", type=pathlib.Path)
    parser.add_argument("--allow-change", action="append", default=[])
    args = parser.parse_args()
    require(re.fullmatch("[0-9a-f]{40}", args.head), "full immutable HEAD required")
    require(args.out.is_absolute(), "absolute output directory required")
    output = args.out.resolve()
    require(output != REPO.resolve() and REPO.resolve() not in output.parents, "output must be outside repository")
    require(args.parent and args.full_receipt and args.full_qualification_receipt and args.allow_change, "evidence child requires parent, original full receipt, derived qualification and explicit allowed changes")
    if args.parent: require(re.fullmatch("[0-9a-f]{40}", args.parent), "full immutable parent required")
    output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ)
    env.update(PATH=str(TOOLCHAIN / "bin") + ":" + env.get("PATH", "/usr/bin:/bin"),
               RUSTC=str(TOOLCHAIN / "bin/rustc"), LD_LIBRARY_PATH=str(TOOLCHAIN / "lib"),
               CARGO_HOME="/home/qq/.cargo", CARGO_TARGET_DIR=str(REPO / "trillionnium/target"),
               CARGO_BUILD_JOBS="1", RUST_TEST_THREADS="1", PYTHONPATH=str(REPO / "scripts/ci"))
    records, controls = [], {}
    def save(name, value):
        with (output / name).open("x") as stream:
            json.dump(value, stream, indent=2); stream.write("\n")
    def git(*argv):
        return subprocess.check_output(["git", "-C", str(REPO), *argv], env=env)
    def tree(ref):
        result = {}
        for item in git("ls-tree", "-r", "-z", ref, "--", *PROTECTED).split(b"\0"):
            if not item: continue
            header, path = item.split(b"\t", 1)
            mode, kind, oid = header.decode().split(" ")
            require(kind == "blob", "protected git entry must be a blob")
            name = path.decode("utf-8")
            require(name not in result, "duplicate protected path")
            result[name] = (mode, oid)
        return result
    def compare_protected():
        left, right = tree(NATIVE), tree(args.head)
        require(left.keys() == right.keys(), "protected path set changed since native source")
        ids = sorted({value[1] for value in left.values()} | {value[1] for value in right.values()})
        process = subprocess.run(["git", "-C", str(REPO), "cat-file", "--batch"],
                                 input=("\n".join(ids) + "\n").encode(), stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=env)
        require(process.returncode == 0, "cannot read protected Git blobs")
        raw, offset, blobs = process.stdout, 0, {}
        for expected in ids:
            end = raw.index(b"\n", offset)
            oid, kind, size = raw[offset:end].decode().split()
            size = int(size); offset = end + 1
            require(oid == expected and kind == "blob", "unexpected protected object")
            body = raw[offset:offset + size]; offset += size
            require(len(body) == size and raw[offset:offset + 1] == b"\n", "truncated protected blob")
            offset += 1; blobs[oid] = body
        require(offset == len(raw), "unexpected trailing protected object bytes")
        files = []
        for path in sorted(left):
            lm, lo = left[path]; rm, ro = right[path]
            require(lm == rm and blobs[lo] == blobs[ro], "protected bytes or mode changed: " + path)
            files.append({"path": path, "mode": lm, "native_blob": lo, "candidate_blob": ro,
                          "bytes": len(blobs[lo]), "sha256": sha(blobs[lo])})
        return {"native_source": NATIVE, "candidate": args.head, "protected_roots": list(PROTECTED),
                "comparison": "exact tracked path, Git mode and blob content comparison",
                "all_bytes_equal": True, "files": files, "unique_objects_read": len(ids)}
    def record(label, command, expected_controls=None):
        argv = ["python3", "scripts/ci/record_pq_native_command.py", "--kind", "head",
                "--candidate", args.head, "--tested", args.head, "--label", label,
                "--output", str(output / "records"), "--", *command]
        start = time.monotonic()
        with (output / (label + ".driver.log")).open("xb") as stream:
            completed = subprocess.run(argv, cwd=REPO, env=env, stdout=stream, stderr=subprocess.STDOUT)
        receipt_path = output / "records" / (label + ".json")
        receipt = json.loads(receipt_path.read_text()) if receipt_path.is_file() else None
        row = {"label": label, "recorder_argv": argv, "recorder_exit_code": completed.returncode,
               "elapsed_seconds": time.monotonic() - start, "receipt": str(receipt_path),
               "actual_status": receipt.get("status") if receipt else None,
               "actual_exit_code": receipt.get("exit_code") if receipt else None}
        if expected_controls is not None and receipt:
            log = output / "records" / receipt["log_file"]
            log_text = log.read_text(errors="replace")
            observed = [int(v) for v in re.findall(r"\bRan (\d+) tests?\b", log_text)]
            controls[label] = {"expected": expected_controls, "observed_counts": observed,
                               "count_matches": observed == [expected_controls],
                               "plain_ok_without_skips": log_text.rstrip().endswith("\nOK")}
            row["control_observation"] = controls[label]
        records.append(row); save(label + "-execution.json", row)
        print(json.dumps(row), flush=True)
        require(receipt is not None and receipt.get("before") == receipt.get("after")
                and receipt.get("before", {}).get("tested_commit") == args.head,
                "source recorder did not preserve a complete identity: " + label)
        return bool(completed.returncode == 0 and receipt.get("status") == "command_succeeded"
                    and (expected_controls is None or (controls[label]["count_matches"] and controls[label]["plain_ok_without_skips"])))
    try:
        require(git("rev-parse", "HEAD").decode().strip() == args.head, "checkout is not the supplied head")
        require(not git("status", "--porcelain=v1"), "source is not clean")
        provider_raw = PROVIDER.read_bytes()
        require(sha(provider_raw) == "6de317bdd1826065aefeae7335a552dfae7b87e421a8f1aa66d32aa31adab2ed", "provider environment changed")
        provider_values = dict(line.split("=", 1) for line in provider_raw.decode().splitlines())
        require(set(provider_values) == {"OPENSSL_DIR", "OPENSSL_STATIC", "TRNM_PQ_OPENSSL",
                "TRNM_PQ_OPENSSL_SHA256", "TRNM_PQ_OPENSSL_VERSION", "OPENSSL_CONF", "OPENSSL_MODULES"},
                "unexpected provider environment fields")
        env.update(provider_values)
        for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_INCREMENTAL", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
            require(env.get(key) is None, "unexpected compiler/profile override: " + key)
        protected = compare_protected(); save("protected-native-source-comparison.json", protected)
        child_review = None
        if args.mode == "evidence-child":
            subprocess.run(["git", "-C", str(REPO), "merge-base", "--is-ancestor", args.parent, args.head], env=env, check=True)
            allowed = []
            for path in args.allow_change:
                parsed = pathlib.PurePosixPath(path)
                require(not parsed.is_absolute() and ".." not in parsed.parts and path not in ("", ".", "/"),
                        "invalid allowed change path")
                require(path.startswith(TASK_EVIDENCE) or path == CORPUS, "allowed changes must be specified task evidence or corpus")
                allowed.append(path)
            fields = git("diff", "--no-renames", "--name-status", "-z", args.parent, args.head).split(b"\0")
            if fields and fields[-1] == b"": fields.pop()
            require(len(fields) % 2 == 0, "unexpected diff format")
            changes = []
            for status, raw_path in zip(fields[0::2], fields[1::2]):
                state, path = status.decode(), raw_path.decode("utf-8")
                require(state in ("A", "M"), "evidence child deletes or changes entry type: " + path)
                require(any(path.startswith(rule) if rule.endswith("/") else path == rule for rule in allowed),
                        "change outside explicit evidence child scope: " + path)
                changes.append({"status": state, "path": path})
            old_corpus = json.loads(git("show", args.parent + ":" + CORPUS))
            new_corpus = json.loads(git("show", args.head + ":" + CORPUS))
            require(isinstance(old_corpus, dict) and isinstance(new_corpus, dict), "corpus objects required")
            changing_keys = {"pinned_blobs", "required_paths"}
            require({k: v for k, v in old_corpus.items() if k not in changing_keys}
                    == {k: v for k, v in new_corpus.items() if k not in changing_keys},
                    "evidence child changed corpus policy or reader fields")
            old_pins, new_pins = old_corpus.get("pinned_blobs"), new_corpus.get("pinned_blobs")
            old_required, new_required = old_corpus.get("required_paths"), new_corpus.get("required_paths")
            require(isinstance(old_pins, dict) and isinstance(new_pins, dict)
                    and isinstance(old_required, list) and isinstance(new_required, list),
                    "corpus pin/path containers changed type")
            require(all(isinstance(p, str) for p in old_required + new_required)
                    and len(set(old_required)) == len(old_required)
                    and len(set(new_required)) == len(new_required), "invalid corpus required path set")
            require(set(old_pins).issubset(new_pins), "evidence child removed existing corpus pins")
            require(set(old_required).issubset(new_required), "evidence child removed required paths")
            actual_files = {row["path"]: row["status"] for row in changes if row["path"] != CORPUS}
            changed_pins = {path for path, blob in new_pins.items() if old_pins.get(path) != blob}
            added_required = set(new_required) - set(old_required)
            require(changed_pins.issubset(actual_files), "corpus changed pins outside actual allowed file changes")
            require(added_required.issubset(actual_files), "corpus added required paths outside actual allowed file changes")
            reviewed_pins = []
            for path in sorted(changed_pins | added_required | (set(actual_files) & set(new_pins))):
                require(path in actual_files and path in new_pins, "reviewed evidence path lacks an actual changed file/pin")
                blob = git("rev-parse", args.head + ":" + path).decode().strip()
                require(git("cat-file", "-t", blob).decode().strip() == "blob", "corpus pin is not a file blob")
                require(new_pins[path] == blob, "corpus pin differs from actual child Git blob: " + path)
                reviewed_pins.append({"path": path, "prior_pin": old_pins.get(path),
                                      "reviewed_child_blob": blob, "status": actual_files[path]})
            for path, state in actual_files.items():
                if state == "A":
                    require(path in new_pins and path in new_required, "new evidence file is not registered: " + path)
            corpus_review = {"parent": args.parent, "child": args.head,
                             "non_pin_and_required_fields_equal": True,
                             "existing_pins_preserved": True, "existing_required_paths_preserved": True,
                             "reviewed_actual_file_pins": reviewed_pins,
                             "added_required_paths": sorted(added_required),
                             "unrelated_prior_pins_changed": False}
            require(args.full_receipt.is_absolute() and args.full_qualification_receipt.is_absolute(),
                    "absolute original and derived receipt paths required")
            full_raw = args.full_receipt.read_bytes(); prior = json.loads(full_raw)
            qualification_raw = args.full_qualification_receipt.read_bytes()
            qualification = json.loads(qualification_raw)
            require(prior.get("schema") == "trnm-final-source-gates-v1" and prior.get("mode") == "full"
                    and prior.get("source") == args.parent and prior.get("all_gates_passed") is False
                    and prior.get("source_before_after_equal") is True and prior.get("python_controls_observed") == 65
                    and prior.get("controls", {}).get("authority-and-root-controls", {}).get("plain_ok_without_skips") is True
                    and prior.get("controls", {}).get("source-rejection-controls", {}).get("plain_ok_without_skips") is False,
                    "original F parser refusal is missing or relabelled")
            require(qualification.get("schema") == "trnm-final-source-gates-derived-qualification-v1"
                    and qualification.get("derivation_mode") == "raw-only-parser-correction"
                    and qualification.get("source") == args.parent
                    and qualification.get("tree") == prior.get("tree")
                    and qualification.get("original_summary_sha256") == sha(full_raw)
                    and qualification.get("original_summary_bytes") == len(full_raw)
                    and qualification.get("original_driver_exit_code") == 1
                    and qualification.get("original_all_gates_passed") is False
                    and qualification.get("original_parser_false_preserved") is True
                    and qualification.get("all_actual_commands_passed") is True
                    and qualification.get("actual_commands_verified") == 10
                    and qualification.get("python_controls_verified") == 108
                    and qualification.get("source_before_after_equal") is True
                    and qualification.get("protected_native_bytes_equal") is True
                    and qualification.get("original_artifacts_unchanged") is True
                    and qualification.get("new_repository_test_execution") is False
                    and qualification.get("native_tests_executed") is False
                    and qualification.get("clippy_executed") is False
                    and qualification.get("native_qualification_source") == NATIVE,
                    "derived F qualification is not bound to the preserved original observations")
            parent_tree = git("rev-parse", args.parent + "^{tree}").decode().strip()
            parent_identity = qualification.get("source_identity", {})
            require(parent_identity.get("schema") == "trnm-ci-source-v1"
                    and parent_identity.get("kind") == "head"
                    and parent_identity.get("candidate") == args.parent
                    and parent_identity.get("tested_commit") == args.parent
                    and parent_identity.get("tested_tree") == parent_tree == prior.get("tree")
                    and parent_identity.get("tracked_worktree_verified") is True,
                    "derived source identity is not the complete supplied parent Git commit/tree")
            original_root = args.full_receipt.parent.resolve()
            require(qualification.get("original_directory") == str(original_root), "original receipt directory mismatch")
            original_files = qualification.get("original_files")
            require(isinstance(original_files, list) and original_files, "original file bindings missing")
            file_map = {}
            for item in original_files:
                relative = pathlib.PurePosixPath(item["relative"])
                require(not relative.is_absolute() and ".." not in relative.parts
                        and item["relative"] not in file_map, "invalid or duplicate original artifact path")
                artifact = original_root / relative
                require(artifact.is_file() and not artifact.is_symlink()
                        and artifact.stat().st_size <= 4194304, "unbounded or missing original artifact")
                original_raw = artifact.read_bytes()
                require(len(original_raw) == item["bytes"] and sha(original_raw) == item["sha256"],
                        "original artifact differs from derived qualification: " + item["relative"])
                file_map[item["relative"]] = item
            require(file_map.get("summary.json", {}).get("sha256") == sha(full_raw),
                    "derived file map lacks original summary")
            bindings = qualification.get("command_bindings")
            require(isinstance(bindings, list) and len(bindings) == 10
                    and [b["label"] for b in bindings] == [c["label"] for c in prior["commands"]],
                    "derived command inventory differs from original")
            for binding, original_command in zip(bindings, prior["commands"]):
                require(binding["exit_code"] == binding["recorder_exit_code"]
                        == original_command["actual_exit_code"] == original_command["recorder_exit_code"] == 0,
                        "derived receipt masks an actual command failure")
                require(file_map[binding["receipt_relative"]]["sha256"] == binding["receipt_sha256"]
                        and file_map[binding["log_relative"]]["sha256"] == binding["log_sha256"]
                        and file_map[binding["log_relative"]]["bytes"] == binding["log_bytes"],
                        "derived command/log binding differs from complete original manifest")
                require(binding["receipt_relative"] == "records/" + binding["label"] + ".json"
                        and original_command["receipt"] == str(original_root / binding["receipt_relative"]),
                        "command receipt path does not match the original command")
                receipt = json.loads((original_root / binding["receipt_relative"]).read_bytes())
                require(receipt["argv"] == binding["argv"] and receipt["exit_code"] == 0
                        and receipt["status"] == "command_succeeded"
                        and receipt["before"] == receipt["after"] == parent_identity,
                        "actual command receipt does not preserve the qualified F source")
                require(receipt["log_file"] == binding["label"] + ".log"
                        and "records/" + receipt["log_file"] == binding["log_relative"]
                        and receipt["log_sha256"] == binding["log_sha256"]
                        and receipt["log_bytes"] == binding["log_bytes"],
                        "actual receipt does not authenticate the bound raw command log")
            suites = qualification.get("suite_observations", {})
            require(set(suites) == {"authority-and-root-controls", "source-rejection-controls"}
                    and suites["authority-and-root-controls"]["observed_method_count"] == 65
                    and suites["source-rejection-controls"]["observed_method_count"] == 43
                    and all(item["exact_source_ast_inventory_equal"] is True
                            and item["plain_ok_without_skips_failures_or_errors"] is True for item in suites.values()),
                    "derived exact 65+43 method inventories are not qualified")
            child_review = {"parent": args.parent, "child": args.head, "allowed_changes": allowed,
                            "actual_changes": changes, "parent_full_receipt": str(args.full_receipt),
                            "parent_full_receipt_sha256": sha(full_raw),
                            "parent_full_qualification_receipt": str(args.full_qualification_receipt),
                            "parent_full_qualification_receipt_sha256": sha(qualification_raw),
                            "original_parent_driver_exit_code": 1, "original_parent_all_gates_passed": False,
                            "derived_parent_actual_commands_verified": 10, "derived_parent_python_controls_verified": 108,
                            "parent_controls_are_not_relabelled_as_child_execution": True, "corpus_delta": corpus_review}
            save("evidence-child-scope.json", child_review)
        sys.path.insert(0, str(REPO / "scripts/ci"))
        from verify_ci_source import verify
        before = verify("head", args.head, root=REPO); save("source-before.json", before)
        save("configuration.json", {"mode": args.mode, "source": args.head,
             "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
             "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
             "native_qualification_source": NATIVE, "native_execution_requested": False,
             "parent": args.parent, "allow_change": args.allow_change,
             "environment": {key: env.get(key) for key in ("PATH", "RUSTC", "LD_LIBRARY_PATH",
                "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "RUST_TEST_THREADS",
                "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_INCREMENTAL", "RUSTC_WRAPPER",
                "RUSTC_WORKSPACE_WRAPPER", *sorted(provider_values))},
             "provider_environment_sha256": sha(provider_raw), "status": "HOLD"})
        commands = [("preflight", ["bash", "scripts/project-preflight.sh"], None)]
        if args.mode == "full":
            commands += [
                ("authority-current", ["python3", "scripts/ci/pq_authority_effect_register.py"], None),
                ("root-current", ["python3", "scripts/ci/pq_root_dependency_register.py"], None),
                ("corpus-current", ["python3", "scripts/ci/check_pq_research_integration.py"], None),
                ("authority-and-root-controls", ["python3", "-m", "unittest", "test_pq_authority_effect_register",
                 "test_pq_root_dependency_register", "test_run_pq_root_witness_v5", "-v"], 65),
                ("source-rejection-controls", ["python3", "scripts/ci/test_ci_source_integrity.py"], 43),
                ("repository-links", ["python3", "scripts/ci/check_repository.py"], None),
                ("cargo-format", [str(TOOLCHAIN / "bin/cargo"), "fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"], None),
                ("locked-default-graph", [str(TOOLCHAIN / "bin/cargo"), "metadata", "--locked", "--manifest-path", "trillionnium/Cargo.toml", "--format-version", "1"], None),
                ("locked-all-features-graph", [str(TOOLCHAIN / "bin/cargo"), "metadata", "--locked", "--manifest-path", "trillionnium/Cargo.toml", "--all-features", "--format-version", "1"], None)]
        else:
            commands += [("corpus-current", ["python3", "scripts/ci/check_pq_research_integration.py"], None),
                         ("repository-links", ["python3", "scripts/ci/check_repository.py"], None)]
        outcomes = [record(label, command, count) for label, command, count in commands]
        after = verify("head", args.head, root=REPO); save("source-after.json", after)
        require(before == after and not git("status", "--porcelain=v1"), "source changed during gates")
        require(PROVIDER.read_bytes() == provider_raw, "provider environment changed during gates")
        require(tree(args.head) == tree(NATIVE), "protected source identity changed")
        observed = sum(row["expected"] for row in controls.values() if row["count_matches"] and row["plain_ok_without_skips"])
        report = {"schema": "trnm-final-source-gates-v1", "mode": args.mode, "source": args.head,
                  "tree": after["tested_tree"], "native_qualification_source": NATIVE,
                  "native_tests_executed": False, "clippy_executed": False,
                  "source_before_after_equal": before == after, "protected_native_bytes_equal": True,
                  "all_gates_passed": all(outcomes), "commands": records, "controls": controls,
                  "python_controls_observed": observed, "parent": args.parent,
                  "parent_108_controls_not_claimed_on_child": args.mode == "evidence-child",
                  "evidence_child_scope": child_review, "status": "HOLD",
                  "production_activation": False}
        save("summary.json", report); print(json.dumps(report), flush=True)
        return 0 if all(outcomes) else 1
    except BaseException as error:
        failure = {"schema": "trnm-final-source-gates-failure-v1", "mode": args.mode, "source": args.head,
                   "error_type": type(error).__name__, "error": str(error), "traceback": traceback.format_exc(),
                   "completed_commands": records, "native_tests_executed": False, "status": "HOLD"}
        save("failure.json", failure)
        raise

if __name__ == "__main__":
    raise SystemExit(main())
