#!/usr/bin/python3
"""Run the unchanged external-evidence-contract lane on an exact existing checkout.

Preparation does not execute this driver or any lane. Invoke only after the
operator supplies and approves the exact HEAD/tree. This driver performs no
source fetch, bundle import, checkout or environment installation. Its result
is local Linux evidence, not hosted CI qualification or publication proof.
"""
import argparse, datetime, hashlib, json, os, pathlib, re, signal, subprocess, sys, time

BASE = pathlib.Path("/home/qian-qi/chain-final-consolidation-20261114-root")
SOURCE = BASE / "source"
CONFORMANCE = BASE / "final-python312-env/bin/python"
RUNTIME = BASE / "final-runtime-release-env/bin/python"
TOOLCHAIN = pathlib.Path("/home/qian-qi/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin")
WORKFLOW_PATH = ".github/workflows/trnm-required-baseline.yml"
WORKFLOW_SHA256 = "a93a36bf4a93f078b162403825ea45d92dc4a34989f678125bdbc928662da844"
WORKFLOW_JOB_TIMEOUT_MINUTES = 45
LANE_ARGV = ["bash", "scripts/ci/ci_job.sh", "external-evidence-contract"]
REFERENCE_SELECTORS_TO_UNSET = (
    "TRNM_NATIVE_WORK", "TRNM_NATIVE_EXECUTOR", "TRNM_NATIVE_SESSION",
    "TRNM_EXECUTION_WORKERS", "TRNM_PON_EVALUATION_POLICY",
)
DECLARED_SOURCE_TREES = {
    "1a512c613951af5640dac06cc663392d08927e00": "be23902744141ca769d1b11b3a0f50d8b62a4ed3",
    "242906bae4f281c738c60adbd2c053d2ded1eae5": "160cc493ab4cfb7f3f8c26b2d1621691a0c49502",
    "30b85c34d1be404dcccd9f415286bb43b00f64ea": "4ee1a9d265f09871b0f167d2a5be77ca4b9839c0",
    "3c63c8368187de895e1dc0df8bbc105c6f39f842": "54d2f12c0d783f827d43bc626489f58ab75d7c31",
    "50e158640d8278ca94dbecb6539dab96c6a9fb84": "d61a69d3433db127019924d269bf25ded3aecf60",
    "5d59b9540268914794a62e8fa237caf999499314": "30ee65c0752693f4eecc90f924972279f00c0c73",
    "6cdbf9551aae1754e489773bac29bc0598e20a9b": "521ea862cd063904aaf3acb949208ac87dc0d762",
    "9fedf7ecbbe07177069c030592b4e03dcffebb81": "af52e79d69de2224fa709309704ba6a971453579",
    "b34561d1ade376512a34fed3fd78938ed2431ecd": "5a91b1ecc696b8a0c468ee8ba2a3dd0fe9e8d3d8",
    "c2b1ca2503aeca35873d20d1b188689369edc752": "5df72527b22520b27f5ad858bbca98456c7ad9cf",
    "dbb1c989342639c4c04366a0d12bc3ecb4760e04": "a38495fe234c4ae71aeae3c570d5d91acf847fee",
    "ed4d95c3e558ad28b5f3132152704bdf77df5f49": "a19ecaa4745236753d89b7e6be8de4a9f2156954",
    "faf144086067f9b0a301a2b46760164d80fec04e": "cd3643aec9b12dab647f07b8c561e81eeae1493c",
    "fbe72b70f096d04290b8ef14ac95a4b32cdaf4fb": "31b4df1df65ef70d92936091271d21e1d90c1142"
}
REQUIREMENTS = {
    "formal/pon-nakamoto-v1/requirements.txt": "ae117e781e1420b46bfc2c4b9a550da3fe3f98ff9cbe868192036d34c342aed5",
    "scripts/ci/runtime-release-requirements.txt": "2acf07322b544b1d2318642b59877dd035bc7808590619f3cf23e75eedd0bbe7",
}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def sha_file(path):
    value = hashlib.sha256()
    with pathlib.Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()

def main():
    if sys.flags.optimize:
        raise RuntimeError("optimized interpreter is not allowed")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--evidence-dir", required=True)
    args = parser.parse_args()
    for value in (args.head, args.tree):
        require(re.fullmatch(r"[0-9a-f]{40}", value) is not None, "exact SHA required")
    require(sys.platform == "linux", "this driver is for the prepared local Linux environment")
    require(os.getuid() != 0, "do not run as root")
    require(os.environ.get("GITHUB_ACTIONS", "").lower() not in ("true", "1"),
            "this is a local Linux run, not a hosted runner")
    require(SOURCE.resolve(strict=True) == SOURCE, "canonical source directory required")
    evidence = pathlib.Path(args.evidence_dir)
    require(evidence.is_absolute() and evidence.parent == BASE
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", evidence.name),
            "evidence must be a new direct child of the authorized root")
    evidence.mkdir(mode=0o700, exist_ok=False)
    receipts = evidence / "ci-observations"
    temporary = evidence / "tmp"
    receipts.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    env = os.environ.copy()
    inherited_reference_selector_names = sorted(name for name in REFERENCE_SELECTORS_TO_UNSET if name in env)
    for name in REFERENCE_SELECTORS_TO_UNSET:
        env.pop(name, None)
    require(not any(name in env for name in REFERENCE_SELECTORS_TO_UNSET), "reference selectors must be unset")
    env.update(
        PATH=str(CONFORMANCE.parent) + ":" + str(TOOLCHAIN)
             + ":/home/qian-qi/.cargo/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        CI="true", TRNM_EXPECTED_SOURCE_SHA=args.head,
        TRNM_RUNTIME_RELEASE_PYTHON=str(RUNTIME),
        TRNM_CI_RECEIPT_DIR=str(receipts), TMPDIR=str(temporary),
        CARGO_TARGET_DIR=str(BASE / "target"), CARGO_BUILD_JOBS="2",
        CARGO_INCREMENTAL="0", RUST_TEST_THREADS="1", CARGO_TERM_COLOR="never",
        PYTHONDONTWRITEBYTECODE="1", PYTHONOPTIMIZE="0",
        GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_TERMINAL_PROMPT="0",
    )
    steps, errors = [], []
    result = {
        "schema": "trnm-final-linux-external-evidence-existing-source-v2",
        "head": args.head, "tree": args.tree, "expected_start_head": args.head,
        "lane": "external-evidence-contract", "lane_argv": LANE_ARGV,
        "budget": {"workflow_path": WORKFLOW_PATH, "workflow_sha256": WORKFLOW_SHA256,
                   "workflow_job_timeout_minutes": WORKFLOW_JOB_TIMEOUT_MINUTES,
                   "workflow_step_timeout_seconds": None,
                   "local_lane_timeout_seconds": WORKFLOW_JOB_TIMEOUT_MINUTES * 60,
                   "basis": "current external job has a 45-minute job limit; this local command uses the same numerical ceiling",
                   "hosted_job_walltime_equivalence_claimed": False},
        "driver": {"path": str(pathlib.Path(__file__).resolve(strict=True)),
                   "sha256": sha_file(pathlib.Path(__file__).resolve(strict=True))},
        "invocation": {"argv": list(sys.argv), "executable": sys.executable,
                       "optimize": sys.flags.optimize},
        "source": str(SOURCE), "status": "running", "steps": steps, "errors": errors,
        "environment": {name: env[name] for name in (
            "PATH", "CI", "TRNM_EXPECTED_SOURCE_SHA", "TRNM_RUNTIME_RELEASE_PYTHON", "TRNM_CI_RECEIPT_DIR", "TMPDIR",
            "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "RUST_TEST_THREADS",
            "CARGO_TERM_COLOR", "PYTHONDONTWRITEBYTECODE", "PYTHONOPTIMIZE",
            "GIT_NO_REPLACE_OBJECTS", "GIT_NO_LAZY_FETCH", "GIT_TERMINAL_PROMPT")},
        "hosted_ci_qualification": False, "host_provisioning_performed": False,
        "remote_mutations_performed": False,
        "local_bundle_source": False, "remote_publication_verified": False,
        "source_acquisition": "preexisting-exact-checkout",
        "source_fetch_or_installation_performed_by_driver": False,
        "environment_installation_performed": False,
        "reference_environment": {
            "selectors_unset": list(REFERENCE_SELECTORS_TO_UNSET),
            "inherited_selector_names_cleared": inherited_reference_selector_names,
            "inherited_selector_values_retained": False,
            "original_test_commands_unchanged": True,
        },
        "repository_truth_executed_by_this_driver": False,
        "historical_objects_prechecked": False,
        "lane_prepare_fetched_nothing_verified": False,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    def save():
        (evidence / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    save()
    def run(label, argv, timeout=300, required=True):
        paths = {channel: evidence / (label + "." + channel) for channel in ("stdout", "stderr")}
        start = time.monotonic()
        with paths["stdout"].open("xb") as stdout, paths["stderr"].open("xb") as stderr:
            try:
                process = subprocess.Popen(argv, cwd=SOURCE, env=env, stdin=subprocess.DEVNULL,
                    stdout=stdout, stderr=stderr, start_new_session=True)
                try:
                    code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        stderr.write(b"Owned command did not terminate after timeout.\n")
                    code = 124
            except OSError as error:
                stderr.write((repr(error) + "\n").encode())
                code = 127
        row = {"label": label, "argv": argv, "cwd": str(SOURCE), "exit": code,
               "timeout_seconds": timeout, "elapsed_seconds": round(time.monotonic() - start, 3)}
        for channel, path in paths.items():
            row[channel + "_path"] = str(path)
            row[channel + "_bytes"] = path.stat().st_size
            row[channel + "_sha256"] = sha_file(path)
        steps.append(row)
        save()
        print(json.dumps({"label": label, "exit": code}), flush=True)
        if required:
            require(code == 0, "failed stage: " + label)
        return row, paths["stdout"].read_bytes()
    def git(label, *arguments, required=True):
        return run(label, ["git", "--no-replace-objects", *arguments], required=required)
    before_verified = False
    lane_exit = None
    try:
        for relative, expected in REQUIREMENTS.items():
            require(sha_file(SOURCE / relative) == expected, "prepared Python requirements changed: " + relative)
        _, raw = git("initial-head", "rev-parse", "HEAD")
        require(raw.decode().strip() == args.head, "source HEAD must already equal the explicit candidate")
        _, raw = git("initial-tree", "rev-parse", "HEAD^{tree}")
        require(raw.decode().strip() == args.tree, "source tree must already equal the explicit tree")
        _, raw = git("initial-status", "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none")
        require(not raw.strip(), "source must be clean before this local lane")
        require(sha_file(SOURCE / WORKFLOW_PATH) == WORKFLOW_SHA256,
                "workflow changed; review the actual external-job budget again")
        run("preflight-audit", ["bash", "scripts/project-preflight.sh", "--audit"])
        for relative, expected in REQUIREMENTS.items():
            require(sha_file(SOURCE / relative) == expected, "final requirements need a separately reviewed environment")
        _, raw = run("rust-version", [str(TOOLCHAIN / "rustc"), "--version"])
        require(raw.decode().startswith("rustc 1.95.0 "), "Rust version differs")
        _, raw = run("cargo-version", [str(TOOLCHAIN / "cargo"), "--version"])
        require(raw.decode().startswith("cargo 1.95.0 "), "Cargo version differs")
        for label, python, wanted in (
            ("conformance", CONFORMANCE, {"numpy": "1.26.4", "cryptography": "50.0.2"}),
            ("runtime", RUNTIME, {"packaging": "26.3"}),
        ):
            program = ("import importlib.metadata as m,json,sys; expected=" + repr(wanted)
                       + "; actual={k:m.version(k) for k in expected}; "
                       + "assert actual==expected and sys.version_info[:2]==(3,12); "
                       + "print(json.dumps({'actual':actual,'python':sys.version,'executable':sys.executable}))")
            run(label + "-environment", [str(python), "-B", "-c", program])
        _, raw = run("verify-source-before", [str(CONFORMANCE), "-B", "scripts/ci/verify_ci_source.py",
            "--kind", "head", "--expected-head", args.head, "--output", str(evidence / "source-before.json")])
        identity = json.loads(raw)
        require(identity["tested_commit"] == args.head and identity["tested_tree"] == args.tree
                and identity["tracked_worktree_verified"] is True, "source identity differs")
        before_verified = True
        object_program = (
            "import json,pathlib,subprocess,sys; "
            "sys.path.insert(0,str(pathlib.Path('scripts/ci').resolve())); "
            "from prepare_evidence_sources import declarations; "
            "root=pathlib.Path.cwd(); expected=json.loads(sys.argv[2]); "
            "values=declarations(root,source=sys.argv[1]); "
            "assert values==expected and declarations(root)==expected; "
            "\nfor commit,tree in sorted(values.items()):\n"
            " subprocess.run(['git','--no-replace-objects','cat-file','-e',commit+'^{commit}'],cwd=root,check=True)\n"
            " actual=subprocess.check_output(['git','--no-replace-objects','rev-parse',commit+'^{tree}'],cwd=root,text=True).strip()\n"
            " assert actual==tree\n"
            " subprocess.run(['git','--no-replace-objects','cat-file','-e',tree+'^{tree}'],cwd=root,check=True)\n"
            "print(json.dumps({'verified_object_trees':values,'fetch_attempted':False},sort_keys=True))"
        )
        _, raw = run("verify-required-evidence-objects",
                     [str(CONFORMANCE), "-B", "-c", object_program, args.head,
                      json.dumps(DECLARED_SOURCE_TREES, sort_keys=True)])
        object_check = json.loads(raw)
        require(object_check == {"verified_object_trees": DECLARED_SOURCE_TREES,
                                 "fetch_attempted": False}, "historical object precheck differs")
        result["historical_objects_prechecked"] = True
        save()
        lane, raw = run("external-evidence-contract", LANE_ARGV,
                       timeout=WORKFLOW_JOB_TIMEOUT_MINUTES * 60, required=False)
        lane_exit = lane["exit"]
        # The unchanged first lane command emits its complete prepare() receipt.
        # Missing objects were refused above; record its actual fetch result too.
        preparation = json.loads(raw.splitlines()[0]) if raw.splitlines() else None
        require(preparation == {"verified_object_trees": DECLARED_SOURCE_TREES, "fetched": [],
                                "branch_refs_changed": False, "acceptance_granted": False},
                "original lane did not confirm the pre-existing declared objects")
        result["lane_prepare_fetched_nothing_verified"] = True
        require(lane_exit == 0, "external-evidence-contract failed or timed out")
    except Exception as error:
        errors.append(type(error).__name__ + ": " + str(error))
    finally:
        after_valid = False
        try:
            row, raw = run("verify-source-after", [str(CONFORMANCE), "-B", "scripts/ci/verify_ci_source.py",
                "--kind", "head", "--expected-head", args.head, "--output", str(evidence / "source-after.json")],
                required=False)
            if row["exit"] == 0 and before_verified:
                after = json.loads(raw)
                before = json.loads((evidence / "source-before.json").read_bytes())
                require(after == before, "full source before/after differs")
                after_valid = True
            else:
                errors.append("final source verification did not confirm the tested source")
        except Exception as error:
            errors.append("post-run verification: " + repr(error))
        result["lane_exit"] = lane_exit
        result["source_before_after_verified"] = after_valid
        result["status"] = "passed" if not errors and lane_exit == 0 and after_valid else "failed"
        result["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()
    print(json.dumps({"status": result["status"], "head": args.head, "tree": args.tree,
                      "summary": str(evidence / "summary.json"),
                      "summary_sha256": sha_file(evidence / "summary.json")}), flush=True)
    return 0 if result["status"] == "passed" else 1

if __name__ == "__main__":
    sys.exit(main())
