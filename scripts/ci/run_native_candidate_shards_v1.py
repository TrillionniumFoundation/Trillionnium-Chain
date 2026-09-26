#!/usr/bin/env python3
"""Run complete candidate libtest inventories in source-bound, bounded shards."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import time
from typing import Iterable

PACKAGE = "trnm-native-execution-v0"
FEATURES = "test-fixtures,incremental-epoch-candidate"
BRIDGE = "later_epoch_checkpoint_bridge::tests::"
PRE_HANDOFF = BRIDGE + "later_pre_handoff_"
SCHEMA7 = "durable::incremental_owner_v1::epoch_candidate_v1::commit::tests::schema7_"
POCO_SIGKILL = "poco_checkpoint::native_authorization_tests::epoch_sigkill_commit_boundaries_preserve_exact_prepared_chain"
SHARD_NAMES = ("general", "historical-install", "historical-replay", "historical-receiver", "later-pre-handoff", "later-bridge", "schema7", "poco-sigkill")
REQUIRED_SIGKILL_DRIVERS = {
    BRIDGE + "historical_replay_continuation_sigkill_six_cuts_preserve_exact_c33",
    BRIDGE + "historical_replay_install_sigkill_cuts_recover_exact_nonempty_base",
    BRIDGE + "later_descendant_c22_sigkill_commit_cuts_recover_exact_p_and_proof",
    PRE_HANDOFF + "sigkill_commit_and_attach_cuts_preserve_original_evidence",
}


NODE_EPOCH_PREFIX = "epoch_runtime_candidate_v1::tests::"
NODE_CASE_DEADLINES = {
    NODE_EPOCH_PREFIX + "actual_epoch_successor_activation_preserves_owners_and_initial_ack_v9": 600,
    NODE_EPOCH_PREFIX + "actual_epoch_successor_activation_after_write_callback_blocks_ack_v9": 600,
    # These two cases deliberately execute the complete prior epoch before
    # exercising the first block / first finality of the successor epoch.
    # Their CI process budget is not a protocol or performance SLO; keep the
    # stage-level V8 and other epoch cases on the default 300-second budget.
    NODE_EPOCH_PREFIX + "actual_successor_first_application_persists_executes_and_votes_v10": 600,
    NODE_EPOCH_PREFIX + "actual_successor_core_finalizes_and_applies_first_new_v11": 600,
}
# V11 executes a complete prior epoch and successor continuation. Keep the
# unchanged 600-second process deadline, but qualify that product path with the
# optimized profile used for shipped Rust code. All other node-epoch regressions
# retain debug overflow/assertion coverage, and the runner binds both binaries.
NODE_RELEASE_CASES = {
    NODE_EPOCH_PREFIX + "actual_successor_core_finalizes_and_applies_first_new_v11",
}
NODE_REQUIRED_DRIVERS = {
    *NODE_CASE_DEADLINES,
    NODE_EPOCH_PREFIX + "actual_epoch_handoff_joint_attachment_and_exact_retry_v8",
    NODE_EPOCH_PREFIX + "actual_successor_first_application_persists_executes_and_votes_v10",
    NODE_EPOCH_PREFIX + "actual_epoch_runtime_activation_releases_timer_then_persisted_timeout_once",
    NODE_EPOCH_PREFIX + "actual_epoch_first_core_finalization_applies_three_real_native_executions_v2",
    NODE_EPOCH_PREFIX + "actual_epoch_seals_apply_original_fronts_then_commit_unattached_pre_handoff_v5",
}
SAFETY_REQUIRED_DRIVERS = {
    "journal10_sigkill_initialization_cuts_never_release_an_owner",
    "journal10_sigkill_post_initial_cuts_recover_exact_independently_pinned_revision",
    "journal11_six_sigkill_cuts_keep_original_provenance_and_exact_head",
    "journal12::journal12_six_sigkill_cuts_keep_actual_source_and_prefix",
}
SUITES = {
    "native": (PACKAGE, FEATURES, REQUIRED_SIGKILL_DRIVERS),
    "node-epoch": ("trnm-poco-node", "epoch-runtime-test-fixtures", NODE_REQUIRED_DRIVERS),
    "safety-epoch": ("trnm-consensus-safety-store", "--all-features", SAFETY_REQUIRED_DRIVERS),
}


class ShardError(RuntimeError):
    pass



def validate_ignored_inventory(ignored: set[str], inventory: list[str]) -> None:
    """Admit crash subprocesses by role instead of freezing their exact names.

    Parent SIGKILL/recovery tests are the behavioral authority: adding another
    dedicated child must not require editing this CI runner. A newly ignored
    ordinary regression is still rejected because its name is not a crash-child
    entrypoint.
    """
    available = set(inventory)
    if not ignored.issubset(available):
        raise ShardError("ignored inventory contains tests absent from the complete inventory")
    invalid = sorted(
        name
        for name in ignored
        if not (
            (leaf := name.rsplit("::", 1)[-1]).endswith("_child")
            and ("sigkill" in leaf or "crash" in leaf)
        )
    )
    if invalid:
        raise ShardError(
            "ignored inventory contains non-dedicated crash tests: " + ", ".join(invalid)
        )

def parse_test_inventory(output: str, *, allow_empty: bool = False) -> list[str]:
    names = [line.strip()[:-6] for line in output.splitlines() if line.strip().endswith(": test")]
    if (not names and not allow_empty) or any(not name for name in names) or len(names) != len(set(names)):
        raise ShardError("empty or duplicate native test inventory")
    return sorted(names)


def classify_test(name: str) -> str:
    if name == POCO_SIGKILL:
        return "poco-sigkill"
    if name.startswith(SCHEMA7):
        return "schema7"
    for suffix in ("install", "replay", "receiver"):
        if name.startswith(BRIDGE + "historical_" + suffix):
            return "historical-" + suffix
    if name.startswith(PRE_HANDOFF):
        return "later-pre-handoff"
    return "later-bridge" if name.startswith(BRIDGE) else "general"


def partition_inventory(names: Iterable[str], suite: str = "native") -> dict[str, list[str]]:
    names = sorted(names)
    if suite in ("node-epoch", "safety-epoch"):
        result = {"general": []} if suite == "node-epoch" else {}
        for name in names:
            if suite == "safety-epoch" or name.startswith(NODE_EPOCH_PREFIX):
                key = "epoch-" + hashlib.sha256(name.encode()).hexdigest()[:16]
                if key in result:
                    raise ShardError("duplicate node epoch shard identity")
                result[key] = [name]
            else:
                result["general"].append(name)
    else:
        result = {shard: [] for shard in SHARD_NAMES}
        for name in names:
            result[classify_test(name)].append(name)
    if any(not values for values in result.values()):
        raise ShardError("empty admitted shard")
    flattened = [name for values in result.values() for name in values]
    if sorted(flattened) != names or len(flattened) != len(set(flattened)):
        raise ShardError("native inventory is omitted or duplicated")
    return result


def shard_deadline(suite: str, names: list[str], default: int) -> int:
    if suite == "node-epoch" and len(names) == 1:
        return NODE_CASE_DEADLINES.get(names[0], default)
    return default


def final_test_result(output: str) -> str:
    summaries = [line.strip() for line in output.splitlines() if line.strip().startswith("test result:")]
    if not summaries:
        raise ShardError("native shard produced no top-level test result")
    # SIGKILL drivers may run this same binary as children. Only the final
    # parent summary may account for the complete filtered inventory.
    return summaries[-1]


def parse_test_summary(line: str) -> dict[str, int]:
    match = re.fullmatch(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in [0-9.]+s", line)
    if not match:
        raise ShardError("missing or malformed successful parent summary")
    return dict(zip(("passed", "failed", "ignored", "measured", "filtered"), map(int, match.groups())))


def validate_summary(counts: dict[str, int], *, planned: int, ignored: int, total: int) -> None:
    expected = {"passed": planned - ignored, "failed": 0, "ignored": ignored, "measured": 0, "filtered": total - planned}
    if counts != expected:
        raise ShardError(f"parent summary differs from inventory: {counts}, expected {expected}")


def find_executable(lines: Iterable[str], workspace: Path, suite: str = "native") -> Path:
    candidates = []
    package = SUITES[suite][0]
    target_name = "epoch_journal_v2" if suite == "safety-epoch" else package.replace("-", "_")
    target_kind = "test" if suite == "safety-epoch" else "lib"
    relative_source = "tests/epoch_journal_v2.rs" if suite == "safety-epoch" else "src/lib.rs"
    expected_source = (workspace / "crates" / package / relative_source).resolve()
    for line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict) or item.get("reason") != "compiler-artifact":
            continue
        target = item.get("target", {})
        if (target.get("name") == target_name
                and target.get("kind") == [target_kind]
                and item.get("profile", {}).get("test") is True
                and Path(target.get("src_path", "")).resolve() == expected_source
                and item.get("executable")):
            candidates.append(Path(item["executable"]).resolve())
    if len(candidates) != 1:
        raise ShardError(f"expected one native libtest executable, found {candidates}")
    return candidates[0]


def command_for_shard(executable: Path, shard: str, names: dict[str, list[str]], suite: str = "native") -> list[str]:
    if suite != "native" and shard != "general":
        return [str(executable), names[shard][0], "--exact", "--nocapture", "--test-threads=2"]
    filters = {"historical-install": BRIDGE + "historical_install", "historical-replay": BRIDGE + "historical_replay", "historical-receiver": BRIDGE + "historical_receiver", "later-pre-handoff": PRE_HANDOFF, "later-bridge": BRIDGE, "schema7": SCHEMA7, "poco-sigkill": POCO_SIGKILL}
    command = [str(executable)] + ([filters[shard]] if shard != "general" else [])
    for other, values in names.items():
        if other != shard:
            for name in values:
                command.extend(["--skip", name])
    return command + ["--nocapture", "--test-threads=2"]


def run_bounded(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> tuple[str, int]:
    process = subprocess.Popen(command, cwd=cwd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        output, _ = process.communicate(timeout=timeout)
        return output, process.returncode
    except subprocess.TimeoutExpired as error:
        for sig, grace in ((signal.SIGTERM, 5), (signal.SIGKILL, 2)):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass
            try:
                output, _ = process.communicate(timeout=grace)
                # Drained output proves nothing about descendants that closed
                # their pipes. Kill the original group even if its leader has
                # already exited after TERM.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                return output + "\nTIMEOUT\n", 124
            except subprocess.TimeoutExpired as pending:
                error = pending
        # Even a detached pipe holder must not remove the runner's deadline.
        if process.stdout is not None:
            process.stdout.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        partial = error.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", errors="replace")
        return partial + "\nTIMEOUT: output drain incomplete\n", 124


def git_output(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True, timeout=30).strip()


def clean_source(root: Path) -> tuple[str, str]:
    source = git_output(root, "rev-parse", "HEAD")
    tree = git_output(root, "rev-parse", "HEAD^{tree}")
    if git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ShardError("native candidate source checkout is dirty")
    return source, tree


def binary_digest(path: Path) -> str:
    with path.open("rb") as binary:
        return hashlib.file_digest(binary, "sha256").hexdigest()


def checkpoint_summary(evidence: Path, summary: dict[str, object]) -> None:
    """Retain a complete diagnostic snapshot; an interrupted run stays failed."""
    temporary = evidence / ".summary.json.tmp"
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, evidence / "summary.json")


def execute(args: argparse.Namespace, summary: dict[str, object]) -> int:
    workspace, evidence = args.workspace.resolve(), args.evidence_dir
    env = os.environ.copy()
    env.pop("RUST_MIN_STACK", None)
    env.setdefault("CARGO_TERM_COLOR", "never")
    repo_root = Path(git_output(workspace, "rev-parse", "--show-toplevel"))
    source, tree = clean_source(repo_root)
    package, features, required_drivers = SUITES[args.suite]
    summary.update(source=source, tree=tree, suite=args.suite, package=package, features=features)
    if env.get("TRNM_EXPECTED_SOURCE_SHA", source) != source:
        raise ShardError("source HEAD differs from independently expected source")
    (evidence / "HEAD").write_text(source + "\n")
    (evidence / "TREE").write_text(tree + "\n")

    def invoke(name: str, command: list[str], timeout: int) -> tuple[str, int]:
        summary["phase"] = name
        (evidence / f"{name}.command").write_text(shlex.join(command) + "\n")
        invocation = {"status": "running", "deadline_seconds": timeout, "exit_code": None}
        summary.setdefault("invocations", {})[name] = invocation
        checkpoint_summary(evidence, summary)
        started = time.monotonic_ns()
        try:
            output, code = run_bounded(command, cwd=workspace, env=env, timeout=timeout)
            (evidence / f"{name}.log").write_text(output, encoding="utf-8", errors="replace")
            (evidence / f"{name}.exit-code").write_text(str(code) + "\n")
            invocation.update(status="completed", exit_code=code)
            return output, code
        except (OSError, subprocess.SubprocessError) as error:
            invocation.update(status="failed", error=str(error))
            raise
        finally:
            invocation["elapsed_ms"] = (time.monotonic_ns() - started) // 1_000_000
            checkpoint_summary(evidence, summary)

    feature_args = ["--all-features"] if args.suite == "safety-epoch" else ["--features", features]
    target_args = ["--test", "epoch_journal_v2"] if args.suite == "safety-epoch" else ["--lib"]
    compile_command = [
        "cargo",
        "test",
        "-p",
        package,
        *feature_args,
        *target_args,
        "--locked",
        "--no-run",
        "--message-format=json",
    ]
    output, code = invoke("compile", compile_command, args.deadline_seconds)
    if code:
        return code
    executable = find_executable(output.splitlines(), workspace, args.suite)
    digest = binary_digest(executable)
    summary.update(executable=str(executable), executable_sha256=digest)

    release_executable: Path | None = None
    release_digest: str | None = None
    if args.suite == "node-epoch":
        release_command = [*compile_command]
        release_command.insert(release_command.index("--locked"), "--release")
        release_output, code = invoke(
            "compile-release", release_command, args.deadline_seconds
        )
        if code:
            return code
        release_executable = find_executable(
            release_output.splitlines(), workspace, args.suite
        )
        release_digest = binary_digest(release_executable)
        summary.update(
            release_executable=str(release_executable),
            release_executable_sha256=release_digest,
            release_cases=sorted(NODE_RELEASE_CASES),
        )

    def inventory_for(name: str, command: list[str], *, allow_empty: bool = False) -> list[str]:
        output, code = invoke(name, command + ["--list"], 120)
        if code:
            raise ShardError(f"{name} inventory command failed: {code}")
        return parse_test_inventory(output, allow_empty=allow_empty)

    inventory = inventory_for("inventory", [str(executable)])
    ignored = set(inventory_for("ignored", [str(executable), "--ignored"], allow_empty=True))
    validate_ignored_inventory(ignored, inventory)
    if not required_drivers.issubset(set(inventory) - ignored):
        raise ShardError("required SIGKILL drivers are missing or ignored")
    shards = partition_inventory(inventory, args.suite)
    (evidence / "inventory.json").write_text(json.dumps(shards, indent=2) + "\n")
    # Register every admitted test before any shard runs. A killed runner must
    # not leave later tests indistinguishable from absent or successful tests.
    outcomes = {
        shard: {
            "tests": names,
            "profile": (
                "release"
                if args.suite == "node-epoch"
                and len(names) == 1
                and names[0] in NODE_RELEASE_CASES
                else "dev"
            ),
            "status": "not-run",
            "deadline_seconds": shard_deadline(args.suite, names, args.deadline_seconds),
            "planned_count": len(names),
            "ignored_count": len(set(names) & ignored),
            "exit_code": None,
        }
        for shard, names in shards.items()
    }
    summary["shards"] = outcomes
    checkpoint_summary(evidence, summary)

    def confirm_source() -> None:
        binaries = [(executable, digest)]
        if release_executable is not None and release_digest is not None:
            binaries.append((release_executable, release_digest))
        if clean_source(repo_root) != (source, tree) or any(
            binary_digest(path) != expected for path, expected in binaries
        ):
            raise ShardError("source or native executable changed during the run")

    # Inventory/source failures are not ordinary test failures. Refuse the
    # whole execution plan before running it, rather than guessing new filters.
    commands = {}
    for shard in shards:
        confirm_source()
        selected_executable = (
            release_executable
            if outcomes[shard]["profile"] == "release"
            else executable
        )
        if selected_executable is None:
            raise ShardError("release shard has no release libtest executable")
        command = command_for_shard(
            selected_executable, shard, shards, args.suite
        )
        if inventory_for(shard + ".inventory", command) != shards[shard]:
            raise ShardError(f"{shard} filtered inventory differs from planned names")
        commands[shard] = command
    confirm_source()

    first_failure = 0
    for shard, outcome in outcomes.items():
        confirm_source()
        deadline = outcome["deadline_seconds"]
        print(f"{args.suite} shard={shard} tests={len(shards[shard])} deadline={deadline}s", flush=True)
        outcome["status"] = "running"
        output, code = invoke(shard, commands[shard], deadline)
        outcome.update(exit_code=code, elapsed_ms=summary["invocations"][shard]["elapsed_ms"])
        # Never run another process against source or a binary modified by the
        # preceding one, even when its exit status already indicates failure.
        try:
            confirm_source()
        except (OSError, ShardError, subprocess.SubprocessError) as error:
            outcome.update(status="failed", error=str(error))
            raise
        failure = code if code >= 0 else 128 - code
        if code == 0:
            try:
                outcome["final_test_result"] = result = final_test_result(output)
                counts = parse_test_summary(result)
                validate_summary(counts, planned=outcome["planned_count"], ignored=outcome["ignored_count"], total=len(inventory))
                outcome["counts"] = counts
            except ShardError as error:
                failure = 2
                outcome["error"] = str(error)
        outcome["status"] = "failed" if failure else "passed"
        if failure and not first_failure:
            first_failure = failure
        checkpoint_summary(evidence, summary)
        # Each shard owns a separate bounded libtest process. Retain its first
        # failure, but still obtain feedback from the remaining independent
        # shards. A later success never replaces that failure.
    summary["phase"] = "source-confirmation"
    confirm_source()
    return first_failure


def run(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=tuple(SUITES), default="native")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--deadline-seconds", type=int, default=900)
    args = parser.parse_args(argv)
    if args.deadline_seconds <= 0:
        raise ShardError("deadline must be positive")
    # Never write even failure metadata into a previous run's evidence.
    if args.evidence_dir.exists() and any(args.evidence_dir.iterdir()):
        raise ShardError("evidence directory must be new or empty")
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    summary: dict[str, object] = {"status": "failed", "phase": "source-admission"}
    code = 2
    try:
        code = execute(args, summary)
    except (OSError, ShardError, subprocess.SubprocessError) as error:
        summary["error"] = str(error)
        print(f"native candidate shard runner failed: {error}", file=sys.stderr)
    finally:
        summary.update(status="passed" if code == 0 else "failed", exit_code=code)
        checkpoint_summary(args.evidence_dir, summary)
    return code


if __name__ == "__main__":
    try:
        raise SystemExit(run(sys.argv[1:]))
    except (OSError, ShardError, subprocess.SubprocessError) as error:
        print(f"native candidate shard runner failed: {error}", file=sys.stderr)
        raise SystemExit(2)
