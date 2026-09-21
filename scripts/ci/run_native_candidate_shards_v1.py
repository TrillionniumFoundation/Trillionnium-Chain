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
from typing import Iterable

PACKAGE = "trnm-native-execution-v0"
FEATURES = "test-fixtures,incremental-epoch-candidate"
BRIDGE = "later_epoch_checkpoint_bridge::tests::"
PRE_HANDOFF = BRIDGE + "later_pre_handoff_"
SCHEMA7 = "durable::incremental_owner_v1::epoch_candidate_v1::commit::tests::schema7_"
POCO_SIGKILL = "poco_checkpoint::native_authorization_tests::epoch_sigkill_commit_boundaries_preserve_exact_prepared_chain"
SHARD_NAMES = ("general", "historical-install", "historical-replay", "historical-receiver", "later-pre-handoff", "later-bridge", "schema7", "poco-sigkill")
ALLOWED_IGNORED = {
    BRIDGE + "historical_replay_continuation_sigkill_child",
    BRIDGE + "historical_replay_install_sigkill_child",
    BRIDGE + "later_descendant_c22_sigkill_child",
    PRE_HANDOFF + "sigkill_child",
}
REQUIRED_SIGKILL_DRIVERS = {
    BRIDGE + "historical_replay_continuation_sigkill_six_cuts_preserve_exact_c33",
    BRIDGE + "historical_replay_install_sigkill_cuts_recover_exact_nonempty_base",
    BRIDGE + "later_descendant_c22_sigkill_commit_cuts_recover_exact_p_and_proof",
    PRE_HANDOFF + "sigkill_commit_and_attach_cuts_preserve_original_evidence",
}


NODE_EPOCH_PREFIX = "epoch_runtime_candidate_v1::tests::"
NODE_REQUIRED_DRIVERS = {
    NODE_EPOCH_PREFIX + "actual_epoch_runtime_activation_releases_timer_then_persisted_timeout_once",
    NODE_EPOCH_PREFIX + "actual_epoch_first_core_finalization_applies_three_real_native_executions_v2",
    NODE_EPOCH_PREFIX + "actual_epoch_seals_apply_original_fronts_then_commit_unattached_pre_handoff_v5",
}
SUITES = {
    "native": (PACKAGE, FEATURES, ALLOWED_IGNORED, REQUIRED_SIGKILL_DRIVERS),
    "node-epoch": ("trnm-poco-node", "epoch-runtime-test-fixtures", set(), NODE_REQUIRED_DRIVERS),
}


class ShardError(RuntimeError):
    pass


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
    if suite == "node-epoch":
        result = {"general": []}
        for name in names:
            if name.startswith(NODE_EPOCH_PREFIX):
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
    expected_source = (workspace / "crates" / package / "src/lib.rs").resolve()
    for line in lines:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict) or item.get("reason") != "compiler-artifact":
            continue
        target = item.get("target", {})
        if (target.get("name") == package.replace("-", "_")
                and target.get("kind") == ["lib"]
                and item.get("profile", {}).get("test") is True
                and Path(target.get("src_path", "")).resolve() == expected_source
                and item.get("executable")):
            candidates.append(Path(item["executable"]).resolve())
    if len(candidates) != 1:
        raise ShardError(f"expected one native libtest executable, found {candidates}")
    return candidates[0]


def command_for_shard(executable: Path, shard: str, names: dict[str, list[str]], suite: str = "native") -> list[str]:
    if suite == "node-epoch" and shard != "general":
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


def execute(args: argparse.Namespace, summary: dict[str, object]) -> int:
    workspace, evidence = args.workspace.resolve(), args.evidence_dir
    env = os.environ.copy()
    env.pop("RUST_MIN_STACK", None)
    env.setdefault("CARGO_TERM_COLOR", "never")
    repo_root = Path(git_output(workspace, "rev-parse", "--show-toplevel"))
    source, tree = clean_source(repo_root)
    package, features, allowed_ignored, required_drivers = SUITES[args.suite]
    summary.update(source=source, tree=tree, suite=args.suite, package=package, features=features)
    if env.get("TRNM_EXPECTED_SOURCE_SHA", source) != source:
        raise ShardError("source HEAD differs from independently expected source")
    (evidence / "HEAD").write_text(source + "\n")
    (evidence / "TREE").write_text(tree + "\n")

    def invoke(name: str, command: list[str], timeout: int) -> tuple[str, int]:
        summary["phase"] = name
        (evidence / f"{name}.command").write_text(shlex.join(command) + "\n")
        output, code = run_bounded(command, cwd=workspace, env=env, timeout=timeout)
        (evidence / f"{name}.log").write_text(output, encoding="utf-8", errors="replace")
        (evidence / f"{name}.exit-code").write_text(str(code) + "\n")
        return output, code

    output, code = invoke("compile", ["cargo", "test", "-p", package, "--features", features, "--lib", "--locked", "--no-run", "--message-format=json"], args.deadline_seconds)
    if code:
        return code
    executable = find_executable(output.splitlines(), workspace, args.suite)
    digest = binary_digest(executable)
    summary.update(executable=str(executable), executable_sha256=digest)

    def inventory_for(name: str, command: list[str], *, allow_empty: bool = False) -> list[str]:
        output, code = invoke(name, command + ["--list"], 120)
        if code:
            raise ShardError(f"{name} inventory command failed: {code}")
        return parse_test_inventory(output, allow_empty=allow_empty)

    inventory = inventory_for("inventory", [str(executable)])
    ignored = set(inventory_for("ignored", [str(executable), "--ignored"], allow_empty=True))
    if ignored != allowed_ignored or not ignored.issubset(inventory):
        raise ShardError("ignored inventory differs from dedicated SIGKILL children")
    if not required_drivers.issubset(set(inventory) - ignored):
        raise ShardError("required SIGKILL drivers are missing or ignored")
    shards = partition_inventory(inventory, args.suite)
    (evidence / "inventory.json").write_text(json.dumps(shards, indent=2) + "\n")
    summary["shards"] = outcomes = {}
    for shard in shards:
        command = command_for_shard(executable, shard, shards, args.suite)
        if inventory_for(shard + ".inventory", command) != shards[shard]:
            raise ShardError(f"{shard} filtered inventory differs from planned names")
        print(f"{args.suite} shard={shard} tests={len(shards[shard])} deadline={args.deadline_seconds}s", flush=True)
        output, code = invoke(shard, command, args.deadline_seconds)
        outcome = {"planned_count": len(shards[shard]), "ignored_count": len(set(shards[shard]) & ignored), "exit_code": code}
        outcomes[shard] = outcome
        if code:
            return code
        outcome["final_test_result"] = result = final_test_result(output)
        counts = parse_test_summary(result)
        validate_summary(counts, planned=outcome["planned_count"], ignored=outcome["ignored_count"], total=len(inventory))
        outcome["counts"] = counts
    summary["phase"] = "source-confirmation"
    if clean_source(repo_root) != (source, tree) or binary_digest(executable) != digest:
        raise ShardError("source or native executable changed during the run")
    return 0


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
        (args.evidence_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return code


if __name__ == "__main__":
    try:
        raise SystemExit(run(sys.argv[1:]))
    except (OSError, ShardError, subprocess.SubprocessError) as error:
        print(f"native candidate shard runner failed: {error}", file=sys.stderr)
        raise SystemExit(2)
