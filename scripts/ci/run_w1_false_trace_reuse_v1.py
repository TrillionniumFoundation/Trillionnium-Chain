#!/usr/bin/env python3
"""Explicit W1 observations; preserve original V2/V3/default false-trace gates.

Reuse the original native cost command owner, compiler contract and time limits.
Local mode never satisfies hosted cross-architecture or work-hardness acceptance.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

from ci_observation import ROOT, digest, receipt_root, source
from check_cross_arch_cost import (ARCHITECTURES, COST_BUILD_TIMEOUT_SECONDS,
    COST_CAMPAIGN_TIMEOUT_SECONDS, COST_IDENTITY_TIMEOUT_SECONDS, elf_machine)
from run_cross_arch_cost import (build_environment_overrides, capture,
    cargo_configuration_snapshot, require_cargo_configuration)

sys.path.insert(0, str(ROOT / "scripts"))
from pon_w1_false_trace_reuse_reader_v1 import FALSE_FLAGS, SELECTOR, analyze

EXAMPLE = "pon_w1_false_trace_reuse_v1"
LEGAL_EXAMPLE = "pon_w1_legal_strategy_v1"
CORRECT_PRODUCT_EXAMPLE = "pon_w1_false_trace_correct_product_v1"
FULL_LIMB_SELECTOR = "--false-trace-full-limb-v1"


def correct_product_reader():
    # Separate opt-in counterexperiment; the original schemas stay immutable.
    import pon_w1_false_trace_correct_product_reader_v1
    return pon_w1_false_trace_correct_product_reader_v1


def legal_strategy_reader(version="v1"):
    # The original mode retains its existing reader and complete capture schema.
    # This import occurs only when the separate legal experiment is requested.
    if version == "v2":
        import pon_w1_legal_strategy_reader_v2
        return pon_w1_legal_strategy_reader_v2
    if version != "v1":
        raise ValueError("fixed legal strategy version required")
    import pon_w1_legal_strategy_reader_v1
    return pon_w1_legal_strategy_reader_v1


def legal_campaign(binary, output, observations, report, reader):
    """Retain every fixed shard and the complete-grid verdict, including failures."""
    planned = [{"class": name, "target_index": target_index, "reuse_winners": horizon}
        for name in reader.CLASSES for target_index in range(len(reader.TARGETS))
        for horizon in reader.HORIZONS]
    if len(planned) != 30:
        raise ValueError("original legal strategy grid requires exactly 30 shards")
    report["planned_shards"] = planned
    report["shards"] = []
    paths, failed = [], False
    for index, configuration in enumerate(planned):
        name = f"campaign-{index:02d}"
        path = output / (name + ".stdout")
        paths.append(path)
        command = [str(binary), reader.SELECTOR, "--class", configuration["class"],
            "--target-index", str(configuration["target_index"]),
            "--reuse-winners", str(configuration["reuse_winners"])]
        shard = {"configuration": configuration, "result": "FAIL"}
        errors = []
        try:
            observed = capture(command, output, name, timeout=COST_CAMPAIGN_TIMEOUT_SECONDS, cwd=ROOT)
            observations.append(observed)
            shard["observation"] = observed
            if observed["exit_code"] != 0 or observed["timed_out"]:
                errors.append("native shard failed or timed out; original stdout/stderr retained")
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            # No process exit/timing is invented if capture itself could not
            # observe one. The remaining fixed shards are still attempted.
            shard["capture_error"] = str(error)
            errors.append("native shard capture failed")
        try:
            shard["reader"] = reader.analyze_shard(path)
            if shard["reader"]["selection"] != configuration:
                raise ValueError("retained shard selection differs from exact native command")
            if shard["reader"]["semantic_alerts"]:
                raise ValueError("retained native verifier disagreement")
        except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
            shard["reader_error"] = str(error)
            errors.append("native shard records failed independent reader")
        if errors:
            shard["errors"] = errors
            failed = True
        else:
            shard["result"] = "PASS"
        report["shards"].append(shard)
    try:
        # Recheck all thirty original paths together. A prefix of successful
        # shards, duplicate configurations or a missing last shard cannot pass.
        report["reader"] = reader.analyze(paths)
        if report["reader"]["semantic_alerts"]:
            raise ValueError("retained native verifier disagreement")
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        report["reader_error"] = str(error)
        failed = True
    return failed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=sorted(ARCHITECTURES), required=True)
    parser.add_argument("--local", action="store_true")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--legal-strategy", action="store_true")
    modes.add_argument("--legal-strategy-v2", action="store_true")
    modes.add_argument("--full-limb", action="store_true")
    modes.add_argument("--correct-product", action="store_true")
    args = parser.parse_args()
    spec = ARCHITECTURES[args.arch]
    legal_version = "v2" if args.legal_strategy_v2 else "v1" if args.legal_strategy else None
    reader = legal_strategy_reader(legal_version) if legal_version is not None else None
    product_reader = correct_product_reader() if args.correct_product else None
    example = (CORRECT_PRODUCT_EXAMPLE if product_reader is not None else
        LEGAL_EXAMPLE if reader is not None else EXAMPLE)
    receipt = ("w1-legal-strategy-" + legal_version if reader is not None else
        "w1-correct-product-false-trace-v1" if product_reader is not None else
        "w1-full-limb-reuse-v1" if args.full_limb else "w1-false-trace-reuse-v1")
    schema = ("trnm-w1-legal-strategy-execution-" + legal_version if reader is not None else
        "trnm-w1-correct-product-false-trace-execution-v1" if product_reader is not None else
        "trnm-w1-full-limb-reuse-execution-v1" if args.full_limb else
        "trnm-w1-false-trace-reuse-execution-v1")
    flags = (product_reader.FALSE_FLAGS if product_reader is not None else
        reader.FALSE_FLAGS if reader is not None else FALSE_FLAGS)
    output = receipt_root(receipt)
    observations = []
    report = {"schema": schema, "result": "FAIL",
        "execution_context": "local-native-preflight" if args.local else "github-hosted",
        "expected_source_commit": None,
        "architecture": args.arch, "build_profile": "release", "compiler_channel": "1.95.0",
        "target": spec["target"], "observations": observations, "source_before": None,
        "cargo_configuration_before": None, "cargo_configuration_after": None,
        "cargo_configuration_changed": False, "default_release_configuration_checked": False,
        "runner_context": {key: os.environ.get(key) for key in (
            "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_REPOSITORY",
            "GITHUB_EVENT_NAME", "RUNNER_ARCH", "RUNNER_OS", "RUNNER_NAME", "ImageOS", "ImageVersion",
            "TRNM_COST_RUNNER_LABEL")}, **flags}

    def checked(command, name, timeout=COST_IDENTITY_TIMEOUT_SECONDS):
        result = capture(command, output, name, timeout=timeout, cwd=ROOT)
        observations.append(result)
        if result["exit_code"] != 0 or result["timed_out"]:
            raise ValueError(name + " failed; retain original stdout/stderr and status")

    try:
        expected_source = os.environ.get("TRNM_EXPECTED_SOURCE_SHA")
        if expected_source is None:
            if not args.local:
                raise ValueError("hosted observation requires explicit TRNM_EXPECTED_SOURCE_SHA")
        elif re.fullmatch(r"[0-9a-f]{40}", expected_source) is None:
            raise ValueError("TRNM_EXPECTED_SOURCE_SHA must be 40 lowercase hexadecimal characters")
        report["expected_source_commit"] = expected_source
        report["source_before"] = source()
        if report["source_before"]["source_state"] != "committed-clean":
            raise ValueError("actual complete committed source bytes required")
        if expected_source is not None and report["source_before"].get("commit") != expected_source:
            raise ValueError("actual source commit does not match explicit expected source")
        if platform.system() != "Linux" or platform.machine() != spec["machine"]:
            raise ValueError("actual native Linux architecture required")
        if not args.local and (os.environ.get("TRNM_COST_RUNNER_LABEL") != spec["runner"]
                or os.environ.get("RUNNER_ARCH") != spec["runner_arch"]
                or os.environ.get("GITHUB_ACTIONS") != "true"
                or not os.environ.get("GITHUB_RUN_ID", "").isdigit()
                or not os.environ.get("GITHUB_RUN_ATTEMPT", "").isdigit()):
            raise ValueError("actual hosted runner context required; use --local for preflight")
        overrides = build_environment_overrides(dict(os.environ))
        report["build_environment_overrides"] = overrides
        if overrides:
            raise ValueError("original release compiler/target contract forbids overrides")
        report["cargo_configuration_before"] = cargo_configuration_snapshot(ROOT, dict(os.environ))
        require_cargo_configuration(report["cargo_configuration_before"])
        checked(["uname", "-a"], "uname")
        checked(["rustc", "+1.95.0", "-vV"], "rustc")
        checked(["cargo", "+1.95.0", "--version"], "cargo")
        compiler = (output / "rustc.stdout").read_text()
        if "\nrelease: 1.95.0\n" not in compiler or "\nhost: " + spec["target"] + "\n" not in compiler:
            raise ValueError("actual compiler differs from original native 1.95.0 contract")
        shutil.copyfile("/proc/cpuinfo", output / "cpuinfo.txt")
        checked(["cargo", "+1.95.0", "build", "--locked", "--release", "--manifest-path",
            "trillionnium/Cargo.toml", "--target", spec["target"], "-p", "trnm-pon-node",
            "--example", example], "build", COST_BUILD_TIMEOUT_SECONDS)
        binary = Path(os.environ["CARGO_TARGET_DIR"]) / spec["target"] / "release/examples" / example
        report["binary_elf_machine"] = elf_machine(binary)
        if report["binary_elf_machine"] != spec["elf_machine"]:
            raise ValueError("actual ELF architecture mismatch")
        report["binary_sha256_before"] = digest(binary)
        retained_binary = output / example
        shutil.copyfile(binary, retained_binary)
        report["retained_binary_sha256_before"] = digest(retained_binary)
        if report["retained_binary_sha256_before"] != report["binary_sha256_before"]:
            raise ValueError("retained binary copy differs before execution")
        failed = False
        if reader is not None:
            failed = legal_campaign(binary, output, observations, report, reader)
        elif product_reader is not None:
            checked([str(binary), product_reader.SELECTOR], "campaign", COST_CAMPAIGN_TIMEOUT_SECONDS)
            report["reader"] = product_reader.analyze(output / "campaign.stdout")
            if report["reader"]["semantic_alerts"]:
                raise ValueError("retained native verifier disagreement")
        else:
            selector = FULL_LIMB_SELECTOR if args.full_limb else SELECTOR
            checked([str(binary), selector], "campaign", COST_CAMPAIGN_TIMEOUT_SECONDS)
            report["reader"] = (analyze(output / "campaign.stdout", full_limb=True)
                if args.full_limb else analyze(output / "campaign.stdout"))
            if report["reader"]["semantic_alerts"]:
                raise ValueError("retained native verifier disagreement")
        report["binary_sha256_after"] = digest(binary)
        report["retained_binary_sha256_after"] = digest(retained_binary)
        if report["binary_sha256_before"] != report["binary_sha256_after"]:
            raise ValueError("measured binary changed")
        if report["retained_binary_sha256_after"] != report["binary_sha256_before"]:
            raise ValueError("retained binary copy changed during execution")
        if failed:
            raise ValueError("one or more fixed legal shards or complete-grid checks failed")
        report["result"] = "PASS"
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        if report["cargo_configuration_before"] is not None:
            try:
                report["cargo_configuration_after"] = cargo_configuration_snapshot(ROOT, dict(os.environ))
                require_cargo_configuration(report["cargo_configuration_after"])
                report["cargo_configuration_changed"] = (
                    report["cargo_configuration_before"] != report["cargo_configuration_after"])
                if report["cargo_configuration_changed"]:
                    raise ValueError("Cargo configuration changed during execution")
                report["default_release_configuration_checked"] = True
            except (OSError, ValueError) as error:
                report["cargo_configuration_error"] = str(error)
                report["result"] = "FAIL"
        try:
            report["source_after"] = source()
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            report["source_after"] = {"error": str(error)}
        report["source_changed"] = report["source_before"] != report["source_after"]
        if report["source_changed"]:
            report["result"] = "FAIL"
        report["artifact_sha256"] = {path.relative_to(output).as_posix(): digest(path)
            for path in sorted(output.rglob("*")) if path.is_file()}
        (output / "manifest.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"result": report["result"], "receipt": str(output)}, sort_keys=True))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
