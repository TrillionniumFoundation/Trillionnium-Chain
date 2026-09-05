#!/usr/bin/env bash
set -euo pipefail

source_mode="${1:---worktree}"
root=$(git rev-parse --show-toplevel)

python3 - "$root" "$source_mode" <<'PY'
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(sys.argv[1])
MODE = sys.argv[2]
WORKFLOW_DIR = ".github/workflows"
SELF_HOSTED = "runs-on: [self-hosted, Linux, X64, x230, trillionnium-chain]"
HOSTED_BASELINE = "runs-on: ubuntu-24.04"
BASELINE = "trnm-required-baseline.yml"

STANDARD_GUARD = (
    "github.repository == 'TrillionniumFoundation/Trillionnium-Chain' && "
    "(github.event_name == 'schedule' || (github.actor == 'ProfAlexQI' && "
    "github.triggering_actor == 'ProfAlexQI' && (github.event_name != "
    "'pull_request' || github.event.pull_request.head.repo.full_name == "
    "github.repository)))"
)
MAINTAINER_GUARD = (
    "github.repository == 'TrillionniumFoundation/Trillionnium-Chain' && "
    "(github.event_name == 'schedule' || ((github.actor == 'ProfAlexQI' || "
    "github.actor == 'Tomasrgbsf') && github.triggering_actor == github.actor && "
    "(github.event_name != 'pull_request' || "
    "github.event.pull_request.head.repo.full_name == github.repository)))"
)

PAYLOAD_GUARD = (
    "github.repository == 'TrillionniumFoundation/Trillionnium-Chain' && "
    "((github.actor == 'ProfAlexQI' && github.triggering_actor == 'ProfAlexQI') "
    "|| (github.actor == 'Tomasrgbsf' && github.triggering_actor == "
    "'Tomasrgbsf') || (github.actor == 'github-actions[bot]' && "
    "github.triggering_actor == 'github-actions[bot]' && github.event_name == "
    "'pull_request' && github.event.pull_request.head.repo.full_name == "
    "github.repository && github.event.pull_request.author_association == "
    "'MEMBER' && startsWith(github.head_ref, 'feature/chain-'))) && "
    "(github.event_name != 'pull_request' || "
    "github.event.pull_request.head.repo.full_name == github.repository)"
)
POCO_GUARD = (
    "github.repository == 'TrillionniumFoundation/Trillionnium-Chain' && "
    "(github.event_name == 'schedule' && github.ref == 'refs/heads/main' || "
    "(github.actor == 'ProfAlexQI' && github.triggering_actor == 'ProfAlexQI' "
    "&& (github.event_name != 'pull_request' || "
    "github.event.pull_request.head.repo.full_name == github.repository)))"
)
POCO_MAINTAINER_GUARD = (
    "github.repository == 'TrillionniumFoundation/Trillionnium-Chain' && "
    "(github.event_name == 'schedule' && github.ref == 'refs/heads/main' || "
    "((github.actor == 'ProfAlexQI' || github.actor == 'Tomasrgbsf') && "
    "github.triggering_actor == github.actor && "
    "(github.event_name != 'pull_request' || "
    "github.event.pull_request.head.repo.full_name == github.repository)))"
)

P1_GUARD = (
    "github.repository == 'TrillionniumFoundation/Trillionnium-Chain' && "
    "github.actor == 'ProfAlexQI' && github.triggering_actor == 'ProfAlexQI' "
    "&& (github.event_name != 'pull_request' || "
    "github.event.pull_request.head.repo.full_name == github.repository) && "
    "(github.event_name != 'workflow_dispatch' || github.ref == "
    "'refs/heads/main')"
)


class PolicyError(RuntimeError):
    pass


def git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout


def workflow_names() -> list[str]:
    if MODE == "--worktree":
        base = ROOT / WORKFLOW_DIR
        return sorted(
            path.name
            for path in base.iterdir()
            if path.is_file() and path.suffix in {".yml", ".yaml"}
        )
    if MODE == "--staged":
        paths = git("ls-files", "--cached", "--", f"{WORKFLOW_DIR}/").splitlines()
    elif MODE == "--head":
        git("cat-file", "-e", "HEAD^{commit}")
        paths = git("ls-tree", "-r", "--name-only", "HEAD", "--", f"{WORKFLOW_DIR}/").splitlines()
    else:
        raise PolicyError(f"unsupported CI runner policy source: {MODE}")
    names: list[str] = []
    prefix = f"{WORKFLOW_DIR}/"
    for path in paths:
        if not path.startswith(prefix):
            continue
        name = path[len(prefix):]
        if "/" not in name and pathlib.Path(name).suffix in {".yml", ".yaml"}:
            names.append(name)
    return sorted(names)


def read_workflow(name: str) -> str:
    path = f"{WORKFLOW_DIR}/{name}"
    if MODE == "--worktree":
        return (ROOT / path).read_text(encoding="utf-8")
    if MODE == "--staged":
        return git("show", f":{path}")
    return git("show", f"HEAD:{path}")


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def normalized(parts: list[str]) -> str:
    return re.sub(r"\s+", " ", " ".join(parts)).strip()


def parse_jobs(name: str, text: str) -> dict[str, dict[str, object]]:
    lines = text.replace("\r\n", "\n").splitlines()
    jobs: dict[str, dict[str, object]] = {}
    jobs_sections = 0
    in_jobs = False
    current: str | None = None
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        indent = indent_of(raw)
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        if indent == 0 and re.fullmatch(r"jobs:\s*(?:#.*)?", stripped):
            jobs_sections += 1
            if jobs_sections > 1:
                raise PolicyError(f"{name}: multiple top-level jobs mappings")
            in_jobs = True
            current = None
            i += 1
            continue
        if in_jobs and indent == 0:
            in_jobs = False
            current = None
        if not in_jobs:
            i += 1
            continue
        if indent == 2:
            match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_-]*):\s*(?:#.*)?", stripped)
            if not match:
                raise PolicyError(f"{name}: unsupported jobs entry: {stripped}")
            current = match.group(1)
            jobs[current] = {"runs_on": [], "ifs": [], "guards": [], "uses": []}
            i += 1
            continue
        if current is None:
            raise PolicyError(f"{name}: content appears before a supported job identifier")
        if indent == 4:
            match = re.match(r"['\"]?([A-Za-z0-9_-]+)['\"]?\s*:", stripped)
            if match:
                key = match.group(1)
                props = jobs[current]
                if key == "runs-on":
                    props["runs_on"].append(stripped)
                elif key == "uses":
                    props["uses"].append(stripped)
                elif key == "if":
                    props["ifs"].append(stripped)
                    guard_parts: list[str] = []
                    if stripped == "if: >-":
                        j = i + 1
                        while j < len(lines) and indent_of(lines[j]) > 4:
                            part = lines[j].strip()
                            if part and not part.startswith("#"):
                                guard_parts.append(part)
                            j += 1
                        props["guards"].append(normalized(guard_parts))
                        i = j
                        continue
                    props["guards"].append(stripped.split(":", 1)[1].strip())
        i += 1
    if jobs_sections != 1:
        raise PolicyError(f"{name}: missing top-level jobs mapping")
    if not jobs:
        raise PolicyError(f"{name}: top-level jobs mapping contains no supported jobs")
    return jobs


def required_guard(name: str) -> str:
    if name in {
        "trnm-payload-replay-recovery-v1.yml",
        "trnm-replay-to-core-coordinator-v1.yml",
        "trnm-p2-node-candidate-devnet-cli.yml",
    }:
        return PAYLOAD_GUARD
    if name == "trnm-poco-bft-v0.yml":
        return POCO_MAINTAINER_GUARD
    if name == "p1-rust-sidecar.yml":
        return P1_GUARD
    if name in {
        "trnm-canonical-input-fuzz-smoke.yml",
        "trnm-cometbft-spike.yml",
        "trnm-gate-quick-check.yml",
        "trnm-merge-gates.yml",
    }:
        return MAINTAINER_GUARD
    return STANDARD_GUARD


def validate_baseline(name: str, text: str, jobs: dict[str, dict[str, object]]) -> int:
    required_jobs = {
        "repository-truth",
        "protocol-contract",
        "fuzz-smoke",
        "external-evidence-contract",
        "rust-baseline",
    }
    missing = sorted(required_jobs - set(jobs))
    if missing:
        raise PolicyError(f"{name}: missing required hosted jobs: {missing}")
    if "permissions:\n  contents: read" not in text:
        raise PolicyError(f"{name}: hosted baseline must retain read-only contents permission")
    if re.search(r"(?m)^\s{2}(contents|pull-requests|actions):\s*write\s*$", text):
        raise PolicyError(f"{name}: hosted baseline may not request write permissions")
    if "TRNM_EXPECTED_SOURCE_SHA:" not in text:
        raise PolicyError(f"{name}: exact source identity expression is missing")
    if text.count("persist-credentials: false") < len(jobs):
        raise PolicyError(f"{name}: every hosted job must disable persisted checkout credentials")
    if text.count("ref: ${{ env.TRNM_EXPECTED_SOURCE_SHA }}") < len(jobs):
        raise PolicyError(f"{name}: every hosted job must check out the exact source SHA")
    for job, props in jobs.items():
        if props["uses"]:
            raise PolicyError(f"{name}: job {job} uses an unauthorized reusable workflow")
        if props["runs_on"] != [HOSTED_BASELINE]:
            raise PolicyError(
                f"{name}: job {job} must contain exactly one pinned hosted runner {HOSTED_BASELINE}; "
                f"found {props['runs_on']}"
            )
        if props["ifs"]:
            raise PolicyError(
                f"{name}: job {job} must remain actor-independent and may not have a job-level if"
            )
    return len(jobs)


def accepted_privileged_guards(name: str, job: str) -> set[str]:
    canonical = required_guard(name)
    variants = {canonical}
    variants.add(
        canonical.replace(
            "github.actor == 'ProfAlexQI' && github.triggering_actor == 'ProfAlexQI'",
            "(github.actor == 'ProfAlexQI' || github.actor == 'Franksudoman') && github.triggering_actor == github.actor",
        )
    )
    variants.add(
        canonical.replace(
            "github.actor == 'ProfAlexQI' && github.triggering_actor == 'ProfAlexQI'",
            "(github.actor == 'ProfAlexQI' || github.actor == 'Franksudoman' || github.actor == 'ProfHepta') && github.triggering_actor == github.actor",
        )
    )
    variants.add(
        canonical.replace(
            "(github.actor == 'ProfAlexQI' || github.actor == 'Tomasrgbsf')",
            "(github.actor == 'ProfAlexQI' || github.actor == 'Tomasrgbsf' || github.actor == 'Franksudoman')",
        )
    )
    variants.add(
        canonical.replace(
            "|| (github.actor == 'github-actions[bot]'",
            "|| (github.actor == 'Franksudoman' && github.triggering_actor == 'Franksudoman') || (github.actor == 'github-actions[bot]'",
        )
    )
    # The prospective-merge documentation job is meaningful only for a PR.
    # Keep the exact trusted-runner guard intact, but bind it at the job level
    # so push/dispatch runs are visibly skipped rather than succeeding after
    # every step was skipped.
    if name == "trnm-documentation-truth.yml" and job == "prospective-merge":
        variants = {f"github.event_name == 'pull_request' && ({guard})" for guard in variants}
    return variants

def validate_privileged(name: str, jobs: dict[str, dict[str, object]]) -> int:
    for job, props in jobs.items():
        expected_guards = accepted_privileged_guards(name, job)
        if props["uses"]:
            raise PolicyError(f"{name}: job {job} uses an unauthorized reusable workflow")
        if props["runs_on"] != [SELF_HOSTED]:
            raise PolicyError(
                f"{name}: job {job} must contain exactly one trusted runner {SELF_HOSTED}; "
                f"found {props['runs_on']}"
            )
        if props["ifs"] != ["if: >-"] or len(props["guards"]) != 1:
            raise PolicyError(
                f"{name}: job {job} must contain exactly one direct folded trust guard"
            )
        if props["guards"][0] not in expected_guards:
            raise PolicyError(
                f"{name}: job {job} does not use its canonical trusted X230 invocation guard"
            )
    return len(jobs)


def main() -> int:
    names = workflow_names()
    if not names:
        raise PolicyError("no GitHub Actions workflows were found")
    hosted_jobs = 0
    privileged_jobs = 0
    for name in names:
        text = read_workflow(name)
        jobs = parse_jobs(name, text)
        if name == BASELINE:
            hosted_jobs += validate_baseline(name, text, jobs)
        else:
            privileged_jobs += validate_privileged(name, jobs)
    if hosted_jobs == 0 or privileged_jobs == 0:
        raise PolicyError(
            "runner policy requires both an actor-independent hosted baseline and privileged X230 jobs"
        )
    print(
        "ci_runner_policy=mixed-trust "
        f"hosted_jobs={hosted_jobs} privileged_jobs={privileged_jobs} source={MODE[2:]}"
    )
    return 0


try:
    raise SystemExit(main())
except (PolicyError, OSError, subprocess.CalledProcessError) as exc:
    print(f"ERROR: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
