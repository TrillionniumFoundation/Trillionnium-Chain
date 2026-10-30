#!/usr/bin/env python3
"""Reproduce the actual workflow's same-step environment boundary locally."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
PARENT = "abe552b6d2a408adbf82e27c817b4f914a7322a2"
WORKFLOW = ".github/workflows/pon-model-controls-diagnostic.yml"


def original(path):
    return subprocess.check_output(["git", "show", PARENT + ":" + path], cwd=ROOT)


before = original(WORKFLOW).decode()
after = (ROOT / WORKFLOW).read_text()
needle = "          printf 'MODEL_DIAGNOSTIC_OUT=%s\\n' \"$out\" >> \"$GITHUB_ENV\"\n"
assert before.count(needle) == 1
assert after == before.replace(needle, needle + '          export MODEL_DIAGNOSTIC_OUT="$out"\n')
old_job = yaml.safe_load(before)["jobs"]["original-five-role-diagnostic"]
new_job = yaml.safe_load(after)["jobs"]["original-five-role-diagnostic"]
assert new_job["timeout-minutes"] == 15
assert next(step for step in new_job["steps"] if step.get("id") == "model")["timeout-minutes"] == 10


def relevant_shell(job):
    script = next(step for step in job["steps"] if step.get("id") == "source")["run"]
    lines = script.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith('out="$RUNNER_TEMP/'))
    end = next(i for i, line in enumerate(lines) if line.startswith("python3 scripts/ci/verify_ci_source.py"))
    probe = next(line for line in lines if "resources-before.json" in line)
    return "set -euo pipefail\n" + "\n".join(lines[start:end] + [probe]) + "\n", probe


results = {}
with tempfile.TemporaryDirectory(prefix="ci-same-step-", dir=HERE) as area:
    base = Path(area)
    for kind, job in (("before", old_job), ("after", new_job)):
        folder = base / kind
        folder.mkdir()
        envfile = folder / "github-env"
        env = dict(os.environ)
        env.pop("MODEL_DIAGNOSTIC_OUT", None)
        env.update(RUNNER_TEMP=str(folder), GITHUB_RUN_ID="local-reproduction", GITHUB_RUN_ATTEMPT="1",
                   GITHUB_ENV=str(envfile))
        script, probe = relevant_shell(job)
        child = subprocess.run(["bash", "--noprofile", "--norc", "-c", script], env=env,
                               cwd=ROOT, capture_output=True, text=True, timeout=30)
        results[kind] = {"exit_code": child.returncode, "stdout": child.stdout, "stderr": child.stderr}
        expected = folder / "pon-model-controls-local-reproduction-1"
        assert envfile.read_text() == "MODEL_DIAGNOSTIC_OUT=" + str(expected) + "\n"
        if kind == "before":
            assert child.returncode != 0 and "KeyError: 'MODEL_DIAGNOSTIC_OUT'" in child.stderr
            assert not (expected / "evidence/resources-before.json").exists()
            continue
        assert child.returncode == 0 and (expected / "evidence/resources-before.json").is_file()
        # GITHUB_ENV is consumed by the runner between steps. A new real shell
        # receives its exact value; it must not depend on the previous export.
        key, value = envfile.read_text().rstrip("\n").split("=", 1)
        fresh_env = dict(env)
        fresh_env[key] = value
        next_step = subprocess.run(["bash", "--noprofile", "--norc", "-c", "set -euo pipefail\n" + probe],
                                   env=fresh_env, cwd=ROOT, capture_output=True, text=True, timeout=30)
        assert next_step.returncode == 0 and fresh_env[key] == str(expected)
        results["next_step"] = {"exit_code": next_step.returncode, "same_output_path": True,
                                "stdout": next_step.stdout, "stderr": next_step.stderr}

pins = {}
for path in ("scripts/ci/prepare_model_cloud_inputs.py", "scripts/ci/model-runtime-cpu-requirements.txt",
             "scripts/llm_runtime_pilot.py", "config/pon/model-family-smollm2-135m-v1.json",
             "scripts/llm_runtime_release.py"):
    raw = (ROOT / path).read_bytes()
    assert raw == original(path)
    pins[path] = hashlib.sha256(raw).hexdigest()
assert all("export MODEL_DIAGNOSTIC_OUT=" not in step.get("run", "")
           and "MODEL_DIAGNOSTIC_OUT=%s" not in step.get("run", "")
           for step in new_job["steps"] if step.get("id") != "source")
report = {"schema": "pon-ci-preparation-repair-observation-v1", "parent": PARENT,
          "result": "PASS", "actual_same_shell_red_then_green": results,
          "unchanged_pins_and_production_validator": pins, "job_minutes": 15, "model_step_minutes": 10,
          "model_execution_performed": False, "ordinary_installation_qualified": False}
(HERE / "same-step-environment-control.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps({"result": "PASS", "before_exit": results["before"]["exit_code"],
                  "after_exit": results["after"]["exit_code"], "next_step_exit": results["next_step"]["exit_code"],
                  "unchanged_material_pins": len(pins)}, sort_keys=True))
