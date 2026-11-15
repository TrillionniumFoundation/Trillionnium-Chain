#!/usr/bin/env python3
"""Prepare literal-head validation queues; never execute any queued command.

Supply the actual E SHA and reviewed assembly payload and manifest hashes.
No expected commit is discovered from HEAD. Outputs are new coordination files.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import pprint
import re

TASK = Path("/workspace/scratch/a4188f5c86b5")
COORD = TASK / "coordination"
Z = "cdd984808a088e6c2e13b1e1ae6630a94d500c89"
LOCAL_REPO = TASK / "chain-pq-profile-boundary"
REMOTE_REPO = Path("/home/qian-qi/chain-pq-profile-boundary-20261111-a418-final")
REMOTE_RECORDS = Path("/home/qian-qi/chain-pq-a418-final-records")
REMOTE_TARGET = "/data/chain-pq-a418-node-retained-target-20261111"
PRIMARY = TASK / "desktop-evidence" / Z / "primary-evidence-v1/primary/validation" / Z
FULL_PRIMARY = TASK / "desktop-evidence" / Z / "full-rust-evidence-v1/primary"

CONTEXTS = {
    "main-graph": (TASK / "validation" / Z / "final-workspace-graph/context.json", "983bf04ee649fd8ba0322bc8598d8ad0c2811db5146016435f6c2660c2bad33f"),
    "fuzz-graph": (TASK / "validation" / Z / "final-fuzz-graph/context.json", "3e2ca391bc554b14bb519acdb52dead9d6025ed86c49a19db3912e46b700bb56"),
    "fmt": (TASK / "validation" / Z / "final-format/context.json", "2df93c093d36bc7c792f90b6199f964195abcfd44de92e47810a0723aff21cd6"),
    "pq-check": (TASK / "validation" / Z / "source-pq-research-integration-check/context.json", "e80223790f770b43fa956137a34b3f5982324aefb0779c9d5f7d9a2b8bee1c74"),
    "pq-tests": (TASK / "validation" / Z / "source-pq-research-integration-tests/context.json", "af64aca29a40f9d6680a3403b2eec1efbcd40e9250f623dc88375d122e4e80da"),
    "ci-source-tests": (TASK / "validation" / Z / "source-ci-integrity-tests/context.json", "cd50b3293795f53f20092d6fae37b3c6054d8ed24eaf7211b33d71fb3a4a19ec"),
    "w1-tests": (TASK / "validation" / Z / "source-w1-lifetime-ledger-tests/context.json", "7ff2b4df4db1bef97dad8fde1ef7fd864e3a2ab2329b7da4384ba51019048372"),
    "m06-retained": (TASK / "validation" / Z / "m06-retained-tests/context.json", "bef2281ee8a9aa1d731a8bece7e288fa9a02377ca539b412e6916b685b7126ef"),
    "node-four": (PRIMARY / "node-new-tests/context.json", "694bbbe4da96dfd144dc124c961510819215257750de43a6a72a0b332d24611e"),
    "strict-clippy": (PRIMARY / "strict-workspace-clippy/context.json", "7a0c6dc2cb0f4a7c3d94985c5f2589e43ba8d8f85bc75fc7125c68e15879eb1e"),
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pinned(path: Path, expected: str):
    if sha(path) != expected:
        raise ValueError("original bytes changed: " + str(path))
    return json.loads(path.read_text())


def write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)


LAUNCHER = '''#!/usr/bin/env python3
"""Execute only this reviewed bounded queue, with one original wrapper per step.

Generated with a literal E SHA. No native result is inferred from preparation.
Raw prior Y/Z observations and all source files remain outside this program's
write operations. The original recorders own fresh E receipt creation.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

QUEUE = __QUEUE_LITERAL__

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def require(ok, text):
    if not ok:
        raise RuntimeError(text)

def invoke(step):
    argv = [QUEUE['python'], QUEUE['runner'], '--head', QUEUE['expected_head'],
            '--id', step['id'], '--', *step['argv']]
    print(json.dumps({'queue_step': step['id'], 'wrapper_argv': argv}), flush=True)
    completed = subprocess.run(argv, cwd=QUEUE['repo'], check=False)
    folder = Path(QUEUE['records_root']) / QUEUE['expected_head'] / step['id']
    observation = {'id': step['id'], 'wrapper_returncode': completed.returncode,
                   'receipt_state': 'INCOMPLETE_OR_UNAVAILABLE',
                   'recorded_pass': None, 'recorded_returncode': None,
                   'full_ci_acceptance_granted': False}
    try:
        result = json.loads((folder / 'result.json').read_bytes())
        require(result['id'] == step['id'] and result['argv'] == step['argv']
                and result['source_head_before'] == QUEUE['expected_head'], 'receipt source/argv mismatch')
        require(type(result['pass']) is bool, 'receipt lacks a terminal boolean')
        for name in ('stdout', 'stderr'):
            require(sha(folder / (name + '.log')) == result[name + '_sha256'], 'raw log hash differs')
        actual_pass = (result['returncode'] == 0 and result.get('launch_error') is None
                       and result.get('source_head_after') == QUEUE['expected_head']
                       and result.get('source_status_after') == '')
        require(result['pass'] == actual_pass, 'receipt pass is inconsistent')
        observation.update(receipt_state='PASS' if actual_pass else 'FAIL',
                           recorded_pass=result['pass'], recorded_returncode=result['returncode'])
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
        observation['receipt_read_error'] = str(error)
    print(json.dumps(observation), flush=True)
    return observation

def main():
    head = QUEUE['expected_head']
    require(head != QUEUE['base_commit'] and len(head) == 40, 'literal new E SHA required')
    require(sha(QUEUE['runner']) == QUEUE['runner_sha256'], 'recorder changed')
    require(sha(QUEUE['environment_file']) == QUEUE['environment_sha256'], 'environment report changed')
    require(sha(QUEUE['proof_helper']) == QUEUE['proof_helper_sha256'], 'proof helper changed')
    require(Path(QUEUE['existing_target']).is_dir(), 'the original selected cache target is unavailable')
    for name, value in QUEUE['inherited_build_overrides'].items():
        require(os.environ.get(name) == value, 'inherited build override differs: ' + name)
    actual = subprocess.check_output(['git', '--no-replace-objects', 'rev-parse', 'HEAD'],
                                     cwd=QUEUE['repo'], text=True).strip()
    require(actual == head, 'checkout does not match literal E')
    require(not subprocess.check_output(['git', '--no-replace-objects', 'status', '--porcelain=v1',
                                         '--untracked-files=all'], cwd=QUEUE['repo']), 'source is dirty')
    for step in QUEUE['steps']:
        require(not (Path(QUEUE['records_root']) / head / step['id']).exists(),
                'a receipt directory already exists; no overwrite/retry: ' + step['id'])
    observations = []
    preconditions_ok = True
    final = QUEUE['steps'][-1]
    require(final['role'] == 'final-source-guard', 'final full source guard missing')
    try:
        for step in QUEUE['steps'][:-1]:
            if not preconditions_ok:
                skipped = {'id': step['id'], 'receipt_state': 'NOT_STARTED',
                           'reason': 'earlier precondition did not complete successfully'}
                observations.append(skipped)
                print(json.dumps(skipped), flush=True)
                continue
            observation = invoke(step)
            observations.append(observation)
            if step['role'] == 'precondition' and observation['receipt_state'] != 'PASS':
                preconditions_ok = False
    finally:
        observations.append(invoke(final))
        print(json.dumps({'expected_head': head, 'host': QUEUE['host'],
                          'bounded_queue_only': True, 'observations': observations,
                          'full_ci_acceptance_granted': False,
                          'production_qualification_granted': False,
                          'prior_observations_reclassified': False}), flush=True)
    return 0 if all(x['receipt_state'] == 'PASS' and x.get('wrapper_returncode') == 0
                    for x in observations) else 1

if __name__ == '__main__':
    sys.exit(main())
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True, help="Actual full SHA of the newly committed evidence child")
    parser.add_argument("--expected-payload-sha256", required=True, help="Reviewed helper payload hash, not inferred")
    parser.add_argument("--expected-manifest-sha256", required=True, help="Reviewed final manifest hash, binding derived indexes too")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.head) or args.head == Z:
        parser.error("--head must be an explicit new 40-hex commit SHA, different from Z")
    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_payload_sha256):
        parser.error("--expected-payload-sha256 must be the full reviewed hash")
    if not re.fullmatch(r"[0-9a-f]{64}", args.expected_manifest_sha256):
        parser.error("--expected-manifest-sha256 must be the full reviewed hash")
    out = args.output_dir
    if not out.is_absolute() or out.exists() or not out.parent.resolve().is_relative_to(COORD.resolve()):
        parser.error("output must be a fresh absolute directory within coordination")
    contexts = {name: pinned(path, digest) for name, (path, digest) in CONTEXTS.items()}
    if any(value["source_commit"] != Z for value in contexts.values()):
        raise ValueError("original command contexts must remain bound to Z")
    data_observation_path = COORD / "data-node-wrapper-first-decoded.json"
    data_observation = pinned(data_observation_path, "109a9cacd294b239f30af42883c5051c9196e9a2e7775a2d45a277051346716c")
    started = [json.loads(line) for line in data_observation["stdout"]["text"].splitlines()
               if line.startswith('{"event": "started"')]
    data_argv = next(row["argv"] for row in started if row["id"] == "node-retained-data-all-targets")
    remote_prefix = data_argv[:data_argv.index("cargo")]
    if remote_prefix != ["env", "CARGO_HOME=/home/qian-qi/chain-pq-a418-final-cargo-home",
                         "TRNM_CI_TOOL_ROOT=/home/qian-qi/chain-pq-a418-final-ci-tools",
                         "CARGO_TARGET_DIR=" + REMOTE_TARGET]:
        raise ValueError("actual /data retry environment prefix differs")
    proof_original = COORD / "verify_evidence_only_child.py"
    proof_sha = sha(proof_original)
    local_env = pinned(COORD / "local-build-environment.json", "cd30481e6cc512540e75750e35c5858d09a366f60ce00e6b2bc7e098451ce085")
    remote_env = pinned(FULL_PRIMARY / "environment.json", "ba267446879606ff269f511309223e323d45afe30d47443e64a6d33daf178350")
    runner_pins = {
        "local-cloud": "86d497c38986114c8d1d158f6736e18441e27b12d9d12a5ebf4713414c70c5f6",
        "desktop": "10089fad39140cbb56c15b85c72c8e5e8c76fc368d74c2ac2cb11233b1310562",
    }
    for host, path in (("local-cloud", COORD / "run_validation.py"), ("desktop", FULL_PRIMARY / "run_validation.py")):
        if sha(path) != runner_pins[host]:
            raise ValueError("original recorder changed: " + host)
    queues = {}
    for host in ("local-cloud", "desktop"):
        local = host == "local-cloud"
        records = TASK / "validation" if local else REMOTE_RECORDS / "validation"
        runner = COORD / "run_validation.py" if local else REMOTE_RECORDS / "run_validation.py"
        environment_file = COORD / "local-build-environment.json" if local else REMOTE_RECORDS / "environment.json"
        proof = out / proof_original.name if local else REMOTE_RECORDS / proof_original.name
        repo = LOCAL_REPO if local else REMOTE_REPO
        environment_sha = "cd30481e6cc512540e75750e35c5858d09a366f60ce00e6b2bc7e098451ce085" if local else "ba267446879606ff269f511309223e323d45afe30d47443e64a6d33daf178350"
        def row(identifier, argv, role="check", scope="", prior=None):
            item = {"id": identifier, "role": role, "argv": argv, "scope": scope}
            if prior is not None:
                item["prior_Z_observation_not_an_E_result"] = prior
            return item
        def guard(identifier, role):
            return row(identifier, ["python3", "scripts/ci/verify_ci_source.py", "--kind", "head",
                       "--expected-head", args.head, "--output", str(records / args.head / identifier / "source-identity.json")],
                       role, "Complete committed E raw tracked-byte/source identity guard")
        steps = [row("e-preflight", ["bash", "scripts/project-preflight.sh"], "precondition", "Original project preflight"),
                 guard("e-source-before", "precondition"),
                 row("e-evidence-only-relation", ["python3", str(proof), "--head", args.head,
                     "--repo", str(repo), "--expected-self-sha256", proof_sha,
                     "--expected-payload-sha256", args.expected_payload_sha256,
                     "--expected-manifest-sha256", args.expected_manifest_sha256,
                     "--runner", str(runner), "--expected-runner-sha256", runner_pins[host],
                     "--environment", str(environment_file), "--expected-environment-sha256", environment_sha],
                     "precondition", "Direct child Z; every old tracked object/mode identical; only reviewed evidence additions; full payload hashes and preserved FAIL/INCOMPLETE")]
        if local:
            for identifier, key, scope, prior in [
                ("e-workspace-graph", "main-graph", "Original locked offline all-feature main dependency graph", None),
                ("e-fuzz-graph", "fuzz-graph", "Original locked offline fuzz graph with its original isolated Cargo home; not fuzz execution", None),
                ("e-format", "fmt", "Original all-workspace formatting check", None),
            ]:
                steps.append(row(identifier, contexts[key]["argv"], scope=scope, prior=prior))
            steps.append(row("e-repository-source-contract", ["python3", "scripts/ci/check_repository.py"],
                             scope="Repository Markdown links, JSON/TOML, source inventory, claim flags and CI contract validator; not the full repository-truth lane"))
            for identifier, key, scope, prior in [
                ("e-pq-integration-check", "pq-check", "Original PQ source/corpus check; HOLD/NO-GO preserved", None),
                ("e-pq-integration-tests", "pq-tests", "Original integration suite including positive and negative controls", {"tests": 59}),
                ("e-ci-source-integrity-tests", "ci-source-tests", "Original source-integrity positive and negative controls", {"tests": 43}),
                ("e-w1-fixed-fixture-tests", "w1-tests", "Original fixed historical/current W1 report and lifetime controls; no rewritten golden", {"tests": 19}),
                ("e-m06-retained-tests", "m06-retained", "Complete original M06 --tests target set with all features, not doc tests/examples", {"suites": 18, "passed": 272, "failed": 0, "ignored": 9, "filtered": 0}),
            ]:
                steps.append(row(identifier, contexts[key]["argv"], scope=scope, prior=prior))
        else:
            steps.append(row("e-node-new-tests", remote_prefix + contexts["node-four"]["argv"],
                             scope="Four new Node boundary controls using the existing /data target, unchanged native flags",
                             prior={"passed": 4, "failed": 0, "ignored": 0, "filtered": 1398}))
            steps.append(row("e-strict-workspace-clippy", remote_prefix + contexts["strict-clippy"]["argv"],
                             scope="Original locked offline workspace/all-target/all-feature strict Clippy -D warnings on /data"))
        steps.append(guard("e-source-after", "final-source-guard"))
        queues[host] = {
            "schema": "trnm-evidence-child-validation-queue-v1", "host": host,
            "expected_head": args.head, "base_commit": Z, "reviewed_payload_sha256": args.expected_payload_sha256,
            "reviewed_manifest_sha256": args.expected_manifest_sha256,
            "python": "python3" if local else "/usr/bin/python3", "repo": str(repo),
            "runner": str(runner), "runner_sha256": runner_pins[host],
            "environment_file": str(environment_file), "environment_sha256": environment_sha,
            "proof_helper": str(proof), "proof_helper_sha256": proof_sha, "records_root": str(records),
            "existing_target": local_env["environment"]["CARGO_TARGET_DIR"] if local else REMOTE_TARGET,
            "inherited_build_overrides": contexts["m06-retained" if local else "node-four"]["inherited_build_overrides"],
            "provider_files": (local_env if local else remote_env)["provider"]["five_files"],
            "steps": steps,
            "execution_prerequisites": ["Do not change the desktop checkout or reuse its target while the original Z /data native job is active.",
                                         "Actual checkout is this literal E and clean; all receipt IDs are fresh; original tool/provider/flags remain unchanged."],
            "failure_policy": "Stop remaining checks after a precondition failure; otherwise retain independent failed observations and continue. Attempt final full source guard in finally. Never auto-retry or overwrite.",
            "prepared_only": True, "native_tests_executed_by_preparation": False,
            "full_ci_acceptance_granted": False, "production_qualification_granted": False,
            "prior_Z_observations_reclassified": False,
        }
    launchers = {host: LAUNCHER.replace("__QUEUE_LITERAL__", pprint.pformat(queue, width=100, sort_dicts=False))
                 for host, queue in queues.items()}
    for source in launchers.values():
        ast.parse(source)
    out.mkdir(parents=False, exist_ok=False)
    write_new(out / proof_original.name, proof_original.read_bytes())
    for host, queue in queues.items():
        name = "local" if host == "local-cloud" else "desktop"
        write_new(out / (name + "-queue.json"), (json.dumps(queue, indent=2) + "\n").encode())
        write_new(out / ("run-" + name + "-queue.py"), launchers[host].encode())
    provenance = {"schema": "trnm-evidence-child-queue-provenance-v1", "expected_head": args.head,
                  "reviewed_payload_sha256": args.expected_payload_sha256,
                  "reviewed_manifest_sha256": args.expected_manifest_sha256,
                  "original_contexts": {key: {"path": str(path), "sha256": digest}
                                        for key, (path, digest) in CONTEXTS.items()},
                  "actual_data_env_observation": {"path": str(data_observation_path), "sha256": sha(data_observation_path)},
                  "builder_sha256": sha(Path(__file__)), "proof_helper_sha256": proof_sha,
                  "copied_command_argv_from_original_contexts": True,
                  "new_native_or_CI_execution": False, "full_ci_acceptance_granted": False,
                  "required_desktop_transfers": [{"from": str(out / proof_original.name), "to": str(REMOTE_RECORDS / proof_original.name)},
                                                  {"from": str(out / "run-desktop-queue.py"), "to": str(REMOTE_RECORDS / ("run-evidence-child-" + args.head + ".py"))}]}
    write_new(out / "provenance.json", (json.dumps(provenance, indent=2) + "\n").encode())
    print(json.dumps({"prepared_only": True, "expected_head": args.head,
                      "output_dir": str(out), "files": [{"name": p.name, "sha256": sha(p)} for p in sorted(out.iterdir())],
                      "queued_commands": {host: len(queue["steps"]) for host, queue in queues.items()},
                      "commands_executed": False, "full_ci_acceptance_granted": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
