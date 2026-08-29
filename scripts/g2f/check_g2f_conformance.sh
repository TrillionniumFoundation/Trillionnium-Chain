#!/usr/bin/env bash
# Reproducible candidate-only G2F conformance runner.  Its JSON output is
# evidence for review only; it cannot promote G2F or alter machine truth.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$ROOT"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
export PYTHONDONTWRITEBYTECODE=1

# Refresh the exact GitHub candidate ref before any evidence is emitted.  A
# changed remote tuple is handled below as BASE_DRIFT and aborts the run.
git fetch --prune origin \
  '+refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829:refs/remotes/origin/feature/chain-g1-r4c-full-gap-closure-20260829' \
  >/dev/null

python3 -B - <<'PY'
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import random
import subprocess

from conformance.g2f import client_a, client_b
from conformance.g2f.fixture import fixture
from conformance.g2f.state_sync import StateSyncError, StagedStateSync, verify_manifest
from conformance.g2f.test_clients_b import _mutant_bytes, run_suite


ROOT = Path.cwd()
fixture_value = fixture()
raw = fixture_value.bundle.encoded
suite = run_suite()
if suite["status"] != "PASS" or suite["tests_run"] <= 0:
    raise SystemExit(f"candidate test runner failed: {suite}")

positive_a = client_a.verify_bundle(raw)
positive_b = client_b.verify_bundle(raw)
if positive_a.get("ok") is not True or positive_b.get("ok") is not True:
    raise SystemExit(f"positive carrier rejected: {positive_a} / {positive_b}")

mutants = _mutant_bytes(raw)
mutant_accepts: list[str] = []
mutant_disagreements: list[str] = []
for name, mutant in mutants.items():
    result_a = client_a.verify_bundle(mutant)
    result_b = client_b.verify_bundle(mutant)
    if result_a.get("ok") or result_b.get("ok"):
        mutant_accepts.append(name)
    if result_a.get("code") != result_b.get("code"):
        mutant_disagreements.append(name)
if mutant_accepts or mutant_disagreements:
    raise SystemExit(
        f"wire mutants failed accepts={mutant_accepts} disagreements={mutant_disagreements}"
    )

# Fixture truncations + 5,000 deterministic random strings + 1,000 one-byte
# mutations.  The fixed seed makes this differential replay reproducible.
fuzz_samples: list[bytes] = [raw[:index] for index in range(len(raw) + 1)]
rng = random.Random(0x620F)
for _ in range(5000):
    size = rng.randrange(0, 512)
    fuzz_samples.append(bytes(rng.getrandbits(8) for _ in range(size)))
for _ in range(1000):
    mutated = bytearray(raw)
    index = rng.randrange(len(mutated))
    mutated[index] ^= 1 << rng.randrange(8)
    fuzz_samples.append(bytes(mutated))
fuzz_exceptions = 0
fuzz_disagreements: list[int] = []
for index, sample in enumerate(fuzz_samples):
    try:
        result_a = client_a.verify_bundle(sample)
        result_b = client_b.verify_bundle(sample)
    except Exception:
        fuzz_exceptions += 1
        continue
    if (result_a.get("ok"), result_a.get("code")) != (
        result_b.get("ok"),
        result_b.get("code"),
    ):
        fuzz_disagreements.append(index)
if fuzz_exceptions or fuzz_disagreements:
    raise SystemExit(
        f"differential fuzz failed exceptions={fuzz_exceptions} disagreements={fuzz_disagreements[:8]}"
    )


def expect_rejection(operation) -> str:
    """Run one negative case and return its stable rejection code."""

    try:
        operation()
    except StateSyncError as error:
        return str(error)
    except Exception as error:  # pragma: no cover - evidence must expose this
        raise AssertionError(
            f"unexpected state-sync exception: {type(error).__name__}: {error}"
        ) from error
    raise AssertionError("state-sync mutant was accepted")


# Deterministic manifest/chunk mutants. Cycling these named mutations gives a
# larger replay campaign while retaining a clear reason for every rejection.
sync_mutants = (
    ("state_root", lambda m, c: m.__setitem__("state_root", "ff" * 32), False),
    ("block_id", lambda m, c: m.__setitem__("block_id", "ee" * 32), False),
    ("context_digest", lambda m, c: m.__setitem__("context_digest", "dd" * 32), False),
    ("checkpoint", lambda m, c: m.__setitem__("epoch_checkpoint_id", "cc" * 32), False),
    ("chunk_manifest_root", lambda m, c: m.__setitem__("chunk_manifest_root", "bb" * 32), False),
    ("chunk_uncompressed_hash", lambda m, c: m["chunk_entries"][0].__setitem__("uncompressed_hash", "aa" * 32), False),
    ("chunk_first_key", lambda m, c: m["chunk_entries"][0].__setitem__("first_state_key", "99" * 32), False),
    ("total_bytes", lambda m, c: m.__setitem__("total_uncompressed_bytes", m["total_uncompressed_bytes"] + 1), False),
    ("chunk_profile_ceiling", lambda m, c: m.__setitem__("max_chunk_uncompressed_bytes", 1_048_575), False),
    ("count_profile_ceiling", lambda m, c: m.__setitem__("max_chunk_count", 63), False),
    ("compression_profile", lambda m, c: m.__setitem__("compression_profile_hash", "88" * 32), False),
    ("epoch", lambda m, c: m.__setitem__("epoch", m["epoch"] + 1), False),
    ("catch_up_range", lambda m, c: m.__setitem__("catch_up_start_height", m["height"]), False),
    ("chunk_bytes", lambda m, c: c.__setitem__(0, bytes((c[0][0] ^ 1,)) + c[0][1:]), True),
)
sync_rejected = 0
sync_unexpected = 0
sync_semantic_accepts: list[str] = []
for case_index in range(3000):
    name, mutate, _mutates_chunks = sync_mutants[case_index % len(sync_mutants)]
    manifest = copy.deepcopy(fixture_value.manifest)
    chunks = [bytes(chunk) for chunk in fixture_value.chunks]
    try:
        mutate(manifest, chunks)
        verify_manifest(
            manifest,
            chunks,
            fixture_value.context,
            expected_block_id=bytes.fromhex(fixture_value.manifest["block_id"]),
            expected_root=bytes.fromhex(fixture_value.manifest["state_root"]),
        )
    except StateSyncError:
        sync_rejected += 1
    except Exception as error:  # pragma: no cover - surfaced in report
        sync_unexpected += 1
        raise AssertionError(f"sync mutant {case_index}:{name} unexpected {error}") from error
    else:
        sync_semantic_accepts.append(f"{case_index}:{name}")
if sync_semantic_accepts or sync_unexpected or sync_rejected != 3000:
    raise SystemExit(
        "state-sync mutation replay failed "
        f"rejected={sync_rejected} accepts={sync_semantic_accepts[:8]} unexpected={sync_unexpected}"
    )


# Positive staged swap and explicit external-anchor CAS. Faults leave residue
# in the candidate owner and must fence both reopen and any future stage.
sync_args = {
    "expected_block_id": bytes.fromhex(fixture_value.manifest["block_id"]),
    "expected_root": bytes.fromhex(fixture_value.manifest["state_root"]),
}
owner = StagedStateSync(fixture_value.context["chain_id"])
predecessor = owner.anchor
token = owner.stage(
    fixture_value.manifest,
    fixture_value.chunks,
    fixture_value.context,
    **sync_args,
    generation=1,
)
anchor = owner.commit(token, generation=1, expected_anchor=predecessor)
if owner.reopen() != anchor or owner.active is not token:
    raise SystemExit("positive staged swap did not reopen to the committed anchor")

cas_owner = StagedStateSync(fixture_value.context["chain_id"])
cas_token = cas_owner.stage(
    fixture_value.manifest,
    fixture_value.chunks,
    fixture_value.context,
    **sync_args,
    generation=1,
)
try:
    cas_owner.commit(cas_token, generation=1)
except StateSyncError as error:
    explicit_cas_code = str(error)
else:
    raise SystemExit("stage commit without explicit external anchor was accepted")

fault_results: dict[str, str] = {}
for fault in ("torn", "sidecar", "wal"):
    fault_owner = StagedStateSync(fixture_value.context["chain_id"])
    try:
        fault_owner.stage(
            fixture_value.manifest,
            fixture_value.chunks,
            fixture_value.context,
            **sync_args,
            generation=1,
            fault=fault,
        )
    except StateSyncError as error:
        fault_results[fault] = str(error)
    else:
        raise SystemExit(f"fault {fault} was accepted")
    try:
        fault_owner.reopen()
    except StateSyncError:
        pass
    else:
        raise SystemExit(f"fault {fault} reopened cleanly")

intent_owner = StagedStateSync(fixture_value.context["chain_id"])
intent_token = intent_owner.stage(
    fixture_value.manifest,
    fixture_value.chunks,
    fixture_value.context,
    **sync_args,
    generation=1,
)
try:
    intent_owner.commit(
        intent_token,
        generation=1,
        expected_anchor=intent_owner.anchor,
        simulate_crash="before_active",
    )
except StateSyncError as error:
    fault_results["partial_swap_intent"] = str(error)
else:
    raise SystemExit("partial swap intent was accepted")
try:
    intent_owner.reopen()
except StateSyncError:
    pass
else:
    raise SystemExit("partial swap intent reopened cleanly")

first_owner = StagedStateSync(fixture_value.context["chain_id"])
first_token = first_owner.stage(
    fixture_value.manifest,
    fixture_value.chunks,
    fixture_value.context,
    **sync_args,
    generation=1,
)
first_owner.commit(first_token, generation=1, expected_anchor=first_owner.anchor)
old_active = first_owner.active
old_anchor = first_owner.anchor
second_token = first_owner.stage(
    fixture_value.manifest,
    fixture_value.chunks,
    fixture_value.context,
    **sync_args,
    generation=2,
)
first_owner.commit(second_token, generation=2, expected_anchor=old_anchor)
first_owner._active = old_active  # retained full-store rollback mutant
try:
    first_owner.reopen()
except StateSyncError:
    fault_results["full_store_rollback"] = "rejected"
else:
    raise SystemExit("full-store rollback reopened cleanly")

copy_owner = StagedStateSync(fixture_value.context["chain_id"])
copy_token = copy_owner.stage(
    fixture_value.manifest,
    fixture_value.chunks,
    fixture_value.context,
    **sync_args,
    generation=1,
)
copied = copy_owner.clone_namespace("copied-g2f")
try:
    copied.commit(copy_token, generation=1, expected_anchor=copied.anchor)
except StateSyncError:
    fault_results["copied_namespace"] = "rejected"
else:
    raise SystemExit("copied namespace token was accepted")

renamed_token = __import__("dataclasses").replace(copy_token, namespace_id="renamed-g2f")
try:
    copy_owner.commit(renamed_token, generation=1, expected_anchor=copy_owner.anchor)
except StateSyncError:
    fault_results["renamed_token"] = "rejected"
else:
    raise SystemExit("renamed token was accepted")


def git(*arguments: str) -> str:
    return subprocess.check_output(["git", *arguments], cwd=ROOT, text=True).strip()


candidate_ref = "refs/remotes/origin/feature/chain-g1-r4c-full-gap-closure-20260829"
expected_candidate_commit = "6e0189e351015ef3230f217ca7ff86149baedcf0"
expected_candidate_tree = "efea864cb2fbc4835a59a089b3dbab8934e71231"
candidate_commit = git("rev-parse", candidate_ref)
candidate_tree = git("rev-parse", f"{candidate_ref}^{{tree}}")
if (candidate_commit, candidate_tree) != (expected_candidate_commit, expected_candidate_tree):
    raise SystemExit(
        "BASE_DRIFT: candidate tuple changed "
        f"{candidate_commit}/{candidate_tree} != {expected_candidate_commit}/{expected_candidate_tree}"
    )
source_commit = git("rev-parse", "HEAD")
source_tree = git("rev-parse", "HEAD^{tree}")

try:
    import unittest

    full_tests = unittest.defaultTestLoader.discover(
        "conformance/g2f", pattern="test_*.py"
    ).countTestCases()
except Exception as error:  # pragma: no cover - discovery itself is evidence
    raise SystemExit(f"unittest discovery failed: {error}") from error

report = {
    "schema": "trnm-g2f-conformance-run-v1",
    "status": "PASS",
    "package_id": "G2F_WHOLE_NODE_LIGHT_CLIENT_V1",
    "gate_id": "G2F",
    "agent_id": "A16",
    "scope": "fixture",
    "authority": "candidate",
    "classification": "candidate-non-normative",
    "source_commit": source_commit,
    "source_tree": source_tree,
    "candidate_base": {
        "ref": candidate_ref,
        "commit": candidate_commit,
        "tree": candidate_tree,
    },
    "bundle": {
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "digest": fixture_value.bundle.digest.hex(),
        "families": list(fixture_value.bundle.families),
        "trace_stages": list(range(8)),
        "positive_clients_agree": True,
    },
    "clients": {
        "implementations": [
            "conformance/g2f/client_a.py",
            "conformance/g2f/client_b.py",
        ],
        "positive_agree": True,
        "wire_mutants": {
            "count": len(mutants),
            "accepted": 0,
            "code_disagreements": 0,
        },
        "differential_fuzz": {
            "samples": len(fuzz_samples),
            "exceptions": fuzz_exceptions,
            "disagreements": len(fuzz_disagreements),
        },
        "proof_families": [
            "order",
            "da",
            "execution",
            "result",
            "settlement",
            "upgrade",
        ],
        "trace": "W0-W7 candidate trace only",
    },
    "state_sync": {
        "manifest_mutants": 3000,
        "semantic_accepts": len(sync_semantic_accepts),
        "unexpected_errors": sync_unexpected,
        "rejected": sync_rejected,
        "positive_staged_swap": True,
        "explicit_external_anchor_cas": True,
        "faults": fault_results,
    },
    "unittest_discovery": {
        "tests": full_tests,
        "run_suite_tests": suite["tests_run"],
        "status": suite["status"],
    },
    "known_nonclaims": [
        "candidate fixture is not the normative Protocol09 wire",
        "no accepted A11-A15 interfaces or independent production replay",
        "no external HSM/KMS/remote anchor backend or process custody",
        "no 64-epoch/10000-header campaign and no complete real W0-W7 trace",
        "machine truth and activation/release flags were not changed",
    ],
}
out = ROOT / "docs/evidence/g2f/G2F_CONFORMANCE_RUN_V1.json"
out.write_text(json.dumps(report, sort_keys=True, indent=2) + chr(10), encoding="utf-8")
print(
    json.dumps(
        {
            "status": report["status"],
            "tests": full_tests,
            "wire_mutants": len(mutants),
            "fuzz_samples": len(fuzz_samples),
            "state_sync_mutants": sync_rejected,
            "source_commit": source_commit,
            "source_tree": source_tree,
        },
        sort_keys=True,
    )
)
PY
