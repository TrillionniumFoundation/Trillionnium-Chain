#!/usr/bin/env python3
"""One-shot source fixes applied after the immutable Plan v2 overlays."""
from __future__ import annotations

import pathlib

root = pathlib.Path(__file__).resolve().parents[1]

repair_path = root / "tools/repair_plan_v2_remaining_blockers.py"
source = repair_path.read_text(encoding="utf-8")
old_imports = '''import hashlib
import json
import pathlib
'''
new_imports = '''import hashlib
import json
import os
import pathlib
'''
count = source.count(old_imports)
if count != 1:
    raise SystemExit(f"repair generator source drift: expected one import edge, found {count}")
source = source.replace(old_imports, new_imports, 1)

old = '''            body = inline.group("body").strip()
            if body and not body.endswith(","):
                body += ","
            line = f'{inline.group("prefix")} version = "{version}", {body}{inline.group("suffix")}'
'''
new = '''            body = inline.group("body").strip()
            if body.endswith(","):
                body = body[:-1].rstrip()
            require(bool(body), f"{manifest.relative_to(ROOT)}: empty inline path dependency")
            line = f'{inline.group("prefix")} version = "{version}", {body}{inline.group("suffix")}'
'''
count = source.count(old)
if count != 1:
    raise SystemExit(f"repair generator source drift: expected one inline-table edge, found {count}")
source = source.replace(old, new, 1)

old_lock_edge = '''    pin_all_path_dependencies()
    patch_runner_policy_fixture()
'''
new_lock_edge = '''    pin_all_path_dependencies()
    for lockfile in sorted(ROOT.rglob("Cargo.lock")):
        if any(part in {".git", "node_modules", "target"} for part in lockfile.parts):
            continue
        manifest = lockfile.parent / "Cargo.toml"
        if manifest.is_file():
            run(
                "cargo",
                "generate-lockfile",
                "--manifest-path",
                str(manifest.relative_to(ROOT)),
                "--offline",
            )
    github_env = os.environ.get("GITHUB_ENV")
    runner_temp = os.environ.get("RUNNER_TEMP")
    if github_env and runner_temp:
        cargo_home = pathlib.Path(runner_temp) / "plan-v2-cargo-home"
        cargo_home.mkdir(mode=0o700, parents=True, exist_ok=True)
        with pathlib.Path(github_env).open("a", encoding="utf-8") as handle:
            handle.write(f"CARGO_HOME={cargo_home}\\n")
    patch_runner_policy_fixture()
'''
count = source.count(old_lock_edge)
if count != 1:
    raise SystemExit(f"repair generator source drift: expected one lock-generation edge, found {count}")
source = source.replace(old_lock_edge, new_lock_edge, 1)
repair_path.write_text(source, encoding="utf-8")

control_path = root / "trillionnium/crates/trnm-control-plane-v0/src/lib.rs"
control = control_path.read_text(encoding="utf-8")
old_identifier = "fn forbidden_authority_is_explicitly rejected()"
new_identifier = "fn forbidden_authority_is_explicitly_rejected()"
count = control.count(old_identifier)
if count != 1:
    raise SystemExit(f"control-plane overlay drift: expected one malformed test identifier, found {count}")
control_path.write_text(control.replace(old_identifier, new_identifier, 1), encoding="utf-8")

registry_path = root / "scripts/check_repository_blocker_registry_v0.py"
registry = registry_path.read_text(encoding="utf-8")
old_metadata = '''            package = packages_by_name.get(name)
            if package is not None:
                metadata_trnm = package.get("metadata", {}).get("trnm", {})
                require(metadata_trnm.get("candidate_authority") is not True, f"candidate authority entered production root: {name}")
'''
new_metadata = '''            package = packages_by_name.get(name)
            if package is not None:
                package_metadata = package.get("metadata")
                if not isinstance(package_metadata, dict):
                    package_metadata = {}
                metadata_trnm = package_metadata.get("trnm", {})
                if not isinstance(metadata_trnm, dict):
                    metadata_trnm = {}
                require(metadata_trnm.get("candidate_authority") is not True, f"candidate authority entered production root: {name}")
'''
count = registry.count(old_metadata)
if count != 1:
    raise SystemExit(f"repository blocker registry drift: expected one Cargo metadata edge, found {count}")
registry_path.write_text(registry.replace(old_metadata, new_metadata, 1), encoding="utf-8")

technical_path = root / "docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md"
technical = technical_path.read_text(encoding="utf-8")


def replace_module_primary(
    module: str,
    next_module: str,
    marker: str,
    old_primary: str,
    new_primary: str,
) -> None:
    global technical
    section = technical.split(f"## {next_module}", 1)[0].split(f"## {module}", 1)[-1]
    if marker in section:
        return
    count = technical.count(old_primary)
    if count != 1:
        raise SystemExit(
            f"{module} technical reference drift: expected one primary-code edge, found {count}"
        )
    technical = technical.replace(old_primary, new_primary, 1)


replace_module_primary(
    "M03",
    "M04",
    "`trnm-durable-file-adapters-v0`",
    '''**Primary code.** `trnm-consensus-safety-rules`, `trnm-consensus-safety-store`,
`trnm-consensus-signer-journal`, `trnm-consensus-unix-remote-signer`,
`trnm-consensus-unix-fleet-signer`, `trnm-consensus-external-watermark`,
`trnm-consensus-external-node-checkpoint`,
`trnm-consensus-remote-signer-service`, and
`trnm-whole-node-checkpoint-types`.
''',
    '''**Primary code.** `trnm-consensus-safety-rules`, `trnm-consensus-safety-store`,
`trnm-consensus-signer-journal`, `trnm-consensus-unix-remote-signer`,
`trnm-consensus-unix-fleet-signer`, `trnm-consensus-external-watermark`,
`trnm-consensus-external-node-checkpoint`,
`trnm-consensus-remote-signer-service`, `trnm-whole-node-checkpoint-types`, and
`trnm-durable-file-adapters-v0`. The durable-file package supplies bounded,
hash-chained, sync-before-return repository adapters; it does not substitute for
device-backed custody, an independent monotonic anchor, or physical durability
evidence.
''',
)
replace_module_primary(
    "M05",
    "M06",
    "`trnm-tx-lifecycle-v0`",
    '''**Primary code.** `trnm-mempool` and `trnm-application-tx-builder-v0`.
''',
    '''**Primary code.** `trnm-mempool`, `trnm-application-tx-builder-v0`, and
`trnm-tx-lifecycle-v0`. The lifecycle crate freezes deterministic phase,
receipt, authorization, replacement, broadcast-intent, finality-readback,
tombstone, and replay-floor contracts without opening a socket or holding a
signer.
''',
)
replace_module_primary(
    "M13",
    "M14",
    "`trnm-state-sync-v0`",
    '''**Primary code.** `trnm-poco-cross-plane-readback-v1`,
`trnm-poco-order-finality-verifier-v1`, `trnm-finality-types`, and
`trnm-finality-verifier`.
''',
    '''**Primary code.** `trnm-poco-cross-plane-readback-v1`,
`trnm-poco-order-finality-verifier-v1`, `trnm-finality-types`,
`trnm-finality-verifier`, `trnm-migration-v0`, and `trnm-state-sync-v0`.
Migration and state-sync packages remain proof-bound and cannot manufacture a
trust anchor, finality receipt, schema root, or activation authority.
''',
)
replace_module_primary(
    "M15",
    "M16",
    "`trnm-release-bundle-v0`",
    '''**Primary code.** `trnm-poco-node` and `trnm-bridge-poc`; legacy
`trnm-consensus-app` and `trnm-node` are excluded migration residue.
''',
    '''**Primary code.** `trnm-poco-node`, `trnm-poco-node-authority`,
`trnm-poco-node-io`, `trnm-poco-node-host`, `trnm-poco-node-cli`,
`trnm-bridge-poc`, `trnm-node-boundary-v0`, `trnm-poco-node-production-v0`, and
`trnm-release-bundle-v0`; legacy `trnm-consensus-app` and `trnm-node` are
excluded migration residue. Production-shaped composition remains inert until
its independent authority, evidence, review, release, and activation gates all
bind the same exact source.
''',
)
replace_module_primary(
    "M16",
    "M17",
    "`trnm-control-plane-v0`",
    '''**Primary code.** No production crate is commissioned. Current authority is the
machine module registry, telemetry/evidence contracts, and node-local guard
interface. This absence is explicit and cannot be hidden by a service mock.
''',
    '''**Primary code.** `trnm-control-plane-v0` implements the bounded,
non-authoritative plan and receipt contracts plus the node-local independent
guard interface. It is not commissioned as production authority and cannot
silently promote machine truth, consensus parameters, placement, release, or
activation.
''',
)
replace_module_primary(
    "M17",
    "Module completion rule",
    "`trnm-production-adapter-conformance-v0`",
    '''**Primary code.** `trnm-bench`, `trnm-consensus-sim`,
`trnm-research-protocol`, and `trnm-poco-lab-validator`, plus `scripts/ci`,
`formal`, fuzz targets, evidence schemas, and read-only campaign tooling.
''',
    '''**Primary code.** `trnm-bench`, `trnm-consensus-sim`,
`trnm-research-protocol`, `trnm-poco-lab-validator`, and
`trnm-production-adapter-conformance-v0`, plus `scripts/ci`, `formal`, fuzz
targets, evidence schemas, and read-only campaign tooling. Conformance outputs
are evidence inputs only and cannot self-accept an adapter or open production
truth.
''',
)

technical_path.write_text(technical, encoding="utf-8")

workflow_root = root / ".github/workflows"
audited_one_shots = {
    "zz-apply-plan-v2-closure-tree.yml",
    "zz-clean-temporary-carriers.yml",
    "zz-consolidate-repository-owned-v1.yml",
    "zz-consolidate-repository-owned-v2.yml",
    "zz-finalize-repository-closure-v3.yml",
    "zz-finalize-repository-closure-v4.yml",
    "zz-finalize-repository-closure-v5.yml",
    "zz-integrate-node-split-v1.yml",
    "zz-integrate-repository-cores-v0.yml",
    "zz-plan-v2-durable-adapter-repair.yml",
    "zz-qualify-plan-v2-exact-head.yml",
    "zz-refresh-plan-v2-implementation-truth.yml",
}
retained_until_shell_cleanup = {
    "zz-apply-plan-v2-closure-tree.yml",
    "zz-plan-v2-durable-adapter-repair.yml",
}
present_one_shots = {path.name for path in workflow_root.glob("zz-*.yml")}
if present_one_shots != audited_one_shots:
    missing = sorted(audited_one_shots - present_one_shots)
    unexpected = sorted(present_one_shots - audited_one_shots)
    raise SystemExit(
        f"one-shot workflow inventory drift: missing={missing} unexpected={unexpected}"
    )
for path in sorted(workflow_root.glob("zz-*.yml")):
    if path.name not in retained_until_shell_cleanup:
        path.unlink()
