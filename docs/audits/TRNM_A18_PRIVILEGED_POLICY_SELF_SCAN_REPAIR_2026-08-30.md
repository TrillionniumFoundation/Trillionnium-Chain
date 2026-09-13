# A18 privileged Cargo-policy self-scan repair audit — 2026-08-30

Status: **candidate evidence only; no Gate, release, production, public-testnet,
mainnet, or activation promotion**.

## Exact repair tuple

```text
repair_commit=2c594d39230f8832f609760351861e22370911d0
repair_tree=da6ceb6e30ca401a2f010493054f071e571ab5ad
one_shot_run=33297623482
one_shot_job=99219895607
```

The repair adds the renamed
`scripts/check_privileged_cargo_offline_policy.sh` to the policy checker’s own
static-analysis exemption list. The checker must inspect every other repository
shell script for network-capable Cargo or Rust setup, but it cannot treat its
own embedded forbidden-pattern recognizers as executable violations.

The temporary write-capable workflow was deleted in the same repair commit. It
is not a retained repository execution surface.

## Source-bound replay result

The one-shot GitHub-hosted job completed successfully and reported:

```text
ci_runner_policy=mixed-trust hosted_jobs=5 privileged_jobs=20 source=worktree
cargo_offline_policy=passed workflows=13 jobs=20 cargo_jobs=18 no_cargo_jobs=2 source=worktree
mixed_trust_cargo_policy=passed hosted_required_jobs=5 privileged_offline_jobs=20 source=worktree
```

No workflow, job, package, fault cut, mutation case, offline-cache condition,
network prohibition, or toolchain pin was removed or relaxed. The only source
change is the self-exemption for the renamed policy implementation.

## Exact-head acceptance requirement

The bot-authored repair commit is not itself accepted evidence for PR #39.
This maintainer-authored audit record advances the candidate head only to obtain
fresh exact-source conclusions. Acceptance requires completed-success on this
record’s exact descendant head for:

- `repository-truth`;
- `protocol-contract`;
- `fuzz-smoke`;
- `external-evidence-contract`;
- `rust-baseline`;
- `TRNM payload replay recovery v1 gate`, including real process/SIGKILL
  recovery, canonical plan/mainline verification, mixed-trust project
  preflight, and offline-input immutability.

Independent review, live branch protection and required-check enforcement,
real multi-host campaigns, external HSM/KMS and monotonic anchor, physical
power-loss evidence, independent audits/red team, wall-clock soak, governance,
release, and activation remain open. All readiness and production flags remain
false.
