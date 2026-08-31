# A18 mixed-trust project-preflight migration audit — 2026-08-30

Status: **candidate evidence only; no Gate, release, production, public-testnet,
mainnet, or activation promotion**.

## Exact source observation

The one-shot source migration completed successfully and produced:

```text
commit=83dce97313b03bec680ae6b5e73ba7631c7dc5e1
message=fix(repo): make project preflight mixed-trust aware
```

The temporary write-capable workflow was deleted by that same commit. It is
not a retained repository execution surface.

## Policy migration

The migration preserves both trust classes instead of weakening either:

1. `scripts/check_cargo_offline_policy.sh` is the stable mixed-trust entry
   point used by `project-preflight.sh` and process/fault gates.
2. `scripts/check_privileged_cargo_offline_policy.sh` retains the complete
   historical 13-workflow / 20-job X230 offline-Cargo contract.
3. The mixed-trust entry point first validates all five actor-independent,
   GitHub-hosted required jobs plus every privileged X230 job with
   `scripts/check_ci_runner_policy.sh`.
4. It then evaluates the privileged offline policy against a source snapshot
   in which only the separately reviewed hosted baseline is omitted.
5. Worktree, staged-index, and exact-HEAD modes remain fail-closed and retain
   source-representation checks.

No test, fault cut, mutant, schema, wire vector, process boundary, or Cargo
package was removed to make the policy pass.

## Boundary compatibility repair

`PROJECT_BOUNDARY.json` remains schema `trnm-project-boundary-v2` and retains
Native PoCO-BFT as the only forward consensus route. The migration adds the
legacy preflight compatibility fields required by the existing generic project
root verifier:

- canonical repository directory identity;
- development-lane marker;
- canonical remote policy and slug;
- protected/development branch policy;
- forbidden cross-project path expression.

These additive fields do not make GitHub branch protection active. The live
`main` branch administrative state must still be independently read and remain
an external P0 until protection and required checks are actually enforced.

## Exact-head acceptance requirement

The GitHub platform classified workflows triggered by the bot-authored
migration commit as `action_required`; those records are not pass evidence.
This maintainer-authored audit record advances the exact candidate head solely
to obtain executable, source-bound conclusions.

Acceptance of the repository-owned migration requires completed-success on the
exact descendant head for:

- `repository-truth`;
- `protocol-contract`;
- `fuzz-smoke`;
- `external-evidence-contract`;
- `rust-baseline`;
- `TRNM payload replay recovery v1 gate`, including the real SIGKILL/process
  recovery matrix, canonical plan/mainline checks, project preflight, and
  offline-input immutability.

Independent review, active branch protection, real multi-host campaigns,
external HSM/KMS and monotonic anchor, physical power-loss evidence,
independent audits/red team, wall-clock soak, governance, release, and
activation remain open. All readiness and production flags remain false.
