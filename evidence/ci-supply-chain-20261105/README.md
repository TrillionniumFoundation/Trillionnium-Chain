# Exact-source supply-chain audit after the fuzz lock repair

Actual source: `7ae0d1b227853fc75e02334b497f69dd52d50235`, tree
`f59e2f42ce5fb6740806ef99d60e3396397de10a`. The unchanged
`python3 scripts/ci/run_supply_chain.py` completed **PASS** on this clean committed
source, verifying all tracked source before and after its commands.

Both locked graphs (`trillionnium/Cargo.toml` and `tests/fuzz/Cargo.toml`) completed
all-feature, frozen advisory, license, ban and source checks with cargo-deny 0.20.2.
All eight category results have **zero errors**. The existing policy's warnings
remain visible: three duplicate-version warnings per graph and five/four unused
license-allowance warnings. No advisory exception, weakened category, new license
allowance, dependency upgrade or modified CI command was introduced.

The original RustSec database was fetched and then frozen at commit
`26fd2d43f7280a1fb925a3743ec463017afe7119`, tree
`6cec6aa884aba1df6d5c62888f21760f4bd1d1de`, committed
2026-11-05T09:50:49+01:00. Its complete archive is retained in the receipt, not
replaced with a current or synthetic database during interpretation.

[Complete audit receipt, ordered parts](archive-parts.json) contains all command logs,
both diagnostic streams, original database archive and manifest. All eight
manifested files were hash-checked before packaging. [Verification](verification.json)
retains source binding, commands, exit statuses, category counts and archive hashes.
This is an actual audit run, not replayed success metadata.

## Relationship to the repaired blocker

The [old prospective quality job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41985420968/job/127144977186)
ran merge `d5c2de69af98a7f3e0ce8ae34d5711f4467353e2` over head `6ee52904`.
Its [original artifact](historical-quality-failure.zip), GitHub artifact 13411537198,
shows the same missing fuzz-lock dependency edges stopped the workflow at the
second locked fetch. No advisory database or policy-check result existed there.
That old failure is not a new-head advisory finding.

The [lock repair](../ci-fuzz-lock-20261105/README.md) fixed only the missing edges
and added negative controls. This new run verifies that repair also unblocks the
actual supply-chain checks. No further security defect was observed requiring a
code or policy change, so this commit records evidence only.

## Reproduce and limits

```
bash scripts/project-preflight.sh
bash scripts/ci/install_ci_tools.sh supply-chain
python3 scripts/ci/run_supply_chain.py
```

Use a fresh receipt directory; keep the original config and both manifests.
A future database may add findings and must produce its own result. This does not
prove absence of unknown vulnerabilities, pass the entire quality lane, complete
the fuzz sanitizer run, certify PQ security, or grant production activation.
Every business, independent-operator and global acceptance gate remains separate.

## Receipt packaging

The original ZIP is split into ordered 32 KiB pieces for reliable publication.
Join the parts in the order in archive-parts.json, then verify every part and
the full ZIP SHA-256 before extracting. This changes no byte of the original
receipt. The original full ZIP hash remains in verification.json.

```
cat exact-source-supply-chain.zip.part* > exact-source-supply-chain.zip
sha256sum exact-source-supply-chain.zip
```
