# W1 construction scope and native-packet differential

**Quantum mining security and production qualification remain HOLD / NO-GO.**

This continuation adds a separately versioned construction/accounting scope
reader and a read-only bridge between an original native PGH2/PNP2 packet,
the complete scalar W1 relation and the reversible macro program. The
[scope contract](../../docs/research/W1_ORACLE_EVIDENCE_SCOPE_V1.md) explains
the acceptance boundaries. Original V1 accounting and simulator bytes remain
unchanged; their local `full_W1_oracle_constructed=false` is not a statement
that the repository lacks the retained fixed-context construction.

## Original native input cohort

The frozen [artifact provenance](native-artifact.json) binds the original
[ZIP](native-fullpath-e4abb172.zip), fetched through GitHub and independently
hashed before use. It is not regenerated or relabelled as a later native run.

| Identity | Original value |
| --- | --- |
| Source | `e4abb172147e941b62483652b0ceabaae4317624` |
| Tree | `016ebf3deeac88d6d7a782edf563f2291ebe17f5` |
| GitHub Actions | [Run 42830743579](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42830743579), job `129927393431` |
| Artifact | `13785762485`, 129,999 bytes |
| ZIP SHA-256 | `d9ce3ead97f87759707829220525f50420126fa0347cbd64ec46aeb69bbd57c9` |
| Original preregistration SHA-256 | `9ba442904cc481e8371ff90bef97908dd1f0dcf59ce442375b18d0fd8a10f443` |
| Native binary SHA-256 | `fe18172189e555693c701d0d6b686c519e2a4c5d7a55ecdf999cb7c4e77db7b7` |

The original source-before/source-after guards agree. Nine native processes
produce four scheduled observations: valid accepted, exact duplicate, corrupt
product rejected as `WORK:Product`, and cancellation before `VerifiedWork`.
Only one newly admitted local block is recorded, at depth zero, with zero timely
accepted progress under the original service contract. That component's
successful workflow explicitly retains `overall_gate=security_gate=HOLD`.

The new bridge must independently reparse the full packet, replay the scalar
W1 relation, compare the same input with the native-sized macro oracle and
verify clean uncomputation. Its late-product control must preserve the winning
nonce while rejecting the submitted product. It never executes quantum
hardware or a new native binary and never grants a global admission result.

## Retained upstream CI failure

At original source `e4abb172`, the
[repository-truth job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42830743518/job/129995452145)
failed in `test_pq_lifetime_budget.py`: 58 methods ran, one errored on
`source lock hash mismatch: trillionnium/crates/trnm-pon-node/src/consensus.rs`.
The quantum suites occur later in that lane and were not executed there.
This is an original source-identity refusal, not an observed oracle failure.
The separately successful native-fullpath component does not erase it.

## Validation record

The source commit introduces the readers, their negative controls, original
artifact and CI wiring. Exact committed-source execution and review results
are recorded by a subsequent evidence-only update. Until those receipts are
present, this file makes no new committed-source test or hosted-CI pass claim.
