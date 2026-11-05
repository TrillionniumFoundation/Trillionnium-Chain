# Full-chain PQ R3 qualification record

Status: **HOLD / no production activation / no self-awarded 9.6 score**.
This records implementation and evidence under the existing development plan.
It is not an independent cryptographic acceptance or a replacement plan.

## Source and recovery boundary

This round starts from the remotely recoverable Chain commit
`da31aff73adadda492da2642bef1f8d3d74be530` and Hepta commit
`6b172cd1980133d60a6aec69cd2e9ab6be70e098`. Prior unretained local commits,
archives and test binaries are not evidence for this round. See `baseline.json`.
Source checkpoints are published on the existing feature branches with complete
tree identity verified; a published checkpoint is not a passing test result.

The new [PQ continuous contract](../../docs/security/PQ_CONTINUOUS_STARTUP_V3.md)
describes the actual protected constructor, original Journal/CPU ownership,
fresh namespace, fixed genesis and real signed bootstrap work. Generic mixed
owner construction, classic wire fallback and arbitrary bootstrap replacement
remain rejected. Controller inputs use the selected protocol's byte, count and
verification limits.

## Original capacity failure and bounded candidate

The unchanged 8,625,548-byte custom-genesis fixture reproduces the original
authenticated-state CPU failure on the fixed baseline executable. Two original
requests consumed approximately 2.807 and 2.792 seconds against the unchanged
2-second burst policy. The Legacy comparison consumed about 1.062 seconds.
These are measurements on a shared development host, not a WAN or isolated
hardware throughput campaign. Failed and interrupted observations remain labeled.

The candidate reuses only deterministic sparse-tree arithmetic after rereading,
canonically encoding and hashing every actual input row. One bounded entry holds
either the original M06 canonical material or exact original leaf-hash tuples and
partition roots. It does not accept a root claim, row-set verdict, partial state
or admission capability. Existing SQL, delta, account, ancestry, CPU, cancellation
and post-write readback checks remain authoritative. The retained payload limit
is still 2 MiB, the software-charge limit 16 MiB, and the entry limit one.

This candidate is not a claim that every 65,536-key state fits the same CPU
budget. Oversized arithmetic material still falls back to the original root.
The original two capacity tests, independent original-function differentials and
full affected native regression suite must determine its actual result.

## Security changes requiring runtime verification

- Settings-selected PQ packet re-encoding after SQL publication; same-length
  signature corruption must roll back the complete native write.
- Final History activation within the original paid operation and deadline,
  with explicit packet/activation-target equality. Known locators use the
  already-bound original account and do not repeat W1 or create warm credit.
- Real heavier-fork payment rejection, while an ancestor locator cannot undo
  a settlement on the heavier active PoN branch.
- PQ revocation survives branch reorganization and cold reopen; rejected
  signature attempts remain charged.
- Protected PQ startup, nonempty Controller search/receiver/activation, lease
  renewal and restart/revocation rejection in a fresh continuous namespace.

Until exact-source execution is recorded, new Rust cases are **NOT YET RUN**.
Formatting, source-pin checks and static review do not change that status.
Hepta's own evidence must separately identify its source, profile and tests;
Chain results cannot certify AuthBus, installation or FinalUse.

## Gates that remain independent

Production network confidentiality and PQ endpoint identity; continuous public
service beyond finite development budgets; complete authorization and running
chain migration; the Cell-to-Hepta installation authority bridge; all actual
RunStart/ObjectiveStart/automation consumers; physical rollback resistance;
independent custody, key lifecycle and supply-chain review; quantum-effective
PoN work and proof-system/QROM assumptions; model efficacy; and the development
plan's independent administrative/WAN campaign remain separate gates.

ML-DSA signatures, functional test counts and source-integrity success do not
establish any of those gates. Pure PoN remains the consensus constraint.
