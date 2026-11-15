# Recovered fixed-domain mapping and conditional sampler arithmetic

Status: **HOLD / NO-GO**. This continuation reconstructs work after loss of the
previous scratch workspace. It grants no production or consensus authority.

## New executed source

- Parent #849: `85a53d09604a765352102f91a865dcf25ecede38`.
- Tested code: `11e6dc957943868555d022c254a1885b3582683a`; tree `6111f91f37440f99428c721e7f7402670fc6e5ba`.
- Git source observations before and after the selected validation match and
  are clean. This directory is an evidence-only child; its publication identity
  must not replace the executed-code identity.
- Lost prior unpushed local identities `e616c6ffd741af9d7e76b7741fb09bffc8b286ce`
  and `b85cfe89673a9f6a56c658281ba98f1df427afc4` are **UNRECOVERED historical
  attempts**, not the source or evidence for this new result. Their old reported
  test counts and unavailable logs are not credited to this reconstruction.

## Changes and scope

The route registry now derives existing known negative primitive premises from
pinned sources. Original P3 unrestricted-compressor collision resistance and an
independent leaf/branch function model are refuted; actual pruned-MMCS binding
remains OPEN. Its conditional estimator input is not a raw-compressor security
bound. Tagged SHA3 retains the documented observe-boundary and consumed-output
count omissions without inferring a fixed W1 forgery or transcript injectivity.

DKTZ Revision 1 Theorem 5.22, printed page 50, allows a prime power base but
requires a full-field/hyperplane evaluation-domain cardinality divisible by its
characteristic. The fixed routes have odd characteristic and multiplicative
two-adic domain cardinalities coprime to it. The check excludes only that
necessary direct-domain match. Padding, restriction, other results, complete
FRI/list-size soundness and reachable trace sizes remain open. The formal
statement was read in the earlier full document-reader review; no fresh PDF
byte digest or independent full theorem proof verification is claimed here.

Assuming four iid uniform normal-form base draws, the fixed first-nonzero/mask
sampler has exact law `(1-p^-4)U_(2^b)+p^-4 delta_0`, and single-query TV
`p^-4*(1-2^-b)`. Assuming independent query blocks additionally gives coupling
upper bound `1-(1-p^-4)^k <= k*p^-4`; it is not exact product TV. Reports use
exact reduced rational arithmetic for saved `b=20`, declared maximum `b=26`,
and `k=50`. Actual Poseidon2 iid behavior, adversarial or quantum conditioning,
joint-oracle soundness, extraction and lifecycle bounds remain unproved.

## Exact-source validation

| Scope | Actual completed result |
|---|---|
| Route suite | 28/28 PASS |
| Field suite | 16/16 PASS |
| New conditional sampler suite | 7/7 PASS |
| Retained receipt replay suite | 13/13 PASS |
| CI contract suite | 168/168 PASS |
| Source-integrity suite | 43/43 PASS |
| PQ corpus suite | 57/57 PASS |
| Original named proof-chain roster | 69/69 successful controls |
| Preflight, repository/link, corpus, inventory and three report commands | Exit 0 |
| Cargo metadata | Could not launch: Cargo executable absent; OSError retained |

The original named roster includes the separately reported replay suite; counts
are not added into a unique global test total. There are 16 recorded commands:
15 exited 0 and one could not launch. Native Rust graph/build, formatting,
strict Clippy, new STARK proofs, recursive execution and resource acceptance
were not established. Rust cryptographic sources, locks, wire formats and
admission rules are unchanged. The original historical replay test file and
69-name roster remain byte-identical to the parent. New sampler commands run
once in repository-truth, with independent negative-command controls.

## Preserved unsuccessful observations

An initial shared clone from another local partial Git repository exited 128:
Git could not obtain missing promisor/lazy objects. A fresh direct filtered
clone succeeded. The message mentioning possible corruption is Git's generic
failure text; this observation does not establish repository corruption.
Several interrupted tool dispatches returned `aborted before dispatch`; they
were not treated as completed edits or tests. The full retained receipt fixture
was available and identity-checked in this reconstruction; no missing-fixture
failure from the lost earlier attempt is attributed to this new execution.

Parent hosted CI is not new-head evidence. #849's required baseline and QROM
implementation/closure failures remain historical failures; #850's split of
historical/current implementation lanes does not discharge lifetime closure or
cryptographic obligations. This reconstruction changes none of those original
failure records and does not imply hosted CI success.

All 15 historical obligation IDs remain. One manuscript-version correspondence
sub-obligation had been recorded closed; zero complete security obligations are
discharged and all eight implementation interfaces stay OPEN. Actual security
bits and lifetime bounds remain null, and production/consensus flags false.
