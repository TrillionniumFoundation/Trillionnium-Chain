# P0–P6 integrated W1/W2 admission research candidate — 2026-10-26

**HOLD_NO_GO / SHADOW_ONLY.** This is a source-tree integration, not a
runtime, cryptographic, production or independent-operator qualification.

## Exact merge ancestry, without replacing parent evidence

The integration is rooted at Chain #335 commit
`db0dad68f0909460e8b1cf0c248d8bab4b59c129`.
Three previously isolated, DRAFT children are combined without rewriting
or dropping their original commits:

- **#340:** `563a8c982106dc38880f4a8cbaf37f4f89fa9cb4` —
  original Node CPU-domain charging in pinned-peer W1 replay, including
  M06 workers and fail-closed unknown post-settlement;
- **#342:** `e55107450eb1a1f051a6c98101f3f88b7afa8f91` —
  fixed administrator-owned cgroup verification on externally sourced
  History sync and public source-bound importer;
- **#339:** `f06ccc809ebd7f553a55d5a54af1ba80e6523126` —
  isolated receiver-bound, MACed, short-lived W2-C admission research
  and counterexamples.

Their changed file paths were checked pairwise **disjoint**, and exact
GitHub blob SHAs were preserved in the combined tree. This is not a
claim that the independent PRs have been individually accepted or merged
into `main`. The integration touches neither W1 proof semantics nor
target/chainwork nor Hepta final-use nor any production activation flag.

## Explicit attack surfaces still needing qualification

1. **P0:** Existing four distinct forged transcript vectors continue to
   require exact Rust W1 refusal, no VerifiedWork, no state or chainwork
   increase and a cold-reopen check. The Python/Go oracle comparisons do
   not replace the native receipt.
2. **P1:** Pinned-peer polling now requests the Node's *already bound*
   `public_service_cpu_domain`, while native/CLI outbound History sync
   separately demands the actual fixed `trnmponpublic.slice` kernel parent
   for nonloopback endpoints. The kernel parent is a **physical aggregate**
   bound and not itself the V3 per-request CPU budget. No claim of the
   two resources being identical is made: they are complementary.
3. **P1 residual:** The public `receive_page_from(node, source: SocketAddr,...)`
   is guarded according to its caller-supplied **address**, rather than
   network-derived provenance. A malicious embedding caller or a remote
   connection forwarded through loopback can claim a loopback source.
   Therefore source-address gating is NOT a complete trusted capability
   boundary for all transitive callers. A future enforced import capability
   or a fail-closed host policy at every untrusted embedding entry is needed.
4. **P2:** The Python cost studies measure synthetic local CPU; valid
   Hashcash prepayment does not establish GPU/ASIC or honest-client
   economics. A second receiver must pay a separate ticket in #339,
   but the receiver still pays much more W1 CPU on one forged transcript.
5. **P3/P4:** Identity churn, spent token replay, bad-StateRoot after
   *valid* W1, M06 costs and 3 modes × 3 complete A03 runs × 3 timely
   client-confirmed honest rounds remain whole-system obligations, with
   all Busy/timeouts/unknown measurements counted.
6. **P5:** W2-A admits deliberately corrupted unsampled tiles; W2-B
   replays the full computation and has no succinct proof; W2-C adds
   separate work that can be replayed globally unless scoped per receiver.
   None is a qualified or activated W2 consensus replacement.
7. **P6:** Internal Rust/Python/Go authored implementations are not an
   independent external cryptanalytic acceptance. Third-party adversarial
   soundness and actual multi-operator review remain mandatory.

## Mandatory follow-up checks on the actual combined SHA

Run `bash scripts/project-preflight.sh` in an exact checkout, audit
applicable source-integrity controls, compile and execute the new Rust
selectors for pinned peer, remote sync, W1 original false cases, run
cross-language differential oracles and repeat physically bounded A03
without weakening its acceptance test. Measure the full host cgroup
counters and original V3 CPU account independently; their numbers
must not be added as independent CPU spend. Unknown data, incomplete
runs and tests not run remain **UNKNOWN / OPEN**, not PASS.

**Important:** The conversation tools presently provide GitHub source
editing but no access to the user's dot host or complete remote source
checkout. This document records exact work and missing evidence, not
a fabricated local preflight or CI success.
