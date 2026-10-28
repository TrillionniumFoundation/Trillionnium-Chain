# Completed research evidence: W1, legal-ticket costs, and public campaigns

This evidence-only increment retains completed observations. It does not run a
new solver experiment, change a proof verifier, relax a campaign predicate, or
claim that the parent branch's new Succinct implementation has passed its native
gate. Each result below belongs to its own exact source and workflow run.

## Source and outcome boundaries

| Observation | Exact source | Original run | Actual outcome |
| --- | --- | --- | --- |
| Complete frozen W1 Composite proof | `febf622c7e4e919ad2ee4e0864230ab572f5d5b4` | `40611562747` | Both continuation shards and assembly succeeded; complete receipt and all 62 claims were independently read back. |
| Legal-ticket V4 x86_64 and aarch64 | `7e3543f8817d019975ae578b56b4997eb92bc422` | `40619573406` | Both original native jobs succeeded; the two original artifact ZIPs are retained byte for byte. |
| Original public campaign, W1 candidate | `303afe7a4581e67117bff135eed5892232aabb70` | `40616722050` | All original baseline, from-zero, and late-product predicates passed in all three campaigns. |
| Original public campaign, PQ candidate | `29e1f194742e436b44b4c8758777341e62fe2bd8` | `40614010338` | Failed the actual-credit-depletion and overlap predicates in all six hostile phases; the failure is preserved. |

The W1 proof preserves the original proof semantics with no extra proof PoW.
The separately reported public transport campaigns used their original
`ticket_bits = 8` policy. These are different measurements and must not be
substituted for one another.

## Complete W1 receipt and observed costs

The four receipt parts concatenate to 15,862,780 bytes, SHA-256
`f816a6265004ae1f35c75add10268687e9afd996d8e1eaee9ddc4efa815d32d5`.
The full SDK verification took 855,614,899 ns. The slowest rejection among the
17 measured invalid cases took 821,908,140 ns. Receipt-only local TCP transfer
took 181,903,647 ns, and the measured two verifications plus transfer took
2,048,281,335 ns. These are observed cases, not a proof of a global worst-case
bound or a WAN benchmark.

The 73 non-overlapping outer phases consumed 20,658.740713 CPU seconds, including
duplicate builds, controls, and export work. Continuation plus assembly consumed
18,992.254422 CPU seconds. Accounting that also includes the prior failed window
is 32,885.624191 CPU seconds; including the earlier V1 rejection is
32,887.072672 CPU seconds. This was continuation from the 26 frozen original
receipts, not a new from-zero proof. Nested measurements must not be added twice.

The complete receipt and 1,041 small original members are retained here. The
104,925,197-byte original assembly ZIP was independently read and verified but
is not retained in this increment. Its identity and the exact retention scope
are stated in `../pon-w1-complete-febf-20261028/manifest.json`. The earlier,
different complete receipt and its original archives remain in the parent
history. Neither receipt is a production-size 49,188-byte PNW1 certificate.

## Legal-ticket V4: actual admitted-ticket denominator

Each architecture used 12 cohorts: two rounds, two legal methods, and 1/2/4
actual workers. Each architecture recorded 768 searches, 1,638 attempts,
876 misses, six exhausted searches, and 762 first admissions to fresh stores.
There are only 127 distinct fixture ticket IDs shared across these cohorts and
architectures. A repeated fresh-store admission is not a new network reward.

The following values divide each pair of rounds' complete measured phase costs
by its 127 actual first admissions. All 14 non-overlapping phases are included,
including shared setup, failed attempts, durable packet archival, serialized
native admission, close, and cold reopen. Process CPU is measured once for the
concurrent batch; overlapping worker wall times are not counted as CPU.

| Architecture | Method | Workers | CPU ms / admitted ticket | Wall ms / admitted ticket |
| --- | --- | ---: | ---: | ---: |
| x86_64 | general | 1 | 8.663303520 | 11.494020488 |
| x86_64 | general | 2 | 8.535451858 | 9.003882866 |
| x86_64 | general | 4 | 8.987837173 | 11.465082819 |
| x86_64 | split | 1 | 8.610680575 | 12.107841866 |
| x86_64 | split | 2 | 8.583115717 | 12.016102835 |
| x86_64 | split | 4 | 8.966779102 | 10.335425646 |
| aarch64 | general | 1 | 13.886288630 | 14.953966898 |
| aarch64 | general | 2 | 13.820620031 | 13.633487661 |
| aarch64 | general | 4 | 13.867739213 | 13.246628937 |
| aarch64 | split | 1 | 13.799267843 | 14.470106890 |
| aarch64 | split | 2 | 13.824920000 | 13.676746945 |
| aarch64 | split | 4 | 13.851331087 | 13.687791764 |

The observed CPU minima are x86_64 general with two workers and aarch64 split
with one worker. The wall-time minima are x86_64 general with two workers and
aarch64 general with four workers. Two repeated rounds on shared hosted CPUs
do not establish statistical significance, a global cheapest solver, energy
cost, GPU/ASIC performance, all special matrix families, or hardware attestation.
Native admission accounts for about 81% of the complete CPU cost and limits the
end-to-end benefit of faster generation. Producer-only advantages must not be
reported as the same percentage of complete admitted-ticket cost.

The original V4 ZIPs contain the actual native executable and all 762 winning
packets for each architecture. All 780 members in each ZIP passed CRC and
identity checks. Packet-byte inspection separately bound the ticket ID,
challenge, target, header, nonce, and complete proof digest. That inspection is
not an additional native execution; the original hosted Node admission is the
native acceptance observation. Missed-attempt full proof bytes were not retained.

The small V4 package records its earlier freeze-time retention status. This new
index records the subsequent successful retrieval and preservation of the two
original ZIPs; the earlier document has not been rewritten retrospectively.

## Public-campaign difference remains a failure on its own source

The paired reader recomputes all 18 original phase predicates and the paid-CPU
flow from the raw records. On source `29e1f194`, all six hostile phases admitted
21 honest blocks, rejected 3,819 of 3,840 full-work requests, and retained matching
client/receiver state and clean actor termination. They nevertheless failed
actual credit depletion and depletion overlapping a confirmation round.
Minimum observed credit was 0.882--1.478 seconds against the original 0.1-second
predicate; paid CPU was 7.002--8.575 seconds.

On source `303afe7a`, all six hostile phases met the original predicates. Minimum
credit was 0.0324--0.0371 seconds and paid CPU was 9.394--9.397 seconds. The
two campaigns shared the policy hash and original budgets, but differed in
source and hosted CPU model (EPYC 9V45 versus EPYC 7763). This is an observational
comparison. It does not isolate code or hardware as the cause. No threshold,
round count, worker cap, original timeout, or test ignore was changed.

Both complete original campaign ZIPs, including the failed run, are retained in
four-MiB parts. `../pon-original-campaign-paired-20261028/campaign-criteria-comparison.json`
contains the per-phase predicate and paid-flow recomputation. Its paths, raw
digests, and exact source bindings remain auditable.

## Exact-source CodeQL export

The separate `../codeql-a99-export-readback-20261028/` package retains the
original artifact for source `a99ef8e333b6f1b7486b33e820464cf824fec273`, PR #533,
export run `40623893027`. The original exporter completed in 740.911364 seconds
within its unchanged 1,200-second budget. Actions, Python, and Rust analyses,
the actual GitHub source check, and stable pre/post-export identities were
independently checked. This is not an analysis of the evidence branch or any
other runtime candidate.

The API SARIF subset reports 322 warnings: 316 in test/fuzz locations, five in
examples, and one at the runtime CLI output. The examined runtime flow includes
owner-hash account-tree traversal and account/state query output; no private
signing-key source was established in those reported flows. The package retains
every warning location and the limits of the review. Check success does not
mean zero repository alerts, full historical alert coverage, or an authenticated
verdict on every PR gate. The earlier failed export remains in its own history.

## Reconstruction and integrity

`raw-archive-index.json` lists complete archive sizes, SHA-256 digests, ordered
part paths, byte offsets, and each part's SHA-256 and Git blob identity. Join
parts in the recorded order and verify the complete digest before opening an
archive. Do not infer part order from an unordered directory traversal. The
small readback packages retain the readers and selected original observations.

`publication-content-manifest.json` inventories this increment's other files,
including the exact CodeQL package, both V4 original archives, and the local
readback of their subsequent retrieval. The complete parent tree's 14 workflow
definitions were read: its only push trigger is restricted to `main`. This new
evidence branch has no pull request and changes none of the proof workflow's
trigger paths. `workflow-trigger-readback.json` retains that check.

This increment changes only evidence paths. The parent is the independently
verified `bfdb557412204244e43fef2007c31e20c9c8e5ff` tree. Existing failure records,
mandatory gate definitions, original resource floors, and all runtime source
files are unchanged. New Succinct, History, PQ, and Hepta native runs continue
to require their own exact-source results.
