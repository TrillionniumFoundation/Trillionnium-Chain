# Six-axis throughput continuation, 2026-11-06

Status: development candidate; original service, long-history, independent
acceptance and production gates remain **HOLD / UNQUALIFIED**.

This continuation starts from integration
`513e92dfc27044ef3e0c9d62e7ae504fa5bea38f` and composes the complete
[#736 throughput candidate](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/736),
`9eda0ada15be1702269e08e527917568c710f4d3`. The local composition commit is
`a303f71e7`. Its only conflict was the exact-source inventory; it retains the
current packaging compatibility test and both historical bridge fixtures.
The inherited raw evidence is preserved byte-for-byte, including its whitespace.
Historical executions are not executions of this new combination.

## Work boundaries

| Priority | Existing owner and this continuation | Acceptance boundary |
| --- | --- | --- |
| 1. Incremental state and ancestry | Compose #736's completed-history suffix reuse within the same checked writer scope; reuse the Growth header SQL program while freshly binding and reading each row. | New scopes, ordinary full-state reads and cold audits still perform their required full checks. This does not add a cross-snapshot validity cache or a PNP2 ancestry index. |
| 2. Stateless preparation and ordered commit | Keep the existing bounded M06 1/2/4/8 worker preparation and canonical state owner; reduce repeated immutable PQ configuration preparation within one entry call. | Current key, generation, nonce, balances, expiry, conflicts, rewards and final root remain owned by canonical apply. |
| 3. Hostile-load scheduling | Add bounded shared-domain ordering at the existing mutation start-reserve gate. | Only already dequeued tasks gain ordering; no peer identity preference, extra credit, worker or deadline. Verified complete W1 retains its prior priority. |
| 4. Host and recovery cost | Preserve #736's checked Host directory descriptor and all five fresh limit-file reads; retain current authority/frontier/recovery checks. | No successful authorization, resource limit or recovery verdict is cached. |
| 5. Large-object transport | Preserve the existing independent Cell data plane and its bounded verified transfer contracts. | Whole-host CPU, storage and network isolation during simultaneous consensus and Cell load remains unqualified. Complete W1 proof validation is unchanged. |
| 6. Complete costs | Include PQ client pin preparation in the original call duration; reject invalid native clock values in report readers while preserving unknown values. | Inclusive and overlapping process/thread/setup samples are not added into a fictitious total. Missing network/recovery/remote costs remain unknown. |

The changed scheduling contract is explicitly **r15**. Raw r10--r14 and
arithmetic r13/r14 policy vectors remain readable as historical identities;
current native clients and Host harnesses select r15 and cannot relabel an old
signed cookie as the new schedule. CPU refill/burst, start principal, live worker
count and each workload's original absolute deadlines retain their values.
Ordering applies after dequeue/registration. Continuously queued public work
can keep immediate local miner/operator `begin()` calls refused; this is not
general fairness across those classes or a four-second service guarantee.

PQ client deadline precedence is explicit: if its caller-supplied outer deadline
has already expired at entry, `PUBLIC_CLIENT_DEADLINE` is returned before public
key expansion, even for an invalid pin. With a live or absent outer deadline,
an invalid pin still returns `PUBLIC_CHALLENGE_SIGNATURE`. Both failures retain
actual construction/total elapsed time and the Construction failure stage.
The original implicit 30-second network interval still starts after construction
when no outer deadline was supplied; the expanded elapsed sample does not change
that contract into a 30-second whole-call bound.

## Fixed business gates

No resource ceiling, proof relation, task input, original timeout, confirmation
depth or failure denominator is relaxed. Preserve the original four-second
business-completion gate and 4,105-block cold-sync/reopen/corrupt-index test.

Keep distinct workload identities: the original 16-attacker service test, the
three-phase native campaign's declared 0/24/24 attacker processes, and the
separate F0 baseline/ROOT experiment are different measurements. Acknowledgment,
registration, component success and a late confirmation do not satisfy a timely
independent confirmation.

The [inherited source-bound throughput record](../pon-throughput-20261106/README.md)
retains the failed original campaigns and F0 results. The
[ordered execution record](../pon-ordered-request-cost-20261105/README.md)
retains its own failed Node tests, original interrupted Growth observation and
unknown CPU accounting. This continuation does not overwrite those observations.

## Validation record

Implementation and exact-source command receipts will be recorded here after
the candidate is frozen. A successful source check is not a native test or a
service qualification. Every reported native command must bind its own actual
commit, tree, Cargo profile/features, compiler, raw log and terminal exit.
