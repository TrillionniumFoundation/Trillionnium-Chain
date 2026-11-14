# Production nonce-prefix proposal: reachability, semantics and measured scale

## Finding

The nonce loop is real production client code. A small intra-call SHA-256 prefix reuse is algorithmically possible without changing any ticket, wire byte, nonce, bit target or verifier. Existing original traces, however, put the entire attack-client solve interval at only about 13.7 ms per pressure phase. This is a qualified component proposal, not an adequate or measured four-second repair. No implementation, native run, hosted run, project test or source mutation was performed.

## Real production reachability

Three non-fixture callers select the same ordinary client: main.rs::public_pool_call_before at line 955; peer_polling.rs's runtime RPC closure at line 816; and public_submit.rs's bounded recovery call at line 237. Their immutable blobs and excerpts are bound by the source-input index.

The production chain is call_public_protected_v3[_with_metrics/_with_deadline] → call_public_protected_v3_with_profile → call_public_authenticated → call_public_authenticated_with_timing → the existing measure_solution_search closure at public_v3.rs 3814–3835. The ordinary public Submit, Head, History and pool client operations share it. It is outside the cfg(test) helper starting at line 3917. The original pressure fixture calls these production APIs; no change to its Client, caller identity construction, workload or request generator is proposed.

## Exact hash contract and smallest change

The current server/client winner at 613–615 calls pon_wire::hash with tag public-ticket-v3 and parts [32-byte cookie ID, 8-byte little-endian nonce]. The first ten magic bytes, u16 little-endian tag length, 16-byte tag, u32 little-endian cookie length and cookie ID total exactly 64 bytes. The remaining u32 length and u64 nonce add 12 bytes. SHA-256 therefore processes two padded blocks for the original 76-byte message.

Inside one solve only, a lazily initialized unfinalized SHA-256 state after those exact 64 bytes could be cloned per trial. Each clone appends the exact original nonce length and nonce, finalizes, and applies the same big-endian first-u32 leading-zero test. The original server winner stays unchanged and can be an independent implementation oracle. This is not a global cookie cache, precomputed ticket or cached acceptance.

Smallest proposed scope: one existing Rust file, one private helper, and a local Option<Sha256> in the production solve closure. The held prefix is created only at the first existing winner evaluation. No public API, dependency, lockfile or signed resource-profile change is required. The policy-prefix proposal remains separate and unimplemented.

Proof obligation: after consuming the same exact 64-byte message prefix, the cloned state must retain the same SHA chaining state, byte count and buffer. Appending the same 12 bytes then gives the same digest for every cookie and nonce. Reusing SHA256(prefix) as a finalized digest would not satisfy this equation.

## Error and deadline order

The proposed implementation must keep cookie.id()? first. For every original nonce divisible by 256 it must then perform the outer deadline check (when supplied) followed by the policy-lifetime check, in that order. It must then assign solution_trials = nonce + 1 and only then evaluate the candidate. Lazy prefix initialization belongs at that evaluation; hoisting it before the first deadline check would change the work performed before a refusal.

Keep the 0..1_048_576 enumeration, first successful nonce, break, PUBLIC_SOLVE_BUDGET exhaustion, original clock origin, every-256 check frequency and measured CPU interval. Keep all later signing, writes, response verification and final deadline checks. Faster execution can change how many trials fit before a real deadline; this proposal claims the same check locations and logical ordering, not identical time-dependent outcomes.

The exact current r20 resource-contract literal and its policy ID stay untouched. Its original no-new-deadline/worker/credit rules, lane/grant/output/body reservations and complete work-key behavior remain intact. The 1,048,576 packet-byte token in the signed contract is distinct from the nonce-loop cap in the source. Neither is to be altered.

## Original pressure measurements

| Original C0 pressure trace | attack calls | all recorded trials | actual solve-CPU records | solve thread CPU | whole attacker-thread CPU |
|---|---:|---:|---:|---:|---:|
| x64 cross-cost | 335 | 80,522 | 332 | 13.658895 ms | 354.481431 ms |
| arm64 cross-cost | 476 | 118,806 | 470 | 13.737288 ms | 337.787584 ms |

The three/six calls without a serialized solve-CPU field all have zero recorded trials. The missing CPU values remain missing, not fabricated zero values. Every positive-trial call in these originals has a measured solve-CPU field. The successful response.solve_trials values are a subset of metrics.solution_trials and were not counted again.

The metric explicitly includes cookie identity, complete search, failed trials and the return/error tail. It is nested within the whole attacker-thread measurement, so those columns must not be added. The sum is not an estimate of removable work. Prefix reuse still performs one SHA block per trial, cloning, all checks and bookkeeping.

The 16 workers are closed-loop clients. Making their ticket generation cheaper could increase pressure requests within the same window. Consequently a local reduction in per-ticket compute does not prove an end-to-end improvement. The original 4 seconds / 16 workers / quarter-CPU Host conditions and acceptance test remain the only relevant acceptance conditions.

## Source pins and focused validation if later selected

Because the only prospective runtime change is public_v3.rs, the same pin-impact closure documented in candidate-impact-final-v1 applies: current PQ21 lock/register, its strict composition metadata/literals, actual corpus OIDs and accurate current mapping documentation. Authority44, current-lifetime20, QROM six-crate closure, root46 and the 21/46/1/66 union counts do not change solely for this source edit. A new real source checkpoint must precede its metadata mapping; no new source bytes may be attributed to dc42/M5.

Any implementation review should retain the unchanged server winner as a full-message reference; use original-byte golden digest vectors across zero, nonuniform and maximum cookies/nonces; test first winning nonce and exhausted ranges; and independently check original checkpoint/error order and CPU-counter placement. Existing ticket/profile/refusal controls and all fixtures remain intact. This report does not run or replace those controls.

## Is there a larger evidenced optimization now?

No adequate one is established. In the decisive x64 original W1 interval, fresh Host CPU is 78.779013 ms within 82.609255 ms of calling-thread W1 CPU. The difference is not a pure arithmetic benchmark, and there is no basis to remove required per-progress dynamic checks. Held signing keys/public strings, Submit's exact-envelope fast path, scoped openat/stack reads and the already-removed adjacent Host repetition are present in current source.

Classic reactor challenge signing and caller verification remain outside the paid mutation CPU intervals and are explicitly not covered by current V4/V5 CPU flags. Repeated pure Cookie serialization/key parsing offers only unmeasured bounded candidates. No existing switch exposes the missing classic-reactor interval. Selecting a larger change from those intervals would require the separately reviewed diagnostic engineering already described in the prior sealed report; no cache/observer API or extra run has been introduced here.
