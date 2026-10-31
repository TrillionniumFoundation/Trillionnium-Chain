# Hosted no-attacker confirmation lateness

Evidence-only readback of source `cf84391a474ee1f3ac78f4a907bd95184b816a54`, hosted run `41155114590`. No new execution or post-fix qualification. Original 30-second pressure window and 2-second transport deadlines are unchanged.

## Exact x64 baseline cause

`campaign/pressure-native/baseline.json` records seven successful submissions, seven successful History RPCs and no verification errors. Native `observation.confirmed` is **true**: depth 6, included/observed heights 5/11, work delta and required work both hexadecimal `0c` (12), policy `installed-depth-and-required-work`. Reorged, finalized and execution authority are false.

| Event | Time relative to phase epoch (ns) |
| --- | ---: |
| Round start | 1,000,152,562 |
| Seventh Submit ends | 2,447,785,492 |
| Seventh History RPC ends | 23,386,645,219 |
| Seventh independent import starts | 23,387,974,673 |
| Original deadline | 30,000,000,000 |
| Seventh independent import ends | 36,373,479,919 |
| Successful native confirmation starts | 36,376,171,354 |
| Successful native confirmation ends | 36,570,648,643 |
| Round ends | 36,571,404,988 |

The seventh independent import takes 12,985,505,246 ns by its recorded timestamps and crosses the deadline. Its recorded process CPU is 3,249,567,956 ns. Different CPU/wall scopes do not attribute their gap to a scheduler, quota, syscall or competing process. Confirmation itself takes 194,477,289 ns by phase timestamps. The evidence localizes the overrun to the independent import interval, not a narrower internal bottleneck.

The Python reader computes derived `confirmed` from native flags, depth 6 **and `round.ended_ns < WINDOW`**. Its false value is correct. `on_time_history_and_independent_verification` requires a History RPC within its original deadline and successful, ordered import/confirmation ending no later than the round end. It does not require that local verification finish within the phase window. Hence it can be true while derived confirmation is false. The Rust fixture independently checks the same phase deadline.

This observation is not a missing-depth/work, reorg, conservative-risk or new-block-timestamp rejection: the native predicate actually succeeded after all seven blocks were already submitted. The finite campaign nevertheless fails correctly.

## Other baseline observations

The x64 fresh-caller baseline has native confirmation true but round end 36,770,843,277 ns. ARM64 pure pressure confirms its first round at 20,449,440,252 ns, then ends its next round at 30,046,569,967 ns without a native observation. ARM64 fresh-caller confirms its first round at 20,475,448,221 ns and ends its next incomplete round at 30,059,385,437 ns. These are separate machine observations, not a controlled architecture-speed comparison. Exact reports are retained without JSON reserialization.

## Separate from-zero reader remains ambiguous

Run `41155114648` protocol-contract and both architecture-cost jobs each show five named native tests passing, then `CONFIRMATION_TARGET`. Their raw `confirmation/report.json` is absent from the three locally downloaded archives. Existing provider logs in the sibling `cf843-hosted-readback/provider/` directory retain jobs 124400083149, 124400083244 and 124400083251; advertised artifact IDs and ZIP hashes are recorded in `observations.json` for later retrieval.

`validate_confirmation_report` uses `CONFIRMATION_TARGET` for any required true flag: document finite/invariant/same-packet flags, phase finite/invariant/confirmation/overlap/state flags, or native confirmed. This separate fixture has an unchanged **4-second** window. Its native test asserts safety/accounting invariants while recording finite service success separately. Passing that named test plus this generic reader error does not identify the failing phase or flag. Available evidence cannot establish that its attack-free phase missed its deadline, lacked depth, or failed another predicate. The proven 30-second explanation above must not be transferred to this distinct report.

## Relationship to the current repairs

The MTP correction affects ordinary `run_pool_mining` readiness. This campaign prepares signed business packets with `make_consensus_maintenance` before the pressure phase, then submits those packets and imports History. Its observed lateness is orthogonal to that scheduler correction.

The strict fixed client chooses `receive_public_page_from`; native `receive_page_from` calls fresh `kernel.verify()` around and during replay. The kernel allocation optimization therefore affects a relevant code path, but does not establish that it closes this 6.57-second overrun or all rounds. An isolated quota-read measurement cannot qualify whole-import, whole-round, public fairness, or post-fix campaign success. Such claims require a separately retained run under unchanged complete predicates.

## Provenance

`manifest.json` binds each losslessly gzipped exact ZIP member to its artifact ID, URL, original archive SHA-256, member name, byte length and SHA-256. The original archives were hashed and compared with existing hosted readback bindings. Every gzip was decompressed and compared byte for byte. `observations.json` is a compact derivative. `source-excerpts.txt` was read directly from the pinned commit, with complete source file blob IDs and SHA-256 hashes in the manifest.

No existing hosted-readback evidence, native source, workflow, plan or deadline was modified. No build, native rerun, remote write or new large-artifact download was performed.
