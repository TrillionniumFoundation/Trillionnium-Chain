# W1 V5 original Actions artifact readback

This packet preserves evidence reading and arithmetic verification of existing native executions. It records no new native W1 execution, rerun, source change or production activation.

Both head jobs in run 43147686753 completed all 66 declared V5 shards on source 229b14c2d366a257f51f287d502a550df2332338, tree b386c32458589f81944ddd69c04a56c28c55e284. The ARM64 job is 130949245425 / artifact 13917333858; the x64 job is 130949245331 / artifact 13917828728. Each original ZIP contains 220 files: all 440 file CRCs and complete byte hashes were checked. The independent readers exited zero; their original command/exit receipts, output and stderr are retained unchanged.

Each architecture has 11 material classes, 17 preregistered arms and eight cohorts. There are 44 cost cells (class × two targets × H1/H8) and 22 controls. Each original campaign counts 8,976 preparations, including 3,696 unsupported probes, 17,600 searches, 274,647 physical attempts, 17,845 physical hits, 256,802 misses, 880 exhausted searches, 3,204 speculative attempts, 170,344 materialized proof buffers and 73,288 verifier calls. Counts repeat matched strategy streams and are not independent lottery samples or unique business effects. Physical postwinner hits do not create additional accepted winners.

The complete per-cell tables retain every fixed arm and its support state, preparation selection, full producer CPU/wall totals, setup, misses, speculation, cleanup and teardown. Cost comparisons use ratio of sums within one architecture/class/target/horizon/arm, without per-sample fastest selection, controls or H1/H8 pooling. The per-cell minimum among measured aggregate arms is descriptive, selected after the samples: it is an achievable-cost observation, never a global cheapest-strategy proof or an attacker cost lower bound. Zero-winner and unsupported comparison rates stay null. Eight cohorts do not establish confidence bounds or hardware independence.

Fixture/material and scalar-reference construction, observation/hashing, full-verifier work, inclusive cohort intervals and outer wait4/observer costs remain separately visible. Inclusive clocks are not added to their components. Separate clocks do not eliminate cache and allocator effects in the shared process. The reader reconstructs declared commitments, checks records and recalculates arithmetic; it does not independently execute all W1 mathematics or authenticate physical clocks. Production security and whole-chain qualification remain HOLD.

V5 emits setup and search journal records only after that work completes. These successful complete-grid readbacks therefore do not qualify interruption or cancellation accounting for work interrupted before emission. Exhaustion-control misses are not replayed by both full verifiers in V5; do not inherit that different coverage from newer zero-paired V1. Winner, mutant and declared postwinner verifier checks retain their exact original scope. `independent_w1_math_replay=false`; no repeated native executions or all-algorithm closure is claimed.

## Contents and reproduction

- `arm64/` and `x64/` retain successful readbacks, actual exit receipts, zero-byte stderr and original metadata bytes. `original-zip-members.json` identifies every original file. Each original ZIP is preserved once as ordered parts of at most 4,194,304 bytes; `original-zip-parts.json` binds each part and the full original. Concatenating the listed parts reproduces the byte-identical ZIP; verify full length and hash before extraction.
- `helpers/review_artifact.py` is the actual executed helper copied byte-for-byte, together with its three actual pinned imports. The original exit receipts retain their earlier absolute command paths. After reassembly/extraction, run `python3 helpers/review_artifact.py EXTRACTED_ROOT --zip ORIGINAL_ZIP --arch arm64` (or `x64`) to repeat the evidence readback. This command runs Python readers, not the retained native ELF.
- `full-cost-grid.json` contains all 17 arms in all 44 cost cells per architecture. `t1-h8-tables.md` is a compact 11-material view per architecture; `numerical-summary.json` retains exact input identities and outer observation costs. Both complete original readbacks retain all controls as well.
- `packet-manifest.json` identifies every packet file except itself. Its integrity is separate from native execution or security qualification. `build-packet.py` records this new packaging/arithmetic operation; it does not replace or reconstruct an original execution receipt.

## User-requested strategy coverage

| Strategy class | Evidence in these V5 artifacts | Remaining boundary |
| --- | --- | --- |
| Zero, sparse, low-rank, diagonal, short-column padding | Synthetic zero; rank1/2/4/8 left; rank4 right; rank9 explicit fallback; full rank; sparse diagonal; one-zero rank1. Original winner/mutant and declared postwinner production/reference checks retain their exact scope. | Exhaustion-control misses have no dual full replay; real short-column task provenance and general nonfixture demand are not established. |
| Preparation across nonce, miners and epochs | Actual paid preparation reused across H1/H8 searches on fixed A/B; full challenge-dependent transcript work retained. | No cross-miner or cross-epoch ownership/cost qualification; correlated horizons are not pooled. |
| GPU/ASIC, shared cache and early screening | Native x64 and ARM64 CPU implementations; batch4 charges worker spawn/join and all completed speculation. | No GPU/ASIC measurement, shared-cache campaign or general early-screening bound. |
| Omit failing proofs | Lazy arms retain complete losing attempts while constructing proof buffers under the declared policy. | No proof that these arms are globally cheapest legal strategies. |
| Cheap fake transcripts and expensive receiver rejection | Original verifier/control observations remain in the ZIPs; this V5 cost grid measures the declared legal producers. | No production public-inbound rejection-service/liveness qualification. |
| Attacker-chosen tasks, sponsor self-traffic and repeated reward | Synthetic task choice is explicit and all task/challenge/stream identities are retained. | No independent authorization, real demand, sponsor anti-self-traffic or unique settlement/reward qualification. |
| Maintenance without real tasks | `continuity-maintenance-v1` is an explicit measured synthetic material class. | It does not establish real useful demand or complete maintenance economics. |

Under independent uniform inclusive 256-bit tickets, p=(T+1)/2^256. The empirical grids do not prove this assumption. Shared preparation, failing attempts and winner-only costs must be charged at their actual reuse/ownership scope. The ESA 2026 asymptotic conjecture does not supply a finite-parameter lower bound for this concrete 64×64 profile.

## Per-file size cap and reconstruction

Every final packet file is at most 4,194,304 bytes. Oversized standalone metadata copies are preserved as ordered raw parts described by large-file-parts.json; their original path, complete length and SHA256 are bound. The new packet duplicate monoliths were removed only after byte-identical reconstruction validation. All external original artifacts/readbacks remain untouched. packet-manifest-initial.json retains the initial packaging observation and its historical file roster; packet-manifest.json is the current packet roster.

Use python3 reconstruct-parts.py large-file-parts.json NEW_EXTERNAL_DIRECTORY to reconstruct standalone metadata. Use the same helper with arm64/original-zip-parts.json or x64/original-zip-parts.json and a separate new directory to reconstruct the original ZIP. Verify the resulting full length/hash before extraction. The compact T1/H8 tables still include both CPU and wall for all 11 materials on each architecture.
