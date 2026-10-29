# Native PQ quota closure continuation, 2026-10-28

## What this changes

The first actual NPQ3 four-case Node run reproduced a real migration failure:
three cases passed, while a valid same-profile imported-account CLAIM failed at
pool submission with `PQ2_ENCODING`. The migration apply owner decoded its raw
command with the public NPQ2-only decoder after the preceding NPQ3 signature and
state checks. The fix uses the existing configuration-selected strict decoder.
The NPQ2 entry remains NPQ2-only; no input negotiation or downgrade was added.

The new controls additionally execute provider rotation with a stable provider
account, actual consumer registration with both same-block order refusals,
and parent-only resolution of a newly reserved quota. Rejected inner signatures,
wrong consumer/provider accounts, retired keys, replay, fees and unit bounds
retain the exact input State. The native capacity case admits 71 full dual-proof
commands through five original M05 pool bundles, complete W1 producer and
independent reference verification, SQL activation and a cold read. Each frame
has 7,314 bytes: 71 occupy 519,294 bytes and 72 occupy 526,608 bytes against the
unchanged 524,288-byte budget. The 72nd pool submission and 72-command block are
refused without spending; the accepted block preserves the consumer account,
advances the provider nonce to 71 and leaves 290 of its original 1,000 units.

Strict Clippy also found an inherited manual saturating subtraction in migration
and three avoidable single-element clones in quota tests. Those exact failures
are retained; equivalent `saturating_sub` / `slice::from_ref` changes remove the
warnings without suppression or altered acceptance bounds.

## Evidence and limits

Final executed targets:

| Target | Passed | Original ignored cases |
| --- | ---: | ---: |
| M00 complete unit target | 46 | 2 |
| M06 complete unit target | 88 | 6 |
| NPQ3 dual quota authority | 8 | 0 |
| Retained NPQ2 authority capacity | 2 | 0 |
| NPQ3 native Node | 5 | 0 |
| Retained NPQ2 native Node | 9 | 0 |
| Retained PQ1 native Node | 6 | 0 |

There are **164 distinct passes** across these seven targets. All **30 integration
cases** ran with zero ignored or filtered substitutions. The eight ignored unit
cases are the original explicit long-running/measurement cases; they were not
executed or relabelled. The exact readers accept 21 actual NPQ3 complete-call
phase records and 196 retained NPQ2 phase records. Six direct source Clippy targets
pass with warnings denied. Formatting, source inventory, 34 source-integrity
negative controls and five quota observation-reader controls also pass.

The final source was compiled using real Rust 1.95.0. Current M00, M01, M06 and
Node production libraries were rebuilt; source snapshots, explicit compiler
arguments, 223 immutable external artifact hashes, raw terminal logs and actual
native binary hashes are retained. Other workspace and third-party artifacts
were read from the original compiled dependency tree. This is a component
native linking experiment, **not a fresh full Cargo build or all-targets Cargo
qualification**. Multiple compiled versions of unchanged shared workspace
components may coexist in this explicitly linked graph. The exact locked,
offline Cargo graph was separately resolved, with 173 packages, 26 workspace
members and unchanged Cargo.lock. Metadata does not establish compilation.

The [summary](summary.json) states each actual result and its scope. The
[raw observation archive](observations.json.gz) preserves original failures,
all per-command source/link-input hashes and later passing observations.
[Final native output](native-quota-final.log) records every NPQ3 case and all 21
complete-call phase rows. [First native failure](native-quota-first-failure.log)
is retained separately. The [test binary](native-quota-test.bin.gz) is the actual
final native target, with public fixture seeds only. Phase times are wall-clock
observations on a shared host, not isolated CPU, energy, worst-case or TPS bounds.
The [validation helper](run_frozen_native.py) records the explicit component graph;
it is not substituted for the dedicated Cargo qualification workflow.

The original source freeze was from `376f3a7d707f616ba694d297830da35e7d4bd35f`
plus eight then-uncommitted trusted-migration paths. Those exact bytes were
subsequently committed by the prior owner as
`0fc50c0701e0bfc94faa8c48df5957956cc6b8a3`; this continuation uses that commit as
its parent and retains its original evidence. The provenance records demonstrate
that taking that parent did not overwrite any current source edit.

Local pool ordinal/removal history is retained across chain forks. Chain account
key generation and provider nonce can return to an earlier valid branch; actual
pool reauthorization remains required. The controls do not turn chain rotation
into a permanent off-chain revocation registry.

## Remaining acceptance boundaries

The complete dedicated Cargo lane and all-targets/all-features strict Clippy are
still required on the published source. The initial fresh Cargo test command
was stopped at the shared capacity boundary; no passing result is attributed to
it. Direct warnings-denied source Clippy results are separately identified.

NPQ3 still covers tags 1–5, account REGISTER/ROTATE/CLAIM, and quota 10–11.
Contribution, evaluation, release, reward and work-registration authority owners
(tags 6–9 and 12–24), transport, service, governance, custody, History permission
and Hepta final use remain outside this closure. Trusted migration requires
independent prior-PQ registry trust, final source checkpoint selection and source
retirement evidence; the real source-Node checkpoint fixture does not prove
those premises. Positive imported quota/release liabilities remain explicitly
refused. No old store or live network is upgraded. Physical I/O, whole-chain PQ,
P1 completion and production activation remain false.
