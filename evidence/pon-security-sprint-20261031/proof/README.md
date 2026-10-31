# Complete W1: public-claim rejection and immutable verifier context

This is a bounded receiver improvement using the existing, genuine 62-segment,
15,862,780-byte Composite receipt. The original valid proof still verifies.
Public-claim mismatch can be rejected before segment cryptography. Public claims
that remain consistent still require the unchanged complete SDK verifier. No new
proof was generated, and worst-case invalid-proof cost remains **OPEN**.

## Source and acceptance boundary

The base is `7da4964d02b42076996e89a78d13f68572d33be5`. The native output embeds
17 exact source inputs; both independent readers matched their lengths and hashes
against this candidate. This was a sparse checkout, so these observations do not
attest every tracked file in the entire repository. The pinned Cargo lockfile,
guest, full relation, image ID, statement/witness domains and resource caps did
not change.

The new `PreparedVerifier` has private fields and a constructor that computes and
checks the locally pinned ELF image, disables development receipts, and derives
fixed SDK Composite and segment parameter digests. It accepts no miner-supplied
image or parameter configuration. Reuse retains only that immutable verifier
context. It does not cache receipt authentication, work, trace, or claim outcomes.

Before cryptography, it checks aggregate claim equality against the exact pinned
image and complete expected journal; every nonfinal segment must have the SDK's
required SystemSplit/no-output/unpruned-post conditions and matching continuation
state digests. These are necessary conditions already enforced by RISC Zero
3.0.6 after or between segment authentication. Every successful new call still
executes the same `Receipt::verify_with_context`. Therefore a successful original
strict verification satisfies these prechecks, and a successful new verification
still satisfies the original strict profile and full SDK verification. Only
rejection order changes; matching unauthenticated claims grant no acceptance.

The comparison route deliberately uses this same candidate executable, prepared
strict profile and original SDK order. It is **not** a reconstructed measurement
of every instruction or process cost in an older host executable.

## Actual paired observation

One observation per route/context/case on a shared x86_64 host, using Rust 1.95.0
and the locked release graph. The real positive prerequisite warmed the runtime.
“Fresh” means a newly created pinned context, not cold hardware. The receiver
clock includes optional context creation, bounded decoding, strict profile,
public predicates when selected, full SDK when reached, and owned-object drop.
File I/O, statement binding, prerequisite, mutation construction, hashes, JSON,
error formatting and process startup are excluded. No statistical confidence,
exclusive-host performance or service qualification is inferred.

All values below are receiver milliseconds from `public-claims.stdout.log`.

| Case | Original SDK order, fresh | Claims first, fresh | Original SDK order, reused | Claims first, reused | New route enters full SDK |
| --- | ---: | ---: | ---: | ---: | --- |
| valid | 1165.263 | 1312.480 | 1261.054 | 1213.709 | yes |
| outer_journal_rebound | 1236.987 | 19.878 | 1242.833 | 3.971 | no |
| late_link_tamper | 1208.462 | 20.873 | 1140.130 | 4.031 | no |
| late_nonfinal_exit | 1139.578 | 24.397 | 1116.967 | 3.775 | no |
| matching_claims_corrupt_seal | 1146.234 | 1185.568 | 1130.768 | 1550.887 | yes |
| coordinated_public_claim_forgery | 1113.962 | 1184.664 | 1176.148 | 1169.097 | yes |

Shared prepared-context setup was 21.774 ms; setup for individual fresh contexts
was separately measured in each row. The real positive prerequisite took
1,164.600 ms, including its decode and complete verification.

The coordinated forgery changes the miner-bound statement, outer journal and
terminal public output claim together, leaving the real seals unchanged. It
passes the public predicates, enters full SDK verification, and fails. The other
expensive negative changes the final seal while leaving public claims matching.
These controls are why the early-rejection gain does **not** close expensive
rejection. The native host verifies a real positive before running any mutations.

## Executed checks and retained limitations

The locked production host build passed. The original real-proof audit passed
its positive and all 16 negatives. All eight original `audit-one` cases passed
with independent readers. The new paired audit passed all 24 observations and
its independent reader. Python fixture controls passed 39 tests; original reader
controls passed 15 and the new reader passed 8. Rust formatting and diff checks
passed. The reader validates metadata, complete-statement binding, and compiled
source hashes; it does not independently verify a STARK, reconstruct these SDK
claim mutations, authenticate runtime timing, or grant consensus authority.

At the initial checkpoint, the 21 Rust host unit tests and strict Clippy had
**not run** because the shared disk reached zero. After space became available,
all **21 native host tests passed**, strict release/locked Clippy for host and
relation with all targets and `-D warnings` passed, and formatting passed on
committed source `b0e3da2b3c9b5d60e1515af4ef908a544d1f4762`. No source fix was
needed. The follow-up process records retain actual results; `checkpoint.json`
preserves its original pending state and `verification-followup.json` supersedes
those two pending gates. The four new Rust tests were now actually executed.
The exact native-test stdout is losslessly retained as `host-tests.stdout.log.gz`;
its accompanying binding pins the original uncompressed bytes.

`committed-source-inputs.json` also matches all 17 inputs embedded by the already
frozen executable against exact Git blobs of that commit. It explicitly records
that compilation preceded the commit and does not attest the whole sparse tree
or external dependency source files. The frozen native executable was retained
before deleting only this lane's disposable build target; shared SDK sources,
other lanes' targets, original fixture and all native observations were preserved.

The first baseline build actually completed, but its executable was lost during
an earlier authorized cache cleanup before any native use. Both that successful
build and the candid cleanup correction remain here. They supply no baseline
runtime measurement. Candidate attempt 01 failed on a missing offline crate
archive; attempt 02 failed to reach the inherited proxy in the sandbox; the
retained authorized proxy retry (03) built successfully. No failure was relabeled
as proof acceptance or hidden behind a fallback.

The candidate executable has SHA-256
`123cb1717d23a1c685f43929909f161f70171664da5e41e85f4f9feb7e2cb3f8`
and is 6,042,000 bytes. The before/after records match. Its immutable local copy
was retained at `/tmp/pon-proof-sprint-observations/candidate-verifier`;
the repository retains the source bindings, raw observations, process records
and executable digest, not another committed binary. The original durable proof
objects remain in the existing fixture directory and are not duplicated here.

## Reproduction

Use the exact standalone locked backend and original durable fixture loader.
After building and freezing the executable, retain the original `audit` and all
eight `audit-one` controls, then run:

```sh
python3 "$BACKEND/test_check_claim_audit.py"
python3 "$BACKEND/measure_step.py" --out "$OUT" --name public-claims --timeout 180 -- "$OUT/verifier" audit-claims "$OUT/fixture/guest.bin" "$OUT/fixture/input.bin" "$OUT/fixture/receipt.bin"
python3 "$BACKEND/check_claim_audit.py" --record "$OUT/public-claims.stdout.log" --input "$OUT/fixture/input.bin" --receipt "$OUT/fixture/receipt.bin" > "$OUT/public-claims-readback.json"
```

This is receiver engineering for the standalone research host. It adds no main
node integration, proof-generation practicality result, admission guarantee,
minimum-work theorem, chainwork authority, or post-quantum security qualification.

## Later hosted verification of the published implementation

The [completed 2a69 W1 job](../integration/2a69-hosted-readback/w1-receiver-124412661337/README.md)
now retains exact published-source execution independently of the local lane
above. It passes 21 native host tests, strict release/locked Clippy, the complete
historical proof and 16 mutations, eight cases, and 24 paired public-claim
observations. Full source-before/after guards agree. Its own single-observation
timings remain distinct from this earlier host's timings; claims-consistent
invalid proofs still cost approximately 1.21–1.23 seconds to reject. The
historical Composite fixture is unchanged, and this run does not generate a
new proof or qualify the native node admission path.
