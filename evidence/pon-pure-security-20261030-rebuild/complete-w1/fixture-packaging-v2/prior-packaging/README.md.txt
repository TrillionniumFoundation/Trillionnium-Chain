# Complete W1 receiver audit rebuilt from actual historical proof bytes

This directory records new execution from the `540d72356a921da31dde1113537382e5c0f0c4fd`
integration baseline. The previous local `bb358a91` workspace and its measurements
were unavailable after the environment changed. Their logs, binaries and timings
are not reconstructed or presented as recovered evidence here. The historical
proof bytes were downloaded again and verified against their existing pins; the
host was rebuilt and every result below was newly executed.

This is a research receiver observation. No prover or guest execution ran, no
new proof was generated, no complete native W1 replay is credited to the receiver,
and no `VerifiedWork`, admission, chainwork or release authority is granted.

## Delivered changes and source scope

The standalone host refuses inconsistent header task/target and zero target
before opening an untrusted receipt. Its guest, complete W1 relation, pinned
image, original strict verifier, receipt bounds and proof-production limit are
unchanged. The additional `audit-one` command accepts only eight fixed cases.

Every case must first pass actual verification of the original real proof.
Its encoded receiver then uses the original bounded preflight/SDK decoder and
strict verifier, and includes decoded-receipt destruction in receiver timing.
The positive prerequisite warms the verifier and is separately timed. Case
construction, expected-journal/context preparation, file I/O, source and byte
hashing, error formatting, JSON output and process startup are outside that
receiver timer. The separate process records include the complete command.

The native records embed 15 direct source, manifest and lockfile hashes. All
match [source-before.json](native/source-before.json) and
[source-after.json](native/source-after.json). The exact executable is retained
as gzip with a checked decompression in [executable.json](executable.json):

```text
SHA256 9fb009fbfe142fa9ed50de713bdd3ae57eba8568457981b6c8dd0388e6bd3755
Bytes  5983776
```

These runs used an uncommitted candidate; they do not claim a whole clean Git
source guard or execution on the later publication commit. Process records
therefore keep `source_sha: null`. Compiler and shared-host details are in
[environment.json](environment.json). The enclosing Git commit identifies the
delivered source; [delivered-source.json](delivered-source.json) binds the lane's
source files and durable fixture objects. This is not a reproducible-build proof.

## Actual validation

| Check | Result | Retained record |
| --- | --- | --- |
| Locked release host build | Passed | [process](native/host-build.process.json), [log](native/host-build.stderr.log) |
| Final release host tests | 17 passed; none failed or ignored | [stdout](native/host-tests.stdout.log), [process](native/host-tests.process.json) |
| Host/relation, all-target release Clippy `-D warnings` | Passed | [process](native/host-clippy.process.json), [log](native/host-clippy.stderr.log) |
| Actual context refusal before receipt I/O | Positive missing-file control and three invalid contexts behaved as required | [report](context-integration/report.json) |
| Original real-proof audit | Positive verified; all 16 original negative controls rejected | [raw result](actual-cases/original-audit.stdout.log), [process](actual-cases/original-audit.process.json) |
| Eight uniform receiver cases | One valid accepted; seven invalid refused | [summary](actual-cases/local-summary.json) |
| Independent metadata reader | All eight real records bound to actual bytes/source; 15 hostile metadata controls passed | [control log](logs/reader-controls.stderr.log), per-case binding files in `actual-cases/` |
| Bounded historical fixture reader | 26 controls passed | [control log](logs/fixture-controls.stderr.log) |
| Explicit object and ZIP restoration | Both passed on the final reader | [object process](fixture-restoration/objects.process.json), [ZIP process](fixture-restoration/archive.process.json) |
| New workflow syntax | YAML and all eight shell blocks passed | [syntax record](workflow-syntax.json) |

The initial context-only checkpoint's 14 passing host tests are retained
separately in `first-context-checkpoint/`; they are not added to the final 17.
The first default-network download failed with `URLError`; that
[failure](download-failure.json) is retained. Recovery then succeeded through
the existing proxy with the exact [download hash and byte count](download.json).

### Receiver observations

These are individual observations on a shared host with `RAYON_NUM_THREADS=2`,
not medians, worst-case bounds, cold-start costs or performance guarantees.

| Case | Receiver milliseconds | Observed outcome |
| --- | ---: | --- |
| Valid | 1332.826232 | Verified |
| First seal tampered | 57.424247 | Verification failed |
| Last seal tampered | 1187.393954 | Verification failed |
| Wrong segment verifier parameters | 30.613254 | Verification failed |
| Wrong statement miner | 26.058207 | Verification failed |
| Truncated receipt | 0.014742 | Malformed encoding |
| Trailing receipt byte | 0.016314 | Malformed encoding |
| Seal length allocation bomb | 0.005468 | Refused without evaluation |

The last-seal case still takes about 1.19 seconds to reject. An attacker can
reuse a public proof and corrupt a late seal; the original honest proving cost
cannot be charged to each submission. This experiment does not close the
cheap-submission/expensive-rejection problem or establish public honest service.
It does not replace the different historical 256,886-byte Succinct proof and
its size/time experiment, nor establish a speedup against a lost local run.

The independent Python reader checks exact types, limits, direct source hashes,
input/receipt hashes, mutation bytes, claimed journal and timing consistency.
It does not cryptographically verify a STARK, independently recover SDK seal
or parameter positions, authenticate reported timings or establish execution
provenance by itself. Those limits are explicit false fields in every reader
binding. Its synthetic unit records are metadata controls, never valid-proof
fixtures or empirical results.

## Durable historical fixture

The source is artifact **12784520070**, run **40608715148**, historical commit
`a54dc7355f58f40784b5a71fe7e73c4062a14951`. The 80,366,759-byte ZIP was recovered
and its SHA256 checked:

```text
bae22e7fab8f5475dc396a4225292f90e582a92558fecf1710e30da0b0d76ecc
```

The original [input and guest manifest](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/a54dc7355f58f40784b5a71fe7e73c4062a14951/evidence/pon-w1-session-continuation-20261027/original-artifact.json)
and [receipt assembly job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40608715148/job/122567159292)
remain the historical provenance. The raw assets have the original hashes:

| Asset | Original bytes | SHA256 |
| --- | ---: | --- |
| `guest.bin` | 291,592 | `b8f32cd9c1b1edbb0cde04acf9aab146b7ff1aeeeaee0188e4d6e80d077b0c0a` |
| `input.bin` | 49,640 | `4babd290b10f7a68be27c2adf3b97448bb7bef04dba8bcb97f914acf4ac69020` |
| `receipt.bin` | 15,862,780 | `0a5336a797c51829ed25d4ec2f1a03f4f56fda4c737a230b493d4abbe96f0ec8` |

The [object manifest](fixture-objects/manifest.json) and three deterministic gzip
files retain the assets in this repository, using 14,032,963 compressed bytes.
These are newly packaged gzip objects over the recovered original bytes; their
compressed hashes are not claimed to equal the missing prior packaging.
The case-cost CI workflow explicitly selects `--objects`, uses only
`contents: read`, and does not depend on artifact expiration or a download token.

The loader permits exactly one source and no automatic fallback. Object mode
checks its exact canonical manifest, regular-file descriptors and identities,
compressed lengths/hashes, a single bounded gzip member, and original lengths/
hashes before creating output. It refuses extra entries, symlinks, FIFO inputs,
truncation, trailing bytes, multiple members and excessive expansion. ZIP mode
separately checks the whole fixed archive, canonical member names, byte budgets
and exact root assets. Object mode explicitly leaves
`historical_zip_verified_this_run` false; neither loader mode verifies a proof.

## Remaining acceptance obligations

Open-network intake, global minimum effective work cost, task/hardware and
precomputation advantages, practical complete-proof economics, and quantitative
quantum security remain unqualified. This host remains separate from Chain
admission. No independent Hashcash gate, alternative work identity, reduced W1
relation, stake/quality weight, BFT fallback or activation is introduced.
