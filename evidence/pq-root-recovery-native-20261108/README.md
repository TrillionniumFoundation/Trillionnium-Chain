# Root recovery V2 exact-source component evidence

**HOLD / NO-GO.** [PR #813](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/813)
continues #806. These receipts cover the implementation commit
[`aa7ba29a5485a6b04ccb909e34bb3d8ae2528669`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/aa7ba29a5485a6b04ccb909e34bb3d8ae2528669),
tree `15c3a8c10b7406ec9919fa5f36d2f3a1dbba1833`, with base
`0788c44f4139c74772a8a9d7d475821f56e5b727`. The evidence delivery commit adds only
this directory; it does not change the tested implementation or transfer these
native results to a new combined owner/deployment source.

The [machine summary](summary.json), [environment](committed-aa7ba29/environment.json),
[source before](committed-aa7ba29/source-before.json) and
[source after](committed-aa7ba29/source-after.json) retain exact identity and
scope. Before/after records are equal: **11,282 tracked entries and
1,116,951,243 tracked bytes** were independently checked against Git objects.
All implementation upload blobs and the complete GitHub tree matched the local
source before the remote commit was fetched and tested.

## Actual native and structural execution

| Suite | Passed | Receipt |
| --- | ---: | --- |
| Real root signatures | 14 | [native-00.log](committed-aa7ba29/native-00.log) |
| Real provider receipts | 6 | [native-01.log](committed-aa7ba29/native-01.log) |
| Real durable SQLite journal | 14 | [native-02.log](committed-aa7ba29/native-02.log) |
| Signature structure | 17 | [static-05.log](committed-aa7ba29/static-05.log) |
| Provider structure | 15 | [static-06.log](committed-aa7ba29/static-06.log) |
| Original V1 policy model | 26 | [static-04.log](committed-aa7ba29/static-04.log) |
| Lifetime checker | 58 | [static-01.log](committed-aa7ba29/static-01.log) |
| Default native crypto library | 165 | [rust-06.log](committed-aa7ba29/rust-06.log) |
| Default release library | 43 | [rust-07.log](committed-aa7ba29/rust-07.log) |

The three native suites execute actual pinned OpenSSL **3.5.7** with temporary
real keys and no successful crypto substitute or skipped native test. Their
34 tests are distinct across those three suites. Structural checks remain
separately labeled. Individual subcases are not added to the test denominator.
The Rust library runs are complete for their named default-feature `--lib`
selectors, not full Node/workspace runtime acceptance.

The journal campaign takes 246.735 seconds including process setup. These are
shared-host elapsed observations, not a root throughput benchmark, matching-cost
public-node budget test, or original four-second acceptance.

All **20 static commands** passed. Named suites also retain 49 claim controls,
18 authority/effect controls, 15 authority scanner controls, 55 PQ source
negatives, 107 CI contract controls, 9 provider CI controls, 43 raw-source
negatives and 50 repository negatives. The corpus has 737 pinned paths; local
Markdown validation covers 3,749 links. No cross-suite total is advertised as a
security bound.

## Original failed build and exact-source correction

The first three groups execute 31 commands: native **3/3**, static **20/20**, and
Rust **7/8**. [The original Clippy failure](committed-aa7ba29/rust-05.log) is retained.
The explicit `OPENSSL_DIR=/usr` caused openssl-sys to search `/usr/lib64` and
`/usr/lib`, whereas this host's installed libraries use the Debian multiarch
path `/usr/lib/x86_64-linux-gnu`.

The [corrected Clippy command](committed-aa7ba29/rust-clippy-multiarch.json) uses
that installed library path and `/usr/include`, on the **same exact commit**, with
the same locked/offline workspace/all-target/all-feature command and `-D warnings`.
It [passed](committed-aa7ba29/rust-clippy-multiarch.log). No source, dependency,
feature selection or budget was changed. The original Rust group exit remains
1; the corrected gate is recorded separately, rather than rewriting that run.
Default/all-feature/fuzz graphs and formatting also passed.

## Rollback and provider interpretation

The native journal suite deliberately covers opposite outcomes:

- Full owner database/journal rollback with a retained anchor is refused.
- Full **owner plus anchor** rollback accepts the restored valid operation after
  genuinely signing a fresh challenge. This is the retained indistinguishability
  counterexample. It does **not** close independent rollback qualification.

The fixture has distinct root/writer/anchor/provider keys on one machine. It
proves neither independent operators/devices nor independent recovery custody.
Provider signatures authenticate declarations. They do not establish an actual
payment, API call, resource expenditure, or compensation in an independent
service. `not-applied` means terminal non-execution/cancellation in the contract.
A current caller-supplied height remains a research trust input.

Pending-before-CAS, exact-target resumption, nonce/revocation persistence,
reorganization liability, one dispatch, and expiry/rotation/revocation checks at
entry are exercised without changing deployed state. The old M15 ML-DSA-65 and
SHA-256 owner path remains separate. Full production integration and all eight
actual lifetime bounds remain open.

## Raw records and reproducibility

[Native commands](committed-aa7ba29/native-commands.json),
[static commands](committed-aa7ba29/static-commands.json) and
[Rust commands](committed-aa7ba29/rust-commands.json) retain argv, source, duration,
exit status, raw log size and SHA-256. The two runner files preserve the exact
local campaign commands and paths. Native verification requires operator-chosen
OpenSSL executable, SHA-256, version and prefix pins; absent pins fail.

[storage.json](committed-aa7ba29/storage.json) maps original log names to stored
files. Only logs larger than 256 KiB are compressed with deterministic gzip.
For these, decompress the named `.gz` file and verify `raw_sha256` and `raw_bytes`
from the map/command record. Both compressed and decompressed hashes are retained.
All other logs are stored byte-for-byte. [SHA256SUMS](SHA256SUMS) covers archived
files; checksums are corruption checks, not independent provenance or a PQ proof.

The preliminary directory preserves the two fixture API startup failures
(before real native tests executed), the first CI diagnostic-order failure, and
the first 11-test unfrozen journal campaign. Those preliminary logs are not
claimed as evidence for this exact committed source. Existing #796 failures
and original system/Host/CPU/custody/production gates remain unaffected.
