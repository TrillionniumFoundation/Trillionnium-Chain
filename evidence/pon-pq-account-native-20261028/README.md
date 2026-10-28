# Native PQ account continuation — 2026-10-28

Status: **candidate source under validation; HOLD / NO GO**. The parent checkpoint
is `48aaeddb1ab5115169cb1bc8d80647888bba3d2d`. This is new source and new execution,
not recovered historical commits. The [bounded account contract](../../docs/security/PQ_NATIVE_ACCOUNT_OWNER_V1.md)
states the actual authority and remaining migration gaps.

## Preserved observations before the final candidate

| Attempt | Actual result |
| --- | --- |
| `m06-initial.*` | Compiler rejected the new private command at the original qualified-task lifecycle's `Envelope` interface. No native tests ran. The failure is retained. |
| `m06-second.*` | Fixed original lifecycle seam; real M06 tests passed 5/5 in 0.51 s, compile/run wall 25.757 s. One private-interface warning remained and was subsequently fixed. |
| `node-build-first.*` | Actual Rust 1.95.0 / OpenSSL 3.5.9 build succeeded in 140.075 s. Exact emitted executables and source manifest are recorded. |
| `node-native-first.*` | Actual Node executable ran 7 tests: 5 passed, 2 failed, 0 skipped, 0 timed out. The branch fixture omitted the existing explicit activation call. The TCP fixture's response was negative; inspection also found that its unchanged installed genesis was 1,800,000,000 (2027-01-15), later than this actual run. The first assertion did not print the response error, so that specific error is not reconstructed. |
| `cli-canary-first.*` | The actual newly built CLI passed its original canary: 2 normal client, 2 normal server and 2 error paths; 1/1 test, wall 6.137 s. No private raw/hex/half-hex canary appeared. This does not close all CodeQL flows or make the CLI post-quantum. |
| `clippy-7acad-first.*` | Exact committed source `7acad34a46f63208448b4dbdf0624548f64f6405` failed whole-workspace/all-target/all-feature strict Clippy on three test-only clone-to-slice lints. No lint allowance was added. |
| `cross-import-prepatch.*` | An added actual native regression against the pre-fix owner **failed as required to expose the bug**: the same real ML-DSA QTX1 applied in two different import genesis/parameter contexts reusing one declared network. The raw event records both genesis and parameter IDs and `foreign_transaction_applied=true`. Build/run wall 51.624 s; test execution 0.27 s. The complete source manifest and added regression patch are retained. This is a real local replay counterexample, not a quantum computation. |

The next candidate fixes the test's activation call and binds an explicit genesis
timestamp into the migration protocol identity, exact parameters and resulting
native genesis. It does not suppress the original future-time rule. It removes
the draft's miner-roster restriction: work qualification remains pure PoN and a
reward address gains no automatic signing authority. Additional tests compare
real Rust QTX1 signatures, body, identity and fee with the existing Python oracle,
and exercise mature PoN rewards to an address outside the migration roster.

All tests use disposable development keys and stores. Native M06 execution never
calls the Python/OpenSSL CLI oracle; that subprocess is confined to independent
reference tests. All real native signatures use in-process OpenSSL EVP.

## Source provenance correction

The previous reconstruction report incorrectly said the baseline CLI `main.rs`
was absent from the embedded source table. A fresh bounded extraction of the
surviving ELF verified offset 10,704,803, length 124,046, SHA-256
`4a790ce3f4cefaa11bc59165845da17bdf3a83269b7d32681db1a9a8135f8d5c`,
Git blob `13eaca34f2fe3b46b25d387836f978a38168e40f`, and equality to the committed
baseline. [The correction receipt](main-source-provenance-correction.json)
retains the ELF hash and hashes of both old reports. The newer CLI's changed
source remains unrecovered; the present opaque-key/error-boundary implementation
is expressly new work. No old recovery archive was overwritten.

## Replay and migration adversary follow-up

The repair derives the actual signed native network ID from the declared PQG1
namespace, complete native parameter identity, verified source digest and target
genesis. The same cross-import refusal test remains a required post-change run;
no completed native receipt for that run has been observed. Imported addresses
retain the old PQG1 projection domain, while the QTX1 network binds the complete
new execution context. No caller Boolean can grant another network's transaction.

A separate newly written control gives its adversary the published old fixture
keys and selects different real ML-DSA keys. Its native execution also remains
unqualified. At the authorization level, an old-key holder can produce both
signatures with their own chosen new key; only the
independently pinned target projection/genesis distinguishes the authorized
mapping. Thus dual migration signatures do not repair a quantum-compromised old
identity. An old balance snapshot without a previously authenticated target key
mapping is insufficient. No quantum hardware or forgery computation is claimed.

## Acceptance boundaries

Transfer-only import does not complete WP3. Every original liability is retained
and locked, but its future settlement is not migrated. Public account creation,
rotation/revocation/recovery, task authorization, Cell/model installation, Hepta
FinalUse, source-history authenticity, physical antirollback and independent WAN
remain open. A new native transfer test result cannot turn any release flag on.

Final exact-source build, regression, strict Clippy, formatting and integrity
results will be recorded below with their actual outcomes; the initial rows do
not qualify later edits by inheritance.

## Recorded interruption and exact-source result

On source `e6429b9a226ac43682f11ecb5f760ef0243c35a7`, the complete locked/offline
workspace Clippy command with all targets/features and `-D warnings` completed
successfully in 86.800480401 seconds. Its original receipt and output are retained
in `clippy-e642.record.json` and the adjacent stdout/stderr files. Source bytes
were unchanged across that command; it was concurrent with W1 proving and is not
an isolated performance benchmark.

The execution agent was then stopped by an automatic safety check reporting a
possible cybersecurity risk. The native build has no completed process receipt
and no Cargo `build-finished` message in the retained output. A CLI compiler
artifact message alone cannot qualify the complete native build or any native
regression. The pre-fix cross-import failure, unfinished build output and source
snapshot remain retained. No post-fix native PASS, full account migration,
production activation or whole-chain post-quantum acceptance is claimed.
