# Receiver-verified history and current confirmation evidence

Measured implementation: `ed4d95c3e558ad28b5f3132152704bdf77df5f49`.
Measured tree: `a19ecaa4745236753d89b7e6be8de4a9f2156954`.

The [qualification](qualification.json) was executed on this clean source. The original
[manifest](manifest.json) and raw logs are copied byte-for-byte from that run, not made
by repinning old model observations. Later publication and checker tests are separate.

## Executed scope

- 1801 native tests, 15 documentation tests,
  the separately invoked ignored helper, locked/offline release examples, strict
  all-target/all-feature Clippy and formatting passed.
- 35 client cases passed with the reference backend;
  35 cases passed with explicit native work and eight-worker
  native application execution. These are two configurations, not twice as many unique cases.
- Every page is bounded before expensive admission. The receiver verifies real work,
  signatures, target, execution roots and transaction membership using its existing Ledger.
  Interrupted delivery retains only verified prefixes and resumes by block-hash cursor.
- Complete locally verified ancestry is reobserved against the receiver's clock, including
  ancestors below inclusion, duplicate pages and empty terminal pages. A prior logical-clock
  import cannot become a current wall-clock confirmation. Observation cancellation grants
  no cached currentness; later observations still check the complete branch.
- Genuine competing work, restart/resume, missing or changed bodies/proofs, forged peer
  work totals, invalid continuations, stale confirmation and both client backends ran.

This is a full-verifying reference client with native compute components, not a succinct
light client or complete native consensus/persistence/P2P host. A local observation does
not prove global freshness, eclipse resistance, deterministic finality or execution permission.

## Evidence and remaining boundaries

All five preceding evidence manifests remain unchanged and retain their measured source.
No model training, future task window or independently administered evaluation was rerun.
Source-object bootstrap includes the exact qualification runner and its immutable inputs.
The publication mutation suite runs separately in the existing external-evidence-contract
job; its checks are not retrospectively inserted into this runtime qualification.

Python dependencies were NumPy 1.26.4 and cryptography 41.0.7.
The preparation copied already-installed matching public packages and the cffi dependency
into a new owned environment after download stalls; system installations were not changed.
Cargo dependency preparation preceded the locked/offline qualification. Preparation
timeouts and unavailable-cache probes are not passing or failing runtime test results.
Temporary filesystem: `ext4   /`. Process/filesystem
regressions do not establish physical controller power-loss safety.

Work hardness, hostile public proof admission, independently administered operation,
long-term availability, ordinary Hepta ownership, future model benefit and a complete
native host remain separate obligations. Unmeasured VRAM, live inclusion and public
client-confirmed throughput remain null. Production/public-testnet activation stays false.

## Retained qualification failure and repair

The [first full attempt](failures/initial-qualification/qualification.json), source
`9ba2129c4f6eb1e88e78c3a490a329f57016c13b`, passed native and both client configurations
but failed the historical E3 source-omission counterexample. Component mode had accepted
an omitted original runtime binding as though it were a newly added unmeasured file.
The original failed manifest and logs remain unchanged. The checker now derives the
complete original runtime inventory from the measured Git tree, never from a possibly
edited receipt. Deleting a transitive model input or Cargo.lock also rejects. The entire
qualification was then executed again on the repaired commit into a new output directory.
The earlier failed attempt is not included in the successful command/test counts.

## Publication selector correction

The initial publication checker incorrectly treated three local callbacks nested inside
real client test methods as separate unittest cases. The collector's 35 cases per backend
and their raw logs were correct and remain unchanged. The checker now selects direct
VerifiedHistoryTests methods only; regressions retain every direct case and exclude local
callbacks. The separately executed 23-case publication suite also rejects forged scope,
missing source/commands, invented measurements and stale responsibility navigation. None
of those publication checks is inserted retrospectively into the measured runtime report.
