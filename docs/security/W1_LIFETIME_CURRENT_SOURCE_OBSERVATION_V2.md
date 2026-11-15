# W1 lifetime: separate historical reproduction from current observation

Status: **HOLD / NO-GO**. No lifetime bound or cryptographic qualification is
created by this source-survey continuation of #850.

## Selected source correspondence after ordering review, 2026-11-14

The active 20-path contract selects
`5c04c60e463462d9df8884786e0d5bb32af08a64`; its SHA-256 is
`bd22f0db32c479dd7d42ae541eeed0ad0c1115d40b88b01d07acefd25930fbb7`.
The selected store is 391,470 bytes with SHA-256
`5918270368c61b420d26910dc5934714e1423f71c686b2d01f8d2e3ccceb990c`.
The preceding FC39 selection is retained below as historical context and is
superseded following the readiness/epoch and same-row work/time review.
The ordered roster, frozen historical hashes, eight changed-path comparison
and every lifetime/qualification limitation remain unchanged.

The current QROM report correspondence still permits exactly provenance
lock fields 0 and 2, for the verifier and zkVM locks. Guest lock field 1 and
all other values remain identical. The older zkVM-only description and the
382,866-byte store describe their historical checkpoints.

## Historical corrective source binding, 2026-11-14 (superseded)

The superseded contract selected `fc39da5f35298ce8a4c34aa5bdb25849648612f9`,
tree `20ef410a1ea847a3585de91d5f0a0380009cf874`, with the same
ordered 20-path roster and the same 20 historical SHA-256 values.
Its SHA-256 is `ed9d948a4815aa2fdd858acdcda104341ab96fb504a15e761c86ae04d6547c63`.
All 20 current inputs were independently read from the immutable Git
checkpoint and compared with the checkout.

Only Node `store.rs` changes from the preceding `5c04c60e` mapping:
391,470 bytes / `5918270368c61b420d26910dc5934714e1423f71c686b2d01f8d2e3ccceb990c`
become 391,556 bytes /
`ae54afb15c78e20b5fbb80c89d2a7346aafb2c20e6a1bf665663adc422625da5`.
The historical-versus-current difference list still contains eight paths.
The current reader's fixed contract digest and independent positive assertions
move together. The frozen `7150d96a` reader, original pins and source refusal,
arithmetic evaluator, bounds and all null/false qualification outputs remain
unchanged. No historical execution or lifetime failure bound is inferred.

## Original failure and preserved contract

On exact #850 source `3898582a321471fc2a6945b37ff4d0cd58c7a255`, hosted
[closure run 42645116454](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42645116454)
failed on head and prospective merge. Its original lifetime test class failed
in setup before executing any tests, because the V1 source survey rejected
the changed `store.rs` identity. Reproduction separately returned the same
refusal. Other named suites ran; a later completion refusal did not replace
the missing lifetime tests. #850's implementation workflow separation did
not repair this distinct closure workflow.

The historical ledger, its 20 pins, original lifetime tests, original closure
runner, original 105-name roster and seven saved reports remain unchanged.
The historical job now checks out the known original positive closure source
`1a14f7d4826363daefac9ec10131c66d7e70ece7`. Its positive result applies only
to that source. Current jobs must separately retain the real historical V1
refusal; raising a byte limit or silently replacing its pin is not a repair.

## Retained combined-source binding, 2026-11-13

The contract at that retained checkpoint selected `332d7f723d71707d88a2cffa52b3754579a46926`, tree
`c93086b354d75827ca96a42c7eaa3f8be8954311`. Its 20 regular-file inputs
were read from the immutable Git revision and matched to the isolated checkout.
Compared with the previous current checkpoint `975ab0937243949b73cdbea9f13902802bbd7d00`,
only `formal/pon-nakamoto-v1/quantum_oracle_resources.py` changes:
28,132 bytes / `23a2f810685e5f352b3cc4b7b9e8b8ab76d6208122d7e2379ee9c9d51edf849a` become
29,812 bytes / `3768567c5e2905c90ef766a9ff4e1ff625e14fd7614aede108ae81df000a6049`.
The source now rejects inconsistent gate counts, depths and live-wire widths
for both circuit stages and serial totals. These are necessary arithmetic
conditions for one declared schedule, not circuit verification or a physical
resource lower bound. The current contract SHA-256 is
`66aaee2e08e666f32a106832274703d8c9c9fa6be9882ddc45017882c66be96b`.

Exactly six of the 20 selected paths differ from the original historical V1
pins; the roster and historical pins themselves remain unchanged:

- `trillionnium/crates/trnm-crypto-primitives/Cargo.toml`
- `trillionnium/Cargo.lock`
- `trillionnium/crates/trnm-pon-node/src/pq_application_v6.rs`
- `trillionnium/crates/trnm-pon-node/src/store.rs`
- `trillionnium/crates/trnm-pon-node/src/consensus.rs`
- `formal/pon-nakamoto-v1/quantum_oracle_resources.py`

The historical reader bytes, historical source identity, arithmetic evaluator,
all qualification flags and the null lifetime failure bound are unchanged.
The old current mapping actually refused the 29,812-byte source before this
repair. The update fixes its exact byte count and digest; it does not enlarge
the general reader cap or relax source identity checks.

## Retained initial current-source observation

The initial V2 contract retained the same 20 selected paths under a new
namespace. At that initial checkpoint, comparison with V1 found one changed
path; the later six-path comparison at `332d7f72` is retained above:

| Path | Historical SHA-256 | Current SHA-256 |
|---|---|---|
| `trillionnium/crates/trnm-pon-node/src/store.rs` | `b712a86b9997a098df5e8257f309d22445b2c749c9aa474457e958a0f65f5153` | `108621f304255841ea2e1a7353858c3f0f5d8cb70a235f6a4aef6d57ebe0c554` |

At that initial checkpoint the file was 382,866 bytes and retained both the native work-verification
and cumulative-required-work anchors used by the selected survey. These
anchors are source observations, not proofs of complete entry-point coverage,
runtime behavior, execution cost or consensus security.

The [observer](../../scripts/w1_lifetime_current_observation.py) independently
pins the current manifest and the complete unchanged historical reader bytes.
It reuses the historical source-observation function code in a private copied
data context whose current pin map and source label are explicit. It does not
modify the historical module, reader file or pin map. The historical reader
continues to reject the current store. The arithmetic evaluator and three
independent acceptance lines are unchanged; supplied counts remain premises.

The new output schema is `TRNM-W1-LIFETIME-CURRENT-OBSERVATION2`. Current jobs
do not compare it to the historical V1 lifetime report. They compare five
unaffected reports byte for byte. The semantics report has an independent,
explicit current comparison in the
[QROM mapping](W1_QROM_CURRENT_SOURCE_MAPPING_V2.md). Its current correspondence
permits only provenance lock-check SHA fields 0 and 2, for the V2 verifier
and zkVM locks, to differ from the frozen report. Both current lock digests
are independently fixed. Guest lock field 1, every other report property
and all qualification fields must remain identical. The earlier zkVM-only
comparison belongs to its retained source checkpoint; it is not the complete
current correspondence. This is not
dependency-graph execution or compiler refinement evidence.

The jobs check complete source identity before and after, and require every
stage and every actual named test to complete successfully. The current roster and the
historical 105-name roster have separate namespaces and are not interchangeable.

## Validation and remaining obligations

The current observer's tests cover the actual V1 refusal, retained unknown
outputs, immutable historical context, source-plus-manifest changes, missing
files, aliases and strict CLI failure behavior. The current closure controls
also cover actual named completion and workflow gate behavior. Repository CI
requires the observer tests, report and current closure controls once in the
original straight-line lane. No test or CI source check grants security bits.

All project lifetime failure bounds remain null, coverage exhaustiveness and
composition remain unproved, and production/consensus qualification stays false.
Source-before/after equality is not a native execution certificate. Concrete
quantum auxiliary-state hypotheses, a complete shared-oracle reduction,
recursive composition and complete lifetime event coverage still require their
own mathematical and operational evidence.

## Selected consolidated source mapping, 2026-11-14

The selected mapped checkpoint 5c04c60e463462d9df8884786e0d5bb32af08a64 retains the exact ordered 20-path roster and all
20 historical SHA-256 values from 7150d96a. Four current rows changed from
332d7f72: the crypto Cargo manifest, pon_work.rs, pq_accounts_v2.rs and Node
store.rs. The historical-versus-current difference list now has eight paths,
including the two newly different pon_work.rs and pq_accounts_v2.rs.

Current contract SHA-256: bd22f0db32c479dd7d42ae541eeed0ad0c1115d40b88b01d07acefd25930fbb7. The current reader still calls the original
byte-pinned survey function in a private copied context. The 7150 fixture,
the separate 1f2b0187 ledger and the 0f9b3054 PQ128 source lock retain their
bytes and identities. All source limits, arithmetic rules, missing/symlink
refusals and unknown qualification outputs remain. Current observation does
not reproduce a historical execution or establish a lifetime failure bound.
