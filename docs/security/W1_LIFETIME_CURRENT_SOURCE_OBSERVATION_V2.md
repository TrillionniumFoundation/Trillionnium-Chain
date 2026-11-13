# W1 lifetime: separate historical reproduction from current observation

Status: **HOLD / NO-GO**. No lifetime bound or cryptographic qualification is
created by this source-survey continuation of #850.

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

## Explicit current-source observation

The [current contract](../../config/pon/w1-lifetime-current-source-v2.json)
retains the same 20 selected paths under a new namespace. Comparison with V1
finds exactly one changed path:

| Path | Historical SHA-256 | Current SHA-256 |
|---|---|---|
| `trillionnium/crates/trnm-pon-node/src/store.rs` | `b712a86b9997a098df5e8257f309d22445b2c749c9aa474457e958a0f65f5153` | `108621f304255841ea2e1a7353858c3f0f5d8cb70a235f6a4aef6d57ebe0c554` |

The current file is 382,866 bytes and retains both the native work-verification
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
explicit current comparison: the only reviewed difference is the SHA-256 of
`formal/pon-nakamoto-v1/w1_zkvm/Cargo.lock` in its provenance. The current lock
adds the `risc0-binfmt` and `sha2` dependency edges to the local
`trnm-w1-zk-methods-v2` package; package entries and other report values remain
unchanged. Both lock identities and the original report identity are frozen;
arbitrary provenance or mathematical-output changes are refused. This is not
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
