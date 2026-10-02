# Native integer factor candidate V2

Status: isolated development successor, no production activation or public-readiness acceptance. This profile adds an actual native admission path, not a contribution-quality certificate. M00 codec and M06 State integrate the frozen M11 integer arithmetic component without a new Cargo package, dependency edge, SQL table, authority cache or reward ledger. The typed operation inventory has **39** operations after adding `M10.SubmitFactorContribution`.

## Fresh installed context

`--model-profile linear-factor-witness-dev-v2` is selectable only with `--evaluation-policy native-public-evaluation-dev-v1` and the existing legacy maintenance task profile. Config selects revision11 and commits both new configuration files through family/parameters/plan and a distinct chain label. Settings derives the same full canonical genesis model and installs its chunks in its actual initial State. `factor_genesis_artifact` is its computed artifact hash in parameters; the initial State root also binds every byte. A store from another namespace is refused. Old model profiles, tag6 bytes and meanings, signed domains and genesis values are unchanged. New profile refuses hash-only tag6; historical profiles refuse tag23.

The family V2 shares the bounded 3×257 integer numerical substrate with `INTEGER_LINEAR_FAMILY_V1`. M11's frozen V1 kernel authenticates only its original arithmetic contract; it does **not** authenticate a V2 model or caller parent. M06 separately loads the complete V2 parent and authenticates its family and actual current model reference. There is no zero-ID, missing-data or development-model fallback.

## Closed witness and complete model

ILF2 tag23 payload: magic4, LE version2, rank1, slot1, LE scale2, seven32-byte hashes (family, current parent reference, loaded parent artifact, computed candidate artifact, computed update ID, contribution ID, components root), LE round8, then row-major B(3×rank) and A(rank×257) signed LE i16. Rank is1..2, slot0..2, scale exactly1024 and coefficients[-32767,32767]. Payload762/1282B; complete PNX1 signed envelope921/1441B, below the unchanged2048B limit. No artifact-hash-only witness is accepted.

ILM2 full model is exactly7756B: magic4/version2/family32/scale+rows+columns+slots (four LE u16), then base(3×257), router(3×257), delta slots(3×3×257), all row-major signed LE i16. Every coefficient is in[-32767,32767]. Artifact ID is `H('integer-linear-model-artifact-v2', full_bytes)`. Genesis explicitly installs this format with all3855 coefficients zero; that is actual context-bound model data, not a missing-model substitute.

Models use original logical State keys `linear-model-v2:<id>:meta` and two-digit chunks. Chunks are1024 raw bytes encoded as lowercase hex, exact8 chunks for this fixed model. Decoder requires exact metadata, key set, chunk lengths, full size, header/shape, family, coefficient range and full hash. General hard bounds remain65536 artifact bytes/64 chunks; State retains the original65536-key,160-byte key,4096-byte canonical value limits and complete root verification.

## Actual computation and duplicate semantics

M06 resolves `model:current`: genesis points to the installed model; after native adoption it is a release ID and is resolved through the actual release's family/artifact fields to stored full model bytes. Caller hashes cannot substitute for this loading.

M06 recomputes all771 BA coordinates via the unchanged checked M11 kernel, adds them to the actual selected parent's delta slot, and checks all3855 model coefficients. It rejects all-zero BA, computed candidate equal to parent, overflow/range violations, malformed witness and forged derived hashes. The complete canonical candidate artifact is stored in the same native transition. Product budget is at most1542 checked products. Coefficients and BA are integers: no FP32/LoRA or arbitrary neuron model equivalence is implied.

Update ID uses a fresh domain over installed N/P/family, actual parent reference, loaded parent artifact, round, slot, fixed numeric/scale and all771 canonical LE i16 BA coordinates. The duplicate record also retains all coordinates in three bounded State rows and compares full context/matrix on a repeated ID. Author key and raw basis representation do not affect the update ID. Contribution ID still binds author, components and native context. Equivalent basis/sign/zero-padding updates over the same parent/round/slot are refused even under a different author; different parent, round or slot has a separate duplicate scope.

A different BA does **not** establish different router/argmax behavior: an unused slot or classification margins can hide numerical changes. This mechanism screens exact declared insertions; it does not establish general functional equivalence, marginal quality, optimal circuits or fair rewards.

## Errors and validation order

The M00 `FactorWitnessV2` codec returns `WireError::Length` for truncated or wrong
rank-dependent extents, `Version` for wrong ILF2 magic/version/scale, `Limit` for
rank/slot bounds, and `Noncanonical` for coefficient/encoding shape violations.
Outer PNX1 admission preserves its original `ENCODING` mapping; M06's direct
witness encode/decode helpers map codec failures to `FACTOR_ENCODING`. No successful
codec result authenticates a parent, model or transaction signature.

The complete dedicated M06 string catalogue in
[`integer_factor_candidate_v2.rs`](../../../../trillionnium/crates/trnm-mvcc-fee/src/integer_factor_candidate_v2.rs)
and its executor profile gate is:

| Layer | Exact errors | Rejection condition |
| --- | --- | --- |
| Installed context / bootstrap | `FACTOR_PROFILE`, `FACTOR_GENESIS` | Tag23 or full genesis is not selected; hash-only tag6 is refused in the factor context; computed genesis artifact differs from installed parameters. Config separately retains `MODEL_PROFILE_POLICY`, `MODEL_PROFILE_TASK`, `MODEL_PROFILE` and `CONFIG` refusals for incompatible selections/registries. |
| Hash / witness / arithmetic | `FACTOR_HASH`, `FACTOR_FAMILY`, `FACTOR_ENCODING`, `FACTOR_CONTEXT`, `FACTOR_ARITHMETIC`, `FACTOR_RANGE` | Noncanonical lowercase hash; installed family/profile mismatch; bad witness; invalid frozen kernel context; failed checked integer kernel; BA conversion/addition outside checked range. |
| Complete stored model | `FACTOR_MODEL_LENGTH`, `FACTOR_MODEL_VERSION`, `FACTOR_MODEL_CONTEXT`, `FACTOR_MODEL_RANGE`, `FACTOR_MODEL_CANONICAL`, `FACTOR_MODEL_COLLISION`, `FACTOR_MODEL_LIMIT`, `FACTOR_MODEL_MISSING`, `FACTOR_MODEL_METADATA`, `FACTOR_MODEL_CHUNK`, `FACTOR_MODEL_HASH` | Wrong exact extent/header/family/numerical shape/range/round-trip; conflicting bytes under a model ID; hard size bound; missing or malformed exact chunks/metadata; computed full hash mismatch. |
| Actual parent | `FACTOR_PARENT`, `FACTOR_PARENT_RELEASE`, `FACTOR_PARENT_FAMILY` | Missing/wrong current reference or loaded artifact; absent/ill-formed release reference; release family mismatch. |
| Candidate / retained duplicate | `SUBMISSION_ROUND`, `FACTOR_NOOP`, `FACTOR_COMPUTED_HASH`, `FACTOR_NORMAL_STATE`, `FACTOR_UPDATE_COLLISION`, `DUPLICATE_FUNCTION_UPDATE` | Wrong containing-height round; all-zero BA or unchanged candidate; claimed candidate/update/CID mismatch; malformed retained normal rows; context/full-matrix mismatch under an ID; exact previously retained same-context update. |

`pon_executor::prepare` first preserves bounded canonical envelope decoding and
profile/network/expiry/main-signature checks. Applying a prepared command preserves
actual nonce, fee and balance checks. The tag23 handler checks actual `model:current`,
current candidate-history/active limits and contribution-ID absence before calling
factor admission. Thus inherited `STATE`, `CANDIDATE_WINDOW_FULL`, `LIMIT`,
`DUPLICATE`, `NONCE`, `FEE`, `FUNDS`, `NETWORK`, `EXPIRED`, `SIGNATURE`, `ENCODING`,
`RANGE` and `CONFIG` errors are still possible; this is not a replacement executor
error enum. Actual factor admission checks submission round, then loaded parent/
full BA/range/no-op, computed hashes, complete retained duplicate rows and model
storage in that source order. Finally the original public evaluation freeze can
refuse its roster/round/plan configuration. Generic execution, conservation,
MVCC, canonical State/resource and native admission errors retain their own
[execution contract](EXECUTION_PARALLEL.md),
[wire contract](LEDGER_WIRE.md) and
[public evaluation contract](PUBLIC_EVALUATION_LIFECYCLE.md). None becomes a valid
partial candidate; the original staged transaction failure boundary is preserved.

## Retention and rollback

Update markers and complete normal rows survive candidate expiration, missing-score abort and evaluation archive closure throughout the same current parent and128-block round. They are removed only after parent reference or round changes. Model cleanup retains installed genesis, actual current model, active contributions, retained evaluation archives, open/remaining release artifact references and each retained factor candidate's loaded-parent artifact reference. Existing release/archive retirement rules continue to determine history retention; no local journal is removed or rewound. Marker/model writes and removal are ordinary M06 State changes and participate in its original branch deltas, rollback and durable reopen. No physical database schema is added.

The original native public evaluation freeze/commit/reveal/closure and adoption/reward rules are reused. Those signed test scores are not independent scientific evaluations. This change does not enforce a source-group work budget, complementary bundle attribution, fair payout across sources, a strongest-control positive quality gain, useful demand, or LLM execution. Those remain explicit integration/qualification gaps. Historical inference or application use is not reversed by these branch-state rules.

## Verification and usable local entry

The ordinary local CLI already accepts this explicit `--model-profile`; `status` installs the context and `mine --transactions <JSON hex list> --output <packet>` executes a full signed tag23. `build_witness` is producer convenience only: it loads actual supplied State and computes claims; native M06 independently repeats all checks. No new network RPC or actor permission exists. Local `mine --logical-now` is a declared trusted test clock; network sync/serve retain their wall-clock guard.

Dedicated controls execute actual signed PNX1, complete PNW1, full native M06 State roots, SQLite reopen and genuine fork rollback. A128-block actual native chain performs original funded evaluation/adoption, resolves its release to the full accepted model, rejects full-parent coefficient overflow and accepts the next-round candidate. Separate independent Python controls recompute full BA, candidate bytes/hash, normal rows and update/CID domains against retained native artifacts, without claiming another PNW1 or whole-State replay. Physical source/binary, per-phase resource limits, actual child waits and all failures are preserved in work receipts. These finite logical-clock controls do not certify live-network throughput, public admission fairness, independent governance, mining hardness or model utility.
