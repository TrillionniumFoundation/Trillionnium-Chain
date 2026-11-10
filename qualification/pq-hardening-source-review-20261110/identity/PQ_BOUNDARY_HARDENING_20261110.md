# PQ boundary hardening: source, identity and numerical controls

Date: 2026-11-10. Disposition: **candidate hardening; whole-chain security HOLD**.

This note records three concrete corrections: complete public-key pinning at
native TLS admission, execution of the field helper whose bytes the STARK
route reader actually checked, and finite numerical inputs and results in the
offline quantum/DAA models. It also records the current limits of the surrounding
security paths. It is a security observation, not a second development plan.
The sole plan remains
[TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

**Delivered scope:** a reviewable patch package with local selected-source
Python observations. The new Rust controls, negative-only execution, original
native TLS suite, strict Clippy, formatting, final source rebinding,
full-repository source gates and hosted CI are **not yet verified for a final
combined commit**. The H remote channel has repeatedly timed out without
returning confirmed completion evidence. Submission and timeout are not native
test receipts, and this package is not a claimed pushed branch. No result below
promotes a selected-source run into whole-repository, native-service or
deployment acceptance.

## 1. Exact source scope

| Input | Fixed identity | Meaning |
|---|---|---|
| Joint candidate baseline | [`da1374a200022bc14dc2bd325cc9ba29dbcd24ab`][baseline] | Basis for the TLS, identity, Cell and quantum-model review |
| Packaged STARK route/sampler continuation | [PR #857 head `06c3d24cc4fc05011e04951d30f066c057394836`][stark-input] | Patch-package inputs import and harden the route and field files; they were not present in the joint baseline |
| Earlier route continuation | [PR #849 head `85a53d09604a765352102f91a865dcf25ecede38`][stark-earlier] | Historical predecessor of the imported route work |
| Literature observation basis | `e2a02f9271b49f146e70806c8a66e161b5973971` | Historical manuscript/source observation; not silently relabelled as current execution |
| Final integrated commit, native result and push | **not established** | A final source checkpoint, provider/binary receipts and completed remote publication are still required |

The changes to the native identity boundary do not change a signature domain,
wire schema, persisted schema, profile identifier or consensus rule. The
numerical changes apply to offline calculators. The STARK changes repair the
provenance of an audit calculation, not the cryptographic relation accepted by
a proof verifier.

The authoring workspace is an extracted source subset. Its attempted
`bash scripts/project-preflight.sh` returned exit 128 because no Git repository
was available there. This is an unavailable preflight, not a pass. Integration
must run the original preflight in the complete checkout.

## 2. Native identity: compare the complete pinned SPKI

The existing policy contains independently supplied complete ML-DSA public
keys, but several native-client/TLS admission decisions compared only a
32-byte public-key identifier. That loses an available exact-key check at the
point where the policy intends to bind one particular key. The selected
identity identifier remains useful for lookup; acceptance now also requires
the exact canonical SubjectPublicKeyInfo bytes already held by the policy.
See the [baseline native client][native-client] and
[baseline TLS context][tls-context].

The prepared source patch adds three checks:

1. `PqClient::new` looks up the peer by its identifier and compares the
   selected verifier's complete SPKI with the local signer's SPKI.
2. `TlsContext::new` checks the local certificate key against the complete
   independently pinned policy key for both client and server roles.
3. `TlsContext::admit` checks the peer certificate's complete SPKI against
   the policy's server key or the selected rostered client key before
   application dispatch.

This is a real admission-boundary strengthening. It does **not** demonstrate
a SHA-256 collision, an efficiently constructible colliding ML-DSA key, or an
existing remotely exploitable session. The negative controls deliberately
alter private test policy state so that the old identifier selects a different
real complete public key. This is a conditional alias control: it tests whether
exact-key authority is enforced after lookup without pretending to have broken
the identifier hash.

The retained controls are extended with:

| Control | Required observation |
|---|---|
| `pq_client_requires_complete_key_pin_after_identity_lookup` | Construction refuses the aliased policy pin with `PQ_NETWORK_UNKNOWN_PEER` |
| `tls_local_identity_requires_complete_key_pin_for_both_roles` | Both local roles refuse the substituted complete key with `PQ_TLS_LOCAL_PIN` |
| `actual_tls_peer_identity_alias_refuses_before_application_dispatch_in_both_directions` | Real mutual TLS is attempted in both directions; the affected admission side refuses with `PQ_TLS_PEER_PIN`; the Node records no operation and no inbound application-signature attempt |

The TLS control prepares the application request before starting its original
five-second deadline and worker. Its listener is nonblocking, and the accept
loop checks that same absolute deadline. A client that refuses before connecting
therefore still leaves a terminating server worker; the test does not rely on
an unbounded `accept` followed by `join`. The budget remains five seconds.
These are source-level control properties; actual Rust execution remains
pending at this checkpoint.

### Native session status

The joint baseline already has a distinct TLS-required owner in addition to
the signed plaintext PNQ2 development path. The TLS profile fixes TLS 1.3,
`X25519MLKEM768`, `mldsa65`, `TLS_AES_256_GCM_SHA384`, mutual certificates,
role-specific local certificate checks and the protocol ALPN. It disables
resumption tickets, early data and renegotiation. The immutable context permits
only one group; the selected group is inferred from that context rather than
claimed to have been independently observed through an unavailable safe
getter. See [TLS profile][tls-profile] and [TLS context][tls-context].

Both owners remain **loopback-only**. The TLS-required policy rejects the
plaintext path, and feature-off use refuses instead of selecting a classical
transport. Application signatures, original request deadlines, durable ingress
charging and work admission still apply after TLS. The existence of this local
hybrid TLS path is substantive progress, but it grants no public-WAN, private-task,
ordinary deployed service or whole-chain confidentiality qualification.
The [required TLS control manifest][tls-controls] explicitly keeps those
qualification flags false. NIST's [ML-KEM standard][fips203] and the
[OpenSSL ML-DSA documentation][openssl-mldsa] describe primitives; neither
certifies this application composition.

## 3. STARK route audit: execute the checked helper bytes

The imported route reader used ordinary Python import resolution for
`w1_stark_field_certificates`. That helper was absent from the original
18-item fixed-input roster. A reproduced negative control supplied a forged
cached helper through `sys.modules` and a matching caller-supplied registry,
while preserving all 18 pinned source inputs.

The old reader returned
`ROUTE_MAPPING_REPRODUCED_SECURITY_HOLD`,
`FIXED_FIELD_ALGEBRA_CERTIFIED_SECURITY_HOLD`, and
`source_mapping_reproduced=True` while reporting reducible `X^2` as the
Goldilocks extension polynomial. Production and quantum-qualification flags
remained false. The observation establishes an audit-helper provenance failure;
it is not a forged W1 proof or a demonstrated chain attack. The retained
reproducer is `reproduce_helper_injection.py`, and the original observation is
`helper-injection-before.json`.

The corrected `scripts/w1_stark_route_audit.py` adds the helper to the
19-item fixed source roster. Its `field_certificate_report` compiles and
executes the exact helper bytes that were already checked, with helper identity
recorded in the report. It does not re-resolve the helper from `sys.modules`
or an earlier `sys.path` entry. The helper SHA-256 is
`7a0b78bc9b2e3e4cdd9507f7600bab8495190f1ec8f74033b32bb85f993578cf`.

The negative tests cover both module-cache and search-path substitution.
Changing the helper and updating the registry's self-reported pin together
still refuses because the source-roster commitment is separately frozen.
Upstream Rust text being inspected is never executed. This binds the selected
audit calculation to checked source; it does not establish a complete dependency
closure, trusted Python runtime, compiled field arithmetic or a proof-system
security theorem.

The saved `joint-route-tests.log`, `joint-field-tests.log`,
`joint-sampler-tests.log` and `joint-replay-tests.log` report 32, 16, seven and
13 tests passing respectively. All 28 original route-test identities are
retained. These are selected-source Python results, not an original complete
Git checkout, native proof execution or hosted CI.

The supplemental `after-pack-corpus-tests.stderr.log` records 63 passing tests
in the corpus test file using the local extracted-source/fixture environment.
`after-pack-review.json` additionally records 12 passing selected
`MergedQualificationLaneTests` and seven passing rebinder controls. The four
new literal-roster methods are part of the corpus suite and cover 42 omission
cases and 14 retained-pin byte mutations. These counts describe named local
runs; they must not be added as if every rerun or nested control were a distinct
test. The selected 12-method class is not the complete CI-contract test suite.

The prepared rebinder permits changes to exactly two reviewed source pins,
for `pq_network.rs` and `quantum_daa_model.py`, and constrains the resulting
report changes. Its fixture tests do not produce the final real Git checkpoint,
formatted-source identities or completed source-lock update. That final
rebinding and the integrated route, corpus and command-sequence gates still
require the complete combined source. See the candidate
[route-instance audit](W1_STARK_ROUTE_INSTANCE_AUDIT_V1.md).

Three proof routes retain distinct identities: RISC Zero 3.0.6/BabyBear,
Plonky3 0.8.0/Goldilocks with Poseidon2, and the tagged SHA3-512 Goldilocks route.
Finite prime, extension and root checks do not supply complete noninteractive,
quantum or lifetime security bits. Those values remain null, with zero complete
security obligations discharged across the historical 15-obligation roster.

The [RISC Zero 3.0 security model][risc0-security] lists conditional 96-bit
RISC-V and 99-bit recursion estimates, and identifies the Groth16/BN254
translator as not quantum safe. Those upstream statements cannot be assigned
to this repository's particular guest, receipt composition or all three routes.

The relevant primary-source obligations remain separate: [CDHZ's QROM
reduction][cdhz] requires the actual knowledge and extraction hypotheses;
[Fenzi--Sanso][fenzi] concerns small-base-field extension-code soundness;
[DKTZ's proximity-gap work][dktz] requires matching the selected theorem's field
and domain; and [Krachun--Kazanin--Haböck][kkh] supplies a different
near-capacity line of results. The odd characteristics of BabyBear and
Goldilocks exclude selected characteristic-two hypotheses, not every
proximity-gap result. Excluding one theorem's direct domain is not a soundness
proof. This continuation does not claim a fresh complete audit of every latest
manuscript or an instantiated quantum extractor.

## 4. Quantum/DAA calculators: reject invalid arithmetic explicitly

The [baseline adversarial-search model][quantum-search] and
[baseline DAA model][quantum-daa] accept conditional research inputs, not native
consensus authority. Finite operands could produce nonfinite intermediate clocks
or trial costs. Decimal coercion also accepted inappropriate input types, and
extreme decimal exponents could reach costly or invalid arithmetic before a
typed rejection.

The patch checks finite results at the relevant clock and trial boundaries,
requires bounded decimal text instead of bool/float coercion, and refuses
out-of-range decimal inputs before simulation. The decimal-text length and
absolute adjusted-exponent limits are both 100. These are calculator limits;
they do not set a protocol difficulty, change a resource budget, or prove a
minimum quantum attack cost.

For nonnegative elapsed time, the honest-height calculation uses
`int(elapsed) // 10` instead of a precision-limited Decimal integer quotient.
This preserves the intended floor while avoiding the Decimal quotient's
precision failure on otherwise admissible inputs.

The original selected numerical suite passed 71 test methods. The corrected
suite passed 75. The four new methods, when run against the unmodified source,
reported 24 failing subtest entries and three error entries; these counts are
not 27 distinct test methods. Three methods failed and the retained positive
method passed. The same four methods passed against the corrected source.
The four methods are already included in the corrected 75-method suite; their
separate before/after rerun does not add four new distinct controls. The first
unsuccessful correction attempt is retained rather than overwritten.

All 11 standard scenarios were regenerated from both sources. Their summaries
and all **109,190 trace rows** are byte-identical in the canonical combined
stream: 50,534,673 uncompressed bytes, SHA-256
`53f1a902a01ed57b0de2285b928801b323d11a273bcc79b828e46371e28cddb3`.
The equality concerns these finite scenarios and their stated premises.
It is neither a proof for every strategy nor a native attack execution.

The retained [complete W1 oracle construction][w1-construction] is a particular
construction with fixed context, public matrix and bounded nonce domain.
Its resource figures are constructive upper bounds. Macro interpretation of
the native-size construction, reduced-shape leaf-gate controls and actual
fault-tolerant hardware execution remain distinct evidence types. This
numerical repair supplies no optimality or attack lower bound.

[Bailey--Sattath][bailey] explains why a square-root quantum search-cost
hypothesis must be studied jointly with difficulty, timestamps and cumulative
chainwork. Its result does not by itself instantiate an exploitable attack
against this chain. The model's security-theorem and production-activation
flags remain false.

## 5. Eight current security boundaries

These eight rows are review categories, not new protocol profiles or independent
security certifications.

| Boundary | What the selected source supports | What remains open |
|---|---|---|
| 1. Signature primitive | Native RustCrypto ML-DSA-65 with canonical key encoding is substantive PQ implementation progress | Implementation hardening, operational keys and the complete protocol composition are not certified by the primitive's category |
| 2. Profile selection and migration | Legacy Ed25519 and explicit PQ profiles coexist; candidate CPQ1 profiles are refused by current-authority selectors | Prior trusted migration registry, source finality, retirement and deployment policy require their own evidence |
| 3. Current authority, revocation and recovery | Native owner policies, generations, sequence checks and optional independent rollback witnesses exist | A mathematical verification receipt is not a current authorization; host-wide rollback, external freshness and recovery trust remain separate obligations |
| 4. Hash purpose and semantic binding | SHA-256, SHA-384 and SHA-512 serve different purposes; the stronger content paths bind their full intended inputs | No uniform claim that every 32-byte digest supplies 128-bit general quantum collision resistance; old authority namespaces still exist |
| 5. Cell content and execution | Selected CCH1/TCM2 and TCV2/CPV4 verification/readback paths check actual bytes, strong chunk/payload hashes and complete-version binding; sealed handoff checks actual payload hashes | Legacy TCM1/TCV1/CPV3 paths coexist; `content_at` does not re-read bytes; availability, all transitive dependencies, fresh FinalUse and the real execution sandbox are not implied |
| 6. Session network | Separate loopback hybrid TLS-required owner with fixed TLS/group/signature policy; candidate exact-SPKI checks strengthen both roles | PNQ2 plaintext remains a development path; public-WAN and deployed confidential service are unqualified |
| 7. STARK instances | Three explicit routes, source correspondence and finite field checks; the candidate helper fix closes one audit-source gap | Full AIR/compiler correspondence, FRI/PCS assumptions, RBR/QROM extraction, concrete primitive model, recursion and lifetime composition remain open |
| 8. Quantum mining and chain accounting | Particular W1 reversible construction and conditional DAA/timestamp/chainwork models with finite-input controls | No optimal-attack lower bound, end-to-end machine failure bound, complete adversary/lifetime budget or whole-chain security conclusion |

Sources for the identity and profile rows are the
[native PQ primitive][pq-auth], [profile selector][profiles] and
[explicit account migration][migration].
[FIPS 204, section 4][fips204] places ML-DSA-65 in NIST category 3; that is a
parameter-set claim, not a whole-chain certification.

For an ideal n-bit hash, generic quantum preimage search has the familiar
square-root query scale, while [BHT collision search][bht] has cube-root
query scale. Thus the usual general-collision query estimate for SHA-256 is
about 2^85.3. Query complexity is not elapsed hardware attack time, and a
general collision is not a second preimage for a fixed authenticated file.
An outer SHA-512 cannot repair semantics already collapsed into a shorter
inner commitment.

### Cell: actual strong bytes and remaining shorter authority bindings

The strong-content review found actual re-reading, not just an outer hash:

- [CCH1 `observe_reader`][cch1] hashes the complete domain/context header and
  declared content bytes, checks the length and EOF, and charges the bounded
  read. [TCM2][tcm2] checks an independently pinned complete claim and the
  payload; its closure covers the declared direct dependency objects.
- [TCV2][tcv2] checks the complete stored manifest, reads each chunk, hashes
  each actual chunk under `TRNM/Cell/ChunkContent/v2`, hashes the ordered
  actual payload under `TRNM/Cell/PayloadContent/v2`, and binds these
  strong hashes with complete version metadata. `verify_cached` compares
  the independently pinned strong root and rescans the stored content.
- [CPV4][cpv4] binds the full TCV2 root and a SHA-512 commitment to the
  complete signer SPKI. The [sealed loader][sealed] and
  [host handoff][handoff] check the actual sealed payload and selected
  model/environment objects. The cached `content_at` operation rechecks its
  time/authority conditions but does not re-read content bytes. A past
  observation does not create a new monotone authority view at FinalUse.

These observations do not upgrade every Cell entry point. In particular,
[V2 discovery metadata][discovery-v2] persists a 32-byte authority digest,
and [V3 epoch discovery][discovery-v3] persists 32-byte authority and source
digests. Reopening compares those digests; receipt handoff and same-sequence
equivocation checks also use shorter digest identities. They therefore
remain authorization/namespace or equality boundaries, not uniformly
non-authoritative cache indexes. Older CPR2/CPV3 cached observations also
retain their older key-identity contract. This patch does not migrate those
schemas. No practical collision or replay through them was demonstrated in
this read-only review.

The current [crypto-profile policy][profiles] still rejects candidate CPQ1
profiles from `select_current`. A valid candidate signature over a complete
CCH1 record is a mathematical observation, not a production selector or an
application effect.

## 6. Verification commands and provider contract

Run from the complete repository root on the final frozen candidate.
Preserve each command, exit and complete output. Listing these commands
does not assert that they have already passed.

The [toolchain][toolchain] is Rust 1.95.0 with Clippy and rustfmt. The native
Rust OpenSSL dependency is exactly 0.10.81. The repository's
[provider preparation][provider] builds isolated static OpenSSL **3.5.9**
from the pinned archive SHA-256
`603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`.
It performs real ML-DSA-65 key generation, signing, verification and wrong-message
rejection before exporting the provider environment. It does not run the
upstream complete OpenSSL suite or the Rust tests.

A system OpenSSL 3.5.5 satisfies the native code's minimum version check but
does not meet this pinned evidence contract. Provider reuse must retain and
check the original provider receipt and exact binary/header/static-library
identities. The preparation script accepts a pinned local source archive as
an alternative download source, never as a substitute for building and testing.

```bash
bash scripts/project-preflight.sh
cargo +1.95.0 metadata --locked --manifest-path trillionnium/Cargo.toml --format-version 1
cargo +1.95.0 fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib --all-features ingress::pq_network::canonical_tests -- --show-output --test-threads=1
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib --all-features ingress::pq_network::tls::tests -- --show-output --test-threads=1
cargo +1.95.0 clippy --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib --tests --all-features -- -D warnings
```

Run the new three controls on the unmodified source with only the added tests,
then on the corrected source. For exact selection use their complete module
paths, and verify the actual binary's test registry so that zero selected tests
cannot count as success. The original [PQ continuation workflow][pq-workflow]
also requires the complete node library, TLS CLI, feature-off and witness CLI
controls. The [required baseline workflow][baseline-workflow] retains its wider
repository, workspace and quality obligations.

The imported STARK checks are:

```bash
python3 scripts/ci/test_w1_stark_field_certificates.py
python3 scripts/w1_stark_field_certificates.py
python3 scripts/ci/test_w1_stark_route_audit.py
python3 scripts/w1_stark_route_audit.py
python3 scripts/ci/test_w1_fri_ideal_sampler.py
python3 scripts/ci/test_w1_fri_query_replay.py
python3 scripts/w1_fri_query_replay.py --ideal-sampler-law
```

The final checkout must also run its original corpus/source and workflow-command
gates. Local selected-source numerical evidence used
`run_scoped_checks.py`, `run_numeric_regressions.py` and
`check_standard_scenarios.py` against separate original and patched source
directories. The scoped runner deliberately excludes Git/campaign-identity
controls; it cannot satisfy those gates. Full-checkout commands include:

```bash
python3 formal/pon-nakamoto-v1/test_quantum_adversarial_search.py
python3 formal/pon-nakamoto-v1/test_quantum_daa_model.py
python3 scripts/ci/test_pq_quantum_daa_scenarios.py
python3 scripts/ci/test_pq_research_integration.py
python3 scripts/ci/check_pq_research_integration.py
python3 scripts/ci/test_ci_contract.py
python3 scripts/ci/check_ci_contract.py
```

### Evidence retained at this patch-package checkpoint

| Artifact or observation | Identity / result | Scope |
|---|---|---|
| Exact-SPKI patch, revision 2 | SHA-256 `939910be8e0941fae8f5431d3977de0182a82bcfeda255888e87648c0c9e90e8` | Source patch; Rust execution pending |
| Negative-controls-only patch | SHA-256 `24f142a6fca0f25d8d525ef4fd22c3f0b03485bf484f17463d4959d37830082b` | Added controls on unchanged production source; execution pending |
| Quantum numerical patch | SHA-256 `3bb17bb9e66b0d22145a5bc479390b35ce3f2d6c663a33434400f2ca844c11fd` | Four changed model/test files |
| Quantum selected suite | Original 71/71; corrected 75/75 | Extracted-source numerical controls |
| Complete standard scenarios | 11 scenarios, 109,190 trace rows, equal canonical stream | Conditional-model regression, not a security theorem |
| STARK selected suites | Route 32, field 16, sampler 7, replay 13 | Selected-source Python execution |
| Supplemental local corpus test file | 63 passing tests; includes the four new literal-roster methods | Extracted-source/fixture tests, not a final corpus source-check receipt |
| Supplemental selected CI/rebinder controls | Review record reports 12 and seven passing tests | Selected class and rebinder fixtures; no completed final-source rebind |
| Native/complete checkout/hosted qualification | **pending** | Must be appended from actual final-source observations |
| Final source checkpoint, source-lock rebinding and remote push | **not completed/confirmed** | Current delivery is the reviewable patch package |

Retain the helper-injection result, original numerical failures, unsuccessful
intermediate correction, native failures or timeouts, original ignored gates,
and historical observations under their real source identities. A successful
successor does not rewrite them. Production activation and whole-chain
post-quantum security remain unqualified.

[baseline]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/da1374a200022bc14dc2bd325cc9ba29dbcd24ab
[stark-input]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/06c3d24cc4fc05011e04951d30f066c057394836
[stark-earlier]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/85a53d09604a765352102f91a865dcf25ecede38
[native-client]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/trillionnium/crates/trnm-pon-node/src/ingress/pq_network.rs
[tls-context]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/context.rs
[tls-profile]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls_profile.rs
[tls-controls]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/config/pon/pq-native-tls-required-tests-v1.json
[pq-auth]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs
[profiles]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/trillionnium/crates/trnm-protocol/src/crypto_profile.rs
[migration]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/migration.rs
[cch1]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/trillionnium/crates/trnm-protocol/src/content_commitment.rs
[tcm2]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/trillionnium/crates/trnm-data-availability/src/cell/content_v2.rs
[tcv2]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/trillionnium/crates/trnm-data-availability/src/cell/version_content.rs
[cpv4]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/trillionnium/crates/trnm-data-availability/src/cell/pq/content.rs
[sealed]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/trillionnium/crates/trnm-data-availability/src/cell/residency/sealed_loader.rs
[handoff]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/trillionnium/crates/trnm-data-availability/src/cell/host_handoff.rs
[discovery-v2]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/directory.rs
[discovery-v3]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/epoch_directory.rs
[quantum-search]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/formal/pon-nakamoto-v1/quantum_adversarial_search.py
[quantum-daa]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/formal/pon-nakamoto-v1/quantum_daa_model.py
[w1-construction]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/evidence/pon-quantum-construction-20261104/reproduction.json
[toolchain]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/rust-toolchain.toml
[provider]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/scripts/ci/prepare_pq_provider.sh
[pq-workflow]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/.github/workflows/pon-pq-system-continuation.yml
[baseline-workflow]: https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/da1374a200022bc14dc2bd325cc9ba29dbcd24ab/.github/workflows/trnm-required-baseline.yml
[fips204]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
[fips203]: https://csrc.nist.gov/pubs/fips/203/final
[openssl-mldsa]: https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/
[risc0-security]: https://dev.risczero.com/api/security-model
[cdhz]: https://eprint.iacr.org/2025/2166
[fenzi]: https://cic.iacr.org/p/3/3/44
[dktz]: https://eccc.weizmann.ac.il/report/2026/237/
[kkh]: https://eprint.iacr.org/2026/782
[bht]: https://arxiv.org/abs/quant-ph/9705002
[bailey]: https://arxiv.org/abs/2403.08023

