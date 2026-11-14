# Selected proof profile and system-budget scope binding V1

Status: **HOLD / NO-GO**. This is a selected-source consistency reader. It grants
no consensus admission, production activation, model installation or FinalUse.

The [binding declaration](../../config/pon/pq-proof-profile-binding-v1.json) fixes
one research proof candidate. The [reader](../../scripts/ci/pq_proof_profile_binding.py)
checks its actual declared input bytes, entry profile, guest image, SDK lock,
control and verifier-parameter identities. It also checks the different profile
identities in the system lifetime register and the two P3 source configurations.
Those other records cannot supply the selected candidate's security parameters
or failure budget.

## Selected candidate

The selected identity is `trnm-w1-risc0-3.0.6-poseidon2-join-v2`. Its current
[QROM contract](../../config/pon/w1-qrom-implementation-current-v2.json) has
SHA-256 `272275f202b896b74b7f7499695fa3f50b28a36465806c60b8c369e2e76db5b9`.
The current reference inputs were read from Chain commit
`39336622c63df1ae746d83a76bb53202cd01ba17`. The preceding dependency continuation
reviewed `189b9b5959d836ef6ae96e14fb285948e4920aa9` and contract SHA-256
`846efa5cedfb811ae8255a5b3d5c0223e6e89180a89c9670e7bcb9204cbbed30`; those
observations remain historical. The current mapping now retains those 137 local
closure records and adds the finite `pon_from_zero_filter_cost_v1.rs` diagnostic
example, for 138 inputs. All 16 selected project inputs, saved proof fixtures,
parameters and proof obligations are unchanged. The 138-input count preserves
the existing crate-root and literal-data scope; cross-root Rust `#[path]` imports,
including the example's node-side `w1_from_zero.rs` helper, are not enumerated by
that mapping. Complete native source guarding is a separate observation.
The historical V1 contract and
reader retain their own source revision and bytes. The binding successor must
reproduce these declared inputs; it does not acquire the native execution claims
recorded on source `39336622`.

| Selected property | Checked declaration |
| --- | --- |
| Independent entry | `w1_v2_verifier`, profile ending `join-v2` |
| Locked SDK | `risc0-zkvm` 3.0.6 |
| Proof field | BabyBear, modulus 2,013,265,921 |
| Extension | Degree 4, polynomial `X^4 + 11` |
| Hash suite | `poseidon2` |
| FRI | 50 queries; inverse rate 4; folding factor 16; final minimum degree 256 |
| Final recursion control | `7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e` |
| Verifier parameter digest | `ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013` |
| Guest image words | `[1958252411, 3287394615, 1805488136, 1516578702, 78549041, 790278610, 301018785, 4279049364]` |

Field and FRI values are extracted from the exact pinned upstream source
snapshot. They are declarations, not a proof that compiled code, every reachable
recursive trace, or the actual transcript satisfies a security theorem. The
separate current QROM audit remains responsible for its broader mapping.

The hardened verifier library still contains its historical `join-v1`
`PROFILE_ID` and default guest image. The v2 entry explicitly calls its
`verify_image` API with the independent v2 image. This reader therefore binds
the entry and the image used by that entry; it does not replace the v2 image
with the library's historical default merely because the library is reused.
Its source checks do not establish compiler refinement.

The selected descriptor hashes the profile ID, mapping-contract bytes,
extracted identity, selected project and saved-fixture hashes, and upstream
snapshot identity. For these reference inputs its SHA-256 is:

```text
9e5766a7eb14cb972531e12aa0be6d21a1e545400d89add72656b63c0f6407ad
```

The preceding dependency continuation produced descriptor
`5cb35b39dda38d096620e70909bea0cc380464ac2166eddfed83469537deb031`.
The earlier M2–M7 mapping produced descriptor
`da0c97f1c549e10ecfc066f6b0a9721147dc3d430eab6f53d502cbc7b91dd48c`.
The descriptor changes because it includes the mapping contract bytes; the
selected image, SDK, field, FRI, control and verifier-parameter identities do
not change. Prior candidate evidence keeps its original descriptor.

This is an audit identity, not a new protocol commitment or a security-bit
estimate. It does not replace a candidate's full repository, dependency,
provider, executable, loaded-model or operation identities.

## Cross-register boundaries

| Record | Actual scope | Consequence for the selected RISC Zero profile |
| --- | --- | --- |
| Current QROM contract | RISC Zero v2/Poseidon2/BabyBear | All 15 obligations remain `UNRESOLVED`; lifetime fields remain null and policy unadopted |
| PQ128 lifetime register | `pon-nakamoto-v1-pq-research-native-pnw1` | Separate native-system experiment; its bounds and allocations are never imported |
| P3 original public STARK configuration | Goldilocks with a degree-2 challenge field and its own Poseidon2 construction | Different proof and oracle construction; no parameter or error transfer |
| Tagged P3 profile | `TRNM-W1-P3-SHA3-512-TAGGED-R1` | Separate framing, MMCS and transcript construction; no parameter or error transfer |

The current native-system register lists SHA-256, SHA-512, SHAKE128 and SHAKE256.
It does not register the selected RISC Zero Poseidon2/BabyBear construction.
The reader reports that inventory gap explicitly. Even a shared SHA-256 label
would not establish compatible experiments, complete query scope or a common
reduction. SHA-512 and SHA3-512 also retain different primitive identities.

`pq_lifetime_budget.evaluate` checks the native register's own schema and exact
arithmetic. Its numeric terms, if supplied in a future research declaration,
still cannot become a RISC Zero failure bound. This reader does not call the
native register's source-lock inspection and reports its source revision as
**unbound** here. A caller must run that separate check on its proper candidate.
The native register's bytes and declared revision are retained in the output.

## Theorem revision remains unresolved

On 2026-11-09 the [official ePrint record](https://eprint.iacr.org/2025/2166)
listed 2026-03-02 as the latest of three revisions. The
[conference publication](https://link.springer.com/chapter/10.1007/978-3-032-25336-1_14)
was first published online on 2026-05-09. These metadata observations do not
establish equivalence between the manuscripts.

The pinned [composition evaluator](../../scripts/w1_qrom_composition_budget.py)
implements a hypothetical expression from the **2026-01-01** manuscript's
Theorem 10.6. The latest full PDF could not be obtained in this review, and its
theorem statements and proof have not been compared with that evaluator.
`version_equivalence_verified=false` is mandatory in this binding schema.
The metadata observation is dated; the reader does not claim to discover later
revisions while running offline.

## Candidate integration

The 2026-11-14 independent-lock review binds source
`d9e6aa1ec8d1cdf4f506238f2df452c8c6215b00`. Its V2 lock is now
consistent with the selected shared crypto graph. The composed profile and
upstream-security register both reference mapping SHA-256
`5c53b9aba5255a163256bb9865448ea44e5b5f2f45079adf682ea4ace662a2fb`.
The selected proof/image, unresolved obligations and current-use withdrawal
are unchanged. The descriptor fixes this reviewed input set:

```sh
python3 scripts/ci/pq_proof_profile_binding.py \
  --expected-profile-descriptor-sha256 9e5766a7eb14cb972531e12aa0be6d21a1e545400d89add72656b63c0f6407ad
python3 scripts/ci/test_pq_proof_profile_binding.py -v
```

The Python interface is
`inspect(root, manifest=DEFAULT_MANIFEST, expected_profile_descriptor_sha256=None)`.
A supplied digest must match exactly. If none is supplied, the reader can still
describe the current selected profile, but it reports
`candidate_profile_identity_matched=false`. A caller requiring a frozen
candidate must require that field to be true and must separately bind the
manifest hash and complete candidate identity.

Inputs are descriptor-bound regular-file reads. Duplicate JSON keys, unsafe
paths, malformed identities, Boolean byte counts, unsupported extra fields,
changed sources, missing fixtures, a different profile, omitted obligations
and self-declared qualification are refused. The reader compares input bytes
again before returning. These observations do not constitute continuous
immutability, authentication of the reviewer or executor, full dependency
closure, a fresh proof verification or a deployed-binary observation.

An exit-zero `PROFILE_BOUND_UPSTREAM_REVOKED_HOLD` means only that these declarations
and selected byte identities are consistent. The output always retains:

```text
actual_lifetime_failure_bound = null
composition_coverage_proved = false
whole_chain_hash_query_scope_closed = false
whole_chain_pq_qualified = false
production_activation = false
```

## Consolidated current source review, 2026-11-14

The explicit current mapping now binds source 5c04c60e463462d9df8884786e0d5bb32af08a64 and its 145-input local
inventory. Its descriptor SHA-256 is 8e95754db175bf8f2c4b3ffc0afe46f7b1eff476479d15fb2c005bf6d79dd0f1. The mapping,
profile descriptor, upstream-policy mapping pin and route-source pin are
updated together; the candidate workflow and independent controls require the
same descriptor. The preceding 9e5766a7 descriptor remains a rejected current
identity.

The selected SDK, guest image, control root, verifier parameters, fixed proof
assets and all 15 open obligations retain their original identities. The
upstream policy remains the dated 2026-11-11 observation, with an empty current
approval list. No new upstream advisory check or reinstatement is claimed.
The diagnostic status remains PROFILE_BOUND_UPSTREAM_REVOKED_HOLD and
--require-current continues to refuse.
