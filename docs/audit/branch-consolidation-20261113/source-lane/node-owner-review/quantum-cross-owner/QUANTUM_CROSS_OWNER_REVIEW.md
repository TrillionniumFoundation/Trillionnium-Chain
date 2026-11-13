# Quantum cross-owner source disposition

Selected source: `395af460d0c1b6e48a7ede41f230b2954c52c1a3`. This is a static source review; no native tests or campaign were executed. All HOLD and activation fields remain unchanged.

## proof_wire/root role codec

Original head: `360556e9664fcb563877c05e74fd83974a5d9dba`. **superseded_current**.

proof_wire.rs:74 deserialize_roles accepts only canonical names 1..4, rejects duplicate roles before insertion; Root::kernel still enforces four roles, keys/quorum/domain. root_separation_tests.rs:8,46,83 and245,319,368 cover all tagged boundaries, complete roots, duplicate/alias/unknown/canonical spellings. Current exact-byte codec remains the canonical serialization owner.

## sealed metadata recheck/refusal

Original head: `360556e9664fcb563877c05e74fd83974a5d9dba`. **superseded_current_stronger_refusal_controls**.

sealed_tests.rs:60,82,297 and later ctime-only controls distinguish content seals from metadata identity. Current source refuses changed identity for read/copy/descriptor/exec and retains CLOEXEC on refusal; no metadata pin refresh. Incoming blanket recheck-success after every denied write is incompatible with selected O_RDWR description because Linux may change mtime/ctime on a denied write.

## read-only reserved descriptor conversion

Original head: `360556e9664fcb563877c05e74fd83974a5d9dba`. **archived_descriptor_policy_alternative**.

Incoming sealed_handoff_retains_reserved_descriptor_as_read_only_and_cloexec presupposes original branch Sealed::validated reopening O_RDONLY and atomically replacing the reserved owned descriptor with dup3. This selected source keeps sealed O_RDWR creation descriptions and complete identity refusal. Both preserve byte/seal authority and reject real metadata change, but only the archived variant promises an unchanged identity after denied writes. Do not copy this test alone or claim selected O_RDONLY equivalence. The extra capability attenuation may be considered independently later; it is not required to retain the present fail-closed authority contract.

## PQ CLI enum-null diagnostic

Original head: `360556e9664fcb563877c05e74fd83974a5d9dba`. **superseded_current**.

pq_application_local_cli.rs:187-201 independently expects null owner_profile to contain expected value and null witness to contain invalid type: null; all refusal checks precede owner mutation, with added current config/profile cases. Retain current broader diagnostic test.

## growth ancestry precheck and post-W1 recheck

Original head: `9fc0ff44d7406a042c15befe2eb874c430143d96`. **superseded_current_stronger**.

growth.rs:140-157 checks complete parent ancestry at the same fresh clock before full W1 and before duplicate fast return. growth.rs:189-216 rechecks after unlocked W1 under original callback and uses admit_growth_work_checked_with_completion with original ServiceMutationCpuCheckpoint. growth/tests.rs:449 already expects no fresh durable admission/work for future ancestry; :812 separately checks fresh+duplicate refusal before work plus a subsequent eligible listener request. Keep current full paid completion semantics; do not restore older worker-only admission.

## Scope

The quantum formal/source additions and test-only quantum bridge module remain root-owned. This review covers only the listed Node release owner and growth paths. Exact selected blobs are recorded in review.json. The read-only descriptor policy is explicitly not claimed as equivalent coverage.
