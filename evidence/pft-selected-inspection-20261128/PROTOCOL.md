# Selected PFT candidate inspection v1

Frozen before implementing the adapter or running its new binding controls.
This is a new profile for the existing TCV1 container. It changes no old family's
layout, tensor representation, loader dispatch or adoption policy.

The inspection namespace is `trnm.pft.selected-candidate-inspection.v1`.
The required TCD1 loader-profile digest is SHA-256 of these exact concatenated
UTF-8 components, each followed by a NUL byte:

1. `trnm.pft.selected-candidate-profile.v1`
2. `hcsn-pft-readout-research-v1`
3. `trnm.pft.native-pinned-json-loader.v1`
4. `trnm.pft.binary64-rounded-products-exact-sum-rne.v1`

The model family must equal the second component. Only under this fresh profile,
TCV1 model context `base` binds the PFT `parent_model_sha256`, and `layout` binds
SHA-256 of the declared original `contract_canonical_json` string. `tokenizer`
must be SHA-256 of `trnm.pft.expanded-features-no-tokenizer.v1` followed by one NUL.
The TCV1 `parent`, runtime/environment relation, lineage, generation and original
adoption rules keep their existing meanings and checks. The profile does not
execute features or normalization or interpret an existing tokenizer artifact.
A changed fixed base/layout/profile needs the original independently authorized
boundary and fresh owner namespace; the adapter performs no migration.

The model TCD1 contains exactly one Base file at `pft/online-candidate.json`,
one root index 0 and no file dependencies. The environment remains the complete
original TCV1 environment declaration. The original adoption owner's transaction
must supply the actual selected manifest to the callback. The adapter accepts no
caller-supplied manifest or expected model pins as selection authority.

Inside that callback, the selected file's complete payload size and SHA-256,
contract layout pin and parent/base pin are the reader's independent references.
The candidate must be 1..16 MiB, match those bytes exactly, and pass the existing
strict JSON framing, full contract/head/batch/shape/numeric and weight LE checks.
Head, weight, feature semantics and objective fields are fixed by the complete
selected candidate hash; they are not accepted as unauthenticated external pins.
Declared canonical strings are hashed verbatim, without reproving Python float
canonicalization. Binary64 decimal decoding, including rounded signed zero,
retains the #1022 profile.

The adapter returns only a typed nonauthorizing observation of the selected
commitment/revision/generation and bounded model descriptor. It exposes neither
weight bytes nor a prepared/executable model handle, reads no feature packet,
and performs no prediction. The selection is current only during the original
transaction. This observation is not reusable authority after that fence.

The original selection owner supplies durable local selection, not the host's
current Root authorization, withdrawal/resource guard or FinalUse. Without those
original objects, actual execution remains disconnected and adoption=false.
No int257/TMT1 reinterpretation, quantization, transpose, user B, quality claim,
training statistics, normal equations, payment or production activation occurs.

Engineering verification separates two scopes. Real SQLite owner repository
tests belong to complete-crate CI and stay pending until actually observed.
Only the new pure binding/refusal controls may run in a separate offline harness,
with its own exact-source receipt and one bounded 120-second engineering gate.
Do not rerun the prior 9 loader or 11 arithmetic controls, historical inference,
training, labels, DEV or final data. Synthetic binding tests do not claim to have
exercised the original owner or to establish permission.
