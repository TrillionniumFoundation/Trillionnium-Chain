# M15 linked shadow qualification

The fixed native HIA compiler refused a deduplicated 355,719-byte assembly
union of the six current stages with exit 2 and no ELF output. This
qualification instead compiles each of the six actual HIA objects separately.
It checks each object's import/export inventory and `.text` before and after
binding the private symbol, then links a single ELF with exactly one dynamic
export: `trnm_release_shadow_v1`. It runs both pinned emitters. A checked C
bridge does bounded frame custody, sequencing, comparisons, and final copy.
All cryptographic and content primitives still run the real HIA in the
linked objects. This is **not a pure HIA owner, public release API, or
production route**.

The private qualification protocol is `RSO1`, followed by little-endian state
and unsigned bundle lengths (32 bits each), selected NodeSoftware pin count,
threshold and signature count (16 each), and six zero reserved bytes. Next
come the exact borrowed [state/metadata layout](../../src/release_bundle/PQ_BUNDLE_STATE.md),
the [unsigned V0 candidate](../../src/release_bundle/UNSIGNED_CANDIDATE.md),
selected pinned SPKI roster and fixed-width [signature set](../../src/release_bundle/PQ_SIGNING.md).
The root scope used by both stable identity and quorum comes from the same
state frame, not the candidate's offered network. Shape and ABI errors are
private and do not assign new meanings to errors in the Rust release owner.

The entry requires stable readable input for the duration of the copy and
disjoint writable output. It takes one bounded private copy, owns all scratch
and intermediates, calls real unsigned validation, role identity, signature
locator, canonical message, ML-DSA quorum, and finally state plus checkpoint.
A return from math can only be observed inside that call. A scratch digest or
a supplied success flag cannot start the later state stage. The only
successful output is the 64-byte [proposal plus scoped descriptor identity](../../src/release_bundle/PQ_BUNDLE_CHECKPOINT.md);
it cannot approve a release or advance an authority. Capacity or refusal
leaves output unchanged. No inputs arrive through filesystem or live state.

The actual [locked Rust callback differential](../../tests/qualify_release_pq_callback.py)
compares staged HIA, the fused ELF call and unmodified original Rust over
ephemeral synthetic signed bundles. It tests compound rejection order,
borrowed input/output canaries, malformed private bounds, independent stale
anchor refusal after true math, and success after refusals. A scoped PASS does
not prove production snapshot freshness, root-role custody, persisted replay
or transfer the Rust caller's existing private verifier token.
