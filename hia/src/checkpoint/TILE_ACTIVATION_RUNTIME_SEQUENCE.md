# Bounded nested positional Runtime activation

The private three-buffer wrapper accepts the same immutable composed
activation frame and bounds, with one explicit additional representation:
a named root can carry Runtime as exactly 16 positional members. They are
decoded in frozen Rust `Runtime` struct declaration order:
device, python, torch, transformers, safetensors, numpy, threads, base_only,
training, local_files_only, trust_remote_code, forward_calls, hook_calls,
parameter_count, storage_dtype, material_manifest_sha256.
No caller-supplied positional index or extracted typed value is trusted.

After the same raw pin and strict lexical checks, the wrapper indexes the
already scanned primitive array in private scratch, then applies the same
concrete type projection and full activation semantic checks to it. Missing,
extra or mistyped positional members return the concrete typed refusal. The
named Runtime object remains supported. Frozen Rust also accepts some
positional root representations; TAR1 still excludes those (status 103).
Old named-only composed and typed wrappers intentionally keep their previous
scope, statuses, output bytes and scratch bound.

The full frozen original private activation with an inert test observer
is the oracle for both supported nested forms, original refusal precedence
and exact decoded bytes. Native invokes no observer or model execution,
file, network, verified material, training, provenance or authority.
