# Inert Node resource snapshot accounting

`resource_snapshot_fold.hepta` implements the three-lane accounting
projection of the exact frozen private Rust `State::snapshot`. It accepts
only synthetic typed contents, not real Node state, a journal, or an
authorized replay. The differential uses original typed `State` and
the full original snapshot method with deterministic synthetic keys and
fixed valid profile metadata. Neither implementation opens a Node owner.

The borrowed frame `NRSF0001` begins with the 8-byte magic, an LE u64 row
count, the three grant pairs (bootstrap, committed, recovery), and one
overshoot pair. Every resource pair is LE u64 CPU then LE u64 I/O. Grant
components and overshoot CPU are positive, and all eight components are
at most 2^60. This is the valid profile family obtained with the original
fixed nonzero synthetic owner ID and fixed legal operation/in-flight
limits; it is not an ABI for general profile identity or validation.

Exactly 0–1024 rows follow, in synthetic map iteration order. Each row
is nine LE u64 words: class (0–2), state (0 reserved, 1 running, 2
settled), charge tag (0 none, 1 measured, 2 conservative), execution
pair, cleanup pair, measured pair. Non-measured tails must be zero.
Record construction is not validation of a real request, charge,
receipt, or operation. Rust snapshots ignore charge for unsettled
records. A settled missing charge remains the original journal-state
diagnostic; this ABI does not read a journal.

The 328-byte result is three 104-byte lane rows, then two LE u64
diagnostics (original `admission_fenced` and
`within_declared_accounting_bound`, in that order; each 0/1). Each lane
is: grant, charged, in-flight execution, in-flight cleanup, available
option tag (0/1), available pair (zero if absent), retained count and
unresolved count. Observing either diagnostic conveys no permission,
guarantee, or admission decision. Replay order is used only as the
arithmetic order of explicit inert rows. No profile hash, real sequence,
time, record identity, physical resource qualification or service
qualification is emitted.

Status 0 denotes a result, 1 malformed frame/out-of-family profile,
2 insufficient caller workspace or output, 32 the original arithmetic
overflow, 33 the original missing-settled-charge diagnostic. The input
is immutable. Output is written only after all checks complete; the
unused output tail and scratch tail are preserved. At least 328 bytes
of scratch are required; the first 328 bytes can change once work begins,
including on typed refusal. With enough scratch, original typed errors
precede a short output. No clock, file, network, live resource ownership,
reserve, settle, or replay operation is present.
