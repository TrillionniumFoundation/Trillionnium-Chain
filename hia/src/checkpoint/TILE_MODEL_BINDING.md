# Private checkpoint matrix byte and digest comparison

The input is one immutable numeric frame (the unchanged TAR1 activation and
checkpoint layout) followed by 16,384 expected A bytes, 16,384 expected B
bytes, 32 expected artifact digest bytes, and 32 expected input digest
bytes. The footer of the numeric subframe is read at that subframe's end,
not the whole loan's end. The whole loan remains limited to 1 MiB. The
existing numeric, input format and checkpoint limits still apply. This
private profile does not cover every size accepted by the Rust API.

The original A/B bytes are produced inside private scratch. If either
differs from its supplied expectation, the result is `MATRIX_REPLAY` (40).
Only after both equality checks do SHA-256 framed with `TRNM-PON1\0` and
the original `artifact` and `qualified-task-input-v1` domains run. The
expected digests are supplied independently of the derived bytes. If
either does not match, the result is `MATERIAL_PIN` (41). Success copies
the two computed 32-byte digest values to output in order. All refusal
paths leave public output unchanged. The working span is still 500,000
bytes; scratch is private and can change on refusal.

The comparison witness executes the exact frozen pre-task Rust fragment
on owned inert synthetic checkpoint/activation loans, using the original
framework to assemble fixture expectations. It stops before building
any task/work identity. This is not the whole material API; original
context pre-validation, progress observers, task and descriptor
construction, model execution and production authority are outside
this entry. Neither fixture inputs nor the reported digests attest to
any real model, training or provenance.
