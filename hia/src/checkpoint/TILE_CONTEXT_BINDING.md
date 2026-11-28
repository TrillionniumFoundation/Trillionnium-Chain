# Private tile context and numeric comparison

This entry takes the complete original private numeric and matrix-binding
frame, followed by two independent opaque 32-byte declarations for network
and parameters, in that order. The entire loan is bounded at 1 MiB; the
original fixture's declared checkpoint size may be larger, but the actual
held checkpoint cannot exceed the stock input cap. No file is opened.

Once basic physical frame bounds are proved, the original context checks
run first. The declared checkpoint size must be 10 through 536,870,912,
inclusive (42, `CHECKPOINT_LIMIT`). Then all six expected 32-byte
values must be nonzero (43, `PINNED_CONTEXT`): the two new suffix values,
the activation and checkpoint SHA pins in the numeric frame, and the two
detached model/input pins. These are actual in-frame values, not a separate
context compared against unrelated data. The two new declarations have
no authority or semantic interpretation here.

The bounded prefix is passed unchanged to the numeric replay and detached
material comparison, using the same immutable loan and exact prefix end.
Its refusal ordering and successful pair of inert digest values remain
unchanged. Output is untouched on refusal, including context errors.
The native work span remains 500,000 bytes. No original progress
observer is invoked by this native entry; no task, work proof, training,
live model, authorized decision or production material is created.

The frozen in-scope Rust differential starts with the actual context
validation in `derive_observed` and runs the contiguous original body
until immediately before task computation. Synthetic tests include all six
missing values independently, layered refusals, original u64 size
boundaries, both activation layouts, and exact detached digest bytes.
