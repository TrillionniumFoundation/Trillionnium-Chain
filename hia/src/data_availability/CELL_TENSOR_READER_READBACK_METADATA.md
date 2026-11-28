# Full metadata immutable Safetensors readback

This independent candidate composes the existing three-loan reader with the
unchanged bounded sorted-run metadata kernel. It accepts the original 1,024
metadata keys inside a 1 MiB raw JSON header, alongside the qualified 128 tensors.
The total logical frame remains at most 2 MiB. Direct `f1` borrows independent
declarations plus LE64 prefix, complete raw header and complete tensor body,
each at most 1 MiB. Selfhost `f0` borrows the same frame contiguously with the
existing private fixture bound. Previous standalone and reader entries stay
unchanged; no compiler, loan or logical input limit is raised.

Scratch is exactly 446,976 bytes, also used by the standalone metadata
candidate. The declared digest locator remains live across parsing in the
8-byte window [159992,160000), outside the tensor name arena (at most 52640),
the parsing temporary [160000,160256), and the metadata key and index arena
[160256,446976). After metadata validation finishes, interval sorting and
coverage reuse [291080,293128); there is no subsequent metadata read. Output
uses a physically separate mutable loan and is not published until digest
equality and output capacity are both checked.

The header and body are not host-validated: native execution binds the real
selected declaration, validates JSON and layout and hashes the actual raw
container bytes before publication. Frozen Rust `verify_reader` using owned
synthetic `Cursor` bytes supplies the exact 114-byte value and original error
classes. Tests accept a 1 MiB dense 1,024-key header with all decoded metadata
keys at 255 bytes, 128 rank-eight tensors and an exact 2 MiB frame. A same-size,
well-formed edit in either header or body fails the final digest independently.
The 1,025th key and an escaped duplicate fail JSON before digest comparison;
a wrong declaration pin still fails first. Borrow-state diagnostics on both
stock emitters check the live digest locator, first and last intervals and
refusal without output publication on the same dense input.

No original file stream, clock or deadline behavior, tensor execution, live
storage, loading, authentication or production authority is in scope.
