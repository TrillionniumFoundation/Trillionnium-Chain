# One-loan immutable tensor readback

The candidate takes the same private envelope as tensor reader framing:
32-byte independently supplied TMT1 content digest, BE16 file index, BE32
TMT1 length and TMT1, BE32 TMR1 length and TMR1, then the entire Safetensors
container. It checks one borrowed input from declaration through final digest.
No previously validated flag, decoded-header buffer, layout, trusted pin, or
caller-supplied computed digest is accepted in place of these bytes.

The native profile is 1 MiB for the whole loan, up to 128 KiB JSON header,
128 declared JSON tensors and 64 metadata keys; 293,256 bytes of private
scratch are required. This is smaller than the original reader and visitor.
The two existing native entries keep their exact source/ABI. Framing's
published CFG is reused by a pinned mechanical derivation which carries the
previously validated TMR member's expected SHA offset into the next stage.
The published header parser itself processes the bounded nested JSON span.
Scratch areas are deliberately disjoint: the parser uses up to byte 291071,
the saved declared digest position starts at 291072, and the 128 fixed
start/end interval pairs start at 291080. The exact TMT roster is reread from
the same immutable loan, never reconstructed by a host.

Original ordering within the bounded profile: declared pin/model/coverage,
selected file/length/header framing, entire JSON, roster count, then each
canonical name's metadata followed by that tensor's exact byte range. Next,
numeric intervals are sorted and checked for contiguous coverage and complete
data consumption. Finally, the original full container SHA-256 is computed
and compared with the selected declared TMR digest. Roster order can differ
from both JSON encounter order and physical interval order. All checks run
before the output copy. Status 0 emits 114 bytes: contract digest (32), model
root (32), LE16 file index, LE64 tensor count, LE64 payload byte length, SHA-256
(32). The returned projection matches public Rust `CellTensorReadbackV1`.
It does not publish private ranges, handles or authorization.

217 is original JSON refusal; 218 is outside this private JSON profile;
219–224 are original roster count, roster metadata, per-tensor range, sorted
hole/overlap, trailing data, and final digest refusals. Framing and ordinary
capacity/internal results are unchanged. A loan beyond 1 MiB is not admitted
by the standard ABI. A larger original profile accepted in the test is not
claimed native.

Qualification uses the unchanged, locked original public
`CellTensorContractV1::verify_reader` through a standard `Cursor` over generated
synthetic bytes with a non-restrictive test deadline. This pure value candidate
has no live reads, seek behavior, clock or deadline, storage, loader, owner,
deployment, or production admission semantics.
