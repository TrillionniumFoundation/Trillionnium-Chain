# Local Node resource-vector value

`resource_vector.hepta` implements the immutable typed `ResourcesV1`
methods `add`, `within`, `subtract` and `validate` from the frozen Rust
`trnm-pon-node/src/resource_owner_v1.rs`. Arithmetic uses the complete
unsigned 64-bit domain: the separate validation ceiling does not limit
checked addition, containment, or optional subtraction.

`f0` takes a private 48-byte frame: eight bytes `NRVT0001`, a little-endian
u64 opcode, then two consecutive pairs of little-endian u64 CPU and I/O
values. Opcodes are 0 add, 1 within (both components), 2 subtract, 3
validate. The second pair must be zero for unary validate. Addition and
successful subtraction write a 16-byte pair; containment writes one
little-endian u64 0 or 1; validation writes nothing. The input, arena and
remaining output bytes are unchanged.

Status 0 is a typed result, 1 malformed frame, 2 insufficient output for
a typed result, 32 the original overflow error, 33 the original unit
error (a component greater than 2^60), and 34 represents original
subtraction `None` rather than a Rust error. Malformed frames and typed
failures do not inspect or write output; capacity failure leaves output
unchanged. In particular a valid unary value and a subtraction returning
`None` both work with empty output.

This component does not inspect a profile, validate resource admission,
observe time, mutate a ledger, reserve or release resources, or grant
authority. The paired test uses the pinned original method bodies and
error plumbing without linking a live Node owner and checks both stock
native emitters.
