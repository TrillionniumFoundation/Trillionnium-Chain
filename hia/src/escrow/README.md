# Private native settlement vault

`vault.hepta` implements the complete public value and state operations of the
unchanged `trnm-escrow-vault` crate. HIA owns the owner identity, paused state,
account balances, request locks, audit events, and independent clones inside
real private allocations. It implements all seven changing methods and all
public queries, raw/normalized audit retrieval, audit consumption, and Clone.

This is a **private session owner**. A session supplies an ordered collection
of public method calls and receives their complete results. The native code
copies the admitted UTF-8 inputs into its own allocation, creates and grows
its own state arena, and retains every owner throughout the session. No public
argument contains a State snapshot, authorization result, balance table, lock
table, event list, allocator address, or writable owner context. The third
foreign scratch argument is unused and unchanged.

The current entry accepts a complete ordered session and releases all private
allocations before returning. An incremental streaming lifetime API, live Node
caller, durable settlement storage, crash recovery, external caller
authentication, and the original whole-service acceptance remain integration
work. The component does not retire the original package and does not confer
consensus or production authority.

## Exact original behavior

- The constructor accepts every Rust `String`, including empty owners, Unicode
  whitespace, and embedded NUL. Caller identity compares complete UTF-8 bytes.
- Accounts are opaque complete strings. Beneficiary validation rejects only
  strings that are empty after Rust Unicode whitespace trimming. Valid account
  names are never trimmed, normalized, case folded, or NUL terminated.
- Request IDs must be nonempty and have no leading or trailing Rust Unicode
  whitespace. Interior whitespace and NUL remain ordinary contents.
- Amounts and balances retain every `u128` bit. Addition checks both 64-bit
  words and carry. Separate accounts may together hold more than `u128::MAX`.
- Every method preserves the original error order. Authorization precedes
  pause and argument checks. Release/slash validate destination credit before
  changing lock status; transfer validates destination credit before debit.
- Self-transfer checks sufficient balance and appends its original event
  without changing the balance. Zero balances are removed from the live map.
- Released and slashed locks remain present permanently within the owner, so
  their request IDs cannot be reused. Rejected changes append no event and
  leave balances, locks, and pause state unchanged.
- Clone copies the actual live owner records and event order. Subsequent
  changes, consumption, and destruction are independent. Consume removes only
  audit events. Normalized events preserve all original option-presence bits,
  strings, and `u128` amounts, including the exact `beneficiary=` note prefix.

The whitespace table is the original Rust Unicode White_Space set:
U+0009–000D, U+0020, U+0085, U+00A0, U+1680, U+2000–200A, U+2028,
U+2029, U+202F, U+205F, and U+3000. U+001C–001F, U+180E, U+200B,
and U+FEFF are not whitespace under this contract.

## Native boundary

The foreign entry is
`f0(input: readbuf, output: mutbuf, scratch: mutbuf) -> u32`.
All integer words in the session protocol are unsigned little-endian `u64`;
amounts are two words, low then high. The complete input is validated before
creating a vault. All string fields are independently validated UTF-8. There
is no fixed per-string, account-count, lock-count, or history-length limit in
the component. Actual buffer extents, address space, memory allocation, and
the caller's execution budget bound an invocation.

The input has a 32-byte header:

| Offset | Field |
| --- | --- |
| 0 | Eight bytes `VES10001` |
| 8 | Exact number of method frames |
| 16, 24 | Reserved zero words |

Every method frame has a 64-byte header followed by the three complete strings
in order. Each command's declared lengths must exactly fit the next frame;
trailing data and unused nonzero arguments refuse the complete session.

| Offset | Field |
| --- | --- |
| 0 | Operation |
| 8 | Owner handle; zero for New |
| 16, 24 | Amount low/high words |
| 32, 40, 48 | Caller, A, and B byte lengths |
| 56 | Reserved zero |
| 64 onward | Caller, A, and B UTF-8 bytes |

Handles are native-issued monotonically increasing session-local identifiers,
starting at one. They are selectors for existing private owners, not pointers
or authentication claims. Drop invalidates the selected owner and its records;
handles are never reused in the same session.

| Operation | Original operation | Caller | A | B | Amount |
| --- | --- | --- | --- | --- | --- |
| 0 | New | New owner | Empty | Empty | Zero |
| 1 | Deposit | Caller | Account | Empty | Deposit |
| 2 | Lock | Caller | Request ID | Account | Lock |
| 3 | Release | Caller | Request ID | Empty | Zero |
| 4 | Slash | Caller | Request ID | Beneficiary | Zero |
| 5 | Transfer | Caller | From | To | Transfer |
| 6 | Pause | Caller | Empty | Empty | Zero |
| 7 | Unpause | Caller | Empty | Empty | Zero |
| 8 | Owner | Empty | Empty | Empty | Zero |
| 9 | Is paused | Empty | Empty | Empty | Zero |
| 10 | Balance of | Empty | Account | Empty | Zero |
| 11 | Lock record | Empty | Request ID | Empty | Zero |
| 12 | Audit log | Empty | Empty | Empty | Zero |
| 13 | Consume audit log | Empty | Empty | Empty | Zero |
| 14 | Normalized audit log | Empty | Empty | Empty | Zero |
| 15 | Clone | Empty | Empty | Empty | Zero |
| 16 | Drop session owner | Empty | Empty | Empty | Zero |

The result starts with `VER10001`, operation count, exact result byte length,
and a reserved zero word. Every response has operation, supplied owner handle,
method status, payload byte length, then the complete payload. The unused
output suffix is preserved. New and Clone return the newly issued handle as
one word. Owner returns the original owner bytes. Is paused returns one word.
Balance returns a complete `u128`. Changing methods and Drop have empty payloads.

Lock record begins with presence 0 or 1. An absent record ends there. A present
record then contains status (0 Locked, 1 Released, 2 Slashed), amount low/high,
account byte length, and the account bytes.

Raw audit logs begin with event count. Each event has event kind (1 Deposited,
2 Locked, 3 Released, 4 Slashed, 5 Transferred, 6 Paused, 7 Unpaused), amount
low/high, four string lengths, and caller/A/B/C strings. Deposit uses A=account;
Lock/Release use A=request and B=account; Slash adds C=beneficiary; Transfer uses
A=from and B=to. Pause/Unpause use only caller and zero amount words.

Normalized audit logs begin with count and contain the complete `NAER0001`
records defined in the [native AuditEvent contract](../audit/README.md).

Method statuses preserve the original error variants:

| Status | Meaning |
| --- | --- |
| 0 | Success |
| 1–4 | Unauthorized, Paused, AlreadyPaused, NotPaused |
| 5–8 | InvalidAmount, InvalidBeneficiary, InvalidRequestId, InsufficientBalance |
| 9–12 | DuplicateRequest, RequestNotFound, InvalidStateTransition, BalanceOverflow |
| 64 | Session owner handle is absent or dropped |

Native entry status is separate: 0 complete session published; 1 malformed
frame; 2 invalid UTF-8; 3 insufficient complete-result capacity; 4 actual private
allocation or representable arena-capacity refusal. Every nonzero entry result
preserves the entire external output. Intermediate results stay private.
Allocation failures release all acquired owners, including the predecessor
arena when growth fails. No partially executed session can be resumed or
mistaken for an accepted transcript.

The arena grows geometrically through actual HIA `buffer.try_new`. New private
storage receives all used bytes before the old owner is dropped. Clone copies
records rather than retaining mutable aliases. Zero-balance records become
inactive tombstones and are excluded from lookup and Clone; Consume and Drop
clear their selected records. The aggregate arena and immutable session string
owner are released when the session ends. This is not an assertion of
cryptographic allocator erasure.

## Execution and independent comparison

Set the locked `HIA_TOOLCHAIN_ROOT`, `HIA_NATIVE_COMPILER`, and
`HIA_NATIVE_COMPILER_SHA256`; then run:

```sh
python3 -B -m unittest hia.tests.test_escrow -v
```

`rustc` and a C compiler for the allocation-fault interposer are mandatory.
Missing tools fail the suite. Tests compile the complete unchanged original
AuditEvent and SettlementVault crates, execute all their retained unit tests,
and link `rust_escrow_reference.rs` against those actual libraries. The adapter
only frames public calls and serializes returned values; it implements no
balance, lock, authorization, error, or event logic.

The native test child loads only a sealed snapshot of the emitted HIA shared
artifact, with independent misaligned buffers, byte guards, and resource
limits. It does not load a host compiler or a Python vault model. The artifact
uses the exact pinned self-hosted compiler; its ordinary shared-library loader
and `calloc`/`free` boundary remain explicit.

Set `TRNM_HIA_ESCROW_OUTPUT` to a **new** directory to retain original binaries,
test stdout/stderr, actual native compiler receipt and artifact, complete
comparison streams, all native worker requests/stdout/stderr, and `report.json`.
Without that variable the same execution uses a temporary directory.
The report schema is `trnm.hia.escrow-development.v1`; every captured file has
an independently computed size and SHA-256. Its observations remain distinct
from commit-bound hosted qualification and whole-Node acceptance.
