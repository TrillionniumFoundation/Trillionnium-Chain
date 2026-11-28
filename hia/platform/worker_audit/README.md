# Owned Worker audit output library

This candidate exposes exactly one Linux x86-64 shared-library symbol,
`trnm_worker_audit_export_v1`. Its arguments are three borrowed pointer/byte
length pairs documented in [the C declaration](worker_audit.h). It accepts
only the [WJB3 typed input](../../src/worker_agent/audit_jsonl_batch.md) and
returns the length of the complete ordered JSONL stream written into caller
memory. A zero-length output is a successful empty selection.

The entry accepts live, disjoint storage valid throughout the synchronous
call. Input and output extents are at most 1 MiB, the existing direct
foreign-buffer ceiling. The third length is reserved and must be zero.
The result's high 32 bits report a direct foreign-buffer guard refusal,
if any. In-domain calls return a zero high word and a low word with the
byte count, `0xffffffff` for invalid input/ABI version or nonzero reserved
extent, or `0xfffffffe` for inadequate capacity. Beyond-capacity extents
return a direct ABI extent refusal or the selfhost low-word capacity
error. The selfhost profile relies on the caller's live, disjoint memory
precondition; the entry does not authenticate arbitrary native pointers.
The output tail is unchanged on success, and malformed or insufficient
requests do not write to output. The older internal WJB entry still accepts
all three existing frame versions under its original limits.

## Build and independent observation

With project preflight and the qualified pinned HIA toolchain, choose a
fresh child directory of a private owned directory outside the checkout:

```sh
python3 -B -m hia.platform.worker_audit.build --backend selfhost --output /private/proof/selfhost
python3 -B -m unittest -v hia.tests.test_worker_audit_owned
python3 -B -m hia.tests.test_worker_audit_owned --output /private/proof/actual \
  --original-binary /private/locked/trnm-worker-agent \
  --original-build-receipt /private/locked/build.json
```

An explicit HIA emitter produces the underlying object. A symbol-table
rename and closed linker map label it; the builder compares the original
and renamed `.text` byte for byte, rechecks exact source/tool identities and
checks the resulting dynamic symbol inventory. The selfhost artifact has
no imports or library dependencies; the direct emitter's sole `abort`
import and libc dependency implement its trap epilogue, not formatting,
I/O, or caller callbacks. There is no authored C or Rust bridge. The
test child opens and calls the exact emitted library under its public
symbol. The original Rust executable from the existing locked build is
run independently on its local, synthetic journal fixtures, then the two
named HIA artifacts must emit the complete original JSONL bytes. The
proof retains per-artifact build identity and output receipts. Processes
and file writes in this command are test/build ownership, not an effect
of invoking the named audit entry.

This candidate is not installed, linked into production, or granted
filesystem authority. The original Worker still owns journal parsing,
record sources, nonported conversion facts such as protocol and fingerprints,
publish/index, and production dispatch. Neither candidate success nor a
matching fixture authorizes retiring that owner.
