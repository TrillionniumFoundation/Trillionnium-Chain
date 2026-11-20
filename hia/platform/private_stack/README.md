# Native private stack for secret-bearing calls

`linux_emitter.hepta` emits a 288-byte Linux x86-64 adapter followed by the
unchanged native kernel image. The emitter is itself compiled and executed by
the pinned HIA native compiler. Hosted code captures sources, invokes native
stages and checks exact byte identities; it does not assemble runtime code.

The adapter retains the six-register borrowed-buffer `f0` ABI. It saves only
the original callee-saved registers and public buffer pointers/lengths on the
caller's stack, creates a private anonymous mapping, enables a 1 MiB inner
stack between two inaccessible 4 KiB guards, and calls the captured kernel on
that stack. On every ordinary kernel return it restores the caller's stack,
zeros the complete private 1 MiB with `rep stosq`, and releases the mapping.
It restores callee-saved registers, clears caller-saved argument/temporary
registers and the direction flag, and returns only the public result code.

The instruction bytes are an explicitly trusted ISA boundary. Successful Core
admission of the emitter checks its buffer operations; it does not prove the
semantics of those literal machine instructions. The adapter requires a trusted
kernel that follows the native compiler's x86-64 calling convention, does not
change its private mapping permissions or escape its stack, and uses no SIMD
registers for secrets. The current signing image uses integer instructions.
This is not a generic isolation boundary for arbitrary machine code.

The caller must enter this boundary without unrelated secrets in callee-saved
registers. Their original values belong to the caller and are saved/restored on
its stack; this adapter cannot erase that preexisting caller state while also
preserving the calling convention. The observed fixture acquires seed bytes
directly into its input buffer and passes their address. A future key owner
must establish the same entry discipline or put its entire secret-bearing call
chain inside this boundary.

## Errors and output publication

| Result | Meaning |
| --- | --- |
| Original kernel result | Kernel returned and the private mapping was released |
| `0x80001000 \| errno` | `mmap` failed; the kernel was not called |
| `0x80002000 \| errno` | `mprotect` failed; the kernel was not called and the mapping was released |
| `0x80003000 \| errno` | `munmap` failed; if the kernel ran, its entire private stack was already zeroed |

A high-bit private-stack result is fatal for that invocation. In particular,
the output may already contain a complete signature when `munmap` fails. The
connection/response owner must not publish any output for that return code.
The original mathematical kernel's no-output-on-refusal property does not
cover this later OS cleanup failure. Failed release also retains an anonymous
mapping until the containing process reclaims it; a long-lived owner must
terminate/reap that failed invocation rather than retrying without bound.

The emitter accepts native images of 1 through 524,288 bytes. The adapter's
1 MiB stack is separate from input/output/work arenas and does not limit the
frame size. Each containing kernel must be exercised through this wrapper at
its own admitted extents. The adapter does not erase caller-owned input or
work buffers: the mathematical signer wipes its declared workspace, and the
future private key owner must control the seed's complete lifetime.

## Observed defect and verification

The unwrapped signer genuinely left secret-dependent bytes on its compiler
stack after returning, despite wiping all 141,568 workspace bytes. Tests used
three public synthetic seeds and observed seed, clamped scalar, prefix and
nonce-scalar byte spills at specific stack offsets. The original observation
remains FAIL; searching only for contiguous 32-byte secrets had missed it.

The wrapper's native development checks preserved the exact signature output
for all three seeds and left those caller-stack positions untouched. Additional
test-only restrictive seccomp filters made actual Linux `munmap` return EPERM.
The unchanged production prefix returned `0x80003001`; an observation shim
read all 1,048,576 bytes of the retained private stack and found every byte zero.
An unrestricted observation received ENOMEM from `mincore` after normal
release. Actual allocation and protection denials returned their distinct
errors without calling the kernel or modifying output/work. Test observers
are instrumentation, not runtime components or alternative signing code.

These checks cover ordinary returns and the observed OS failures. They do not
certify cleanup after traps, stack exhaustion, signals, process suspension,
core dumps or swapping. They do not prove machine-level constant time, erase
the caller's seed, establish key-file permissions, or close the complete Node
key and connection owner. Those requirements remain explicit integration work.
