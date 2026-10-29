# Bounded W1 receipt loopback observation candidate

This candidate supplies an executable Linux research harness for a retained,
genuinely verified W1 Composite receipt. The local validation completed **13
controls**, including eight actual TCP loopback cases with **synthetic,
non-proof bytes**. No real receipt was available to this candidate's validation.
Actual proof verification and receipt propagation costs remain **unmeasured**.
The script cannot qualify a cost until an explicitly trusted real verifier
accepts the original receipt, all transport cases complete, the same verifier
accepts the received bytes, and the outer process owner completes cleanup.

The candidate is based directly on Chain commit
`974932be6dcfe830ce1ce92d58cb10e89cb8358d` (E), tree
`d4435ebdecac15e9a3fb2852eb1f835b336e452e`. It adds two Python files and evidence.
It does not modify the existing host, guest, receipt parser, backend manifest,
PoN predicates, workflows, or proof budgets. The separately running four-hour
cost profile remains a separate observation; it cannot erase E's original
5,400-second proof timeout.

## Sources and acceptance

The implementation is
[measure_w1_receipt_loopback_v1.py](../../scripts/ci/measure_w1_receipt_loopback_v1.py)
and its finite controls are
[test_w1_receipt_loopback_v1.py](../../scripts/ci/test_w1_receipt_loopback_v1.py).
The harness SHA-256 is
`001fe427999077a254dfdff7c747103cd1d75350566658b1817534ea85c59fa8`;
the test SHA-256 is
`9585a3bf42bad57b767f7b85b06b1bf1cde0534f0a0ff099042ffba0d9f832b4`.

The harness requires the exact original E process owner, SHA-256
`fb3fd8a033ac0781052b5da55577bbeb59e6f4c714d2b4b3ff8e2c6c866e62bd`,
Git blob `6669976055d77cb1966611d7aba2d80abac76cc7`. It makes private copies
of that source and its own source before running. It adds a documented
cancellation adapter around the owner's deadline checks; the original owner
file is unchanged. **Use this E-based checkout as `--repository-root`.** A
checkout containing the cost profile's different owner bytes is deliberately
refused. The proof artifact may come from that separate cost run: its expected
commit is supplied independently, and its backend manifest must still match E.

The public entry requires source-before/source-after equality, a verified
tracked worktree, the explicit expected proof commit, successful original prove
records, stable original prover identity, and finite original cleanup. It then
holds regular files by descriptor, fingerprints their bytes and identities,
and calls the real host's existing `verify` operation. The ELF, input and
receipt are passed as inherited descriptors through `/proc/self/fd`; the
verifier executable is also executed from its held ELF descriptor. Identities
are checked before and after both verifications.

`--expected-host-sha256` is an independent caller trust input. The harness does
not establish source provenance merely by reading this string. It records the
actual verifier digest, original prover host digest, and whether they match.
A separately rebuilt host is permitted, but its measured costs are costs of
that actual rebuilt executable. They must not be described as a measurement of
the original prover ELF unless the hashes match. Successful child exit alone
is insufficient: the host's real Composite verification fields, statement,
image and receipt length must match.

## Transport and fixed bounds

E's existing `PWAI0001` admission format accepts Succinct receipts with a
1 MiB total packet cap. After its 16-byte header and 49,640-byte input, only
998,920 bytes remain for a receipt. That format does not admit this Composite
research object. The harness uses a separate `PWCO0001` research frame on
**127.0.0.1 IPv4 TCP only**. It makes no production admission or WAN claim.

| Bound | Fixed value and scope |
| --- | --- |
| Input | Exactly 49,640 bytes |
| Receipt | 1 through 134,217,728 bytes |
| Frame | 16-byte header plus input plus receipt; at most 134,267,384 bytes |
| Streaming chunk | 65,536 bytes; header rejected before body files or allocation |
| Campaign | 2,400-second owner work deadline, then original five-second cooperative cleanup |
| Verifier | At most 900 seconds of work per child, then at most two seconds of cleanup within the campaign deadline |
| Network case | At most 30 seconds, further restricted by remaining campaign time |
| Worker / verifier address space | 2 GiB per process; not a family or cgroup memory bound |
| Verifier CPU / logs | CPU soft/hard limits 1,800/1,801 seconds; each log at most 128 KiB |
| Parallelism | `RAYON_NUM_THREADS=2`, one verifier child and one receiver thread at a time |
| Network cases | Three positive transfers and five finite invalid frames |

The negative frames are wrong magic, wrong input length, receipt length above
the cap, truncated receipt, and one trailing byte. Each receiver checks the
fixed header, exact streamed lengths, SHA-256 digests and EOF. Each case gets a
durable result before proceeding. All cases must pass; a socket timeout,
unexpected exception, verifier failure or incomplete cleanup remains an
operational failure. Only the third positive copy is retained for the final
real verification. Other files created by this invocation are removed after
their case record, limiting temporary receipt copies to two at a time.

Default SIGCHLD disposition is required. The outer owner reserves its process
group leader until signalling and reaping. Internal verifier children stay in
that group and do not create their own session. Their `waitid(WNOWAIT)` observation
does not reap before the final signal and `wait4`. Cancellation handlers only
set a flag. Every subsequent original work-deadline safe point refuses after
cancellation; the separate cleanup deadline remains operational.

These are cooperative process and I/O deadlines, with the original owner's
documented blocking-kernel-I/O limitations. Parent final record readback and
durable metadata writes occur after the owner returns; the 2,400-second figure
is not a hard wall bound on every instruction in the parent. Per-process
address-space limits and child peak RSS are not whole-family peak RAM.

## Running with a real artifact

The following command has **not** been run against an actual receipt in this
candidate. Use a fresh output directory, the retained artifact directory,
its exact proof source commit, and an independently trusted verifier digest:

```sh
RAYON_NUM_THREADS=2 python3 -B scripts/ci/measure_w1_receipt_loopback_v1.py \
  --repository-root "$PWD" \
  --artifact /absolute/retained-cost-artifact \
  --host /absolute/trusted/trnm-w1-risc0-host \
  --expected-proof-source EXACT_40_HEX_PROOF_COMMIT \
  --expected-host-sha256 TRUSTED_64_HEX_VERIFIER_DIGEST \
  --out /absolute/new-loopback-observation
```

`RISC0_DEV_MODE` must be absent. Required retained files are `source-before.json`,
`source-after.json`, `backend-manifest.json`, `prove.stdout.log`,
`prove.process.json`, `prove.observer.json`, `guest.bin`, `input.bin` and
`receipt.bin`. No SDK prover or new proof is invoked by this command.

The top-level acceptance record is `campaign-owner.json`. The worker result is
`campaign/result.json`; individual network records are `campaign/<case>.json`.
`campaign/verify-before/` and `campaign/verify-received/` retain host output,
wait4 CPU, peak RSS and elapsed time. Owner observations remain separate.

The transport wall measurement includes sender `pread`/send and receiver
receive/write/hash/fsync/EOF work. Sender and receiver thread CPU overlap the
worker's process CPU and must not be added to it. Successful application-byte
counters are not physical wire bytes and do not measure retransmissions.
Loopback timing cannot establish cross-node, WAN, bandwidth-contended or gossip
propagation cost. The three positive transfers are finite observations, not
percentile or universal worst-case estimates.

### Rebuilding the verifier without another proof

The cost workflow retains the guest and receipt, but does not copy its host ELF
out of the build directory. If that exact executable is unavailable, use a
clean E-based full checkout with this candidate's additions, the isolated
backend `Cargo.lock`, and Rust 1.95.0. Relevant E blobs are host `main.rs`
`e9953beab2d8833d271b454f50dc0c80ac251722`, workspace manifest
`a01b05aa419b5a17ad3cd0a1f8e08c0fc89b0d8d`, host manifest
`8514c3564a54e92f5cba938c58f24677dad9ed7d`, and isolated lockfile
`b3d413c55be3831770e0d05498a05917ed8b1e3a`. These are the same Rust inputs used
by the cost profile; its Python owner changes do not change those blobs.

The minimal native build command is the cost workflow's existing host build:

```sh
export RUSTC="$(rustup which --toolchain 1.95.0 rustc)"
native_cargo="$(rustup which --toolchain 1.95.0 cargo)"
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 RAYON_NUM_THREADS=2
export CARGO_TARGET_DIR=/absolute/exclusive-host-build-target
backend="$PWD/trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0"
python3 "$backend/measure_step.py" --out /absolute/new-host-build-records \
  --name host-build --timeout 1800 -- \
  "$native_cargo" build --release --locked --manifest-path "$backend/Cargo.toml" \
  -p trnm-w1-risc0-host
```

Capture source-before/source-after with the repository's existing source
checker, `rustc -Vv`, Cargo version, build logs, lockfile digest, actual ELF
digest and runtime resources. The command does not build a new guest, execute
W1, or invoke `prove`. It has not been executed for this candidate. No
bit-reproducible-ELF claim follows from using the same Rust sources.

The shared local filesystem had only approximately 630 MiB available when
this candidate was frozen. No local host rebuild was attempted. This is not a
measured sufficient Cargo build budget; a clean builder should reserve a
separate disk allocation and retain an out-of-space failure rather than
removing concurrent work or silently increasing its limit. The harness input
caps additionally allow up to a 256 MiB host and 16 MiB program, with at most
two temporary receipt copies plus bounded output during transfer. The old
target directories found locally were not established as this exact host
build and were not reused as trusted verifier executables.

## Validation and retained failures

[controls-reviewed.stderr.log](controls-reviewed.stderr.log) and
[controls-reviewed.process.json](controls-reviewed.process.json) record all
13 controls passing in 0.751 seconds. They cover header/length caps, unsafe file
types, growth after open, strict metadata, a real held ELF's nonzero exit,
owned-child timeout/reaping, nondefault SIGCHLD refusal, absent real artifact,
actual SIGTERM cancellation, deterministic swallowed-OSError cancellation,
eight actual TCP cases, digest mismatch and socket deadline failure.
[synthetic-wire-controls-reviewed.json](synthetic-wire-controls-reviewed.json)
explicitly labels the transferred bytes as synthetic. None is a cryptographic
proof success. [independent-source-review.json](independent-source-review.json)
records an independent source review and a separate deterministic cancellation
control; it does not claim a real-receipt run.

The initial sandbox refused creating an IPv4 socket with EPERM, so the network
controls were run with explicit approval for bounded localhost sockets. No
external endpoint was used. Earlier failures remain in this evidence:

* [prior-12-controls.stderr.log](prior-12-controls.stderr.log) and
  [prior-12-controls.process.json](prior-12-controls.process.json) retain the
  12-control run whose cancellation test timed out. It was not a passing run.
* [prior-one-shot-cancel.observer.json](prior-one-shot-cancel.observer.json) and
  [prior-one-shot-cancel.process-samples.jsonl](prior-one-shot-cancel.process-samples.jsonl)
  retain signal 15 being swallowed as sampling errno 4 under the previous
  one-shot adapter, allowing child and owner to exit zero naturally. This was
  a defect in the new adapter, not an observed defect in E's original contract.
  The final persistent work-deadline adapter fixes that mechanism.
* [final-cancel.observer.json](final-cancel.observer.json) and
  [final-cancel.process-samples.jsonl](final-cancel.process-samples.jsonl) retain
  the repaired real cancellation: outer exit 125, direct child wait4 exit -9,
  finite cleanup true and no secondary failures.
* [prior-fixture-ELOOP.observer.json](prior-fixture-ELOOP.observer.json) retains
  an earlier fixture refusal: unresolved `sys.executable` was a symlink and
  the E owner rejected it before spawn with ELOOP. An initial suggestion that
  this observed a Popen cancellation race was explicitly retracted. The
  fixture now resolves the real executable. Avoiding asynchronous exceptions
  across PID assignment is a design precaution, not that observation's result.

[validation.json](validation.json) binds the raw files, source identities,
failure explanations and scope flags. No failure was converted into a proof
or resource-bound qualification.

## Remaining finite invalid-proof and propagation evidence

The existing E host audit, also used by the separate cost workflow, retains
16 invalid cases with per-case inner wall time. It has no individual-case
wait4 CPU/RSS or process deadline: its one final JSON is produced after all
cases. The workflow bounds that whole audit at 900 seconds. A final timeout
can prevent retention of the earlier per-case inner timings.

The pinned SDK is RISC Zero commit
[`1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`](https://github.com/risc0/risc0/tree/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9).
Its [Composite verifier](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkvm/src/receipt/composite.rs)
processes the preceding segments before the last segment. E's existing
`last_seal_tamper` changes only the last segment's last seal word. A genuinely
verified 62-segment receipt therefore sends its first 61 segments through
cryptographic verification before attempting the damaged final segment. This
does not prove that every internal operation on the last segment completes.
The SDK's [outer receipt verifier](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkvm/src/receipt.rs)
does inner cryptographic verification before its aggregate image/journal claim
comparison, so the audit's direct-SDK `wrong_image` is a late rejection. E's
`wrong_statement_miner` calls strict verification, whose journal comparison
rejects before cryptographic verification. These are source-order findings;
their real-receipt costs still need the actual retained proof.

The smallest next cost increment is an additive research `audit-one` entry,
leaving the original `verify` and `audit` behavior unchanged. Run one real
positive verification, then separately owned `wrong_image`, `last_seal_tamper`
and `wrong_statement_miner` children from the same immutable receipt and
trusted host. Record whole-child CPU/RSS/time separately from the inner
rejection timer; whole-child cost includes input read, decoding and mutation.
Only an expected structured refusal is a negative-control success. A crash,
timeout or incomplete cleanup is an operational failure. E's current CLI
cannot select one audit case, and changing receipt bytes alone cannot
reproduce the `wrong_image` verifier-argument test. That additive entry and
its controls are follow-up work, not implemented or measured by this patch.

Even a successful 62-segment campaign would establish only a finite maximum
for that retained receipt. The parser admits shapes up to 128 MiB, 2,048
segments and 2^28 padded cycles; those caps alone do not establish a proven
SDK CPU/RAM worst-case bound. Cross-machine transmission, WAN delay, gossip
fanout, queueing, contention, packet loss and propagation in an actual node
remain outside this loopback experiment. The original W1 relation and all
admission PoW settings remain unchanged.
