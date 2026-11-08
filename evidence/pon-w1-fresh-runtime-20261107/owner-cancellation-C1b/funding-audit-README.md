# Trial02: independent closed-state audit

Source: C1b `0f18f93f2d35b62c6ca6d63faf4f336d55cbf4bf`, tree `94334bb6b52cfd13040059a5e71f47d8cc9603f2`.
Original operation: `ebe3c586d634730e7464f2e3661aea37f6ed7402c0d74f1a695224510d2e2f5e`.

The original costly generation/cancel entry and separate cold entry both reached actual succeeded/exit 0, complete and durable terminal states. This audit then copied four closed SQLite files as ordinary bytes and opened only those new private copies with `mode=ro&immutable=1` and query-only enabled. Original DB hashes and absent sidecars were checked before and after. It performed zero Node/M12/target method calls, transaction submissions, generation dispatches or proofs.

## Actual request and persistent state

The real target request contains all 339 configured executable/source pins, checked by exact reconstruction from the original config. It is 68,944 raw UTF-8 bytes (SHA256 `d1cf5f237edb4b2d24cd8136e51064a3fce1493fe186ca7d572814c989f77cf6`) and 66,585 canonical bytes (SHA256 `090361c6425009b00738aa06e14d045ab16b68498a9ce36536424f768000e0e2`). This exceeds the former 64 KiB limit and satisfies the new explicit 128 KiB raw-file policy. The persisted target BLOB equals those canonical bytes.

M12 contains exactly Prepare, Intent, BindJob and Cancel, one of each. All event sequence numbers, hash-chain roots and Borsh payload lengths/field boundaries were checked against the fixed source. Statement, operation, original job, cancellation reason, original deadline and owner assignment remain bound. There is no Verified, Failure, Settlement or Payment event. Cold begin is Pending. The original resource cap remains reserved; unknown GPU use is not replaced with zero and does not authorize credit or provider payment.

The native chain has exactly genesis -> Reserve -> Cancel. The height-2 stored packet is byte-identical to the original retained signed Cancel packet and occurs once in that canonical history. Owner nonces are 0 -> 1 -> 2. Task remaining is 1000 after Reserve and 0 after Cancel; status is cancelled. This is one canonical effect, not a newly executed duplicate-wire rejection test. The separate cold entry submitted no new native transaction.

| Native owner transition | Balance before | Balance after | Net change |
| --- | ---: | ---: | ---: |
| Reserve | 10,000,000 | 9,998,581 | -1,419 |
| Cancel | 9,998,581 | 9,999,290 | +709 |
| Combined | 10,000,000 | 9,999,290 | -710 |

Gross NativeTask principal returned is 1000. It is not the +709 net account change, a provider payout or M12 resource credit. The 419/291 balance residuals are arithmetic from those rows; this audit did not separately decode wire fee fields. Neither canonical transaction block has a provider-account delta. This does not assert the provider's complete account balance.

The original target operation is terminal/cancelled with sticky veto; cold reconciliation retained the same request, worker identity and result and permits no redispatch/payment. The primary recorded child cgroup was recursively empty, direct child reaped, and the separate post-job snapshot found the named original scopes absent. Historical all-descendants wait/reap and complete resource accounting remain unknown. One real costly proving stage started; this cancellation trial produced zero new complete proofs.

## Scope and retained failures

This is an independent byte/schema/hash-chain/canonical-row audit. It does not rerun native signature verification, decode the whole Packet transaction list, manufacture a completed segment, execute another cold entry, or prove pre/post-cold DB byte identity (this audit took no pre-cold DB snapshot). The original native entry performed its own real consensus admission and the original cold entry observed that same packet.

The separate trial02 prelaunch preparation failure is retained. It occurred before a proof deadline, NativeTask funding or target dispatch. Audit setup also retains two failed create-only writes before the new external parent directory existed and a failed private-copy row inspection that omitted genesis packet=NULL handling; the corrected inspection and final analysis used the same private copies and did not mutate or rerun the original operation.

## Publication boundary

Publish only `PUBLIC-ALLOWLIST.json` and its exact files, or the generated public-only archive. The four SQLite copies and full private dumps under `private-analysis-only/` are deliberately excluded. No original Node DB, private keys or complete private state are included. Public artifacts contain normalized task/owner account deltas, original DB hashes, exact public wire/packet bytes, source excerpts, actual raw reports and unmodified connector content.text strings. Large u64 connector fields were not parsed and reserialized in JavaScript.
