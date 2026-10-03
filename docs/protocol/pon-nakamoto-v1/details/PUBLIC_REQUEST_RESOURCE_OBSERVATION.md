# Optional local public V3 request resource observations

This M15 observer is an operator-selected measurement API. It does not authorize
requests, change the selected resource policy or signed frames, add ledger operations,
or persist guest identities. It adds no Node, scheduler, worker, queue or database
owner. Existing service/client APIs retain their signed bytes and native checks.
The new measurements are not backfilled into earlier observations whose CPU or
wire fields were null.

## API and bounded capture

`ingress::public_v3::PublicRequestObserver::new(capacity)` accepts 1 through 4096
records; other values return `PUBLIC_OBSERVATION_CAPACITY`. Pass a clone to
`serve_public_protected_v3_with_request_observer` with the existing listener,
`Arc<Mutex<Node>>`, stop signal, server and metrics. Use `snapshot()` after the
service and all workers have actually joined.

The observer retains the first records without eviction. Each accepted socket
increments `accepted_connections_seen`; full capacity or unavailable capture
locks increase `records_not_retained`. A record has six fixed frame counters,
optional local connection number, operation and request-body digest, and closure
flags. It stores no peer address, caller key, caller nonce, body, signature, proof
or secret. Capture uses `try_lock`; contention, poisoning or arithmetic failure
marks the observation failed and increases `measurement_failures`. Counters
saturate and expose `counter_overflow`; they do not wrap. Capture failures and
missing records do not become transport or ledger rejection conditions.

Connection and task handles share only the measurement cell. Each handle marks
its own closure once on Drop, including failed, abandoned and pending-enqueue
paths. A row is complete only after the connection and any created task have
closed, with no capture failure. This does not mean the request succeeded or
that every frame completed. Live snapshots may be incomplete and their capture
contention can produce explicit measurement failures. Snapshot allocation and
the bounded record allocations are additional operator measurement overhead,
not a new hard RSS guarantee or part of the guest body/output budgets.

## CPU intervals

| Field | Measured interval |
| --- | --- |
| `full_work_thread_cpu_ns` | Immediately around the actual `WorkCheckedPacket::verify` call in the Submit callback. |
| `dispatch_thread_cpu_ns` | The actual worker thread's complete `public_dispatch` call, including its native context/admission/execution checks and any full-work call. |

On Linux, safe rustix reads `CLOCK_THREAD_CPUTIME_ID` at both ends. A different
execution thread, unsupported platform, clock-read error, invalid timestamp or
subtraction failure returns null. No work call means `full_work_started=false`
and work CPU/acceptance null, including reads, pool operations, duplicate
shortcuts and tasks skipped before dispatch. The corresponding dispatch fields
remain null if dispatch did not start. A failed actual verify still records its
interval and `full_work_accepted=false` when the clock is available.

The intervals are nested and must not be added. Dispatch includes native ledger
signature checks executed inside that call; it excludes reactor framing,
transport-cookie/caller authentication, resource-ticket solving, response
signing/serialization, socket output and other threads such as the miner.
Worker lock waiting may increase elapsed time without increasing that thread's
CPU time. These are not process CPU, lock occupancy, energy, economic minimum
cost or the fastest possible attacker/producer cost. Clock/capture overhead is
real observation overhead and is not subtracted. Default service APIs allocate
no request records. The separately specified V3 r5 paid mutation CPU account
uses the same checked thread clock even when optional capture is absent.
Mutation dispatch totals can include bounded reservation/accounting start
overhead; its disjoint full-work/remainder counters are charged once. Optional
capture failure does not alter admission; mandatory r5 accounting failure
separately prevents future mutation starts while preserving completed outcomes.

## Actual application-frame byte counters

Each positive `TcpStream::read`/`write` result is counted at its existing reactor
I/O site, including partial progress before EOF, timeout or another error.
WouldBlock/Interrupted and unsuccessful syscalls add no invented bytes.

| Frame | Server direction and scope |
| --- | --- |
| Hello | Fixed 108 bytes read, or actual incomplete prefix. |
| Challenge | Actual written 4-byte length prefix plus signed JSON frame. |
| Solution | Fixed 108 bytes read, or actual incomplete prefix. |
| Ready | Actual written 4-byte length prefix plus signed ready JSON. |
| Body | Actual raw request JSON bytes read; there is no additional body prefix. |
| Response | Actual written 4-byte length prefix plus signed response JSON. |

`complete` on each frame marks completion at that I/O site. On capture failure,
row-level byte totals are null; retained partial counters are diagnostic only.
Writes count bytes accepted by the socket syscall, which is not proof of peer
delivery. `physical_network_bytes` remains null. These values exclude TCP/IP,
Tailscale, retransmission, routing and encryption overhead. Socket peek calls
used for disconnect fences consume no application bytes. All original frame
caps, quantum, permits, absolute deadlines and phase rejection order remain.

## Verification and scope

`src/ingress/public_v3/request_observation.rs` unit controls cover cross-thread
connection/task closure, bounded omission, counter/byte overflow, nonblocking
capture failure, nested thread clocks and cross-thread/null failure. Actual
socket controls in `src/ingress/public_v3.rs` compare independently received
signed-frame lengths, partial EOF, quantum writes and retained partial bytes
after a real write error. `tests/public_v3_request_accounting.rs` verifies real
paid Product rejection, subsequent native admission/activation, complete State
and packet parity, Head/History null work CPU, concurrent honest service after
record-cap exhaustion, and shutdown with all permits released.

Source selectors describe these checks; actual command receipts must bind the
new candidate bytes and binary. They do not inherit earlier clean-source or
network measurements. A finite loopback component result is not WAN/hostile
service, anonymity/fairness under saturation, independent operation, useful
model output, production activation, economic hardness or public readiness.
