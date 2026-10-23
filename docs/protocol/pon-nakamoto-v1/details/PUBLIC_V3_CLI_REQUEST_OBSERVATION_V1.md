# Explicit local Public V3 request capture

`serve --request-observation-output NEWFILE` selects the existing bounded local
`PublicRequestObserver` for the explicit `public-protected-development-v3` service.
Use the actual `ingress::public_v3::PROFILE` spelling from the installed source;
the option also requires `--public-development-network`. The optional
`--request-observation-capacity` is 1..4096, default 1024. Capacity without an
output, another command or another admission profile is refused. This is an
operator diagnostic option, not a signed protocol, permission, scheduler,
Node owner, ledger operation or new namespace. The default service remains
unchanged and creates no observer or observation file.

The parser validates this option combination and opens the final path component
with create-new, no-follow and close-on-exec before `Node::open`. The held
descriptor must be a regular file with one link and permissions 0600. It is
checked again after joins and after writing; the output path is never reopened.
The operator is responsible for the parent directory. Existing files, symlinks
and directories are refused without overwriting them. A later configuration or
Node initialization error may leave the new file empty; it is not a completed
capture. Node opening and recovery follow the ordinary native rules and are not
an OS read-only mode.

After the ingress workers and the optional miner and peer poller have joined,
the CLI writes one newline-terminated JSON value, at most 16 MiB, flushes it and
syncs the descriptor. It writes before propagating returned service or thread
errors. The `public-v3-local-cli-request-observation-v1` document contains the
actual N/P/G, installed task/admission profiles, admission policy and local pool
context, the typed observer snapshot, and separate service/mining/polling success
facts. All public, production, independent, work, model and SLA qualification
flags remain false. Commit and tree claims are null: an external executor must
bind the actual binary and exact source bytes; mutable files or runtime Git do
not attest the running executable.

Captured operation and body digests are public commitments, not request bodies
or authenticated guest identity claims. The export omits request bodies, keys,
guest identities, peer addresses, paths and raw error strings. Connection IDs
are local counters, not process IDs. Application bytes count successful stream
syscalls, not physical network bytes or acknowledged delivery. Dispatch and full
work thread CPU intervals overlap and must not be added. The nested observer
schema `public-v3-local-request-resource-observation-v3` reports the owner
interval introduced in r11 and retained by r12/r13, including paid body digest/canonical
decoding and signed response construction. The shared observer schema does not
identify scheduling policy; preserve the actual signed admission policy identifier.
New original campaign reports retain it separately as `public_resource_policy`,
and missing historical policy metadata stays unknown. Its separate CPU flags
explicitly exclude reactor authentication and
socket copying. Historical v1/v2 observer records excluded response signing;
their CPU totals retain that original meaning. The seven native Submit phase
slots continue to exclude body-envelope decoding, response construction and
scoped worker CPU. A finite record capacity or measurement
failure sets capture coverage incomplete; it does not invent absent samples.
Native stages remain nonpreemptive and the observation is unsigned local data.

A service or thread error may coexist with a complete capture of recorded
connections. A serialization, descriptor or write error is an explicit
`REQUEST_OBSERVATION_OUTPUT_IO` refusal carrying only static completion and
success facts. Neither error rolls back already admitted/activated ledger
effects. Killing the process before joins leaves an empty file; killing it
during output can leave a partial file. An empty, truncated or missing capture
must never be read as successful closure. A panic that prevents the scoped
return cannot produce a claimed completed snapshot.

Focused actual CLI controls cover default/opt-in context equality, a legitimate
signed Head request, record-capacity loss, option/file refusal before store
creation, post-join descriptor failure, pre-join SIGKILL, and a real miner stdout
failure after native activation. These are finite local tests, not a network
service guarantee, independent accounting certificate or consensus rollback
test. No existing signed admission bytes or numerical verifier are replaced.

## R13 scheduling observations are separate

The request observer's v3 CPU scope does not identify the resource revision.
R13 keeps the same paid CPU coverage and adds the exact signed policy digest plus
a separate `completion_work_observation` in campaign phases. That object reports
the current shared live CPU owner's fixed 4,096 identities (131,072 identity
bytes), live promotions and duplicate/capacity skips. Its restart flag is false:
identity retention is monotonic only within that live owner epoch, while an
actual process restart begins a new zero-credit epoch. Full capacity withholds
extra promotion and does not reject ordinary verification or recovery.

The reader requires these explicit bounds for r13 and preserves r12 derivations
without adding fields. Unknown observations stay unknown and cannot manufacture
a genuine depletion interval, a confirmation, permanent-once work or fairness.
See [the signed policy boundary](PUBLIC_POOL_INTAKE_V3.md#bounded-completion-replay-and-controlled-existing-recovery).
