# PQ post-intent cancellation: real baseline and local-origin repair candidate

**Original native baseline: one real selected FAIL, with five of five calls
and zero of three honest followups succeeding. Repaired candidate: NOT YET
COMPILED OR RUN.** The first build failed on a test-only macro error and was
preserved before the corrected baseline ran. That second run verified the
first retained real ML-DSA `PQ_NETWORK_DEADLINE` failure but found the original
reorg still pending. Cold reopen changed active State by recovering that
intent; the peer request, sequence and revocation ledger remained intact.

The current candidate changes two production files: explicit local-only PQ
cancellation identities and their three original control producers. Profiles,
dependencies, deadlines, wire diagnostics, CPU accounting and original tests
remain unchanged. The original deadline test function is byte-identical to
the failing baseline. The retained observations and their archive binding are
summarized in `baseline-observation.json`.

The exact selector is:

```text
ingress::pq_network::tests::post_intent_cancellation::actual_pq_deadline_after_intent_preserves_owner_nonce_and_other_peer_service
```

After root's separately bounded native build is authorized and available, the
equivalent Cargo selector is:

```sh
cargo test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib --features pq-native-openssl \
  ingress::pq_network::tests::post_intent_cancellation::actual_pq_deadline_after_intent_preserves_owner_nonce_and_other_peer_service \
  -- --exact --nocapture --test-threads=1
```

This is a new ordinary `#[test]`, with no ignore/skip and no expectation of
failure annotation. It must reach its genuine success assertions after a fix.
The future native runner must reject zero selected tests and preserve all
stdout/stderr, failed observations, compiler/source/ELF bindings and budgets.
The command above was not executed during the initial test-design step. Root
subsequently ran the bounded original native baseline. No repaired candidate
execution, process kill or CI qualification is claimed here.

## Reachable cut and frozen controls

The fixture uses the existing native OpenSSL ML-DSA test-key helper, an actual
fresh `PqNetworkV1` Node, and two separately authorized test peers. It generates
and fully verifies real W1 packets for a competing branch and an honest child
of the active branch. The original `cancel_next_activation_intent_for_test()`
switch pauses only after the actual durable intent transaction. Its existing
loop calls the original progress control until the real request deadline is
observed, with its existing 11-second assertion ceiling. No error value,
signature, checked-work object, output, CPU charge or credit is fabricated.

The test uses the **actual `serve_pq_authenticated` TCP listener** and its
unchanged ten-second request deadline. It does not duplicate the server loop or
substitute a classical listener. Each signed request is prepared once before
execution, with an original bounded expiry. The same first wire bytes and
expiry are retained for replay. Later independent requests get their own normal
socket deadline; the timed-out original operation gets no deadline extension.

This remains an injected scheduling pause at an original commit boundary. It
does not represent a physical process kill, power failure, paid Host service,
independent operator, WAN or full authorization migration. The transport-only
research profile's separate account-migration limitations remain explicit.

## Complete request denominator

The test declares and then attempts all five calls in order:

| Call | Peer / sequence | Expected behavior after repair |
| --- | --- | --- |
| Original heavier-branch Submit | 72 / 1 | Actual ten-second timeout; complete W1/M06 block fact may exist, but unpublished activation is cancelled |
| Same peer's next Head | 72 / 2 | Timely valid signed success; original operation consumed exactly once under current PQ completion rules |
| Different authorized peer's Head | 73 / 1 | Timely valid signed success without depending on original sender retry |
| Different peer's original honest Submit | 73 / 2 | Timely signed success and the expected original honest branch becomes active |
| Exact original request replay | 72 / 1 | Same retained signed failure bytes; no renewed activation, nonce or new record |

All I/O and signature-verification failures become observation records.
Desired cleanup assertions run only after all requests, live snapshots, server
join and cold-open observation are collected. A first failure therefore cannot
silently reduce the three honest followups to zero attempted requests.

The production PQ listener is serial. A correctly verified response from the
second socket proves successor handling, but a client-side timeout alone does
not. In the failing baseline the same read-only SQLite snapshot must contain
the first operation's actual `status=1`, exact operation identity and retained
response, whose real signature is independently verified. The original
`finish_pq_network_request` transaction is `handle()`'s final mutation; its
later socket output cannot alter State. Without this completed original record
the cleanup observation is unknown and the test fails. No grace period is
added to the original request.

## Checks and raw evidence emitted

The test emits all four setup/candidate packet bytes, each exact signed request
wire, each available response wire, real elapsed wall time, I/O errors,
signature-verification errors, and final server metrics. Read-only SQLite
transactions capture active tip/generation/slot and full active State, block
facts, reorg/lifecycle rows, each peer's sequence/revocation, retained response
bytes and metadata. A separate real nonblocking file-lock probe checks that the
same owner fence remains held; directory, database and owner-file identities
are observed without opening another live Node.

The five-call regression and its actual `fs2` nonblocking owner-lock probe are
not gated to Unix. Only the device/inode observation uses `#[cfg(unix)]`.
On other targets its record explicitly says `supported=false`, and the final
`checks_not_evaluated` contains precisely the device/inode identity check;
absence of that probe cannot become a vacuous identity PASS. Windows retains
all requests, lock, State, sequence, replay and cold-open checks. This static
portability correction has not been cross-compiled or run on Windows.

The original first signed failure may be stored although its expired socket
cannot deliver a response. The test retrieves those exact retained bytes and
verifies their real native PQ signature against the original operation and
current time. It does not invent a terminal success or treat absence of a
network ACK as absence of the durable record.

Success requires the correct original target and `done=2`, a matching lifecycle
reason `PQ_NETWORK_DEADLINE`, unchanged active State after cancellation, three
successful honest followups, each peer ending at sequence two, four distinct
retained operation records, exact failed-replay equality and no replay state
change. Owner identity and metadata remain unchanged. Cold reopen must preserve
the already observed live active state and peer ledger; repairing the system by
reopening does not satisfy live recovery.

## Baseline and repair sequence

The exact test was run against unchanged production code and its complete
failure preserved by root. Compile and fixture failures remain distinct from
the observed post-intent liveness failure; the earlier macro failure is not
counted as a runtime counterexample.

Root's first exact native baseline attempt at integrated source
`283d6e5ef8975ae66d0f4de9ced2c967b878adc2` stopped in compilation: `json!` did
not accept an array literal followed directly by an iterator expression inside
an object value. The original stderr is retained as
`baseline-attempt1-compile.stderr`. The correction computes the same three-call
success count in a separate local variable, preserving the denominator and
all assertions. It is a test-source correction, with no production repair.
The corrected baseline subsequently ran at source
`6762be6bad760d17c6cbb50ff7f8b1928c6284df`. It selected one test and failed after
all five planned calls. Its first request elapsed 10,005,566,867 ns; the four
following sockets all ended with `FRAME_EOF`. The retained first response was
really verified, and the unfinished intent was observed after the original
completion record. The run took 433.211385 s including compilation and settled
424.179358 child CPU seconds. Those totals are not import or network latency.

The candidate adds an explicit `local_only` group to `error_codes!`. Its three
PQ variants have exact public diagnostics and `Cancelled` kind, but have no
`ErrorCode::parse` arms. Only the original `PqServer::handle` deadline, expiry
and epoch checks construct these variants explicitly. Existing 138 parseable
identities and the remote constructors are unchanged. Quoting an exact new
diagnostic through `Error::from`, even by a signed remote peer, cannot acquire
local cancellation authority.

Read-only review covered legacy and protected `REMOTE:` wrappers, authenticated
and durable-outbox terminality wrappers, Public V3 response data, public-submit
and peer-polling `Error::remote` paths, and native PQ response verification.
The persisted cancellation reason is checked as an existing nonempty lifecycle
field; reopening does not reparse it into a new cancellation authority.

## Additional repair controls, not yet executed

All selectors below are ordinary tests with no ignore, skip or blanket lint
allowance. The three native additions and original deadline test are selected
by the existing `ingress::pq_network::tests::post_intent_cancellation::` prefix.

| Selector suffix | Required observations |
| --- | --- |
| `expiry::actual_signed_expiry_after_intent_cancels_without_renewing_live_authority` | Five original signed calls; real now+5-second first expiry inside the original ten-second deadline; unchanged honest requests; historical response verification and current-time request/response refusal |
| `local_control_origin::actual_mldsa_remote_control_text_and_forgery_never_authorize_local_cancellation` | Six real TCP exchanges through `PqClient::send`: three correctly signed quoted errors and three actual signature corruptions; all responses and failures retained |
| `local_control_origin::actual_durable_intent_cleanup_requires_local_origin_for_each_pq_control_code` | Fifteen real native intent cases, three codes times explicit-local, quoted-text, remote-refusal, authenticated-terminal and authenticated-retryable origins; only explicit local origin may cancel unpublished staging |
| `error::tests::pq_control_codes_require_explicit_local_origin` (full selector) | Exact diagnostic, raw text, owned text, prefix, I/O and remote-wrapper identity controls for all three variants |

The expiry test signs each request once. Its first retained response still has
the original public `PQ_NETWORK_EXPIRED_UNCONFIRMED` diagnostic. Historical
verification uses the original signed expiry and explicitly grants no live
authority. Actual current-time verification and the original expired-wire
replay must refuse; the replay must not edit State or the peer ledger.

The fifteen origin cases use the existing fault hook after a genuine durable
intent, with complete W1/M06 inputs. They are explicitly labeled error-origin
injection controls, not real elapsed-deadline, durable-revocation or physical
kill observations. Real post-intent durable revocation cannot concurrently
acquire the Node that activation already holds; the current serial production
listener exposes no external concurrent operator revoke handle. Direct Atomic
mutation is not used to simulate that missing reachability.

Candidate validation is limited to Rust formatting/syntax parsing, unchanged
original test inventory, source-only diff review and local evidence links.
`test-design.json` binds current source bytes, the preserved deadline function,
the actual baseline and the outstanding repaired build/native/Clippy gates.
No account migration, paid Host saturation, physical kill, WAN or whole-chain
quantum-security gate is promoted by this candidate.
