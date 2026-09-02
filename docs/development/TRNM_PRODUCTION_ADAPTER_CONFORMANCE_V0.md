# TRNM Production Adapter Conformance v0

Status: testkit only; forbidden from the production dependency closure.

`trnm-production-adapter-conformance-v0` validates adapter ordering and failure
semantics for the versioned repository blocker cores.  It is not a replacement
for device-backed, physical-power-loss, or multi-host evidence.

## Required probes

1. **Durable authority crash after persist**
   - persist the exact operation binding and next authority stage;
   - inject process termination before returning the receipt;
   - restart from the same durable journal;
   - recover the retained stage and sequence; and
   - replay the exact command without a second stage advance.

2. **Non-destructive state-sync installation**
   - inject failure at staging begin, each chunk write, and commit before swap;
   - prove the currently serving root and height are unchanged;
   - prove staging abort is idempotent;
   - complete a successful install once; and
   - bind the receipt to previous root, installed root, height, and generation.

3. **Transaction effect substitution**
   - retain a monotonic broadcast intent;
   - accept the exactly matching transport receipt once or repeatedly; and
   - reject any same-sequence receipt with a changed transport digest.

4. **Control authority exclusion**
   - supply a shape-valid and signature-valid plan containing `Finalize`;
   - prove the local guard returns a rejected action receipt.

5. **Migration authority-state exclusion**
   - attempt to project a signer journal namespace; and
   - prove validation stops before target-root construction.

## Adapter acceptance rule

An adapter passes only if every pre-commit failure preserves the old serving
state.  A target that mutates the serving generation and subsequently returns
an error from `commit_staging_cas` is non-atomic and must be quarantined; the
protocol must not attempt a destructive abort against a generation that might
already be active.

## Non-claims

Passing this testkit does not establish physical disk flush semantics, actual
SIGKILL timing, filesystem behavior, remote signer/HSM behavior, network
partitions, Byzantine peers, real epoch transitions, or wall-clock soak.
Those require the external and campaign evidence listed in Plan v2.
