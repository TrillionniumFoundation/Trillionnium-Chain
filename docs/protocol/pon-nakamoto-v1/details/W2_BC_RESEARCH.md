# W2-B / W2-C and matched W1/W2 alternatives: bounded research

Status: **unqualified research-only code**. No native Rust consensus integration, chainwork,
genesis/profile activation, cryptographic succinct proof, model upgrade, or public service
security authorization. Source starts from Chain #328 and the isolated W1 P0 branch.

## Executable research sources

- 'formal/pon-nakamoto-v1/w2a_merkle_sampling.py': original 512-tile Merkle
  sampled-prefix filter; an explicit altered *unsampled* tile passes it.
- 'formal/pon-nakamoto-v1/w2b_relation_witness.py': W2-B exact full arithmetic
  witness of all 512 tile states (131,072 bytes). It binds
  challenge + task + target + full PNW1 statement; reconstructs every tile,
  SHA256 trace and product in the independent Python oracle. **It is not a
  SNARK/STARK** and does not reduce verification cost.
- 'formal/pon-nakamoto-v1/w2c_separated_security_pow.py': W2-C independent
  hashcash ticket over versioned research domain, **exact 318-byte header** and
  **entire 49,188-byte original W1 proof**. A failed ticket rejects *before*
  expensive W1; a passing ticket still executes the unchanged complete
  mathematical relation. Even a valid result explicitly returns
  'verified_work=false' and no chainwork.
- 'formal/pon-nakamoto-v1/w2_matched_costs.py': one frozen challenge, task,
  target and A/B, records valid W1, forged W1, sampled W2-A, full W2-B witness
  and paired W2-C security work under bounded Python process-CPU clocks.
  Unknown attacker hardware advantages and GPU cost remain null.

Independent test selectors are:
'python3 formal/pon-nakamoto-v1/test_w2a_merkle_sampling.py',
'python3 formal/pon-nakamoto-v1/test_w2b_relation_witness.py',
'python3 formal/pon-nakamoto-v1/test_w2c_separated_security_pow.py', and
'python3 formal/pon-nakamoto-v1/test_w2_matched_costs.py'.

A manual bounded same-statement collection from repository root is:

    python3 formal/pon-nakamoto-v1/w2_matched_costs.py \
        --seed 7 --samples 8 --security-bits 8 12 \
        --security-cap 65536 --out /unique/new/path.json

Existing output must not be overwritten; failures and exhausted searches stay in
the raw report. The code makes no external network requests.

## One measured Python-only exploratory cohort

An earlier local same-task W1/W2 research prototype with seed 7 and eight W2-A
openings produced the following **nonexclusive** Python process-CPU observations.
These are not native Rust runtime costs, end-to-end requester costs, GPU/ASIC
measurements or an execution of the exact later committed code:

| Approach | Approximate measured CPU | Important interpretation |
| --- | ---: | --- |
| Complete W1 honest proof | 84.36 ms | Python full work production; excludes network/task lifecycle |
| Complete W1 legal validation | 86.17 ms | Same input, known legitimate transcript |
| Complete W1 from-zero false rejection | 76.55 ms | False material under all-ff research target; not a production lower bound |
| W2-A sidecar construction | 61.13 ms | Extra work for a separate candidate sidecar |
| W2-A sampled check (8 tiles) | 15.67 ms | Known unsound: one wrong committed tile escaped sampling |
| W2-B complete witness preparation | 138.68 ms | 131,072 bytes; **not** a cryptographic succinct proof |
| W2-B complete witness validation | 142.53 ms | Still replays the same mathematical relation |

For W2-C at low research bits, SHA256 search may be cheaper than the original
~80ms W1 replay; no admission-cost equilibrium has been proven. Quantitative
cost comparisons remain conditional on the chosen implementation, CPU/GPU and
work distribution, and preserve all target misses.

## Security blockers that source/tests DO NOT close

1. W2-A: no sample-only correctness theorem and an explicit false acceptance
   counterexample. Producer-controlled Merkle-root grinding may further bias
   samples. No W1's SHA256 final transcript authentication.
2. W2-B: no succinct cryptographic proof, soundness argument, independent
   primitive implementation, trusted field representation or independent audit.
   W1 modulus 2^32-5 cannot simply be replaced with a new SNARK field.
3. W2-C: exact commitment adds independent hashing not useful matrix computation.
   CPU/GPU/ASIC asymmetry and large-scale honest service burden are unknown;
   valid security tickets can still carry fake W1 transcripts. It does not
   repair original neural useful-work hardness and is not authorized fallback.
4. All W2 arms: no versioned native block wire, retarget/fork weight, upgrade
   migration, source validity, replay protection or explicit activation decision.
5. P1–P4: host kernel parent and public V3 admission/fairness have separate
   operational qualification; a mathematical candidate is not evidence for A03.
6. P6: independent external cryptographic researchers, code-review chain,
   hidden blind vectors and signed reproductions have not been obtained.

## P1 concrete legacy ingress correction

The older native 'ingress::serve_inner' kept unauthenticated entrypoints on
loopback, but **authenticated** legacy endpoints could select nonloopback and
run 'WorkCheckedPacket::verify' without the V3 measured CPU bucket. The newer
fix calls 'host_kernel_parent::require_for_listener(listener_addr)' before
any socket is accepted. For any nonloopback endpoint the kernel-required parent
is the **same fixed administrator-controlled cgroup v2 parent** used by V3,
not a per-process namespace or an identity-based allowance. Actual worker
threads verify membership and finite quotas before and after W1 replay.
Unpriced authenticated-only WAN ingress is refused even when the parent
exists; the explicitly protected authenticated route also requires the existing
native transport Hashcash AdmissionPolicy. DEVELOPMENT_REMOTE_ADMISSION_REQUIRED
is a local service refusal, never a consensus-invalid work judgment.
Separately collected known calling-thread CPU and explicit unknown counts
do not replace kernel host limits or make the legacy entry a V3 worker.

Remaining P1 boundary: remote port forwarding into **loopback** remains a
potential exposure requiring deployment controls and cross-service budget
checks. Authenticated native intake also lacks the V3 per-request CPU debit;
P1 cannot close until all reachable real network/relay paths and operator
deployment policies have been exercised with measured host totals and failures.


## Cross-language Go oracle: third implementation, not third-party acceptance

The isolated 'formal/pon-nakamoto-v1/go_w1_oracle' module has no Rust or
external Go dependencies. Its matrix products deliberately use exact reduced
uint64 partial terms instead of Rust's original u128 accumulator, and it
reconstructs all 512 W1 transcript tiles, the challenge expansions, exact
q=2^32-5 field operations and both late rejection errors.

Manual execution with a local Go 1.23+ toolchain:

    cd formal/pon-nakamoto-v1/go_w1_oracle
    go test ./... -count=1
    go build -o /new/isolated/path/pon_w1_io ./cmd/pon_w1_io

The research-only bridge has 'prove' and 'verify' stdin modes. A successful
'verify' returns a separately tagged 32-byte test receipt, NOT native
VerifiedWork, Chainwork, a full Node state acceptance, or final-use authority.

A separately run local Go/Python experiment compared exact full 49,188-byte
valid proof equality, the SHA256 proof vector, four deterministic forged
transcripts passing the cheap ticket filter, and both early/late native-like
error codes. The four incorrect transcripts all returned Transcript from
Go. Go test ./... -count=1 passed on Go 1.23.2. No Rust compiler was
available in that scratch container; the same exact committed source and
native Rust differential on the proper Chain checkout remain unverified.

An assistant-written Go implementation does not constitute an independent
external reviewer. P6 is still open for external cryptanalysis of hardness,
soundness, work-unique lottery, resource costs, and adversarial vectors.
