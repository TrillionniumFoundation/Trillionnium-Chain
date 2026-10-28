# Controlled loopback receipt cost observation

This separate research helper measures actual application bytes between two
owned processes over IPv4 `127.0.0.1`. It does not measure WAN, gossip,
retransmissions, TCP/IP headers, chain throughput, or public ingress capacity.
The existing bandwidth serialization lower bounds in `analyze_costs.py` retain
their original meaning. Neither a transport success nor a receiver `fsync`
verifies a proof.

## Fixed public entry

```sh
python3 "$BACKEND/measure_loopback.py" \
  --host "$CARGO_TARGET_DIR/release/trnm-w1-risc0-host" \
  --elf "$OUT/guest.bin" --input "$OUT/input.bin" \
  --receipt "$OUT/receipt.bin" --out "$OUT/loopback"
```

The CLI invokes the reviewed original Rust host's real `verify` operation
before transmission and again after receiver materialization, with the same
fixed input and guest program. It requires the backend's exact guest program
hash/image identity, complete receipt byte/hash equality, matching verified
statement and segment profile, successful exact-child `wait4`, and fresh native
result output. There is no supplied-result or skip-verification option. The
helper never invokes a prover or changes receipt reuse/segment scheduling.
`RISC0_DEV_MODE` being present is rejected, including an empty value.

The native executable must come from the reviewed, source-verified build. Its
before/after hash and command are recorded, along with the Python executable,
input, guest, receipt, backend sources, guest-source pins and original process
owner. This is reproducibility evidence, not an attestation that an arbitrary
executable supplied by another administrator implements that source. This is
not an untrusted-binary or public-network service.

The original M01 crypto-primitives directory owns this helper. It borrows the
existing `scripts/llm_runtime_pilot.py` exact-child wait4/RSS owner without
modifying it or importing Torch. The two fixed private transport roles do not
spawn descendants. An unresolved original cleanup receipt remains failed and
retained; the helper cannot declare an unobservable kernel child reaped.

## Bounds and cost interpretation

- Receipt payload: positive length at most 128 MiB, checked before allocation
  and read again while streaming in at most 1 MiB blocks. The fresh receiver
  verifies the length, SHA-256 and final EOF; short, trailing, wrong-hash and
  over-limit streams fail. A per-run nonce separates the two controlled roles;
  it is not peer authentication or Sybil resistance.
- Transfer: one fixed 30-second monotonic deadline. The sender receives only
  the remaining window. Each role has a 128 MiB address-space limit and a
  separate 128 MiB measured RSS gate, including original 50 ms samples and
  exact wait4 high-water RSS. This is a **per-role** cap, not a claim that the
  parent plus both roles jointly consume at most 128 MiB. Streaming alone is
  not treated as a memory measurement.
- On failure, only the owned child is signalled through the original owner.
  Its original five-second TERM grace and one-second KILL cleanup are not
  counted as a successful extension of the 30-second transfer window. Failure
  receipts, partial bytes, process logs and actual terminal costs remain.
- Each native verification has its own fixed 900-second/8 GiB measured RSS
  cap. Its wait4 costs and native inner verification timing remain separate
  from the TCP phase. These are overlapping views of one verifier, not costs
  to add together. No whole-process-tree or held-runtime qualification follows.
- Transfer wall time includes process startup, socket setup, streaming hashes,
  receiver file/directory fsync, parent hash readback and both child closures.
  Payload bytes count once; the application frame plus acknowledgement add
  160 bytes. Neither number counts TCP/IP traffic. The parent CPU interval is
  measured once; overlapping per-role observer CPU intervals are not summed.

The destination is fresh and published with an atomic no-replace link only
after complete stream checks and file fsync, followed by directory fsync.
Existing files are never overwritten. Final receipt bytes are checked again
after the second native verification. All public-ingress, resource,
work-hardness, PQ128 and consensus qualifications remain false even if the
actual two-verification observation succeeds.

## Finite controls and still-open real observation

Run the private synthetic byte/process controls with:

```sh
python3 -m unittest discover -s "$BACKEND" -p test_measure_loopback.py -v
```

The [retained observations](../../../../../evidence/pon-w1-loopback-controls-20261027/README.md)
include the initial sandbox `EPERM` failures, then fourteen passing controls
under explicitly approved loopback networking, and fourteen passing controls
on the final helper source. These use a labelled 2 MiB synthetic byte pattern,
not a W1 receipt. Real RSS-breach and timeout processes are actually reaped;
an exited `/bin/true` without a native verifier result cannot verify anything.
The public proof-verifying CLI's two positive native controls remain **NOT_RUN**.

## Continuation workflow

The same-session continuation workflow supplies exactly two fixed batches of
missing segments. It preserves the original failed attempt and all previous
receipts. Only a complete 62-segment native Composite verification can enable
this helper's public command. It neither starts a prover nor accepts supplied
positive results. The workflow runs real native verification, hostile-input
checks and the continuation report before the actual transfer. Its always-upload
steps retain failures. Original guest, generation caps and segment scheduling
remain pinned.

Only an actual terminal complete receipt and two successful fresh native
verifications can close this narrow loopback observation. They cannot close
work hardness, WAN propagation, permissionless verification DoS, production
consensus or whole-chain quantum security.
