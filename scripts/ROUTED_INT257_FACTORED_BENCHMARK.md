# Optional warm INT257 comparison with fresh factor checks

This Linux x86-64, offline diagnostic compares complete warm HIA f0
calls for three implementations on the same deterministic mathematical
workloads: Direct, Grouped and Factored. The Factored ABI consumes the
full immutable model/factor/feature frame and performs fresh complete
B×A equality on **every invocation**, including warmup and timing. The
other two use the identical dense model/feature values and their own
full validation. The difference in work at each public ABI is part of
what this measures, not a claim about an amortized prepared-factor API.

The 40 fixtures use batches 1/8/32/64, one/balanced/skew expert
distributions where distinct, and rank 1/2/4/8 per expert. The synthetic
factorizations deliberately implement the same dense delta with a
repeated basis at every rank; the comparison isolates shape/rank, not
representative model quality. All three native results on each backend
must yield identical normalized Product bytes. Factored diagnostic
counts are checked separately. An optional unit suite runs the unchanged
public locked Rust Factored callable on the exact 40 cases.

Use the same pinned [toolchain setup](ROUTED_INT257_WARM_BENCHMARK.md) and
independently known ELF hashes. Add the Factored entries to the two
backend rows of the documented pin file:

- direct backend, Factored: `0d3f1da2197adaaf725652543813fe66d66d94de10fbc1311b8c461fd9a66f50`
- selfhost backend, Factored: `543a195f750b8a98d99548af4f296a0d2dc272afef85b2e5168d2ef404daa17a`

Each of the six distinct actual emitted images must match its pin, and
the selected source closure must match the current **committed** Chain
source before and after timing. Run on one allowed logical CPU:

```sh
python3 -B -m unittest -v scripts.test_routed_int257_factored_benchmark
taskset -c "$cpu" python3 -B -m scripts.routed_int257_factored_benchmark \
  --elf-pins pins.json --cycles 1 > factored-warm.json
```

Each cycle contains all six call orders so each implementation occupies
each position equally often. Blocks use a common repetition count
within a fixture/backend. Raw monotonic nanoseconds include Python/ctypes
call and status overhead. Compiling, loading sealed images, allocating
buffers, verifying outputs and initial warmup are outside timed blocks.
The JSON binds each input frame, normalized Product, full Factored
result, compiler and six machine objects; timings are not a substitute
for the exact output checks. Divide elapsed nanoseconds by repetitions
for per-call estimates. Processor affinity does not imply exclusive host
or stable frequency. Report per-order spread alongside any median and
do not infer a production crossover, speed selector, proof or entitlement.
