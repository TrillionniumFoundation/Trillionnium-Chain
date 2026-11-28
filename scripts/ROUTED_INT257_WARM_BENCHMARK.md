# Optional warm routed INT257 comparison

This offline developer diagnostic measures the complete borrowed-buffer
`f0` ABI call for the existing Direct and Grouped Product implementations.
It does not select an implementation, benchmark a node, or change any test
or acceptance gate.

From a committed Chain checkout, set `HIA_TOOLCHAIN_ROOT`,
`HIA_NATIVE_COMPILER`, and `HIA_NATIVE_COMPILER_SHA256` to the existing
checkout/compiler pinned by [the toolchain lock](../hia/toolchain.lock.json)
and [its compiler binding](../hia/qualification/compiler-binding.json).
This requires Linux x86-64, the existing HIA linker, and a single allowed
logical CPU. Pass a small JSON mapping each backend (`direct` and
`selfhost`) to the independently known distinct `direct` and `grouped`
ELF SHA-256 values. A previously observed pin set for these source kernels
and the pinned toolchain is:

```json
{
  "direct": {
    "direct": "3f956ca6175fc5adbd573c5ee1c99d1d0e237f883c86dffddd07ce6593d6588f",
    "grouped": "d7699273b454e46a17da2b862cbd9ab90faf2bd023adad507069ac427fe6b4b7"
  },
  "selfhost": {
    "direct": "ffed027212694520b1f9c49163d0a1c3d2000c1e022270bae5ec8c0a8b8930fa",
    "grouped": "19612119fb2128f830e83eebf271a07ae70bfd3a57e1565e3c53c7fc4ed7b4e7"
  }
}
```

Save that mapping outside the checkout as `pins.json`. Use available CPU
index `$cpu` (for example, as shown by `taskset -pc $$`):

```sh
taskset -c "$cpu" python3 -B -m scripts.routed_int257_warm_benchmark \
  --elf-pins pins.json > warm.json
python3 -B -m unittest -v scripts.test_routed_int257_warm_benchmark
```

A different verified build can use its own independently recorded pins.
A mismatch refuses the benchmark; it does not silently change a pin or
substitute an emitter. The benchmark loads exactly the SHA-256-checked
ELF images from sealed temporary descriptors. It validates committed Git
HEAD/tree and closure/input bytes before measurement and again before
emitting observations. It records frame, full Product, ELF, composed-input,
and toolchain identities without checkout-local paths.

Batch sizes are 1, 8, 32, and 64. Each larger batch has one-expert, balanced,
and skewed variants; the singleton has only one distinct distribution.
Each recorded pair alternates execution order, with equal repetitions per
side and half of the pairs starting on each side. Timers exclude compiling,
loading, preallocating, comparing and warming the buffers. Raw integer
monotonic elapsed nanoseconds include the Python/ctypes call and status
check. Divide by the repetition count to obtain per-call observations; for
same-pair grouped/direct ratios this common denominator cancels. Existing
qualification for Product correctness is separate. This diagnostic checks
full byte parity and expected route bins, not performance thresholds or a
production crossover. CPU contention, frequency, and instrumentation can
affect local values; no runtime routing recommendation follows from one run.
