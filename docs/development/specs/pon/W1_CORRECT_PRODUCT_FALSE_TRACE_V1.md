# W1 correct-product false-trace counterexperiment V1

This separate opt-in experiment preserves the existing W1 relation, PNW1 wire,
verifier ordering, original false-trace captures and public-service budgets.
Selector: `--false-trace-correct-product-v1`; schema:
`pon-w1-false-trace-correct-product-v1`. The new challenge domain is
`pon-w1-false-trace-correct-product-challenge-v1`.

The fixed grid contains the existing nine public diagnostic material classes,
eight actual preparations per class and four independent challenge/searches per
preparation: 72 preparations and 288 searches. Target is `7f` followed by 31
`ff` bytes; each search retains all attempts up to the original 4,096 cap,
including exhaustion. A successful ticket does not establish valid work.

Each preparation validates public A/B, computes complete canonical C=AB with
ordinary u128 scalar accumulation modulo Q, and serializes the actual prefix.
It never calls a valid transcript/proof producer. The four searches share that
one real prefix; none receives a modeled fraction of an unmeasured setup.
Each trial forges a trace with the retained two-hash strategy. Winning complete
buffers are cloned inside the measured search interval, and the default full
native verifier actually checks every submitted winner. Unexpected acceptance,
wrong-product acceptance, exhaustion and other refusals remain observations.

The independent reader reconstructs canonical AB using Python integer scalar
products from the exact public recipes, then checks all original trial, hash,
coverage and identity rules. Reader success certifies record consistency only;
external provenance must bind source, executable, clocks and raw captures.
Material generation is separately timed; trial retention is included. Later
evidence output, network transmission and public admission are outside these
primitive intervals. They cannot become a public attack-amplification claim.

For any field vector r, correct C satisfies A(Br)=Cr exactly. Consequently a
filter that checks only products, selected entries or these projections cannot
reject this correctly prepared C on product inconsistency. An arbitrary forged
final transcript digest still owes complete verification under PNW1. This is a
countercontrol for proposed product-first filtering, not a proof of the cheapest
attacker, a hash-oracle lower bound, or an implemented new verifier order.

Reproduction after building the exact example:

```sh
cargo +1.95.0 test --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --example pon_w1_false_trace_correct_product_v1
cargo +1.95.0 build --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --example pon_w1_false_trace_correct_product_v1
trillionnium/target/release/examples/pon_w1_false_trace_correct_product_v1 --false-trace-correct-product-v1 > correct-product.jsonl
python3 scripts/pon_w1_false_trace_correct_product_reader_v1.py correct-product.jsonl
```

Use the actual `CARGO_TARGET_DIR` binary path when that directory is isolated.
Retain before/after source and executable identities, full stdout/stderr and
process results. Finite CPU ratios do not qualify work hardness, honest service,
independent hardware, quantum competition, model utility or production.
