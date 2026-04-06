# Trillionnium Examples (C2 MVP)

## 1) Task lifecycle query
```bash
cd trillionnium
cargo run -q -p trnm-rpc -- query-task 42
```

## 2) Governance proposal query
```bash
cd trillionnium
cargo run -q -p trnm-rpc -- query-proposal 9001
```

## 3) Event stream query
```bash
cd trillionnium
cargo run -q -p trnm-rpc -- query-events 42
```

## 4) SDK quickstart (JavaScript)

10 分钟接入流程：`create wallet -> faucet -> sendTx -> getTx`

```bash
cd examples/sdk-js
npm install
npm start
```

详情见：`examples/sdk-js/README.md`
