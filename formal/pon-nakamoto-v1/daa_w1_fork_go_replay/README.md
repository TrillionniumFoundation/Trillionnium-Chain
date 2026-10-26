# Independent Go replay of W1 research fork evidence

This package independently recalculates the 64×64 finite-field W1 transcript,
challenge-bound 49,188-byte proof, canonical PNH1 context, legacy 16-block
retarget, cumulative required work and fork-selection outcome for the
**research-only** `daa_w1_fork_replay.py` evidence format.

It is intentionally independent of the Python work oracle and the existing
Go W1 cost campaign. The pinned initial header/proof/block-id vectors are
checked by `main_test.go`, so agreeing with the current generator is not itself
the expected result. All 217 nonce attempts in the frozen 52-winner cohort can
be regenerated; a fabricated cheap Ticket cannot count as verified chainwork.

Run from the `formal/pon-nakamoto-v1` directory:

```sh
python3 -m unittest -v test_daa_w1_fork_replay.py
python3 daa_w1_fork_replay.py --output /new/nonexistent/w1-fork.json
python3 daa_w1_fork_replay.py --verify /new/nonexistent/w1-fork.json --verify-search
go test daa_w1_fork_go_replay/main.go daa_w1_fork_go_replay/main_test.go
go run daa_w1_fork_go_replay/main.go --verify /new/nonexistent/w1-fork.json --strict-search
```

The original 52-winner JSON was separately retained as a ChatGPT development
artifact, SHA-256
`2e1e682091c5ed4efc73bcd801b97e2579e57f5df020d4ef13e93f554126ad4d`.
That full evidence file is not committed to Git. The Go port replays this
artifact locally with **52 matching valid W1 proofs, 217 matching actual
attempts, 16 branch-A blocks removed on healing, and 0 branch-B blocks removed**.
Rebuilding another source or regenerating a different artifact needs its own
source and evidence identity.

## Strict scope boundary

- The **real** work performed is the exact scalar W1 mathematical relation;
  the signed transaction, state and receipt roots are explicitly fabricated
  *research commitments*, not actual M06 execution or consensus authority.
- Lease failure and source outage are simulated inputs. There are no QDL2/QWA2
  signatures, operations permissions, task owner receipts or lease registrations.
- Each branch is a local in-memory simulation; no real network packet transport,
  independent operators or native SQLite reorganization is executed.
- The legacy DAA, revision9 Q4 signatures, revision12 Maintenance implementation
  and PoN Node validity rules remain untouched and unactivated.
- W1 work-hardness, cost fairness, hostile proof rejection service, a new ASERT
  consensus profile, a real Hepta source and P2 WAN acceptance remain OPEN.
