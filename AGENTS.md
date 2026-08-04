# Project Boundary (binding)

This Git root is **Trillionnium Chain** (`trillionnium-chain`), lane
`chain-consensus`. Before any write, build, commit, branch, remote, or
dependency change, run `bash scripts/project-preflight.sh`.

Stop on a root, project ID, lane, remote, branch, topic, or dependency mismatch.
Use `/home/alex/projects/trillionnium-chain`; the old `TrillionniumChain` path
and capitalized alias are temporary compatibility links.

This repository owns consensus, canonical runtime/state, mempool/RPC/node
interfaces, genesis/validator/operator tooling, and canonical finality/proof
semantics. It does not own World gameplay, Hepta business services, Nakama
rooms/matches, or integration orchestration. Do not add game-product packages
or sibling-working-tree Cargo dependencies.
