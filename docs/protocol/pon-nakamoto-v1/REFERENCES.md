# Primary research and implementation references

These are research inputs, not inherited security/efficacy claims or dependencies.
Consulted 2026-09-28. No referenced external software is enabled by this documentation.

- R1: [Bitcoin developer guide: Block Chain](https://developer.bitcoin.org/devguide/block_chain.html).
  Independent validation, proof target, accumulated work, forks and reward maturity.
  PoN must prove its own neural-work assumptions; Bitcoin's analysis does not transfer
  merely because the target arithmetic looks similar.
- R2: [Branch-Train-MiX, Sukhbaatar et al., 2024](https://arxiv.org/abs/2403.07816).
  Common-seed expert specialization followed by MoE combination and router fine-tuning.
  It does not show arbitrary local optima compose automatically or survive hostile updates.
- R3: [Proofs of Useful Work from Arbitrary Matrix Multiplication,
  Komargodski and Weinstein, v4 2025](https://arxiv.org/abs/2504.09971v4).
  Concrete candidate for useful matrix work with prescribed hardness; the authors'
  optimal-security statement is explicitly a conjecture. The exact Hepta/chain
  arithmetic, circuit, integration and attacker-cost model still need qualification.
- R4: [Proof-of-Learning is Currently More Broken Than You Think,
  Fang et al., 2022](https://arxiv.org/abs/2208.03567).
  Demonstrates checkpoint-proof spoofing weaknesses. Training logs are not assumed
  Byzantine-secure mining proofs.
- R5: [Proof-of-Learning with Incentive Security, Zhao et al., 2024](https://arxiv.org/abs/2404.09005).
  Distinguishes rational incentive guarantees from Byzantine resistance. Do not replace
  adversarial ledger assumptions with rational-agent incentives without declaring it.
- R6: [TIES-Merging, Yadav et al., 2023](https://arxiv.org/abs/2306.01708).
  Parameter interference motivates composition tests instead of blind weight averaging.

Hepta integration input (read-only, version-bound):
[NEURAL_BIOMIMICRY_SPEC.md at a126987b8473](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/a126987b84737dbc2ee2592442a314117bddb4a2/docs/learning/NEURAL_BIOMIMICRY_SPEC.md)
and [CNS technical contract at the same source](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/a126987b84737dbc2ee2592442a314117bddb4a2/docs/cns/TECHNICAL.md).
Those define base/organ/cell composition, frozen generations, local authority and
existing owner boundaries; they do not establish deployed cross-chain integration.
