# Activation boundary

The current PoN/Nakamoto useful-work profile is experimental and deny-by-default.
Production consensus, public testnet, release, model promotion and Hepta FinalUse remain disabled.

The native consensus runtime, public P2P host, permissionless work qualification and independent
verifier are not accepted by this profile. Chain inclusion, depth or cumulative work cannot grant
Hepta model selection, FinalUse, provider dispatch or external effects.

The machine-readable source is [`config/consensus-mainline.json`](../config/consensus-mainline.json),
with the fail-closed policy in [`config/activation-policy-v1.json`](../config/activation-policy-v1.json).
Promotion requires deterministic finality, artifact availability, independent evaluator evidence,
three real predecessor/future-window generations, and WAN/partition/power-loss/deep-reorg validation.
