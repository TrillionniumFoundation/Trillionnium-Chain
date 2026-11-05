# Experimental native PoN composition

M15 composes the existing M00 codecs, M01 work verifier and M06 twelve-command
executor. `consensus` owns M02 pure target/time arithmetic; `store` owns M07
fresh-namespace branch/delta persistence and M08 recoverable activation. The Python
Ledger remains a separate conformance oracle, never a runtime fallback or a second
writer of this namespace. M14 confirmations are receiver-computed observations.

This executable uses valueless development accounts and an unqualified work profile.
It does not enable public-network, model-quality, funded-service or production claims.
See the existing [network contract](../../../docs/protocol/pon-nakamoto-v1/details/NETWORK_CLIENT.md)
and [state/recovery contract](../../../docs/protocol/pon-nakamoto-v1/details/STATE_RECOVERY.md).

The explicit [pure PoN public bootstrap](../../../docs/protocol/pon-nakamoto-v1/details/PURE_PON_PUBLIC_BOOTSTRAP_V1.md)
profile removes the extra transport hash-search gate, exposes the exact public
genesis maintenance material and retains native W1 verification and shared service
budgets. Its CLI examples name the new profile on both sides. Public maintenance
has zero useful-output credit and does not qualify model demand or work hardness.
