# Authenticated caller mutation grants: resource revision r20

The selected development public-v3 resource identity is now r20-authenticated-caller-grants-v1. It retains the complete r19 native-completion and output-refusal contract, and adds two concurrent paid mutation grants per authenticated caller in the shared listener-intake epoch. The fixed registry has at most 64 caller rows. This is a local saturation rule, not anonymous or Sybil fairness, an identity entitlement, consensus authority, production activation, or a claim of native performance.

A caller row is allocated only after the original cookie, work solution, caller signature and spent reservation pass. The original global eight mutation grants, eight read grants, body pools, workers, CPU account, refill, absolute deadlines and completion boundaries remain unchanged. A capped caller is refused without waiting at the FIFO head. Failed global/body acquisition creates no row. Connection and task share one composite lease, so caller capacity returns only after the last owner releases it; this does not refund CPU spending or spent-cookie state.

The registry is ephemeral and shares the existing intake owner. No durable database schema or storage namespace changes. Registry poisoning or inconsistent release accounting refuses further mutation admission. Read requests have no caller mutation grant.

The r20 signed resource identifier is distinct from r19. Correctly signed r19 raw and arithmetic cookies are rejected under the selected r20 identity; no compatibility fallback reinterprets old evidence. Exact r19 and earlier contracts/vectors remain historical entries with their original bytes. The arithmetic-facts cache keeps its original 64-slot, 4-MiB contract and derives a separate r20 identity.

The port retains all seven original caller controls, adapting only the signed-profile vector control to r20, and preserves existing saturation request counts using multiple authenticated caller keys. Native execution receipts are recorded separately from source vectors. Historical phase reports and qualification flags are unchanged.
