#ifndef TRNM_HIA_TASK_STORE_V1_H
#define TRNM_HIA_TASK_STORE_V1_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

/* Opaque, independently owned objects. No public byte-to-readback/preview mint.
 * All functions other than kind return 0 for a completed ABI operation,
 * 100 for malformed ABI framing, 103 for allocation/physical extent failure,
 * or 104 for an invalid ABI borrow.
 * Completed store calls return either their success kind or kind 255 (a full
 * original AgentMarket error). Out is null on an ABI failure. Data views are
 * borrowed and immutable until the owning object is dropped. Caller pointers
 * must be live, correctly sized, nonoverlapping writable outputs; do not drop an
 * object while it is borrowed. Concurrent read-only Store calls are supported
 * with separate per-call continuation/provider owners. */
typedef struct trnm_task_owned trnm_task_owned;

/* Config: LE u64 path_length, LE u64 bundle_length, store_id[32], path bytes,
 * canonical Borsh AgentMarketFreshGenesisTrustBundleV1. Path uses Unix bytes.
 * Store owns a copy; caller may release all input memory after return.
 * Kinds: 1 Store, 2 FreshReadback, 3 ExecutionOutcome, 4 ExecutionPreview,
 * 5 ConfirmedReceipt, 100+ObjectKind State, 255 AgentMarketError. */
uint64_t trnm_task_store_open(const uint8_t *,uint64_t,trnm_task_owned **);
uint64_t trnm_task_store_open_existing(const uint8_t *,uint64_t,trnm_task_owned **);
uint64_t trnm_task_store_clone(const trnm_task_owned *,trnm_task_owned **);
uint64_t trnm_task_store_fresh_readback(const trnm_task_owned *,trnm_task_owned **);
uint64_t trnm_task_store_execute(const trnm_task_owned *,const uint8_t *,uint64_t,const uint8_t *,uint64_t,trnm_task_owned **);
uint64_t trnm_task_store_advance_empty(const trnm_task_owned *,const uint8_t *,uint64_t,trnm_task_owned **);
/* Commands: LE u64 count followed by exactly count canonical KernelCommandV1
 * values. This ABI does not add a u32-count limit to the original slice API.
 * Expected parent must be an owned FreshReadback actually returned by any
 * Store. Equality is the original complete value equality, not owner identity. */
uint64_t trnm_task_store_preview(const trnm_task_owned *,const trnm_task_owned *,uint64_t,const uint8_t *,const uint8_t *,uint64_t,trnm_task_owned **);
uint64_t trnm_task_store_confirm_receipt(const trnm_task_owned *,const uint8_t *,uint64_t,trnm_task_owned **);

#define TRNM_TASK_STATE(name) \
uint64_t trnm_task_store_##name##_state(const trnm_task_owned *,const uint8_t *,trnm_task_owned **); \
uint64_t trnm_task_##name##_state_bytes(const trnm_task_owned *,const uint8_t **,uint64_t *);
TRNM_TASK_STATE(capability)
TRNM_TASK_STATE(session)
TRNM_TASK_STATE(nonce_lane)
TRNM_TASK_STATE(task)
TRNM_TASK_STATE(bid)
TRNM_TASK_STATE(lease)
TRNM_TASK_STATE(escrow)
TRNM_TASK_STATE(account)
TRNM_TASK_STATE(bond)
#undef TRNM_TASK_STATE

uint64_t trnm_task_owned_kind(const trnm_task_owned *);
uint64_t trnm_task_owned_drop(trnm_task_owned *);
uint64_t trnm_task_readback_equal(const trnm_task_owned *,const trnm_task_owned *,uint64_t *);
uint64_t trnm_task_readback_context(const trnm_task_owned *,const uint8_t **,uint64_t *);
uint64_t trnm_task_readback_schema(const trnm_task_owned *,uint64_t *);
uint64_t trnm_task_readback_store_id(const trnm_task_owned *,const uint8_t **,uint64_t *);
uint64_t trnm_task_readback_sequence(const trnm_task_owned *,uint64_t *);
uint64_t trnm_task_readback_order_height(const trnm_task_owned *,uint64_t *);
uint64_t trnm_task_readback_order_block_id(const trnm_task_owned *,const uint8_t **,uint64_t *);
uint64_t trnm_task_readback_state_root(const trnm_task_owned *,const uint8_t **,uint64_t *);
uint64_t trnm_task_readback_journal_root(const trnm_task_owned *,const uint8_t **,uint64_t *);
uint64_t trnm_task_readback_committed_block_root(const trnm_task_owned *,const uint8_t **,uint64_t *);
uint64_t trnm_task_confirmed_receipt(const trnm_task_owned *,const uint8_t **,uint64_t *);
uint64_t trnm_task_outcome_receipt(const trnm_task_owned *,const uint8_t **,uint64_t *);
uint64_t trnm_task_outcome_is_replay(const trnm_task_owned *,uint64_t *);
uint64_t trnm_task_preview_source_sequence(const trnm_task_owned *,uint64_t *);
uint64_t trnm_task_preview_source_state_root(const trnm_task_owned *,const uint8_t **,uint64_t *);
uint64_t trnm_task_preview_source_journal_root(const trnm_task_owned *,const uint8_t **,uint64_t *);
uint64_t trnm_task_preview_candidate_post_state_root(const trnm_task_owned *,const uint8_t **,uint64_t *);
/* Output length is a count of contiguous canonical 180-byte receipts. */
uint64_t trnm_task_preview_candidate_receipts(const trnm_task_owned *,const uint8_t **,uint64_t *);
uint64_t trnm_task_preview_unchanged_inventory(const trnm_task_owned *,const uint8_t **,uint64_t *);
uint64_t trnm_task_error_code(const trnm_task_owned *,uint64_t *);
uint64_t trnm_task_error_clone(const trnm_task_owned *,trnm_task_owned **);
uint64_t trnm_task_error_message(const trnm_task_owned *,const uint8_t **,uint64_t *);
uint64_t trnm_task_error_display(const trnm_task_owned *,const uint8_t **,uint64_t *);
#ifdef __cplusplus
}
#endif
#endif
