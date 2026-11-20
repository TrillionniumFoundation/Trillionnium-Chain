#ifndef TRNM_HIA_SETTLEMENT_ENGINE_OWNED_H
#define TRNM_HIA_SETTLEMENT_ENGINE_OWNED_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct trnm_settlement_owned trnm_settlement_owned;

/* SysV x86_64 ABI. All non-null handles must be live handles from this image.
 * Input byte ranges and output pointers must be valid for their stated extent;
 * writable outputs must not overlap borrowed input or immutable owned storage.
 * Successful methods return ABI 0 and an independently owned result. Domain
 * errors are kind 255 results, with the original enum code and UTF-8 message.
 * ABI 103 is allocation/extent exhaustion; ABI 104 is invalid arguments/type.
 * An ABI failure clears the result pointer and leaves every existing owner
 * unchanged. Other nonzero ABI values identify a refused native kernel call.
 * Kind: 1 engine, 2 digest bytes, 3 serialized/display bytes, 4 unit, 255 error.
 * Owners are immutable and may be read concurrently. Drop must be exclusive;
 * borrowed views remain valid only until their owning handle is dropped.
 */
uint64_t trnm_settlement_engine_new(const void *trust, uint64_t size, trnm_settlement_owned **result);
uint64_t trnm_settlement_engine_apply(const trnm_settlement_owned *engine, uint64_t height, const void *command, uint64_t size, trnm_settlement_owned **result);
uint64_t trnm_settlement_engine_replay(const trnm_settlement_owned *engine, uint64_t height, const void *command, uint64_t size, trnm_settlement_owned **result);
uint64_t trnm_settlement_engine_validate_execution(const trnm_settlement_owned *engine, const void *execution, uint64_t size, trnm_settlement_owned **result);
uint64_t trnm_settlement_engine_clone(const trnm_settlement_owned *engine, trnm_settlement_owned **result);
uint64_t trnm_settlement_engine_trust(const trnm_settlement_owned *engine, const void **data, uint64_t *size);
uint64_t trnm_settlement_engine_state(const trnm_settlement_owned *engine, const void **data, uint64_t *size);
uint64_t trnm_settlement_engine_state_root(const trnm_settlement_owned *engine, const void **data, uint64_t *size);
uint64_t trnm_settlement_engine_history_count(const trnm_settlement_owned *engine, uint64_t *count);
uint64_t trnm_settlement_engine_state_copy(const trnm_settlement_owned *engine, trnm_settlement_owned **result);
uint64_t trnm_settlement_owned_clone(const trnm_settlement_owned *value, trnm_settlement_owned **result);
uint64_t trnm_settlement_owned_drop(trnm_settlement_owned *value);
uint64_t trnm_settlement_owned_kind(const trnm_settlement_owned *value);
uint64_t trnm_settlement_error_code(const trnm_settlement_owned *error, uint64_t *code);
uint64_t trnm_settlement_error_message(const trnm_settlement_owned *error, const void **data, uint64_t *size);
uint64_t trnm_settlement_error_display(const trnm_settlement_owned *error, trnm_settlement_owned **result);
uint64_t trnm_settlement_bytes_view(const trnm_settlement_owned *bytes, const void **data, uint64_t *size);
uint64_t trnm_settlement_consumption_receipt_id(const void *body, uint64_t size, trnm_settlement_owned **result);
uint64_t trnm_settlement_consumption_rollup_id(const void *body, uint64_t size, trnm_settlement_owned **result);
uint64_t trnm_settlement_settlement_policy_hash(const void *policy, uint64_t size, trnm_settlement_owned **result);
uint64_t trnm_settlement_operation_id(const void *command, uint64_t size, trnm_settlement_owned **result);

#ifdef __cplusplus
}
#endif
#endif
