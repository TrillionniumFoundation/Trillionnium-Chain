#ifndef TRNM_HIA_PQ_AUTH_H
#define TRNM_HIA_PQ_AUTH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Linux x86-64 SysV. Handles are opaque, live allocations from this library.
 * See README.md for input lifetimes, exclusivity and exact byte encodings. */
typedef struct trnm_pq_value trnm_pq_value;
typedef struct {
    uint64_t status;
    trnm_pq_value *value;
} trnm_pq_result;
typedef struct {
    const uint8_t *data;
    uint64_t size;
} trnm_pq_view;

enum trnm_pq_abi_status {
    TRNM_PQ_ABI_OK = 0,
    TRNM_PQ_ABI_ALLOCATION = 103,
    TRNM_PQ_ABI_ARGUMENT = 104,
    TRNM_PQ_ABI_INTERNAL = 105
};
enum trnm_pq_value_kind {
    TRNM_PQ_SEED = 1, TRNM_PQ_SIGNING_KEY = 2, TRNM_PQ_VERIFIER = 3,
    TRNM_PQ_PROFILE_VERIFIER = 4, TRNM_PQ_BUDGET = 5,
    TRNM_PQ_PUBLIC_IDENTITY = 100, TRNM_PQ_SIGNATURE = 101,
    TRNM_PQ_MESSAGE_OBSERVATION = 102, TRNM_PQ_SIGNED_FRAME = 103,
    TRNM_PQ_FRAME_OBSERVATION = 104, TRNM_PQ_VERIFICATION_UNIT = 105,
    TRNM_PQ_CANDIDATE_OBSERVATION = 107, TRNM_PQ_BUDGET_SNAPSHOT = 108,
    TRNM_PQ_CANDIDATE_MESSAGE = 109, TRNM_PQ_COMMITMENT = 110,
    TRNM_PQ_PROFILE_QUERY = 111, TRNM_PQ_BOUND_PROFILE = 112,
    TRNM_PQ_SIGNER_IDS = 113, TRNM_PQ_PINNED_KEYS = 114,
    TRNM_PQ_ERROR_TEXT = 115, TRNM_PQ_ERROR = 255
};

trnm_pq_result trnm_pq_seed_copy(const uint8_t *, uint64_t);
trnm_pq_result trnm_pq_public_spki_from_seed(const trnm_pq_value *);
/* Consumes a valid seed on every return, including allocation/argument errors. */
trnm_pq_result trnm_pq_signing_from_owned_seed(trnm_pq_value *, const uint8_t[32]);
trnm_pq_result trnm_pq_verifier_from_pinned_spki(const uint8_t *, uint64_t, const uint8_t[32]);
trnm_pq_result trnm_pq_sign_exact_message(const trnm_pq_value *, const uint8_t *, uint64_t);
trnm_pq_result trnm_pq_verify_exact_message(const trnm_pq_value *, const uint8_t *, uint64_t, const uint8_t *, uint64_t);
trnm_pq_result trnm_pq_sign_statement(const trnm_pq_value *, const uint8_t *, uint64_t, const uint8_t[136], const uint8_t *, uint64_t);
trnm_pq_result trnm_pq_verify_frame(const trnm_pq_value *, const uint8_t *, uint64_t, const uint8_t[136], const uint8_t *, uint64_t);
trnm_pq_result trnm_pq_verify_tpq1(const uint8_t *, uint64_t, const uint8_t[136], const uint8_t *, uint64_t, const uint8_t *, uint64_t);
/* public key, message, context, signature; each pointer is followed by length. */
trnm_pq_result trnm_pq_verify_ml_dsa_65(const uint8_t *, uint64_t, const uint8_t *, uint64_t, const uint8_t *, uint64_t, const uint8_t *, uint64_t);

/* profile tag, binding128, encoded key list, encoded key-list length. */
trnm_pq_result trnm_pq_profile_from_pinned_keys(uint64_t, const uint8_t[128], const uint8_t *, uint64_t);
trnm_pq_result trnm_pq_profile_snapshot(const trnm_pq_value *);
trnm_pq_result trnm_pq_profile_signer_ids(const trnm_pq_value *);
trnm_pq_result trnm_pq_profile_pinned_keys(const trnm_pq_value *);
/* Budget is exclusively borrowed and failed verification can consume it. */
trnm_pq_result trnm_pq_profile_verify(const trnm_pq_value *, trnm_pq_value *, const uint8_t *, uint64_t, const uint8_t *, uint64_t);
trnm_pq_result trnm_pq_budget_new(void);
trnm_pq_result trnm_pq_budget_snapshot(trnm_pq_value *);
trnm_pq_result trnm_pq_budget_reserve(trnm_pq_value *, uint64_t, uint64_t);
trnm_pq_result trnm_pq_profile_candidate_message(const trnm_pq_value *, const uint8_t *, uint64_t);
trnm_pq_result trnm_pq_profile_commitment(const trnm_pq_value *, uint64_t, const uint8_t *, uint64_t);
trnm_pq_result trnm_pq_profile_active_at(const trnm_pq_value *, uint64_t);
trnm_pq_result trnm_pq_profile_require_claim(const trnm_pq_value *, const uint8_t[64]);

uint64_t trnm_pq_drop(trnm_pq_value *);
uint64_t trnm_pq_kind(const trnm_pq_value *);
uint64_t trnm_pq_value_code(const trnm_pq_value *);
uint64_t trnm_pq_value_detail_a(const trnm_pq_value *);
uint64_t trnm_pq_value_detail_b(const trnm_pq_value *);
trnm_pq_view trnm_pq_value_bytes(const trnm_pq_value *);
trnm_pq_view trnm_pq_key_public_spki(const trnm_pq_value *);
trnm_pq_view trnm_pq_key_public_key_id(const trnm_pq_value *);
trnm_pq_view trnm_pq_identity_spki(const trnm_pq_value *);
trnm_pq_view trnm_pq_identity_key_id(const trnm_pq_value *);
trnm_pq_view trnm_pq_signature_bytes(const trnm_pq_value *);
trnm_pq_view trnm_pq_signed_frame_bytes(const trnm_pq_value *);
trnm_pq_view trnm_pq_message_authenticated_message(const trnm_pq_value *);
trnm_pq_view trnm_pq_message_signer_key_id(const trnm_pq_value *);
trnm_pq_view trnm_pq_frame_authenticated_statement(const trnm_pq_value *);
trnm_pq_view trnm_pq_frame_statement(const trnm_pq_value *);
trnm_pq_view trnm_pq_frame_signer_key_id(const trnm_pq_value *);
trnm_pq_view trnm_pq_candidate_message(const trnm_pq_value *);
trnm_pq_view trnm_pq_candidate_crypto_profile_id(const trnm_pq_value *);
uint64_t trnm_pq_candidate_signer_count(const trnm_pq_value *);
uint64_t trnm_pq_bound_kind(const trnm_pq_value *);
trnm_pq_view trnm_pq_bound_profile_id(const trnm_pq_value *);
trnm_pq_view trnm_pq_bound_work_digest(const trnm_pq_value *);
trnm_pq_view trnm_pq_bound_binding(const trnm_pq_value *);
trnm_pq_view trnm_pq_bound_configuration_bytes(const trnm_pq_value *);
trnm_pq_view trnm_pq_profile_signer_id_at(const trnm_pq_value *, uint64_t);
trnm_pq_view trnm_pq_profile_pinned_key_at(const trnm_pq_value *, uint64_t);
uint64_t trnm_pq_budget_attempts(const trnm_pq_value *);
uint64_t trnm_pq_budget_total_bytes(const trnm_pq_value *);
uint64_t trnm_pq_budget_exhausted(const trnm_pq_value *);
trnm_pq_result trnm_pq_error_display(const trnm_pq_value *);
trnm_pq_result trnm_pq_native_error_display(uint64_t, uint64_t);
trnm_pq_result trnm_pq_profile_error_display(uint64_t, uint64_t, uint64_t, uint64_t);

#ifdef __cplusplus
}
#endif
#endif
