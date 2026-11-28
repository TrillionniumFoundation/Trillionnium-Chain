#ifndef TRNM_HIA_PQ_CANDIDATE_H
#define TRNM_HIA_PQ_CANDIDATE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Linux x86-64 SysV. Every handle is a live allocation from this library. */
typedef struct trnm_candidate_value trnm_candidate_value;
typedef struct { uint64_t status; trnm_candidate_value *value; } trnm_candidate_result;
typedef struct { uint64_t status; uint64_t value; } trnm_candidate_scalar;
typedef struct { const uint8_t *data; uint64_t size; } trnm_candidate_view;

enum trnm_candidate_algorithm { TRNM_CANDIDATE_ML_DSA_65 = 65, TRNM_CANDIDATE_ML_DSA_87 = 87 };
enum trnm_candidate_abi_status {
    TRNM_CANDIDATE_OK = 0, TRNM_CANDIDATE_ALLOCATION = 103,
    TRNM_CANDIDATE_ARGUMENT = 104, TRNM_CANDIDATE_INTERNAL = 105
};
enum trnm_candidate_kind {
    TRNM_CANDIDATE_SEED = 1, TRNM_CANDIDATE_SIGNING_KEY = 2, TRNM_CANDIDATE_VERIFIER = 3,
    TRNM_CANDIDATE_SIGNATURE = 101, TRNM_CANDIDATE_VERIFICATION_UNIT = 102,
    TRNM_CANDIDATE_ALGORITHM_NAME = 103, TRNM_CANDIDATE_ALGORITHM_ALL = 104,
    TRNM_CANDIDATE_ERROR_TEXT = 105, TRNM_CANDIDATE_ERROR = 255
};

trnm_candidate_result trnm_candidate_seed_copy(const uint8_t *, uint64_t);
/* Consumes a valid seed on every return, including invalid algorithm or OOM. */
trnm_candidate_result trnm_candidate_signing_from_owned_seed(uint64_t, trnm_candidate_value *);
trnm_candidate_result trnm_candidate_verifier_from_pinned_raw(uint64_t, const uint8_t *, uint64_t);
trnm_candidate_scalar trnm_candidate_signing_algorithm(const trnm_candidate_value *);
trnm_candidate_scalar trnm_candidate_verifier_algorithm(const trnm_candidate_value *);
trnm_candidate_view trnm_candidate_signing_public_key(const trnm_candidate_value *);
trnm_candidate_view trnm_candidate_verifier_public_key(const trnm_candidate_value *);
trnm_candidate_result trnm_candidate_sign(const trnm_candidate_value *, const uint8_t *, uint64_t);
trnm_candidate_result trnm_candidate_verify(const trnm_candidate_value *, const uint8_t *, uint64_t, const uint8_t *, uint64_t);

trnm_candidate_result trnm_candidate_algorithm_all(void);
trnm_candidate_result trnm_candidate_algorithm_name(uint64_t);
trnm_candidate_scalar trnm_candidate_algorithm_public_key_bytes(uint64_t);
trnm_candidate_scalar trnm_candidate_algorithm_signature_bytes(uint64_t);
trnm_candidate_scalar trnm_candidate_algorithm_nist_category(uint64_t);

/* Error codes preserve the original Candidate error enum: 2 through 8. */
trnm_candidate_result trnm_candidate_candidate_error_display(uint64_t, uint64_t, uint64_t);
trnm_candidate_result trnm_candidate_error_display(const trnm_candidate_value *);
uint64_t trnm_candidate_drop(trnm_candidate_value *);
uint64_t trnm_candidate_kind(const trnm_candidate_value *);
uint64_t trnm_candidate_value_code(const trnm_candidate_value *);
uint64_t trnm_candidate_value_expected(const trnm_candidate_value *);
uint64_t trnm_candidate_value_actual(const trnm_candidate_value *);
trnm_candidate_view trnm_candidate_value_bytes(const trnm_candidate_value *);
trnm_candidate_view trnm_candidate_signature_bytes(const trnm_candidate_value *);
trnm_candidate_view trnm_candidate_algorithm_name_bytes(const trnm_candidate_value *);
trnm_candidate_view trnm_candidate_algorithm_all_bytes(const trnm_candidate_value *);

#ifdef __cplusplus
}
#endif
#endif
