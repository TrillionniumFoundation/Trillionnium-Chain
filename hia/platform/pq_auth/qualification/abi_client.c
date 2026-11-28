/* Qualification-only C consumer of the public declarations. */
#include "pq_auth.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

_Static_assert(sizeof(trnm_pq_result) == 16, "SysV result size");
_Static_assert(offsetof(trnm_pq_result, value) == 8, "SysV result pointer");
_Static_assert(sizeof(trnm_pq_view) == 16, "SysV view size");
_Static_assert(offsetof(trnm_pq_view, size) == 8, "SysV view length");

static trnm_pq_value *value(trnm_pq_result result, uint64_t kind) {
    assert(result.status == TRNM_PQ_ABI_OK && result.value != NULL);
    assert(trnm_pq_kind(result.value) == kind);
    return result.value;
}

int main(void) {
    uint8_t seed_bytes[32] = {0};
    uint8_t message[3] = {1, 2, 3};
    const uint8_t original[3] = {1, 2, 3};
    trnm_pq_value *seed = value(trnm_pq_seed_copy(seed_bytes, 32), TRNM_PQ_SEED);
    memset(seed_bytes, 0xa5, sizeof(seed_bytes));
    trnm_pq_value *identity = value(trnm_pq_public_spki_from_seed(seed), TRNM_PQ_PUBLIC_IDENTITY);
    trnm_pq_view spki = trnm_pq_identity_spki(identity);
    trnm_pq_view id = trnm_pq_identity_key_id(identity);
    assert(spki.data && spki.size == 1974 && id.data && id.size == 32);
    trnm_pq_value *key = value(trnm_pq_signing_from_owned_seed(seed, id.data), TRNM_PQ_SIGNING_KEY);
    seed = NULL;
    trnm_pq_value *verifier = value(trnm_pq_verifier_from_pinned_spki(spki.data, spki.size, id.data), TRNM_PQ_VERIFIER);
    assert(trnm_pq_drop(identity) == 0);
    trnm_pq_value *signed_value = value(trnm_pq_sign_exact_message(key, message, sizeof(message)), TRNM_PQ_SIGNATURE);
    trnm_pq_view signature = trnm_pq_signature_bytes(signed_value);
    assert(signature.data && signature.size == 3309);
    trnm_pq_value *observation = value(trnm_pq_verify_exact_message(verifier, message, sizeof(message), signature.data, signature.size), TRNM_PQ_MESSAGE_OBSERVATION);
    assert(trnm_pq_drop(signed_value) == 0);
    assert(trnm_pq_drop(key) == 0);
    assert(trnm_pq_drop(verifier) == 0);
    memset(message, 0xa5, sizeof(message));
    trnm_pq_view authenticated = trnm_pq_message_authenticated_message(observation);
    assert(authenticated.data && authenticated.size == sizeof(original));
    assert(memcmp(authenticated.data, original, sizeof(original)) == 0);
    assert(trnm_pq_drop(observation) == 0);
    trnm_pq_value *budget = value(trnm_pq_budget_new(), TRNM_PQ_BUDGET);
    trnm_pq_value *reserved = value(trnm_pq_budget_reserve(budget, 9, 1), TRNM_PQ_BUDGET_SNAPSHOT);
    assert(trnm_pq_value_code(reserved) == 0);
    assert(trnm_pq_budget_attempts(budget) == 1 && trnm_pq_budget_total_bytes(budget) == 9);
    assert(trnm_pq_budget_exhausted(budget) == 0);
    assert(trnm_pq_drop(reserved) == 0 && trnm_pq_drop(budget) == 0);
    assert(trnm_pq_drop(seed) == 0);
    puts("{\"status\":\"PASS\",\"public_header_consumer\":true}");
    return 0;
}
