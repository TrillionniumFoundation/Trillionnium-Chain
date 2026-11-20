/* Test-only C consumer of the actual public HIA ELF ABI. */
#include "pq_candidate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(value) do { if (!(value)) { fprintf(stderr, "ABI check %d\n", __LINE__); return 1; } } while (0)

int main(void) {
    trnm_candidate_result all = trnm_candidate_algorithm_all();
    CHECK(all.status == 0 && all.value);
    trnm_candidate_view algorithms = trnm_candidate_algorithm_all_bytes(all.value);
    CHECK(algorithms.data && algorithms.size == 2 && algorithms.data[0] == 65 && algorithms.data[1] == 87);
    for (unsigned index = 0; index < 2; ++index) {
        uint64_t algorithm = algorithms.data[index];
        uint8_t source[32];
        memset(source, 31, sizeof(source));
        trnm_candidate_result seed = trnm_candidate_seed_copy(source, sizeof(source));
        CHECK(seed.status == 0 && seed.value);
        memset(source, 0xa5, sizeof(source));
        trnm_candidate_result key = trnm_candidate_signing_from_owned_seed(algorithm, seed.value);
        CHECK(key.status == 0 && key.value && trnm_candidate_kind(key.value) == 2);
        trnm_candidate_scalar parameter = trnm_candidate_signing_algorithm(key.value);
        CHECK(parameter.status == 0 && parameter.value == algorithm);
        trnm_candidate_view public_key = trnm_candidate_signing_public_key(key.value);
        CHECK(public_key.data && public_key.size == (algorithm == 65 ? 1952 : 2592));
        trnm_candidate_result verifier = trnm_candidate_verifier_from_pinned_raw(algorithm, public_key.data, public_key.size);
        CHECK(verifier.status == 0 && verifier.value);
        parameter = trnm_candidate_verifier_algorithm(verifier.value);
        CHECK(parameter.status == 0 && parameter.value == algorithm);
        trnm_candidate_view copy = trnm_candidate_verifier_public_key(verifier.value);
        CHECK(copy.size == public_key.size && memcmp(copy.data, public_key.data, copy.size) == 0);
        trnm_candidate_result name = trnm_candidate_algorithm_name(algorithm);
        CHECK(name.status == 0 && name.value);
        trnm_candidate_view text = trnm_candidate_algorithm_name_bytes(name.value);
        CHECK(text.size == 9 && memcmp(text.data, algorithm == 65 ? "ML-DSA-65" : "ML-DSA-87", 9) == 0);
        parameter = trnm_candidate_algorithm_public_key_bytes(algorithm);
        CHECK(parameter.status == 0 && parameter.value == public_key.size);
        parameter = trnm_candidate_algorithm_signature_bytes(algorithm);
        CHECK(parameter.status == 0 && parameter.value == (algorithm == 65 ? 3309 : 4627));
        uint64_t signature_size = parameter.value;
        parameter = trnm_candidate_algorithm_nist_category(algorithm);
        CHECK(parameter.status == 0 && parameter.value == (algorithm == 65 ? 3 : 5));
        trnm_candidate_result signed_value = trnm_candidate_sign(key.value, NULL, 0);
        CHECK(signed_value.status == 0 && signed_value.value);
        trnm_candidate_view signature = trnm_candidate_signature_bytes(signed_value.value);
        CHECK(signature.size == signature_size);
        trnm_candidate_result checked = trnm_candidate_verify(verifier.value, NULL, 0, signature.data, signature.size);
        CHECK(checked.status == 0 && checked.value && trnm_candidate_value_code(checked.value) == 0);
        trnm_candidate_result invalid = trnm_candidate_verify(verifier.value, NULL, 0, NULL, 0);
        CHECK(invalid.status == 0 && invalid.value && trnm_candidate_kind(invalid.value) == 255);
        CHECK(trnm_candidate_value_code(invalid.value) == 5);
        CHECK(trnm_candidate_value_expected(invalid.value) == signature_size && trnm_candidate_value_actual(invalid.value) == 0);
        trnm_candidate_result display = trnm_candidate_error_display(invalid.value);
        trnm_candidate_result direct = trnm_candidate_candidate_error_display(5, signature_size, 0);
        CHECK(display.status == 0 && direct.status == 0 && display.value && direct.value);
        trnm_candidate_view first = trnm_candidate_value_bytes(display.value);
        trnm_candidate_view second = trnm_candidate_value_bytes(direct.value);
        CHECK(first.size == second.size && memcmp(first.data, second.data, first.size) == 0);
        CHECK(trnm_candidate_drop(key.value) == 0 && trnm_candidate_drop(verifier.value) == 0);
        CHECK(trnm_candidate_signature_bytes(signed_value.value).size == signature_size);
        CHECK(trnm_candidate_value_code(checked.value) == 0);
        trnm_candidate_value *values[] = {name.value, signed_value.value, checked.value, invalid.value, display.value, direct.value};
        for (unsigned at = 0; at < sizeof(values) / sizeof(values[0]); ++at) CHECK(trnm_candidate_drop(values[at]) == 0);
    }
    CHECK(trnm_candidate_drop(all.value) == 0 && trnm_candidate_drop(NULL) == 0);
    puts("{\"status\":\"PASS\",\"algorithms\":2,\"public_entries_used\":25}");
    return 0;
}
