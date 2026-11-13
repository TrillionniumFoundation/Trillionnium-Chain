/* PQL9 research-only TPQ1 signature conformance C ABI. Not production authority. */
#ifndef TRNM_PQL9_TPQ1_CRYPTO_VERIFY_H
#define TRNM_PQL9_TPQ1_CRYPTO_VERIFY_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct trnm_tpq1_expectation_v1 {
    unsigned char network[32];
    unsigned char context[32];
    unsigned char signer_key_id[32];
    unsigned char purpose;
    uint64_t generation;
    uint64_t sequence;
    uint64_t expires_at;
    uint64_t now;
    const unsigned char *payload;
    size_t payload_len;
} trnm_tpq1_expectation_v1;

/* 1 = genuine pure ML-DSA-65 signed statement under the supplied expectation;
 * 0 = reject or provider error. No trusted grants, consensus, nonce, or writes.
 */
int trnm_tpq1_crypto_verify_research_v1(
    const unsigned char *frame, size_t frame_len,
    const unsigned char *pinned_spki, size_t spki_len,
    const trnm_tpq1_expectation_v1 *expected);

#ifdef __cplusplus
}
#endif
#endif
