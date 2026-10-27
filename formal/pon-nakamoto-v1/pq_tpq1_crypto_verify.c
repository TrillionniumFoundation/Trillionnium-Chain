/* PQL9: research-only, read-only TPQ1 pure ML-DSA-65 crypto verification.
 *
 * This C ABI returns ONLY cryptographic validity for independently supplied
 * caller expectations and an out-of-band pinned DER SPKI. It grants no Chain
 * transaction, nonce, release, custody, PoN work, or Hepta Final-use authority.
 * Do not link this into a production consensus node without separate review.
 */
#include "pq_tpq1_crypto_verify.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define TPQ1_STATEMENT_BYTES 176U
#define TPQ1_SIGNATURE_BYTES 3309U
#define TPQ1_FRAME_BYTES (TPQ1_STATEMENT_BYTES + 2U + TPQ1_SIGNATURE_BYTES)
#define MLDSA65_SPKI_BYTES 1974U
#define TPQ1_MAX_PAYLOAD (64U * 1024U * 1024U)

static const unsigned char SPKI_PREFIX[22] = {
    0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
    0x01, 0x65, 0x03, 0x04, 0x03, 0x12, 0x03, 0x82, 0x07, 0xa1, 0x00
};
static const unsigned char KEY_DOMAIN[] = "TRNM/PoN/PQKey/v1";
static const unsigned char AUTH_DOMAIN[] = "TRNM/PoN/PQAuth/ML-DSA-65/v1";
static const unsigned char PAYLOAD_LABEL[] = "payload";

static uint64_t read_u64be(const unsigned char *p) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

static void write_u64be(unsigned char out[8], uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        out[i] = (unsigned char)value;
        value >>= 8;
    }
}

static int digest_fragments(const EVP_MD *algorithm,
                            const unsigned char *const *segments,
                            const size_t *sizes, size_t count,
                            unsigned char *out, unsigned int expected_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int got = 0;
    int ok = ctx != NULL;
    if (ok) ok = EVP_DigestInit_ex(ctx, algorithm, NULL) == 1;
    for (size_t i = 0; ok && i < count; ++i) {
        if (sizes[i] && !segments[i]) { ok = 0; break; }
        if (sizes[i]) ok = EVP_DigestUpdate(ctx, segments[i], sizes[i]) == 1;
    }
    if (ok) ok = EVP_DigestFinal_ex(ctx, out, &got) == 1 && got == expected_len;
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* Return 1 only for a *real* signature of the exact 176-byte TPQ1 statement.
 * This does not establish trusted expectation provenance or spend authority.
 * Return 0 for all malformed, stale, nonmatching, unverified and crypto-error
 * frames. No private key, network, DB, OS file, or runtime authority accessed.
 */
int trnm_tpq1_crypto_verify_research_v1(
    const unsigned char *frame, size_t frame_len,
    const unsigned char *pinned_spki, size_t spki_len,
    const trnm_tpq1_expectation_v1 *expected) {
    if (!frame || !pinned_spki || !expected ||
        frame_len != TPQ1_FRAME_BYTES || spki_len != MLDSA65_SPKI_BYTES ||
        expected->payload_len > TPQ1_MAX_PAYLOAD ||
        (expected->payload_len && !expected->payload) ||
        expected->purpose < 1 || expected->purpose > 6 ||
        !expected->generation || !expected->sequence || !expected->expires_at ||
        expected->now > expected->expires_at)
        return 0;

    /* Bounded cheap structural and state checks before OpenSSL key parsing. */
    if (memcmp(frame, "TPQ1", 4) || frame[4] != 1 || frame[5] != 0x65 ||
        frame[6] != expected->purpose || frame[7] != 0 ||
        CRYPTO_memcmp(frame + 8, expected->network, 32) ||
        CRYPTO_memcmp(frame + 40, expected->context, 32) ||
        read_u64be(frame + 104) != expected->generation ||
        read_u64be(frame + 112) != expected->sequence ||
        read_u64be(frame + 120) != expected->expires_at ||
        frame[176] != 0x0c || frame[177] != 0xed ||
        memcmp(pinned_spki, SPKI_PREFIX, sizeof(SPKI_PREFIX)))
        return 0;

    unsigned char size_be[8], payload_digest[48], key_id[32];
    write_u64be(size_be, (uint64_t)expected->payload_len);
    const unsigned char *const payload_parts[] = {
        AUTH_DOMAIN, PAYLOAD_LABEL, size_be, expected->payload
    };
    const size_t payload_sizes[] = {
        sizeof(AUTH_DOMAIN), sizeof(PAYLOAD_LABEL), 8, expected->payload_len
    };
    if (!digest_fragments(EVP_sha384(), payload_parts, payload_sizes, 4,
                          payload_digest, sizeof(payload_digest)) ||
        CRYPTO_memcmp(payload_digest, frame + 128, sizeof(payload_digest)))
        return 0;

    const unsigned char *const id_parts[] = { KEY_DOMAIN, pinned_spki };
    const size_t id_sizes[] = { sizeof(KEY_DOMAIN), spki_len };
    if (!digest_fragments(EVP_sha256(), id_parts, id_sizes, 2,
                          key_id, sizeof(key_id)) ||
        CRYPTO_memcmp(key_id, expected->signer_key_id, sizeof(key_id)) ||
        CRYPTO_memcmp(key_id, frame + 72, sizeof(key_id)))
        return 0;

    /* Actual provider decode and pure ML-DSA-65 signature verification. */
    const unsigned char *cursor = pinned_spki;
    EVP_PKEY *key = d2i_PUBKEY(NULL, &cursor, (long)spki_len);
    int ok = key && cursor == pinned_spki + spki_len &&
             EVP_PKEY_is_a(key, "ML-DSA-65");
    EVP_MD_CTX *ctx = NULL;
    if (ok) {
        ctx = EVP_MD_CTX_new();
        ok = ctx && EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1;
        if (ok) ok = EVP_DigestVerify(ctx, frame + 178, TPQ1_SIGNATURE_BYTES,
                                      frame, TPQ1_STATEMENT_BYTES) == 1;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok ? 1 : 0;
}
