/* Third-language, research-only ASERT u256 reference; never a consensus verifier.
 * GCC/Clang signed __int128 checks and GMP for exact, unbounded arithmetic.
 * No Bitcoin-style compact bits; truncate exponent toward zero, Euclidean split.
 * argv: anchor_u256hex anchor_parent_time parent_time anchor_height
 *       candidate_height spacing half_life pow_limit_u256hex
 */
#include <stdio.h>
#include <errno.h>
#include <gmp.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int u64(const char *s, uint64_t *v) {
    if (!s || !*s || *s == '-' || *s == '+') return 0;
    for (const char *p = s; *p; ++p) if (*p < '0' || *p > '9') return 0;
    errno = 0;
    char *end = NULL;
    unsigned long long z = strtoull(s, &end, 10);
    if (errno || !end || *end || (uint64_t)z != z) return 0;
    *v = (uint64_t)z;
    return 1;
}

static int target(const char *s, mpz_t value) {
    if (!s || strlen(s) != 64) return 0;
    for (const char *p = s; *p; ++p)
        if (!(*p >= '0' && *p <= '9') && !(*p >= 'a' && *p <= 'f')) return 0;
    return mpz_set_str(value, s, 16) == 0 && mpz_sgn(value) > 0;
}

int main(int argc, char **argv) {
    if (argc != 9) { fputs("ASERT_RESEARCH_PARAMETERS\n", stderr); return 2; }
    mpz_t a, limit, result;
    mpz_inits(a, limit, result, NULL);
    int rc = 2;
    uint64_t at, pt, ah, ch, spacing, half;
    if (!target(argv[1], a) || !target(argv[8], limit)
        || mpz_cmp(a, limit) > 0
        || !u64(argv[2], &at) || !u64(argv[3], &pt)
        || !u64(argv[4], &ah) || !u64(argv[5], &ch)
        || !u64(argv[6], &spacing) || !u64(argv[7], &half)
        || !ah || ch <= ah || !spacing || !half) {
        fputs("ASERT_RESEARCH_PARAMETERS\n", stderr);
        goto done;
    }
    __int128 ideal, diff, deviation, scaled;
    if (__builtin_mul_overflow((__int128)(ch - ah), (__int128)spacing, &ideal)
        || __builtin_sub_overflow((__int128)pt, (__int128)at, &diff)
        || __builtin_sub_overflow(diff, ideal, &deviation)
        || __builtin_mul_overflow(deviation, (__int128)65536, &scaled)) {
        fputs("ASERT_RESEARCH_RANGE\n", stderr);
        goto done;
    }
    __int128 exponent = scaled / (__int128)half;
    __int128 shift = exponent / 65536;
    __int128 fraction = exponent % 65536;
    if (fraction < 0) { fraction += 65536; --shift; }
    const __int128 f = fraction;
    const __int128 factor = 65536 +
        ((195766423245049 * f + 971821376 * f * f + 5127 * f * f * f
          + (((__int128)1) << 47)) >> 48);
    if (factor < 65536 || factor > 131072) {
        fputs("ASERT_RESEARCH_FACTOR\n", stderr);
        goto done;
    }
    if (shift >= 256) {
        mpz_set(result, limit);
    } else if (shift <= -512) {
        mpz_set_ui(result, 1);
    } else {
        mpz_mul_ui(result, a, (unsigned long)factor);
        if (shift >= 0) mpz_mul_2exp(result, result, (mp_bitcnt_t)shift);
        else mpz_fdiv_q_2exp(result, result, (mp_bitcnt_t)(-shift));
        mpz_fdiv_q_2exp(result, result, 16);
        if (mpz_sgn(result) <= 0) mpz_set_ui(result, 1);
        if (mpz_cmp(result, limit) > 0) mpz_set(result, limit);
    }
    mpz_out_str(stdout, 16, result);
    putchar('\n');
    rc = 0;
done:
    mpz_clears(a, limit, result, NULL);
    return rc;
}
