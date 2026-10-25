/*
 * Independent research-only C / OpenSSL BIGNUM ASERT integer oracle.
 * This is not a consensus implementation, does not mine W1, and never
 * interprets a model or grants release/fork-choice authority.
 *
 * Usage: ./daa_reference_c --anchor HEX64 --limit HEX64
 *   --anchor-parent-time U64 --parent-time U64 --anchor-height U64
 *   --height U64 --spacing U64 --half-life U64
 */
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/bn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef __int128 i128;
typedef unsigned __int128 u128;

struct Params {
    const char *anchor;
    const char *limit;
    uint64_t anchor_parent_time, parent_time, anchor_height, height, spacing, half_life;
};

static int parse_u64(const char *s, uint64_t *out) {
    if (!s || !*s || *s == '-' || *s == '+' || *s == ' ') return 0;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(s, &end, 10);
    if (errno || !end || *end || end == s) return 0;
    *out = (uint64_t)value;
    return 1;
}
static int hex64(const char *s) {
    if (!s || strlen(s) != 64) return 0;
    for (size_t i = 0; i < 64; i++) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    }
    return 1;
}
static int parse_args(int argc, char **argv, struct Params *p) {
    if (argc != 17) return 0;
    unsigned seen = 0;
    for (int i = 1; i < argc; i += 2) {
        const char *name = argv[i], *value = argv[i + 1];
        int index = -1;
        const char *keys[] = {"--anchor", "--limit", "--anchor-parent-time", "--parent-time",
                              "--anchor-height", "--height", "--spacing", "--half-life"};
        for (int j = 0; j < 8; j++) if (strcmp(name, keys[j]) == 0) index = j;
        if (index < 0 || (seen & (1u << index))) return 0;
        seen |= (1u << index);
        switch (index) {
        case 0: p->anchor = value; break;
        case 1: p->limit = value; break;
        case 2: if (!parse_u64(value, &p->anchor_parent_time)) return 0; break;
        case 3: if (!parse_u64(value, &p->parent_time)) return 0; break;
        case 4: if (!parse_u64(value, &p->anchor_height)) return 0; break;
        case 5: if (!parse_u64(value, &p->height)) return 0; break;
        case 6: if (!parse_u64(value, &p->spacing)) return 0; break;
        case 7: if (!parse_u64(value, &p->half_life)) return 0; break;
        }
    }
    return seen == 255 && hex64(p->anchor) && hex64(p->limit);
}
static int compute(const struct Params *p) {
    int rc = 2;
    BIGNUM *base = NULL, *limit = NULL, *result = NULL;
    base = BN_new(); limit = BN_new(); result = BN_new();
    if (!base || !limit || !result ||
        BN_hex2bn(&base, p->anchor) != 64 ||
        BN_hex2bn(&limit, p->limit) != 64) goto failed;
    if (BN_is_zero(base) || BN_cmp(base, limit) > 0 ||
        p->anchor_height == 0 || p->height <= p->anchor_height ||
        p->spacing == 0 || p->half_life == 0) {
        fputs("ASERT_RESEARCH_PARAMETERS\n", stderr);
        goto done;
    }
    const i128 intervals = (i128)(p->height - p->anchor_height);
    i128 ideal, deviation, scaled;
    if (__builtin_mul_overflow(intervals, (i128)p->spacing, &ideal) ||
        __builtin_sub_overflow((i128)p->parent_time, (i128)p->anchor_parent_time, &deviation) ||
        __builtin_sub_overflow(deviation, ideal, &deviation) ||
        __builtin_mul_overflow(deviation, (i128)65536, &scaled)) {
        fputs("ASERT_RESEARCH_RANGE\n", stderr);
        goto done;
    }
    const i128 exponent = scaled / (i128)p->half_life; /* truncate toward zero */
    i128 shifts = exponent / (i128)65536;
    i128 fractional = exponent % (i128)65536;
    if (fractional < 0) { shifts--; fractional += 65536; }
    const i128 factor = ((195766423245049 * fractional +
                          971821376 * fractional * fractional +
                          5127 * fractional * fractional * fractional +
                          ((i128)1 << 47)) >> 48) + 65536;
    if (factor < 65536 || factor > 131072) {
        fputs("ASERT_RESEARCH_FACTOR\n", stderr);
        goto done;
    }
    if (shifts >= 256) {
        if (!BN_copy(result, limit)) goto failed;
    } else if (shifts <= -512) {
        if (!BN_one(result)) goto failed;
    } else {
        if (!BN_copy(result, base) || !BN_mul_word(result, (BN_ULONG)factor)) goto failed;
        if (shifts >= 0) {
            if (!BN_lshift(result, result, (int)shifts)) goto failed;
        } else {
            if (!BN_rshift(result, result, (int)-shifts)) goto failed;
        }
        if (!BN_rshift(result, result, 16)) goto failed;
        if (BN_is_zero(result) && !BN_one(result)) goto failed;
        if (BN_cmp(result, limit) > 0 && !BN_copy(result, limit)) goto failed;
    }
    unsigned char bytes[32];
    if (BN_bn2binpad(result, bytes, sizeof bytes) != (int)sizeof bytes) goto failed;
    for (size_t i = 0; i < sizeof bytes; i++) printf("%02x", bytes[i]);
    putchar('\n');
    rc = 0;
    goto done;
failed:
    fputs("ASERT_RESEARCH_INTERNAL\n", stderr);
done:
    BN_free(base); BN_free(limit); BN_free(result);
    return rc;
}
int main(int argc, char **argv) {
    struct Params p = {0};
    if (!parse_args(argc, argv, &p)) {
        fputs("ASERT_RESEARCH_ARGUMENTS\n", stderr);
        return 2;
    }
    return compute(&p);
}
