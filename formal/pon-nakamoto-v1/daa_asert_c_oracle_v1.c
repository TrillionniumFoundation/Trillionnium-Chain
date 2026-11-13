/*
 * Non-authoritative, standalone C11 + unsigned __int128 ASERT integer verifier.
 * Independent from the Rust/Python implementations; no consensus integration.
 * Input: <anchorTargetHex64> <powLimitHex64> <anchorParentTime> <parentTime>
 *        <anchorHeight> <candidateHeight> <spacing> <halfLife>\n
 * One line yields 64 lowercase hex digits or ERR. No work proof is checked.
 */
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(__SIZEOF_INT128__) || __SIZEOF_INT128__ != 16
#error "This research verifier requires __int128 support"
#endif

typedef unsigned __int128 u128;
#define WORDS 9U
#define MAX_LINE 512U

static void clear_words(uint64_t value[WORDS]) {
    for (size_t i = 0; i < WORDS; ++i) value[i] = 0;
}

static bool parse_hex256(const char *s, uint64_t value[WORDS]) {
    static const char digits[] = "0123456789abcdef";
    if (strlen(s) != 64U) return false;
    clear_words(value);
    for (size_t i = 0; i < 64U; i++) {
        char c = s[63U-i];
        const char *at = strchr(digits, c);
        if (at == NULL) return false;
        value[i/16U] |= (uint64_t)(at-digits) << ((i%16U)*4U);
    }
    return true;
}

static bool parse_u64(const char *s, uint64_t *out) {
    if (*s == '\0' || *s == '-' || *s == '+') return false;
    for (const char *p = s; *p; p++) if (*p < '0' || *p > '9') return false;
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(s, &end, 10);
    if (errno == ERANGE || end == s || *end != '\0') return false;
    *out = (uint64_t)value;
    return true;
}

static int compare(const uint64_t a[WORDS], const uint64_t b[WORDS]) {
    for (size_t i = WORDS; i-- > 0;) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

static bool nonzero(const uint64_t a[WORDS]) {
    for (size_t i = 0; i < WORDS; ++i) if (a[i]) return true;
    return false;
}

static void mul_small(uint64_t a[WORDS], uint64_t factor) {
    u128 carry = 0;
    for (size_t i = 0; i < WORDS; ++i) {
        const u128 product = (u128)a[i] * factor + carry;
        a[i] = (uint64_t)product;
        carry = product >> 64;
    }
}

static void left_shift(uint64_t a[WORDS], unsigned int bits) {
    uint64_t old[WORDS];
    memcpy(old, a, sizeof old);
    size_t wide = bits/64U;
    unsigned int small = bits%64U;
    for (size_t i=0; i<WORDS; ++i) {
        uint64_t next = 0;
        if (i >= wide) {
            next = old[i-wide] << small;
            if (small != 0 && i > wide) next |= old[i-wide-1U] >> (64U-small);
        }
        a[i] = next;
    }
}

static void right_shift(uint64_t a[WORDS], unsigned int bits) {
    uint64_t old[WORDS];
    memcpy(old, a, sizeof old);
    size_t wide = bits/64U;
    unsigned int small = bits%64U;
    for (size_t i=0; i<WORDS; ++i) {
        uint64_t next = 0;
        if (i+wide < WORDS) {
            next = old[i+wide] >> small;
            if (small != 0 && i+wide+1U < WORDS)
                next |= old[i+wide+1U] << (64U-small);
        }
        a[i] = next;
    }
}

static bool calculate(uint64_t anchor[WORDS], const uint64_t limit[WORDS],
                      const uint64_t params[6]) {
    uint64_t anchor_time = params[0], parent_time = params[1],
             anchor_height = params[2], candidate_height = params[3],
             spacing = params[4], half_life = params[5];
    if (anchor_height == 0 || anchor_height >= candidate_height ||
        spacing == 0 || half_life == 0 || !nonzero(anchor) || !nonzero(limit) ||
        compare(anchor, limit)>0) return false;

    const u128 i128max = ((u128)1 << 127) - 1;
    const u128 i128minmag = (u128)1 << 127;
    u128 work_time = (u128)(candidate_height-anchor_height) * spacing;
    if (work_time > i128max) return false;

    /* Avoid overflow even when signed parent-anchor-work would underflow. */
    const bool time_positive = parent_time >= anchor_time;
    u128 diff = time_positive ? (u128)(parent_time-anchor_time) :
                                (u128)(anchor_time-parent_time);
    bool negative;
    u128 magnitude;
    if (!time_positive) {
        negative = true;
        magnitude = diff + work_time;
    } else if (diff >= work_time) {
        negative = false;
        magnitude = diff - work_time;
    } else {
        negative = true;
        magnitude = work_time - diff;
    }
    u128 scaled_bound = negative ? i128minmag : i128max;
    if (magnitude > scaled_bound || magnitude > scaled_bound/65536U) return false;
    u128 quotient = magnitude*65536U / half_life;
    u128 whole = quotient / 65536U;
    u128 remainder = quotient % 65536U;

    int shift;
    uint64_t fractional;
    if (!negative) {
        if (whole >= 256U) { memcpy(anchor, limit, sizeof(uint64_t)*WORDS); return true; }
        shift = (int)whole;
        fractional = (uint64_t)remainder;
    } else {
        if (whole > 511U || (whole == 511U && remainder != 0U)) {
            clear_words(anchor); anchor[0] = 1; return true;
        }
        shift = -(int)whole - (remainder != 0U ? 1 : 0);
        fractional = remainder == 0U ? 0U : (uint64_t)(65536U - remainder);
    }
    const u128 f = (u128)195766423245049ULL*fractional +
                  (u128)971821376ULL*fractional*fractional +
                  (u128)5127ULL*fractional*fractional*fractional +
                  ((u128)1 << 47);
    const uint64_t factor = 65536U + (uint64_t)(f >> 48);
    mul_small(anchor, factor);
    if (shift >= 0) left_shift(anchor, (unsigned int)shift);
    else right_shift(anchor, (unsigned int)(-shift));
    right_shift(anchor, 16U);
    if (compare(anchor, limit) > 0) memcpy(anchor, limit, sizeof(uint64_t)*WORDS);
    if (!nonzero(anchor)) anchor[0] = 1U;
    return true;
}

static void print_target(const uint64_t a[WORDS]) {
    static const char d[] = "0123456789abcdef";
    for (size_t i=64U; i-- > 0;) putchar(d[(a[i/16U] >> ((i%16U)*4U)) & 0xfU]);
    putchar('\n');
}

int main(void) {
    char line[MAX_LINE];
    while (fgets(line, sizeof line, stdin)) {
        char ah[65], ph[65], numbers[6][32], extra[2];
        const int n = sscanf(line, "%64s %64s %31s %31s %31s %31s %31s %31s %1s",
                             ah, ph, numbers[0],numbers[1],numbers[2],numbers[3],
                             numbers[4],numbers[5],extra);
        uint64_t a[WORDS],lim[WORDS],p[6];
        bool ok = (n == 8) && parse_hex256(ah,a) && parse_hex256(ph,lim);
        for (size_t i=0; ok && i<6U; i++) ok = parse_u64(numbers[i],&p[i]);
        if (!ok || !calculate(a,lim,p)) { puts("ERR"); continue; }
        print_target(a);
    }
    return ferror(stdin) ? 2 : 0;
}
