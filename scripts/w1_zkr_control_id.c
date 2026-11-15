/* SPDX-License-Identifier: Apache-2.0
 * Independent normal-form reconstruction of the RISC Zero recursion code
 * commitment. Algorithm/parameters: RISC Zero Apache-2.0 source at 8c215e2f.
 * Constants and independent Python KATs are supplied by the pinned-source
 * Python driver in a generated header. This executes no recursive bytecode.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <omp.h>
#include "w1_zkr_constants.h"

#define P UINT32_C(2013265921)
#define WIDTH 24
#define COLS 23
#define RATE 16
#define MONT_R UINT32_C(268435454)

static inline uint32_t add(uint32_t a, uint32_t b) {
    uint32_t c = a + b;
    return c >= P ? c - P : c;
}
static inline uint32_t sub(uint32_t a, uint32_t b) {
    return a >= b ? a - b : a + P - b;
}
static inline uint32_t mul(uint32_t a, uint32_t b) {
    return (uint32_t)(((uint64_t)a * b) % P);
}
static uint32_t power(uint32_t a, uint32_t b) {
    uint32_t result = 1;
    while (b) {
        if (b & 1) result = mul(result, a);
        a = mul(a, a);
        b >>= 1;
    }
    return result;
}
static inline uint32_t seventh(uint32_t a) {
    uint32_t a2 = mul(a, a), a4 = mul(a2, a2);
    return mul(mul(a4, a2), a);
}

static void external_matrix(uint32_t *s) {
    uint32_t out[WIDTH];
    uint64_t sums[4] = {0, 0, 0, 0};
    for (unsigned k = 0; k < WIDTH; k += 4) {
        uint64_t t0 = (uint64_t)s[k] + s[k + 1];
        uint64_t t1 = (uint64_t)s[k + 2] + s[k + 3];
        uint64_t t2 = 2 * (uint64_t)s[k + 1] + t1;
        uint64_t t3 = 2 * (uint64_t)s[k + 3] + t0;
        uint64_t t4 = 4 * t1 + t3, t5 = 4 * t0 + t2;
        out[k] = (uint32_t)((t3 + t5) % P);
        out[k + 1] = (uint32_t)(t5 % P);
        out[k + 2] = (uint32_t)((t2 + t4) % P);
        out[k + 3] = (uint32_t)(t4 % P);
        for (unsigned j = 0; j < 4; j++) sums[j] += out[k + j];
    }
    for (unsigned j = 0; j < 4; j++) sums[j] %= P;
    for (unsigned k = 0; k < WIDTH; k++) s[k] = add(out[k], (uint32_t)sums[k % 4]);
}

static void permutation(uint32_t *s) {
    external_matrix(s);
    for (unsigned round = 0; round < 29; round++) {
        if (round < 4 || round >= 25) {
            for (unsigned k = 0; k < WIDTH; k++)
                s[k] = seventh(add(s[k], ROUND_CONSTANTS[round * WIDTH + k]));
            external_matrix(s);
        } else {
            s[0] = seventh(add(s[0], ROUND_CONSTANTS[round * WIDTH]));
            uint64_t total = 0;
            for (unsigned k = 0; k < WIDTH; k++) total += s[k];
            total %= P;
            for (unsigned k = 0; k < WIDTH; k++)
                s[k] = (uint32_t)((total + (uint64_t)DIAGONAL[k] * s[k]) % P);
        }
    }
}

static void hash23(const uint32_t *v, size_t stride, uint32_t *out) {
    uint32_t s[WIDTH] = {0};
    for (unsigned k = 0; k < RATE; k++) s[k] = v[k * stride];
    permutation(s);
    for (unsigned k = 0; k < RATE; k++) s[k] = k < 7 ? v[(k + RATE) * stride] : 0;
    permutation(s);
    memcpy(out, s, 8 * sizeof(uint32_t));
}

static void hash_pair(const uint32_t *left, const uint32_t *right, uint32_t *out) {
    uint32_t s[WIDTH] = {0};
    memcpy(s, left, 8 * sizeof(uint32_t));
    memcpy(s + 8, right, 8 * sizeof(uint32_t));
    permutation(s);
    memcpy(out, s, 8 * sizeof(uint32_t));
}

/* Natural-order Cooley-Tukey DFT. The SDK internally keeps bit-reversed
 * coefficients; this implementation makes that ordering conversion explicit
 * by using ordinary coefficient order and zero padding for the 4x LDE. */
static void ntt(uint32_t *values, unsigned bits, int inverse) {
    size_t n = (size_t)1 << bits;
    for (size_t i = 1, j = 0; i < n; i++) {
        size_t bit = n >> 1;
        while (j & bit) { j ^= bit; bit >>= 1; }
        j ^= bit;
        if (i < j) { uint32_t t = values[i]; values[i] = values[j]; values[j] = t; }
    }
    for (unsigned level = 1; level <= bits; level++) {
        size_t length = (size_t)1 << level, half = length / 2;
        uint32_t step = inverse ? ROU_REV[level] : ROU_FWD[level];
        for (size_t start = 0; start < n; start += length) {
            uint32_t w = 1;
            for (size_t j = 0; j < half; j++) {
                uint32_t a = values[start + j], b = mul(values[start + j + half], w);
                values[start + j] = add(a, b);
                values[start + j + half] = sub(a, b);
                w = mul(w, step);
            }
        }
    }
    if (inverse) {
        uint32_t scale = power((uint32_t)n, P - 2);
        for (size_t i = 0; i < n; i++) values[i] = mul(values[i], scale);
    }
}

static double seconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

struct result {
    uint32_t root[8];
    uint32_t samples[16];
    double lde_seconds, leaf_seconds, tree_seconds;
};

static int control_root(const uint32_t *code, size_t code_rows, unsigned bits,
                        int threads, struct result *result) {
    size_t n = (size_t)1 << bits, domain = 4 * n;
    uint32_t *matrix = calloc(COLS * domain, sizeof(uint32_t));
    uint32_t *nodes = calloc(2 * domain * 8, sizeof(uint32_t));
    uint32_t *shifts = malloc(n * sizeof(uint32_t));
    if (!matrix || !nodes || !shifts) { free(matrix); free(nodes); free(shifts); return 0; }
    shifts[0] = 1;
    for (size_t i = 1; i < n; i++) shifts[i] = mul(shifts[i - 1], 3);
    double began = seconds();
    #pragma omp parallel for num_threads(threads) schedule(static)
    for (unsigned col = 0; col < COLS; col++) {
        uint32_t *column = matrix + col * domain;
        for (size_t row = 0; row < code_rows; row++) column[row] = code[row * COLS + col];
        ntt(column, bits, 1);
        for (size_t i = 0; i < n; i++) column[i] = mul(column[i], shifts[i]);
        ntt(column, bits + 2, 0);
    }
    result->lde_seconds = seconds() - began;
    for (unsigned i = 0; i < 8; i++) {
        result->samples[i] = matrix[i];
        result->samples[8 + i] = matrix[(COLS - 1) * domain + i];
    }
    began = seconds();
    #pragma omp parallel for num_threads(threads) schedule(static)
    for (size_t row = 0; row < domain; row++)
        hash23(matrix + row, domain, nodes + (domain + row) * 8);
    result->leaf_seconds = seconds() - began;
    free(matrix); free(shifts);
    began = seconds();
    for (size_t layer = domain / 2; layer; layer /= 2) {
        #pragma omp parallel for num_threads(threads) schedule(static)
        for (size_t i = 0; i < layer; i++)
            hash_pair(nodes + (2 * layer + 2 * i) * 8,
                      nodes + (2 * layer + 2 * i + 1) * 8, nodes + (layer + i) * 8);
    }
    result->tree_seconds = seconds() - began;
    memcpy(result->root, nodes + 8, sizeof(result->root));
    free(nodes);
    return 1;
}

static int self_test(void) {
    uint32_t s[24], out[8], values[32] = {0}, code[4 * COLS];
    for (unsigned i = 0; i < 24; i++) s[i] = i;
    permutation(s);
    if (memcmp(s, KAT_PERM, sizeof(s))) return 0;
    for (unsigned i = 0; i < 24; i++) s[i] = i;
    hash23(s, 1, out);
    if (memcmp(out, KAT_HASH23, sizeof(out))) return 0;
    hash_pair(s, s + 8, out);
    if (memcmp(out, KAT_PAIR, sizeof(out))) return 0;
    for (unsigned i = 0; i < 8; i++) values[i] = i + 1;
    ntt(values, 3, 0);
    if (memcmp(values, KAT_NTT8, 8 * sizeof(uint32_t))) return 0;
    for (unsigned i = 0; i < 8; i++) values[i] = i + 1;
    ntt(values, 3, 1);
    if (memcmp(values, KAT_IFFT8, 8 * sizeof(uint32_t))) return 0;
    uint32_t shift = 1;
    for (unsigned i = 0; i < 8; i++) { values[i] = mul(values[i], shift); shift = mul(shift, 3); }
    ntt(values, 5, 0);
    if (memcmp(values, KAT_LDE32, sizeof(values))) return 0;
    for (unsigned row = 0; row < 4; row++)
        for (unsigned col = 0; col < COLS; col++) code[row * COLS + col] = 100 * (row + 1) + col;
    struct result result;
    if (!control_root(code, 4, 3, 1, &result) || memcmp(result.root, KAT_TINY_ROOT, sizeof(out))) return 0;
    return 1;
}

static void hex_digest(const uint32_t *root) {
    for (unsigned i = 0; i < 8; i++) {
        uint32_t raw = mul(root[i], MONT_R);
        for (unsigned j = 0; j < 4; j++) printf("%02x", (raw >> (8 * j)) & 255);
    }
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--self-test")) {
        if (!self_test()) { fputs("native arithmetic known-answer failure\n", stderr); return 1; }
        puts("{\"self_test\":\"PASS\",\"checks\":7,\"arithmetic\":\"normal BabyBear\"}");
        return 0;
    }
    if (argc != 4) { fputs("usage: control-id input.zkr po2 threads\n", stderr); return 2; }
    char *end_bits = NULL, *end_threads = NULL;
    long parsed_bits = strtol(argv[2], &end_bits, 10), parsed_threads = strtol(argv[3], &end_threads, 10);
    if (!*argv[2] || !*argv[3] || *end_bits || *end_threads || parsed_bits < 11 || parsed_bits > 18
        || parsed_threads < 1 || parsed_threads > 4) {
        fputs("unsupported audit po2 or thread limit\n", stderr); return 2;
    }
    unsigned bits = (unsigned)parsed_bits;
    int threads = (int)parsed_threads;
    FILE *input = fopen(argv[1], "rb");
    if (!input || fseek(input, 0, SEEK_END)) { fputs("cannot read program\n", stderr); return 2; }
    long length = ftell(input);
    if (length <= 0 || length > 32 * 1024 * 1024 || length % (4 * COLS)
        || (size_t)length / (4 * COLS) > ((size_t)1 << bits) - 1024) {
        fclose(input); fputs("invalid program size or capacity\n", stderr); return 2;
    }
    rewind(input);
    unsigned char *bytes = malloc((size_t)length);
    uint32_t *code = malloc((size_t)length);
    if (!bytes || !code) { fclose(input); free(bytes); free(code); return 2; }
    if (fread(bytes, 1, (size_t)length, input) != (size_t)length || fgetc(input) != EOF) {
        fclose(input); free(bytes); free(code); return 2;
    }
    fclose(input);
    for (size_t i = 0; i < (size_t)length / 4; i++) {
        code[i] = (uint32_t)bytes[4 * i] | ((uint32_t)bytes[4 * i + 1] << 8)
            | ((uint32_t)bytes[4 * i + 2] << 16) | ((uint32_t)bytes[4 * i + 3] << 24);
        if (code[i] >= P) { free(bytes); free(code); fputs("noncanonical code word\n", stderr); return 2; }
    }
    free(bytes);
    struct result result;
    size_t rows = (size_t)length / (4 * COLS);
    if (!control_root(code, rows, bits, threads, &result)) { free(code); return 2; }
    free(code);
    printf("{\"control_id\":\""); hex_digest(result.root);
    printf("\",\"code_rows\":%zu,\"trace_po2\":%u,\"domain_rows\":%zu,\"threads\":%d,",
           rows, bits, (size_t)4 << bits, threads);
    printf("\"root_normal_words\":[");
    for (unsigned i = 0; i < 8; i++) printf("%s%u", i ? "," : "", result.root[i]);
    printf("],\"lde_samples_normal\":[");
    for (unsigned i = 0; i < 16; i++) printf("%s%u", i ? "," : "", result.samples[i]);
    printf("],\"phase_seconds\":{\"lde\":%.6f,\"leaves\":%.6f,\"tree\":%.6f}}\n",
           result.lde_seconds, result.leaf_seconds, result.tree_seconds);
    return 0;
}
