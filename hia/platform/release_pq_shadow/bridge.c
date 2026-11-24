/*
 * Test-only C glue for one linked call over real HIA release phases.
 * It neither implements cryptography nor creates a transferable capability.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum {
    HEADER = 24, STATE_FIXED = 334, STATE_MAX = STATE_FIXED + 4096 * 33,
    BUNDLE_MIN = 1067 + 322, BUNDLE_MAX = BUNDLE_MIN + 64 * (877 + 1351 + 772 + 578),
    KEY_SIZE = 2006, KEY_MAX = 16, SIG_SIZE = 4130, SIG_MAX = 32, QUORUM_HEAD = 232,
    MAX_INPUT = HEADER + STATE_MAX + BUNDLE_MAX + KEY_MAX * KEY_SIZE + 2 + SIG_MAX * SIG_SIZE,
    OUTPUT = 64, WORK = 32896,
};
enum phase {
    WIRE = 1, OUTER, UNSIGNED, IDENTITY_MISMATCH, LOCATOR, LOCATOR_MISMATCH, QUORUM, STATE, INTERNAL,
};

typedef uint64_t unit(const uint8_t *, uint64_t, uint8_t *, uint64_t, uint8_t *, uint64_t);

#define PRIVATE __attribute__((visibility("hidden")))
extern PRIVATE unit trnm_release_shadow_unsigned;
extern PRIVATE unit trnm_release_shadow_identity;
extern PRIVATE unit trnm_release_shadow_locator;
extern PRIVATE unit trnm_release_shadow_message;
extern PRIVATE unit trnm_release_shadow_quorum;
extern PRIVATE unit trnm_release_shadow_state;

struct workspace {
    uint8_t native[WORK];
    uint8_t quorum[QUORUM_HEAD + KEY_MAX * KEY_SIZE + SIG_MAX * SIG_SIZE];
    uint8_t unsigned_output[168], identity[33], digest[32], proposal[OUTPUT];
    uint8_t owned[];
};

static uint32_t le(const uint8_t *p, size_t n) {
    uint32_t value = 0;
    for (size_t i = 0; i < n; i++) value |= (uint32_t)p[i] << (8 * i);
    return value;
}

static void put16(uint8_t *p, unsigned n) {
    p[0] = (uint8_t)n;
    p[1] = (uint8_t)(n >> 8);
}

static uint64_t tagged(unsigned status, enum phase where, uint64_t detail) {
    if (detail > UINT8_MAX) return 250U | ((uint64_t)INTERNAL << 8);
    return status | ((uint64_t)where << 8) | (detail << 16);
}

static int disjoint(const void *input, size_t n, const void *output, size_t m) {
    const uintptr_t a = (uintptr_t)input, b = (uintptr_t)output;
    return a <= UINTPTR_MAX - n && b <= UINTPTR_MAX - m && (a + n <= b || b + m <= a);
}

static int same_digest(const uint8_t *a, const uint8_t *b) {
    unsigned difference = 0;
    for (size_t i = 0; i < 32; i++) difference |= (unsigned)(a[i] ^ b[i]);
    return difference == 0;
}

static uint64_t run(struct workspace *w, size_t extent) {
    const uint8_t *header = w->owned;
    const size_t state_n = le(header + 4, 4), bundle_n = le(header + 8, 4);
    const unsigned keys = le(header + 12, 2), threshold = le(header + 14, 2);
    const unsigned sigs = le(header + 16, 2);
    if (header[0] != 'R' || header[1] != 'S' || header[2] != 'O' || header[3] != '1' ||
        le(header + 18, 2) || le(header + 20, 4) ||
        state_n < STATE_FIXED || state_n > STATE_MAX || bundle_n < BUNDLE_MIN || bundle_n > BUNDLE_MAX ||
        keys > KEY_MAX || sigs > SIG_MAX || (keys == 0 ? threshold != 0 : threshold == 0 || threshold > keys))
        return tagged(100, WIRE, 100);
    const size_t pins_n = KEY_SIZE * keys, packed_n = 2 + SIG_SIZE * sigs;
    if (extent != HEADER + state_n + bundle_n + pins_n + packed_n)
        return tagged(100, WIRE, 100);
    const uint8_t *state = header + HEADER, *bundle = state + state_n;
    const uint8_t *pins = bundle + bundle_n, *packed = pins + pins_n;
    if (sigs != le(packed, 2)) return tagged(100, WIRE, 100);

    const unsigned arts = le(bundle + 4, 2), packages = le(bundle + 6, 2), required = le(bundle + 8, 2);
    const size_t declared = 1067 + 877U * arts + 1351U * packages + 772U * required + 290;
    if (arts > 64 || packages > 64 || required > 64 || declared + 32 > bundle_n)
        return tagged(100, WIRE, 100);
    if (state[0] != 1 || !same_digest(state + 122, bundle + declared))
        return tagged(1, OUTER, 1);
    // Normal Rust roots require all role pins; reject absent NodeSoftware before V0 content.
    if (!keys) return tagged(209, OUTER, 209);

    uint64_t code = trnm_release_shadow_unsigned(bundle, bundle_n, w->unsigned_output, 168, w->native, 5360);
    if (code) return tagged(2, UNSIGNED, code);
    if (!same_digest(w->unsigned_output, state + 122)) return tagged(250, INTERNAL, 0);

    memcpy(w->identity, state + 187, 32);  // trusted root network, never offered network
    w->identity[32] = state[0];
    code = trnm_release_shadow_identity(w->identity, 33, w->digest, 32, w->native, 1256);
    if (code) return tagged(250, INTERNAL, code);
    if (!same_digest(w->digest, bundle + 42)) return tagged(2, IDENTITY_MISMATCH, 0);
    code = trnm_release_shadow_locator(packed, packed_n, w->digest, 32, w->native, 1240);
    if (code) return tagged(2, LOCATOR, code);
    if (!same_digest(w->digest, bundle + 74)) return tagged(2, LOCATOR_MISMATCH, 0);

    uint8_t *q = w->quorum;
    put16(q, keys);
    put16(q + 2, sigs);
    put16(q + 4, threshold);
    q[6] = state[0];
    memcpy(q + 8, state + 187, 40);  // checked root network and root generation
    code = trnm_release_shadow_message(state, 155, q + 48, 184, w->native, 0);
    if (code) return tagged(2, QUORUM, code);
    memcpy(q + QUORUM_HEAD, pins, pins_n);
    memcpy(q + QUORUM_HEAD + pins_n, packed + 2, packed_n - 2);
    // This result comes only from linked callback-phase math, and stays on this stack.
    code = trnm_release_shadow_quorum(q, QUORUM_HEAD + pins_n + packed_n - 2, w->digest, 0, w->native, WORK);
    if (code) return tagged(2, QUORUM, code);
    // Same owned metadata and state: state order is after actual callback verification.
    code = trnm_release_shadow_state(state, state_n, w->proposal, OUTPUT, w->native, 1504);
    if (code > UINT8_MAX) return tagged(250, INTERNAL, code);
    return tagged((unsigned)code, STATE, code);
}

__attribute__((visibility("default")))
uint64_t trnm_release_shadow_v1(const uint8_t *input, uint64_t extent, uint8_t *output, uint64_t capacity) {
    if (!input || extent < HEADER || extent > MAX_INPUT) return tagged(100, WIRE, 100);
    if (!output || capacity < OUTPUT) return tagged(102, WIRE, 102);
    if (!disjoint(input, (size_t)extent, output, OUTPUT)) return tagged(100, WIRE, 100);
    struct workspace *work = calloc(1, sizeof(*work) + (size_t)extent);
    if (!work) return tagged(250, INTERNAL, 0);
    memcpy(work->owned, input, (size_t)extent);
    const uint64_t status = run(work, (size_t)extent);
    if ((status & UINT64_C(0xff)) == 0) memcpy(output, work->proposal, OUTPUT);
    free(work);
    return status;
}
