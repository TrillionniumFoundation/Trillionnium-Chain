#ifndef TRNM_WORKER_AUDIT_V1_H
#define TRNM_WORKER_AUDIT_V1_H
#include <stddef.h>
#include <stdint.h>

/* Linux x86-64 LP64. Synchronous, live mutually disjoint borrowed buffers.
 * Input and output lengths must be <= 1 MiB. Reserved extent must be zero;
 * pass a live disjoint dummy pointer. Only WJB3 is accepted.
 * Return high word: nonzero foreign-buffer ABI refusal (not a result).
 * Return low word: bytes written, 0xffffffff malformed, 0xfffffffe capacity.
 * Refusals leave output bytes unchanged for valid borrowed regions.
 * No filesystem, network, or production-dispatch capability.
 */
uint64_t trnm_worker_audit_export_v1(
    const uint8_t *input, size_t input_bytes,
    uint8_t *output, size_t output_capacity,
    uint8_t *reserved, size_t reserved_bytes);

#endif
