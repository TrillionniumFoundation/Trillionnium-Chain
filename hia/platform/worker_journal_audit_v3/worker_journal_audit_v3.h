#ifndef TRNM_WORKER_JOURNAL_AUDIT_V3_H
#define TRNM_WORKER_JOURNAL_AUDIT_V3_H
#include <stddef.h>
#include <stdint.h>

/* Linux x86-64 LP64; live disjoint, synchronous caller-owned buffers.
 * Snapshot: WQX3 raw journal bytes <= 65536. Output capacity <= 1048576.
 * Scratch capacity [102400, 1048576]. Any extra scratch tail is untouched.
 * Nonzero high result word is an outer foreign ABI refusal; otherwise the
 * low word is WAO1 byte count, 0xffffffff malformed or 0xfffffffe capacity.
 * Refusals do not write valid output; success preserves its unused suffix.
 * The HIA runtime has no file, journal-lock, query or production authority.
 */
uint64_t trnm_worker_journal_audit_export_v3(
    const uint8_t *snapshot, size_t snapshot_bytes,
    uint8_t *output, size_t output_capacity,
    uint8_t *scratch, size_t scratch_capacity);
#endif
