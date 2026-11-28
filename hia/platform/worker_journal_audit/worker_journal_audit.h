#ifndef TRNM_WORKER_JOURNAL_AUDIT_V1_H
#define TRNM_WORKER_JOURNAL_AUDIT_V1_H
#include <stddef.h>
#include <stdint.h>

/* Linux x86-64 LP64; synchronous, live and mutually disjoint regions.
 * Snapshot: WQX1 raw bytes, at most 65536. Output: at most 1048576.
 * Caller scratch: at least 102400, at most 1048576; its tail is unchanged.
 * The high result word is the outer foreign-buffer status. With high word
 * zero, the low word is the complete WAO1 byte count, 0xffffffff for
 * malformed data, or 0xfffffffe for a capacity or profile-size refusal.
 * Valid regions preserve all output on refusal and the unused tail on
 * success. Input is never written. No filesystem or production dispatch.
 */
uint64_t trnm_worker_journal_audit_export_v1(
    const uint8_t *snapshot, size_t snapshot_bytes,
    uint8_t *output, size_t output_capacity,
    uint8_t *scratch, size_t scratch_bytes);
#endif
