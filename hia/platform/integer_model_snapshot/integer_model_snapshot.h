#ifndef TRNM_INTEGER_MODEL_SNAPSHOT_H
#define TRNM_INTEGER_MODEL_SNAPSHOT_H

#include <stddef.h>
#include <stdint.h>

/* Local snapshot IMD2 only. Buffers are disjoint and valid for the call.
 * Upper 32 bits: foreign ABI status. Lower 32 bits: component status.
 * Outputs: computed ID (32 bytes), then 7756/7758 canonical ILM bytes.
 * Scratch: 9014 bytes; contents not valid model data or a result.
 * Input and output on refusal remain unchanged. No original state effects.
 */
uint64_t trnm_integer_model_snapshot_load_v1(
    const uint8_t *input, size_t input_extent, uint8_t *output, size_t output_extent,
    uint8_t *scratch, size_t scratch_extent
);

#endif
