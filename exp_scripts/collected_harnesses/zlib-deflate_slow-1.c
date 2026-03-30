#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"
#include "deflate.h"

/* Define block_state as in deflate.c */
typedef enum {
    need_more,      /* block not completed, need more input or more output */
    block_done,     /* block flush performed */
    finish_started, /* finish started, need only more output at next deflate */
    finish_done     /* finish done, accept no more input or output */
} block_state;

/* Forward declaration of deflate_slow, which we will call after patching deflate.c */
block_state deflate_slow(deflate_state *s, int flush);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Need at least 4 bytes for parameters and some data */
    if (size < 4) {
        return 0;
    }

    /* Extract parameters from the first four bytes */
    int level = (data[0] % 6) + 4;          /* levels 4–9 use deflate_slow */
    int strategy = data[1] % 5;             /* 0: default, 1: filtered, 2: huffman, 3: rle, 4: fixed */
    unsigned out_buf_size = (data[2] % 4096) + 1;  /* output buffer size 1..4096 */
    unsigned num_flush = data[3] % 16;      /* number of flush commands (0..15) */

    /* Map strategy to Zlib constants */
    static const int strategy_map[] = {
        Z_DEFAULT_STRATEGY,
        Z_FILTERED,
        Z_HUFFMAN_ONLY,
        Z_RLE,
        Z_FIXED
    };
    strategy = strategy_map[strategy];

    /* Map flush to Zlib constants */
    static const int flush_map[] = {
        Z_NO_FLUSH,
        Z_PARTIAL_FLUSH,
        Z_SYNC_FLUSH,
        Z_FULL_FLUSH,
        Z_FINISH,
        Z_BLOCK
    };

    /* Determine the position of flush commands and input data */
    size_t flush_start = 4;
    size_t data_start = flush_start + num_flush;
    if (data_start > size) {
        return 0;
    }

    /* Use the remaining bytes as input data */
    const uint8_t *input = data + data_start;
    size_t input_len = size - data_start;
    if (input_len < 300) {
        return 0;
    }

    /* Create a buffer with repetitive pattern to increase match chances.
       Use the first 3 bytes of the input as a pattern. */
    uint8_t *patterned_input = (uint8_t*)malloc(input_len);
    if (!patterned_input) {
        return 0;
    }
    uint8_t pattern[3];
    if (input_len >= 3) {
        memcpy(pattern, input, 3);
    } else {
        pattern[0] = pattern[1] = pattern[2] = 0;
    }
    for (size_t i = 0; i < input_len; i++) {
        patterned_input[i] = pattern[i % 3];
    }
    /* But also keep the original data in the first part to avoid being completely uniform */
    size_t copy_len = input_len < 1024 ? input_len : 1024;
    memcpy(patterned_input, input, copy_len);

    /* Initialize zlib stream with the selected level and strategy */
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    if (deflateInit2(&strm, level, Z_DEFLATED, MAX_WBITS, 8, strategy) != Z_OK) {
        free(patterned_input);
        return 0;
    }

    /* Allocate output buffer */
    uint8_t *out_buf = (uint8_t*)malloc(out_buf_size);
    if (!out_buf) {
        deflateEnd(&strm);
        free(patterned_input);
        return 0;
    }

    /* Provide the patterned input to the stream */
    strm.next_in = patterned_input;
    strm.avail_in = (uInt)input_len;
    strm.next_out = out_buf;
    strm.avail_out = (uInt)out_buf_size;

    /* Process each flush command in sequence */
    for (unsigned i = 0; i < num_flush; ++i) {
        int flush = flush_map[data[flush_start + i] % 6];
        int err = deflate(&strm, flush);
        if (err == Z_STREAM_END) {
            break;
        }
        if (err != Z_OK && err != Z_BUF_ERROR) {
            /* Ignore errors; we are fuzzing, not producing valid output */
            break;
        }
        /* If the output buffer is full, reset it to continue */
        if (strm.avail_out == 0) {
            strm.next_out = out_buf;
            strm.avail_out = (uInt)out_buf_size;
        }
        /* If no input left, break */
        if (strm.avail_in == 0) {
            break;
        }
    }

    /* Now call deflate_slow directly to cover its code paths.
       The state is already primed by the previous deflate calls. */
    deflate_state *s = (deflate_state*)strm.state;
    if (s != NULL) {
        /* Use a flush command derived from the last byte of the flush sequence (or Z_NO_FLUSH) */
        int flush = num_flush > 0 ? flush_map[data[flush_start + num_flush - 1] % 6] : Z_NO_FLUSH;
        block_state result = deflate_slow(s, flush);
        (void)result;
    }

    /* Clean up */
    deflateEnd(&strm);
    free(out_buf);
    free(patterned_input);

    return 0;
}