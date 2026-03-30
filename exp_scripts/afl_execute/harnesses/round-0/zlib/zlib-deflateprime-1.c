#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Need at least 10 bytes for scenario, bits, value, and extra data. */
    if (size < 10) {
        return 0;
    }

    /* Limit input size to avoid excessive memory usage. */
    static const size_t kMaxSize = 1024 * 1024;
    if (size > kMaxSize) {
        return 0;
    }

    /* First byte: scenario selector (0-7). */
    unsigned int scenario = data[0] % 8;
    /* Second byte: bits as raw int8_t (may be negative or >16). */
    int bits = (int8_t)data[1];
    /* Next four bytes: value as 32-bit integer. */
    int value = (data[2] << 24) | (data[3] << 16) | (data[4] << 8) | data[5];

    z_stream strm;
    int ret;
    size_t data_offset = 6;

    /* Scenario 2: invalid stream (zeroed). */
    if (scenario == 2) {
        memset(&strm, 0, sizeof(strm));
        (void)deflatePrime(&strm, bits, value);
        return 0;
    }

    /* For scenarios 0,1,3,4,5,6,7: initialize a valid raw deflate stream. */
    memset(&strm, 0, sizeof(strm));
    ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        return 0;
    }

    if (scenario == 1) {
        /* Feed some data to deflate to change state and possibly fill buffer. */
        size_t deflate_len = size - data_offset;
        if (deflate_len > 0) {
            /* Provide input and output buffers. */
            strm.next_in = (Bytef *)data + data_offset;
            strm.avail_in = deflate_len;
            /* Allocate output buffer for compressed data. */
            size_t out_len = deflate_len;  /* May be too small, but okay for fuzzing. */
            Bytef *out_buf = (Bytef *)malloc(out_len);
            if (out_buf) {
                strm.next_out = out_buf;
                strm.avail_out = out_len;
                (void)deflate(&strm, Z_NO_FLUSH);
                free(out_buf);
            }
            data_offset += deflate_len;
        }
    } else if (scenario == 3) {
        /* End the stream immediately, making it invalid. */
        deflateEnd(&strm);
        (void)deflatePrime(&strm, bits, value);
        return 0;
    } else if (scenario == 4) {
        /* Reset the stream. */
        ret = deflateReset(&strm);
        if (ret != Z_OK) {
            deflateEnd(&strm);
            return 0;
        }
    } else if (scenario == 5) {
        /* Attempt to fill the pending buffer by compressing with a tiny output buffer. */
        /* Use a 1-byte output buffer to force data to stay in pending buffer. */
        Bytef out_byte;
        while (data_offset < size) {
            strm.next_in = (Bytef *)data + data_offset;
            strm.avail_in = 1;
            strm.next_out = &out_byte;
            strm.avail_out = 1;
            ret = deflate(&strm, Z_NO_FLUSH);
            if (ret == Z_STREAM_ERROR || ret == Z_BUF_ERROR) {
                break;
            }
            data_offset++;
            /* If the output buffer was not consumed, break to avoid infinite loop. */
            if (strm.avail_out == 1) {
                break;
            }
        }
        /* Now pending buffer may be full; call deflatePrime. */
    } else if (scenario == 6) {
        /* Multiple deflatePrime calls. Use each subsequent byte pair for bits and value. */
        int i;
        for (i = 0; data_offset + 1 < size && i < 10; i++) {
            int b = (int8_t)data[data_offset];
            int v = data[data_offset + 1];
            (void)deflatePrime(&strm, b, v);
            data_offset += 2;
        }
        /* Then call with the original bits and value. */
        (void)deflatePrime(&strm, bits, value);
        deflateEnd(&strm);
        return 0;
    } else if (scenario == 7) {
        /* Test edge cases: bits = 0, bits = 16, extreme value. */
        (void)deflatePrime(&strm, 0, 0);
        (void)deflatePrime(&strm, 16, 0xFFFF);
        (void)deflatePrime(&strm, bits, value);
        deflateEnd(&strm);
        return 0;
    }

    /* Call deflatePrime with the given bits and value. */
    ret = deflatePrime(&strm, bits, value);

    /* Optionally call deflatePrime again with different parameters to test loop. */
    if (ret == Z_OK && size - data_offset >= 2) {
        int bits2 = (int8_t)data[data_offset];
        int value2 = data[data_offset + 1];
        (void)deflatePrime(&strm, bits2, value2);
    }

    /* Clean up. */
    deflateEnd(&strm);

    return 0;
}