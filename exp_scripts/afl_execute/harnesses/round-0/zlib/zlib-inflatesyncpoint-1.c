#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static size_t kMaxSize = 1024 * 1024;
    if (size < 1 || size > kMaxSize)
        return 0;

    uint8_t scenario = data[0];
    const uint8_t *input_data = data + 1;
    size_t input_size = size - 1;

    /* Error scenario: test invalid streams */
    if (scenario & 0x80) {
        if (scenario & 0x40) {
            /* Test NULL stream pointer */
            (void)inflateSyncPoint(NULL);
            return 0;
        } else if (scenario & 0x20) {
            /* Test state->strm != strm by swapping states between two streams */
            z_stream strm1, strm2;
            memset(&strm1, 0, sizeof(strm1));
            memset(&strm2, 0, sizeof(strm2));
            strm1.zalloc = NULL;
            strm1.zfree = NULL;
            strm2.zalloc = NULL;
            strm2.zfree = NULL;
            if (inflateInit2(&strm1, -15) == Z_OK &&
                inflateInit2(&strm2, -15) == Z_OK) {
                /* Swap the states */
                void *tmp = strm1.state;
                strm1.state = strm2.state;
                strm2.state = tmp;
                /* Now strm1.state->strm points to strm2, and vice versa */
                (void)inflateSyncPoint(&strm1);
                (void)inflateSyncPoint(&strm2);
                /* Restore states and end */
                tmp = strm1.state;
                strm1.state = strm2.state;
                strm2.state = tmp;
                inflateEnd(&strm1);
                inflateEnd(&strm2);
            }
            return 0;
        } else {
            /* Original error scenarios: NULL allocators or NULL state */
            z_stream strm;
            memset(&strm, 0, sizeof(strm));
            if (scenario & 0x10) {
                /* Set zalloc and zfree to NULL */
                strm.zalloc = NULL;
                strm.zfree = NULL;
            } else {
                /* Set them to non-NULL but state to NULL */
                strm.zalloc = (alloc_func)0x1;
                strm.zfree = (free_func)0x1;
                strm.state = NULL;
            }
            (void)inflateSyncPoint(&strm);
            return 0;
        }
    }

    /* Valid scenario: inflate the input */
    if (input_size == 0)
        return 0;

    int windowBits = (scenario & 0x20) ? 15 : -15;  /* raw or zlib */
    int flush = Z_NO_FLUSH;
    if (scenario & 0x10)
        flush = Z_SYNC_FLUSH;
    if (scenario & 0x08)
        flush = Z_FINISH;

    /* Decide whether to use manual uncompressed block or raw deflate stream */
    if (scenario & 0x04) {
        /* Manual uncompressed block - use raw inflate only */
        windowBits = -15;
        /* Limit data size to 65535 for stored block length */
        size_t data_len = input_size;
        if (data_len > 65535)
            data_len = 65535;

        /* Build an uncompressed deflate block (final, type 00) */
        size_t block_len = 5 + data_len; /* 1 byte header, 4 bytes length, data */
        uint8_t *block = (uint8_t *)malloc(block_len);
        if (!block) return 0;

        /* Block header: final bit = 1, type = 00 -> bits = 0b001, padded to byte */
        block[0] = 0x01; /* 00000 001 in bits: the 3 bits are 001 (final, type 00), rest are zero padding */
        /* Length and ~length (little-endian) */
        uint16_t len = (uint16_t)data_len;
        block[1] = (uint8_t)(len & 0xFF);
        block[2] = (uint8_t)(len >> 8);
        block[3] = (uint8_t)(~len & 0xFF);
        block[4] = (uint8_t)(~len >> 8);
        /* Copy data */
        memcpy(block + 5, input_data, data_len);

        /* Inflate this block */
        z_stream strm;
        strm.zalloc = NULL;
        strm.zfree = NULL;
        strm.opaque = NULL;
        strm.next_in = block;
        strm.avail_in = block_len;
        strm.next_out = NULL;
        strm.avail_out = 0;

        int err = inflateInit2(&strm, windowBits);
        if (err != Z_OK) {
            free(block);
            return 0;
        }

        /* Call inflateSyncPoint right after init */
        (void)inflateSyncPoint(&strm);

        /* Inflate in 1-byte chunks, calling inflateSyncPoint after each chunk */
        uint8_t out[1024];
        strm.next_out = out;
        strm.avail_out = sizeof(out);

        while (strm.total_in < block_len && strm.total_out < sizeof(out)) {
            strm.avail_in = 1;
            strm.avail_out = 1;
            err = inflate(&strm, flush);
            if (err == Z_STREAM_END)
                break;
            if (err != Z_OK && err != Z_BUF_ERROR) {
                /* Call inflateSyncPoint after an error */
                (void)inflateSyncPoint(&strm);
                break;
            }
            (void)inflateSyncPoint(&strm);
        }

        /* Call inflateSyncPoint one more time at the end */
        (void)inflateSyncPoint(&strm);

        inflateEnd(&strm);
        free(block);
    } else {
        /* Original method: treat input as raw deflate stream */
        z_stream strm;
        strm.zalloc = NULL;
        strm.zfree = NULL;
        strm.opaque = NULL;
        strm.next_in = (Bytef *)input_data;
        strm.avail_in = input_size;
        strm.next_out = NULL;
        strm.avail_out = 0;

        int err = inflateInit2(&strm, windowBits);
        if (err != Z_OK)
            return 0;

        /* Optionally prime the bit buffer */
        if (scenario & 0x02) {
            if (input_size >= 3) {
                int bits = input_data[0] % 17;
                int value = input_data[1];
                (void)inflatePrime(&strm, bits, value);
            }
        }

        /* Call inflateSyncPoint right after init */
        (void)inflateSyncPoint(&strm);

        /* Inflate in small chunks, calling inflateSyncPoint frequently */
        uint8_t out[1024];
        strm.next_out = out;
        strm.avail_out = sizeof(out);

        while (strm.total_in < input_size && strm.total_out < sizeof(out)) {
            strm.avail_in = 1;
            strm.avail_out = 1;
            err = inflate(&strm, flush);
            if (err == Z_STREAM_END)
                break;
            if (err != Z_OK && err != Z_BUF_ERROR) {
                /* Call inflateSyncPoint after an error */
                (void)inflateSyncPoint(&strm);
                /* Try to recover with inflateSync */
                (void)inflateSync(&strm);
                (void)inflateSyncPoint(&strm);
                break;
            }
            (void)inflateSyncPoint(&strm);
        }

        /* Call inflateSyncPoint one more time at the end */
        (void)inflateSyncPoint(&strm);

        inflateEnd(&strm);
    }

    return 0;
}