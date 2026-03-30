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
        } else if (scenario & 0x10) {
            /* Cause BAD mode by feeding an invalid block type (type 3) */
            uint8_t invalid_block[] = {0xE0}; /* final=1, type=3, rest zero padding */
            z_stream strm;
            strm.zalloc = NULL;
            strm.zfree = NULL;
            strm.opaque = NULL;
            strm.next_in = invalid_block;
            strm.avail_in = sizeof(invalid_block);
            strm.next_out = NULL;
            strm.avail_out = 0;
            if (inflateInit2(&strm, -15) == Z_OK) {
                (void)inflate(&strm, Z_NO_FLUSH); /* This should set state->mode to BAD */
                (void)inflateSyncPoint(&strm);
                inflateEnd(&strm);
            }
            return 0;
        } else if (scenario & 0x08) {
            /* Cause BAD mode by feeding an uncompressed block with invalid length */
            if (input_size >= 2) {
                uint16_t len = (input_data[0] << 8) | input_data[1];
                uint16_t nlen = ~len;
                /* Build an uncompressed block with correct length but wrong ~length */
                uint8_t block[5];
                block[0] = 0x01; /* final, type 00 */
                block[1] = (uint8_t)(len & 0xFF);
                block[2] = (uint8_t)(len >> 8);
                block[3] = (uint8_t)(nlen & 0xFF);
                block[4] = (uint8_t)(nlen >> 8);
                /* Flip one byte of nlen to make it invalid */
                block[3] ^= 0x01;
                z_stream strm;
                strm.zalloc = NULL;
                strm.zfree = NULL;
                strm.opaque = NULL;
                strm.next_in = block;
                strm.avail_in = sizeof(block);
                strm.next_out = NULL;
                strm.avail_out = 0;
                if (inflateInit2(&strm, -15) == Z_OK) {
                    (void)inflate(&strm, Z_NO_FLUSH); /* This should set state->mode to BAD */
                    (void)inflateSyncPoint(&strm);
                    inflateEnd(&strm);
                }
            }
            return 0;
        } else {
            /* Original error scenario: zeroed stream */
            z_stream strm;
            memset(&strm, 0, sizeof(strm));
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

    if (scenario & 0x04) {
        /* Manual uncompressed block to hit the true condition */
        windowBits = -15; /* raw deflate required for manual block */
        /* Limit data size to 65535 */
        size_t data_len = input_size;
        if (data_len > 65535)
            data_len = 65535;

        /* Build an uncompressed deflate block (final, type 00) */
        size_t block_len = 5 + data_len;
        uint8_t *block = (uint8_t *)malloc(block_len);
        if (!block) return 0;

        /* Block header: final bit = 1, type = 00 -> 0b001 */
        block[0] = 0x01;
        uint16_t len = (uint16_t)data_len;
        block[1] = (uint8_t)(len & 0xFF);
        block[2] = (uint8_t)(len >> 8);
        block[3] = (uint8_t)(~len & 0xFF);
        block[4] = (uint8_t)(~len >> 8);
        memcpy(block + 5, input_data, data_len);

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

        /* Feed the first byte (block header) */
        strm.avail_in = 1;
        err = inflate(&strm, flush);
        /* Now call inflate with no input to let it go to STORED and BYTEBITS() */
        strm.avail_in = 0;
        err = inflate(&strm, flush);
        /* At this point, state->mode should be STORED and state->bits == 0 */
        (void)inflateSyncPoint(&strm);

        /* Continue with the rest of the block */
        uint8_t out[1024];
        strm.next_out = out;
        strm.avail_out = sizeof(out);
        while (strm.total_in < block_len && strm.total_out < sizeof(out)) {
            strm.avail_in = 1;
            strm.avail_out = 1;
            err = inflate(&strm, flush);
            if (err == Z_STREAM_END)
                break;
            if (err != Z_OK && err != Z_BUF_ERROR)
                break;
            (void)inflateSyncPoint(&strm);
        }

        (void)inflateSyncPoint(&strm);
        inflateEnd(&strm);
        free(block);
    } else {
        /* Original method: compress and inflate */
        size_t comprLen = compressBound(input_size);
        uint8_t *compr = (uint8_t *)malloc(comprLen);
        if (compr == NULL) return 0;

        z_stream c_stream;
        c_stream.zalloc = NULL;
        c_stream.zfree = NULL;
        c_stream.opaque = NULL;

        int err = deflateInit(&c_stream, Z_DEFAULT_COMPRESSION);
        if (err != Z_OK) {
            free(compr);
            return 0;
        }

        c_stream.next_in = (Bytef *)input_data;
        c_stream.avail_in = input_size;
        c_stream.next_out = compr;
        c_stream.avail_out = comprLen;

        err = deflate(&c_stream, Z_FINISH);
        if (err != Z_STREAM_END) {
            deflateEnd(&c_stream);
            free(compr);
            return 0;
        }
        size_t actual_comprLen = c_stream.total_out;
        deflateEnd(&c_stream);

        z_stream strm;
        strm.zalloc = NULL;
        strm.zfree = NULL;
        strm.opaque = NULL;
        strm.next_in = compr;
        strm.avail_in = actual_comprLen;

        err = inflateInit2(&strm, windowBits);
        if (err != Z_OK) {
            free(compr);
            return 0;
        }

        (void)inflateSyncPoint(&strm);

        uint8_t out[1024];
        strm.next_out = out;
        strm.avail_out = sizeof(out);

        while (strm.total_in < actual_comprLen && strm.total_out < sizeof(out)) {
            strm.avail_in = 1;
            strm.avail_out = 1;
            err = inflate(&strm, flush);
            if (err == Z_STREAM_END)
                break;
            if (err != Z_OK && err != Z_BUF_ERROR)
                break;
            (void)inflateSyncPoint(&strm);
        }

        (void)inflateSyncPoint(&strm);
        inflateEnd(&strm);
        free(compr);
    }

    return 0;
}