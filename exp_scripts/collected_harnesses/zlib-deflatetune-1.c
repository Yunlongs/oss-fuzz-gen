#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

/* Helper to compress data with small buffers and a given flush mode */
static void test_compress_with_tuned_params(z_stream *strm,
                                            const uint8_t *data,
                                            size_t dataLen,
                                            uint8_t *compr,
                                            size_t comprLen,
                                            int flush) {
    int err;
    unsigned long len = dataLen;

    strm->next_in = (Bytef *)data;
    strm->next_out = compr;

    while (strm->total_in != len && strm->total_out < comprLen) {
        strm->avail_in = strm->avail_out = 1; /* force small buffers */
        err = deflate(strm, Z_NO_FLUSH);
        if (err != Z_OK) break;
    }
    if (flush == Z_FINISH) {
        for (;;) {
            strm->avail_out = 1;
            err = deflate(strm, Z_FINISH);
            if (err == Z_STREAM_END) break;
            if (err != Z_OK) break;
        }
    } else {
        /* For other flush modes, just do one step */
        strm->avail_in = 0;
        strm->avail_out = comprLen - strm->total_out;
        err = deflate(strm, flush);
    }
}

/* Helper to decompress using uncompress (simpler) */
static void test_decompress_simple(uint8_t *compr, size_t comprLen,
                                   const uint8_t *expected, size_t expectedLen) {
    uint8_t *uncompr = (uint8_t *)malloc(expectedLen);
    if (uncompr == NULL) return;
    uLongf uncomprLen = expectedLen;
    int err = uncompress(uncompr, &uncomprLen, compr, comprLen);
    if (err == Z_OK) {
        /* Verify only if decompression succeeded */
        assert(uncomprLen == expectedLen);
        assert(memcmp(uncompr, expected, expectedLen) == 0);
    }
    free(uncompr);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* We need at least 17 bytes: 1 byte for mode and 16 for four ints */
    if (size < 17) {
        return 0;
    }

    /* Discard large inputs to avoid timeouts */
    static size_t kMaxSize = 1024 * 1024;
    if (size > kMaxSize) {
        return 0;
    }

    uint8_t mode = data[0] % 3;  /* 0,1,2 */
    data++; size--;

    /* Extract four integers and bound them to reasonable ranges */
    int good_length, max_lazy, nice_length, max_chain;
    memcpy(&good_length, data, 4);
    memcpy(&max_lazy, data + 4, 4);
    memcpy(&nice_length, data + 8, 4);
    memcpy(&max_chain, data + 12, 4);
    data += 16; size -= 16;

    /* Bound the parameters to avoid extreme values that cause timeouts */
    good_length = good_length & 0xFF;        /* 0..255 */
    max_lazy = max_lazy & 0xFF;              /* 0..255 */
    nice_length = (nice_length & 0xFF) + 1;  /* 1..256 */
    max_chain = (max_chain & 0xFFF) + 1;     /* 1..4096 */

    const uint8_t *dataToCompress = data;
    size_t dataLen = size;

    if (mode == 0) {
        /* Valid stream: initialize, tune, compress, optionally decompress */
        z_stream strm;
        int err;
        size_t comprLen;

        /* Determine compression level and flush mode from input */
        int level = Z_DEFAULT_COMPRESSION;
        int flush = Z_FINISH;
        if (dataLen > 0) {
            level = dataToCompress[0] % 11;  /* 0..9, 10 -> default */
            if (level == 10) level = Z_DEFAULT_COMPRESSION;
            flush = (dataToCompress[0] >> 4) & 3;  /* 0..3 */
            if (flush == 0) flush = Z_NO_FLUSH;
            else if (flush == 1) flush = Z_SYNC_FLUSH;
            else if (flush == 2) flush = Z_FULL_FLUSH;
            else flush = Z_FINISH;
            dataToCompress++; dataLen--;
        }

        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;

        err = deflateInit(&strm, level);
        if (err != Z_OK) {
            return 0;
        }

        /* Call the function under test */
        err = deflateTune(&strm, good_length, max_lazy, nice_length, max_chain);
        /* Ignore return value for fuzzing */

        comprLen = compressBound(dataLen);
        uint8_t *compr = (uint8_t *)malloc(comprLen);
        if (compr == NULL) {
            deflateEnd(&strm);
            return 0;
        }

        deflateReset(&strm);
        test_compress_with_tuned_params(&strm, dataToCompress, dataLen,
                                        compr, comprLen, flush);

        /* Optionally decompress if we have enough data and flush is Z_FINISH */
        if (flush == Z_FINISH && strm.total_out > 0) {
            test_decompress_simple(compr, strm.total_out,
                                   dataToCompress, dataLen);
        }

        free(compr);
        deflateEnd(&strm);
    } else if (mode == 1) {
        /* Invalid stream: NULL pointer */
        deflateTune(NULL, good_length, max_lazy, nice_length, max_chain);
    } else if (mode == 2) {
        /* Invalid stream: state = NULL */
        z_stream strm;
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        strm.state = NULL;
        deflateTune(&strm, good_length, max_lazy, nice_length, max_chain);
    }

    /* This function must return 0. */
    return 0;
}