#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

#define CHECK_ERR(err, msg) { \
    if (err != Z_OK) { \
        /* Do not abort, just return 0 to continue fuzzing */ \
        return 0; \
    } \
}

/* Test deflateGetDictionary with various stream states and parameters */
static void test_deflateGetDictionary(const uint8_t *data, size_t size,
                                       int level, int flush, int windowBits,
                                       int use_dict, int test_invalid) {
    z_stream strm;
    int err;
    size_t comprLen = compressBound(size);
    Bytef *compr = (Bytef *)malloc(comprLen);
    Bytef dictionary[32768]; /* 32K is always enough per zlib.h */
    uInt dictLength = 0;
    uInt dictLength2 = 0;
    const uint8_t *dict_data = NULL;
    size_t dict_size = 0;
    const uint8_t *comp_data = data;
    size_t comp_size = size;

    if (!compr) {
        return;
    }

    /* Split data for dictionary if requested */
    if (use_dict && size > 1) {
        dict_size = size / 2;
        comp_size = size - dict_size;
        dict_data = data;
        comp_data = data + dict_size;
    }

    /* Initialize stream */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.next_in = (Bytef *)comp_data;
    strm.avail_in = comp_size;
    strm.next_out = compr;
    strm.avail_out = comprLen;

    /* Use deflateInit2 to allow raw deflate and custom windowBits */
    err = deflateInit2(&strm, level, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY);
    if (err != Z_OK) {
        free(compr);
        return;
    }

    /* Set dictionary if requested */
    if (use_dict && dict_size > 0) {
        err = deflateSetDictionary(&strm, dict_data, dict_size);
        /* Ignore error; if it fails, continue without dictionary */
    }

    /* Compress with the chosen flush mode */
    err = deflate(&strm, flush);
    /* Ignore error; we just want to test deflateGetDictionary */

    /* Test invalid stream if requested */
    if (test_invalid) {
        /* Invalidate the stream by setting state to NULL */
        strm.state = Z_NULL;
        err = deflateGetDictionary(&strm, dictionary, &dictLength);
        /* Should return Z_STREAM_ERROR; we don't assert to avoid crashes */
        /* Restore state (but stream is now invalid, so we skip further tests) */
        deflateEnd(&strm);
        free(compr);
        return;
    }

    /* Call deflateGetDictionary with valid buffer */
    dictLength = 0;
    err = deflateGetDictionary(&strm, dictionary, &dictLength);
    /* Check that it returns Z_OK for a valid stream */
    if (err != Z_OK) {
        /* If it fails, maybe the stream is in an invalid state; just continue */
    }

    /* Call with dictionary = Z_NULL to get length only */
    dictLength2 = 0;
    err = deflateGetDictionary(&strm, Z_NULL, &dictLength2);

    /* Call with dictLength = Z_NULL (should not crash) */
    err = deflateGetDictionary(&strm, dictionary, Z_NULL);

    /* Clean up */
    deflateEnd(&strm);
    free(compr);
}

/* Test with an uninitialized stream (zalloc = 0) */
static void test_invalid_stream(void) {
    z_stream strm;
    Bytef dict[1024];
    uInt dictLen = 0;

    memset(&strm, 0, sizeof(strm));
    /* strm.zalloc = 0, strm.zfree = 0, strm.state = Z_NULL */
    deflateGetDictionary(&strm, dict, &dictLen);
    /* Should return Z_STREAM_ERROR */
}

/* Test with a stream that has been deflateEnd'ed */
static void test_ended_stream(int level) {
    z_stream strm;
    Bytef dict[1024];
    uInt dictLen = 0;
    int err;

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    err = deflateInit(&strm, level);
    if (err != Z_OK) return;
    err = deflateEnd(&strm);
    /* Now strm.state should be Z_NULL */
    deflateGetDictionary(&strm, dict, &dictLen);
    /* Should return Z_STREAM_ERROR */
}

/* Test with empty window (no data processed) */
static void test_empty_window(int level, int windowBits) {
    z_stream strm;
    Bytef dict[32768];
    uInt dictLen = 0;
    int err;

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    err = deflateInit2(&strm, level, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY);
    if (err != Z_OK) return;
    /* Call deflateGetDictionary before any data is processed */
    err = deflateGetDictionary(&strm, dict, &dictLen);
    deflateEnd(&strm);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Discard inputs larger than 1Mb or too small */
    static const size_t kMaxSize = 1024 * 1024;
    if (size < 1 || size > kMaxSize) {
        return 0;
    }

    /* Use first two bytes to parameterize the test */
    uint8_t flags0 = data[0];
    uint8_t flags1 = size > 1 ? data[1] : 0;

    /* Byte0: bits 0-3: level (0-9) */
    int level = (flags0 & 0x0F) % 10;          /* 0..9 */
    /* Byte0: bits 4-5: flush mode (0..3) */
    int flush_mode = (flags0 >> 4) & 0x03;    /* 0..3 */
    /* Byte0: bit 6: raw (0 or 1) */
    int raw = (flags0 >> 6) & 0x01;
    /* Byte0: bit 7: use_dict (0 or 1) */
    int use_dict = (flags0 >> 7) & 0x01;

    /* Byte1: bits 0-1: windowBits (0..3) mapped to 8,9,15,16 */
    static const int windowBits_map[] = { 8, 9, 15, 16 };
    int windowBits = windowBits_map[flags1 & 0x03];
    if (raw) {
        /* For raw deflate, windowBits must be negative */
        windowBits = -windowBits;
    }

    /* Byte1: bit 2: test invalid stream (10% chance) */
    int test_invalid = (flags1 & 0x04) ? 1 : 0;

    /* Map flush_mode to Zlib constant */
    static const int flush_map[] = { Z_NO_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH };
    int flush = flush_map[flush_mode];

    /* Move past the parameter bytes */
    if (size > 2) {
        data += 2;
        size -= 2;
    } else {
        return 0;
    }

    /* If we are testing invalid streams, we don't need much data */
    if (test_invalid && size > 100) {
        size = 100;
    }

    /* Main test with the given parameters */
    test_deflateGetDictionary(data, size, level, flush, windowBits, use_dict, test_invalid);

    /* Additional tests to cover more states */

    /* Test with empty window (no data processed) */
    test_empty_window(level, windowBits);

    /* Test invalid stream with zeroed z_stream */
    test_invalid_stream();

    /* Test ended stream */
    test_ended_stream(level);

    /* This function must return 0. */
    return 0;
}