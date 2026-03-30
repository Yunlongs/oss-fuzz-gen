#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

/* ===========================================================================
 * Test deflate() with small buffers, using Z_HUFFMAN_ONLY to encourage dynamic blocks.
 */
static int test_deflate(const uint8_t *data, size_t dataLen, unsigned char *compr, size_t comprLen) {
    z_stream c_stream;
    int err;
    unsigned long len = dataLen;

    c_stream.zalloc = NULL;
    c_stream.zfree = NULL;
    c_stream.opaque = (void *)0;

    /* Use deflateInit2 with Z_HUFFMAN_ONLY and low memory to force dynamic blocks */
    err = deflateInit2(&c_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, MAX_WBITS, 1, Z_HUFFMAN_ONLY);
    if (err != Z_OK) {
        return err;
    }

    c_stream.next_in = (Bytef *)data;
    c_stream.next_out = compr;

    while (c_stream.total_in != len && c_stream.total_out < comprLen) {
        c_stream.avail_in = c_stream.avail_out = 1;
        err = deflate(&c_stream, Z_NO_FLUSH);
        if (err != Z_OK) {
            deflateEnd(&c_stream);
            return err;
        }
    }

    for (;;) {
        c_stream.avail_out = 1;
        err = deflate(&c_stream, Z_FINISH);
        if (err == Z_STREAM_END)
            break;
        if (err != Z_OK) {
            deflateEnd(&c_stream);
            return err;
        }
    }

    err = deflateEnd(&c_stream);
    return err;
}

/* ===========================================================================
 * Test inflate() with small buffers and call inflateCodesUsed at various points.
 */
static void test_inflate_with_codes_used(const uint8_t *data, size_t dataLen,
                                         unsigned char *compr, size_t comprLen,
                                         unsigned char *uncompr, size_t uncomprLen) {
    int err;
    z_stream d_stream;
    unsigned long codes_used;

    d_stream.zalloc = NULL;
    d_stream.zfree = NULL;
    d_stream.opaque = (void *)0;

    d_stream.next_in = compr;
    d_stream.avail_in = 0;
    d_stream.next_out = uncompr;

    err = inflateInit(&d_stream);
    if (err != Z_OK) {
        return;
    }

    /* Call inflateCodesUsed right after init (should be 0) */
    codes_used = inflateCodesUsed(&d_stream);

    while (d_stream.total_out < uncomprLen && d_stream.total_in < comprLen) {
        d_stream.avail_in = d_stream.avail_out = 1;
        err = inflate(&d_stream, Z_NO_FLUSH);
        if (err == Z_STREAM_END)
            break;
        if (err != Z_OK) {
            /* Error encountered: call inflateCodesUsed in error state */
            codes_used = inflateCodesUsed(&d_stream);
            break;
        }
        /* Optionally call inflateCodesUsed during decompression */
        codes_used = inflateCodesUsed(&d_stream);
    }

    /* Final call after decompression (or after error break) */
    codes_used = inflateCodesUsed(&d_stream);

    inflateEnd(&d_stream);
}

/* ===========================================================================
 * Additional test: inflate raw fuzz input (without prior compression) to trigger errors.
 */
static void test_raw_inflate(const uint8_t *data, size_t size) {
    z_stream stream;
    unsigned char out[1024];
    unsigned long codes_used;

    stream.zalloc = NULL;
    stream.zfree = NULL;
    stream.opaque = (void *)0;
    stream.next_in = (Bytef *)data;
    stream.avail_in = size;
    stream.next_out = out;
    stream.avail_out = sizeof(out);

    /* Use negative window bits to handle raw deflate data */
    if (inflateInit2(&stream, -MAX_WBITS) != Z_OK)
        return;

    int err = inflate(&stream, Z_FINISH);
    codes_used = inflateCodesUsed(&stream);

    inflateEnd(&stream);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    size_t comprLen;
    size_t uncomprLen = size;
    uint8_t *compr, *uncompr;

    /* Discard inputs larger than 1Mb. */
    static size_t kMaxSize = 1024 * 1024;
    if (size < 1 || size > kMaxSize)
        return 0;

    /* Allocate buffers */
    comprLen = compressBound(size);
    compr = (uint8_t *)calloc(1, comprLen);
    uncompr = (uint8_t *)calloc(1, uncomprLen);
    if (!compr || !uncompr) {
        free(compr);
        free(uncompr);
        return 0;
    }

    /* Test 1: Normal compression/decompression with dynamic blocks */
    if (test_deflate(data, size, compr, comprLen) == Z_OK) {
        test_inflate_with_codes_used(data, size, compr, comprLen, uncompr, uncomprLen);
    }

    /* Test 2: Raw inflation of the fuzz input (may trigger errors) */
    test_raw_inflate(data, size);

    free(compr);
    free(uncompr);

    /* This function must return 0. */
    return 0;
}