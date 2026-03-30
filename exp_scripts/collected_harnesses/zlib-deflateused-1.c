#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

/* Helper to consume bytes from the input */
static const uint8_t* consume(const uint8_t* data, size_t size, size_t n, size_t *remaining) {
    if (*remaining < n) {
        *remaining = 0;
        return NULL;
    }
    const uint8_t* ptr = data;
    *remaining -= n;
    return ptr + n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const size_t kMaxSize = 1024 * 1024;
    if (size > kMaxSize || size < 2) {
        return 0;
    }

    size_t remaining = size;
    uint8_t scenario = data[0] % 19;  // 0-18
    data = consume(data, size, 1, &remaining);
    if (data == NULL) return 0;

    z_stream strm;
    int err;
    int bits_used;
    size_t comprLen;
    Bytef *compr = NULL;
    const uint8_t *dict = NULL;
    uInt dictLen = 0;

    switch (scenario) {
        case 0: /* Original: compress with Z_FINISH (zlib) */
            if (remaining == 0) return 0;
            comprLen = compressBound(remaining);
            compr = (Bytef *)malloc(comprLen);
            if (!compr) return 0;

            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = (Bytef *)data;
            strm.avail_in = remaining;
            strm.next_out = compr;
            strm.avail_out = comprLen;

            err = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }

            while (strm.total_in != remaining && strm.total_out < comprLen) {
                strm.avail_in = strm.avail_out = 1;
                err = deflate(&strm, Z_NO_FLUSH);
                if (err != Z_OK) {
                    deflateEnd(&strm);
                    free(compr);
                    return 0;
                }
            }

            for (;;) {
                strm.avail_out = 1;
                err = deflate(&strm, Z_FINISH);
                if (err == Z_STREAM_END) break;
                if (err != Z_OK) {
                    deflateEnd(&strm);
                    free(compr);
                    return 0;
                }
            }

            err = deflateUsed(&strm, &bits_used);
            assert(err == Z_OK);
            assert(bits_used >= 0 && bits_used <= 8);

            err = deflateUsed(&strm, Z_NULL);
            assert(err == Z_OK);

            err = deflateEnd(&strm);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }
            free(compr);
            break;

        case 1: /* Only deflateInit, no compression */
            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = Z_NULL;
            strm.avail_in = 0;
            strm.next_out = Z_NULL;
            strm.avail_out = 0;

            err = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
            if (err != Z_OK) return 0;

            err = deflateUsed(&strm, &bits_used);
            assert(err == Z_OK);
            assert(bits_used >= 0 && bits_used <= 8);

            err = deflateEnd(&strm);
            assert(err == Z_OK);
            break;

        case 2: /* Partial compression with Z_NO_FLUSH, varying parameters */
            if (remaining < 4) return 0;
            {
                int level = data[0] % 10;
                int windowBits = 8 + (data[1] % 8);  // 8..15
                int memLevel = 1 + (data[2] % 9);    // 1..9
                int strategy = data[3] % 4;          // 0: default, 1: filtered, 2: huffman, 3: rle
                data = consume(data, remaining, 4, &remaining);
                if (data == NULL || remaining == 0) return 0;
                comprLen = compressBound(remaining);
                compr = (Bytef *)malloc(comprLen);
                if (!compr) return 0;

                strm.zalloc = Z_NULL;
                strm.zfree = Z_NULL;
                strm.opaque = Z_NULL;
                strm.next_in = (Bytef *)data;
                strm.avail_in = remaining;
                strm.next_out = compr;
                strm.avail_out = comprLen;

                int actual_strategy;
                switch (strategy) {
                    case 0: actual_strategy = Z_DEFAULT_STRATEGY; break;
                    case 1: actual_strategy = Z_FILTERED; break;
                    case 2: actual_strategy = Z_HUFFMAN_ONLY; break;
                    case 3: actual_strategy = Z_RLE; break;
                    default: actual_strategy = Z_DEFAULT_STRATEGY;
                }
                err = deflateInit2(&strm, level, Z_DEFLATED, windowBits, memLevel, actual_strategy);
                if (err != Z_OK) {
                    free(compr);
                    return 0;
                }

                size_t half = remaining / 2;
                if (half == 0) half = 1;
                while (strm.total_in < half && strm.total_out < comprLen) {
                    strm.avail_in = strm.avail_out = 1;
                    err = deflate(&strm, Z_NO_FLUSH);
                    if (err != Z_OK) {
                        deflateEnd(&strm);
                        free(compr);
                        return 0;
                    }
                }

                err = deflateUsed(&strm, &bits_used);
                assert(err == Z_OK);
                assert(bits_used >= 0 && bits_used <= 8);

                err = deflateEnd(&strm);
                if (err != Z_OK) {
                    free(compr);
                    return 0;
                }
                free(compr);
            }
            break;

        case 3: /* Compression with Z_SYNC_FLUSH, varying parameters */
            if (remaining < 4) return 0;
            {
                int level = data[0] % 10;
                int windowBits = 8 + (data[1] % 8);
                int memLevel = 1 + (data[2] % 9);
                int strategy = data[3] % 4;
                data = consume(data, remaining, 4, &remaining);
                if (data == NULL || remaining == 0) return 0;
                comprLen = compressBound(remaining);
                compr = (Bytef *)malloc(comprLen);
                if (!compr) return 0;

                strm.zalloc = Z_NULL;
                strm.zfree = Z_NULL;
                strm.opaque = Z_NULL;
                strm.next_in = (Bytef *)data;
                strm.avail_in = remaining;
                strm.next_out = compr;
                strm.avail_out = comprLen;

                int actual_strategy;
                switch (strategy) {
                    case 0: actual_strategy = Z_DEFAULT_STRATEGY; break;
                    case 1: actual_strategy = Z_FILTERED; break;
                    case 2: actual_strategy = Z_HUFFMAN_ONLY; break;
                    case 3: actual_strategy = Z_RLE; break;
                    default: actual_strategy = Z_DEFAULT_STRATEGY;
                }
                err = deflateInit2(&strm, level, Z_DEFLATED, windowBits, memLevel, actual_strategy);
                if (err != Z_OK) {
                    free(compr);
                    return 0;
                }

                size_t flush_len = remaining / 3;
                if (flush_len == 0) flush_len = 1;
                while (strm.total_in < flush_len && strm.total_out < comprLen) {
                    strm.avail_in = strm.avail_out = 1;
                    err = deflate(&strm, Z_SYNC_FLUSH);
                    if (err != Z_OK) {
                        deflateEnd(&strm);
                        free(compr);
                        return 0;
                    }
                }

                err = deflateUsed(&strm, &bits_used);
                assert(err == Z_OK);
                assert(bits_used >= 0 && bits_used <= 8);

                err = deflateEnd(&strm);
                if (err != Z_OK) {
                    free(compr);
                    return 0;
                }
                free(compr);
            }
            break;

        case 4: /* Invalid stream: after deflateEnd */
            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = Z_NULL;
            strm.avail_in = 0;
            strm.next_out = Z_NULL;
            strm.avail_out = 0;

            err = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
            if (err != Z_OK) return 0;

            err = deflateEnd(&strm);
            assert(err == Z_OK);

            err = deflateUsed(&strm, &bits_used);
            assert(err == Z_STREAM_ERROR);
            break;

        case 5: /* Uninitialized stream (all zeros) */
            memset(&strm, 0, sizeof(strm));
            err = deflateUsed(&strm, &bits_used);
            assert(err == Z_STREAM_ERROR);
            break;

        case 6: /* Gzip compression with windowBits=31 */
            if (remaining == 0) return 0;
            comprLen = compressBound(remaining);
            compr = (Bytef *)malloc(comprLen);
            if (!compr) return 0;

            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = (Bytef *)data;
            strm.avail_in = remaining;
            strm.next_out = compr;
            strm.avail_out = comprLen;

            err = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }

            while (strm.total_in != remaining && strm.total_out < comprLen) {
                strm.avail_in = strm.avail_out = 1;
                err = deflate(&strm, Z_NO_FLUSH);
                if (err != Z_OK) {
                    deflateEnd(&strm);
                    free(compr);
                    return 0;
                }
            }

            for (;;) {
                strm.avail_out = 1;
                err = deflate(&strm, Z_FINISH);
                if (err == Z_STREAM_END) break;
                if (err != Z_OK) {
                    deflateEnd(&strm);
                    free(compr);
                    return 0;
                }
            }

            err = deflateUsed(&strm, &bits_used);
            assert(err == Z_OK);
            assert(bits_used >= 0 && bits_used <= 8);

            err = deflateEnd(&strm);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }
            free(compr);
            break;

        case 7: /* NULL stream pointer */
            err = deflateUsed(NULL, &bits_used);
            assert(err == Z_STREAM_ERROR);
            break;

        case 8: /* Raw deflate (negative windowBits) */
            if (remaining == 0) return 0;
            comprLen = compressBound(remaining);
            compr = (Bytef *)malloc(comprLen);
            if (!compr) return 0;

            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = (Bytef *)data;
            strm.avail_in = remaining;
            strm.next_out = compr;
            strm.avail_out = comprLen;

            err = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }

            while (strm.total_in != remaining && strm.total_out < comprLen) {
                strm.avail_in = strm.avail_out = 1;
                err = deflate(&strm, Z_NO_FLUSH);
                if (err != Z_OK) {
                    deflateEnd(&strm);
                    free(compr);
                    return 0;
                }
            }

            err = deflateUsed(&strm, &bits_used);
            assert(err == Z_OK);
            assert(bits_used >= 0 && bits_used <= 8);

            err = deflateEnd(&strm);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }
            free(compr);
            break;

        case 9: /* Use Z_FULL_FLUSH */
            if (remaining == 0) return 0;
            comprLen = compressBound(remaining);
            compr = (Bytef *)malloc(comprLen);
            if (!compr) return 0;

            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = (Bytef *)data;
            strm.avail_in = remaining;
            strm.next_out = compr;
            strm.avail_out = comprLen;

            err = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }

            size_t full_flush_len = remaining / 2;
            if (full_flush_len == 0) full_flush_len = 1;
            while (strm.total_in < full_flush_len && strm.total_out < comprLen) {
                strm.avail_in = strm.avail_out = 1;
                err = deflate(&strm, Z_FULL_FLUSH);
                if (err != Z_OK) {
                    deflateEnd(&strm);
                    free(compr);
                    return 0;
                }
            }

            err = deflateUsed(&strm, &bits_used);
            assert(err == Z_OK);
            assert(bits_used >= 0 && bits_used <= 8);

            err = deflateEnd(&strm);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }
            free(compr);
            break;

        case 10: /* Use Z_BLOCK */
            if (remaining == 0) return 0;
            comprLen = compressBound(remaining);
            compr = (Bytef *)malloc(comprLen);
            if (!compr) return 0;

            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = (Bytef *)data;
            strm.avail_in = remaining;
            strm.next_out = compr;
            strm.avail_out = comprLen;

            err = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }

            size_t block_len = remaining / 2;
            if (block_len == 0) block_len = 1;
            while (strm.total_in < block_len && strm.total_out < comprLen) {
                strm.avail_in = strm.avail_out = 1;
                err = deflate(&strm, Z_BLOCK);
                if (err != Z_OK) {
                    deflateEnd(&strm);
                    free(compr);
                    return 0;
                }
            }

            err = deflateUsed(&strm, &bits_used);
            assert(err == Z_OK);
            assert(bits_used >= 0 && bits_used <= 8);

            err = deflateEnd(&strm);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }
            free(compr);
            break;

        case 11: /* deflateReset and then deflateUsed */
            if (remaining == 0) return 0;
            comprLen = compressBound(remaining);
            compr = (Bytef *)malloc(comprLen);
            if (!compr) return 0;

            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = (Bytef *)data;
            strm.avail_in = remaining;
            strm.next_out = compr;
            strm.avail_out = comprLen;

            err = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }

            /* Do a little compression */
            size_t reset_len = remaining / 4;
            if (reset_len == 0) reset_len = 1;
            while (strm.total_in < reset_len && strm.total_out < comprLen) {
                strm.avail_in = strm.avail_out = 1;
                err = deflate(&strm, Z_NO_FLUSH);
                if (err != Z_OK) {
                    deflateEnd(&strm);
                    free(compr);
                    return 0;
                }
            }

            err = deflateReset(&strm);
            assert(err == Z_OK);

            err = deflateUsed(&strm, &bits_used);
            assert(err == Z_OK);
            assert(bits_used >= 0 && bits_used <= 8);

            err = deflateEnd(&strm);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }
            free(compr);
            break;

        case 12: /* deflateSetDictionary */
            if (remaining < 2) return 0;
            dictLen = (data[0] << 8) | data[1];
            if (dictLen > remaining - 2) dictLen = remaining - 2;
            dict = data + 2;
            data = consume(data, remaining, 2 + dictLen, &remaining);
            if (data == NULL || remaining == 0) return 0;
            comprLen = compressBound(remaining);
            compr = (Bytef *)malloc(comprLen);
            if (!compr) return 0;

            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = (Bytef *)data;
            strm.avail_in = remaining;
            strm.next_out = compr;
            strm.avail_out = comprLen;

            err = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }

            err = deflateSetDictionary(&strm, dict, dictLen);
            assert(err == Z_OK);

            err = deflateUsed(&strm, &bits_used);
            assert(err == Z_OK);
            assert(bits_used >= 0 && bits_used <= 8);

            err = deflateEnd(&strm);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }
            free(compr);
            break;

        case 13: /* deflateParams */
            if (remaining == 0) return 0;
            comprLen = compressBound(remaining);
            compr = (Bytef *)malloc(comprLen);
            if (!compr) return 0;

            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = (Bytef *)data;
            strm.avail_in = remaining;
            strm.next_out = compr;
            strm.avail_out = comprLen;

            err = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }

            /* Change level and strategy */
            err = deflateParams(&strm, Z_BEST_COMPRESSION, Z_FILTERED);
            assert(err == Z_OK);

            err = deflateUsed(&strm, &bits_used);
            assert(err == Z_OK);
            assert(bits_used >= 0 && bits_used <= 8);

            err = deflateEnd(&strm);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }
            free(compr);
            break;

        case 14: /* Multiple calls to deflateUsed during compression */
            if (remaining == 0) return 0;
            comprLen = compressBound(remaining);
            compr = (Bytef *)malloc(comprLen);
            if (!compr) return 0;

            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = (Bytef *)data;
            strm.avail_in = remaining;
            strm.next_out = compr;
            strm.avail_out = comprLen;

            err = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }

            size_t steps = 5;
            size_t step_len = remaining / steps;
            if (step_len == 0) step_len = 1;
            for (int i = 0; i < steps && strm.total_in < remaining && strm.total_out < comprLen; i++) {
                size_t to_compress = step_len;
                if (strm.total_in + to_compress > remaining) to_compress = remaining - strm.total_in;
                while (to_compress > 0 && strm.total_out < comprLen) {
                    strm.avail_in = strm.avail_out = 1;
                    err = deflate(&strm, Z_NO_FLUSH);
                    if (err != Z_OK) {
                        deflateEnd(&strm);
                        free(compr);
                        return 0;
                    }
                    to_compress--;
                }
                err = deflateUsed(&strm, &bits_used);
                assert(err == Z_OK);
                assert(bits_used >= 0 && bits_used <= 8);
            }

            err = deflateEnd(&strm);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }
            free(compr);
            break;

        case 15: /* Custom zalloc and zfree (set to Z_NULL, which is already done, but we test) */
            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = Z_NULL;
            strm.avail_in = 0;
            strm.next_out = Z_NULL;
            strm.avail_out = 0;

            err = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
            if (err != Z_OK) return 0;

            err = deflateUsed(&strm, &bits_used);
            assert(err == Z_OK);
            assert(bits_used >= 0 && bits_used <= 8);

            err = deflateEnd(&strm);
            assert(err == Z_OK);
            break;

        case 16: /* Gzip compression with intermediate calls to deflateUsed during header processing */
            if (remaining == 0) return 0;
            comprLen = compressBound(remaining);
            compr = (Bytef *)malloc(comprLen);
            if (!compr) return 0;

            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = (Bytef *)data;
            strm.avail_in = remaining;
            strm.next_out = compr;
            strm.avail_out = comprLen;

            err = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }

            /* Compress in small steps, calling deflateUsed after each step */
            while (strm.total_in < remaining && strm.total_out < comprLen) {
                strm.avail_in = strm.avail_out = 1;
                err = deflate(&strm, Z_NO_FLUSH);
                if (err != Z_OK) {
                    deflateEnd(&strm);
                    free(compr);
                    return 0;
                }
                err = deflateUsed(&strm, &bits_used);
                assert(err == Z_OK);
                assert(bits_used >= 0 && bits_used <= 8);
            }

            /* Finish the stream */
            for (;;) {
                strm.avail_out = 1;
                err = deflate(&strm, Z_FINISH);
                if (err == Z_STREAM_END) break;
                if (err != Z_OK) {
                    deflateEnd(&strm);
                    free(compr);
                    return 0;
                }
            }

            err = deflateUsed(&strm, &bits_used);
            assert(err == Z_OK);
            assert(bits_used >= 0 && bits_used <= 8);

            err = deflateEnd(&strm);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }
            free(compr);
            break;

        case 17: /* Failed initialization: invalid parameters */
            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = Z_NULL;
            strm.avail_in = 0;
            strm.next_out = Z_NULL;
            strm.avail_out = 0;

            /* Try to initialize with invalid windowBits (0) */
            err = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 0, 8, Z_DEFAULT_STRATEGY);
            if (err == Z_OK) {
                /* If by chance it succeeds, clean up and return */
                deflateEnd(&strm);
                return 0;
            }
            /* Now call deflateUsed on the uninitialized stream */
            err = deflateUsed(&strm, &bits_used);
            assert(err == Z_STREAM_ERROR);
            break;

        case 18: /* Error during compression: invalid flush parameter */
            if (remaining == 0) return 0;
            comprLen = compressBound(remaining);
            compr = (Bytef *)malloc(comprLen);
            if (!compr) return 0;

            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
            strm.next_in = (Bytef *)data;
            strm.avail_in = remaining;
            strm.next_out = compr;
            strm.avail_out = comprLen;

            err = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }

            /* Force an error by passing an invalid flush value */
            err = deflate(&strm, 100);  /* invalid flush */
            assert(err != Z_OK);  /* Should return Z_STREAM_ERROR */

            /* Now call deflateUsed on the stream in error state */
            err = deflateUsed(&strm, &bits_used);
            assert(err == Z_STREAM_ERROR);

            err = deflateEnd(&strm);
            if (err != Z_OK) {
                free(compr);
                return 0;
            }
            free(compr);
            break;

        default:
            return 0;
    }

    return 0;
}