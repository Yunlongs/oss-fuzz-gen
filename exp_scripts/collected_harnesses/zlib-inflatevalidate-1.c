#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

/* Fixed compressed data for "hello" (zlib format, generated once) */
static const uint8_t hello_compressed[] = {
    0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x06, 0x2c, 0x02, 0x15
};
static const size_t hello_compressed_len = 13;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static size_t kMaxSize = 1024 * 1024;
    if (size < 4 || size > kMaxSize)
        return 0;

    uint8_t flags = data[0];
    int wrap_type = flags & 3;           // 0: raw, 1: zlib, 2: gzip
    int use_valid = (flags >> 2) & 1;    // 0: invalid, 1: valid
    int check1 = (flags >> 3) & 1;       // first check value
    int check2 = (flags >> 4) & 1;       // second check value
    int reset_wrap = (flags >> 5) & 1;   // whether to change wrap via inflateReset2 before first validate
    int feed_data = (flags >> 6) & 1;    // whether to feed compressed data before first validate
    int use_dict = (flags >> 7) & 1;     // whether to use dictionary

    int second_wrap_type = data[1] & 3;  // wrap type for reset_between
    int flush_mode = (data[1] >> 2) & 3; // flush mode for inflate (0: Z_NO_FLUSH, 1: Z_SYNC_FLUSH, 2: Z_FULL_FLUSH, 3: Z_BLOCK)
    int prime_bits = (data[1] >> 4) & 15; // bits for inflatePrime (0-15)

    int dict_len_byte = data[2];         // dictionary length (0-255)
    int invalid_condition = data[3] & 7; // for invalid streams

    size_t data_offset = 4;              // start of data used for compression/dictionary

    if (use_valid) {
        z_stream strm;
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        strm.next_in = Z_NULL;
        strm.avail_in = 0;

        int windowBits;
        switch (wrap_type) {
            case 0: windowBits = -15; break;        // raw
            case 1: windowBits = 15; break;         // zlib
            case 2: windowBits = 15 + 16; break;    // gzip
            default: windowBits = 15;
        }

        int err = inflateInit2(&strm, windowBits);
        if (err != Z_OK) {
            return 0;
        }

        if (reset_wrap) {
            int new_windowBits;
            switch (wrap_type) {
                case 0: new_windowBits = 15; break;
                case 1: new_windowBits = 15 + 16; break;
                case 2: new_windowBits = -15; break;
                default: new_windowBits = 15;
            }
            inflateReset2(&strm, new_windowBits);
        }

        if (use_dict && size > data_offset) {
            /* Use a dictionary from the input */
            size_t dict_len = dict_len_byte % (size - data_offset + 1);
            if (dict_len > 0) {
                inflateSetDictionary(&strm, data + data_offset, dict_len);
            }
        }

        if (feed_data) {
            /* Compress a portion of the input and feed it to inflate */
            size_t data_len = size - data_offset;
            if (data_len > 0) {
                uLongf compr_len = compressBound(data_len);
                Bytef *compr = (Bytef*)malloc(compr_len);
                if (compr) {
                    if (compress2(compr, &compr_len, data + data_offset, data_len, Z_DEFAULT_COMPRESSION) == Z_OK) {
                        strm.next_in = compr;
                        strm.avail_in = compr_len;
                        strm.next_out = NULL;
                        strm.avail_out = 0;
                        int flush;
                        switch (flush_mode) {
                            case 0: flush = Z_NO_FLUSH; break;
                            case 1: flush = Z_SYNC_FLUSH; break;
                            case 2: flush = Z_FULL_FLUSH; break;
                            case 3: flush = Z_BLOCK; break;
                            default: flush = Z_NO_FLUSH;
                        }
                        inflate(&strm, flush);
                    }
                    free(compr);
                }
            } else {
                /* Fallback to fixed compressed data */
                strm.next_in = (Bytef *)hello_compressed;
                strm.avail_in = hello_compressed_len;
                strm.next_out = NULL;
                strm.avail_out = 0;
                inflate(&strm, Z_NO_FLUSH);
            }
        }

        if (prime_bits > 0 && size > data_offset) {
            /* Insert bits into the stream */
            int bits = prime_bits;
            int value = data[data_offset] & ((1 << bits) - 1);
            inflatePrime(&strm, bits, value);
        }

        /* First call to inflateValidate */
        err = inflateValidate(&strm, check1);
        /* We ignore the error because for valid streams it should be Z_OK,
           but if something went wrong we don't want to crash. */
        (void)err;

        /* Call other inflate functions to increase coverage */
        (void)inflateMark(&strm);
        (void)inflateCodesUsed(&strm);

        /* Optionally reset with a different wrap type */
        if (second_wrap_type != wrap_type) {
            int new_windowBits;
            switch (second_wrap_type) {
                case 0: new_windowBits = -15; break;
                case 1: new_windowBits = 15; break;
                case 2: new_windowBits = 15 + 16; break;
                default: new_windowBits = 15;
            }
            inflateReset2(&strm, new_windowBits);
        }

        /* Second call with possibly different check value */
        err = inflateValidate(&strm, check2);
        (void)err;

        inflateEnd(&strm);
    } else {
        /* Invalid stream scenarios (simplified to avoid unreliable dummy states) */
        switch (invalid_condition) {
            case 0: {
                /* Zeroed stream (zalloc and zfree are zero) */
                z_stream strm;
                memset(&strm, 0, sizeof(strm));
                (void)inflateValidate(&strm, check1);
                break;
            }
            case 1:
                /* NULL stream pointer */
                (void)inflateValidate(NULL, check1);
                break;
            case 2: {
                /* Non-zero allocators but NULL state */
                z_stream strm;
                memset(&strm, 0, sizeof(strm));
                strm.zalloc = (alloc_func)1;
                strm.zfree = (free_func)1;
                strm.state = NULL;
                (void)inflateValidate(&strm, check1);
                break;
            }
            /* We omit other dummy state cases to avoid potential undefined behavior */
            default:
                break;
        }
    }

    return 0;
}