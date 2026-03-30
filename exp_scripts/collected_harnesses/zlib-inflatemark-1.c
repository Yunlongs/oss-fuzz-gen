#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

/* Dummy alloc/free functions to test error paths */
static voidpf dummy_alloc(voidpf opaque, uInt items, uInt size) {
    (void)opaque;
    (void)items;
    (void)size;
    return Z_NULL;
}

static void dummy_free(voidpf opaque, voidpf address) {
    (void)opaque;
    (void)address;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Discard large inputs to avoid timeouts. */
    static size_t kMaxSize = 1024 * 1024;
    if (size == 0 || size > kMaxSize) {
        return 0;
    }

    /* --- Part 1: Test invalid streams --- */
    {
        z_stream invalid_strm;
        memset(&invalid_strm, 0, sizeof(invalid_strm));
        /* This should trigger inflateStateCheck failure. */
        long mark = inflateMark(&invalid_strm);
        (void)mark;  /* Ignore result. */
    }
    /* Test with non-NULL alloc/free but state still Z_NULL */
    {
        z_stream strm;
        memset(&strm, 0, sizeof(strm));
        strm.zalloc = dummy_alloc;
        strm.zfree = dummy_free;
        strm.opaque = Z_NULL;
        /* Do not call inflateInit, so state remains Z_NULL */
        long mark = inflateMark(&strm);
        (void)mark;
    }

    /* --- Part 2: Use first bytes as parameters --- */
    if (size < 6) return 0;
    uint8_t param = data[0];
    int level = param % 11;                     /* 0..10 */
    int windowBits = (param & 0x1F) - 15;       /* -15..16 */
    if (windowBits == 0) windowBits = 15;
    int strategy = data[1] % 5;                 /* 0..4, see deflateInit2 */
    int flush_mode = data[2] % 5;               /* 0: Z_NO_FLUSH, 1: Z_SYNC_FLUSH, 2: Z_FULL_FLUSH, 3: Z_FINISH, 4: Z_BLOCK */
    unsigned chunk_shift = data[3] % 10;        /* 0..9 -> chunk size = 1 << shift */
    size_t chunk_size = 1U << chunk_shift;
    if (chunk_size == 0) chunk_size = 1;

    /* Determine size of data to compress (max 64KB). */
    size_t compr_data_len = (data[4] << 8) | data[5];
    if (compr_data_len > 65535) compr_data_len = 65535;
    if (compr_data_len > size - 6) compr_data_len = size - 6;
    const uint8_t *compr_src = data + 6;
    size_t compr_src_len = compr_data_len;
    const uint8_t *raw_src = compr_src + compr_src_len;
    size_t raw_src_len = size - 6 - compr_src_len;

    /* --- Part 3: Generate compressible data with dictionary --- */
    uint8_t *compressible = NULL;
    uint8_t *dict = NULL;
    size_t compressible_len = 32768;  /* 32KB for more matches */
    if (compr_src_len > 10) {
        uint8_t pattern = compr_src[0];
        compressible = (uint8_t *)malloc(compressible_len);
        if (compressible) {
            for (size_t i = 0; i < compressible_len; i++) {
                compressible[i] = pattern ^ (i & 0xFF);
            }
            compr_src = compressible;
            compr_src_len = compressible_len;
            /* Use first 256 bytes as dictionary */
            dict = (uint8_t *)malloc(256);
            if (dict) {
                memcpy(dict, compressible, 256);
            }
        }
    }

    /* --- Part 4: Valid compression and chunked decompression --- */
    if (compr_src_len > 0) {
        size_t compr_bound = compressBound(compr_src_len);
        uint8_t *compr = (uint8_t *)malloc(compr_bound);
        uint8_t *uncompr = (uint8_t *)malloc(compr_src_len);
        if (compr && uncompr) {
            z_stream c_stream;
            memset(&c_stream, 0, sizeof(c_stream));
            c_stream.zalloc = Z_NULL;
            c_stream.zfree = Z_NULL;
            c_stream.opaque = Z_NULL;
            int err = deflateInit2(&c_stream, level, Z_DEFLATED, windowBits, 8, strategy);
            if (err == Z_OK) {
                if (dict) {
                    deflateSetDictionary(&c_stream, dict, 256);
                }
                c_stream.next_in = (Bytef *)compr_src;
                c_stream.avail_in = (uInt)compr_src_len;
                c_stream.next_out = compr;
                c_stream.avail_out = (uInt)compr_bound;
                err = deflate(&c_stream, Z_FINISH);
                if (err == Z_STREAM_END) {
                    size_t compr_len = c_stream.total_out;
                    deflateEnd(&c_stream);

                    z_stream d_stream;
                    memset(&d_stream, 0, sizeof(d_stream));
                    d_stream.zalloc = Z_NULL;
                    d_stream.zfree = Z_NULL;
                    d_stream.opaque = Z_NULL;
                    err = inflateInit2(&d_stream, windowBits);
                    if (err == Z_OK) {
                        if (dict) {
                            inflateSetDictionary(&d_stream, dict, 256);
                        }
                        d_stream.next_in = compr;
                        d_stream.avail_in = (uInt)compr_len;
                        d_stream.next_out = uncompr;
                        d_stream.avail_out = (uInt)compr_src_len;

                        /* Call inflateMark before any decompression. */
                        long mark = inflateMark(&d_stream);
                        (void)mark;

                        /* Test inflatePrime with varying bits */
                        if (compr_len > 0) {
                            for (int bits = 1; bits <= 16; bits *= 2) {
                                inflatePrime(&d_stream, bits, compr[0] & ((1 << bits) - 1));
                                mark = inflateMark(&d_stream);
                                (void)mark;
                            }
                        }

                        /* Decompress in 1‑byte chunks to catch intermediate states. */
                        while (d_stream.avail_in > 0) {
                            size_t this_chunk = 1;
                            d_stream.avail_in = (uInt)this_chunk;
                            int flush;
                            switch (flush_mode) {
                                case 0: flush = Z_NO_FLUSH; break;
                                case 1: flush = Z_SYNC_FLUSH; break;
                                case 2: flush = Z_FULL_FLUSH; break;
                                case 3: flush = Z_FINISH; break;
                                case 4: flush = Z_BLOCK; break;
                                default: flush = Z_NO_FLUSH;
                            }
                            err = inflate(&d_stream, flush);
                            mark = inflateMark(&d_stream);
                            (void)mark;
                            if (err != Z_OK && err != Z_STREAM_END) {
                                inflateSync(&d_stream);
                                mark = inflateMark(&d_stream);
                                (void)mark;
                                break;
                            }
                            if (err == Z_STREAM_END) break;
                            d_stream.avail_in = (uInt)(compr_len - (d_stream.next_in - compr));
                        }
#ifdef inflateUndermine
                        inflateUndermine(&d_stream, 1);
                        mark = inflateMark(&d_stream);
                        (void)mark;
#endif
#ifdef inflateValidate
                        inflateValidate(&d_stream, 0);
                        mark = inflateMark(&d_stream);
                        (void)mark;
#endif
                        inflateEnd(&d_stream);
                    }
                } else {
                    deflateEnd(&c_stream);
                }
            }
            free(compr);
            free(uncompr);
        } else {
            free(compr);
            free(uncompr);
        }
    }

    /* --- Part 5: Raw decompression of the remaining input with multiple windowBits --- */
    if (raw_src_len > 0) {
        /* Try three different windowBits: raw deflate, zlib, and gzip. */
        int wb[] = { -15, 15, 31 };
        for (int w = 0; w < 3; w++) {
            z_stream raw_strm;
            memset(&raw_strm, 0, sizeof(raw_strm));
            raw_strm.zalloc = Z_NULL;
            raw_strm.zfree = Z_NULL;
            raw_strm.opaque = Z_NULL;
            if (inflateInit2(&raw_strm, wb[w]) != Z_OK) continue;

            /* Allocate output buffer: up to 2x input size, capped at 1MB. */
            size_t out_size = raw_src_len * 2;
            if (out_size > 1024 * 1024) out_size = 1024 * 1024;
            uint8_t *raw_out = (uint8_t *)malloc(out_size);
            if (!raw_out) {
                inflateEnd(&raw_strm);
                continue;
            }

            raw_strm.next_in = (Bytef *)raw_src;
            raw_strm.avail_in = (uInt)raw_src_len;
            raw_strm.next_out = raw_out;
            raw_strm.avail_out = (uInt)out_size;

            long mark = inflateMark(&raw_strm);
            (void)mark;

            /* Decompress in 1‑byte chunks, calling inflateMark after each. */
            while (raw_strm.avail_in > 0) {
                size_t this_chunk = 1;
                raw_strm.avail_in = (uInt)this_chunk;
                int err = inflate(&raw_strm, Z_NO_FLUSH);
                mark = inflateMark(&raw_strm);
                (void)mark;
                if (err != Z_OK && err != Z_STREAM_END) {
                    inflateSync(&raw_strm);
                    mark = inflateMark(&raw_strm);
                    (void)mark;
                    break;
                }
                if (err == Z_STREAM_END) break;
                raw_strm.avail_in = (uInt)(raw_src_len - (raw_strm.next_in - raw_src));
            }
            inflateEnd(&raw_strm);
            free(raw_out);
        }
    }

    /* --- Part 6: Dictionary test (if enough data) --- */
    if (size > 100) {
        size_t dict_len = 256;
        if (dict_len > size) dict_len = size;
        uint8_t *dict2 = (uint8_t *)malloc(dict_len);
        if (dict2) {
            memcpy(dict2, data, dict_len);
            z_stream dict_strm;
            memset(&dict_strm, 0, sizeof(dict_strm));
            dict_strm.zalloc = Z_NULL;
            dict_strm.zfree = Z_NULL;
            dict_strm.opaque = Z_NULL;
            if (inflateInit2(&dict_strm, 15) == Z_OK) {
                inflateSetDictionary(&dict_strm, dict2, (uInt)dict_len);
                long mark = inflateMark(&dict_strm);
                (void)mark;
                /* Also try to decompress a minimal input with the dictionary */
                uint8_t tmp_out[1];
                dict_strm.next_in = (Bytef *)"\x00";  /* Minimal input */
                dict_strm.avail_in = 1;
                dict_strm.next_out = tmp_out;
                dict_strm.avail_out = 1;
                (void)inflate(&dict_strm, Z_NO_FLUSH);
                mark = inflateMark(&dict_strm);
                (void)mark;
                inflateEnd(&dict_strm);
            }
            free(dict2);
        }
    }

    /* --- Part 7: Extended stored block test (COPY mode with non‑zero length) --- */
    {
        uint8_t stored_block[5 + 100];
        stored_block[0] = 0x00;  /* BFINAL=0, BTYPE=00 */
        stored_block[1] = 100;   /* length low */
        stored_block[2] = 0;     /* length high */
        stored_block[3] = (uint8_t)~100;  /* negated length low */
        stored_block[4] = (uint8_t)~0;    /* negated length high */
        for (int i = 0; i < 100; i++) {
            stored_block[5 + i] = (uint8_t)i;
        }
        z_stream stored_strm;
        memset(&stored_strm, 0, sizeof(stored_strm));
        stored_strm.zalloc = Z_NULL;
        stored_strm.zfree = Z_NULL;
        stored_strm.opaque = Z_NULL;
        if (inflateInit2(&stored_strm, -15) == Z_OK) {  /* raw deflate */
            stored_strm.next_in = stored_block;
            stored_strm.avail_in = sizeof(stored_block);
            uint8_t out[100];
            stored_strm.next_out = out;
            stored_strm.avail_out = sizeof(out);
            /* Decompress in 10‑byte output chunks, calling inflateMark after each. */
            while (stored_strm.avail_out > 0) {
                size_t out_chunk = stored_strm.avail_out > 10 ? 10 : stored_strm.avail_out;
                stored_strm.avail_out = (uInt)out_chunk;
                int err = inflate(&stored_strm, Z_NO_FLUSH);
                long mark = inflateMark(&stored_strm);
                (void)mark;
                if (err != Z_OK) break;
            }
            inflateEnd(&stored_strm);
        }
    }

    /* --- Part 8: Fixed block test (compress zeros with Z_FIXED) --- */
    {
        uint8_t zeros[100] = {0};
        size_t compr_bound = compressBound(sizeof(zeros));
        uint8_t *compr = (uint8_t *)malloc(compr_bound);
        if (compr) {
            z_stream c_stream;
            memset(&c_stream, 0, sizeof(c_stream));
            c_stream.zalloc = Z_NULL;
            c_stream.zfree = Z_NULL;
            c_stream.opaque = Z_NULL;
            if (deflateInit2(&c_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15, 8, Z_FIXED) == Z_OK) {
                c_stream.next_in = zeros;
                c_stream.avail_in = sizeof(zeros);
                c_stream.next_out = compr;
                c_stream.avail_out = (uInt)compr_bound;
                if (deflate(&c_stream, Z_FINISH) == Z_STREAM_END) {
                    size_t compr_len = c_stream.total_out;
                    deflateEnd(&c_stream);

                    z_stream d_stream;
                    memset(&d_stream, 0, sizeof(d_stream));
                    d_stream.zalloc = Z_NULL;
                    d_stream.zfree = Z_NULL;
                    d_stream.opaque = Z_NULL;
                    if (inflateInit2(&d_stream, 15) == Z_OK) {
                        d_stream.next_in = compr;
                        d_stream.avail_in = (uInt)compr_len;
                        uint8_t out[100];
                        d_stream.next_out = out;
                        d_stream.avail_out = sizeof(out);
                        while (d_stream.avail_in > 0) {
                            size_t this_chunk = 1;
                            d_stream.avail_in = (uInt)this_chunk;
                            int err = inflate(&d_stream, Z_NO_FLUSH);
                            long mark = inflateMark(&d_stream);
                            (void)mark;
                            if (err != Z_OK && err != Z_STREAM_END) break;
                            if (err == Z_STREAM_END) break;
                            d_stream.avail_in = (uInt)(compr_len - (d_stream.next_in - compr));
                        }
                        inflateEnd(&d_stream);
                    }
                } else {
                    deflateEnd(&c_stream);
                }
            }
            free(compr);
        }
    }

    /* --- Part 9: Match block test (compress repeated pattern to generate matches) --- */
    {
        uint8_t pattern[1000];
        for (int i = 0; i < 1000; i++) {
            pattern[i] = 'a' + (i % 26);
        }
        size_t compr_bound = compressBound(sizeof(pattern));
        uint8_t *compr = (uint8_t *)malloc(compr_bound);
        if (compr) {
            z_stream c_stream;
            memset(&c_stream, 0, sizeof(c_stream));
            c_stream.zalloc = Z_NULL;
            c_stream.zfree = Z_NULL;
            c_stream.opaque = Z_NULL;
            if (deflateInit2(&c_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15, 8, Z_DEFAULT_STRATEGY) == Z_OK) {
                c_stream.next_in = pattern;
                c_stream.avail_in = sizeof(pattern);
                c_stream.next_out = compr;
                c_stream.avail_out = (uInt)compr_bound;
                if (deflate(&c_stream, Z_FINISH) == Z_STREAM_END) {
                    size_t compr_len = c_stream.total_out;
                    deflateEnd(&c_stream);

                    z_stream d_stream;
                    memset(&d_stream, 0, sizeof(d_stream));
                    d_stream.zalloc = Z_NULL;
                    d_stream.zfree = Z_NULL;
                    d_stream.opaque = Z_NULL;
                    if (inflateInit2(&d_stream, 15) == Z_OK) {
                        d_stream.next_in = compr;
                        d_stream.avail_in = (uInt)compr_len;
                        uint8_t out[1000];
                        d_stream.next_out = out;
                        d_stream.avail_out = sizeof(out);
                        /* Decompress in 1‑byte input steps to catch MATCH mode */
                        while (d_stream.avail_in > 0) {
                            size_t this_chunk = 1;
                            d_stream.avail_in = (uInt)this_chunk;
                            int err = inflate(&d_stream, Z_NO_FLUSH);
                            long mark = inflateMark(&d_stream);
                            (void)mark;
                            if (err != Z_OK && err != Z_STREAM_END) break;
                            if (err == Z_STREAM_END) break;
                            d_stream.avail_in = (uInt)(compr_len - (d_stream.next_in - compr));
                        }
                        inflateEnd(&d_stream);
                    }
                } else {
                    deflateEnd(&c_stream);
                }
            }
            free(compr);
        }
    }

    if (compressible) free(compressible);
    if (dict) free(dict);

    return 0;
}