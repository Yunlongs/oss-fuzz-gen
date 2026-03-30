#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

/* Custom allocator for testing */
static int alloc_count = 0;
static int alloc_fail_after = -1;

voidpf custom_alloc(voidpf opaque, uInt items, uInt size) {
    (void)opaque;
    if (alloc_fail_after >= 0 && alloc_count >= alloc_fail_after) {
        return Z_NULL;
    }
    alloc_count++;
    return malloc(items * size);
}

void custom_free(voidpf opaque, voidpf address) {
    (void)opaque;
    alloc_count--;
    free(address);
}

/* Helper to create repetitive data */
static void create_patterned_data(uint8_t *dest, size_t destLen, 
                                  const uint8_t *pattern, size_t patternLen) {
    if (patternLen == 0) patternLen = 1;
    for (size_t i = 0; i < destLen; i++) {
        dest[i] = pattern[i % patternLen];
    }
}

/* Helper to slightly corrupt data */
static void corrupt_data(uint8_t *data, size_t len, unsigned int seed) {
    if (len == 0) return;
    /* Flip a few random bits */
    for (int i = 0; i < 3; i++) {
        size_t pos = (seed + i) % len;
        data[pos] ^= (1 << ((seed >> i) & 7));
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Need at least 20 bytes for header */
    if (size < 20) {
        return 0;
    }

    static size_t kMaxSize = 1024 * 1024;
    if (size > kMaxSize) {
        return 0;
    }

    /* Parse extended header */
    uint8_t mode = data[0] % 10;
    uint8_t good_length = data[1];
    uint8_t max_lazy = data[2];
    uint8_t nice_length = data[3];
    uint16_t max_chain = (data[4] << 8) | data[5];
    uint8_t level = data[6] % 11;  /* 0-9, 10 = default */
    if (level == 10) level = Z_DEFAULT_COMPRESSION;
    uint8_t strategy_idx = data[7] % 5;
    int strategy;
    switch (strategy_idx) {
        case 0: strategy = Z_DEFAULT_STRATEGY; break;
        case 1: strategy = Z_FILTERED; break;
        case 2: strategy = Z_HUFFMAN_ONLY; break;
        case 3: strategy = Z_RLE; break;
        case 4: strategy = Z_FIXED; break;
        default: strategy = Z_DEFAULT_STRATEGY;
    }
    uint8_t flush_mode = data[8] % 5;
    int flush;
    switch (flush_mode) {
        case 0: flush = Z_NO_FLUSH; break;
        case 1: flush = Z_SYNC_FLUSH; break;
        case 2: flush = Z_FULL_FLUSH; break;
        case 3: flush = Z_FINISH; break;
        case 4: flush = Z_BLOCK; break;
        default: flush = Z_FINISH;
    }
    uint8_t pattern_len = data[9] % 32;
    uint8_t use_custom_alloc = data[10] & 1;
    uint8_t corrupt_after = data[11] & 1;
    uint8_t multi_stream = data[12] & 1;
    
    const uint8_t *pattern_data = data + 13;
    size_t pattern_data_len = (size - 13 > 256) ? 256 : size - 13;
    size_t data_to_compress_len = 1024; /* Fixed size for reproducibility */
    
    /* Create data with pattern if requested */
    uint8_t *data_to_compress = malloc(data_to_compress_len);
    if (!data_to_compress) return 0;
    
    if (pattern_len > 0 && pattern_data_len > 0) {
        create_patterned_data(data_to_compress, data_to_compress_len,
                             pattern_data, pattern_len);
    } else {
        /* Use random data */
        size_t copy_len = (data_to_compress_len < pattern_data_len) ? 
                         data_to_compress_len : pattern_data_len;
        memcpy(data_to_compress, pattern_data, copy_len);
        /* Fill remainder with repeating pattern */
        for (size_t i = copy_len; i < data_to_compress_len; i++) {
            data_to_compress[i] = data_to_compress[i % copy_len];
        }
    }
    
    if (mode < 7) { /* Valid stream modes */
        z_stream strm;
        int err;
        
        if (use_custom_alloc) {
            alloc_count = 0;
            alloc_fail_after = (data[13] % 5) == 0 ? 0 : -1;
            strm.zalloc = custom_alloc;
            strm.zfree = custom_free;
            strm.opaque = Z_NULL;
        } else {
            strm.zalloc = Z_NULL;
            strm.zfree = Z_NULL;
            strm.opaque = Z_NULL;
        }
        
        err = deflateInit2(&strm, level, Z_DEFLATED, 
                          MAX_WBITS, 8, strategy);
        if (err != Z_OK) {
            free(data_to_compress);
            return 0;
        }
        
        /* First tuning */
        err = deflateTune(&strm, good_length, max_lazy, 
                         nice_length, max_chain);
        
        /* Test extreme parameter values in some cases */
        if (mode == 1) {
            deflateTune(&strm, 0, 0, 0, 0);
        } else if (mode == 2) {
            deflateTune(&strm, 255, 255, 258, 65535);
        }
        
        size_t compr_len = compressBound(data_to_compress_len);
        uint8_t *compr = malloc(compr_len);
        if (!compr) {
            deflateEnd(&strm);
            free(data_to_compress);
            return 0;
        }
        
        strm.next_in = data_to_compress;
        strm.avail_in = data_to_compress_len;
        strm.next_out = compr;
        strm.avail_out = compr_len;
        
        /* Compress with specified flush mode */
        err = deflate(&strm, flush);
        
        /* For multi-stream test */
        if (multi_stream && mode >= 3) {
            /* Create second stream with different parameters */
            z_stream strm2;
            strm2.zalloc = Z_NULL;
            strm2.zfree = Z_NULL;
            strm2.opaque = Z_NULL;
            
            if (deflateInit(&strm2, (level + 1) % 9) == Z_OK) {
                deflateTune(&strm2, good_length / 2, max_lazy / 2,
                           nice_length / 2, max_chain / 2);
                deflateEnd(&strm2);
            }
        }
        
        /* Test reset if not finished */
        if (flush != Z_FINISH && mode >= 4) {
            deflateReset(&strm);
            strm.next_in = data_to_compress;
            strm.avail_in = data_to_compress_len / 2;
            strm.next_out = compr + strm.total_out;
            strm.avail_out = compr_len - strm.total_out;
            err = deflate(&strm, Z_FINISH);
        }
        
        size_t total_compr = strm.total_out;
        deflateEnd(&strm);
        
        /* Decompress test */
        if (total_compr > 0) {
            z_stream d_strm;
            d_strm.zalloc = Z_NULL;
            d_strm.zfree = Z_NULL;
            d_strm.opaque = Z_NULL;
            d_strm.next_in = compr;
            d_strm.avail_in = total_compr;
            
            uint8_t *uncompr = malloc(data_to_compress_len);
            if (uncompr) {
                d_strm.next_out = uncompr;
                d_strm.avail_out = data_to_compress_len;
                
                if (inflateInit(&d_strm) == Z_OK) {
                    /* Corrupt data before decompression in some cases */
                    if (corrupt_after && total_compr > 10) {
                        corrupt_data(compr + total_compr/2, 
                                    total_compr/2, data[14]);
                    }
                    
                    int d_err = inflate(&d_strm, Z_FINISH);
                    inflateEnd(&d_strm);
                    
                    /* Test partial decompression */
                    if (d_err == Z_OK || d_err == Z_BUF_ERROR) {
                        /* Try to continue */
                        d_strm.avail_in = 0;
                        d_strm.next_out = uncompr + d_strm.total_out;
                        d_strm.avail_out = data_to_compress_len - d_strm.total_out;
                        inflate(&d_strm, Z_FINISH);
                        inflateEnd(&d_strm);
                    }
                }
                free(uncompr);
            }
        }
        
        free(compr);
        free(data_to_compress);
    } else if (mode == 7) {
        /* Test stream with invalid status */
        z_stream strm;
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        
        /* Initialize then put in "bad" state */
        if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) == Z_OK) {
            /* Force a state change by starting compression */
            uint8_t dummy = 0;
            strm.next_in = &dummy;
            strm.avail_in = 0;
            uint8_t out[1];
            strm.next_out = out;
            strm.avail_out = 1;
            deflate(&strm, Z_SYNC_FLUSH);
            
            /* Now try to tune - should work since we're in BUSY_STATE */
            deflateTune(&strm, good_length, max_lazy, nice_length, max_chain);
            
            deflateEnd(&strm);
        }
    } else if (mode == 8) {
        /* Test with custom allocators that fail */
        z_stream strm;
        strm.zalloc = custom_alloc;
        strm.zfree = custom_free;
        strm.opaque = Z_NULL;
        alloc_count = 0;
        alloc_fail_after = 0; /* Fail immediately */
        
        /* This should fail allocation */
        deflateInit(&strm, Z_DEFAULT_COMPRESSION);
        /* Try tune anyway */
        deflateTune(&strm, good_length, max_lazy, nice_length, max_chain);
        if (strm.state != NULL) {
            deflateEnd(&strm);
        }
    } else if (mode == 9) {
        /* Test parameter boundary cases */
        z_stream strm;
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        
        if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) == Z_OK) {
            /* Test with max possible values (cast to uInt) */
            deflateTune(&strm, 0xFFFFFFFF, 0xFFFFFFFF, 
                       0x7FFFFFFF, 0xFFFFFFFF);
            /* Test with negative values */
            deflateTune(&strm, -1, -100, -1000, -10000);
            deflateEnd(&strm);
        }
    }
    
    return 0;
}