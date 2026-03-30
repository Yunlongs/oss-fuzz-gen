#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

/* Dummy functions to use as non-NULL alloc/free pointers, but they are never called. */
static voidpf dummy_alloc(voidpf opaque, uInt items, uInt size) {
    (void)opaque; (void)items; (void)size;
    return NULL;
}

static void dummy_free(voidpf opaque, voidpf address) {
    (void)opaque; (void)address;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static size_t kMaxSize = 1024 * 1024;
    if (size < 2 || size > kMaxSize)
        return 0;

    uint8_t scenario = data[0] % 11;  /* Now 11 scenarios (0-10) */
    int subvert = data[1] & 1;
    const uint8_t *input = data + 2;
    size_t input_len = size - 2;

    z_stream strm, strm1, strm2;
    int ret;

    switch (scenario) {
        case 0: /* NULL stream */
            (void)inflateUndermine(NULL, subvert);
            break;

        case 1: /* stream with zalloc = NULL, zfree = non-NULL */
            memset(&strm, 0, sizeof(strm));
            strm.zfree = dummy_free;
            (void)inflateUndermine(&strm, subvert);
            break;

        case 2: /* stream with zfree = NULL, zalloc = non-NULL */
            memset(&strm, 0, sizeof(strm));
            strm.zalloc = dummy_alloc;
            (void)inflateUndermine(&strm, subvert);
            break;

        case 3: /* stream with both alloc/free set to non-NULL but state = NULL */
            memset(&strm, 0, sizeof(strm));
            strm.zalloc = dummy_alloc;
            strm.zfree = dummy_free;
            strm.state = NULL;
            (void)inflateUndermine(&strm, subvert);
            break;

        case 4: /* valid stream, just initialized */
            memset(&strm, 0, sizeof(strm));
            ret = inflateInit2(&strm, 15 + 16);
            if (ret != Z_OK)
                return 0;
            (void)inflateUndermine(&strm, subvert);
            inflateEnd(&strm);
            break;

        case 5: /* valid stream, feed some data to change state */
            memset(&strm, 0, sizeof(strm));
            ret = inflateInit2(&strm, 15 + 16);
            if (ret != Z_OK)
                return 0;
            if (input_len > 0) {
                uint8_t out[1024];
                strm.next_in = (Bytef*)input;
                strm.avail_in = input_len > 1024 ? 1024 : (uInt)input_len;
                strm.next_out = out;
                strm.avail_out = sizeof(out);
                inflate(&strm, Z_NO_FLUSH);
            }
            (void)inflateUndermine(&strm, subvert);
            inflateEnd(&strm);
            break;

        case 6: /* valid stream, cause an error, then call undermine */
            memset(&strm, 0, sizeof(strm));
            ret = inflateInit2(&strm, 15 + 16);
            if (ret != Z_OK)
                return 0;
            if (input_len > 0) {
                uint8_t out[1024];
                strm.next_in = (Bytef*)input;
                strm.avail_in = input_len > 1024 ? 1024 : (uInt)input_len;
                strm.next_out = out;
                strm.avail_out = sizeof(out);
                do {
                    ret = inflate(&strm, Z_NO_FLUSH);
                } while (ret == Z_OK && strm.avail_in > 0 && strm.avail_out > 0);
            }
            (void)inflateUndermine(&strm, subvert);
            inflateEnd(&strm);
            break;

        case 7: /* valid stream, call undermine twice with different subvert */
            memset(&strm, 0, sizeof(strm));
            ret = inflateInit2(&strm, 15 + 16);
            if (ret != Z_OK)
                return 0;
            (void)inflateUndermine(&strm, subvert);
            (void)inflateUndermine(&strm, subvert ^ 1); /* toggle subvert */
            inflateEnd(&strm);
            break;

        case 8: /* valid stream, reset the stream and then undermine */
            memset(&strm, 0, sizeof(strm));
            ret = inflateInit2(&strm, 15 + 16);
            if (ret != Z_OK)
                return 0;
            /* Feed a little data to change state */
            if (input_len > 0) {
                uint8_t out[1024];
                strm.next_in = (Bytef*)input;
                strm.avail_in = input_len > 1024 ? 1024 : (uInt)input_len;
                strm.next_out = out;
                strm.avail_out = sizeof(out);
                inflate(&strm, Z_NO_FLUSH);
            }
            inflateReset(&strm);
            (void)inflateUndermine(&strm, subvert);
            inflateEnd(&strm);
            break;

        case 9: /* swap states between two streams to trigger state->strm != strm */
            memset(&strm1, 0, sizeof(strm1));
            memset(&strm2, 0, sizeof(strm2));
            strm1.zalloc = NULL;
            strm1.zfree = NULL;
            strm2.zalloc = NULL;
            strm2.zfree = NULL;
            ret = inflateInit2(&strm1, 15 + 16);
            if (ret != Z_OK) return 0;
            ret = inflateInit2(&strm2, 15 + 16);
            if (ret != Z_OK) {
                inflateEnd(&strm1);
                return 0;
            }
            /* Swap states: now strm1.state is from strm2, so state->strm points to strm2 */
            void *tmp = strm1.state;
            strm1.state = strm2.state;
            (void)inflateUndermine(&strm1, subvert);
            /* Restore before cleanup */
            strm1.state = tmp;
            inflateEnd(&strm1);
            inflateEnd(&strm2);
            break;

        case 10: /* valid stream, initialize with different window bits and then undermine */
            memset(&strm, 0, sizeof(strm));
            /* Use a negative windowBits to get raw deflate stream (no header) */
            ret = inflateInit2(&strm, -8);
            if (ret != Z_OK)
                return 0;
            (void)inflateUndermine(&strm, subvert);
            inflateEnd(&strm);
            break;
    }

    /* This function must return 0. */
    return 0;
}