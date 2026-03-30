#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Reject empty or excessively large inputs. */
    if (size == 0 || size > 1024 * 1024) return 0;

    /* Use first byte to select mode. */
    int mode = data[0] % 4;
    int inject_gzip = (mode == 0) ? 1 : 0;  /* only in mode 0 */
    int windowBits;
    int skip_init = 0;

    switch (mode) {
        case 0:
        case 1:
            windowBits = 31;  /* gzip mode */
            break;
        case 2:
            windowBits = 0;   /* no wrapper, will cause wrap & 2 == 0 */
            break;
        case 3:
            skip_init = 1;    /* do not call inflateInit2 */
            windowBits = 31;  /* unused */
            break;
    }

    z_stream strm;
    gz_header head;
    memset(&strm, 0, sizeof(strm));
    memset(&head, 0, sizeof(head));

    /* Always set up buffers. */
    unsigned char extra_buf[1024];
    unsigned char name_buf[1024];
    unsigned char comment_buf[1024];
    head.extra = extra_buf;
    head.extra_len = sizeof(extra_buf);
    head.name = name_buf;
    head.name_max = sizeof(name_buf);
    head.comment = comment_buf;
    head.comm_max = sizeof(comment_buf);

    int ret = Z_OK;
    if (!skip_init) {
        ret = inflateInit2(&strm, windowBits);
    }

    /* First call to inflateGetHeader. */
    (void)inflateGetHeader(&strm, &head);

    if (ret == Z_OK && !skip_init) {
        /* Prepare inflation input: start at byte 1, limit to 64KB. */
        const uint8_t *inflate_input = data + 1;
        uInt inflate_len = (uInt)(size - 1);
        if (inflate_len > 65536) inflate_len = 65536;

        unsigned char *modified_input = NULL;
        if (inject_gzip && inflate_len >= 2) {
            modified_input = (unsigned char *)malloc(inflate_len);
            if (modified_input) {
                memcpy(modified_input, inflate_input, inflate_len);
                modified_input[0] = 0x1f;
                modified_input[1] = 0x8b;
                inflate_input = modified_input;
            }
        }

        unsigned char out[65536];
        strm.next_in = (Bytef *)inflate_input;
        strm.avail_in = inflate_len;
        strm.next_out = out;
        strm.avail_out = sizeof(out);

        int iterations = 0;
        const int max_iterations = 100;
        do {
            ret = inflate(&strm, Z_NO_FLUSH);
            if (ret < 0) break; /* error */
            iterations++;
            if (iterations >= max_iterations) break;
        } while (strm.avail_out > 0 && ret != Z_STREAM_END);

        /* Call inflateGetHeader again if header was read. */
        if (head.done == 1) {
            (void)inflateGetHeader(&strm, &head);
        }

        if (modified_input) free(modified_input);
        inflateEnd(&strm);
    }
    return 0;
}