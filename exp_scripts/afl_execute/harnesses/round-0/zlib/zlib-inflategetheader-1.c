#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Reject empty or excessively large inputs. */
    if (size == 0 || size > 1024 * 1024) return 0;

    /* Use first byte for windowBits (range -15..40, covering valid and invalid). */
    int windowBits = (int)(data[0] % 56) - 15;
    /* Use second byte for flags; if size==1, flags=0. */
    int flags = size > 1 ? data[1] : 0;

    z_stream strm;
    gz_header head;
    memset(&strm, 0, sizeof(strm));
    memset(&head, 0, sizeof(head));

    /* Set up gz_header buffers if bit 0 is set. */
    unsigned char extra_buf[1024];
    unsigned char name_buf[1024];
    unsigned char comment_buf[1024];
    if (flags & 1) {
        head.extra = extra_buf;
        head.extra_len = sizeof(extra_buf);
        head.name = name_buf;
        head.name_max = sizeof(name_buf);
        head.comment = comment_buf;
        head.comm_max = sizeof(comment_buf);
    }

    /* Initialize stream; may fail for invalid windowBits. */
    int ret = inflateInit2(&strm, windowBits);

    /* Call inflateGetHeader regardless of initialization success. */
    (void)inflateGetHeader(&strm, &head);

    if (ret != Z_OK) {
        /* If initialization failed, we still exercised error paths. */
        return 0;
    }

    /* Inflate the remaining input (bytes 2..end). */
    const uint8_t *inflate_input = data + (size > 2 ? 2 : size);
    uInt inflate_len = (uInt)(size > 2 ? size - 2 : 0);
    unsigned char out[65536];
    strm.next_in = (Bytef *)inflate_input;
    strm.avail_in = inflate_len;
    strm.next_out = out;
    strm.avail_out = sizeof(out);

    do {
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret < 0) break; /* Z_STREAM_ERROR, Z_DATA_ERROR, Z_MEM_ERROR, Z_BUF_ERROR */
    } while (strm.avail_out > 0 && ret != Z_STREAM_END);

    /* Optionally call inflateGetHeader again if header was read. */
    if (head.done == 1) {
        (void)inflateGetHeader(&strm, &head);
    }

    inflateEnd(&strm);
    return 0;
}