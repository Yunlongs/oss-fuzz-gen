#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataLen) {
  uint32_t crc0 = crc32(0L, NULL, 0);
  uint32_t crc1 = crc0;
  uint32_t crc2 = crc0;
  uint32_t adler0 = adler32(0L, NULL, 0);
  uint32_t adler1 = adler0;
  uint32_t adler2 = adler0;
  /* Checksum with a buffer of size equal to the first byte in the input. */
  uint32_t buffSize = data[0];
  uint32_t offset = 0;
  uint32_t op;

  /* Discard inputs larger than 1Mb. */
  static size_t kMaxSize = 1024 * 1024;
  if (dataLen < 1 || dataLen > kMaxSize)
    return 0;

  /* Make sure the buffer has at least a byte. */
  if (buffSize == 0)
    ++buffSize;

  /* CRC32 */
  op = crc32_combine_gen(buffSize);
  for (offset = 0; offset + buffSize <= dataLen; offset += buffSize) {
    uint32_t crc3 = crc32_z(crc0, data + offset, buffSize);
    uint32_t crc4 = crc32_combine_op(crc1, crc3, op);
    crc1 = crc32_z(crc1, data + offset, buffSize);
    assert(crc1 == crc4);
  }
  crc1 = crc32_z(crc1, data + offset, dataLen % buffSize);

  crc2 = crc32(crc2, data, (uint32_t) dataLen);

  assert(crc1 == crc2);
  assert(crc32_combine(crc1, crc2, dataLen) ==
         crc32_combine(crc1, crc1, dataLen));

  /* Fast CRC32 combine. */
  op = crc32_combine_gen(dataLen);
  assert(crc32_combine_op(crc1, crc2, op) ==
         crc32_combine_op(crc2, crc1, op));
  assert(crc32_combine(crc1, crc2, dataLen) ==
         crc32_combine_op(crc2, crc1, op));

  /* Adler32 */
  for (offset = 0; offset + buffSize <= dataLen; offset += buffSize)
    adler1 = adler32_z(adler1, data + offset, buffSize);
  adler1 = adler32_z(adler1, data + offset, dataLen % buffSize);

  adler2 = adler32(adler2, data, (uint32_t) dataLen);

  assert(adler1 == adler2);
  assert(adler32_combine(adler1, adler2, dataLen) ==
         adler32_combine(adler1, adler1, dataLen));

  /* Enhanced gzfwrite fuzzing */
  if (dataLen >= 12) {
    uint8_t control = data[1];
    uint8_t mode_idx = data[2];
    uint32_t size_u32, nitems_u32;
    memcpy(&size_u32, data + 3, sizeof(uint32_t));
    memcpy(&nitems_u32, data + 7, sizeof(uint32_t));

    z_size_t size = (z_size_t)size_u32;
    z_size_t nitems = (z_size_t)nitems_u32;

    /* Control flags */
    int size_zero = control & 0x01;
    int overflow = control & 0x02;
    int null_file = control & 0x04;
    int do_seek = control & 0x08;
    int two_writes = control & 0x10;
    int three_writes = control & 0x20;
    int zero_nitems = control & 0x40;
    int boundary = (control >> 7) & 0x01; /* 0 for small, 1 for large */

    /* Mode selection */
    const char *modes[] = {
        "wb",   /* 0: compressed write */
        "wT",   /* 1: transparent write */
        "wbN",  /* 2: non‑blocking write (if supported) */
        "rb",   /* 3: read‑only */
        "ab",   /* 4: append */
        NULL,   /* 5: explicit NULL file */
        "?",    /* 6: invalid mode */
        "wx",   /* 7: exclusive create (may fail) */
    };
    if (mode_idx >= 8) mode_idx = 0;
    const char *mode = modes[mode_idx];

    /* Special cases */
    if (size_zero) {
        size = 0;
        overflow = 0;  /* overflow not relevant when size is zero */
    }
    if (overflow) {
        size = (z_size_t)-1;
        nitems = 2;
    }
    if (zero_nitems) {
        nitems = 0;
        overflow = 0;  /* overflow not relevant when nitems is zero */
    }

    const uint8_t *buf = data + 11;
    size_t buf_len = dataLen - 11;

    /* Adjust size and nitems for boundary testing if not overflow and size > 0 and nitems > 0 */
    if (!overflow && size > 0 && nitems > 0) {
        if (boundary) {
            /* Force len to be exactly 8192 (state->size) */
            if (size > 8192) {
                size = 8192;
                nitems = 1;
            } else if (size == 0) {
                size = 1;
            }
            /* Adjust nitems so that len == 8192 */
            z_size_t target = 8192;
            nitems = (z_size_t)(target / size);
            if (nitems == 0) nitems = 1;
            if (size * nitems < target) {
                size = target / nitems;
                if (size == 0) size = 1;
            }
        } else {
            /* Force len to be 8191 (just below the buffer size) */
            if (size > 8191) {
                size = 8191;
                nitems = 1;
            }
            z_size_t target = 8191;
            nitems = (z_size_t)(target / size);
            if (nitems == 0) nitems = 1;
            if (size * nitems < target) {
                size = target / nitems;
                if (size == 0) size = 1;
            }
        }
    }

    /* Compute len and adjust nitems to fit buffer if not overflow and size > 0 and nitems > 0 */
    z_size_t len = 0;
    if (!overflow && size > 0 && nitems > 0) {
        /* Avoid overflow in multiplication */
        if (nitems > 0 && size > (z_size_t)-1 / nitems) {
            overflow = 1;
            size = (z_size_t)-1;
            nitems = 2;
        } else {
            len = size * nitems;
            if (len > buf_len) {
                /* Reduce nitems to fit available buffer */
                nitems = (z_size_t)(buf_len / size);
                if (nitems == 0) {
                    nitems = 1;
                    size = buf_len;
                }
                len = size * nitems;
            }
        }
    }

    gzFile file = NULL;
    char fname[] = "gzfwrite_fuzz.XXXXXX";
    int fd = -1;

    /* Create temporary file if we are going to open one */
    if (!null_file && mode != NULL && mode_idx != 5 && mode_idx != 6) {
        fd = mkstemp(fname);
        if (fd < 0) return 0;
        if (mode_idx == 2) {
            /* Set non‑blocking flag on the file descriptor */
            int flags = fcntl(fd, F_GETFL, 0);
            if (flags != -1) {
                fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            }
        }
        close(fd);
        file = gzopen(fname, mode);
    } else if (mode_idx == 5 || null_file) {
        /* Explicit NULL file */
        file = NULL;
    } else if (mode_idx == 6 || mode_idx == 7) {
        /* Invalid or exclusive mode, attempt to open */
        fd = mkstemp(fname);
        if (fd < 0) return 0;
        close(fd);
        file = gzopen(fname, mode);
    }

    /* If file is open or null, perform operations */
    if (file != NULL || null_file || mode_idx == 5 || mode_idx == 6 || mode_idx == 7) {
        /* Seek if requested and file is open and buffer has at least 2 bytes */
        if (do_seek && file != NULL && buf_len >= 2) {
            long offset = (long)((buf[0] * 256 + buf[1]) % 10000);
            gzseek(file, offset, SEEK_SET);
        }

        /* First write */
        gzfwrite(buf, size, nitems, file);

        /* Second write if requested and buffer remains */
        if (two_writes && !overflow && size > 0 && nitems > 0 && len <= buf_len) {
            const uint8_t *buf2 = buf + len;
            size_t buf2_len = buf_len - len;
            z_size_t nitems2 = (z_size_t)(buf2_len / size);
            if (nitems2 > 0) {
                /* Seek between writes if do_seek is set and we have a file and enough buffer */
                if (do_seek && file != NULL && buf2_len >= 2) {
                    long offset2 = (long)((buf2[0] * 256 + buf2[1]) % 10000);
                    gzseek(file, offset2, SEEK_CUR);
                }
                gzfwrite(buf2, size, nitems2, file);
            }
        }

        /* Third write if requested and buffer remains */
        if (three_writes && !overflow && size > 0 && nitems > 0 && len <= buf_len) {
            const uint8_t *buf2 = buf + len;
            size_t buf2_len = buf_len - len;
            z_size_t nitems2 = (z_size_t)(buf2_len / size);
            if (nitems2 > 0) {
                const uint8_t *buf3 = buf2 + size * nitems2;
                size_t buf3_len = buf2_len - size * nitems2;
                z_size_t nitems3 = (z_size_t)(buf3_len / size);
                if (nitems3 > 0) {
                    gzfwrite(buf3, size, nitems3, file);
                }
            }
        }

        if (file != NULL) {
            gzclose(file);
        }
    }

    /* Clean up temporary file if created */
    if (fd >= 0) {
        remove(fname);
    }
  }

  /* This function must return 0. */
  return 0;
}