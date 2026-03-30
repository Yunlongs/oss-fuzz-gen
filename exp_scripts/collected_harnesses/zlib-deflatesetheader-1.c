#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
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

  /* Enhanced test for deflateSetHeader (requires at least 200 bytes). */
  if (dataLen >= 200) {
    z_stream strm;
    gz_header head;
    int ret;
    size_t used = 0;

    /* Determine wrap and initialization from the second byte. */
    uint8_t wrap_choice = data[1] % 3;          /* 0: raw, 1: zlib, 2: gzip */
    uint8_t init_invalid = data[1] & 0x80;      /* if non-zero, create invalid stream */

    /* Initialize the z_stream. */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.next_in = Z_NULL;
    strm.avail_in = 0;

    if (!init_invalid) {
      /* Proper initialization with the chosen wrap. */
      int windowBits;
      switch (wrap_choice) {
        case 0: windowBits = -15; break;  /* raw deflate */
        case 1: windowBits = 15; break;   /* zlib wrapper */
        default: windowBits = 15 + 16;    /* gzip wrapper */
      }
      ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                         windowBits, 8, Z_DEFAULT_STRATEGY);
      if (ret != Z_OK) {
        /* If initialization fails, skip the test. */
        return 0;
      }
    } else {
      /* Create an invalid stream by leaving strm uninitialized (zalloc and zfree are zero)
         or by initializing and then ending it. */
      if (wrap_choice == 0) {
        /* Option 1: leave as is (zalloc=zfree=0) -> deflateStateCheck will fail. */
      } else {
        /* Option 2: init and end to set state to NULL. */
        deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15+16, 8, Z_DEFAULT_STRATEGY);
        deflateEnd(&strm);
      }
    }

    /* Set up gz_header using bytes starting from index 2. */
    memset(&head, 0, sizeof(head));
    used = 2;
    if (used + sizeof(int) <= dataLen) {
      memcpy(&head.text, data + used, sizeof(int));
      used += sizeof(int);
    }
    if (used + sizeof(uLong) <= dataLen) {
      memcpy(&head.time, data + used, sizeof(uLong));
      used += sizeof(uLong);
    }
    if (used + sizeof(int) <= dataLen) {
      memcpy(&head.xflags, data + used, sizeof(int));
      used += sizeof(int);
    }
    if (used + sizeof(int) <= dataLen) {
      memcpy(&head.os, data + used, sizeof(int));
      used += sizeof(int);
    }
    if (used + sizeof(int) <= dataLen) {
      memcpy(&head.hcrc, data + used, sizeof(int));
      used += sizeof(int);
    }

    /* Set extra data if there is enough input. */
    if (used + 2 <= dataLen) {
      head.extra_len = (data[used] << 8) | data[used+1];
      used += 2;
      /* Limit extra_len to avoid excessive memory usage. */
      if (head.extra_len > 1000) head.extra_len = 1000;
      if (used + head.extra_len <= dataLen) {
        head.extra = (Bytef*)(data + used);
        used += head.extra_len;
      } else {
        head.extra = NULL;
        head.extra_len = 0;
      }
    }

    /* Set name (null-terminated string). */
    if (used < dataLen) {
      size_t name_len = 0;
      while (used + name_len < dataLen && data[used + name_len] != 0 && name_len < 1000)
        name_len++;
      if (used + name_len < dataLen) {
        head.name = (Bytef*)(data + used);
        used += name_len + 1; /* include the null terminator */
      }
    }

    /* Set comment (null-terminated string). */
    if (used < dataLen) {
      size_t comm_len = 0;
      while (used + comm_len < dataLen && data[used + comm_len] != 0 && comm_len < 1000)
        comm_len++;
      if (used + comm_len < dataLen) {
        head.comment = (Bytef*)(data + used);
        used += comm_len + 1;
      }
    }

    /* Call deflateSetHeader and check the result. */
    ret = deflateSetHeader(&strm, &head);
    if (init_invalid || wrap_choice != 2) {
      /* Expect an error. */
      assert(ret == Z_STREAM_ERROR);
    } else {
      /* Expect success. */
      assert(ret == Z_OK);
    }

    /* If the header was set successfully and the stream is valid, compress some data. */
    if (ret == Z_OK && !init_invalid && wrap_choice == 2) {
      size_t compr_len = compressBound(dataLen - used);
      Bytef *compr = (Bytef*)malloc(compr_len);
      if (compr) {
        strm.next_in = (Bytef*)(data + used);
        strm.avail_in = (uInt)(dataLen - used);
        strm.next_out = compr;
        strm.avail_out = (uInt)compr_len;
        ret = deflate(&strm, Z_FINISH);
        assert(ret == Z_STREAM_END || ret == Z_OK || ret == Z_BUF_ERROR);
        free(compr);
      }
    }

    /* Clean up only if we initialized the stream properly. */
    if (!init_invalid) {
      deflateEnd(&strm);
    }
  }

  /* This function must return 0. */
  return 0;
}