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

  /* Enhanced test for deflateUsed */
  {
    z_stream strm;
    int ret;
    int bits;
    unsigned char *compr;
    size_t comprLen;
    unsigned long len = dataLen;

    if (dataLen == 0) {
      return 0;
    }

    comprLen = compressBound(dataLen);
    compr = (unsigned char *)calloc(1, comprLen);
    if (compr == NULL) {
      return 0;
    }

    /* Test 1: NULL stream pointer */
    ret = deflateUsed(NULL, &bits);
    ret = deflateUsed(NULL, NULL);

    /* Test 2: Stream with zero allocators and no state */
    {
        z_stream invalid_strm;
        memset(&invalid_strm, 0, sizeof(invalid_strm));
        invalid_strm.zalloc = (alloc_func)0;
        invalid_strm.zfree = (free_func)0;
        invalid_strm.state = Z_NULL;
        ret = deflateUsed(&invalid_strm, &bits);
        ret = deflateUsed(&invalid_strm, NULL);
    }

    /* Test 3: Different wrapper modes */
    int wrap_modes[] = {0, 1, 2};  /* raw, zlib, gzip */
    for (int i = 0; i < 3; i++) {
        z_stream strm2;
        strm2.zalloc = Z_NULL;
        strm2.zfree = Z_NULL;
        strm2.opaque = Z_NULL;
        strm2.next_in = (Bytef *)data;
        strm2.next_out = compr;

        ret = deflateInit2(&strm2, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                           15 + (wrap_modes[i] == 2 ? 16 : 0), 8,
                           Z_DEFAULT_STRATEGY);
        if (ret != Z_OK) {
            continue;
        }

        /* For gzip, optionally set a header */
        if (wrap_modes[i] == 2) {
            gz_header head;
            memset(&head, 0, sizeof(head));
            head.os = 0;
            deflateSetHeader(&strm2, &head);
        }

        /* Compress a few bytes */
        strm2.avail_in = len > 10 ? 10 : len;
        strm2.avail_out = comprLen;
        ret = deflate(&strm2, Z_NO_FLUSH);
        /* Call deflateUsed regardless of deflate return value */
        ret = deflateUsed(&strm2, &bits);
        ret = deflateUsed(&strm2, NULL);

        /* Finish stream */
        strm2.avail_in = 0;
        ret = deflate(&strm2, Z_FINISH);
        ret = deflateUsed(&strm2, &bits);

        deflateEnd(&strm2);
    }

    /* Original test with more robust error handling */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.next_in = (Bytef *)data;
    strm.next_out = compr;

    ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        free(compr);
        return 0;
    }

    /* Compress in small chunks (1 byte at a time) */
    while (strm.total_in != len && strm.total_out < comprLen) {
        strm.avail_in = strm.avail_out = 1;
        ret = deflate(&strm, Z_NO_FLUSH);
        /* Call deflateUsed even on Z_BUF_ERROR */
        ret = deflateUsed(&strm, &bits);
        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            break;
        }
    }

    /* Finish the stream */
    for (;;) {
        strm.avail_out = 1;
        ret = deflate(&strm, Z_FINISH);
        ret = deflateUsed(&strm, &bits);
        if (ret == Z_STREAM_END) {
            break;
        }
        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            break;
        }
    }

    /* Test after deflateReset */
    ret = deflateReset(&strm);
    ret = deflateUsed(&strm, &bits);

    /* Test after deflateEnd (state becomes NULL) */
    deflateEnd(&strm);
    ret = deflateUsed(&strm, &bits);  /* Should return Z_STREAM_ERROR */

    free(compr);
  }

  /* This function must return 0. */
  return 0;
}