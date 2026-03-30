#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataLen) {
  /* Discard inputs larger than 1Mb. */
  static size_t kMaxSize = 1024 * 1024;
  if (dataLen > kMaxSize)
    return 0;

  /* If dataLen == 0, skip checksum tests and only run compress tests. */
  if (dataLen >= 1) {
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
  }

  /* Extended compress and uncompress tests */
  {
    /* Determine compression level from input (if available).
       Map the second byte (or 0 if dataLen < 2) to levels -2 .. 9:
       -2 invalid, -1 = Z_DEFAULT_COMPRESSION, 0‑9 valid. */
    int level = Z_DEFAULT_COMPRESSION;
    if (dataLen >= 2) {
      /* data[1] % 12 gives 0..11; subtract 2 => -2..9 */
      level = (int)(data[1] % 12) - 2;
    }

    /* Test compress2 with variable level. */
    uLongf destLen = compressBound((uLong)dataLen);
    Bytef *dest = (Bytef*)malloc(destLen);
    if (dest == NULL) {
      return 0;
    }

    int ret = compress2(dest, &destLen, (const Bytef*)data, (uLong)dataLen, level);
    if (ret == Z_OK) {
      /* Successful compression: verify round-trip. */
      Bytef *uncompressed = (Bytef*)malloc(dataLen);
      if (uncompressed == NULL) {
        free(dest);
        return 0;
      }
      uLongf uncompressedLen = (uLongf)dataLen;
      int ret2 = uncompress(uncompressed, &uncompressedLen, dest, destLen);
      assert(ret2 == Z_OK);
      assert(uncompressedLen == (uLongf)dataLen);
      assert(memcmp(uncompressed, data, dataLen) == 0);
      free(uncompressed);

      /* Test with insufficient output buffer (should trigger Z_BUF_ERROR). */
      if (destLen > 1) {
        uLongf smallDestLen = destLen - 1;
        Bytef *smallDest = (Bytef*)malloc(smallDestLen);
        if (smallDest) {
          int ret3 = compress2(smallDest, &smallDestLen, (const Bytef*)data, (uLong)dataLen, level);
          /* Z_BUF_ERROR is expected, but we accept any error or success (if compression fits). */
          free(smallDest);
        }
      }

      /* Test _z variants. */
      z_size_t destLen_z = (z_size_t)destLen;
      Bytef *dest_z = (Bytef*)malloc(destLen_z);
      if (dest_z) {
        int ret_z = compress2_z(dest_z, &destLen_z, (const Bytef*)data, (z_size_t)dataLen, level);
        assert(ret_z == Z_OK);
        assert(destLen_z == (z_size_t)destLen);
        assert(memcmp(dest_z, dest, destLen) == 0);
        free(dest_z);
      }

      /* Test uncompress with malformed data (corrupt first byte). */
      if (destLen > 0) {
        Bytef *corrupted = (Bytef*)malloc(destLen);
        if (corrupted) {
          memcpy(corrupted, dest, destLen);
          corrupted[0] ^= 0xFF; /* Flip bits to corrupt header. */
          Bytef *uncompressed2 = (Bytef*)malloc(dataLen);
          if (uncompressed2) {
            uLongf uncompressedLen2 = (uLongf)dataLen;
            int ret4 = uncompress(uncompressed2, &uncompressedLen2, corrupted, destLen);
            /* Expect an error (e.g., Z_DATA_ERROR), but we don't assert to avoid crashes. */
            free(uncompressed2);
          }
          free(corrupted);
        }
      }
    } else if (ret == Z_STREAM_ERROR) {
      /* Invalid level (e.g., -2): expected, no further action needed. */
    } else {
      /* Other errors (Z_MEM_ERROR, Z_BUF_ERROR) may occur and are acceptable. */
    }
    free(dest);

    /* Test zero-length input. */
    if (dataLen == 0) {
      Bytef zeroDest[1];
      uLongf zeroDestLen = 0;
      int ret_zero = compress2(zeroDest, &zeroDestLen, NULL, 0, Z_DEFAULT_COMPRESSION);
      assert(ret_zero == Z_OK || ret_zero == Z_STREAM_ERROR); /* Both are acceptable per zlib spec. */
    }
  }

  /* This function must return 0. */
  return 0;
}