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

  /* Adler32 - original property test (keep existing coverage) */
  for (offset = 0; offset + buffSize <= dataLen; offset += buffSize)
    adler1 = adler32_z(adler1, data + offset, buffSize);
  adler1 = adler32_z(adler1, data + offset, dataLen % buffSize);

  adler2 = adler32(adler2, data, (uint32_t) dataLen);

  assert(adler1 == adler2);
  assert(adler32_combine64(adler1, adler2, (z_off64_t)dataLen) ==
         adler32_combine64(adler1, adler1, (z_off64_t)dataLen));

  /* New: Extended test for adler32_combine64 and adler32_combine with varied inputs */
  if (dataLen >= 8) {
    /* Extract a signed 64-bit length from the first 8 bytes (little-endian) */
    union {
      uint8_t bytes[8];
      z_off64_t len2;
    } u;
    memcpy(u.bytes, data, 8);
    z_off64_t len2 = u.len2;

    /* Compute two different Adler-32 checksums from the remaining data */
    uLong adler3 = adler32(0L, NULL, 0);
    uLong adler4 = adler32(0L, NULL, 0);
    size_t remaining = dataLen - 8;
    if (remaining > 0) {
      /* Split remaining data into two parts for different checksums */
      size_t half = remaining / 2;
      adler3 = adler32(adler3, data + 8, (uInt)half);
      adler4 = adler32(adler4, data + 8 + half, (uInt)(remaining - half));
    }

    /* Test adler32_combine64 */
    uLong combined64 = adler32_combine64(adler3, adler4, len2);
    /* Test adler32_combine (32-bit version) */
    uLong combined32 = adler32_combine(adler3, adler4, (z_off_t)len2);

    /* For non-negative len2 that fits in 32 bits, results should be equal */
    if (len2 >= 0 && len2 <= 0x7fffffff) {
      assert(combined64 == combined32);
    }

    /* If len2 is negative, both functions should return 0xffffffffUL */
    if (len2 < 0) {
      assert(combined64 == 0xffffffffUL);
      assert(combined32 == 0xffffffffUL);
    }

    /* Additional sanity: combining with zero length should return the first checksum */
    if (len2 == 0) {
      assert(combined64 == adler3);
      assert(combined32 == adler3);
    }
  }

  /* This function must return 0. */
  return 0;
}