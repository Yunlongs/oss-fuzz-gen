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

  /* Test inflateCopy */
  {
    int ret;
    z_stream src, dest;
    unsigned char out[1024];

    /* Test error case */
    ret = inflateCopy(Z_NULL, Z_NULL);
    assert(ret == Z_STREAM_ERROR);

    /* Try different window bits to create varied stream states */
    int windowBits[] = {8, 15, -8, -15, 15 + 32, 31};
    for (size_t i = 0; i < sizeof(windowBits) / sizeof(windowBits[0]); ++i) {
      src.zalloc = Z_NULL;
      src.zfree = Z_NULL;
      src.opaque = Z_NULL;
      src.next_in = (Bytef*)data;
      src.avail_in = (uInt)dataLen;
      src.next_out = out;
      src.avail_out = sizeof(out);

      ret = inflateInit2(&src, windowBits[i]);
      if (ret != Z_OK) {
        /* If initialization fails, try next set of parameters */
        continue;
      }

      /* Attempt to inflate to create a more interesting state */
      (void)inflate(&src, Z_NO_FLUSH);

      /* Copy the stream state */
      ret = inflateCopy(&dest, &src);

      if (ret == Z_OK) {
        /* Verify that the copied stream matches the source in public fields */
        assert(dest.adler == src.adler);
        assert(dest.total_in == src.total_in);
        assert(dest.total_out == src.total_out);
        assert(dest.data_type == src.data_type);
        /* Clean up the destination stream */
        inflateEnd(&dest);
      } else {
        /* inflateCopy failed, which is acceptable (e.g., Z_MEM_ERROR) */
        /* Ensure dest is not in an undefined state */
        /* No cleanup needed because inflateCopy cleans up on failure */
      }

      /* Clean up the source stream */
      inflateEnd(&src);
    }
  }

  /* This function must return 0. */
  return 0;
}