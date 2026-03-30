#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static size_t kMaxSize = 1024 * 1024;
  if (size == 0 || size > kMaxSize)
    return 0;

  /* Use the first byte as a bitmask for parameter selection. */
  uint8_t flags = data[0];
  data++; size--;

  /* Use the second byte (if available) for additional control. */
  uint8_t extra = 0;
  if (size > 0) {
    extra = data[0];
    data++; size--;
  }

  /* Determine destination buffer size based on bits 5‑6 of flags. */
  unsigned int scale = (flags >> 5) & 3;
  z_size_t destLen = 0;
  if (size > 0) {
    switch (scale) {
      case 0: destLen = 1; break;
      case 1: destLen = (z_size_t)size / 4 + 1; break;
      case 2: destLen = (z_size_t)size; break;
      case 3: destLen = (z_size_t)size * 2; break;
    }
  }
  /* Cap destLen to avoid huge allocations. */
  if (destLen > kMaxSize)
    destLen = kMaxSize;

  Bytef *dest = NULL;
  const Bytef *source = data;
  z_size_t sourceLen = (z_size_t)size;

  /* Apply parameter flags. */
  if (flags & 0x01) dest = NULL;          /* bit 0: dest = NULL */
  if (flags & 0x02) source = NULL;        /* bit 1: source = NULL */
  if (flags & 0x04) dest = Z_NULL;        /* bit 2: dest = Z_NULL (overrides NULL) */
  if (flags & 0x08) destLen = 0;          /* bit 3: destLen = 0 */
  if (flags & 0x10) sourceLen = 0;        /* bit 4: sourceLen = 0 */

  /* If bit4 is not set, use extra bits 0‑1 to adjust sourceLen. */
  if (!(flags & 0x10)) {
    switch (extra & 0x03) {
      case 0: sourceLen = 0; break;
      case 1: sourceLen = 1; break;
      case 2: sourceLen = (z_size_t)size / 2; break;
      case 3: sourceLen = (z_size_t)size; break;
    }
  }

  /* Allocate destination buffer if needed. Use stack for small buffers to avoid malloc failure. */
  Bytef stack_buf[1024];
  int allocated = 0;
  if (dest == NULL && !(flags & 0x04) && destLen > 0) {
    if (destLen <= sizeof(stack_buf)) {
      dest = stack_buf;
    } else {
      dest = (Bytef *)malloc(destLen);
      if (!dest) return 0;
      allocated = 1;
    }
  } else if (dest == NULL && destLen == 0) {
    /* If both dest and destLen are zero, use Z_NULL to allow internal buffer. */
    dest = Z_NULL;
  }

  /* Call uncompress_z with the chosen parameters. */
  int ret = uncompress_z(dest, &destLen, source, sourceLen);
  (void)ret;

  /* Free the destination buffer if we allocated it with malloc. */
  if (allocated)
    free(dest);

  /* If bit 7 is set and there is at least one more byte, perform a compression‑decompression round‑trip. */
  if ((flags & 0x80) && size > 0) {
    /* Use 'extra' as compression parameters. */
    int level = extra % 10;                 /* 0‑9 */
    int strategy = (extra / 10) % 4;        /* 0‑3 */

    /* Use the entire remaining input for compression. */
    size_t part = size;  /* size is the remaining data after consuming two bytes. */
    const uint8_t *comp_data = data;

    z_size_t comprLen = compressBound_z((z_size_t)part);
    if (comprLen <= 2 * kMaxSize) {
      Bytef *compr = (Bytef *)malloc(comprLen);
      if (compr) {
        /* Use compress2_z with the specified level and strategy. */
        if (compress2_z(compr, &comprLen, comp_data, (z_size_t)part, level) == Z_OK) {
          /* Decompress with an output buffer of exactly the original size. */
          z_size_t uncomprLen = (z_size_t)part;
          Bytef *uncompr = (Bytef *)malloc(uncomprLen);
          if (uncompr) {
            int ret1 = uncompress_z(uncompr, &uncomprLen, compr, comprLen);
            if (ret1 == Z_OK) {
              assert(uncomprLen == (z_size_t)part);
              assert(memcmp(comp_data, uncompr, part) == 0);
            }
            free(uncompr);
          }

          /* Decompress with a buffer that is too small (may trigger Z_BUF_ERROR). */
          z_size_t smallLen = (z_size_t)part / 2;
          if (smallLen == 0) smallLen = 1;
          Bytef *smallOut = (Bytef *)malloc(smallLen);
          if (smallOut) {
            int ret2 = uncompress_z(smallOut, &smallLen, compr, comprLen);
            (void)ret2;
            free(smallOut);
          }
        }
        free(compr);
      }
    }
  }

  return 0;
}