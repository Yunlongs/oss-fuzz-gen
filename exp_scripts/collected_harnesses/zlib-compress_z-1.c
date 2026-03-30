#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Discard inputs larger than 1Mb. */
  static size_t kMaxSize = 1024 * 1024;
  if (size > kMaxSize || size < 1)
    return 0;

  /* Extract a control byte to vary parameters. */
  uint8_t flags = data[0];
  data++;
  size--;

  /* Use the rest as source data. */
  z_size_t sourceLen = (z_size_t)size;
  const Bytef *source = data;

  /* Determine compression level: 0-9 from flags bits 0-3. */
  int level = flags & 0x0F;
  if (level > 9) level = 9;  /* clamp */

  /* Determine destination condition from bits 4-5. */
  int dest_condition = (flags >> 4) & 0x03;

  /* Bit 6: if set and sourceLen == 0, set source = NULL. */
  int source_null_flag = (flags >> 6) & 0x01;

  /* Bit 7: if set, pass NULL as destLen to compress2_z. */
  int destLen_null_flag = (flags >> 7) & 0x01;

  /* Optionally set source to NULL if sourceLen == 0 (allowed). */
  if (source_null_flag && sourceLen == 0) {
    source = NULL;
  }

  z_size_t destCapacity = 0;
  Bytef *dest = NULL;
  z_size_t destLen = 0;

  /* Compute a safe upper bound for the compressed size (used for some strategies). */
  z_size_t safeBound = compressBound_z(sourceLen);

  switch (dest_condition) {
    case 0: /* Sufficient buffer (if safeBound is valid) */
      if (safeBound == (z_size_t)-1) {
        /* Overflow; cannot allocate. */
        destCapacity = 0;
        dest = NULL;
        destLen = 0;
      } else {
        destCapacity = safeBound;
        destLen = destCapacity;
        dest = (Bytef *)malloc(destCapacity);
        if (!dest) return 0;
      }
      break;
    case 1: /* Small buffer (likely too small) */
      destCapacity = (sourceLen > 10) ? 10 : sourceLen;
      destLen = destCapacity;
      if (destCapacity > 0) {
        dest = (Bytef *)malloc(destCapacity);
        if (!dest) return 0;
      } else {
        dest = NULL;
      }
      break;
    case 2: /* Non‑NULL buffer but zero length */
      dest = (Bytef *)malloc(1);  /* dummy buffer, not dereferenced because destLen=0 */
      destLen = 0;
      break;
    case 3: /* NULL buffer with non‑zero length (should cause Z_STREAM_ERROR) */
      dest = NULL;
      destLen = 1;
      break;
  }

  int ret;
  if (destLen_null_flag) {
    /* Pass NULL as destLen to trigger Z_STREAM_ERROR. */
    ret = compress2_z(dest, NULL, source, sourceLen, level);
  } else {
    ret = compress2_z(dest, &destLen, source, sourceLen, level);
  }

  /* If compression succeeded and we have a valid buffer, try round‑trip decompression. */
  if (ret == Z_OK && dest != NULL && destLen > 0) {
    z_size_t uncompressedCapacity = sourceLen;
    Bytef *uncompressed = NULL;
    if (uncompressedCapacity > 0) {
      uncompressed = (Bytef *)malloc(uncompressedCapacity);
      if (uncompressed) {
        z_size_t uncompressedLen = uncompressedCapacity;
        int ret2 = uncompress_z(uncompressed, &uncompressedLen, dest, destLen);
        if (ret2 == Z_OK) {
          assert(uncompressedLen == sourceLen);
          assert(memcmp(source, uncompressed, sourceLen) == 0);
        }
        free(uncompressed);
      }
    } else if (sourceLen == 0) {
      /* Zero‑length source: nothing to compare. */
    }
  }

  free(dest); /* free(NULL) is safe. */
  return 0;
}