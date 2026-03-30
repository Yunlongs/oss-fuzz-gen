#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  /* Limit input size to 1 MB to avoid excessive memory usage. */
  if (size > 1 * 1024 * 1024)
    return 0;

  /* Use the first four bytes as parameters; default to zero if missing. */
  uint8_t flags = size > 0 ? data[0] : 0;
  uint8_t level_byte = size > 1 ? data[1] : 0;
  uint8_t size_byte = size > 2 ? data[2] : 0;
  /* fourth byte is currently unused, reserved for future extensions */

  /* The remainder is the source data. If size <= 4, sourceLen is zero. */
  const uint8_t *source = data + (size > 4 ? 4 : size);
  size_t sourceLen = size > 4 ? size - 4 : 0;

  /* Decode flags. */
  int use_compress2 = (flags & 0x01);   /* bit 0: also call compress2_z */
  int dest_null = (flags & 0x02);       /* bit 1: dest = NULL */
  int destLen_null = (flags & 0x04);    /* bit 2: destLen = NULL */
  int source_null = (flags & 0x08);     /* bit 3: source = NULL */

  /* Optionally set source to NULL to trigger Z_STREAM_ERROR. */
  if (source_null)
    source = NULL;

  /* Compute worst‑case compressed size. */
  z_size_t safeBound = compressBound_z((z_size_t)sourceLen);

  /* Prepare destination buffer and length for compress_z. */
  Bytef *dest = NULL;
  z_size_t destLen = 0;

  if (destLen_null) {
    /* destLen will be passed as NULL. */
    destLen = 0;
    if (!dest_null && safeBound != (z_size_t)-1 && safeBound > 0) {
      dest = (Bytef *)malloc(safeBound);
      if (!dest) return 0;
    } else {
      dest = NULL;
    }
  } else {
    if (dest_null) {
      /* dest = NULL, destLen > 0 triggers Z_STREAM_ERROR. */
      dest = NULL;
      destLen = (safeBound != (z_size_t)-1 && safeBound > 0) ? safeBound : 1;
    } else {
      /* Allocate a destination buffer. Size is derived from safeBound and size_byte. */
      if (safeBound != (z_size_t)-1) {
        destLen = safeBound + size_byte;   /* size_byte ∈ [0,255] */
        if (destLen == 0) destLen = 1;
        dest = (Bytef *)malloc(destLen);
        if (!dest) return 0;
      } else {
        /* Overflow in compressBound_z – cannot allocate a meaningful buffer. */
        destLen = 0;
        dest = NULL;
      }
    }
  }

  /* ---- REQUIRED CALL to compress_z ---- */
  int ret;
  if (destLen_null) {
    ret = compress_z(dest, NULL, source, (z_size_t)sourceLen);
  } else {
    ret = compress_z(dest, &destLen, source, (z_size_t)sourceLen);
  }

  /* If compression succeeded and we have a valid buffer, try decompression. */
  if (ret == Z_OK && dest != NULL && destLen > 0) {
    z_size_t uncompressedCapacity = (z_size_t)sourceLen;
    if (uncompressedCapacity > 0) {
      Bytef *uncompressed = (Bytef *)malloc(uncompressedCapacity);
      if (uncompressed) {
        z_size_t uncompressedLen = uncompressedCapacity;
        (void)uncompress_z(uncompressed, &uncompressedLen, dest, destLen);
        free(uncompressed);
      }
    }
  }

  /* ---- Additional call to compress2_z for extra coverage ---- */
  if (use_compress2 && safeBound != (z_size_t)-1) {
    Bytef *dest2 = (Bytef *)malloc(safeBound);
    if (dest2) {
      z_size_t destLen2 = safeBound;
      int level2 = level_byte;   /* full range 0‑255 */
      if (level2 == 10) {
        level2 = Z_DEFAULT_COMPRESSION;
      } else if (level2 > 10) {
        level2 = 100;   /* invalid level */
      }
      (void)compress2_z(dest2, &destLen2, source, (z_size_t)sourceLen, level2);
      free(dest2);
    }
  }

  free(dest);
  return 0;
}