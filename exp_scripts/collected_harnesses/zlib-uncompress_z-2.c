#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

/* Maximum size for stack‑allocated buffers. */
#define STACK_MAX (64 * 1024)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static size_t kMaxSize = 1024 * 1024;
  if (size == 0 || size > kMaxSize)
    return 0;

  uint8_t flags = data[0];   /* use first byte as control, but don't consume it */

  /* ------------------------------------------------------------------------
   * 1. Compression‑decompression round‑trip with varying levels/strategies.
   * ------------------------------------------------------------------------ */
  {
    int level = flags % 10;                 /* 0‑9 */
    int strategy = (flags / 10) % 4;        /* 0‑3 */

    /* Compress the entire input. */
    z_size_t comprLen = compressBound_z((z_size_t)size);
    if (comprLen <= 2 * kMaxSize) {
      Bytef *compr = (Bytef *)malloc(comprLen);
      if (compr) {
        if (compress2_z(compr, &comprLen, data, (z_size_t)size, level) == Z_OK) {
          /* Decompress with exact buffer size. */
          z_size_t uncomprLen = (z_size_t)size;
          Bytef *uncompr = (Bytef *)malloc(uncomprLen);
          if (uncompr) {
            int ret = uncompress_z(uncompr, &uncomprLen, compr, comprLen);
            if (ret == Z_OK) {
              assert(uncomprLen == (z_size_t)size);
              assert(memcmp(data, uncompr, size) == 0);
            }
            free(uncompr);
          }

          /* Decompress with a buffer that is too small. */
          z_size_t smallLen = (z_size_t)size / 2;
          if (smallLen == 0) smallLen = 1;
          Bytef *smallOut = (Bytef *)malloc(smallLen);
          if (smallOut) {
            (void)uncompress_z(smallOut, &smallLen, compr, comprLen);
            free(smallOut);
          }

          /* Decompress only a prefix of the compressed data with a tiny buffer,
             which may trigger Z_BUF_ERROR with no input left. */
          if (comprLen > 1) {
            z_size_t prefixLen = comprLen / 2;
            z_size_t tinyOutLen = 1;
            Bytef *tinyOut = (Bytef *)malloc(tinyOutLen);
            if (tinyOut) {
              (void)uncompress_z(tinyOut, &tinyOutLen, compr, prefixLen);
              free(tinyOut);
            }
          }
        }
        free(compr);
      }
    }
  }

  /* ------------------------------------------------------------------------
   * 2. Decompress raw input (likely invalid) with various buffer sizes.
   * ------------------------------------------------------------------------ */
  {
    unsigned int scale = (flags >> 5) & 3;
    z_size_t destLen = 0;
    switch (scale) {
      case 0: destLen = 0; break;                     /* zero‑length buffer */
      case 1: destLen = (z_size_t)size / 4 + 1; break;
      case 2: destLen = (z_size_t)size; break;
      case 3: destLen = (z_size_t)size * 2; break;
    }
    if (destLen > kMaxSize) destLen = kMaxSize;

    Bytef stack_buf[STACK_MAX];
    Bytef *dest = NULL;
    int allocated = 0;

    if (destLen == 0) {
      /* For zero‑length buffer, use Z_NULL to allow internal buffer. */
      dest = Z_NULL;
    } else if (destLen <= STACK_MAX) {
      dest = stack_buf;
    } else {
      dest = (Bytef *)malloc(destLen);
      if (!dest) {
        dest = stack_buf;
        destLen = STACK_MAX;
      } else {
        allocated = 1;
      }
    }

    (void)uncompress_z(dest, &destLen, data, (z_size_t)size);

    if (allocated) free(dest);
  }

  /* ------------------------------------------------------------------------
   * 3. Invalid‑parameter tests (using stack buffers to avoid malloc failures).
   * ------------------------------------------------------------------------ */
  {
    Bytef stack_buf[STACK_MAX];
    z_size_t destLen = (z_size_t)size;
    if (destLen > STACK_MAX) destLen = STACK_MAX;
    const Bytef *source = data;
    z_size_t sourceLen = (z_size_t)size;

    /* Case A: dest = NULL, destLen > 0 */
    (void)uncompress_z(NULL, &destLen, source, sourceLen);

    /* Case B: source = NULL, sourceLen > 0 */
    (void)uncompress_z(stack_buf, &destLen, NULL, sourceLen);

    /* Case C: dest = Z_NULL, destLen = 0 */
    destLen = 0;
    (void)uncompress_z(Z_NULL, &destLen, source, sourceLen);

    /* Case D: dest = Z_NULL, destLen > 0 */
    destLen = (z_size_t)size;
    if (destLen > STACK_MAX) destLen = STACK_MAX;
    (void)uncompress_z(Z_NULL, &destLen, source, sourceLen);

    /* Case E: sourceLen = 0 */
    sourceLen = 0;
    (void)uncompress_z(stack_buf, &destLen, source, sourceLen);

    /* Case F: dest = stack_buf, destLen = 0 (non‑Z_NULL zero‑length buffer) */
    destLen = 0;
    (void)uncompress_z(stack_buf, &destLen, source, sourceLen);
  }

  return 0;
}