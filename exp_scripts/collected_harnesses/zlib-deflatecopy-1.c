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
  if (size < 6)
    return 0;

  /* Use the first byte to choose a scenario */
  uint8_t scenario = data[0] % 7;  /* 0..6 */
  data++; size--;

  /* Parse parameters from the next 5 bytes */
  int level = data[0] % 21 - 1;          /* -1 .. 19 (including invalid) */
  int windowBits = (int8_t)data[1];      /* full range -128..127 */
  int memLevel = data[2];                /* 0..255 */
  int strategy = data[3] % 10;           /* 0..9 (including invalid) */
  unsigned int dictSize = data[4];       /* 0..255 */
  data += 5; size -= 5;

  /* Ensure there is enough data for the dictionary and compression */
  if (dictSize > size)
    dictSize = size;
  const uint8_t *dict = data;
  const uint8_t *compData = data + dictSize;
  size_t compSize = size - dictSize;

  z_stream src, dest;
  int err;

  /* Initialize source stream based on scenario */
  if (scenario == 3) {
    /* Invalid stream: zalloc and zfree are NULL, state is NULL */
    src.zalloc = NULL;
    src.zfree = NULL;
    src.opaque = NULL;
    src.state = NULL;
  } else if (scenario == 4) {
    /* Initialize then end to set state to NULL */
    src.zalloc = Z_NULL;
    src.zfree = Z_NULL;
    src.opaque = Z_NULL;
    err = deflateInit2(&src, level, Z_DEFLATED, windowBits, memLevel, strategy);
    if (err == Z_OK)
      deflateEnd(&src);
    /* Now src.state should be NULL */
  } else {
    /* Valid stream initialization */
    src.zalloc = Z_NULL;
    src.zfree = Z_NULL;
    src.opaque = Z_NULL;
    err = deflateInit2(&src, level, Z_DEFLATED, windowBits, memLevel, strategy);
    if (err != Z_OK) {
      /* Initialization failed, src.state is NULL */
      /* We can still test deflateCopy on this stream (will fail) */
    } else {
      /* Initialization succeeded */
      if (dictSize > 0) {
        deflateSetDictionary(&src, dict, dictSize);
      }
      if (scenario == 1 && compSize > 0) {
        /* Compress some data without finishing -> BUSY_STATE */
        Bytef *out = (Bytef*)malloc(deflateBound(&src, compSize));
        if (out) {
          src.next_out = out;
          src.avail_out = deflateBound(&src, compSize);
          src.next_in = (Bytef*)compData;
          src.avail_in = compSize;
          deflate(&src, Z_NO_FLUSH);
          free(out);
        }
      } else if (scenario == 2 && compSize > 0) {
        /* Compress with Z_FINISH -> FINISH_STATE */
        Bytef *out = (Bytef*)malloc(deflateBound(&src, compSize));
        if (out) {
          src.next_out = out;
          src.avail_out = deflateBound(&src, compSize);
          src.next_in = (Bytef*)compData;
          src.avail_in = compSize;
          deflate(&src, Z_FINISH);
          free(out);
        }
      }
      /* scenario 0: INIT_STATE (do nothing) */
    }
  }

  /* Set dest based on scenario */
  if (scenario == 5) {
    /* dest is NULL */
    err = deflateCopy(NULL, &src);
  } else {
    dest.zalloc = Z_NULL;
    dest.zfree = Z_NULL;
    dest.opaque = Z_NULL;
    err = deflateCopy(&dest, &src);
    if (err == Z_OK) {
      deflateEnd(&dest);
    }
  }

  /* Cleanup source stream if it was successfully initialized */
  if (scenario != 3 && scenario != 4) {
    if (src.state != NULL) {
      deflateEnd(&src);
    }
  }

  /* This function must return 0. */
  return 0;
}