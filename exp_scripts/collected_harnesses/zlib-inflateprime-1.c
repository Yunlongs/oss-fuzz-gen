#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const size_t kMaxSize = 1024 * 1024;
  if (size < 1 || size > kMaxSize)
    return 0;

  z_stream strm;
  memset(&strm, 0, sizeof(strm));

  if (inflateInit(&strm) != Z_OK) {
    return 0;
  }

  int bits = (signed char)data[0];
  int value = 0;
  if (size >= 3) {
    value = (data[1] << 8) | data[2];
  } else if (size >= 2) {
    value = data[1];
  }

  inflatePrime(&strm, bits, value);

  inflateEnd(&strm);
  return 0;
}