#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataLen) {
  static const size_t kMaxSize = 1024 * 1024;
  if (dataLen > kMaxSize)
    return 0;

  /* Extract parameters from input with defaults */
  size_t offset = 0;
  
  int level = Z_DEFAULT_COMPRESSION;
  int strategy = Z_DEFAULT_STRATEGY;
  int wrap = 0;
  int memLevel = 8;
  int windowBits = 15;
  int setGzipHeader = 0;
  int usePrime = 0;
  int primeBits = 0;
  int primeValue = 0;

  /* Use available bytes for parameters, don't require minimum size */
  if (offset < dataLen) level = data[offset++] % 11; /* 0-10 (including Z_NO_COMPRESSION=0) */
  if (offset < dataLen) strategy = data[offset++] % 5;
  if (offset < dataLen) wrap = data[offset++] % 3;
  if (offset < dataLen) memLevel = (data[offset++] % 9) + 1;
  if (offset < dataLen) {
    int windowBitsParam = data[offset++] % 16;
    /* Map to valid windowBits based on wrap */
    if (wrap == 0) {
      windowBits = 8 + (windowBitsParam % 8);  /* 8..15 */
    } else if (wrap == 1) {
      windowBits = 16 + 8 + (windowBitsParam % 8); /* 24..31 (16+8..16+15) */
    } else {
      windowBits = -8 - (windowBitsParam % 8); /* -8..-15 */
    }
  }
  if (offset < dataLen) setGzipHeader = (wrap == 1) && (data[offset++] & 1);
  if (offset < dataLen) usePrime = data[offset++] & 1;
  if (offset < dataLen && dataLen - offset >= 1) {
    primeBits = data[offset] % 9;  /* 0-8 bits */
    primeValue = (offset + 1 < dataLen) ? data[offset + 1] : 0;
    offset += 2;
  }

  const uint8_t *input = data + offset;
  size_t inputLen = dataLen - offset;

  z_stream strm;
  unsigned pending;
  int bits;
  int ret;

  /* Test 1: Invalid stream state with varying initialization */
  {
    z_stream invalid_strm;
    /* Partially initialize based on input to create different invalid states */
    memset(&invalid_strm, 0, sizeof(invalid_strm));
    if (dataLen > 0) {
      /* Use first byte to vary zalloc, zfree, opaque pointers */
      uint8_t first_byte = data[0];
      invalid_strm.zalloc = (first_byte & 1) ? Z_NULL : (alloc_func)0x1;
      invalid_strm.zfree = (first_byte & 2) ? Z_NULL : (free_func)0x1;
      invalid_strm.opaque = (first_byte & 4) ? Z_NULL : (void*)0x1;
    }
    (void)deflatePending(&invalid_strm, &pending, &bits);
  }

  /* Test 2: Try to initialize a stream with extracted parameters */
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;

  ret = deflateInit2(&strm, level, Z_DEFLATED, windowBits, memLevel, strategy);
  
  /* Always test deflatePending on the stream, regardless of initialization success */
  deflatePending(&strm, NULL, &bits);
  deflatePending(&strm, &pending, NULL);
  deflatePending(&strm, NULL, NULL);
  deflatePending(&strm, &pending, &bits);

  /* If initialization failed, clean up and return (we've already tested error path) */
  if (ret != Z_OK) {
    if (ret == Z_STREAM_ERROR) {
      /* Stream is already in error state, deflateEnd may not be safe */
      return 0;
    }
    deflateEnd(&strm);
    return 0;
  }

  /* Stream initialized successfully - proceed with compression tests */

  /* Set gzip header if requested */
  if (setGzipHeader && wrap == 1) {
    gz_header gzhead;
    memset(&gzhead, 0, sizeof(gzhead));
    if (inputLen > 0) {
      gzhead.name = (Bytef *)input;
      gzhead.name_max = (uint)inputLen;
      gzhead.comment = (Bytef *)input;
      gzhead.comm_max = (uint)inputLen;
      gzhead.extra = (Bytef *)input;
      gzhead.extra_max = (uint)inputLen;
      deflateSetHeader(&strm, &gzhead);
    }
  }

  /* Optionally prime the bit buffer */
  if (usePrime) {
    deflatePrime(&strm, primeBits, primeValue);
  }

  /* Process input data if available */
  if (inputLen > 0) {
    strm.avail_in = (uInt)inputLen;
    strm.next_in = (Bytef *)input;

    Bytef out[32];
    int flush_modes[] = {Z_NO_FLUSH, Z_SYNC_FLUSH, Z_FULL_FLUSH, Z_FINISH};
    int flush_idx = 0;
    size_t processed = 0;

    while (strm.avail_in > 0) {
      size_t chunk = (strm.avail_in > 100) ? 100 : strm.avail_in;
      strm.avail_in = chunk;

      do {
        strm.avail_out = sizeof(out);
        strm.next_out = out;
        int flush = (chunk < 100) ? flush_modes[flush_idx % 4] : Z_NO_FLUSH;
        flush_idx++;
        deflate(&strm, flush);

        deflatePending(&strm, &pending, &bits);
        if ((chunk % 3) == 0) deflatePending(&strm, NULL, &bits);
        if ((chunk % 5) == 0) deflatePending(&strm, &pending, NULL);
      } while (strm.avail_out == 0);

      processed += chunk;
      if (processed >= inputLen) break;
      strm.avail_in = inputLen - processed;
      strm.next_in = (Bytef *)input + processed;
    }

    /* Final flush modes */
    for (int i = 0; i < 4; i++) {
      strm.avail_out = sizeof(out);
      strm.next_out = out;
      deflate(&strm, flush_modes[i]);
      deflatePending(&strm, &pending, &bits);
    }
  }

  deflateEnd(&strm);

  /* Test after deflateEnd (should error) */
  (void)deflatePending(&strm, &pending, &bits);

  return 0;
}