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

  /* Enhanced inflateCopy test with raw (likely invalid) data */
  {
    /* Test error cases */
    int ret = inflateCopy(Z_NULL, Z_NULL);
    assert(ret == Z_STREAM_ERROR);

    /* Test with a wide range of window bits */
    int windowBits[] = {
      8, 9, 10, 11, 12, 13, 14, 15,
      -8, -9, -10, -11, -12, -13, -14, -15,
      15 + 16, 15 + 32, 31, 47, 63
    };
    
    for (size_t i = 0; i < sizeof(windowBits) / sizeof(windowBits[0]); ++i) {
      z_stream src, dest;
      unsigned char out[4096];

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

      /* Test inflateCopy on a freshly initialized stream */
      ret = inflateCopy(&dest, &src);
      if (ret == Z_OK) {
        inflateEnd(&dest);
      }

      /* Vary dictionary sizes */
      if (dataLen > 0) {
        unsigned char dict[256];
        size_t dict_size = (data[0] % 257);  /* 0 to 256 */
        if (dict_size > dataLen) dict_size = dataLen;
        if (dict_size > 0) {
          memcpy(dict, data, dict_size);
          inflateSetDictionary(&src, dict, (uInt)dict_size);
          ret = inflateCopy(&dest, &src);
          if (ret == Z_OK) {
            inflateEnd(&dest);
          }
        }
      }

      /* Use inflatePrime with various bits */
      if (dataLen > 1) {
        int bits = data[1] % 16;
        int value = data[1] >> 4;
        inflatePrime(&src, bits, value);
        ret = inflateCopy(&dest, &src);
        if (ret == Z_OK) {
          inflateEnd(&dest);
        }
      }

      /* Feed data in varying chunk sizes to create different states */
      size_t consumed = 0;
      int step = 0;
      while (src.avail_in > 0 && src.avail_out > 0 && step < 20) {
        size_t chunk = (src.avail_in > 128) ? 128 : src.avail_in;
        src.avail_in = chunk;
        ret = inflate(&src, Z_NO_FLUSH);
        
        /* Try copying at this state */
        int copy_ret = inflateCopy(&dest, &src);
        if (copy_ret == Z_OK) {
          assert(dest.adler == src.adler);
          assert(dest.total_in == src.total_in);
          assert(dest.total_out == src.total_out);
          assert(dest.data_type == src.data_type);
          inflateEnd(&dest);
        }
        
        if (ret == Z_STREAM_END || ret < Z_OK) {
          /* Also try copying after stream end or error */
          copy_ret = inflateCopy(&dest, &src);
          if (copy_ret == Z_OK) {
            inflateEnd(&dest);
          }
          break;
        }
        
        consumed += chunk;
        src.next_in = (Bytef*)data + consumed;
        src.avail_in = dataLen - consumed;
        if (src.avail_out == 0) {
          src.next_out = out;
          src.avail_out = sizeof(out);
        }
        step++;
      }

      /* Test inflateCopy on a stream that has been ended */
      inflateEnd(&src);
      ret = inflateCopy(&dest, &src);
      assert(ret == Z_STREAM_ERROR);
    }

    /* Test inflateCopy with a stream that has invalid zalloc/zfree */
    {
      z_stream src, dest;
      src.zalloc = (alloc_func)0;
      src.zfree = (free_func)0;
      src.opaque = Z_NULL;
      src.next_in = Z_NULL;
      src.avail_in = 0;
      src.next_out = Z_NULL;
      src.avail_out = 0;
      src.state = Z_NULL;
      ret = inflateCopy(&dest, &src);
      assert(ret == Z_STREAM_ERROR);
    }
  }

  /* New: inflateCopy test with valid compressed data */
  if (dataLen > 0) {
    /* Compress the input (or a subset) to get valid compressed data */
    size_t comprLen = compressBound(dataLen);
    if (comprLen > 10 * 1024 * 1024) {  /* Avoid huge allocations */
      comprLen = 10 * 1024 * 1024;
    }
    uint8_t *compr = (uint8_t *)malloc(comprLen);
    uint8_t *uncompr = (uint8_t *)malloc(dataLen);  /* maximum uncompressed size */
    if (compr && uncompr) {
      /* Compress with a random level derived from the first byte */
      int level = (data[0] % 10) + 1;  /* 1 to 10 */
      if (level > 9) level = 9;
      uLongf destLen = comprLen;
      int ret = compress2(compr, &destLen, data, dataLen, level);
      if (ret == Z_OK) {
        /* Now decompress the compressed data and call inflateCopy during the process */
        int windowBits[] = { 15, 15 + 32, -15 };  /* zlib, gzip, raw */
        for (size_t i = 0; i < sizeof(windowBits) / sizeof(windowBits[0]); ++i) {
          z_stream src, dest;
          src.zalloc = Z_NULL;
          src.zfree = Z_NULL;
          src.opaque = Z_NULL;
          src.next_in = (Bytef*)compr;
          src.avail_in = destLen;
          src.next_out = uncompr;
          src.avail_out = dataLen;

          ret = inflateInit2(&src, windowBits[i]);
          if (ret != Z_OK) continue;

          /* Copy the stream right after init */
          ret = inflateCopy(&dest, &src);
          if (ret == Z_OK) inflateEnd(&dest);

          /* Decompress in chunks, copying the state at each step */
          size_t consumed = 0;
          while (src.avail_in > 0 && src.avail_out > 0) {
            size_t chunk = (src.avail_in > 64) ? 64 : src.avail_in;
            src.avail_in = chunk;
            ret = inflate(&src, Z_NO_FLUSH);
            /* Copy the state */
            int copy_ret = inflateCopy(&dest, &src);
            if (copy_ret == Z_OK) {
              assert(dest.adler == src.adler);
              assert(dest.total_in == src.total_in);
              assert(dest.total_out == src.total_out);
              assert(dest.data_type == src.data_type);
              inflateEnd(&dest);
            }
            if (ret == Z_STREAM_END || ret < Z_OK) break;
            consumed += chunk;
            src.next_in = (Bytef*)compr + consumed;
            src.avail_in = destLen - consumed;
            if (src.avail_out == 0) {
              /* Reset output buffer if full (should not happen with our sizing) */
              break;
            }
          }
          /* Try copying after decompression ends */
          ret = inflateCopy(&dest, &src);
          if (ret == Z_OK) inflateEnd(&dest);
          inflateEnd(&src);
        }
      }
      free(compr);
      free(uncompr);
    }
  }

  /* This function must return 0. */
  return 0;
}