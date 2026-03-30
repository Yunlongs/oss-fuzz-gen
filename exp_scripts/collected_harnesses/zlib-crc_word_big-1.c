#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <malloc.h>
#include "zlib.h"

/* Ensure W is defined (must match the library build). */
#ifndef W
#  define W 8
#endif

/* Define z_word_t as per crc32.c logic. */
#if W == 8 && defined(Z_U8)
   typedef Z_U8 z_word_t;
#elif defined(Z_U4)
   typedef Z_U4 z_word_t;
#else
   /* Fallback: assume 64-bit word. */
   typedef unsigned long long z_word_t;
#endif

/* Declare the functions (now non-static due to -Dlocal= in build). */
extern z_word_t crc_word_big(z_word_t);
extern z_crc_t crc_word(z_word_t);

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

  /* New test: call crc_word_big with the first word of input. */
  if (dataLen >= sizeof(z_word_t)) {
    z_word_t input_word;
    memcpy(&input_word, data, sizeof(z_word_t));
    z_word_t result = crc_word_big(input_word);
    (void)result;
  }

  /* Enhanced testing for crc_word and crc_word_big */
  /* Use N=5 as in the library's braided algorithm. */
#define N 5
  if (dataLen >= N * sizeof(z_word_t)) {
    z_word_t words[N];
    memcpy(words, data, N * sizeof(z_word_t));

    /* Test crc_word on each word. */
    for (int i = 0; i < N; i++) {
      z_crc_t res = crc_word(words[i]);
      (void)res;
    }

    /* Simulate the braided algorithm's chaining of crc_word_big with non-zero CRC values. */
    z_word_t crc[N];
    for (int i = 0; i < N; i++) {
        if (dataLen >= (i+1) * sizeof(z_word_t) + N * sizeof(z_word_t)) {
            memcpy(&crc[i], data + (i+1) * sizeof(z_word_t), sizeof(z_word_t));
        } else {
            crc[i] = 0;
        }
    }
    z_word_t comb = crc_word_big(crc[0] ^ words[0]);
    comb = crc_word_big(crc[1] ^ words[1] ^ comb);
    comb = crc_word_big(crc[2] ^ words[2] ^ comb);
    comb = crc_word_big(crc[3] ^ words[3] ^ comb);
    comb = crc_word_big(crc[4] ^ words[4] ^ comb);
    (void)comb;
  }
#undef N

  /* Trigger the braided algorithm by using an aligned buffer. */
  /* The braided algorithm requires len >= N * W + W - 1 = 5*8+7 = 47 and alignment to sizeof(z_word_t). */
  if (dataLen >= 47) {
    void *aligned_buf = NULL;
    /* Allocate aligned memory. */
    if (posix_memalign(&aligned_buf, sizeof(z_word_t), dataLen) == 0) {
      memcpy(aligned_buf, data, dataLen);
      uint32_t crc = crc32(0L, NULL, 0);
      crc = crc32_z(crc, (unsigned char FAR *)aligned_buf, dataLen);
      /* Also test with a non-zero initial CRC from the input. */
      if (dataLen >= 4) {
        uint32_t init_crc;
        memcpy(&init_crc, data, 4);
        crc = crc32_z(init_crc, (unsigned char FAR *)aligned_buf, dataLen);
      }
      /* Test with longer input to get multiple blocks (blks > 1) if possible. */
      if (dataLen >= 87) {
        /* Use a subset of the input to test exact boundary lengths. */
        size_t len47 = 47;
        if (dataLen >= len47) {
          crc = crc32_z(0L, (unsigned char FAR *)aligned_buf, len47);
        }
        size_t len87 = 87;
        if (dataLen >= len87) {
          crc = crc32_z(0L, (unsigned char FAR *)aligned_buf, len87);
        }
      }
      free(aligned_buf);
    }
  }

  /* Test with the original (likely unaligned) buffer to cover the alignment loop. */
  if (dataLen >= 47) {
    uint32_t crc = crc32(0L, NULL, 0);
    crc = crc32_z(crc, data, dataLen);
    if (dataLen >= 4) {
      uint32_t init_crc;
      memcpy(&init_crc, data, 4);
      crc = crc32_z(init_crc, data, dataLen);
    }
  }

  /* Force misalignment to exercise the alignment loop. */
  if (dataLen >= 48) {  /* Need at least one extra byte to shift. */
    uint8_t *misaligned_buf = (uint8_t *)malloc(dataLen + 1);
    if (misaligned_buf) {
      /* Shift by one byte to guarantee misalignment. */
      memcpy(misaligned_buf + 1, data, dataLen);
      /* Use a length that still meets the braided algorithm threshold. */
      size_t len = dataLen;
      if (len >= 47) {
        uint32_t crc = crc32(0L, NULL, 0);
        crc = crc32_z(crc, (unsigned char FAR *)(misaligned_buf + 1), len);
      }
      free(misaligned_buf);
    }
  }

  /* Test with various initial CRC values, including all-ones. */
  if (dataLen >= 47) {
    uint32_t crc_all_ones = 0xffffffff;
    crc32_z(crc_all_ones, data, dataLen);
    if (dataLen >= 8) {
      uint32_t crc_from_data;
      memcpy(&crc_from_data, data + 4, 4);
      crc32_z(crc_from_data, data, dataLen);
    }
  }

  /* New: Test multiple alignment offsets (0-7) and interesting lengths. */
  if (dataLen >= 200) {  /* Ensure enough data for various lengths. */
    /* Interesting lengths to test: 1, 46, 47, 48, 79, 80, 81, 87, 88, 120, 160 */
    size_t lengths[] = {1, 46, 47, 48, 79, 80, 81, 87, 88, 120, 160};
    int num_lengths = sizeof(lengths) / sizeof(lengths[0]);
    /* Use a byte from input to choose an alignment offset (0-7). */
    size_t align_offset = data[0] % 8;
    /* Use another byte to choose an initial CRC value. */
    uint32_t init_crc_choice = data[1] % 4;
    uint32_t init_crc;
    switch (init_crc_choice) {
      case 0: init_crc = 0L; break;
      case 1: init_crc = 0xffffffff; break;
      case 2: init_crc = crc32(0L, NULL, 0); break;
      default: init_crc = (uint32_t)data[2] << 24 | data[3] << 16 | data[4] << 8 | data[5]; break;
    }
    for (int i = 0; i < num_lengths; i++) {
      size_t len = lengths[i];
      if (len > dataLen - 10) continue;  /* Not enough data. */
      const uint8_t *buf = data + 10;
      /* Allocate buffer with extra space for alignment. */
      uint8_t *test_buf = (uint8_t *)malloc(len + align_offset);
      if (test_buf) {
        uint8_t *aligned_ptr = test_buf + align_offset;
        memcpy(aligned_ptr, buf, len);
        crc32_z(init_crc, aligned_ptr, len);
        free(test_buf);
      }
    }
  }

  /* Additional tests for multiple blocks (blks > 1) with varying alignments. */
  if (dataLen >= 200) {
    /* Test lengths that guarantee multiple blocks: 120, 160, 200, etc. */
    size_t multi_block_lengths[] = {120, 160, 200, 240, 280};
    int num_multi = sizeof(multi_block_lengths) / sizeof(multi_block_lengths[0]);
    for (int i = 0; i < num_multi; i++) {
      size_t len = multi_block_lengths[i];
      if (len > dataLen - 20) continue;
      const uint8_t *buf = data + 20;
      /* Test with alignment offset 0 (aligned) and 1 (misaligned). */
      for (int align = 0; align <= 1; align++) {
        uint8_t *test_buf = (uint8_t *)malloc(len + align);
        if (test_buf) {
          uint8_t *ptr = test_buf + align;
          memcpy(ptr, buf, len);
          /* Test with zero initial CRC and a non-zero one. */
          crc32_z(0L, ptr, len);
          if (dataLen >= 24) {
            uint32_t crc_init;
            memcpy(&crc_init, data + 20, 4);
            crc32_z(crc_init, ptr, len);
          }
          free(test_buf);
        }
      }
    }
  }

  /* Test edge case where length is exactly N*W (40) or multiple. */
  if (dataLen >= 100) {
    size_t len40 = 40;
    size_t len80 = 80;
    size_t len120 = 120;
    const uint8_t *buf = data + 30;
    if (len40 <= dataLen - 30) {
      crc32_z(0L, buf, len40);
    }
    if (len80 <= dataLen - 30) {
      crc32_z(0L, buf, len80);
    }
    if (len120 <= dataLen - 30) {
      crc32_z(0L, buf, len120);
    }
  }

  /* This function must return 0. */
  return 0;
}