#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include "zlib.h"

/* Define z_word_t and W as per the library's internal definition.
   We assume the library was compiled with W defined (4 or 8).
   We use the same logic as in crc32.c to define z_word_t. */
#if defined(__x86_64__) || defined(__aarch64__)
    #define W 8
    typedef unsigned long long z_word_t;
#else
    #define W 4
    typedef unsigned long z_word_t;
#endif

/* Declare byte_swap function from the library (we removed static) */
z_word_t byte_swap(z_word_t word);

/* Number of braids (from source code comments) */
#define N 5
/* Minimum length to trigger braided code in crc32_z (after alignment) */
#define BRAID_THRESHOLD (N * W + W - 1)

/* Reference implementation for validation */
static z_word_t ref_byte_swap(z_word_t word) {
#if W == 8
    return
        (word & (z_word_t)0xff00000000000000) >> 56 |
        (word & (z_word_t)0x00ff000000000000) >> 40 |
        (word & (z_word_t)0x0000ff0000000000) >> 24 |
        (word & (z_word_t)0x000000ff00000000) >>  8 |
        (word & (z_word_t)0x00000000ff000000) <<  8 |
        (word & (z_word_t)0x0000000000ff0000) << 24 |
        (word & (z_word_t)0x000000000000ff00) << 40 |
        (word & (z_word_t)0x00000000000000ff) << 56;
#else
    return
        (word & (z_word_t)0xff000000) >> 24 |
        (word & (z_word_t)0x00ff0000) >>  8 |
        (word & (z_word_t)0x0000ff00) <<  8 |
        (word & (z_word_t)0x000000ff) << 24;
#endif
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataLen) {
  /* Call byte_swap on the CRC table values early to trigger dynamic table generation */
  const z_crc_t *crc_table = get_crc_table();
  if (crc_table) {
    for (int i = 0; i < 256; ++i) {
      z_word_t word = (z_word_t)crc_table[i];
      z_word_t swapped = byte_swap(word);
      z_word_t swapped_back = byte_swap(swapped);
      assert(swapped_back == word);
    }
  }

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

  /* Enhanced byte_swap testing: process multiple words from the input */
  size_t word_size = sizeof(z_word_t);
  size_t num_words = dataLen / word_size;
  if (num_words > 100) num_words = 100; /* Limit to avoid excessive time */
  for (size_t i = 0; i < num_words; ++i) {
    z_word_t word;
    memcpy(&word, data + i * word_size, word_size);
    z_word_t swapped = byte_swap(word);
    z_word_t swapped_back = byte_swap(swapped);
    assert(swapped_back == word);
    /* Validate against reference implementation */
    assert(swapped == ref_byte_swap(word));
  }

  /* Explicit edge-case tests for byte_swap */
  z_word_t edge_cases[] = {0, (z_word_t)-1, (z_word_t)0x12345678, (z_word_t)0x87654321};
  for (size_t i = 0; i < sizeof(edge_cases)/sizeof(edge_cases[0]); ++i) {
    z_word_t word = edge_cases[i];
    z_word_t swapped = byte_swap(word);
    z_word_t swapped_back = byte_swap(swapped);
    assert(swapped_back == word);
    assert(swapped == ref_byte_swap(word));
  }

  /* Trigger braided code in crc32_z with original buffer (let crc32_z align internally) */
  if (dataLen >= BRAID_THRESHOLD + (W - 1)) {
    /* Test with zero initial CRC */
    uint32_t crc_large = crc32_z(0, data, dataLen);
    (void)crc_large;

    /* Test with non-zero initial CRC derived from input */
    uint32_t init_crc = 0;
    if (dataLen >= 4) {
      memcpy(&init_crc, data, 4);
    }
    crc_large = crc32_z(init_crc, data, dataLen);
    (void)crc_large;

    /* Test with a fixed non-zero initial CRC */
    init_crc = 0x12345678;
    crc_large = crc32_z(init_crc, data, dataLen);
    (void)crc_large;
  }

  /* This function must return 0. */
  return 0;
}