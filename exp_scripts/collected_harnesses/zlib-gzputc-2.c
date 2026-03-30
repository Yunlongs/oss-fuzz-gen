#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t dataLen) {
  static size_t kMaxSize = 1024 * 1024;
  if (dataLen > kMaxSize)
    return 0;

  if (dataLen == 0) {
    (void)gzputc(NULL, 'A');
    return 0;
  }

  char fname[] = "gzputc_fuzz.XXXXXX";
  int fd = mkstemp(fname);
  if (fd == -1) {
    return 0;
  }
  close(fd);

  size_t offset = 0;

  /* Test NULL file pointer if first byte is 0. */
  if (data[0] == 0) {
    (void)gzputc(NULL, 'A');
    remove(fname);
    return 0;
  }

  /* Determine mode string length (1-16) from first byte. */
  unsigned mode_len = (data[offset] & 0x0F) + 1;
  offset++;

  /* Build mode string from subsequent bytes, null‑terminate. */
  char mode[17];
  unsigned i;
  for (i = 0; i < mode_len && offset < dataLen; i++) {
    mode[i] = data[offset++];
  }
  mode[i] = '\0';

  int test_read = (mode[0] == 'r');

  /* For read mode, pre‑populate the file with some data. */
  if (test_read) {
    unsigned prepop = 0;
    if (offset < dataLen) {
      prepop = data[offset] % 256;
      offset++;
    }
    if (prepop > 0 && offset + prepop <= dataLen) {
      FILE *tmp = fopen(fname, "wb");
      if (tmp) {
        fwrite(data + offset, 1, prepop, tmp);
        fclose(tmp);
      }
      offset += prepop;
    }
  }

  gzFile file = gzopen(fname, mode);
  if (file == NULL) {
    remove(fname);
    return 0;
  }

  /* For write modes, set buffer size (may be zero). */
  if (!test_read && offset < dataLen) {
    unsigned char buf_size = data[offset];
    (void)gzbuffer(file, buf_size);
    offset++;
  }

  /* Possibly perform an initial seek to set state->skip. */
  if (!test_read && offset < dataLen) {
    signed char seek_off = (signed char)data[offset++];
    (void)gzseek(file, (long)seek_off, SEEK_SET);
  }

  /* Execute up to 20 operations to balance coverage and speed. */
  unsigned op_count = 0;
  while (offset < dataLen && op_count++ < 20) {
    unsigned char op = data[offset++] % 24;
    switch (op) {
      case 0:  /* gzputc */
        if (offset < dataLen) {
          (void)gzputc(file, data[offset++]);
        }
        break;
      case 1:  /* gzseek with larger offset (4 bytes) */
        if (offset + 4 < dataLen) {
          int32_t off;
          memcpy(&off, data + offset, 4);
          offset += 4;
          unsigned char whence = data[offset++] % 3;
          (void)gzseek(file, (long)off, whence == 0 ? SEEK_SET :
                                      whence == 1 ? SEEK_CUR : SEEK_END);
        }
        break;
      case 2:  /* gzsetparams */
        if (offset + 2 < dataLen) {
          unsigned char level = data[offset++];
          unsigned char strategy = data[offset++];
          (void)gzsetparams(file, level, strategy);
        }
        break;
      case 3:  /* gzflush */
        if (offset < dataLen) {
          unsigned char flush = data[offset++] % 5;
          int f = flush == 0 ? Z_NO_FLUSH :
                   flush == 1 ? Z_SYNC_FLUSH :
                   flush == 2 ? Z_FULL_FLUSH :
                   flush == 3 ? Z_FINISH : Z_BLOCK;
          (void)gzflush(file, f);
        }
        break;
      case 4:  /* gzbuffer */
        if (offset < dataLen) {
          (void)gzbuffer(file, data[offset++]);
        }
        break;
      case 5:  /* gzputs (may be empty string) */
        if (offset < dataLen) {
          unsigned char len = data[offset++] % 128;
          if (offset + len <= dataLen) {
            char *str = (char *)malloc(len + 1);
            if (str) {
              memcpy(str, data + offset, len);
              str[len] = 0;
              (void)gzputs(file, str);
              free(str);
            }
            offset += len;
          }
        }
        break;
      case 6:  /* gzwrite (may be zero length) */
        if (offset < dataLen) {
          unsigned char len = data[offset++] % 128;
          if (offset + len <= dataLen) {
            (void)gzwrite(file, data + offset, len);
            offset += len;
          }
        }
        break;
      case 7:  /* gzread (may be zero length) */
        if (offset < dataLen) {
          unsigned char len = data[offset++] % 128;
          if (offset + len <= dataLen) {
            char *buf = (char *)malloc(len);
            if (buf) {
              (void)gzread(file, buf, len);
              free(buf);
            }
            offset += len;
          }
        }
        break;
      case 8:  /* gzgetc */
        (void)gzgetc(file);
        break;
      case 9:  /* gzungetc */
        if (offset < dataLen) {
          (void)gzungetc(data[offset++], file);
        }
        break;
      case 10: /* gzgets (requires at least 1 byte) */
        if (offset < dataLen) {
          unsigned char len = data[offset++] % 128;
          if (len == 0) len = 1;
          if (offset + len <= dataLen) {
            char *buf = (char *)malloc(len);
            if (buf) {
              (void)gzgets(file, buf, len);
              free(buf);
            }
            offset += len;
          }
        }
        break;
      case 11: /* gzprintf with more formats */
        if (offset + 2 < dataLen) {
          unsigned char fmt = data[offset++] % 6;
          unsigned char val = data[offset++];
          switch (fmt) {
            case 0: (void)gzprintf(file, "%d", (int)val); break;
            case 1: (void)gzprintf(file, "%c", (char)val); break;
            case 2: (void)gzprintf(file, "%x", (unsigned)val); break;
            case 3: (void)gzprintf(file, "%%"); break;
            case 4: (void)gzprintf(file, "%u", (unsigned)val); break;
            case 5: (void)gzprintf(file, "%s", "test"); break;
          }
        }
        break;
      case 12: /* gzerror */
        {
          int errnum;
          (void)gzerror(file, &errnum);
        }
        break;
      case 13: /* gzclearerr */
        gzclearerr(file);
        break;
      case 14: /* gztell */
        (void)gztell(file);
        break;
      case 15: /* gzoffset */
        (void)gzoffset(file);
        break;
      case 16: /* gzrewind */
        (void)gzrewind(file);
        break;
      case 17: /* gzeof */
        (void)gzeof(file);
        break;
      case 18: /* gzdirect */
        (void)gzdirect(file);
        break;
      case 19: /* close and reopen */
        gzclose(file);
        file = gzopen(fname, mode);
        if (file == NULL) {
          goto cleanup;
        }
        break;
      case 20: /* write after Z_FINISH (regardless of state) */
        if (offset < dataLen) {
          (void)gzputc(file, data[offset++]);
        }
        break;
      case 21: /* zero-byte gzwrite */
        (void)gzwrite(file, NULL, 0);
        break;
      case 22: /* zero-byte gzread */
        {
          char buf[1];
          (void)gzread(file, buf, 0);
        }
        break;
      case 23: /* set buffer size to zero */
        (void)gzbuffer(file, 0);
        break;
    }
  }

cleanup:
  if (file) {
    gzclose(file);
  }
  remove(fname);

  return 0;
}