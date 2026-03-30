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
  /* Discard inputs larger than 1Mb. */
  static size_t kMaxSize = 1024 * 1024;
  if (dataLen > kMaxSize)
    return 0;

  /* If input is empty, do nothing. */
  if (dataLen == 0)
    return 0;

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
  unsigned mode_len = 1;
  if (dataLen > 0) {
    mode_len = (data[offset] & 0x0F) + 1;
  }
  offset++;

  /* Build mode string from subsequent bytes, null‑terminate. */
  char mode[17];
  unsigned i;
  for (i = 0; i < mode_len && offset < dataLen; i++) {
    mode[i] = data[offset++];
  }
  mode[i] = '\0';

  /* If mode starts with 'r', pre‑populate the file with some data. */
  if (mode[0] == 'r') {
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

  /* Open the file. */
  gzFile file = gzopen(fname, mode);
  if (file == NULL) {
    remove(fname);
    return 0;
  }

  /* Optionally set a small buffer size for write modes. */
  if (offset < dataLen && mode[0] != 'r') {
    unsigned buf_size = data[offset] % 256;
    (void)gzbuffer(file, buf_size);
    offset++;
  }

  /* Execute up to 10 operations to improve speed. */
  unsigned op_count = 0;
  while (offset < dataLen && op_count++ < 10) {
    unsigned char op = data[offset++] % 20;
    switch (op) {
      case 0:  /* gzputc */
        if (offset < dataLen) {
          (void)gzputc(file, data[offset++]);
        }
        break;
      case 1:  /* gzseek */
        if (offset + 1 < dataLen) {
          signed char off = (signed char)data[offset++];
          unsigned char whence = data[offset++] % 3;
          (void)gzseek(file, (long)off, whence == 0 ? SEEK_SET :
                                      whence == 1 ? SEEK_CUR : SEEK_END);
        }
        break;
      case 2:  /* gzsetparams */
        if (offset + 1 < dataLen) {
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
      case 5:  /* gzputs */
        if (offset < dataLen) {
          unsigned char len = data[offset++] % 128;
          if (len == 0) len = 1;
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
      case 6:  /* gzwrite */
        if (offset < dataLen) {
          unsigned char len = data[offset++] % 1024;  /* up to 1024 bytes */
          if (len == 0) len = 1;
          if (offset + len <= dataLen) {
            (void)gzwrite(file, data + offset, len);
            offset += len;
          }
        }
        break;
      case 7:  /* gzread */
        if (offset < dataLen) {
          unsigned char len = data[offset++] % 128;
          if (len > 0 && offset + len <= dataLen) {
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
      case 10: /* gzgets */
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
      case 11: /* gzprintf */
        if (offset + 2 < dataLen) {
          unsigned char fmt = data[offset++] % 4;
          unsigned char val = data[offset++];
          switch (fmt) {
            case 0: (void)gzprintf(file, "%d", (int)val); break;
            case 1: (void)gzprintf(file, "%c", (char)val); break;
            case 2: (void)gzprintf(file, "%x", (unsigned)val); break;
            case 3: (void)gzprintf(file, "%%"); break;
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
    }
  }

cleanup:
  if (file) {
    gzclose(file);
  }
  remove(fname);

  return 0;
}