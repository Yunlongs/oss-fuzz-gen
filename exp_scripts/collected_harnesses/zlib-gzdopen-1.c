#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static const size_t kMaxSize = 1024 * 1024;
  if (size < 1 || size > kMaxSize)
    return 0;

  /* Extract a null-terminated mode string from the input data (up to 255 bytes). */
  char mode[256];
  size_t mode_len = size > 255 ? 255 : size;
  memcpy(mode, data, mode_len);
  mode[mode_len] = '\0';

  /* Choose a file descriptor based on the next byte (if available). */
  int fd_choice = (size > mode_len) ? data[mode_len] : 0;
  int fd = -1;
  int pipefd[2] = {-1, -1};
  int devzero_fd = -1;
  
  switch (fd_choice % 7) {
    case 0:
      fd = dup(0);   /* duplicate stdin */
      break;
    case 1:
      fd = dup(1);   /* duplicate stdout */
      break;
    case 2:
      fd = dup(2);   /* duplicate stderr */
      break;
    case 3:
      fd = -1;       /* invalid file descriptor */
      break;
    case 4:
      /* Pipe (non-seekable) */
      if (pipe(pipefd) == 0) {
        fd = pipefd[0];
        close(pipefd[1]);  /* close write end, read end will see EOF */
      } else {
        fd = -1;  /* fallback to invalid */
      }
      break;
    case 5:
      /* Closed file descriptor */
      fd = dup(0);
      if (fd != -1) {
        close(fd);
        /* fd is now closed, but we keep the number */
      }
      break;
    case 6:
      /* Seekable file descriptor (/dev/zero) */
      devzero_fd = open("/dev/zero", O_RDWR);
      fd = devzero_fd;
      break;
  }

  /* Call gzdopen with the selected file descriptor and mode string. */
  gzFile gz = gzdopen(fd, mode);
  
  if (gz) {
    /* Set a small buffer size. */
    gzbuffer(gz, 128);

    /* If mode suggests writing, try setting compression parameters. */
    if (strchr(mode, 'w') || strchr(mode, 'a')) {
      int level = (data[0] % 10) + 1;  /* 1-10 */
      int strategy = data[1] % 5;      /* 0-4 */
      gzsetparams(gz, level, strategy);
    }

    /* Perform minimal read/write based on mode. */
    char buf[16];
    if (strchr(mode, 'r')) {
      gzread(gz, buf, sizeof(buf));
    }
    if (strchr(mode, 'w') || strchr(mode, 'a')) {
      if (size > 0) {
        size_t write_size = size % sizeof(buf);
        if (write_size > 0) {
          gzwrite(gz, data, write_size);
        }
      }
    }

    /* Flush if writing. */
    if (strchr(mode, 'w') || strchr(mode, 'a')) {
      gzflush(gz, Z_SYNC_FLUSH);
    }

    /* Check various states. */
    gzeof(gz);
    gztell(gz);
    gzdirect(gz);
    gzerror(gz, NULL);
    gzclearerr(gz);

    gzclose(gz);
  } else {
    /* If gzdopen failed, close the file descriptor if it's valid and not already closed. */
    if (fd != -1) {
      /* Check if fd is still open by trying to dup it (avoid closing a closed fd). */
      int test_fd = dup(fd);
      if (test_fd != -1) {
        close(test_fd);
        close(fd);
      }
      /* If dup failed, fd might already be closed (case 5) or invalid, so do nothing. */
    }
  }

  /* Clean up any remaining pipe file descriptors (should already be closed). */
  if (pipefd[0] != -1 && pipefd[0] != fd) close(pipefd[0]);
  if (pipefd[1] != -1) close(pipefd[1]);
  if (devzero_fd != -1 && devzero_fd == fd) close(devzero_fd);

  return 0;
}