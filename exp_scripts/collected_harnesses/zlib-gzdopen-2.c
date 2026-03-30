#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int fd;
    char mode[256];
    size_t mode_len = 0;
    gzFile file;
    char template[] = "/tmp/gzdopen_fuzz_XXXXXX";

    /* Discard inputs larger than 1Mb to avoid excessive resource usage. */
    static size_t kMaxSize = 1024 * 1024;
    if (size > kMaxSize)
        return 0;

    /* Ensure at least one byte for mode string. */
    if (size < 1)
        return 0;

    /* Determine file descriptor: if first byte is 0, use invalid fd (-1),
       otherwise create a temporary file and use its fd. */
    if (data[0] == 0) {
        fd = -1;
        /* Mode string starts from the second byte. */
        if (size == 1) {
            /* No mode string provided, use a default. */
            mode_len = 1;
            mode[0] = 'r';
            mode[1] = '\0';
        } else {
            mode_len = size - 1;
            if (mode_len > 255) mode_len = 255;
            memcpy(mode, data + 1, mode_len);
            mode[mode_len] = '\0';
        }
    } else {
        /* Create a temporary file to get a valid file descriptor. */
        fd = mkstemp(template);
        if (fd == -1) {
            /* Failed to create temporary file, skip this input. */
            return 0;
        }
        /* Mode string is the entire input data. */
        mode_len = size;
        if (mode_len > 255) mode_len = 255;
        memcpy(mode, data, mode_len);
        mode[mode_len] = '\0';
    }

    /* Ensure the mode string contains at least one valid mode character.
       If not, default to 'r' to avoid immediate failure. */
    int has_valid_mode = 0;
    for (size_t i = 0; i < mode_len; i++) {
        if (mode[i] == 'r' || mode[i] == 'w' || mode[i] == 'a') {
            has_valid_mode = 1;
            break;
        }
    }
    if (!has_valid_mode) {
        /* Append 'r' to the mode string if there's room. */
        if (mode_len < 255) {
            mode[mode_len] = 'r';
            mode_len++;
            mode[mode_len] = '\0';
        } else {
            mode[255] = '\0';
            mode[254] = 'r';
        }
    }

    /* Call the function under test. */
    file = gzdopen(fd, mode);

    /* Cleanup. */
    if (file != NULL) {
        gzclose(file);
        /* If we used a temporary file, it has been closed by gzclose.
           We still need to remove the file. */
        if (fd != -1) {
            unlink(template);
        }
    } else {
        /* gzdopen failed. If we used a temporary file, close the fd and remove the file. */
        if (fd != -1) {
            close(fd);
            unlink(template);
        }
    }

    return 0;
}