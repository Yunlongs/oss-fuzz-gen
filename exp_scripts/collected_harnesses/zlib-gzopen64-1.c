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
    /* Discard inputs larger than 1MB. */
    static const size_t kMaxSize = 1024 * 1024;
    if (size < 1 || size > kMaxSize) {
        return 0;
    }

    /* Create a temporary file with the fuzzer input as content. */
    char fname[] = "/tmp/gzopen64_fuzz_XXXXXX";
    int fd = mkstemp(fname);
    if (fd < 0) {
        return 0;
    }

    /* Write the fuzzer data to the temporary file. */
    ssize_t written = write(fd, data, size);
    close(fd);
    if (written != (ssize_t)size) {
        unlink(fname);
        return 0;
    }

    /* Determine the mode for gzopen64.
     * Valid modes are "rb", "wb", "ab", "rb+", "wb+", "ab+", "x", "x+", "h", "hc".
     * We'll use a subset of safe modes: "rb", "wb", "ab".
     */
    const char *modes[] = {"rb", "wb", "ab"};
    unsigned int mode_index = data[0] % (sizeof(modes) / sizeof(modes[0]));

    /* Call the function under test: gzopen64 */
    gzFile file = gzopen64(fname, modes[mode_index]);

    /* If the file opened successfully, we can optionally perform a minimal
     * operation to exercise the code. For "rb" mode, try to read one byte.
     * For "wb" or "ab", write a dummy byte. Then close the file.
     */
    if (file != NULL) {
        if (strchr(modes[mode_index], 'r') != NULL) {
            /* Reading mode: try to read one byte. */
            char buf[1];
            gzread(file, buf, sizeof(buf));
        } else if (strchr(modes[mode_index], 'w') != NULL || strchr(modes[mode_index], 'a') != NULL) {
            /* Writing or appending mode: write a dummy byte. */
            const char dummy = 'A';
            gzwrite(file, &dummy, 1);
        }
        gzclose(file);
    }

    /* Clean up the temporary file. */
    unlink(fname);

    /* This function must return 0. */
    return 0;
}