#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include "zlib.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Limit the input size to avoid excessive memory usage.
    static const size_t kMaxSize = 4096;
    if (size > kMaxSize) {
        size = kMaxSize;
    }
    if (size == 0) {
        return 0;
    }

    // Control byte from the input.
    uint8_t control = data[0];
    size_t offset = 1;

    // Create a temporary file.
    char fname[] = "gzio.XXXXXX";
    int fd = mkstemp(fname);
    if (fd < 0) {
        return 0;
    }
    close(fd);

    gzFile file = NULL;
    int use_null_file = (control & 0x01) && (size > 1); // Sometimes use NULL file pointer.
    int read_mode = (control & 0x02) && (size > 2);     // Open in read mode to cause write error.
    int small_buffer = (control & 0x04) && (size > 3);  // Set small buffer size.
    int multiple_calls = (control & 0x08) && (size > 4); // Call gzprintf multiple times.
    int perturb_state = (control & 0x10) && (size > 5); // Use gzflush or gzseek.
    int induce_skip = (control & 0x20) && (size > 6);   // Call gzseek with positive offset before writing.

    if (!use_null_file) {
        if (read_mode) {
            file = gzopen(fname, "rb");
        } else {
            file = gzopen(fname, "wb");
        }
        if (!file) {
            remove(fname);
            return 0;
        }

        if (small_buffer) {
            // Set buffer size to a small value (1..32) to trigger buffer full conditions.
            unsigned bufsize = (data[offset] & 0x1F) + 1;
            if (offset < size) {
                gzbuffer(file, bufsize);
                offset++;
            }
        }

        // Optionally induce skip condition.
        if (induce_skip && file && !read_mode) {
            // Seek forward by 1 byte to set state->skip.
            gzseek(file, 1, SEEK_CUR);
        }
    }

    // Prepare an argument from the input data.
    // We'll use a union to hold different types and then cast to void*.
    union {
        int i;
        float f;
        char c;
        void *p;
        char str[4096]; // Allow longer strings for buffer full tests.
    } arg;
    memset(&arg, 0, sizeof(arg));

    // Select a format string.
    const char *format = "%s";
    if (offset < size) {
        uint8_t fmt_selector = data[offset] % 5;
        offset++;
        switch (fmt_selector) {
            case 0: format = "%s"; break;
            case 1: format = "%p"; break;
            case 2: format = "%n"; break;
            case 3: format = "Plain text"; break; // No conversions.
            case 4: format = "%%"; break;        // Literal percent.
        }
    }

    // Prepare the argument based on the format.
    if (strcmp(format, "%s") == 0) {
        // Determine desired string length.
        size_t max_str_len = sizeof(arg.str) - 1;
        size_t str_len = 0;
        if (offset < size) {
            // Use the next byte to decide length.
            uint8_t len_selector = data[offset];
            offset = (offset + 1) % size;
            if (len_selector < 128) {
                // Short string (0..127).
                str_len = len_selector % 256;
            } else {
                // Longer string, possibly exceeding buffer size.
                str_len = (len_selector % 256) + 128;
            }
            if (str_len > max_str_len) str_len = max_str_len;
        }
        // If small_buffer is set, ensure the string is longer than buffer size to trigger full condition.
        if (small_buffer && file) {
            // Get the buffer size (state->size) is not directly accessible; we use the bufsize set earlier.
            // Approximate by using the bufsize value (1..32). We'll make string longer than that.
            unsigned bufsize = (data[1] & 0x1F) + 1; // We used this earlier.
            if (str_len < bufsize) {
                str_len = bufsize + 1;
                if (str_len > max_str_len) str_len = max_str_len;
            }
        }
        if (str_len > 0 && offset + str_len <= size) {
            memcpy(arg.str, data + offset, str_len);
            offset += str_len;
        } else {
            // Use a default pattern.
            memset(arg.str, 'A', str_len);
        }
        arg.str[str_len] = 0;
        arg.p = (void*)arg.str;
    } else if (strcmp(format, "%p") == 0) {
        // Use a pointer to a local variable or to the data.
        static int dummy;
        arg.p = (void*)&dummy;
    } else if (strcmp(format, "%n") == 0) {
        static int count;
        arg.p = (void*)&count;
    } else {
        // For plain text or %% formats, argument is ignored.
        arg.p = NULL;
    }

    // Determine the number of gzprintf calls.
    int num_calls = 1;
    if (multiple_calls && offset < size) {
        num_calls = (data[offset] % 8) + 1; // 1 to 8 calls.
        offset++;
    }

    // Call gzprintf the required number of times.
    for (int i = 0; i < num_calls; i++) {
        // Optionally vary the string for %s between calls.
        if (strcmp(format, "%s") == 0 && i > 0 && offset < size) {
            // Modify the string slightly.
            arg.str[0] = data[offset % size];
            offset = (offset + 1) % size;
        }

        gzprintf(file, format, arg.p);

        // Perturb state between calls.
        if (perturb_state && file) {
            if (i % 3 == 0) {
                gzflush(file, Z_SYNC_FLUSH);
            } else if (i % 3 == 1) {
                gzseek(file, 0, SEEK_CUR);
            } else {
                // Seek forward by a small offset to potentially set skip for next call.
                gzseek(file, 1, SEEK_CUR);
            }
        }
    }

    // Clean up.
    if (file) {
        gzclose(file);
    }
    remove(fname);
    return 0;
}