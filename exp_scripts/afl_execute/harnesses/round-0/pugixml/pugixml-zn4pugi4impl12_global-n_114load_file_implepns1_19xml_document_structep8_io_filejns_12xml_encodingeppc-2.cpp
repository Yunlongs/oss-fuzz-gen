#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <cstdio>
#include <unistd.h>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider provider(Data, Size);

    // Bias options toward parse_fragment and other under-tested flags
    unsigned int options = provider.ConsumeIntegral<unsigned int>();
    if (provider.ConsumeBool()) {
        options |= pugi::parse_fragment; // Increase chance of testing fragment parsing
    }
    // Also bias towards other less common flags
    if (provider.ConsumeBool()) {
        options |= pugi::parse_embed_pcdata;
    }
    if (provider.ConsumeBool()) {
        options |= pugi::parse_trim_pcdata;
    }
    if (provider.ConsumeBool()) {
        options |= pugi::parse_ws_pcdata_single;
    }

    // All xml_encoding values
    const pugi::xml_encoding encodings[] = {
        pugi::encoding_auto,
        pugi::encoding_utf8,
        pugi::encoding_utf16_le,
        pugi::encoding_utf16_be,
        pugi::encoding_utf16,
        pugi::encoding_utf32_le,
        pugi::encoding_utf32_be,
        pugi::encoding_utf32,
        pugi::encoding_wchar,
        pugi::encoding_latin1
    };
    pugi::xml_encoding encoding = provider.PickValueInArray(encodings);

    // Decide on the type of path: 0: non-existent, 1: regular file, 2: directory, 3: valid symlink, 4: broken symlink, 5: symlink to directory
    int path_type = provider.ConsumeIntegralInRange(0, 5);

    std::string path;
    bool created_temp_file = false;
    bool created_temp_dir = false;
    bool created_symlink = false;
    bool created_symlink_dir = false;
    char temp_path[] = "/tmp/pugixml_fuzz_XXXXXX";
    char temp_dir_path[] = "/tmp/pugixml_fuzz_dir_XXXXXX";
    char symlink_path[] = "/tmp/pugixml_fuzz_symlink_XXXXXX";
    char symlink_dir_path[] = "/tmp/pugixml_fuzz_symlink_dir_XXXXXX";

    // Determine if we should force an empty file (only for file-based paths)
    bool force_empty_file = provider.ConsumeBool();

    // Determine if we should use a very long path (for non-existent paths)
    bool use_long_path = provider.ConsumeBool();

    if (path_type == 1 || path_type == 3 || path_type == 4) {
        // regular file or symlink to a file (valid or broken)
        bool add_bom = provider.ConsumeBool();
        bool mismatched_bom = provider.ConsumeBool(); // Add a BOM that doesn't match encoding
        bool remove_read_perm = provider.ConsumeBool();

        // Determine file content size from the remaining bytes
        size_t max_file_size = provider.remaining_bytes();
        size_t file_content_size = force_empty_file ? 0 : provider.ConsumeIntegralInRange<size_t>(0, max_file_size);
        std::vector<uint8_t> file_contents = provider.ConsumeBytes<uint8_t>(file_content_size);

        if (add_bom) {
            // Choose a BOM encoding, possibly mismatched
            pugi::xml_encoding bom_encoding = mismatched_bom ? encodings[provider.ConsumeIntegralInRange<size_t>(0, sizeof(encodings)/sizeof(encodings[0])-1)] : encoding;
            switch (bom_encoding) {
                case pugi::encoding_utf8:
                    file_contents.insert(file_contents.begin(), {0xEF, 0xBB, 0xBF});
                    break;
                case pugi::encoding_utf16_le:
                    file_contents.insert(file_contents.begin(), {0xFF, 0xFE});
                    break;
                case pugi::encoding_utf16_be:
                    file_contents.insert(file_contents.begin(), {0xFE, 0xFF});
                    break;
                case pugi::encoding_utf32_le:
                    file_contents.insert(file_contents.begin(), {0xFF, 0xFE, 0x00, 0x00});
                    break;
                case pugi::encoding_utf32_be:
                    file_contents.insert(file_contents.begin(), {0x00, 0x00, 0xFE, 0xFF});
                    break;
                default:
                    break;
            }
        }

        // Create a temporary file
        int fd = mkstemp(temp_path);
        if (fd < 0) return 0;
        FILE* f = fdopen(fd, "wb");
        if (!f) {
            close(fd);
            return 0;
        }
        fwrite(file_contents.data(), 1, file_contents.size(), f);
        fclose(f);
        created_temp_file = true;

        if (remove_read_perm) {
            chmod(temp_path, 0);
        }

        if (path_type == 1) {
            path = temp_path;
        } else { // symlink to file
            // Create a symlink with a random name
            strcpy(symlink_path, "/tmp/pugixml_fuzz_symlink_XXXXXX");
            mktemp(symlink_path); // Not secure but ok for fuzzing
            if (symlink(temp_path, symlink_path) == 0) {
                created_symlink = true;
                path = symlink_path;
                if (path_type == 4) { // broken symlink: delete the target
                    unlink(temp_path);
                    created_temp_file = false; // Already deleted
                }
            } else {
                path = temp_path; // fallback to regular file
            }
        }
    } else if (path_type == 2) { // directory
        if (mkdtemp(temp_dir_path) == NULL) return 0;
        path = temp_dir_path;
        created_temp_dir = true;
    } else if (path_type == 5) { // symlink to directory
        // Create a temporary directory
        if (mkdtemp(temp_dir_path) == NULL) return 0;
        created_temp_dir = true;
        // Create a symlink to the directory
        strcpy(symlink_dir_path, "/tmp/pugixml_fuzz_symlink_dir_XXXXXX");
        mktemp(symlink_dir_path);
        if (symlink(temp_dir_path, symlink_dir_path) == 0) {
            created_symlink = true;
            created_symlink_dir = true;
            path = symlink_dir_path;
        } else {
            path = temp_dir_path; // fallback to directory
        }
    } else { // non-existent (path_type == 0)
        if (use_long_path) {
            // Generate a very long path (up to 4096 characters)
            path = provider.ConsumeRandomLengthString(4096);
        } else {
            path = provider.ConsumeRandomLengthString(256);
        }
    }

    pugi::xml_document doc;

    // Load using char path (may succeed or fail)
    doc.load_file(path.c_str(), options, encoding);

    // Also try with wchar_t path with some non-ASCII characters (within Latin-1)
    std::wstring wpath;
    wpath.reserve(path.size());
    for (char c : path) {
        // Convert to wchar_t, preserving values 0-255 (Latin-1)
        wpath.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    // Optionally add a non-ASCII character if encoding allows
    if (provider.ConsumeBool() && !wpath.empty()) {
        wpath[0] = 0x80; // A non-ASCII character (within Latin-1 supplement)
    }
    doc.load_file(wpath.c_str(), options, encoding);

    // Clean up
    if (created_temp_file) {
        chmod(temp_path, 0600);
        unlink(temp_path);
    }
    if (created_temp_dir) {
        rmdir(temp_dir_path);
    }
    if (created_symlink) {
        if (created_symlink_dir) {
            unlink(symlink_dir_path);
        } else {
            unlink(symlink_path);
        }
    }

    // Explicit test for parse_fragment with empty buffer
    if (provider.ConsumeBool()) {
        pugi::xml_document doc_frag;
        doc_frag.load_buffer(nullptr, 0, options | pugi::parse_fragment, encoding);
    }

    // Test load_buffer with nullptr and non-zero size (error path)
    if (provider.ConsumeBool()) {
        pugi::xml_document doc2;
        doc2.load_buffer(nullptr, 1, options, encoding);
    }
    // Test load_buffer_inplace with nullptr and non-zero size (error path)
    if (provider.ConsumeBool()) {
        pugi::xml_document doc3;
        doc3.load_buffer_inplace(nullptr, 1, options, encoding);
    }

    // Test load_buffer, load_buffer_inplace, and load_buffer_inplace_own with remaining bytes
    std::vector<uint8_t> buffer = provider.ConsumeRemainingBytes<uint8_t>();
    if (!buffer.empty()) {
        pugi::xml_document doc4;
        doc4.load_buffer(buffer.data(), buffer.size(), options, encoding);

        std::vector<char> mutable_buffer(buffer.begin(), buffer.end());
        pugi::xml_document doc5;
        doc5.load_buffer_inplace(mutable_buffer.data(), mutable_buffer.size(), options, encoding);

        void* own_buffer = malloc(buffer.size());
        if (own_buffer) {
            memcpy(own_buffer, buffer.data(), buffer.size());
            pugi::xml_document doc6;
            doc6.load_buffer_inplace_own(own_buffer, buffer.size(), options, encoding);
        }
    }

    return 0;
}