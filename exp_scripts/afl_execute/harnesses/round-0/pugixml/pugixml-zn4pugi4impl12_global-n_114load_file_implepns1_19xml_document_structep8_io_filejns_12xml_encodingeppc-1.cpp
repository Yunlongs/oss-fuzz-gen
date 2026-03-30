#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <cstdio>
#include <unistd.h>
#include <string>
#include <vector>
#include <sys/stat.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider provider(Data, Size);

    // Allow any combination of parsing flags
    unsigned int options = provider.ConsumeIntegral<unsigned int>();

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

    // Decide on the type of path: 0: non-existent, 1: regular file, 2: directory
    int path_type = provider.ConsumeIntegralInRange(0, 2);

    std::string path;
    bool created_temp_file = false;
    bool created_temp_dir = false;
    char temp_path[] = "/tmp/pugixml_fuzz_XXXXXX";
    char temp_dir_path[] = "/tmp/pugixml_fuzz_dir_XXXXXX";

    if (path_type == 1) { // regular file
        bool add_bom = provider.ConsumeBool();
        bool remove_read_perm = provider.ConsumeBool();

        // Determine file content size from the remaining bytes
        size_t max_file_size = provider.remaining_bytes();
        size_t file_content_size = provider.ConsumeIntegralInRange<size_t>(0, max_file_size);
        std::vector<uint8_t> file_contents = provider.ConsumeBytes<uint8_t>(file_content_size);

        if (add_bom) {
            // Prepend BOM according to the encoding
            switch (encoding) {
                case pugi::encoding_utf8:
                    // UTF-8 BOM: EF BB BF
                    file_contents.insert(file_contents.begin(), {0xEF, 0xBB, 0xBF});
                    break;
                case pugi::encoding_utf16_le:
                    // UTF-16 LE BOM: FF FE
                    file_contents.insert(file_contents.begin(), {0xFF, 0xFE});
                    break;
                case pugi::encoding_utf16_be:
                    // UTF-16 BE BOM: FE FF
                    file_contents.insert(file_contents.begin(), {0xFE, 0xFF});
                    break;
                case pugi::encoding_utf32_le:
                    // UTF-32 LE BOM: FF FE 00 00
                    file_contents.insert(file_contents.begin(), {0xFF, 0xFE, 0x00, 0x00});
                    break;
                case pugi::encoding_utf32_be:
                    // UTF-32 BE BOM: 00 00 FE FF
                    file_contents.insert(file_contents.begin(), {0x00, 0x00, 0xFE, 0xFF});
                    break;
                default:
                    // No BOM for other encodings
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
        path = temp_path;
        created_temp_file = true;

        if (remove_read_perm) {
            chmod(temp_path, 0); // remove all permissions
        }
    } else if (path_type == 2) { // directory
        if (mkdtemp(temp_dir_path) == NULL) return 0;
        path = temp_dir_path;
        created_temp_dir = true;
    } else { // non-existent
        path = provider.ConsumeRandomLengthString(256);
    }

    pugi::xml_document doc;

    // Load using char path (may succeed or fail)
    doc.load_file(path.c_str(), options, encoding);

    // Also try with wchar_t path (simple ASCII widening)
    std::wstring wpath;
    wpath.reserve(path.size());
    for (char c : path) {
        wpath.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
    }
    doc.load_file(wpath.c_str(), options, encoding);

    // Restore permissions and clean up
    if (created_temp_file) {
        chmod(temp_path, 0600); // restore read/write permission for owner
        unlink(temp_path);
    }
    if (created_temp_dir) {
        rmdir(temp_dir_path);
    }

    // Test load_buffer_inplace with the remaining bytes
    pugi::xml_document doc2;
    std::vector<uint8_t> buffer = provider.ConsumeRemainingBytes<uint8_t>();
    if (!buffer.empty()) {
        // Make a mutable copy for load_buffer_inplace
        std::vector<char> mutable_buffer(buffer.begin(), buffer.end());
        doc2.load_buffer_inplace(mutable_buffer.data(), mutable_buffer.size(), options, encoding);
        // Also test load_buffer with a separate copy
        pugi::xml_document doc3;
        doc3.load_buffer(buffer.data(), buffer.size(), options, encoding);
    }

    return 0;
}