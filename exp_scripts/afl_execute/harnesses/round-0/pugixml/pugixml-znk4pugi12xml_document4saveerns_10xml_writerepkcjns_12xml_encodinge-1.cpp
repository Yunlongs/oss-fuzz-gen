#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <vector>
#include <cstring>
#include <algorithm>

class FuzzWriter : public pugi::xml_writer {
public:
    virtual void write(const void* /*data*/, size_t /*size*/) override {
        // Discard output to focus on the save logic.
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size == 0) return 0;

    FuzzedDataProvider fdp(Data, Size);

    // Generate 1 to 3 load attempts to test different XML data and parse flags.
    unsigned int num_loads = fdp.ConsumeIntegralInRange<unsigned int>(1, 3);
    for (unsigned int load_idx = 0; load_idx < num_loads && fdp.remaining_bytes() > 0; ++load_idx) {
        // Consume XML data size, limited to 1024 bytes to avoid excessive memory usage.
        size_t xml_size = fdp.ConsumeIntegralInRange<size_t>(0, std::min(fdp.remaining_bytes(), size_t(1024)));
        std::vector<uint8_t> xml_data = fdp.ConsumeBytes<uint8_t>(xml_size);

        // Use random parse flags to diversify the document structure (e.g., include comments, declarations).
        unsigned int parse_flags = fdp.ConsumeIntegral<unsigned int>();

        pugi::xml_document doc;
        doc.load_buffer(xml_data.data(), xml_data.size(), parse_flags);

        // Generate 1 to 5 save calls per document to exercise different save parameters.
        unsigned int num_saves = fdp.ConsumeIntegralInRange<unsigned int>(1, 5);
        for (unsigned int save_idx = 0; save_idx < num_saves && fdp.remaining_bytes() > 0; ++save_idx) {
            // Generate indent string: a null-terminated sequence of pugi::char_t.
            size_t max_indent_chars = fdp.remaining_bytes() / sizeof(pugi::char_t);
            size_t indent_chars = fdp.ConsumeIntegralInRange<size_t>(0, std::min(max_indent_chars, size_t(100)));
            std::vector<pugi::char_t> indent(indent_chars + 1);
            if (indent_chars > 0) {
                auto bytes = fdp.ConsumeBytes<uint8_t>(indent_chars * sizeof(pugi::char_t));
                if (!bytes.empty()) {
                    std::memcpy(indent.data(), bytes.data(), bytes.size());
                }
            }
            indent[indent_chars] = 0;

            // Flags and encoding.
            unsigned int flags = fdp.ConsumeIntegral<unsigned int>();
            pugi::xml_encoding encoding = static_cast<pugi::xml_encoding>(fdp.ConsumeIntegralInRange<int>(0, 8));

            FuzzWriter writer;
            doc.save(writer, indent.data(), flags, encoding);
        }
    }

    return 0;
}