#include "../src/pugixml.hpp"

#include <stdint.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <vector>
#include <string>
#include <algorithm>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider provider(Data, Size);

    // Consume encoding and options
    uint8_t encoding_index = provider.ConsumeIntegral<uint8_t>() % 9;
    pugi::xml_encoding encoding = static_cast<pugi::xml_encoding>(encoding_index);
    unsigned int options = provider.ConsumeIntegral<unsigned int>();

    // Remaining bytes for XML content
    std::vector<uint8_t> xml_bytes = provider.ConsumeRemainingBytes<uint8_t>();

    // Handle empty input
    if (xml_bytes.empty()) {
        pugi::xml_document doc;
        doc.load_string("", options);
        doc.load_buffer(nullptr, 0, options, encoding);
        return 0;
    }

    // Build a base string from the bytes, replacing nulls and occasionally inserting XML tokens
    std::string base_string;
    base_string.reserve(xml_bytes.size() + 64); // reserve extra space for tokens
    for (size_t i = 0; i < xml_bytes.size(); ++i) {
        uint8_t byte = xml_bytes[i];
        // Replace null bytes with spaces for load_string safety
        base_string.push_back(byte == 0 ? ' ' : static_cast<char>(byte));

        // Insert an XML token every 32 bytes to increase chance of triggering specific parsers
        if (i % 32 == 0) {
            switch (byte % 8) {
                case 0: base_string += "<!-- comment -->"; break;
                case 1: base_string += "<![CDATA[ data ]]>"; break;
                case 2: base_string += "<?target instruction?>"; break;
                case 3: base_string += "<!DOCTYPE root [ ]>"; break;
                case 4: base_string += "&amp;"; break;
                case 5: base_string += "&#x20;"; break;
                case 6: base_string += "<child/>"; break;
                case 7: base_string += "</child>"; break;
            }
        }
    }

    // Helper to wrap if not fragment
    auto wrap_if_needed = [&](unsigned int opts) -> std::string {
        if (opts & pugi::parse_fragment) {
            return base_string;
        } else {
            return "<root>" + base_string + "</root>";
        }
    };

    pugi::xml_document doc;

    // Test load_string with the main options
    std::string wrapped_main = wrap_if_needed(options);
    doc.load_string(wrapped_main.c_str(), options);

    // Test load_buffer with raw bytes and chosen encoding
    doc.load_buffer(xml_bytes.data(), xml_bytes.size(), options, encoding);

    // Additionally, test a fixed set of option combinations to cover important flags
    static const unsigned int fixed_options[] = {
        pugi::parse_minimal,
        pugi::parse_full,
        pugi::parse_fragment,
        pugi::parse_default | pugi::parse_comments,
        pugi::parse_default | pugi::parse_cdata,
        pugi::parse_default | pugi::parse_pi,
        pugi::parse_default | pugi::parse_doctype,
    };

    for (unsigned int opts : fixed_options) {
        if (opts != options) {
            std::string wrapped = wrap_if_needed(opts);
            doc.load_string(wrapped.c_str(), opts);
            doc.load_buffer(xml_bytes.data(), xml_bytes.size(), opts, encoding);
        }
    }

    return 0;
}