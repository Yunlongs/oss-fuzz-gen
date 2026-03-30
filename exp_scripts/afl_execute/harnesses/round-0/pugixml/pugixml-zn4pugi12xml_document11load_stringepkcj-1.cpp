#include "../src/pugixml.hpp"

#include <stdint.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <vector>
#include <string>
#include <algorithm>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    FuzzedDataProvider provider(Data, Size);

    // Consume a small portion for encoding and options
    uint8_t encoding_index = provider.ConsumeIntegral<uint8_t>() % 9;
    pugi::xml_encoding encoding = static_cast<pugi::xml_encoding>(encoding_index);

    // Use the remaining bytes for the XML content
    std::vector<uint8_t> xml_bytes = provider.ConsumeRemainingBytes<uint8_t>();
    if (xml_bytes.empty()) return 0;

    // Prepare a string version with null bytes replaced by spaces for load_string
    std::string xml_string;
    xml_string.reserve(xml_bytes.size());
    for (uint8_t byte : xml_bytes) {
        xml_string.push_back(byte == 0 ? ' ' : static_cast<char>(byte));
    }

    // Wrap the string in a root tag to increase chance of valid parsing
    std::string wrapped = "<root>" + xml_string + "</root>";

    // Pick a random set of parsing options
    unsigned int options = provider.ConsumeIntegral<unsigned int>();

    pugi::xml_document doc;

    // Test load_string with the wrapped string and random options
    doc.load_string(wrapped.c_str(), options);

    // Test load_buffer with the raw bytes and random options+encoding
    doc.load_buffer(xml_bytes.data(), xml_bytes.size(), options, encoding);

    // Additionally, test a few fixed option sets that are known to trigger different parsers
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
        // Only test if the options are different from the random ones to avoid duplicate work
        if (opts != options) {
            doc.load_string(wrapped.c_str(), opts);
            doc.load_buffer(xml_bytes.data(), xml_bytes.size(), opts, encoding);
        }
    }

    return 0;
}