#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Generate random parse options for strconv_pcdata_impl
    bool opt_trim = fdp.ConsumeBool();
    bool opt_eol = fdp.ConsumeBool();
    bool opt_escape = fdp.ConsumeBool();

    unsigned int random_options = pugi::parse_minimal;
    if (opt_trim) random_options |= pugi::parse_trim_pcdata;
    if (opt_eol) random_options |= pugi::parse_eol;
    if (opt_escape) random_options |= pugi::parse_escapes;

    // Additional parse options that may affect PCDATA handling
    if (fdp.ConsumeBool()) random_options |= pugi::parse_ws_pcdata;
    if (fdp.ConsumeBool()) random_options |= pugi::parse_ws_pcdata_single;
    if (fdp.ConsumeBool()) random_options |= pugi::parse_embed_pcdata;
    if (fdp.ConsumeBool()) random_options |= pugi::parse_merge_pcdata;

    // Use parse_fragment to allow parsing without a root element
    random_options |= pugi::parse_fragment;

    // Build text content from the remaining bytes
    std::string text = fdp.ConsumeRemainingBytesAsString();
    if (text.empty()) {
        text = "a";
    }

    // Parse the constructed text with the random options
    {
        pugi::xml_document doc;
        doc.load_buffer(text.data(), text.size(), random_options);
        // Traverse the document and retrieve text values to exercise more code
        for (pugi::xml_node node = doc.first_child(); node; node = node.next_sibling()) {
            if (node.type() == pugi::node_pcdata || node.type() == pugi::node_cdata) {
                (void)node.value();
            }
        }
    }

    // Parse the same text with the all-true combination (trim, eol, escape) to ensure coverage of the target instantiation.
    unsigned int target_options = pugi::parse_minimal | pugi::parse_trim_pcdata | pugi::parse_eol | pugi::parse_escapes | pugi::parse_fragment;
    {
        pugi::xml_document doc;
        doc.load_buffer(text.data(), text.size(), target_options);
        for (pugi::xml_node node = doc.first_child(); node; node = node.next_sibling()) {
            if (node.type() == pugi::node_pcdata || node.type() == pugi::node_cdata) {
                (void)node.value();
            }
        }
    }

    return 0;
}