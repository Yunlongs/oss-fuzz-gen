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

    // Build text content with deliberate patterns to increase coverage
    std::string text;

    // First, add a random prefix from the remaining bytes
    size_t total_remaining = fdp.remaining_bytes();
    if (total_remaining > 0) {
        size_t prefix_len = fdp.ConsumeIntegralInRange<size_t>(0, total_remaining);
        std::string prefix = fdp.ConsumeBytesAsString(prefix_len);
        text += prefix;
    }

    // Special patterns that trigger various branches in strconv_pcdata_impl and strconv_escape
    std::vector<std::string> patterns = {
        "   ",                     // spaces for trimming
        "\r",                     // carriage return (single)
        "\r\n",                   // CRLF
        "&amp;",                  // named entity
        "&lt;",
        "&gt;",
        "&quot;",
        "&apos;",
        "&#65;",                  // decimal numeric entity
        "&#x41;",                 // hex numeric entity
        "&",                      // bare ampersand
        "<",                      // less-than (may end PCDATA)
        // Malformed entities
        "&;",                     // bare ampersand with semicolon
        "&#;",                    // empty decimal
        "&#x;",                   // empty hex
        "&#xg;",                  // invalid hex digit
        "&#123a;",                // invalid trailing char in decimal
        "&am;",                   // partial named entity (amp)
        "&apo;",                  // partial named entity (apos)
        "&unknown;",              // unrecognized named entity
        // Edge cases for numeric entities
        "&#0;",                   // zero decimal
        "&#x0;",                  // zero hex
        "&#999999;",              // large decimal
        "&#xabcdef;",             // large hex
        // Multiple spaces for gap handling
        "    ",
        // Carriage return variants
        "\r\r",
        "\r\n\r\n",
    };

    // Interleave random bytes and patterns until we run out of fuzzer data
    while (fdp.remaining_bytes() > 0 && !patterns.empty()) {
        if (fdp.ConsumeBool()) {
            // Add a pattern
            size_t pattern_index = fdp.ConsumeIntegralInRange<size_t>(0, patterns.size() - 1);
            std::string pattern = patterns[pattern_index];
            text += pattern;
        } else {
            // Add a small chunk of random bytes
            size_t len = fdp.ConsumeIntegralInRange<size_t>(1, 10);
            if (len > fdp.remaining_bytes()) len = fdp.remaining_bytes();
            text += fdp.ConsumeBytesAsString(len);
        }
    }

    // Ensure text is not empty to increase chance of creating a text node
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

    // Additionally, parse the same text with all eight combinations of trim, eol, escape
    // to ensure coverage of all strconv_pcdata_impl instantiations.
    const unsigned int flag_combinations[8][3] = {
        {0,0,0}, {0,0,1}, {0,1,0}, {0,1,1},
        {1,0,0}, {1,0,1}, {1,1,0}, {1,1,1}
    };
    for (int i = 0; i < 8; ++i) {
        unsigned int options = pugi::parse_minimal;
        if (flag_combinations[i][0]) options |= pugi::parse_trim_pcdata;
        if (flag_combinations[i][1]) options |= pugi::parse_eol;
        if (flag_combinations[i][2]) options |= pugi::parse_escapes;
        options |= pugi::parse_fragment;

        pugi::xml_document doc;
        doc.load_buffer(text.data(), text.size(), options);
        for (pugi::xml_node node = doc.first_child(); node; node = node.next_sibling()) {
            if (node.type() == pugi::node_pcdata || node.type() == pugi::node_cdata) {
                (void)node.value();
            }
        }
    }

    return 0;
}