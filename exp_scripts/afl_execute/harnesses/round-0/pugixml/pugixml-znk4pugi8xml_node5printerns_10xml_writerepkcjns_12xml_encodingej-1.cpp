#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);

    // Consume the entire input for XML parsing.
    std::vector<uint8_t> xml_buffer = fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, Size));
    pugi::xml_document doc;
    // Parse with a random set of options to potentially generate different node types.
    unsigned int parse_options = fdp.ConsumeIntegral<unsigned int>();
    doc.load_buffer(xml_buffer.data(), xml_buffer.size(), parse_options);

    // Define a null writer that discards all output.
    class null_writer : public pugi::xml_writer {
    public:
        virtual void write(const void* /*data*/, size_t /*size*/) PUGIXML_OVERRIDE {}
    } writer;

    // Collect known formatting flags (from pugixml.hpp).
    const unsigned int known_flags[] = {
        pugi::format_indent,
        pugi::format_write_bom,
        pugi::format_raw,
        pugi::format_no_declaration,
        pugi::format_no_escapes,
        pugi::format_save_file_text,
        pugi::format_indent_attributes,
        pugi::format_no_empty_element_tags,
        pugi::format_skip_control_chars,
        pugi::format_attribute_single_quote
    };
    unsigned int flags = 0;
    for (unsigned int known_flag : known_flags) {
        if (fdp.ConsumeBool())
            flags |= known_flag;
    }
    // Also mix in some random bits to explore unknown flag combinations.
    flags |= fdp.ConsumeIntegral<unsigned int>();

    // Consume indent string (length 0–10).
    std::string indent_narrow = fdp.ConsumeBytesAsString(fdp.ConsumeIntegralInRange<size_t>(0, 10));
    std::basic_string<pugi::char_t> indent;
    for (char c : indent_narrow) {
        indent.push_back(static_cast<pugi::char_t>(c));
    }

    // Encoding: valid enum values 0–9.
    pugi::xml_encoding encoding = static_cast<pugi::xml_encoding>(
        fdp.ConsumeIntegralInRange<int>(0, 9));

    // Depth: limit to a safe range to avoid timeouts.
    unsigned int depth = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);

    // Call print on the document node.
    doc.print(writer, indent.c_str(), flags, encoding, depth);

    // Also call print on a few random nodes within the document to cover different node types.
    // Walk from the document root a random number of steps (but limit steps to avoid long walks).
    if (!doc.empty()) {
        pugi::xml_node node = doc;
        unsigned int steps = fdp.ConsumeIntegralInRange<unsigned int>(0, 20);
        for (unsigned int i = 0; i < steps && !node.empty(); ++i) {
            // Randomly choose to go to a child, sibling, or parent.
            uint8_t choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 3);
            if (choice == 0 && node.first_child())
                node = node.first_child();
            else if (choice == 1 && node.next_sibling())
                node = node.next_sibling();
            else if (choice == 2 && node.parent())
                node = node.parent();
            else
                break;
        }
        // Call print on the selected node with possibly different parameters.
        unsigned int depth2 = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);
        node.print(writer, indent.c_str(), flags, encoding, depth2);
    }

    return 0;
}