#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <vector>
#include <string>
#include <algorithm>
#include <functional>

// A simple xml_writer that writes to a std::string
class string_writer : public pugi::xml_writer
{
public:
    std::string result;
    virtual void write(const void* data, size_t size) override
    {
        result.append(static_cast<const char*>(data), size);
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);

    // Original parsing fuzzing (kept for compatibility)
    pugi::xml_document doc;
    std::vector<uint8_t> xml_buffer = fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, Size));
    if (xml_buffer.size() > 0)
    {
        doc.load_buffer(xml_buffer.data(), xml_buffer.size());
        doc.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_minimal);
        doc.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_full);
    }

    // Fuzzing for text_output_indent with enhanced coverage
    if (fdp.remaining_bytes() > 0)
    {
        // Generate flags: mask with all known format flags
        const unsigned int all_flags = 0x3FF; // format_indent|format_write_bom|format_raw|format_no_declaration|
                                              // format_no_escapes|format_save_file_text|format_indent_attributes|
                                              // format_no_empty_element_tags|format_skip_control_chars|format_attribute_single_quote
        unsigned int flags = fdp.ConsumeIntegral<uint32_t>() & all_flags;

        // Generate indent length: specifically target the switch cases and extreme values
        unsigned int indent_length_choice = fdp.ConsumeIntegralInRange<unsigned int>(0, 10);
        unsigned int indent_length;
        switch (indent_length_choice % 6)
        {
            case 0: indent_length = 0; break;
            case 1: indent_length = 1; break;
            case 2: indent_length = 2; break;
            case 3: indent_length = 3; break;
            case 4: indent_length = 4; break;
            default: indent_length = fdp.ConsumeIntegralInRange<unsigned int>(5, 10000); break;
        }

        // Generate indent string without null characters
        std::string indent;
        if (indent_length > 0)
        {
            indent = fdp.ConsumeBytesAsString(indent_length);
            std::replace(indent.begin(), indent.end(), '\0', ' ');
        }

        // Generate tree depth and breadth with extreme values
        unsigned int depth = fdp.ConsumeIntegralInRange<unsigned int>(0, 1000);
        unsigned int max_children = fdp.ConsumeIntegralInRange<unsigned int>(1, 10);

        // Create XML tree with mixed node types
        pugi::xml_document doc2;
        pugi::xml_node root = doc2.append_child(pugi::node_element);
        root.set_name("root");

        // Helper to build tree with attributes, text content, and mixed node types
        std::function<void(pugi::xml_node, unsigned int)> build_tree;
        build_tree = [&](pugi::xml_node node, unsigned int cur_depth) {
            if (cur_depth >= depth)
                return;

            // Add attributes to trigger node_output_attributes
            unsigned int attr_count = fdp.ConsumeIntegralInRange<unsigned int>(0, 3);
            for (unsigned int i = 0; i < attr_count && fdp.remaining_bytes() > 0; ++i)
            {
                std::string attr_name = fdp.ConsumeRandomLengthString(10);
                std::replace(attr_name.begin(), attr_name.end(), '\0', '_');
                std::string attr_value = fdp.ConsumeRandomLengthString(10);
                std::replace(attr_value.begin(), attr_value.end(), '\0', '_');
                node.append_attribute(attr_name.c_str()).set_value(attr_value.c_str());
            }

            // Sometimes add text content to this element (to test indent_flags reset)
            if (cur_depth % 2 == 0 && fdp.remaining_bytes() > 0)
            {
                std::string text = fdp.ConsumeRandomLengthString(10);
                node.set_value(text.c_str());
            }

            // Create children of various types
            unsigned int children = fdp.ConsumeIntegralInRange<unsigned int>(0, max_children);
            for (unsigned int i = 0; i < children && fdp.remaining_bytes() > 0; ++i)
            {
                // Occasionally create a comment, processing instruction, declaration, or doctype
                unsigned int node_type_choice = fdp.ConsumeIntegralInRange<unsigned int>(0, 20);
                pugi::xml_node child;
                if (node_type_choice == 0 && cur_depth > 0)
                {
                    child = node.append_child(pugi::node_comment);
                    child.set_value(fdp.ConsumeRandomLengthString(20).c_str());
                }
                else if (node_type_choice == 1 && cur_depth > 0)
                {
                    child = node.append_child(pugi::node_pi);
                    child.set_name(fdp.ConsumeRandomLengthString(5).c_str());
                    child.set_value(fdp.ConsumeRandomLengthString(15).c_str());
                }
                else if (node_type_choice == 2 && cur_depth == 0)
                {
                    // Declaration and doctype are only allowed at document level
                    child = doc2.append_child(pugi::node_declaration);
                    child.set_name("xml");
                    child.append_attribute("version").set_value("1.0");
                }
                else if (node_type_choice == 3 && cur_depth == 0)
                {
                    child = doc2.append_child(pugi::node_doctype);
                    child.set_value("html");
                }
                else
                {
                    child = node.append_child(pugi::node_element);
                    child.set_name("child");
                }
                build_tree(child, cur_depth + 1);
            }
        };

        build_tree(root, 0);

        // Ensure at least one attribute if format_indent_attributes is set (to trigger that path)
        if ((flags & pugi::format_indent_attributes) && !root.first_attribute() && fdp.remaining_bytes() > 0)
        {
            std::string attr_name = fdp.ConsumeRandomLengthString(5);
            std::replace(attr_name.begin(), attr_name.end(), '\0', '_');
            std::string attr_value = fdp.ConsumeRandomLengthString(5);
            std::replace(attr_value.begin(), attr_value.end(), '\0', '_');
            root.append_attribute(attr_name.c_str()).set_value(attr_value.c_str());
        }

        // Real writer that writes to a string
        string_writer writer;

        // Call print with various flags and indent
#ifndef PUGIXML_NO_EXCEPTIONS
        try
#endif
        {
            // First, print the entire tree with the generated flags
            root.print(writer, indent.empty() ? "" : indent.c_str(), flags, pugi::encoding_auto, 0);

            // Also test with different starting depths (allow larger offset)
            if (fdp.remaining_bytes() > 0)
            {
                unsigned int start_depth = fdp.ConsumeIntegralInRange<unsigned int>(0, 1000);
                root.print(writer, indent.empty() ? "" : indent.c_str(), flags, pugi::encoding_auto, start_depth);
            }

            // Print a child node if exists (to test different depth calculations)
            if (root.first_child())
            {
                root.first_child().print(writer, indent.empty() ? "" : indent.c_str(), flags, pugi::encoding_auto, 0);
            }

            // Test a set of predefined flag combinations to ensure coverage
            const unsigned int flag_combos[] = {
                pugi::format_indent,
                pugi::format_indent_attributes,
                pugi::format_indent | pugi::format_indent_attributes,
                pugi::format_raw,
                pugi::format_indent | pugi::format_raw,
                pugi::format_indent_attributes | pugi::format_raw,
                pugi::format_indent | pugi::format_indent_attributes | pugi::format_raw,
                0
            };
            for (unsigned int special_flags : flag_combos)
            {
                if (fdp.remaining_bytes() == 0) break;
                root.print(writer, indent.empty() ? "" : indent.c_str(), special_flags, pugi::encoding_auto, 0);
            }

            // Test different encodings
            const pugi::xml_encoding encodings[] = {
                pugi::encoding_auto,
                pugi::encoding_utf8,
                pugi::encoding_latin1,
                pugi::encoding_utf16_le,
                pugi::encoding_utf16_be,
                pugi::encoding_utf32_le,
                pugi::encoding_utf32_be
            };
            if (fdp.remaining_bytes() > 0)
            {
                unsigned int encoding_choice = fdp.ConsumeIntegralInRange<unsigned int>(0, 6);
                root.print(writer, indent.empty() ? "" : indent.c_str(), flags, encodings[encoding_choice], 0);
            }
        }
#ifndef PUGIXML_NO_EXCEPTIONS
        catch (const pugi::xpath_exception&)
        {
            // Ignore exceptions
        }
#endif
    }

    return 0;
}