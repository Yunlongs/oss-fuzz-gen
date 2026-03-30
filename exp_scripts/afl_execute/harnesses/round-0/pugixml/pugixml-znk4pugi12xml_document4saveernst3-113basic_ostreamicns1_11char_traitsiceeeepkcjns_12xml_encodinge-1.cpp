#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <sstream>
#include <vector>
#include <string>
#include <functional>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return 0;
    }

    // Use first byte to split input into XML and manual parts
    uint8_t split_byte = Data[0];
    size_t split = (split_byte * (Size - 1)) / 255;
    if (split == 0) split = 1;
    if (split > Size - 1) split = Size - 1;

    // XML part: bytes 1 to 1+split
    std::vector<uint8_t> xml_buffer(Data + 1, Data + 1 + split);
    // Manual part: the rest, used for FuzzedDataProvider
    FuzzedDataProvider fdp(Data + 1 + split, Size - 1 - split);

    // Part 1: Load a document from the XML buffer
    pugi::xml_document doc;
    doc.load_buffer(xml_buffer.data(), xml_buffer.size());
    doc.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_minimal);
    doc.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_full);

    if (!doc.first_child()) {
        doc.append_child(pugi::node_element).set_name("root");
    }
    // Quick save with default parameters
    std::ostringstream os;
    doc.save(os, "\t", pugi::format_default, pugi::encoding_auto);

    // Part 2: Build a highly configurable manual document using fdp
    pugi::xml_document manual_doc;

    // Decide whether to include declaration and doctype
    if (fdp.ConsumeBool()) {
        pugi::xml_node decl = manual_doc.append_child(pugi::node_declaration);
        decl.append_attribute("version") = "1.0";
        decl.append_attribute("encoding") = fdp.ConsumeBool() ? "UTF-8" : "ISO-8859-1";
    }
    if (fdp.ConsumeBool()) {
        manual_doc.append_child(pugi::node_doctype).set_value(fdp.ConsumeRandomLengthString(100).c_str());
    }

    // Recursive function to build a tree
    std::function<void(pugi::xml_node, int)> build_tree;
    build_tree = [&](pugi::xml_node parent, int depth) {
        if (depth <= 0 || fdp.remaining_bytes() < 10)
            return;

        int children = fdp.ConsumeIntegralInRange(0, 5);
        for (int i = 0; i < children; ++i) {
            pugi::xml_node child;
            int node_type_choice = fdp.ConsumeIntegralInRange(0, 5);
            switch (node_type_choice) {
                case 0: { // element
                    child = parent.append_child(pugi::node_element);
                    // Sometimes anonymous element (no name)
                    if (fdp.ConsumeBool()) {
                        child.set_name(fdp.ConsumeRandomLengthString(15).c_str());
                    }
                    // Add some attributes
                    int attr_count = fdp.ConsumeIntegralInRange(0, 4);
                    for (int a = 0; a < attr_count; ++a) {
                        std::string attr_name = fdp.ConsumeRandomLengthString(10);
                        std::string attr_value = fdp.ConsumeRandomLengthString(20);
                        // Occasionally insert special characters that need escaping
                        if (fdp.ConsumeBool()) {
                            attr_value = "value with <&>\"'";
                        }
                        child.append_attribute(attr_name.c_str()) = attr_value.c_str();
                    }
                    // Recurse
                    build_tree(child, depth - 1);
                    break;
                }
                case 1: // comment
                    child = parent.append_child(pugi::node_comment);
                    child.set_value(fdp.ConsumeRandomLengthString(50).c_str());
                    break;
                case 2: // processing instruction
                    child = parent.append_child(pugi::node_pi);
                    child.set_value(fdp.ConsumeRandomLengthString(50).c_str());
                    break;
                case 3: // cdata
                    child = parent.append_child(pugi::node_cdata);
                    child.set_value(fdp.ConsumeRandomLengthString(50).c_str());
                    break;
                case 4: // pcdata
                    child = parent.append_child(pugi::node_pcdata);
                    // Sometimes empty pcdata
                    if (fdp.ConsumeBool()) {
                        child.set_value(fdp.ConsumeRandomLengthString(50).c_str());
                    }
                    break;
                case 5: // empty (no node)
                    break;
            }
        }
    };

    pugi::xml_node root = manual_doc.append_child(pugi::node_element);
    root.set_name("root");
    build_tree(root, fdp.ConsumeIntegralInRange(1, 5));

    // Part 3: Generate save parameters
    // Predefined interesting flag combinations
    const unsigned int flag_sets[] = {
        0,
        pugi::format_indent,
        pugi::format_write_bom,
        pugi::format_raw,
        pugi::format_no_declaration,
        pugi::format_no_escapes,
        pugi::format_save_file_text,
        pugi::format_indent_attributes,
        pugi::format_no_empty_element_tags,
        pugi::format_skip_control_chars,
        pugi::format_attribute_single_quote,
        pugi::format_indent | pugi::format_indent_attributes,
        pugi::format_raw | pugi::format_no_escapes,
        pugi::format_indent | pugi::format_write_bom,
        pugi::format_default,
    };
    unsigned int flags;
    if (fdp.ConsumeBool()) {
        // Pick from predefined set
        flags = flag_sets[fdp.ConsumeIntegralInRange<size_t>(0, sizeof(flag_sets)/sizeof(flag_sets[0]) - 1)];
    } else {
        // Random flags
        flags = fdp.ConsumeIntegral<unsigned int>();
    }

    // Indent string: sometimes empty, sometimes random
    std::string indent;
    if (fdp.ConsumeBool()) {
        indent = fdp.ConsumeRandomLengthString(10);
    } // else empty

    // Encoding: ensure Latin1 and non-Latin1 are both tested
    pugi::xml_encoding encoding;
    int encoding_choice = fdp.ConsumeIntegralInRange(0, 10);
    if (encoding_choice == 9) {
        encoding = pugi::encoding_latin1;
    } else {
        encoding = static_cast<pugi::xml_encoding>(encoding_choice);
    }

    // Save manual document with chosen parameters
    std::ostringstream os1;
    manual_doc.save(os1, indent.c_str(), flags, encoding);

    // Save again with toggled format_raw and format_indent to explore different formatting
    std::ostringstream os2;
    unsigned int flags2 = flags;
    flags2 ^= pugi::format_raw;
    flags2 ^= pugi::format_indent;
    manual_doc.save(os2, indent.c_str(), flags2, encoding);

    // Wide stream overload (always call)
    std::basic_ostringstream<wchar_t> wos;
    manual_doc.save(wos, indent.c_str(), flags);

    return 0;
}