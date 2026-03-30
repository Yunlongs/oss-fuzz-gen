#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <functional>

static const char* special_strings[] = {
    "<>&\"'",
    "]]>",
    "--",
    "?>",
    "\n",
    "\t",
    "&#x0;",
    "&#0;",
    "&#;",
    "&#x;",
    "&#xD;",
    "&#xA;",
    "&#x2028;",
    "&#x2029;",
    "&#xFEFF;",
    "&#xFFFE;",
    "&#xFFFF;",
    "&#x10FFFF;",
    "&#x110000;",
    "&#xFFFFFFFF;",
    "&#x80000000;",
    "&#x7FFFFFFF;",
    "\xC3\xA9",          // é
    "\xE2\x82\xAC",      // €
    "\xF0\x9F\x8E\x89",  // 🎉
    "\xCE\xB1",          // α
};

static void build_manual_document(pugi::xml_node node, FuzzedDataProvider& fdp, int depth, bool use_special) {
    if (depth <= 0) return;

    // Decide the number of children at this level
    int num_children = fdp.ConsumeIntegralInRange(0, 4);
    for (int i = 0; i < num_children; ++i) {
        // Decide node type
        int node_type = fdp.ConsumeIntegralInRange(0, 6);
        pugi::xml_node child;
        switch (node_type) {
            case 0: child = node.append_child(pugi::node_element); break;
            case 1: child = node.append_child(pugi::node_pcdata); break;
            case 2: child = node.append_child(pugi::node_cdata); break;
            case 3: child = node.append_child(pugi::node_comment); break;
            case 4: child = node.append_child(pugi::node_pi); break;
            case 5: child = node.append_child(pugi::node_declaration); break;
            case 6: child = node.append_child(pugi::node_doctype); break;
        }
        // Set name and value
        if (node_type == 0 || node_type == 4 || node_type == 5 || node_type == 6) {
            std::string name;
            if (use_special && fdp.ConsumeBool()) {
                name = fdp.PickValueInArray(special_strings);
            } else {
                name = fdp.ConsumeRandomLengthString(16);
            }
            child.set_name(name.c_str());
        }
        if (node_type == 1 || node_type == 2 || node_type == 3 || node_type == 4) {
            std::string value;
            if (use_special && fdp.ConsumeBool()) {
                value = fdp.PickValueInArray(special_strings);
            } else {
                value = fdp.ConsumeRandomLengthString(64);
            }
            child.set_value(value.c_str());
        }
        // For element nodes, add attributes and possibly a value, then maybe recurse
        if (node_type == 0) {
            // Sometimes give the element a value (simulating parse_embed_pcdata)
            if (fdp.ConsumeBool()) {
                std::string elem_value;
                if (use_special && fdp.ConsumeBool()) {
                    elem_value = fdp.PickValueInArray(special_strings);
                } else {
                    elem_value = fdp.ConsumeRandomLengthString(64);
                }
                child.set_value(elem_value.c_str());
            }
            // Add attributes
            int num_attrs = fdp.ConsumeIntegralInRange(0, 3);
            for (int j = 0; j < num_attrs; ++j) {
                std::string attr_name;
                std::string attr_value;
                if (use_special && fdp.ConsumeBool()) {
                    attr_name = fdp.PickValueInArray(special_strings);
                } else {
                    attr_name = fdp.ConsumeRandomLengthString(16);
                }
                if (use_special && fdp.ConsumeBool()) {
                    attr_value = fdp.PickValueInArray(special_strings);
                } else {
                    attr_value = fdp.ConsumeRandomLengthString(32);
                }
                child.append_attribute(attr_name.c_str()) = attr_value.c_str();
            }
            // Decide whether to add children to this element
            bool add_children = fdp.ConsumeBool();
            if (add_children) {
                build_manual_document(child, fdp, depth - 1, use_special);
            }
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);

    // Generate indent string from a set of possibilities plus a random string
    static const char* indent_candidates[] = {"", "\t", "  ", "\n", "    ", "\n\t", "  &amp; ", "<indent>", "&#x09;&#x0A;"};
    std::string indent;
    if (fdp.ConsumeBool()) {
        indent = fdp.PickValueInArray(indent_candidates);
    } else {
        indent = fdp.ConsumeRandomLengthString(128);
    }

    // Build format flags by toggling known flags
    unsigned int flags = 0;
    if (fdp.ConsumeBool()) flags |= pugi::format_indent;
    if (fdp.ConsumeBool()) flags |= pugi::format_write_bom;
    if (fdp.ConsumeBool()) flags |= pugi::format_raw;
    if (fdp.ConsumeBool()) flags |= pugi::format_no_declaration;
    if (fdp.ConsumeBool()) flags |= pugi::format_no_escapes;
    if (fdp.ConsumeBool()) flags |= pugi::format_save_file_text;
    if (fdp.ConsumeBool()) flags |= pugi::format_indent_attributes;
    if (fdp.ConsumeBool()) flags |= pugi::format_no_empty_element_tags;
    if (fdp.ConsumeBool()) flags |= pugi::format_skip_control_chars;
    if (fdp.ConsumeBool()) flags |= pugi::format_attribute_single_quote;
    // Also add random extra bits to explore unknown combinations
    flags |= fdp.ConsumeIntegral<unsigned int>() & 0xFFFF0000;

    // Encoding for print
    pugi::xml_encoding encoding = static_cast<pugi::xml_encoding>(
        fdp.ConsumeIntegralInRange(0, static_cast<int>(pugi::encoding_latin1)));

    // Depth parameter
    unsigned int depth = fdp.ConsumeIntegralInRange<unsigned int>(0, 1000);

    // Build parse options similarly, but only 1 load to save input
    unsigned int parse_options = 0;
    pugi::xml_encoding load_encoding;
    {
        unsigned int opts = 0;
        if (fdp.ConsumeBool()) opts |= pugi::parse_pi;
        if (fdp.ConsumeBool()) opts |= pugi::parse_comments;
        if (fdp.ConsumeBool()) opts |= pugi::parse_cdata;
        if (fdp.ConsumeBool()) opts |= pugi::parse_ws_pcdata;
        if (fdp.ConsumeBool()) opts |= pugi::parse_escapes;
        if (fdp.ConsumeBool()) opts |= pugi::parse_eol;
        if (fdp.ConsumeBool()) opts |= pugi::parse_wconv_attribute;
        if (fdp.ConsumeBool()) opts |= pugi::parse_wnorm_attribute;
        if (fdp.ConsumeBool()) opts |= pugi::parse_declaration;
        if (fdp.ConsumeBool()) opts |= pugi::parse_doctype;
        if (fdp.ConsumeBool()) opts |= pugi::parse_ws_pcdata_single;
        if (fdp.ConsumeBool()) opts |= pugi::parse_trim_pcdata;
        if (fdp.ConsumeBool()) opts |= pugi::parse_fragment;
        if (fdp.ConsumeBool()) opts |= pugi::parse_embed_pcdata;
        if (fdp.ConsumeBool()) opts |= pugi::parse_merge_pcdata;
        // Add random extra bits
        opts |= fdp.ConsumeIntegral<unsigned int>() & 0xFFFF0000;
        parse_options = opts;
        load_encoding = static_cast<pugi::xml_encoding>(
            fdp.ConsumeIntegralInRange(0, static_cast<int>(pugi::encoding_latin1)));
    }

    // XML buffer (reduced max size to leave bytes for manual document)
    const size_t max_xml_size = 2048;
    size_t xml_size = fdp.ConsumeIntegralInRange<size_t>(0, std::min(max_xml_size, fdp.remaining_bytes()));
    std::vector<uint8_t> xml_buffer = fdp.ConsumeBytes<uint8_t>(xml_size);

    // One load with parameters
    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_buffer(xml_buffer.data(), xml_buffer.size(), parse_options, load_encoding);

    // Optionally mutate the document if parsing succeeded (or even if not, we can still add nodes)
    if (result) {
        // Add a random attribute to the root element (if any)
        pugi::xml_node root = doc.document_element();
        if (root) {
            std::string attr_name = fdp.ConsumeRandomLengthString(32);
            std::string attr_value = fdp.ConsumeRandomLengthString(64);
            root.append_attribute(attr_name.c_str()) = attr_value.c_str();
        }
        // Add a random child node
        if (fdp.ConsumeBool()) {
            pugi::xml_node child = doc.append_child(fdp.ConsumeRandomLengthString(16).c_str());
            if (child) {
                child.append_child(pugi::node_pcdata).set_value(fdp.ConsumeRandomLengthString(128).c_str());
            }
        }
    }

    // Print entire document to char stream
    std::ostringstream oss;
    doc.print(oss, indent.c_str(), flags, encoding, depth);

    // Print entire document to wchar_t stream
    std::wostringstream woss;
    doc.print(woss, indent.c_str(), flags, depth);

    // Traverse and print each node individually
    std::function<void(pugi::xml_node, unsigned int)> traverse =
        [&](pugi::xml_node node, unsigned int d) {
            if (d > 20) return;
            std::ostringstream oss_node;
            node.print(oss_node, indent.c_str(), flags, encoding, d);
            for (pugi::xml_node child = node.first_child(); child; child = child.next_sibling()) {
                traverse(child, d + 1);
            }
        };
    for (pugi::xml_node node = doc.first_child(); node; node = node.next_sibling()) {
        traverse(node, 0);
    }

    // Build and print a manual document with diverse node types, using special strings if requested
    bool use_special = fdp.ConsumeBool();
    if (fdp.remaining_bytes() > 0) {
        pugi::xml_document manual_doc;
        build_manual_document(manual_doc, fdp, 5, use_special); // max depth 5

        // Add targeted edge‑case nodes when use_special is true
        if (use_special) {
            // Empty element (no children, no value)
            pugi::xml_node empty = manual_doc.append_child("empty");
            // Element with many attributes to test attribute indentation
            pugi::xml_node many_attrs = manual_doc.append_child("many_attrs");
            for (int k = 0; k < 10; ++k) {
                std::string attr_name = "attr" + std::to_string(k);
                many_attrs.append_attribute(attr_name.c_str()) = "value";
            }
            // CDATA node containing ]]> to force splitting
            pugi::xml_node cdata_node = manual_doc.append_child(pugi::node_cdata);
            cdata_node.set_value("]]>");
            // Comment containing --
            pugi::xml_node comment_node = manual_doc.append_child(pugi::node_comment);
            comment_node.set_value("--");
            // Processing instruction containing ?>
            pugi::xml_node pi_node = manual_doc.append_child(pugi::node_pi);
            pi_node.set_name("test");
            pi_node.set_value("?>");
        }

        // Print entire manual document to char stream with the same flags
        std::ostringstream oss_manual;
        manual_doc.print(oss_manual, indent.c_str(), flags, encoding, depth);

        // Print entire manual document to wchar_t stream
        std::wostringstream woss_manual;
        manual_doc.print(woss_manual, indent.c_str(), flags, depth);

        // Also print with a different set of flags (inverted some flags)
        unsigned int alt_flags = flags ^ (pugi::format_raw | pugi::format_indent);
        std::ostringstream oss_manual2;
        manual_doc.print(oss_manual2, indent.c_str(), alt_flags, encoding, depth);

        // When use_special is true, print with a custom flag set that enables attribute indentation and empty‑element formatting
        if (use_special) {
            unsigned int test_flags = pugi::format_indent_attributes | pugi::format_no_empty_element_tags;
            test_flags &= ~pugi::format_raw;   // ensure raw is off
            test_flags |= pugi::format_indent; // keep indentation
            // Also copy other flags that do not interfere
            test_flags |= flags & (pugi::format_write_bom | pugi::format_no_declaration | pugi::format_no_escapes |
                                   pugi::format_save_file_text | pugi::format_skip_control_chars |
                                   pugi::format_attribute_single_quote);
            std::ostringstream oss_test;
            manual_doc.print(oss_test, indent.c_str(), test_flags, encoding, depth);
        }

        // Traverse and print each node individually
        std::function<void(pugi::xml_node, unsigned int)> traverse_manual =
            [&](pugi::xml_node node, unsigned int d) {
                if (d > 20) return;
                std::ostringstream oss_node;
                node.print(oss_node, indent.c_str(), flags, encoding, d);
                for (pugi::xml_node child = node.first_child(); child; child = child.next_sibling()) {
                    traverse_manual(child, d + 1);
                }
            };
        for (pugi::xml_node node = manual_doc.first_child(); node; node = node.next_sibling()) {
            traverse_manual(node, 0);
        }
    }

    // Print a null node (should do nothing)
    pugi::xml_node null_node;
    std::ostringstream null_oss;
    null_node.print(null_oss, indent.c_str(), flags, encoding, depth);
    std::wostringstream null_woss;
    null_node.print(null_woss, indent.c_str(), flags, depth);

    return 0;
}