#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <vector>
#include <string>
#include <sstream>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider provider(Data, Size);

    // Helper to generate a string with special characters, control characters, and ]]>
    auto generate_string = [&](size_t max_len, bool for_cdata = false) -> std::string {
        std::string str = provider.ConsumeRandomLengthString(max_len);
        if (str.empty()) return str;

        // Determine probabilities based on remaining bytes
        size_t remaining = provider.remaining_bytes();
        // Higher probability of modification when we have lots of data
        bool modify = (remaining > 0) ? (provider.ConsumeIntegralInRange(0, 99) < 30) : false;

        if (modify) {
            for (size_t i = 0; i < str.size(); ++i) {
                // 20% chance to modify this character
                if (provider.ConsumeIntegralInRange(0, 99) < 20) {
                    int choice = provider.ConsumeIntegralInRange(0, 3);
                    if (choice == 0) {
                        // Special character
                        const char specials[] = "<>&\"'";
                        str[i] = specials[provider.ConsumeIntegralInRange<size_t>(0, sizeof(specials)-2)];
                    } else if (choice == 1) {
                        // Control character (1-31)
                        str[i] = static_cast<char>(provider.ConsumeIntegralInRange<uint8_t>(1, 31));
                    } else if (choice == 2 && for_cdata) {
                        // Insert ]]> sequence (only for CDATA)
                        if (i + 2 < str.size()) {
                            str[i] = ']';
                            str[i+1] = ']';
                            str[i+2] = '>';
                            i += 2;
                        }
                    }
                    // else leave as is (choice == 3)
                }
            }
        }
        return str;
    };

    // First, try parsing the input as XML with different flags (original tests)
    size_t xml_size = provider.ConsumeIntegralInRange<size_t>(0, provider.remaining_bytes());
    std::vector<uint8_t> xml_data = provider.ConsumeBytes<uint8_t>(xml_size);
    pugi::xml_document parsed_doc1, parsed_doc2, parsed_doc3;
    pugi::xml_parse_result parse_result1 = parsed_doc1.load_buffer(xml_data.data(), xml_data.size());
    pugi::xml_parse_result parse_result2 = parsed_doc2.load_buffer(xml_data.data(), xml_data.size(), pugi::parse_minimal);
    pugi::xml_parse_result parse_result3 = parsed_doc3.load_buffer(xml_data.data(), xml_data.size(), pugi::parse_full);

    // Real writer: write to a string stream
    std::stringstream ss;
    pugi::xml_writer_stream writer(ss);

    // Helper to test a document with random parameters
    auto test_document = [&](pugi::xml_document& doc) {
        // Generate random indent
        std::string indent = generate_string(8);
        // Pick from a set of interesting flag combinations, and also random bits
        const unsigned int interesting_flags[] = {
            0,
            pugi::format_indent,
            pugi::format_raw,
            pugi::format_indent | pugi::format_indent_attributes,
            pugi::format_indent_attributes,
            pugi::format_no_declaration,
            pugi::format_no_escapes,
            pugi::format_save_file_text,
            pugi::format_no_empty_element_tags,
            pugi::format_skip_control_chars,
            pugi::format_attribute_single_quote,
            pugi::format_indent | pugi::format_no_empty_element_tags,
            pugi::format_raw | pugi::format_no_escapes,
            pugi::format_indent_attributes | pugi::format_attribute_single_quote,
        };
        unsigned int flags = provider.PickValueInArray(interesting_flags);

        // Adjust flags based on string content (we cannot know content of all strings, but we can adjust randomly)
        // We'll set flags with higher probability to explore both branches
        if (provider.ConsumeBool()) flags |= pugi::format_indent;
        if (provider.ConsumeBool()) flags |= pugi::format_raw;
        if (provider.ConsumeBool()) flags |= pugi::format_indent_attributes;
        if (provider.ConsumeBool()) flags |= pugi::format_no_declaration;
        if (provider.ConsumeBool()) flags |= pugi::format_no_escapes;
        if (provider.ConsumeBool()) flags |= pugi::format_save_file_text;
        if (provider.ConsumeBool()) flags |= pugi::format_no_empty_element_tags;
        if (provider.ConsumeBool()) flags |= pugi::format_skip_control_chars;
        if (provider.ConsumeBool()) flags |= pugi::format_attribute_single_quote;

        unsigned int depth = provider.ConsumeIntegralInRange<unsigned int>(0, 10);

        // Bias encoding selection towards non-native encodings
        pugi::xml_encoding encodings[] = {
            pugi::encoding_auto,
            pugi::encoding_utf8,
            pugi::encoding_utf16_le,
            pugi::encoding_utf16_be,
            pugi::encoding_utf16,
            pugi::encoding_utf32_le,
            pugi::encoding_utf32_be,
            pugi::encoding_utf32,
            pugi::encoding_latin1
        };
        // Increase probability of non-native encodings (indices 2,3,5,6,7)
        int encoding_index;
        if (provider.ConsumeBool()) {
            // 50% chance to pick a non-native encoding
            const int non_native[] = {2, 3, 5, 6, 7};
            encoding_index = provider.PickValueInArray(non_native);
        } else {
            encoding_index = provider.ConsumeIntegralInRange<int>(0, 8);
        }
        pugi::xml_encoding encoding = encodings[encoding_index];

        // Print entire document
        doc.print(writer, indent.c_str(), flags, encoding, depth);

        // Also test save function (which uses print with depth=0)
        if (provider.ConsumeBool()) {
            doc.save(writer, indent.c_str(), flags, encoding);
        }

        // Print a few random subtrees
        std::vector<pugi::xml_node> nodes;
        for (pugi::xml_node child = doc.first_child(); child; child = child.next_sibling()) {
            nodes.push_back(child);
            for (pugi::xml_node grandchild = child.first_child(); grandchild; grandchild = grandchild.next_sibling()) {
                nodes.push_back(grandchild);
            }
        }
        if (!nodes.empty()) {
            for (int i = 0; i < 3 && provider.remaining_bytes() > 0; ++i) {
                size_t index = provider.ConsumeIntegralInRange<size_t>(0, nodes.size() - 1);
                pugi::xml_node random_node = nodes[index];
                std::string indent2 = generate_string(4);
                unsigned int flags2 = provider.ConsumeIntegral<unsigned int>();
                unsigned int depth2 = provider.ConsumeIntegralInRange<unsigned int>(0, 5);
                pugi::xml_encoding encoding2 = provider.PickValueInArray(encodings);
                random_node.print(writer, indent2.c_str(), flags2, encoding2, depth2);
            }
        }
    };

    // Test the parsed documents
    test_document(parsed_doc1);
    test_document(parsed_doc2);
    test_document(parsed_doc3);

    // Now build a random tree using the remaining fuzzer input
    pugi::xml_document random_doc;
    std::vector<pugi::xml_node> queue;
    queue.push_back(random_doc);
    int node_count = 0;
    const int max_nodes = 200;  // Increased to allow deeper trees

    while (!queue.empty() && node_count < max_nodes && provider.remaining_bytes() > 0) {
        pugi::xml_node parent = queue.back();
        queue.pop_back();

        int num_children = provider.ConsumeIntegralInRange(0, 20);  // Increased for more siblings
        for (int i = 0; i < num_children && node_count < max_nodes && provider.remaining_bytes() > 0; ++i) {
            // Choose node type (exclude node_document and node_null)
            int node_type = provider.ConsumeIntegralInRange(0, 6);
            pugi::xml_node_type type;
            switch(node_type) {
                case 0: type = pugi::node_element; break;
                case 1: type = pugi::node_pcdata; break;
                case 2: type = pugi::node_cdata; break;
                case 3: type = pugi::node_comment; break;
                case 4: type = pugi::node_pi; break;
                case 5: type = pugi::node_declaration; break;
                case 6: type = pugi::node_doctype; break;
                default: type = pugi::node_element;
            }

            pugi::xml_node child = parent.append_child(type);
            node_count++;

            // Set name for appropriate node types (with special characters)
            if (type == pugi::node_element || type == pugi::node_pi || type == pugi::node_declaration) {
                std::string name = generate_string(20);
                child.set_name(name.c_str());
            }

            // Set value for node types that support it (with special characters)
            if (type == pugi::node_pcdata || type == pugi::node_cdata || type == pugi::node_comment ||
                type == pugi::node_pi || type == pugi::node_declaration || type == pugi::node_doctype) {
                std::string value = generate_string(30, type == pugi::node_cdata);
                child.set_value(value.c_str());
            }

            // For elements, add random attributes (with special characters)
            if (type == pugi::node_element) {
                int num_attrs = provider.ConsumeIntegralInRange(0, 10);
                for (int j = 0; j < num_attrs && provider.remaining_bytes() > 0; ++j) {
                    std::string attr_name = generate_string(10);
                    std::string attr_value = generate_string(20);
                    pugi::xml_attribute attr = child.append_attribute(attr_name.c_str());
                    attr.set_value(attr_value.c_str());
                }

                // 30% chance to set an element value (embedded PCDATA)
                if (provider.ConsumeIntegralInRange(0, 99) < 30) {
                    child.set_value(generate_string(15).c_str());
                }

                // 20% chance to create an empty element (no value, no children) by skipping the queue
                if (provider.ConsumeIntegralInRange(0, 99) < 20) {
                    // do not push to queue, so no children will be added
                } else {
                    queue.push_back(child);
                }
            }
        }
    }

    // Test the randomly generated document
    test_document(random_doc);

    return 0;
}