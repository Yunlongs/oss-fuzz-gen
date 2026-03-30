#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <string>
#include <vector>
#include <queue>

// Simple string writer that accumulates data into a std::string
class string_writer : public pugi::xml_writer {
public:
    std::string data;

    virtual void write(const void* buf, size_t size) PUGIXML_OVERRIDE {
        data.append(static_cast<const char*>(buf), size);
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);

    // Decide whether to use a null writer or a real string writer (10% chance).
    // This helps exercise the actual write paths.
    bool use_string_writer = fdp.ConsumeBool() && (fdp.ConsumeIntegralInRange(0, 9) == 0);
    string_writer swriter;
    class null_writer : public pugi::xml_writer {
    public:
        virtual void write(const void* /*data*/, size_t /*size*/) PUGIXML_OVERRIDE {}
    } nwriter;
    pugi::xml_writer& writer = use_string_writer ? static_cast<pugi::xml_writer&>(swriter) :
                                                   static_cast<pugi::xml_writer&>(nwriter);

    // Consume the entire input for XML parsing.
    std::vector<uint8_t> xml_buffer = fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, Size));
    pugi::xml_document doc;
    // Parse with a random set of options to potentially generate different node types.
    unsigned int parse_options = fdp.ConsumeIntegral<unsigned int>();
    doc.load_buffer(xml_buffer.data(), xml_buffer.size(), parse_options);

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

    // Predefined interesting flag combinations.
    const unsigned int interesting_flag_masks[] = {
        pugi::format_indent,
        pugi::format_raw,
        pugi::format_indent | pugi::format_raw,
        pugi::format_indent | pugi::format_indent_attributes,
        pugi::format_no_empty_element_tags,
        pugi::format_no_escapes,
        pugi::format_indent | pugi::format_no_empty_element_tags,
        pugi::format_raw | pugi::format_no_escapes,
        pugi::format_indent_attributes | pugi::format_attribute_single_quote,
        pugi::format_write_bom | pugi::format_indent,
        0  // No flags
    };

    // Helper to generate a random set of parameters from the fuzzer input.
    auto generate_params = [&]() -> std::tuple<unsigned int, std::basic_string<pugi::char_t>, pugi::xml_encoding, unsigned int> {
        unsigned int flags = 0;

        // Sometimes pick an interesting flag combination, otherwise build randomly.
        if (fdp.ConsumeBool()) {
            flags = fdp.PickValueInArray(interesting_flag_masks);
        } else {
            for (unsigned int known_flag : known_flags) {
                if (fdp.ConsumeBool())
                    flags |= known_flag;
            }
        }
        // Also mix in some random bits to explore unknown flag combinations.
        flags |= fdp.ConsumeIntegral<unsigned int>();

        // Consume indent string (length 0–1000 to cover more cases, including very long strings).
        // Also include some non‑ASCII bytes to test encoding conversion.
        std::string indent_narrow = fdp.ConsumeBytesAsString(fdp.ConsumeIntegralInRange<size_t>(0, 1000));
        std::basic_string<pugi::char_t> indent;
        for (char c : indent_narrow) {
            indent.push_back(static_cast<pugi::char_t>(c));
        }

        // Encoding: valid enum values 0–9 (including encoding_auto).
        pugi::xml_encoding encoding = static_cast<pugi::xml_encoding>(
            fdp.ConsumeIntegralInRange<int>(0, 9));

        // Occasionally force a non‑native encoding to exercise conversion paths.
        // UTF‑16 little‑endian is a good candidate (value 2).
        if (fdp.ConsumeBool()) {
            encoding = pugi::encoding_utf16_le;
        }

        // Depth: limit to a safe range to avoid timeouts.
        unsigned int depth = fdp.ConsumeIntegralInRange<unsigned int>(0, 100);

        return {flags, indent, encoding, depth};
    };

    // First, print the entire document with one set of parameters.
    if (fdp.remaining_bytes() >= 4) {
        auto [flags, indent, encoding, depth] = generate_params();
        doc.print(writer, indent.c_str(), flags, encoding, depth);
    }

    // Now traverse the document and print each node with its own set of parameters.
    // We use a queue for breadth‑first traversal, limited to 500 nodes to avoid timeout.
    std::queue<pugi::xml_node> node_queue;
    node_queue.push(doc);
    unsigned int processed_nodes = 0;
    const unsigned int max_nodes = 500;

    while (!node_queue.empty() && processed_nodes < max_nodes) {
        pugi::xml_node node = node_queue.front();
        node_queue.pop();

        // Generate a new set of parameters for this node.
        auto [flags, indent, encoding, depth] = generate_params();
        node.print(writer, indent.c_str(), flags, encoding, depth);

        // Enqueue child and sibling for traversal.
        if (!node.empty()) {
            if (node.first_child())
                node_queue.push(node.first_child());
            if (node.next_sibling())
                node_queue.push(node.next_sibling());
        }

        ++processed_nodes;
    }

    // Create a synthetic document that includes a variety of node types to ensure
    // coverage of all printing code paths.
    pugi::xml_document synthetic;
    // XML declaration
    synthetic.append_child(pugi::node_declaration).set_name(PUGIXML_TEXT("xml"));
    synthetic.child(PUGIXML_TEXT("xml")).append_attribute(PUGIXML_TEXT("version")) = PUGIXML_TEXT("1.0");
    synthetic.child(PUGIXML_TEXT("xml")).append_attribute(PUGIXML_TEXT("encoding")) = PUGIXML_TEXT("UTF-8");
    // Root element with attributes and mixed content
    pugi::xml_node root = synthetic.append_child(pugi::node_element);
    root.set_name(PUGIXML_TEXT("root"));
    root.append_attribute(PUGIXML_TEXT("attr1")) = PUGIXML_TEXT("value1");
    root.append_attribute(PUGIXML_TEXT("attr2")) = PUGIXML_TEXT("value2");
    root.append_child(pugi::node_pcdata).set_value(PUGIXML_TEXT("Some text"));
    root.append_child(pugi::node_comment).set_value(PUGIXML_TEXT("A comment"));
    // Processing instruction with only a target
    {
        pugi::xml_node pi = root.append_child(pugi::node_pi);
        pi.set_name(PUGIXML_TEXT("target"));
    }
    // Processing instruction with target and data
    {
        pugi::xml_node pi = root.append_child(pugi::node_pi);
        pi.set_name(PUGIXML_TEXT("other"));
        pi.set_value(PUGIXML_TEXT("data"));
    }
    root.append_child(pugi::node_cdata).set_value(PUGIXML_TEXT("<cdata> content"));
    root.append_child(pugi::node_doctype).set_value(PUGIXML_TEXT("html"));
    // Element with a namespace prefix (colon in name)
    pugi::xml_node ns = root.append_child(pugi::node_element);
    ns.set_name(PUGIXML_TEXT("ns:element"));
    ns.append_attribute(PUGIXML_TEXT("xmlns:ns")) = PUGIXML_TEXT("http://example.com");
    // Add a nested element with mixed content
    pugi::xml_node nested = root.append_child(pugi::node_element);
    nested.set_name(PUGIXML_TEXT("nested"));
    nested.append_child(pugi::node_pcdata).set_value(PUGIXML_TEXT("inner"));
    // Add an empty element
    root.append_child(pugi::node_element).set_name(PUGIXML_TEXT("empty"));

    // Print the synthetic document with a random set of parameters.
    if (fdp.remaining_bytes() >= 4) {
        auto [flags, indent, encoding, depth] = generate_params();
        synthetic.print(writer, indent.c_str(), flags, encoding, depth);
    }

    // Also traverse and print each node of the synthetic document.
    std::queue<pugi::xml_node> syn_queue;
    syn_queue.push(synthetic);
    processed_nodes = 0;
    while (!syn_queue.empty() && processed_nodes < max_nodes && fdp.remaining_bytes() >= 4) {
        pugi::xml_node node = syn_queue.front();
        syn_queue.pop();

        auto [flags, indent, encoding, depth] = generate_params();
        node.print(writer, indent.c_str(), flags, encoding, depth);

        if (!node.empty()) {
            if (node.first_child())
                syn_queue.push(node.first_child());
            if (node.next_sibling())
                syn_queue.push(node.next_sibling());
        }

        ++processed_nodes;
    }

    return 0;
}