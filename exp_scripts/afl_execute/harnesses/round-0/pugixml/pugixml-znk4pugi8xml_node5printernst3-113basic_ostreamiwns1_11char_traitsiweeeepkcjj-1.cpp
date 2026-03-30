#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <streambuf>
#include <ostream>
#include <vector>
#include <string>

// Null stream buffer that discards all output
template<typename CharType>
class null_streambuf : public std::basic_streambuf<CharType> {
protected:
    std::streamsize xsputn(const CharType* /*s*/, std::streamsize n) override {
        return n; // Discard all characters
    }
    typename std::basic_streambuf<CharType>::int_type overflow(
        typename std::basic_streambuf<CharType>::int_type c) override {
        return std::basic_streambuf<CharType>::traits_type::not_eof(c);
    }
};

// Helper to generate a random string from fuzzer data
static std::string consume_random_string(FuzzedDataProvider& fdp, size_t max_len = 100) {
    size_t len = fdp.ConsumeIntegralInRange<size_t>(0, max_len);
    return fdp.ConsumeBytesAsString(len);
}

// Insert special characters occasionally
static std::string maybe_add_special_chars(FuzzedDataProvider& fdp, std::string str) {
    if (fdp.ConsumeBool()) {
        static const char* specials = "<>&\"'";
        size_t pos = fdp.ConsumeIntegralInRange<size_t>(0, str.size());
        char c = specials[fdp.ConsumeIntegralInRange<size_t>(0, 4)];
        str.insert(pos, 1, c);
    }
    return str;
}

// Build a deep tree recursively
static void build_deep_tree(pugi::xml_node node, int depth, int max_children, FuzzedDataProvider& fdp) {
    if (depth <= 0) return;
    int num_children = fdp.ConsumeIntegralInRange(0, max_children);
    for (int i = 0; i < num_children; ++i) {
        pugi::xml_node child = node.append_child(pugi::node_element);
        std::string child_name = consume_random_string(fdp, 10);
        child_name = maybe_add_special_chars(fdp, child_name);
        child.set_name(child_name.c_str());
        // Occasionally set a value
        if (fdp.ConsumeBool()) {
            std::string child_val = consume_random_string(fdp, 30);
            child_val = maybe_add_special_chars(fdp, child_val);
            child.set_value(child_val.c_str());
        }
        // Add some attributes
        int attr_count = fdp.ConsumeIntegralInRange(0, 3);
        for (int j = 0; j < attr_count; ++j) {
            std::string attr_name = consume_random_string(fdp, 8);
            attr_name = maybe_add_special_chars(fdp, attr_name);
            std::string attr_val = consume_random_string(fdp, 15);
            attr_val = maybe_add_special_chars(fdp, attr_val);
            child.append_attribute(attr_name.c_str()) = attr_val.c_str();
        }
        build_deep_tree(child, depth - 1, max_children, fdp);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    FuzzedDataProvider fdp(Data, Size);

    // Consume parameters first
    unsigned int flags = 0;
    // Sometimes pick from a set of known flag values, otherwise random.
    if (fdp.ConsumeBool()) {
        static const unsigned int flag_values[] = {
            pugi::format_indent,
            pugi::format_raw,
            pugi::format_no_declaration,
            pugi::format_no_escapes,
            pugi::format_indent_attributes,
            pugi::format_no_empty_element_tags,
            pugi::format_skip_control_chars,
            pugi::format_attribute_single_quote,
            pugi::format_default,
            pugi::format_indent | pugi::format_raw,
            pugi::format_indent | pugi::format_indent_attributes,
            pugi::format_raw | pugi::format_no_escapes,
            0,  // No flags
        };
        flags = fdp.PickValueInArray(flag_values);
    } else {
        flags = fdp.ConsumeIntegral<unsigned int>();
    }

    unsigned int depth = fdp.ConsumeIntegralInRange<unsigned int>(0, 20);
    size_t indent_len = fdp.ConsumeIntegralInRange<size_t>(0, 64);
    std::string indent;
    if (fdp.ConsumeBool()) {
        // Generate indent with typical characters
        indent = fdp.ConsumeBytesAsString(indent_len);
    } else {
        // Use a string of spaces or tabs
        static const char* const typical[] = {"", " ", "  ", "\t", "\n", " \t ", "    ", "\t\t\t"};
        indent = fdp.PickValueInArray(typical);
        if (indent_len > indent.size()) {
            indent.resize(indent_len, ' ');
        }
    }

    // Remaining bytes are XML data (limit size to 64KB to avoid huge trees)
    size_t xml_max = fdp.ConsumeIntegralInRange<size_t>(0, 65536);
    std::vector<uint8_t> xml_buffer = fdp.ConsumeBytes<uint8_t>(
        std::min(xml_max, fdp.remaining_bytes()));

    // Create a null wide output stream
    null_streambuf<wchar_t> null_buf;
    std::basic_ostream<wchar_t> null_stream(&null_buf);

    // Part 1: Parse random XML and call print
    if (!xml_buffer.empty()) {
        pugi::xml_document doc;
        doc.load_buffer(xml_buffer.data(), xml_buffer.size());
        doc.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_minimal);
        doc.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_full);

        // Call print on the document
        doc.print(null_stream, indent.c_str(), flags, depth);

        // Also call print on a random child node to cover different node types
        pugi::xml_node root = doc;
        if (root) {
            // Count children
            size_t child_count = 0;
            for (pugi::xml_node child = root.first_child(); child; child = child.next_sibling()) {
                ++child_count;
            }
            if (child_count > 0) {
                size_t chosen = fdp.ConsumeIntegralInRange<size_t>(0, child_count - 1);
                pugi::xml_node target = root.first_child();
                for (size_t i = 0; i < chosen && target; ++i) {
                    target = target.next_sibling();
                }
                if (target) {
                    target.print(null_stream, indent.c_str(), flags, depth);
                }
            }
        }
    }

    // Part 2: Create a dynamic document with various node types using the API
    pugi::xml_document doc_api;

    // Add a declaration (if allowed)
    if (!(flags & pugi::format_no_declaration)) {
        pugi::xml_node decl = doc_api.append_child(pugi::node_declaration);
        std::string decl_name = consume_random_string(fdp, 10);
        decl_name = maybe_add_special_chars(fdp, decl_name);
        decl.set_name(decl_name.c_str());
        std::string attr1_name = consume_random_string(fdp, 10);
        attr1_name = maybe_add_special_chars(fdp, attr1_name);
        std::string attr1_val = consume_random_string(fdp, 20);
        attr1_val = maybe_add_special_chars(fdp, attr1_val);
        decl.append_attribute(attr1_name.c_str()) = attr1_val.c_str();
        std::string attr2_name = consume_random_string(fdp, 10);
        attr2_name = maybe_add_special_chars(fdp, attr2_name);
        std::string attr2_val = consume_random_string(fdp, 20);
        attr2_val = maybe_add_special_chars(fdp, attr2_val);
        decl.append_attribute(attr2_name.c_str()) = attr2_val.c_str();
    }

    // Add a doctype
    pugi::xml_node doctype = doc_api.append_child(pugi::node_doctype);
    std::string doctype_val = consume_random_string(fdp, 50);
    doctype_val = maybe_add_special_chars(fdp, doctype_val);
    doctype.set_value(doctype_val.c_str());

    // Create a root element with fuzzed name and attributes
    pugi::xml_node root_api = doc_api.append_child(pugi::node_element);
    std::string root_name = consume_random_string(fdp, 20);
    root_name = maybe_add_special_chars(fdp, root_name);
    root_api.set_name(root_name.c_str());
    int attr_count = fdp.ConsumeIntegralInRange<int>(0, 5);
    for (int i = 0; i < attr_count; ++i) {
        std::string attr_name = consume_random_string(fdp, 15);
        attr_name = maybe_add_special_chars(fdp, attr_name);
        std::string attr_val = consume_random_string(fdp, 30);
        attr_val = maybe_add_special_chars(fdp, attr_val);
        root_api.append_attribute(attr_name.c_str()) = attr_val.c_str();
    }

    // Add child nodes of various types, with some depth
    int child_count = fdp.ConsumeIntegralInRange<int>(0, 10);
    for (int i = 0; i < child_count; ++i) {
        int node_type = fdp.ConsumeIntegralInRange<int>(0, 5);
        switch (node_type) {
            case 0: {
                pugi::xml_node child = root_api.append_child(pugi::node_element);
                std::string child_name = consume_random_string(fdp, 15);
                child_name = maybe_add_special_chars(fdp, child_name);
                child.set_name(child_name.c_str());
                // Occasionally set an element value (simulating parse_embed_pcdata)
                if (fdp.ConsumeBool()) {
                    std::string child_val = consume_random_string(fdp, 50);
                    child_val = maybe_add_special_chars(fdp, child_val);
                    child.set_value(child_val.c_str());
                }
                int child_attr_count = fdp.ConsumeIntegralInRange<int>(0, 3);
                for (int j = 0; j < child_attr_count; ++j) {
                    std::string attr_name = consume_random_string(fdp, 10);
                    attr_name = maybe_add_special_chars(fdp, attr_name);
                    std::string attr_val = consume_random_string(fdp, 20);
                    attr_val = maybe_add_special_chars(fdp, attr_val);
                    child.append_attribute(attr_name.c_str()) = attr_val.c_str();
                }
                // Occasionally add a grandchild to create depth
                if (fdp.ConsumeBool()) {
                    pugi::xml_node grandchild = child.append_child(pugi::node_element);
                    std::string grandchild_name = consume_random_string(fdp, 10);
                    grandchild.set_name(grandchild_name.c_str());
                    if (fdp.ConsumeBool()) {
                        std::string grandchild_val = consume_random_string(fdp, 30);
                        grandchild.set_value(grandchild_val.c_str());
                    }
                }
                break;
            }
            case 1: {
                pugi::xml_node child = root_api.append_child(pugi::node_comment);
                std::string comment = consume_random_string(fdp, 50);
                comment = maybe_add_special_chars(fdp, comment);
                child.set_value(comment.c_str());
                break;
            }
            case 2: {
                pugi::xml_node child = root_api.append_child(pugi::node_pi);
                std::string pi_name = consume_random_string(fdp, 10);
                pi_name = maybe_add_special_chars(fdp, pi_name);
                child.set_name(pi_name.c_str());
                std::string pi_val = consume_random_string(fdp, 30);
                pi_val = maybe_add_special_chars(fdp, pi_val);
                child.set_value(pi_val.c_str());
                break;
            }
            case 3: {
                pugi::xml_node child = root_api.append_child(pugi::node_cdata);
                std::string cdata = consume_random_string(fdp, 100);
                cdata = maybe_add_special_chars(fdp, cdata);
                child.set_value(cdata.c_str());
                break;
            }
            case 4: {
                pugi::xml_node child = root_api.append_child(pugi::node_pcdata);
                std::string pcdata = consume_random_string(fdp, 100);
                pcdata = maybe_add_special_chars(fdp, pcdata);
                child.set_value(pcdata.c_str());
                break;
            }
            case 5: {
                // Add an empty element (no children) to test format_no_empty_element_tags
                pugi::xml_node child = root_api.append_child(pugi::node_element);
                std::string empty_name = consume_random_string(fdp, 10);
                empty_name = maybe_add_special_chars(fdp, empty_name);
                child.set_name(empty_name.c_str());
                break;
            }
        }
    }

    // Call print on the entire API document with the fuzzed flags
    doc_api.print(null_stream, indent.c_str(), flags, depth);

    // Also call print with two additional flag sets to cover more paths
    static const unsigned int extra_flags[] = { pugi::format_raw, pugi::format_indent };
    for (unsigned int extra_flag : extra_flags) {
        doc_api.print(null_stream, indent.c_str(), extra_flag, depth);
    }

    // Call print on each child of the root element
    for (pugi::xml_node child = root_api.first_child(); child; child = child.next_sibling()) {
        child.print(null_stream, indent.c_str(), flags, depth);
    }

    // Additionally, call print on an empty node (node_null)
    pugi::xml_node empty;
    empty.print(null_stream, indent.c_str(), flags, depth);

    // Test a node that is attached to the document (but we create it separately)
    pugi::xml_node attached_node = doc_api.append_child(pugi::node_element);
    attached_node.set_name("attached");
    attached_node.set_value("attached value");
    attached_node.print(null_stream, indent.c_str(), flags, depth);

    // Also, test printing on a randomly selected node from the entire document
    // Collect all nodes (simple BFS)
    std::vector<pugi::xml_node> nodes;
    nodes.push_back(doc_api);
    for (size_t i = 0; i < nodes.size(); ++i) {
        for (pugi::xml_node child = nodes[i].first_child(); child; child = child.next_sibling()) {
            nodes.push_back(child);
        }
    }
    if (!nodes.empty()) {
        size_t idx = fdp.ConsumeIntegralInRange<size_t>(0, nodes.size() - 1);
        nodes[idx].print(null_stream, indent.c_str(), flags, depth);
    }

    // Part 3: Structured document to cover specific branches
    pugi::xml_document structured_doc;

    // Add a declaration
    pugi::xml_node structured_decl = structured_doc.append_child(pugi::node_declaration);
    structured_decl.set_name("xml");
    structured_decl.append_attribute("version") = "1.0";
    structured_decl.append_attribute("encoding") = "UTF-8";

    // Add a doctype
    pugi::xml_node structured_doctype = structured_doc.append_child(pugi::node_doctype);
    structured_doctype.set_value("html");

    // Create a root element with multiple attributes
    pugi::xml_node structured_root = structured_doc.append_child(pugi::node_element);
    structured_root.set_name("root");
    structured_root.append_attribute("attr1") = "value1";
    structured_root.append_attribute("attr2") = "value2";
    structured_root.append_attribute("attr3") = "value3";
    structured_root.append_attribute("attr4") = "value4";

    // Add an element with value and children
    pugi::xml_node elem_with_value_and_children = structured_root.append_child(pugi::node_element);
    elem_with_value_and_children.set_name("elem_with_value_and_children");
    elem_with_value_and_children.set_value("This is a value");
    // Add two child elements
    pugi::xml_node child1 = elem_with_value_and_children.append_child(pugi::node_element);
    child1.set_name("child1");
    pugi::xml_node child2 = elem_with_value_and_children.append_child(pugi::node_element);
    child2.set_name("child2");

    // Add an element with value and no children
    pugi::xml_node elem_with_value = structured_root.append_child(pugi::node_element);
    elem_with_value.set_name("elem_with_value");
    elem_with_value.set_value("Standalone value");

    // Add an empty element (no value, no children)
    pugi::xml_node empty_elem = structured_root.append_child(pugi::node_element);
    empty_elem.set_name("empty_elem");

    // Add a comment
    pugi::xml_node comment = structured_root.append_child(pugi::node_comment);
    comment.set_value("This is a comment");

    // Add a processing instruction
    pugi::xml_node pi = structured_root.append_child(pugi::node_pi);
    pi.set_name("target");
    pi.set_value("data");

    // Add a CDATA node
    pugi::xml_node cdata = structured_root.append_child(pugi::node_cdata);
    cdata.set_value("<CDATA content>");

    // Add a PCDATA node
    pugi::xml_node pcdata = structured_root.append_child(pugi::node_pcdata);
    pcdata.set_value("Plain text");

    // Build a deep tree (depth 5, max 3 children per node) under a separate element
    pugi::xml_node deep_root = structured_root.append_child(pugi::node_element);
    deep_root.set_name("deep_tree");
    build_deep_tree(deep_root, 5, 3, fdp);

    // Define a set of flag combinations to test systematically
    static const unsigned int flag_sets[] = {
        pugi::format_indent,
        pugi::format_raw,
        pugi::format_no_empty_element_tags,
        pugi::format_indent_attributes,
        pugi::format_attribute_single_quote,
        pugi::format_no_escapes,
        pugi::format_skip_control_chars,
        pugi::format_default,
        pugi::format_indent | pugi::format_indent_attributes,
        pugi::format_raw | pugi::format_no_escapes,
        pugi::format_indent | pugi::format_no_empty_element_tags,
        pugi::format_indent | pugi::format_indent_attributes | pugi::format_attribute_single_quote,
        0,
    };

    // Call print on the structured document with each flag set
    for (unsigned int flag_set : flag_sets) {
        structured_doc.print(null_stream, indent.c_str(), flag_set, depth);
    }

    // Specifically test empty element with and without format_no_empty_element_tags
    unsigned int flags_without = flags & ~pugi::format_no_empty_element_tags;
    unsigned int flags_with = flags | pugi::format_no_empty_element_tags;
    empty_elem.print(null_stream, indent.c_str(), flags_without, depth);
    empty_elem.print(null_stream, indent.c_str(), flags_with, depth);

    return 0;
}