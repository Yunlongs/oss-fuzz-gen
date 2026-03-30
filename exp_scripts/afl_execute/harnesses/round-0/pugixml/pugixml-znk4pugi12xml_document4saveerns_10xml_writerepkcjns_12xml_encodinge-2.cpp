#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <vector>
#include <cstring>
#include <algorithm>
#include <string>

class FuzzWriter : public pugi::xml_writer {
public:
    virtual void write(const void* /*data*/, size_t /*size*/) override {
        // Discard output to focus on the save logic.
    }
};

// Helper to inject a non‑ASCII character into a string.
static void maybe_inject_non_ascii(std::string& str, FuzzedDataProvider& fdp) {
    if (str.empty() || !fdp.ConsumeBool()) return;
    // Replace a random position with a non‑ASCII byte (e.g., 0xA3 for '£').
    size_t pos = fdp.ConsumeIntegralInRange<size_t>(0, str.size() - 1);
    str[pos] = static_cast<char>(0xA3);
}

// Append a variety of node types to the document to increase coverage.
static void append_diverse_nodes(pugi::xml_document& doc, FuzzedDataProvider& fdp) {
    pugi::xml_node root = doc.root();
    if (!root) {
        root = doc.append_child(pugi::node_element);
        std::string root_name = fdp.ConsumeRandomLengthString(8);
        maybe_inject_non_ascii(root_name, fdp);
        root.set_name(root_name.c_str());
    }

    // Append different node types based on fuzzer data.
    // Use a small number of nodes to avoid blowing up.
    unsigned int num_nodes = fdp.ConsumeIntegralInRange<unsigned int>(0, 8);
    for (unsigned int i = 0; i < num_nodes && fdp.remaining_bytes() > 0; ++i) {
        int node_type = fdp.ConsumeIntegralInRange<int>(0, 7);
        switch (node_type) {
            case 0: // node_element
            {
                pugi::xml_node elem = root.append_child(pugi::node_element);
                std::string elem_name = fdp.ConsumeRandomLengthString(16);
                maybe_inject_non_ascii(elem_name, fdp);
                elem.set_name(elem_name.c_str());
                // Possibly add an attribute.
                if (fdp.ConsumeBool()) {
                    std::string attr_name = fdp.ConsumeRandomLengthString(8);
                    std::string attr_value = fdp.ConsumeRandomLengthString(8);
                    maybe_inject_non_ascii(attr_name, fdp);
                    maybe_inject_non_ascii(attr_value, fdp);
                    elem.append_attribute(attr_name.c_str()) = attr_value.c_str();
                }
                break;
            }
            case 1: // node_pcdata
            {
                std::string text = fdp.ConsumeRandomLengthString(32);
                maybe_inject_non_ascii(text, fdp);
                root.append_child(pugi::node_pcdata).set_value(text.c_str());
                break;
            }
            case 2: // node_cdata
            {
                std::string cdata = fdp.ConsumeRandomLengthString(32);
                maybe_inject_non_ascii(cdata, fdp);
                root.append_child(pugi::node_cdata).set_value(cdata.c_str());
                break;
            }
            case 3: // node_comment
                root.append_child(pugi::node_comment).set_value(
                    fdp.ConsumeRandomLengthString(32).c_str());
                break;
            case 4: // node_pi
                root.append_child(pugi::node_pi).set_value(
                    fdp.ConsumeRandomLengthString(32).c_str());
                break;
            case 5: // node_declaration
            {
                pugi::xml_node decl = root.append_child(pugi::node_declaration);
                decl.append_attribute("version") = "1.0";
                break;
            }
            case 6: // node_doctype
                root.append_child(pugi::node_doctype).set_value(
                    fdp.ConsumeRandomLengthString(32).c_str());
                break;
            default:
                // Ignore.
                break;
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size == 0) return 0;

    FuzzedDataProvider fdp(Data, Size);

    // 1. Load document with random parse flags.
    size_t xml_size = fdp.ConsumeIntegralInRange<size_t>(0, std::min(fdp.remaining_bytes(), size_t(1024)));
    std::vector<uint8_t> xml_data = fdp.ConsumeBytes<uint8_t>(xml_size);
    unsigned int parse_flags = fdp.ConsumeIntegral<unsigned int>();

    pugi::xml_document doc;
    doc.load_buffer(xml_data.data(), xml_data.size(), parse_flags);

    // 2. Optionally append diverse nodes to increase node type coverage.
    if (fdp.ConsumeBool()) {
        append_diverse_nodes(doc, fdp);
    }

    // 3. Perform multiple save calls with varying parameters.
    unsigned int num_saves = fdp.ConsumeIntegralInRange<unsigned int>(1, 5);
    for (unsigned int i = 0; i < num_saves && fdp.remaining_bytes() > 0; ++i) {
        // Generate indent string.
        size_t max_indent_chars = fdp.remaining_bytes() / sizeof(pugi::char_t);
        size_t indent_chars = fdp.ConsumeIntegralInRange<size_t>(0, std::min(max_indent_chars, size_t(100)));
        std::vector<pugi::char_t> indent(indent_chars + 1);
        if (indent_chars > 0) {
            if (fdp.ConsumeBool()) {
                // Use typical whitespace.
                const char* whitespace = " \t\n";
                for (size_t j = 0; j < indent_chars; ++j) {
                    indent[j] = whitespace[fdp.ConsumeIntegralInRange<size_t>(0, 2)];
                }
            } else {
                auto bytes = fdp.ConsumeBytes<uint8_t>(indent_chars * sizeof(pugi::char_t));
                if (!bytes.empty()) {
                    std::memcpy(indent.data(), bytes.data(), bytes.size());
                }
            }
        }
        indent[indent_chars] = 0;

        // Generate flags: combine known flags and random bits.
        unsigned int flags = 0;
        // Known format flags from pugixml.hpp.
        const unsigned int known_flags[] = {
            0x01, // format_indent
            0x02, // format_write_bom
            0x04, // format_raw
            0x08, // format_no_declaration
            0x10, // format_no_escapes
            0x20, // format_save_file_text
            0x40, // format_indent_attributes
            0x80, // format_no_empty_element_tags
            0x100, // format_skip_control_chars
            0x200, // format_attribute_single_quote
        };
        // Set a random subset of known flags.
        uint8_t flag_byte = fdp.ConsumeIntegral<uint8_t>();
        for (int j = 0; j < 8 && j < (int)(sizeof(known_flags)/sizeof(known_flags[0])); ++j) {
            if (flag_byte & (1 << j)) {
                flags |= known_flags[j];
            }
        }
        // Add random bits for unknown flags.
        flags |= fdp.ConsumeIntegral<unsigned int>();

        // Encoding: bias towards non‑native encodings to exercise conversion path.
        // We assume a little‑endian system (common) and prioritize big‑endian and Latin1.
        // Use a byte to select from a weighted list.
        uint8_t enc_byte = fdp.ConsumeIntegral<uint8_t>();
        pugi::xml_encoding encoding;
        switch (enc_byte % 16) {
            case 0:  encoding = pugi::encoding_utf16_be; break;
            case 1:  encoding = pugi::encoding_utf32_be; break;
            case 2:  encoding = pugi::encoding_latin1;   break;
            case 3:  encoding = pugi::encoding_utf16_le; break;
            case 4:  encoding = pugi::encoding_utf32_le; break;
            case 5:  encoding = pugi::encoding_utf8;     break;
            case 6:  encoding = pugi::encoding_auto;     break;
            case 7:  encoding = pugi::encoding_wchar;    break;
            case 8:  encoding = pugi::encoding_utf16;    break;
            case 9:  encoding = pugi::encoding_utf32;    break;
            default: encoding = pugi::encoding_utf8;     break;
        }

        // Increase probability of format_write_bom for non‑Latin1 encodings.
        if (encoding != pugi::encoding_latin1 && fdp.ConsumeBool()) {
            flags |= pugi::format_write_bom;
        }

        FuzzWriter writer;
        doc.save(writer, indent.data(), flags, encoding);
    }

    return 0;
}