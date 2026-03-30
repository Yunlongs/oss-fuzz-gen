#define PUGIXML_MEMORY_OUTPUT_STACK 100
#include "../src/pugixml.cpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <string>
#include <vector>
#include <sstream>

// A writer that writes to a stringstream (so that encoding conversion is exercised)
class stringstream_writer : public pugi::xml_writer
{
public:
    std::basic_ostringstream<char> stream;

    virtual void write(const void* data, size_t size) override
    {
        stream.write(static_cast<const char*>(data), size);
    }
};

// Helper to generate a string that contains all special characters and a control character
std::string generate_string_with_all_specials(FuzzedDataProvider& fdp, size_t max_len) {
    // Start with a random string
    std::string result = fdp.ConsumeRandomLengthString(max_len);
    // If the string is too short, we might not have enough space, but we'll just replace the first few characters
    // We'll ensure that the string has at least 6 characters, if not, we'll append.
    if (result.size() < 6) {
        result.append(6 - result.size(), ' ');
    }
    // Replace the first 5 characters with the special characters
    result[0] = '&';
    result[1] = '<';
    result[2] = '>';
    result[3] = '"';
    result[4] = '\'';
    // Insert a control character (0-31) at position 5
    result[5] = static_cast<char>(fdp.ConsumeIntegralInRange<uint8_t>(0, 31));
    return result;
}

// Helper to generate an indent string of a specific length and content
std::string generate_indent_string(FuzzedDataProvider& fdp, size_t length) {
    if (length == 0) return "";
    // Choose between spaces and tabs randomly
    if (fdp.ConsumeBool()) {
        // Spaces
        return std::string(length, ' ');
    } else {
        // Tabs
        return std::string(length, '\t');
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);

    // Generate indent string of a specific length: 0,1,2,3,4,8,100,200
    size_t indent_length_choice = fdp.ConsumeIntegralInRange<size_t>(0, 7);
    size_t indent_length;
    switch (indent_length_choice) {
        case 0: indent_length = 0; break;
        case 1: indent_length = 1; break;
        case 2: indent_length = 2; break;
        case 3: indent_length = 3; break;
        case 4: indent_length = 4; break;
        case 5: indent_length = 8; break;
        case 6: indent_length = 100; break;
        case 7: indent_length = 200; break;
        default: indent_length = 0;
    }
    std::string indent_str = generate_indent_string(fdp, indent_length);
    const pugi::char_t* indent = indent_str.c_str();

    // Generate depth: 0,1,2,5,10,1000
    unsigned int depth = 0;
    size_t depth_choice = fdp.ConsumeIntegralInRange<size_t>(0, 5);
    switch (depth_choice) {
        case 0: depth = 0; break;
        case 1: depth = 1; break;
        case 2: depth = 2; break;
        case 3: depth = 5; break;
        case 4: depth = 10; break;
        case 5: depth = 1000; break;
    }

    // Generate flags from an expanded set of interesting combinations (16 combinations)
    unsigned int flags = 0;
    size_t flag_combination = fdp.ConsumeIntegralInRange<size_t>(0, 15);
    switch (flag_combination) {
        case 0:
            flags = pugi::format_indent_attributes;
            break;
        case 1:
            flags = pugi::format_raw;
            break;
        case 2:
            flags = pugi::format_indent_attributes | pugi::format_raw;
            break;
        case 3:
            flags = pugi::format_no_escapes;
            break;
        case 4:
            flags = pugi::format_attribute_single_quote;
            break;
        case 5:
            flags = pugi::format_skip_control_chars;
            break;
        case 6:
            flags = pugi::format_indent_attributes | pugi::format_attribute_single_quote;
            break;
        case 7:
            flags = pugi::format_indent_attributes | pugi::format_no_escapes;
            break;
        case 8:
            flags = pugi::format_raw | pugi::format_no_escapes;
            break;
        case 9:
            flags = pugi::format_raw | pugi::format_attribute_single_quote;
            break;
        case 10:
            flags = pugi::format_no_escapes | pugi::format_attribute_single_quote;
            break;
        case 11:
            flags = pugi::format_indent_attributes | pugi::format_skip_control_chars;
            break;
        case 12:
            flags = pugi::format_raw | pugi::format_skip_control_chars;
            break;
        case 13:
            flags = pugi::format_no_escapes | pugi::format_skip_control_chars;
            break;
        case 14:
            flags = pugi::format_attribute_single_quote | pugi::format_skip_control_chars;
            break;
        case 15:
            flags = pugi::format_indent_attributes | pugi::format_attribute_single_quote | pugi::format_skip_control_chars;
            break;
    }

    // Sometimes add format_skip_control_chars to the mix (if not already present)
    if (fdp.ConsumeBool() && !(flags & pugi::format_skip_control_chars)) {
        flags |= pugi::format_skip_control_chars;
    }

    // Choose encoding
    const pugi::xml_encoding encodings[] = {
        pugi::encoding_utf8,
        pugi::encoding_utf16_le,
        pugi::encoding_utf16_be,
        pugi::encoding_utf16,
        pugi::encoding_utf32_le,
        pugi::encoding_utf32_be,
        pugi::encoding_utf32,
        pugi::encoding_wchar,
        pugi::encoding_latin1
    };
    pugi::xml_encoding encoding = fdp.PickValueInArray(encodings);

    // Create a writer that writes to a stringstream
    stringstream_writer sswriter;
    pugi::impl::xml_buffered_writer writer(sswriter, encoding);

    // Create a document and a node
    pugi::xml_document doc;
    pugi::xml_node node = doc.append_child(pugi::node_element);

    // Generate node name (not used by node_output_attributes, but set anyway)
    std::string node_name = fdp.ConsumeRandomLengthString(128);
    node.set_name(node_name.c_str());

    // Generate attributes: 0 to 5 (to stay within input limits)
    size_t attr_count = fdp.ConsumeIntegralInRange<size_t>(0, 5);
    for (size_t i = 0; i < attr_count; ++i) {
        // Choose attribute name length and content
        std::string attr_name;
        size_t name_type = fdp.ConsumeIntegralInRange<size_t>(0, 2);
        switch (name_type) {
            case 0:
                // Random string, up to 5000 characters (may exceed buffer capacity)
                attr_name = fdp.ConsumeRandomLengthString(5000);
                break;
            case 1:
                // Empty string
                attr_name = "";
                break;
            case 2:
                // String with special characters
                attr_name = generate_string_with_all_specials(fdp, 5000);
                break;
        }

        std::string attr_value;
        // Choose the type of attribute value
        size_t value_type = fdp.ConsumeIntegralInRange<size_t>(0, 3);
        switch (value_type) {
            case 0:
                // Random string, up to 5000 characters to stress the buffer
                attr_value = fdp.ConsumeRandomLengthString(5000);
                break;
            case 1:
                // String with all special characters and a control character, up to 5000 chars
                attr_value = generate_string_with_all_specials(fdp, 5000);
                break;
            case 2:
                // String that is just a control character (or a sequence of control characters)
                attr_value = std::string(1, static_cast<char>(fdp.ConsumeIntegralInRange<uint8_t>(0, 31)));
                break;
            case 3:
                // Empty string
                attr_value = "";
                break;
        }
        pugi::xml_attribute attr = node.append_attribute(attr_name.c_str());
        attr.set_value(attr_value.c_str());
    }

    // Get internal node pointer
    pugi::xml_node_struct* node_struct = node.internal_object();

    // Call the internal function
    pugi::impl::node_output_attributes(writer, node_struct, indent, indent_length, flags, depth);

    // The writer's destructor will flush, so we don't need an explicit flush.

    return 0;
}