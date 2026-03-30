#include "../src/pugixml.hpp"
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdio>
#include <vector>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider provider(Data, Size);

    // Use at most half of the input for XML data, but at least 0.
    size_t xml_size = provider.ConsumeIntegralInRange<size_t>(0, provider.remaining_bytes());
    auto xml_data = provider.ConsumeBytes<uint8_t>(xml_size);

    // Load the same XML into three documents with different parse options.
    pugi::xml_document docs[3];
    docs[0].load_buffer(xml_data.data(), xml_data.size());
    docs[1].load_buffer(xml_data.data(), xml_data.size(), pugi::parse_minimal);
    docs[2].load_buffer(xml_data.data(), xml_data.size(), pugi::parse_full);

    // Enrich the first document with random nodes and attributes.
    int modifications = provider.ConsumeIntegralInRange(0, 10);
    for (int i = 0; i < modifications && provider.remaining_bytes() > 0; ++i)
    {
        int node_type = provider.ConsumeIntegralInRange(0, 2);
        std::string node_name = provider.ConsumeRandomLengthString(10);
        std::string node_value = provider.ConsumeRandomLengthString(20);

        if (node_type == 0) // element
        {
            pugi::xml_node node = docs[0].append_child();
            node.set_name(node_name.c_str());
            node.append_child(pugi::node_pcdata).set_value(node_value.c_str());

            int attr_count = provider.ConsumeIntegralInRange(0, 5);
            for (int j = 0; j < attr_count && provider.remaining_bytes() > 0; ++j)
            {
                std::string attr_name = provider.ConsumeRandomLengthString(10);
                std::string attr_value = provider.ConsumeRandomLengthString(20);
                node.append_attribute(attr_name.c_str()) = attr_value.c_str();
            }
        }
        else if (node_type == 1) // comment
        {
            pugi::xml_node node = docs[0].append_child(pugi::node_comment);
            node.set_value(node_value.c_str());
        }
        else // processing instruction
        {
            pugi::xml_node node = docs[0].append_child(pugi::node_pi);
            node.set_name(node_name.c_str());
            node.set_value(node_value.c_str());
        }
    }

    // Array of all possible xml_encoding values.
    static const pugi::xml_encoding encodings[] = {
        pugi::encoding_auto,
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

    // Save each document with independently fuzzed parameters.
    for (int i = 0; i < 3 && provider.remaining_bytes() > 0; ++i)
    {
        // Generate a random narrow string for the file path and convert to wide.
        std::string narrow_path = provider.ConsumeRandomLengthString(50);
        std::wstring wide_path(narrow_path.begin(), narrow_path.end());

        // Generate a random narrow string for indent and convert to pugi::string_t.
        std::string narrow_indent = provider.ConsumeRandomLengthString(20);
        pugi::string_t indent(narrow_indent.begin(), narrow_indent.end());

        unsigned int flags = provider.ConsumeIntegral<unsigned int>();
        pugi::xml_encoding encoding = provider.PickValueInArray(encodings);

        docs[i].save_file(wide_path.c_str(), indent.c_str(), flags, encoding);
    }

    return 0;
}