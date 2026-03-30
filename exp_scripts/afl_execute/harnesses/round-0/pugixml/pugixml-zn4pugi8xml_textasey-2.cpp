#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <vector>
#include <string>
#include <algorithm>

// Helper function to find a text node (PCDATA or CDATA) in the entire document tree.
static pugi::xml_node find_text_node(pugi::xml_node node) {
    if (node.type() == pugi::node_pcdata || node.type() == pugi::node_cdata) {
        return node;
    }
    for (pugi::xml_node child = node.first_child(); child; child = child.next_sibling()) {
        pugi::xml_node found = find_text_node(child);
        if (found) return found;
    }
    return pugi::xml_node();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);

    // Consume parameters
    unsigned int scenario = fdp.ConsumeIntegralInRange<unsigned int>(0, 8);
    unsigned long long value1 = fdp.ConsumeIntegral<unsigned long long>();
    unsigned long long value2 = fdp.ConsumeIntegral<unsigned long long>();
    unsigned long long value3 = fdp.ConsumeIntegral<unsigned long long>();
    unsigned int parse_flags = fdp.ConsumeIntegral<unsigned int>();
    std::vector<uint8_t> xml_data = fdp.ConsumeRemainingBytes<uint8_t>();

    // Parse the XML data with fixed options (original parser fuzzing)
    pugi::xml_document doc;
    if (xml_data.size() > 0) {
        doc.load_buffer(xml_data.data(), xml_data.size());
        doc.load_buffer(xml_data.data(), xml_data.size(), pugi::parse_minimal);
        doc.load_buffer(xml_data.data(), xml_data.size(), pugi::parse_full);
    }

    // Parse with random flags
    pugi::xml_document doc2;
    if (xml_data.size() > 0) {
        doc2.load_buffer(xml_data.data(), xml_data.size(), parse_flags);
    }

    // Prepare a simple XML string that contains an element with text, to ensure we have embedded PCDATA or a text child.
    const char* simple_xml = "<root>text</root>";
    pugi::xml_document doc3;
    doc3.load_buffer(simple_xml, strlen(simple_xml), parse_flags | pugi::parse_embed_pcdata);

    // A temporary document that lives for the entire function, used for scenarios that create new nodes.
    pugi::xml_document temp_doc;

    pugi::xml_text text;

    switch (scenario) {
        case 0: // Empty xml_text
            // default constructor, text is already empty.
            break;
        case 1: // xml_text from a text node without value
        {
            pugi::xml_node text_node = temp_doc.append_child(pugi::node_pcdata);
            text = text_node.text();
            break;
        }
        case 2: // xml_text from a text node with value
        {
            pugi::xml_node text_node = temp_doc.append_child(pugi::node_pcdata);
            text_node.set_value("initial");
            text = text_node.text();
            break;
        }
        case 3: // xml_text from an element node with embedded PCDATA (via set_value)
        {
            pugi::xml_node elem = temp_doc.append_child();
            elem.set_value("embedded");
            text = elem.text();
            break;
        }
        case 4: // xml_text from an element node with a text child
        {
            pugi::xml_node elem = temp_doc.append_child();
            elem.append_child(pugi::node_pcdata).set_value("child");
            text = elem.text();
            break;
        }
        case 5: // xml_text from an element node without any text (normal case)
        {
            pugi::xml_node elem = temp_doc.append_child();
            text = elem.text();
            break;
        }
        case 6: // xml_text from an existing text node in the parsed document (doc2)
        {
            pugi::xml_node root = doc2.root();
            pugi::xml_node found = find_text_node(root);
            if (found) {
                text = found.text();
            } else {
                // Fallback to a new node
                pugi::xml_node node = doc2.append_child();
                text = node.text();
            }
            break;
        }
        case 7: // xml_text from an element node with embedded PCDATA from doc3
        {
            pugi::xml_node root = doc3.root();
            if (root) {
                text = root.text();
            } else {
                pugi::xml_node node = temp_doc.append_child();
                text = node.text();
            }
            break;
        }
        case 8: // xml_text from a CDATA node
        {
            pugi::xml_node cdata_node = temp_doc.append_child(pugi::node_cdata);
            text = cdata_node.text();
            break;
        }
    }

    // Perform three assignments to exercise buffer reuse and reallocation.
#ifdef PUGIXML_HAS_LONG_LONG
    text = value1;
    text = value2;
    text = value3;
#endif

    return 0;
}