#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);

    // First, consume a portion of the data for XML parsing (as in original fuzz_parse.cpp)
    size_t xml_size = fdp.ConsumeIntegralInRange<size_t>(0, Size);
    std::vector<uint8_t> xml_buffer = fdp.ConsumeBytes<uint8_t>(xml_size);

    pugi::xml_document doc;
    doc.load_buffer(xml_buffer.data(), xml_buffer.size());
    doc.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_minimal);
    doc.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_full);

    // If there's remaining data, use it for XPath query and variable set.
    if (fdp.remaining_bytes() == 0) {
        return 0;
    }

    // Consume a random length string for the XPath query.
    std::string xpath_query = fdp.ConsumeRandomLengthString(1024);
    if (xpath_query.empty()) {
        return 0;
    }

    // Randomly decide whether to use a variable set.
    bool use_vars = fdp.ConsumeBool();
    pugi::xpath_variable_set vars;

    if (use_vars) {
        size_t var_count = fdp.ConsumeIntegralInRange<size_t>(0, 50);
        for (size_t i = 0; i < var_count && fdp.remaining_bytes() > 0; ++i) {
            std::string var_name = fdp.ConsumeRandomLengthString(128);
            int type = fdp.ConsumeIntegralInRange(0, 3);
            switch (type) {
                case 0: { // boolean
                    bool val = fdp.ConsumeBool();
                    vars.set(var_name.c_str(), val);
                    break;
                }
                case 1: { // number
                    double val = fdp.ConsumeFloatingPoint<double>();
                    vars.set(var_name.c_str(), val);
                    break;
                }
                case 2: { // string
                    std::string val = fdp.ConsumeRandomLengthString(100);
                    vars.set(var_name.c_str(), val.c_str());
                    break;
                }
                case 3: { // node set (empty)
                    pugi::xpath_node_set val;
                    vars.set(var_name.c_str(), val);
                    break;
                }
            }
        }
    }

#ifndef PUGIXML_NO_EXCEPTIONS
    try
#endif
    {
        // Always evaluate on the document root without variables (covers the nullptr branch)
        doc.select_nodes(xpath_query.c_str(), nullptr);

        // If variables are used, evaluate on the root with variables
        if (use_vars) {
            doc.select_nodes(xpath_query.c_str(), &vars);
        }

        // Traverse the document and evaluate on up to 100 nodes (including children)
        pugi::xml_node_iterator it = doc.begin();
        pugi::xml_node_iterator end = doc.end();
        int node_count = 0;
        for (; it != end && node_count < 100; ++it, ++node_count) {
            // Evaluate without variables (nullptr) on this node
            it->select_nodes(xpath_query.c_str(), nullptr);
            // If variables are used, evaluate with variables on this node
            if (use_vars) {
                it->select_nodes(xpath_query.c_str(), &vars);
            }
        }
    }
#ifndef PUGIXML_NO_EXCEPTIONS
    catch (pugi::xpath_exception&)
    {
    }
#endif

    return 0;
}