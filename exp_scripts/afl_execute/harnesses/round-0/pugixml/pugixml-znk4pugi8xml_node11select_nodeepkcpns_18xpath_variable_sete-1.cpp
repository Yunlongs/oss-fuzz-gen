#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);

    // Generate XPath query: either a simple pattern or a random string
    std::string query;
    if (fdp.ConsumeBool() && fdp.remaining_bytes() > 0)
    {
        const char* patterns[] = {"/*", "//*", "/node()", "//@*", "//text()", "//comment()", "/a", "/a/b", "/a/@c", "//a[1]", "//a[last()]", "//a[position()<3]", "//*[local-name()='x']"};
        size_t pattern_index = fdp.ConsumeIntegralInRange<size_t>(0, sizeof(patterns)/sizeof(patterns[0]) - 1);
        query = patterns[pattern_index];
        // Optionally append a random suffix
        if (fdp.ConsumeBool())
            query += fdp.ConsumeRandomLengthString(32);
    }
    else
    {
        query = fdp.ConsumeRandomLengthString(1024);
    }

    // Generate variable set
    pugi::xpath_variable_set vars;
    size_t var_count = fdp.ConsumeIntegralInRange<size_t>(0, 20);
    std::vector<std::string> var_name_storage;
    std::vector<std::string> var_string_val_storage;

    for (size_t i = 0; i < var_count; ++i)
    {
        var_name_storage.push_back(fdp.ConsumeRandomLengthString(128));
        const int xpath_value_type_count = pugi::xpath_type_boolean + 1;
        pugi::xpath_value_type value_type = static_cast<pugi::xpath_value_type>(fdp.ConsumeIntegralInRange(0, xpath_value_type_count));
        vars.add(var_name_storage.back().c_str(), value_type);

        // Set variable value based on type
        switch (value_type)
        {
        case pugi::xpath_type_boolean:
            vars.set(var_name_storage.back().c_str(), fdp.ConsumeBool());
            break;
        case pugi::xpath_type_number:
            vars.set(var_name_storage.back().c_str(), fdp.ConsumeFloatingPoint<double>());
            break;
        case pugi::xpath_type_string:
            {
                std::string str_val = fdp.ConsumeRandomLengthString(100);
                var_string_val_storage.push_back(str_val);
                vars.set(var_name_storage.back().c_str(), str_val.c_str());
            }
            break;
        case pugi::xpath_type_node_set:
            // Leave as default (empty node set) for now; will be set after parsing
            break;
        default:
            break;
        }
    }

    // Remaining bytes are for XML
    std::vector<uint8_t> xml_buffer = fdp.ConsumeRemainingBytes<uint8_t>();

    // Parse with three different modes
    pugi::xml_document doc1;
    pugi::xml_parse_result res1 = doc1.load_buffer(xml_buffer.data(), xml_buffer.size());
    pugi::xml_document doc2;
    pugi::xml_parse_result res2 = doc2.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_minimal);
    pugi::xml_document doc3;
    pugi::xml_parse_result res3 = doc3.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_full);

    // For each document, try to evaluate the query
    pugi::xml_document* docs[] = {&doc1, &doc2, &doc3};
    for (pugi::xml_document* doc : docs)
    {
        // Skip if parsing failed (no root element)
        if (!doc->document_element())
            continue;

        // Update node-set variables with nodes from the document
        for (size_t i = 0; i < var_count; ++i)
        {
            const pugi::xpath_variable* var = vars.get(var_name_storage[i].c_str());
            if (var->type() == pugi::xpath_type_node_set)
            {
                // Create a node-set containing the root element and its first child (if any)
                pugi::xpath_node nodes[2];
                nodes[0] = doc->document_element();
                size_t count = 1;
                if (doc->document_element().first_child())
                {
                    nodes[1] = doc->document_element().first_child();
                    count = 2;
                }
                pugi::xpath_node_set ns(nodes, nodes + count);
                vars.set(var_name_storage[i].c_str(), ns);
            }
        }

#ifndef PUGIXML_NO_EXCEPTIONS
        try
#endif
        {
            pugi::xpath_query q(query.c_str(), &vars);

            // Evaluate the query in various ways
            q.evaluate_boolean(*doc);
            q.evaluate_number(*doc);
            q.evaluate_string(*doc);
            q.evaluate_node(*doc);
            q.evaluate_node_set(*doc);

            // Also test the select_node and select_nodes methods
            doc->select_node(query.c_str(), nullptr);
            doc->select_node(query.c_str(), &vars);
            doc->select_node(q);
            doc->select_nodes(query.c_str(), nullptr);
            doc->select_nodes(query.c_str(), &vars);
            doc->select_nodes(q);
        }
#ifndef PUGIXML_NO_EXCEPTIONS
        catch (pugi::xpath_exception&)
        {
        }
#endif
    }

    return 0;
}