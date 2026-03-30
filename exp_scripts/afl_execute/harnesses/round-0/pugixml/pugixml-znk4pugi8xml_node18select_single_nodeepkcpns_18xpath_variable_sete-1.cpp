#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    if (Size < 1) return 0;

    FuzzedDataProvider fdp(Data, Size);

    // --- Generate XML data with a more complex structure ---
    std::string xml_data = "<?xml version=\"1.0\"?><root>";
    // Generate nested elements with a random depth (up to 3)
    // We'll use a simple stack to keep track of open tags
    std::vector<std::string> open_tags;
    open_tags.push_back("root");
    size_t max_depth = 3;
    size_t current_depth = 0;
    size_t total_elements = fdp.ConsumeIntegralInRange<size_t>(0, 20);
    for (size_t i = 0; i < total_elements; ++i)
    {
        // Decide whether to open a new element or close the current one (if depth>1)
        if (current_depth < max_depth && fdp.ConsumeBool())
        {
            std::string tag = fdp.ConsumeRandomLengthString(5);
            xml_data += "<" + tag;
            // Add random attributes
            size_t attr_count = fdp.ConsumeIntegralInRange<size_t>(0, 5);
            for (size_t j = 0; j < attr_count; ++j)
            {
                xml_data += " " + fdp.ConsumeRandomLengthString(5) + "=\"" + fdp.ConsumeRandomLengthString(10) + "\"";
            }
            xml_data += ">";
            open_tags.push_back(tag);
            current_depth++;
        }
        else
        {
            // Close the current element
            if (open_tags.size() > 1) // keep root open until the end
            {
                xml_data += "</" + open_tags.back() + ">";
                open_tags.pop_back();
                current_depth--;
            }
        }
    }
    // Close all remaining open tags except root (which will be closed later)
    while (open_tags.size() > 1)
    {
        xml_data += "</" + open_tags.back() + ">";
        open_tags.pop_back();
    }
    xml_data += "</root>";

    // --- Build variable set with random values ---
    pugi::xpath_variable_set vars;
    size_t var_count = fdp.ConsumeIntegralInRange<size_t>(0, 10);
    std::vector<std::string> var_names;
    for (size_t i = 0; i < var_count; ++i)
    {
        var_names.push_back(fdp.ConsumeRandomLengthString(10));
        const int xpath_value_type_count = pugi::xpath_type_node_set + 1;
        pugi::xpath_value_type value_type = static_cast<pugi::xpath_value_type>(
            fdp.ConsumeIntegralInRange(0, xpath_value_type_count - 1));
        vars.add(var_names.back().c_str(), value_type);

        // Set a random value matching the type
        switch (value_type)
        {
        case pugi::xpath_type_boolean:
            vars.set(var_names.back().c_str(), fdp.ConsumeBool());
            break;
        case pugi::xpath_type_number:
            vars.set(var_names.back().c_str(), fdp.ConsumeFloatingPoint<double>());
            break;
        case pugi::xpath_type_string:
            vars.set(var_names.back().c_str(), fdp.ConsumeRandomLengthString(30).c_str());
            break;
        case pugi::xpath_type_node_set:
            {
                pugi::xpath_node_set empty_set;
                vars.set(var_names.back().c_str(), empty_set);
            }
            break;
        default:
            break;
        }
    }
    pugi::xpath_variable_set* vars_ptr = var_count > 0 ? &vars : nullptr;

    // --- Generate three XPath queries using an expanded set of patterns ---
    std::vector<std::string> xpath_strings;
    for (int query_idx = 0; query_idx < 3; ++query_idx)
    {
        std::string xpath_string;
        size_t pattern = fdp.ConsumeIntegralInRange<size_t>(0, 15);
        switch (pattern)
        {
        case 0:
            xpath_string = "//*";
            break;
        case 1:
            xpath_string = "//@*";
            break;
        case 2:
            xpath_string = "/root/*";
            break;
        case 3:
            xpath_string = "node()";
            break;
        case 4:
            xpath_string = fdp.ConsumeRandomLengthString(30);
            break;
        case 5:
            xpath_string = "//*[position()<3]";
            break;
        case 6:
            xpath_string = "//*[@attr]";
            break;
        case 7:
            xpath_string = "//*[text()]";
            break;
        case 8:
            xpath_string = "//*[position() mod 2 = 0]";
            break;
        case 9:
            xpath_string = "//*[last()]";
            break;
        case 10:
            xpath_string = "//*[count(*)=0]";
            break;
        case 11:
            // Use a variable reference if variables exist
            if (var_count > 0)
            {
                xpath_string = "$" + var_names[fdp.ConsumeIntegralInRange<size_t>(0, var_count-1)];
            }
            else
            {
                xpath_string = ".";
            }
            break;
        case 12:
            xpath_string = "//*[name()='root']";
            break;
        case 13:
            xpath_string = "//*[contains(name(),'a')]";
            break;
        case 14:
            xpath_string = "//*[1]";
            break;
        case 15:
            xpath_string = "//*[position()>1 and position()<5]";
            break;
        default:
            xpath_string = ".";
            break;
        }
        xpath_strings.push_back(xpath_string);
    }

    // --- Parse XML with three different modes on separate documents ---
    pugi::xml_document doc1, doc2, doc3;
    pugi::xml_node root1, root2, root3;

    // Default parse
    doc1.load_buffer(xml_data.data(), xml_data.size());
    root1 = doc1.root();
    // Minimal parse
    doc2.load_buffer(xml_data.data(), xml_data.size(), pugi::parse_minimal);
    root2 = doc2.root();
    // Full parse
    doc3.load_buffer(xml_data.data(), xml_data.size(), pugi::parse_full);
    root3 = doc3.root();

    // Helper lambda to evaluate a query on a node
    auto evaluate_all = [&](pugi::xml_node node, const char* query, pugi::xpath_variable_set* vars) {
#ifndef PUGIXML_NO_EXCEPTIONS
        try
#endif
        {
            // Required function call
            node.select_single_node(query, vars);
            // Additional related functions
            node.select_node(query, vars);
            node.select_nodes(query, vars);

            // Direct xpath_query evaluations
            pugi::xpath_query q(query, vars);
            if (q)
            {
                q.evaluate_boolean(node);
                q.evaluate_number(node);
#ifndef PUGIXML_NO_STL
                q.evaluate_string(node);
#endif
                q.evaluate_node(node);
                q.evaluate_node_set(node);
            }
        }
#ifndef PUGIXML_NO_EXCEPTIONS
        catch (pugi::xpath_exception&) {}
#endif
    };

    // Evaluate on each parsed document with its own XPath query
    evaluate_all(root1, xpath_strings[0].c_str(), vars_ptr);
    evaluate_all(root2, xpath_strings[1].c_str(), vars_ptr);
    evaluate_all(root3, xpath_strings[2].c_str(), vars_ptr);

    return 0;
}