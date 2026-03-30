#include "../src/pugixml.hpp"
#include <fuzzer/FuzzedDataProvider.h>

#include <stdint.h>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);
    std::string xpath = fdp.ConsumeRandomLengthString(1024);

#ifndef PUGIXML_NO_EXCEPTIONS
    try
#endif
    {
        // Create variable set with random variables
        pugi::xpath_variable_set vars;
        size_t var_count = fdp.ConsumeIntegralInRange<size_t>(0, 10);
        std::vector<std::string> var_name_storage;
        for (size_t i = 0; i < var_count; ++i)
        {
            var_name_storage.push_back(fdp.ConsumeRandomLengthString(128));
            const int xpath_value_type_count = pugi::xpath_type_boolean + 1;
            pugi::xpath_value_type value_type = static_cast<pugi::xpath_value_type>(fdp.ConsumeIntegralInRange(0, xpath_value_type_count));
            vars.add(var_name_storage.back().c_str(), value_type);

            // Set a random value for the variable based on its type
            if (value_type == pugi::xpath_type_boolean)
                vars.set(var_name_storage.back().c_str(), fdp.ConsumeBool());
            else if (value_type == pugi::xpath_type_number)
                vars.set(var_name_storage.back().c_str(), fdp.ConsumeFloatingPoint<double>());
            else if (value_type == pugi::xpath_type_string)
                vars.set(var_name_storage.back().c_str(), fdp.ConsumeRandomLengthString(64).c_str());
            else if (value_type == pugi::xpath_type_node_set)
            {
                // Create a simple node set for the variable
                pugi::xml_document temp_doc;
                std::string temp_xml = "<root><node1/><node2/></root>";
                temp_doc.load_buffer(temp_xml.c_str(), temp_xml.size());
                pugi::xpath_node_set node_set = temp_doc.select_nodes("//*");
                vars.set(var_name_storage.back().c_str(), node_set);
            }
        }

        // Create xpath_query with variable set (if any)
        pugi::xpath_query q(xpath.c_str(), var_count > 0 ? &vars : nullptr);
        
        // Test query compilation status
        if (!q) {
            // Query failed to compile - this is a valid path to test
            return 0;
        }
        
        // Test return type of the query
        pugi::xpath_value_type return_type = q.return_type();

        // Parse XML buffer with random parsing options
        std::vector<uint8_t> xml_buffer = fdp.ConsumeRemainingBytes<uint8_t>();
        pugi::xml_document doc;
        unsigned int parse_options = pugi::parse_default;
        // Randomly select parsing options
        if (fdp.ConsumeBool()) parse_options |= pugi::parse_ws_pcdata;
        if (fdp.ConsumeBool()) parse_options |= pugi::parse_escapes;
        if (fdp.ConsumeBool()) parse_options |= pugi::parse_eol;
        if (fdp.ConsumeBool()) parse_options |= pugi::parse_wconv_attribute;
        if (fdp.ConsumeBool()) parse_options |= pugi::parse_wnorm_attribute;
        if (fdp.ConsumeBool()) parse_options |= pugi::parse_declaration;
        if (fdp.ConsumeBool()) parse_options |= pugi::parse_doctype;
        if (fdp.ConsumeBool()) parse_options |= pugi::parse_pi;
        if (fdp.ConsumeBool()) parse_options |= pugi::parse_comments;
        if (fdp.ConsumeBool()) parse_options |= pugi::parse_cdata;
        if (fdp.ConsumeBool()) parse_options |= pugi::parse_fragment;
        doc.load_buffer(xml_buffer.data(), xml_buffer.size(), parse_options);

        // Get root node (document)
        pugi::xml_node root = doc;

        // Call select_nodes with string overload (with and without variable set)
        pugi::xpath_node_set result1 = root.select_nodes(xpath.c_str(), var_count > 0 ? &vars : nullptr);
        // Call select_nodes with xpath_query overload (the target function)
        pugi::xpath_node_set result2 = root.select_nodes(q);

        // Use the node sets: sort, check size, iterate
        result1.sort(false); // sort ascending
        result2.sort(true);  // sort descending

        // Exercise xpath_node_set methods on result1
        if (!result1.empty()) {
            // Test type
            pugi::xpath_node_set::type_t set_type = result1.type();
            // Test size
            size_t set_size = result1.size();
            // Test first node
            pugi::xpath_node first_node = result1.first();
            // Test node access
            for (size_t i = 0; i < std::min(set_size, static_cast<size_t>(3)); ++i) {
                pugi::xpath_node node_at_index = result1[i];
                // Test node() and attribute() methods
                pugi::xml_node xml_node = node_at_index.node();
                pugi::xml_attribute xml_attr = node_at_index.attribute();
                // Recursively call select_nodes on found nodes (limited depth)
                if (xml_node && fdp.ConsumeBool()) {
                    xml_node.select_nodes(q);
                }
            }
        }
        
        // Exercise xpath_node_set methods on result2
        if (!result2.empty()) {
            result2.sort(fdp.ConsumeBool());
            // Test iteration
            int node_count = 0;
            for (pugi::xpath_node_set::const_iterator it = result2.begin(); it != result2.end() && node_count < 5; ++it) {
                pugi::xml_node node = it->node();
                if (node) {
                    // Test on child nodes
                    int child_count = 0;
                    for (pugi::xml_node child = node.first_child(); child && child_count < 3; child = child.next_sibling()) {
                        child.select_nodes(q);
                        child_count++;
                    }
                }
                node_count++;
            }
        }

        // Test evaluate methods on the query based on return type
        if (return_type == pugi::xpath_type_boolean || return_type == pugi::xpath_type_none) {
            q.evaluate_boolean(root);
        }
        if (return_type == pugi::xpath_type_number || return_type == pugi::xpath_type_none) {
            q.evaluate_number(root);
        }
        if (return_type == pugi::xpath_type_string || return_type == pugi::xpath_type_none) {
            q.evaluate_string(root);
        }
        // Always test node and node_set evaluation
        q.evaluate_node(root);
        q.evaluate_node_set(root);

        // Test variable retrieval
        for (const auto& var_name : var_name_storage) {
            const pugi::xpath_variable* var = vars.get(var_name.c_str());
            if (var) {
                // Test getters based on type
                switch (var->type()) {
                    case pugi::xpath_type_boolean:
                        var->get_boolean();
                        break;
                    case pugi::xpath_type_number:
                        var->get_number();
                        break;
                    case pugi::xpath_type_string:
                        var->get_string();
                        break;
                    case pugi::xpath_type_node_set:
                        var->get_node_set();
                        break;
                    default:
                        break;
                }
            }
        }

        // Call select_nodes on a few child nodes (if any)
        int child_count = 0;
        for (pugi::xml_node child = root.first_child(); child && child_count < 5; child = child.next_sibling())
        {
            child.select_nodes(xpath.c_str(), var_count > 0 ? &vars : nullptr);
            child.select_nodes(q);
            child_count++;
        }

        // Call select_nodes on nodes in result1 (depth limit 1)
        int node_count = 0;
        for (pugi::xpath_node_set::const_iterator it = result1.begin(); it != result1.end() && node_count < 5; ++it)
        {
            pugi::xml_node node = it->node();
            if (node)
            {
                node.select_nodes(xpath.c_str(), var_count > 0 ? &vars : nullptr);
                node.select_nodes(q);
                node_count++;
            }
        }

        // Call select_nodes on nodes in result2 (depth limit 1)
        node_count = 0;
        for (pugi::xpath_node_set::const_iterator it = result2.begin(); it != result2.end() && node_count < 5; ++it)
        {
            pugi::xml_node node = it->node();
            if (node)
            {
                node.select_nodes(xpath.c_str(), var_count > 0 ? &vars : nullptr);
                node.select_nodes(q);
                node_count++;
            }
        }
    }
#ifndef PUGIXML_NO_EXCEPTIONS
    catch (pugi::xpath_exception&)
    {
    }
    catch (std::bad_alloc&)
    {
    }
#endif
    return 0;
}