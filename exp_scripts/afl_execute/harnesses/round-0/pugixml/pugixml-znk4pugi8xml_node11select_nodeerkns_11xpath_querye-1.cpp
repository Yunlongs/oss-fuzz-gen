#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <string>
#include <vector>
#include <stack>
#include <algorithm>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);
    
    // Consume part of the input for XML document (use at most half of the input)
    size_t xml_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes() / 2);
    std::vector<uint8_t> xml_buffer = fdp.ConsumeBytes<uint8_t>(xml_size);
    
    // Keep the original parsing tests to maintain coverage
    pugi::xml_document doc;
    if (!xml_buffer.empty()) {
        doc.load_buffer(xml_buffer.data(), xml_buffer.size());
        doc.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_minimal);
        doc.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_full);
    }
    
    // Collect all nodes and attributes as xpath_node objects
    std::vector<pugi::xpath_node> context_nodes;
    std::stack<pugi::xml_node> node_stack;
    node_stack.push(doc);
    while (!node_stack.empty()) {
        pugi::xml_node node = node_stack.top();
        node_stack.pop();
        
        if (node) {
            // Add the node itself
            context_nodes.push_back(pugi::xpath_node(node));
            
            // Add its attributes
            for (pugi::xml_attribute attr = node.first_attribute(); attr; attr = attr.next_attribute()) {
                context_nodes.push_back(pugi::xpath_node(attr, node));
            }
            
            // Push children in reverse order to maintain document order
            pugi::xml_node child = node.last_child();
            while (child) {
                node_stack.push(child);
                child = child.previous_sibling();
            }
        }
    }
    
    // Use the remaining data for XPath and variables
    // We will consume multiple XPath strings to evaluate multiple queries
    size_t num_queries = fdp.ConsumeIntegralInRange<size_t>(1, 5);
    std::vector<std::string> xpath_strings;
    for (size_t q = 0; q < num_queries && fdp.remaining_bytes() > 0; ++q) {
        size_t xpath_len = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes() / (num_queries - q));
        xpath_strings.push_back(fdp.ConsumeBytesAsString(xpath_len));
    }
    
#ifndef PUGIXML_NO_EXCEPTIONS
    try
#endif
    {
        // Create a variable set with random variables and set their values
        pugi::xpath_variable_set vars;
        size_t var_count = fdp.ConsumeIntegralInRange<size_t>(0, 10);
        std::vector<std::string> var_name_storage;
        for (size_t i = 0; i < var_count && fdp.remaining_bytes() > 0; ++i) {
            // Variable name
            var_name_storage.push_back(fdp.ConsumeRandomLengthString(32));
            const char* name = var_name_storage.back().c_str();
            
            // Variable type
            const int xpath_value_type_count = pugi::xpath_type_boolean + 1;
            pugi::xpath_value_type value_type = static_cast<pugi::xpath_value_type>(
                fdp.ConsumeIntegralInRange(0, xpath_value_type_count - 1));
            
            // Add variable
            pugi::xpath_variable* var = vars.add(name, value_type);
            if (var && fdp.remaining_bytes() > 0) {
                // Set value based on type
                switch (value_type) {
                    case pugi::xpath_type_boolean:
                        vars.set(name, fdp.ConsumeBool());
                        break;
                    case pugi::xpath_type_number:
                        vars.set(name, fdp.ConsumeFloatingPoint<double>());
                        break;
                    case pugi::xpath_type_string:
                        vars.set(name, fdp.ConsumeRandomLengthString(64).c_str());
                        break;
                    case pugi::xpath_type_node_set:
                        // Create a non-empty node set from a random subset of context_nodes
                        if (!context_nodes.empty()) {
                            size_t set_size = fdp.ConsumeIntegralInRange<size_t>(1, std::min<size_t>(5, context_nodes.size()));
                            std::vector<pugi::xpath_node> xpath_nodes;
                            for (size_t j = 0; j < set_size; ++j) {
                                size_t idx = fdp.ConsumeIntegralInRange<size_t>(0, context_nodes.size() - 1);
                                xpath_nodes.push_back(context_nodes[idx]);
                            }
                            pugi::xpath_node_set node_set(xpath_nodes.data(), xpath_nodes.data() + xpath_nodes.size());
                            vars.set(name, node_set);
                        } else {
                            vars.set(name, pugi::xpath_node_set());
                        }
                        break;
                    default:
                        break;
                }
            }
        }
        
        // Copy the variable set to exercise copy constructor
        pugi::xpath_variable_set vars_copy(vars);
        
        // For each XPath string, evaluate queries
        for (const std::string& xpath : xpath_strings) {
            // Modify the XPath string to include variable references (with some probability)
            std::string modified_xpath = xpath;
            if (var_count > 0 && fdp.ConsumeBool()) {
                // Choose a random variable to reference
                size_t var_index = fdp.ConsumeIntegralInRange<size_t>(0, var_count - 1);
                std::string var_ref = "$" + var_name_storage[var_index];
                // Insert the reference at a random position (or append)
                if (modified_xpath.empty() || fdp.ConsumeBool()) {
                    modified_xpath += var_ref;
                } else {
                    size_t pos = fdp.ConsumeIntegralInRange<size_t>(0, modified_xpath.size());
                    modified_xpath.insert(pos, var_ref);
                }
            }
            
            // Create the xpath_query with the variable set (if any)
            pugi::xpath_query query(modified_xpath.c_str(), var_count > 0 ? &vars : NULL);
            
            // Get the parse result
            const pugi::xpath_parse_result& parse_result = query.result();
            (void)parse_result;
            
            // Select a random context node (or the document root if empty)
            pugi::xpath_node context_xpath_node;
            if (!context_nodes.empty()) {
                size_t node_index = fdp.ConsumeIntegralInRange<size_t>(0, context_nodes.size() - 1);
                context_xpath_node = context_nodes[node_index];
            } else {
                context_xpath_node = pugi::xpath_node(doc);
            }
            
            // Get the xml_node for select_node/select_nodes (parent node if context is an attribute)
            pugi::xml_node context_xml_node = context_xpath_node.node();
            
            // Call select_node and select_nodes
            pugi::xpath_node result_node = context_xml_node.select_node(query);
            pugi::xpath_node_set result_set = context_xml_node.select_nodes(query);
            
            // Call all evaluate methods on the query with the xpath_node context
            query.evaluate_boolean(context_xpath_node);
            query.evaluate_number(context_xpath_node);
            query.evaluate_string(context_xpath_node);
            query.evaluate_node(context_xpath_node);
            query.evaluate_node_set(context_xpath_node);
            
            // Use the results to increase coverage
            if (result_node) {
                result_node.node();
                result_node.attribute();
                result_node.parent();
                bool b = result_node == result_node;
                (void)b;
            }
            if (!result_set.empty()) {
                result_set.size();
                result_set[0];
                result_set.begin();
                result_set.end();
                result_set.first();
                result_set.sort(fdp.ConsumeBool());
                result_set.type();
                
                // Copy the node set
                pugi::xpath_node_set result_set_copy(result_set);
                (void)result_set_copy;
            }
            
            // Retrieve a random variable and call its getter (if it exists)
            if (var_count > 0) {
                size_t var_index = fdp.ConsumeIntegralInRange<size_t>(0, var_count - 1);
                const pugi::xpath_variable* var = vars.get(var_name_storage[var_index].c_str());
                if (var) {
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
        }
    }
#ifndef PUGIXML_NO_EXCEPTIONS
    catch (const std::exception&)
    {
        // Ignore XPath parsing errors and memory allocation errors during fuzzing
    }
#endif

    return 0;
}