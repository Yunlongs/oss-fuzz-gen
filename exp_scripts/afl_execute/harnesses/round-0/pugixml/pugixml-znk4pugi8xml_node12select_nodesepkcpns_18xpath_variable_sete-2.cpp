#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>
#include <algorithm>

static void collect_nodes_and_attrs(pugi::xml_node node, std::vector<pugi::xpath_node>& nodes, int max_depth, int depth = 0) {
    if (depth > max_depth) return;
    nodes.push_back(pugi::xpath_node(node));
    for (pugi::xml_attribute attr = node.first_attribute(); attr; attr = attr.next_attribute()) {
        nodes.push_back(pugi::xpath_node(attr, node));
    }
    for (pugi::xml_node child = node.first_child(); child; child = child.next_sibling()) {
        collect_nodes_and_attrs(child, nodes, max_depth, depth + 1);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);

    // Parse XML as in original fuzz_parse.cpp
    size_t xml_size = fdp.ConsumeIntegralInRange<size_t>(0, Size);
    std::vector<uint8_t> xml_buffer = fdp.ConsumeBytes<uint8_t>(xml_size);

    pugi::xml_document doc;
    doc.load_buffer(xml_buffer.data(), xml_buffer.size());
    doc.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_minimal);
    doc.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_full);

    if (fdp.remaining_bytes() == 0) {
        return 0;
    }

    // Collect names from the document
    std::vector<std::string> node_names;
    std::vector<std::string> attr_names;
    std::vector<std::string> text_values;
    if (!doc.empty()) {
        pugi::xml_node_iterator it = doc.begin();
        pugi::xml_node_iterator end = doc.end();
        for (int i = 0; i < 10 && it != end; ++i, ++it) {
            const char* name = it->name();
            if (name && strlen(name) > 0) node_names.push_back(name);
            for (pugi::xml_attribute attr = it->first_attribute(); attr; attr = attr.next_attribute()) {
                const char* aname = attr.name();
                if (aname && strlen(aname) > 0) attr_names.push_back(aname);
            }
            const char* text = it->text().get();
            if (text && strlen(text) > 0) text_values.push_back(text);
        }
    }

    // Seed XPath queries from the project's test data
    const char* seed_queries[] = {
        "a/b/c",
        "sum(nodes) + round(concat(//a[translate(@id, 'abc', '012')]))",
        "1+2*3 div 4 mod 5-6",
        "@*/ancestor::*/near-north/*[4]/@*/preceding::text()",
        "library/nodes[@id=12]/element[@type='translate'][1]",
        "//*",
        "/*",
        "/node()",
        "//node()",
        "//@*",
        "/text()",
        "//attribute::*",
        "//namespace::*",
        "ancestor-or-self::*",
        "following-sibling::*",
        "preceding-sibling::*",
        "descendant-or-self::*",
        "parent::*",
        "child::*",
        "self::*",
        "//*[position()=1]",
        "//*[last()]",
        "//*[count(*)=0]",
        "//*[name()='elem']",
        "//*[contains(@attr,'value')]",
        "//*[starts-with(@attr,'val')]",
        "//*[string-length(@attr)>2]",
        "//*[number(@attr) > 0]",
        "//*[boolean(@attr)]",
        "//*[not(@attr)]",
        "//*[@attr1 and @attr2]",
        "//*[@attr1 or @attr2]",
        "//*[. = 'text']",
        "//*[. != 'text']",
        "//*[. < 'text']",
        "//*[. > 'text']",
        "//*[. <= 'text']",
        "//*[. >= 'text']",
        "//*[. mod 2 = 0]",
        "//*[. div 2 = 0]",
        "//*[. + 1 = 2]",
        "//*[. - 1 = 0]",
        "//*[. * 2 = 4]",
        "//*[. div 2 = 1]",
        "//*[. mod 2 = 1]",
    };
    const size_t num_seed_queries = sizeof(seed_queries) / sizeof(seed_queries[0]);

    // Choose a query template
    std::string xpath_query;
    int query_choice = fdp.ConsumeIntegralInRange(0, 3);
    if (query_choice == 0 && !node_names.empty()) {
        // Use a node name in a simple path
        int idx = fdp.ConsumeIntegralInRange(0, (int)node_names.size() - 1);
        xpath_query = "//" + node_names[idx];
    } else if (query_choice == 1 && !attr_names.empty()) {
        // Use an attribute name in a predicate
        int idx = fdp.ConsumeIntegralInRange(0, (int)attr_names.size() - 1);
        xpath_query = "//*[@" + attr_names[idx] + "]";
    } else if (query_choice == 2 && !text_values.empty()) {
        // Use a text value in a predicate
        int idx = fdp.ConsumeIntegralInRange(0, (int)text_values.size() - 1);
        xpath_query = "//*[text()='" + text_values[idx] + "']";
    } else {
        // Use a seed query
        int idx = fdp.ConsumeIntegralInRange(0, (int)num_seed_queries - 1);
        xpath_query = seed_queries[idx];
        // Replace placeholders with actual names if available
        if (!node_names.empty() && xpath_query.find("nodes") != std::string::npos) {
            size_t pos = xpath_query.find("nodes");
            xpath_query.replace(pos, 5, node_names[0]);
        }
        if (!attr_names.empty() && xpath_query.find("@attr") != std::string::npos) {
            size_t pos = xpath_query.find("@attr");
            xpath_query.replace(pos, 5, "@" + attr_names[0]);
        }
        if (!text_values.empty() && xpath_query.find("'text'") != std::string::npos) {
            size_t pos = xpath_query.find("'text'");
            xpath_query.replace(pos, 6, "'" + text_values[0] + "'");
        }
    }
    if (xpath_query.empty()) {
        xpath_query = fdp.ConsumeRandomLengthString(1024);
    }

    // Variable set
    bool use_vars = fdp.ConsumeBool();
    pugi::xpath_variable_set vars;
    std::vector<std::string> var_names;
    std::vector<int> var_types; // 0: bool, 1: number, 2: string, 3: node set

    if (use_vars) {
        size_t var_count = fdp.ConsumeIntegralInRange<size_t>(0, 50);
        for (size_t i = 0; i < var_count && fdp.remaining_bytes() > 0; ++i) {
            std::string var_name = fdp.ConsumeRandomLengthString(128);
            var_names.push_back(var_name);
            int type = fdp.ConsumeIntegralInRange(0, 3);
            var_types.push_back(type);
            switch (type) {
                case 0: {
                    bool val = fdp.ConsumeBool();
                    vars.set(var_name.c_str(), val);
                    break;
                }
                case 1: {
                    double val = fdp.ConsumeFloatingPoint<double>();
                    vars.set(var_name.c_str(), val);
                    break;
                }
                case 2: {
                    std::string val = fdp.ConsumeRandomLengthString(100);
                    vars.set(var_name.c_str(), val.c_str());
                    break;
                }
                case 3: {
                    pugi::xpath_node_set val;
                    if (fdp.ConsumeBool() && !doc.empty()) {
                        std::vector<pugi::xpath_node> nodes;
                        collect_nodes_and_attrs(doc, nodes, 2);
                        if (!nodes.empty()) {
                            int set_type = fdp.ConsumeIntegralInRange(0, 2);
                            pugi::xpath_node_set::type_t type_enum = static_cast<pugi::xpath_node_set::type_t>(set_type);
                            val = pugi::xpath_node_set(nodes.data(), nodes.data() + nodes.size(), type_enum);
                            if (type_enum == pugi::xpath_node_set::type_unsorted && fdp.ConsumeBool()) {
                                val.sort(false);
                            }
                        }
                    }
                    vars.set(var_name.c_str(), val);
                    break;
                }
            }
        }

        // Occasionally add a variable reference to the query
        if (!var_names.empty() && fdp.ConsumeBool()) {
            int var_idx = fdp.ConsumeIntegralInRange(0, (int)var_names.size() - 1);
            std::string var_ref = "$" + var_names[var_idx];
            // Insert the variable reference in a predicate or as a function argument
            if (var_types[var_idx] == 0) { // boolean
                xpath_query = "//*[" + var_ref + "]";
            } else if (var_types[var_idx] == 1) { // number
                xpath_query = "//*[position()=" + var_ref + "]";
            } else if (var_types[var_idx] == 2) { // string
                xpath_query = "//*[name()=" + var_ref + "]";
            } else { // node set
                xpath_query = "//*[count(" + var_ref + ") > 0]";
            }
        }
    }

#ifndef PUGIXML_NO_EXCEPTIONS
    try
#endif
    {
        // Evaluate on document root (without variables)
        doc.select_nodes(xpath_query.c_str(), nullptr);

        // Evaluate on document root with variables (if any)
        if (use_vars) {
            doc.select_nodes(xpath_query.c_str(), &vars);
        }

        // Create xpath_query for additional evaluations
        pugi::xpath_query q(xpath_query.c_str(), use_vars ? &vars : nullptr);

        q.evaluate_boolean(doc);
        q.evaluate_number(doc);
        q.evaluate_string(doc);
        q.evaluate_node(doc);
        q.evaluate_node_set(doc);

        // Collect diverse context nodes
        std::vector<pugi::xpath_node> contexts;
        contexts.push_back(pugi::xpath_node(doc)); // document node
        if (!doc.empty()) {
            collect_nodes_and_attrs(doc, contexts, 3);
        }

        // Evaluate on a random subset of contexts
        if (!contexts.empty()) {
            size_t num_contexts = fdp.ConsumeIntegralInRange<size_t>(0, contexts.size());
            for (size_t i = 0; i < num_contexts && fdp.remaining_bytes() > 0; ++i) {
                size_t idx = fdp.ConsumeIntegralInRange<size_t>(0, contexts.size() - 1);
                pugi::xpath_node ctx = contexts[idx];
                if (ctx.node()) {
                    ctx.node().select_nodes(xpath_query.c_str(), nullptr);
                    if (use_vars) {
                        ctx.node().select_nodes(xpath_query.c_str(), &vars);
                    }
                }
            }
        }
    }
#ifndef PUGIXML_NO_EXCEPTIONS
    catch (pugi::xpath_exception&) {
        // Ignore XPath errors
    }
    catch (std::exception&) {
        // Catch std::bad_alloc etc.
    }
#endif

    return 0;
}