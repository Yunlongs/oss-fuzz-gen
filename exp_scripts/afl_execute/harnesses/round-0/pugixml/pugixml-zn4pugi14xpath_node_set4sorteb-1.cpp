#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <vector>
#include <functional>
#include <algorithm>
#include <random>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);
    bool reverse = fdp.ConsumeBool();
    uint16_t node_limit = fdp.ConsumeIntegralInRange<uint16_t>(0, 1000);
    uint32_t shuffle_seed = fdp.ConsumeIntegral<uint32_t>();
    bool use_xpath = fdp.ConsumeBool();
    bool use_second_doc = fdp.ConsumeBool();
    bool include_empty = fdp.ConsumeBool();
    std::string xpath_text;
    if (use_xpath) {
        xpath_text = fdp.ConsumeRandomLengthString(256);
    }
    std::vector<uint8_t> xml_buffer = fdp.ConsumeRemainingBytes<uint8_t>();

    pugi::xml_document doc1;
    doc1.load_buffer(xml_buffer.data(), xml_buffer.size());
    doc1.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_minimal);
    doc1.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_full);

    pugi::xml_document doc2;

    std::vector<pugi::xpath_node> nodes;

    // Option 1: Use XPath query to generate node set from doc1
    if (use_xpath && !xpath_text.empty()) {
#ifndef PUGIXML_NO_EXCEPTIONS
        try {
#endif
            pugi::xpath_query query(xpath_text.c_str());
            if (query) {
                pugi::xpath_node_set result = query.evaluate_node_set(doc1);
                nodes.assign(result.begin(), result.end());
            }
#ifndef PUGIXML_NO_EXCEPTIONS
        } catch (pugi::xpath_exception&) {
            // Ignore invalid XPath expressions
        }
#endif
    }

    // Option 2: If XPath not used or failed, traverse doc1
    if (nodes.empty()) {
        std::function<void(pugi::xml_node)> traverse = [&](pugi::xml_node n) {
            if (nodes.size() >= node_limit) return;
            nodes.push_back(pugi::xpath_node(n));
            // Collect attributes with parent node
            for (pugi::xml_attribute a = n.first_attribute(); a; a = a.next_attribute()) {
                if (nodes.size() >= node_limit) return;
                nodes.push_back(pugi::xpath_node(a, n));
            }
            // Recurse children
            for (pugi::xml_node child = n.first_child(); child; child = child.next_sibling()) {
                traverse(child);
            }
        };
        traverse(doc1);
    }

    // If use_second_doc is true, parse the buffer into doc2, modify it to set the shared mask, and add its nodes
    if (use_second_doc && !xml_buffer.empty()) {
        // Parse the same buffer again to create an independent document
        if (doc2.load_buffer(xml_buffer.data(), xml_buffer.size())) {
            // Modify doc2 by moving a node to set the xml_memory_page_contents_shared_mask
            pugi::xml_node root2 = doc2.root();
            pugi::xml_node first_child = root2.first_child();
            if (first_child) {
                // This move operation sets the shared mask, disabling the fast path in document_buffer_order
                root2.append_move(first_child);
            }

            // Collect nodes from doc2, up to node_limit
            std::function<void(pugi::xml_node)> traverse2 = [&](pugi::xml_node n) {
                if (nodes.size() >= node_limit) return;
                nodes.push_back(pugi::xpath_node(n));
                for (pugi::xml_attribute a = n.first_attribute(); a; a = a.next_attribute()) {
                    if (nodes.size() >= node_limit) return;
                    nodes.push_back(pugi::xpath_node(a, n));
                }
                for (pugi::xml_node child = n.first_child(); child; child = child.next_sibling()) {
                    traverse2(child);
                }
            };
            traverse2(doc2);
        }
    }

    // Include an empty xpath_node if requested
    if (include_empty) {
        nodes.push_back(pugi::xpath_node());
    }

    // If no nodes, test empty set with both reverse values
    if (nodes.empty()) {
        pugi::xpath_node_set empty_set;
        empty_set.sort(reverse);
        empty_set.sort(!reverse);
        empty_set.first(); // Cover first() on empty set
        return 0;
    }

    // Create a shuffled copy for unsorted testing
    std::vector<pugi::xpath_node> shuffled = nodes;
    std::minstd_rand rng(shuffle_seed);
    std::shuffle(shuffled.begin(), shuffled.end(), rng);

    // Create a reverse-sorted copy (reverse of document order from the first document's perspective)
    // Note: since we have nodes from two documents, "document order" is not defined across documents.
    // We'll just reverse the vector as it is.
    std::vector<pugi::xpath_node> reversed = nodes;
    std::reverse(reversed.begin(), reversed.end());

    // Helper to test a given vector with a specific type
    auto test_set = [reverse](const std::vector<pugi::xpath_node>& vec, pugi::xpath_node_set::type_t type) {
        pugi::xpath_node_set set(vec.data(), vec.data() + vec.size(), type);
        // Call first() before sorting (to cover unsorted branch if type is unsorted)
        set.first();
        set.sort(reverse);
        set.first(); // first() after sorting
        set.sort(!reverse); // Test opposite direction
        set.first(); // first() after second sorting
    };

    // Test unsorted set (shuffled) with type_unsorted
    test_set(shuffled, pugi::xpath_node_set::type_unsorted);

    // Test sorted set (original order) with type_unsorted
    test_set(nodes, pugi::xpath_node_set::type_unsorted);

    // Test reverse-sorted set (reversed order) with type_unsorted
    test_set(reversed, pugi::xpath_node_set::type_unsorted);

    // Test sorted set with type_sorted
    test_set(nodes, pugi::xpath_node_set::type_sorted);

    // Test reverse-sorted set with type_sorted_reverse
    test_set(reversed, pugi::xpath_node_set::type_sorted_reverse);

    // Additionally, test with a single-node set (if present) to cover xpath_get_order's early return
    if (nodes.size() >= 1) {
        std::vector<pugi::xpath_node> single_node = { nodes[0] };
        pugi::xpath_node_set single_set(single_node.data(), single_node.data() + single_node.size(), pugi::xpath_node_set::type_unsorted);
        single_set.sort(reverse);
        single_set.first();
    }

    return 0;
}