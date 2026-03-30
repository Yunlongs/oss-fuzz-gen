#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <vector>
#include <functional>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);
    bool reverse = fdp.ConsumeBool();
    uint16_t node_limit = fdp.ConsumeIntegralInRange<uint16_t>(0, 1000);
    std::vector<uint8_t> xml_buffer = fdp.ConsumeRemainingBytes<uint8_t>();

    pugi::xml_document doc;
    doc.load_buffer(xml_buffer.data(), xml_buffer.size());

    std::vector<pugi::xpath_node> nodes;

    std::function<void(pugi::xml_node)> traverse = [&](pugi::xml_node n) {
        if (nodes.size() >= node_limit) return;
        nodes.push_back(pugi::xpath_node(n));
        for (pugi::xml_attribute a = n.first_attribute(); a; a = a.next_attribute()) {
            if (nodes.size() >= node_limit) return;
            nodes.push_back(pugi::xpath_node(a, n));
        }
        for (pugi::xml_node child = n.first_child(); child; child = child.next_sibling()) {
            traverse(child);
        }
    };
    traverse(doc);

    if (nodes.empty()) {
        pugi::xpath_node_set empty_set;
        empty_set.sort(reverse);
        return 0;
    }

    pugi::xpath_node_set set(nodes.data(), nodes.data() + nodes.size(), pugi::xpath_node_set::type_unsorted);
    set.sort(reverse);

    return 0;
}