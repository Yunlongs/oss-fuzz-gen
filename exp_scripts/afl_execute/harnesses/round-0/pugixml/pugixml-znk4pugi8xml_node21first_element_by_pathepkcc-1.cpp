#include "../src/pugixml.hpp"
#include <fuzzer/FuzzedDataProvider.h>
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    FuzzedDataProvider provider(Data, Size);
    
    // First, consume the delimiter (one char_t)
    pugi::char_t delimiter = provider.ConsumeIntegral<pugi::char_t>();
    
    // Then, consume the XML buffer
    size_t xml_size = provider.ConsumeIntegralInRange<size_t>(0, provider.remaining_bytes());
    std::vector<uint8_t> xml_buffer = provider.ConsumeBytes<uint8_t>(xml_size);
    
    // The remaining bytes are for the path
    std::vector<pugi::char_t> path_vec = provider.ConsumeRemainingBytes<pugi::char_t>();
    std::basic_string<pugi::char_t> path_str(path_vec.begin(), path_vec.end());
    
    pugi::xml_document doc;
    
    // Parse the XML buffer with different options and call first_element_by_path each time
    doc.load_buffer(xml_buffer.data(), xml_buffer.size());
    pugi::xml_node node1 = doc.first_element_by_path(path_str.c_str(), delimiter);
    (void)node1;
    
    doc.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_minimal);
    pugi::xml_node node2 = doc.first_element_by_path(path_str.c_str(), delimiter);
    (void)node2;
    
    doc.load_buffer(xml_buffer.data(), xml_buffer.size(), pugi::parse_full);
    pugi::xml_node node3 = doc.first_element_by_path(path_str.c_str(), delimiter);
    (void)node3;
    
    return 0;
}