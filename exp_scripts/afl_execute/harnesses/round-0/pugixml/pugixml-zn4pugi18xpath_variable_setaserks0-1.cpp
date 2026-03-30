#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
    FuzzedDataProvider fdp(Data, Size);

#ifndef PUGIXML_NO_EXCEPTIONS
    try
#endif
    {
        // Create two variable sets
        pugi::xpath_variable_set vars1, vars2;

        // Helper to populate a variable set with random variables
        auto populate_set = [&fdp](pugi::xpath_variable_set& set) {
            size_t var_count = fdp.ConsumeIntegralInRange<size_t>(0, 50);
            std::vector<std::string> var_name_storage;
            for (size_t i = 0; i < var_count; ++i) {
                var_name_storage.push_back(fdp.ConsumeRandomLengthString(128));

                const int xpath_value_type_count = pugi::xpath_type_boolean + 1;
                pugi::xpath_value_type value_type = static_cast<pugi::xpath_value_type>(
                    fdp.ConsumeIntegralInRange(0, xpath_value_type_count));
                set.add(var_name_storage.back().c_str(), value_type);
            }
        };

        // Populate both sets
        populate_set(vars1);
        populate_set(vars2);

        // Test the assignment operator
        vars1 = vars2;

        // Optionally test self‑assignment (does not require additional data)
        if (fdp.ConsumeBool()) {
            vars1 = vars1;
        }
    }
#ifndef PUGIXML_NO_EXCEPTIONS
    catch (pugi::xpath_exception&)
    {
    }
#endif
    return 0;
}