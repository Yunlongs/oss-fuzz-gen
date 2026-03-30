#define PUGIXML_HEADER_ONLY
#include "../src/pugixml.hpp"
#include <fuzzer/FuzzedDataProvider.h>

// Dummy xml_writer.
class dummy_xml_writer : public pugi::xml_writer {
public:
    virtual void write(const void* /* data */, size_t /* size */) {}
};

// Enter the same namespaces and anonymous namespace as the target function.
namespace pugi { namespace impl { namespace {

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider stream(data, size);

    // Consume 1 byte for chartypex_t bitmask.
    uint8_t type_bits = stream.ConsumeIntegral<uint8_t>();
    // Mask to keep only bits 0-4 (valid chartypex_t bits).
    type_bits &= 0x1F;
    chartypex_t type = static_cast<chartypex_t>(type_bits);

    // Consume 4 bytes for flags.
    unsigned int flags = stream.ConsumeIntegral<unsigned int>();

    // Remaining bytes as the string.
    std::string text = stream.ConsumeRemainingBytesAsString();

    // Create dummy writer and buffered writer.
    dummy_xml_writer dummy;
    xml_buffered_writer writer(dummy, ::pugi::encoding_auto);

    // Call the function under test.
    text_output(writer, text.c_str(), type, flags);

    return 0;
}

} } } // namespace pugi::impl::<anonymous>