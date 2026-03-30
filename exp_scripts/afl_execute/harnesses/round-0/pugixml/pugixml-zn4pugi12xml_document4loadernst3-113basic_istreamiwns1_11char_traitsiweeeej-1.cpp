#include "../src/pugixml.hpp"
#include <fuzzer/FuzzedDataProvider.h>

#include <stdint.h>
#include <sstream>
#include <cstring>

#ifndef PUGIXML_NO_STL
// Custom stream buffer for non-seekable streams (from test_document.cpp)
template <typename T>
class char_array_buffer : public std::basic_streambuf<T> {
public:
    char_array_buffer(T* begin, T* end) {
        this->setg(begin, begin, end);
    }
};

// Stream buffer that fails on seek (from test_document.cpp)
template <typename T>
class seek_fail_buffer : public std::basic_streambuf<T> {
public:
    int seeks;
    seek_fail_buffer() : seeks(0) {}

    typename std::basic_streambuf<T>::pos_type seekoff(typename std::basic_streambuf<T>::off_type,
                                                       std::ios_base::seekdir,
                                                       std::ios_base::openmode) override {
        seeks++;
        // Pretend that our buffer is seekable (this is called by tellg)
        return seeks == 1 ? 0 : -1;
    }
};

// Stream buffer that fails on tell (from test_document.cpp)
template <typename T>
class tell_fail_buffer : public std::basic_streambuf<T> {
public:
    int seeks;
    tell_fail_buffer() : seeks(0) {}

    typename std::basic_streambuf<T>::pos_type seekoff(typename std::basic_streambuf<T>::off_type,
                                                       std::ios_base::seekdir dir,
                                                       std::ios_base::openmode) override {
        seeks++;
        return seeks > 1 && dir == std::ios_base::cur ? -1 : 0;
    }

    typename std::basic_streambuf<T>::pos_type seekpos(typename std::basic_streambuf<T>::pos_type,
                                                       std::ios_base::openmode) override {
        return 0;
    }
};

// Stream buffer that fails on read (from test_document.cpp)
template <typename T>
class read_fail_buffer : public std::basic_streambuf<T> {
public:
    read_fail_buffer() {}

    typename std::basic_streambuf<T>::int_type underflow() override {
        return std::basic_streambuf<T>::traits_type::eof();
    }
};
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    pugi::xml_document doc;

    FuzzedDataProvider fdp(Data, Size);

    // Split input: first part for buffer load, second part for stream load
    size_t buffer_size = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
    std::vector<uint8_t> buffer_data = fdp.ConsumeBytes<uint8_t>(buffer_size);

    // Existing buffer load calls with fuzzed data (even if empty)
    doc.load_buffer(buffer_data.data(), buffer_data.size());
    doc.load_buffer(buffer_data.data(), buffer_data.size(), pugi::parse_minimal);
    doc.load_buffer(buffer_data.data(), buffer_data.size(), pugi::parse_full);

#ifndef PUGIXML_NO_STL
    // Parse options: either a predefined set or a random combination of known flags
    unsigned int options;
    if (fdp.ConsumeBool()) {
        // Predefined set
        switch (fdp.ConsumeIntegralInRange(0, 2)) {
            case 0: options = pugi::parse_minimal; break;
            case 1: options = pugi::parse_default; break;
            case 2: options = pugi::parse_full; break;
        }
    } else {
        // Random combination of known flags
        static const unsigned int known_flags[] = {
            pugi::parse_pi,
            pugi::parse_comments,
            pugi::parse_cdata,
            pugi::parse_escapes,
            pugi::parse_eol,
            pugi::parse_wconv_attribute,
            pugi::parse_declaration,
            pugi::parse_doctype
        };
        options = 0;
        for (size_t i = 0; i < sizeof(known_flags)/sizeof(known_flags[0]); ++i) {
            if (fdp.ConsumeBool()) {
                options |= known_flags[i];
            }
        }
    }

    // Choose stream type: 0=seekable, 1=non-seekable, 2=seek_fail, 3=tell_fail, 4=read_fail
    int stream_type = fdp.ConsumeIntegralInRange(0, 4);

    // For stream types 0 and 1, we need data; for others, we don't.
    std::vector<uint8_t> bytes;
    if (stream_type == 0 || stream_type == 1) {
        size_t stream_bytes = fdp.ConsumeIntegralInRange<size_t>(0, fdp.remaining_bytes());
        bytes = fdp.ConsumeBytes<uint8_t>(stream_bytes);
    }

    // For seekable streams, possibly set error bits before calling load
    bool set_error_bits = (stream_type == 0) && fdp.ConsumeBool();
    int error_bits = 0;
    if (set_error_bits) {
        error_bits = fdp.ConsumeIntegralInRange(0, 7); // 3 bits for failbit, badbit, eofbit
    }

    switch (stream_type) {
        case 0: { // seekable
            std::basic_istringstream<wchar_t> iss;
            if (!bytes.empty()) {
                size_t wlen = (bytes.size() + sizeof(wchar_t) - 1) / sizeof(wchar_t);
                std::vector<wchar_t> wchars(wlen, 0);
                memcpy(wchars.data(), bytes.data(), bytes.size());
                std::basic_string<wchar_t> ws(wchars.begin(), wchars.end());
                iss.str(ws);
                iss.clear();
            } else {
                // Empty stream
                iss.clear();
            }
            if (set_error_bits) {
                if (error_bits & 1) iss.setstate(std::ios::failbit);
                if (error_bits & 2) iss.setstate(std::ios::badbit);
                if (error_bits & 4) iss.setstate(std::ios::eofbit);
            }
            doc.load(iss, options);
            break;
        }
        case 1: { // non-seekable
            if (!bytes.empty()) {
                size_t wlen = (bytes.size() + sizeof(wchar_t) - 1) / sizeof(wchar_t);
                std::vector<wchar_t> wchars(wlen, 0);
                memcpy(wchars.data(), bytes.data(), bytes.size());
                char_array_buffer<wchar_t> buffer(wchars.data(), wchars.data() + wlen);
                std::basic_istream<wchar_t> is(&buffer);
                doc.load(is, options);
            } else {
                // Empty buffer
                wchar_t empty = 0;
                char_array_buffer<wchar_t> buffer(&empty, &empty);
                std::basic_istream<wchar_t> is(&buffer);
                doc.load(is, options);
            }
            break;
        }
        case 2: { // seek_fail
            seek_fail_buffer<wchar_t> buffer;
            std::basic_istream<wchar_t> is(&buffer);
            doc.load(is, options);
            break;
        }
        case 3: { // tell_fail
            tell_fail_buffer<wchar_t> buffer;
            std::basic_istream<wchar_t> is(&buffer);
            doc.load(is, options);
            break;
        }
        case 4: { // read_fail
            read_fail_buffer<wchar_t> buffer;
            std::basic_istream<wchar_t> is(&buffer);
            doc.load(is, options);
            break;
        }
    }
#endif

    return 0;
}