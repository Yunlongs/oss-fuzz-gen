#include "../src/pugixml.hpp"
#include "fuzzer/FuzzedDataProvider.h"

#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>
#include <functional>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
{
	FuzzedDataProvider fdp(Data, Size);

	// Extended set of XPath patterns, derived from pugixml test suite and XPath 1.0 spec
	static const char* xpath_patterns[] = {
		// Simple paths
		"//*",
		"child::node()",
		"@*",
		"text()",
		".",
		"..",
		"*",
		"/*",
		"//node()",
		"/",
		"//.",
		"//..",
		// Axes
		"child::*",
		"parent::*",
		"attribute::*",
		"descendant::*",
		"descendant-or-self::*",
		"ancestor::*",
		"following-sibling::*",
		"preceding-sibling::*",
		"self::*",
		"ancestor-or-self::*",
		"following::*",
		"preceding::*",
		"namespace::*",
		// Predicates
		"//*[@id]",
		"//*[position()<3]",
		"//*[last()]",
		"//*[1]",
		"//*[position()=1]",
		"//*[text()]",
		"//*[@id='value']",
		"//*[contains(@class,'foo')]",
		"//*[starts-with(@name,'pre')]",
		"//*[substring(@attr,2,3)='alu']",
		"//*[string-length(@attr) > 2]",
		"//*[normalize-space(@attr)='value']",
		"//*[translate(@attr,'abc','ABC')='ABC']",
		"//*[floor(@number) = 1]",
		"//*[ceiling(@number) = 2]",
		"//*[round(@number) = 3]",
		"//*[position() mod 2 = 0]",
		"//*[starts-with(@attr, 'foo') and string-length(@attr) > 5]",
		// Functions
		"count(//*)",
		"string-length(name(.))",
		"concat('a','b')",
		"number(1+2)",
		"true()",
		"false()",
		"not(false())",
		"local-name()",
		"namespace-uri()",
		"name()",
		"substring-before('abcde','cd')",
		"substring-after('abcde','bc')",
		"substring('abcdef',2,3)",
		"normalize-space('  foo  bar  ')",
		"translate('abc','abc','ABC')",
		"floor(3.14)",
		"ceiling(3.14)",
		"round(3.14)",
		"sum(//*/@number)",
		// Operators
		"1 + 2",
		"3 * 4",
		"5 div 2",
		"6 mod 5",
		"1 < 2",
		"1 = 1",
		"1 != 2",
		"(1=1) and (2=2)",
		"(1=1) or (2=3)",
		"1 < 2 and 3 > 1",
		"1 <= 2 or 3 >= 4",
		// Variable references (to be replaced with actual variable names)
		"$var",
		"//*[name()=$var]",
		"//*[@attr=$var]",
		"$var + 1",
		"$var div 2",
		"$var = 'value'",
		"$var and true()",
		// Complex expressions
		"/bookstore/book[price>35]",
		"/bookstore/book/title | /bookstore/book/price",
		"//book/title | //book/price",
		"//title[@lang='en']",
		"//title[@lang='en' and @size='large']",
		"//*[namespace-uri()='']",
		"//*[local-name()='element']",
		"//ns:*",
		"//*[contains(concat(' ', @class, ' '), ' foo ')]",
		// Additional patterns from pugixml test suite
		"a:x/a:y[@p='p' and @q='q']/a:z/text()",
		"//section[../self::section[@role=\"division\"]]",
		"//section[@role=\"subdivision\" and not(../self::section[@role=\"division\"])]",
		"//*[local-name()='c' and @id='b']",
		"/a/c[@id]",
		"/a/c[(@id)]",
		"/a/c[ @id ]",
		"/a/c[ (@id) ]",
		"/a/c[( @id )]",
		"/a/c[ ( @id ) ]",
		" / a / c [ ( @id ) ] ",
	};

	// Choose 1-3 XPath patterns per run
	size_t num_queries = fdp.ConsumeIntegralInRange<size_t>(1, 3);
	std::vector<std::string> xpath_strings;
	for (size_t q = 0; q < num_queries; ++q) {
		std::string xpath_str;
		if (fdp.ConsumeBool()) {
			// Use a random string
			xpath_str = fdp.ConsumeRandomLengthString(1024);
		} else {
			size_t pattern_index = fdp.ConsumeIntegralInRange<size_t>(0, sizeof(xpath_patterns)/sizeof(xpath_patterns[0]) - 1);
			xpath_str = xpath_patterns[pattern_index];
		}
		xpath_strings.push_back(xpath_str);
	}

#ifndef PUGIXML_NO_EXCEPTIONS
	try
#endif
	{
		pugi::xpath_variable_set vars;
		// Create a few variables (0 to 5)
		size_t var_count = fdp.ConsumeIntegralInRange<size_t>(0, 5);
		std::vector<std::string> var_names;
		for (size_t i = 0; i < var_count; ++i) {
			var_names.push_back("var" + std::to_string(i));
			// Exclude xpath_type_none
			const int xpath_value_type_count = pugi::xpath_type_boolean;
			pugi::xpath_value_type value_type = static_cast<pugi::xpath_value_type>(
				fdp.ConsumeIntegralInRange(1, xpath_value_type_count));
			vars.add(var_names.back().c_str(), value_type);
		}

		// For each XPath string, optionally replace "$var" with a random variable name
		for (auto& xpath_str : xpath_strings) {
			if (!var_names.empty() && fdp.ConsumeBool()) {
				size_t var_idx = fdp.ConsumeIntegralInRange<size_t>(0, var_names.size() - 1);
				std::string var_ref = "$" + var_names[var_idx];
				// Replace the first occurrence of "$var" with the actual variable reference
				size_t pos = xpath_str.find("$var");
				if (pos != std::string::npos) {
					xpath_str.replace(pos, 4, var_ref);
				}
			}
		}

		// Create XPath queries (may throw if the string is invalid)
		std::vector<pugi::xpath_query> queries;
		for (const auto& xpath_str : xpath_strings) {
			queries.emplace_back(xpath_str.c_str(), &vars);
		}

		// Generate XML buffer with complex structure
		std::vector<uint8_t> xml_buffer;
		if (fdp.ConsumeBool() && Size > 10) {
			// Recursive XML generator
			std::function<std::string(FuzzedDataProvider&, int)> generate =
				[&](FuzzedDataProvider& fdp_local, int depth) -> std::string {
					if (depth > 4) return "";
					std::string xml;
					int elements = fdp_local.ConsumeIntegralInRange(0, 4);
					for (int i = 0; i < elements; ++i) {
						// Element name with optional namespace prefix
						std::string tag = "elem";
						if (fdp_local.ConsumeBool()) {
							tag = "ns:" + tag;
						}
						xml += "<" + tag;
						// Attributes
						int attrs = fdp_local.ConsumeIntegralInRange(0, 3);
						for (int a = 0; a < attrs; ++a) {
							xml += " attr" + std::to_string(a) + "=\"value" + std::to_string(a) + "\"";
						}
						if (fdp_local.ConsumeBool()) {
							xml += " id=\"" + std::to_string(i) + "\"";
						}
						// Optional namespace declaration
						if (fdp_local.ConsumeBool()) {
							xml += " xmlns:ns=\"http://example.com/ns\"";
						}
						if (fdp_local.ConsumeBool()) {
							xml += ">";
							// Text content
							if (fdp_local.ConsumeBool()) {
								xml += "text";
							}
							// Comment
							if (fdp_local.ConsumeBool()) {
								xml += "<!-- comment -->";
							}
							// Child elements
							xml += generate(fdp_local, depth + 1);
							xml += "</" + tag + ">";
						} else {
							xml += "/>";
						}
					}
					return xml;
				};
			std::string xml = "<?xml version=\"1.0\"?><root>";
			xml += generate(fdp, 0);
			xml += "</root>";
			xml_buffer.assign(xml.begin(), xml.end());
		} else {
			// Use the remaining bytes as raw XML buffer
			xml_buffer = fdp.ConsumeRemainingBytes<uint8_t>();
		}

		// Helper lambda to parse and test the queries on a document
		auto test_doc = [&](pugi::xml_document& doc, unsigned int flags) {
			if (xml_buffer.empty()) return;
			doc.load_buffer(xml_buffer.data(), xml_buffer.size(), flags);

			// Set variable values (including node-set variables) after parsing
			for (size_t i = 0; i < var_names.size(); ++i) {
				const char* name = var_names[i].c_str();
				pugi::xpath_variable* var = vars.get(name);
				if (!var) continue;

				switch (var->type()) {
					case pugi::xpath_type_boolean:
						vars.set(name, fdp.ConsumeBool());
						break;
					case pugi::xpath_type_number:
						vars.set(name, fdp.ConsumeFloatingPoint<double>());
						break;
					case pugi::xpath_type_string:
						vars.set(name, fdp.ConsumeRandomLengthString(256).c_str());
						break;
					case pugi::xpath_type_node_set: {
						// Populate with a few nodes from the document
						pugi::xpath_node_set node_set = doc.select_nodes("//* | //@* | //text() | //comment()");
						vars.set(name, node_set);
						break;
					}
					default:
						break;
				}
			}

			// For each query, test on the root and on a few random nodes
			for (const auto& q : queries) {
				// Test on the root node
				doc.select_single_node(q);

				// Collect nodes of various types (elements, text, comments)
				std::vector<pugi::xml_node> nodes;
				std::vector<std::pair<pugi::xml_node, int>> queue; // node, depth

				for (pugi::xml_node n = doc.first_child(); n; n = n.next_sibling()) {
					queue.emplace_back(n, 1);
				}

				for (size_t i = 0; i < queue.size(); ++i) {
					pugi::xml_node cur = queue[i].first;
					int depth = queue[i].second;
					nodes.push_back(cur);
					if (depth < 3) {
						for (pugi::xml_node child = cur.first_child(); child; child = child.next_sibling()) {
							queue.emplace_back(child, depth + 1);
						}
					}
				}

				// Shuffle and pick up to 5 nodes
				if (!nodes.empty()) {
					// Simple deterministic shuffle using fdp
					for (size_t i = 0; i < nodes.size(); ++i) {
						size_t j = fdp.ConsumeIntegralInRange<size_t>(0, nodes.size() - 1);
						std::swap(nodes[i], nodes[j]);
					}
					size_t limit = std::min<size_t>(5, nodes.size());
					for (size_t i = 0; i < limit; ++i) {
						nodes[i].select_single_node(q);
					}
				}
			}
		};

		pugi::xml_document doc1, doc2, doc3;
		test_doc(doc1, pugi::parse_default);
		test_doc(doc2, pugi::parse_minimal);
		test_doc(doc3, pugi::parse_full);
	}
#ifndef PUGIXML_NO_EXCEPTIONS
	catch (pugi::xpath_exception&)
	{
		// Ignore XPath parsing errors
	}
#endif
	return 0;
}