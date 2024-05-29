/*
c++: 23
package_definitions: true
deps:
    - pub.egorpugin.primitives.http
    - pub.egorpugin.primitives.xml
    - pub.egorpugin.primitives.templates2
    - pub.egorpugin.primitives.sw.main
    - org.sw.demo.zeux.pugixml
    - org.sw.demo.htacg.tidy_html5
    - org.sw.demo.boost.pfr
*/

// https://www.postgresql.org/docs/current/protocol-message-formats.html

#include <pugixml.hpp>
#include <primitives/http.h>
#include <primitives/sw/main.h>
#include <primitives/xml.h>
#include <tidy.h>
#include <tidybuffio.h>

#include <format>
#include <print>

auto tidy_html(auto &&s) {
    TidyDoc tidyDoc = tidyCreate();
    SCOPE_EXIT {
        tidyRelease(tidyDoc);
    };
    TidyBuffer tidyOutputBuffer = {0};
    tidyOptSetBool(tidyDoc, TidyXmlOut, yes) && tidyOptSetBool(tidyDoc, TidyQuiet, yes) &&
        tidyOptSetBool(tidyDoc, TidyNumEntities, yes) && tidyOptSetBool(tidyDoc, TidyShowWarnings, no) &&
        tidyOptSetInt(tidyDoc, TidyWrapLen, 0);
    tidyParseString(tidyDoc, s.c_str());
    tidyCleanAndRepair(tidyDoc);
    tidySaveBuffer(tidyDoc, &tidyOutputBuffer);
    if (!tidyOutputBuffer.bp)
        throw SW_RUNTIME_ERROR("tidy: cannot convert from html to xhtml");
    std::string tidyResult;
    tidyResult = (char *)tidyOutputBuffer.bp;
    tidyBufFree(&tidyOutputBuffer);
    return tidyResult;
}

std::string get_content(pugi::xml_node from) {
    if (from.type() == pugi::node_element) {
        std::string content;
        for (auto &&c : from.children()) {
            content += get_content(c);
        }
        return content;
    }
    if (from.type() == pugi::node_pcdata) {
        return from.text().get();
    }
    throw SW_RUNTIME_ERROR("unknown node type");
}

struct field {
    std::string type;
    std::string comment;

    auto emit() const {
        std::string s;
        s += std::format("    {} {};\n", type, c_name());
        return s;
    }
    std::string c_type() const {
        std::string s;
        for (int i = 0; auto c : type) {
            if (c == ' ') {
                break;
            }
            if (isupper(c)) {
                c = tolower(c);
                if (i) {
                    s += '_';
                }
                s += c;
            } else {
                s += c;
            }
            ++i;
        }
        return s;
    }
    std::string c_name() const {
        std::string s;
        if (comment.starts_with("Identifies the message"sv)) {
            return "id"s;
        }
        if (comment.starts_with("Length"sv)) {
            return "length"s;
        }
        for (int i = 0; auto c : comment) {
            if (c == ' ') {
                break;
            }
            if (isupper(c)) {
                c = tolower(c);
                if (i) {
                    s += '_';
                }
                s += c;
            } else {
                s += c;
            }
            ++i;
        }
        return s;
    }
};
struct type {
    std::string name;
    std::vector<field> fields;

    auto emit() const {
        std::string s;
        s += std::format("struct {} {{\n", c_name());
        for (auto &&f : fields) {
            s += f.emit();
        }
        s += std::format("}};\n\n");
        return s;
    }
    std::string c_name() const {
        std::string s;
        for (int i = 0; auto c : name) {
            if (c == ' ') {
                break;
            }
            if (isupper(c)) {
                c = tolower(c);
                if (i) {
                    s += '_';
                }
                s += c;
            } else {
                s += c;
            }
            ++i;
        }
        return s;
    }
};
using types = std::vector<type>;

struct parser {
    std::string page;
    parser() {
        auto fn = "protocol-message-formats.html";
        if (!fs::exists(fn)) {
            auto f = download_file("https://www.postgresql.org/docs/current/protocol-message-formats.html");
            write_file(fn, tidy_html(f));
        }
        page = read_file(fn);
    }
    auto parse() {
        pugi::xml_document doc;
        if (auto r = doc.load_buffer(page.data(), page.size()); !r) {
            throw std::runtime_error{std::format("xml parse error = {}", r.description())};
        }
        types ts;
        for (auto &&x : doc.select_nodes(pugi::xpath_query{"//div/div/dl/dt"})) {
            auto n = x.node();
            auto &t = ts.emplace_back();
            t.name = get_content(n);
            // comes from <a>
            if (t.name.ends_with('#')) {
                t.name.pop_back();
            }
            for (auto &&x : n.next_sibling().select_nodes(pugi::xpath_query{"div/dl/dt"})) {
                auto n = x.node();
                auto &f = t.fields.emplace_back();
                f.type = get_content(n);
                boost::replace_all(f.type, "\n", "");
                f.comment = get_content(n.next_sibling());
                boost::replace_all(f.comment, "\n", "");
            }
        }
        return ts;
    }
};

int main(int argc, char *argv[]) {
    parser p;
    auto ts = p.parse();
    for (auto &&t : ts) {
        std::println("{}", t.name);
        for (auto &&f : t.fields) {
            std::println("\t{}", f.type);
            std::println("\t\t{}", f.comment);
        }
        std::println("{}", t.emit());
    }
    return 0;
}
