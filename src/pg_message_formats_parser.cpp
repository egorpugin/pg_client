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

#include <algorithm>
#include <ranges>
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

auto prepare_string(auto s) {
    // comes from <a>
    if (s.ends_with('#')) {
        s.pop_back();
    }
    boost::replace_all(s, "SSL", "Ssl");
    boost::replace_all(s, "SASL", "Sasl");
    boost::replace_all(s, "SSPI", "Sspi");
    boost::replace_all(s, "GSSENC", "Gssenc");
    boost::replace_all(s, "GSSAPI", "Gssapi");
    boost::replace_all(s, "GSS", "Gss");
    boost::replace_all(s, "MD5", "Md5");
    boost::replace_all(s, "ID", "Id");
    boost::replace_all(s, "\n", "");
    //boost::replace_all(s, "'", "");
    return s;
}

struct field {
    std::string type;
    std::string comment;

    auto emit() const {
        auto type = prepare_string(this->type);

        auto get_val = [&]() {
            std::string s;
            auto p = type.find('(');
            if (p == -1) {
                return s;
            }
            return "{" + type.substr(p + 1, type.find(')') - (p+1)) + "}";
        };

        auto v = get_val();
        std::string s;
        if (type.starts_with("Byte")) {
            try {
                auto bytes = std::stoi(type.substr(4));
                if (bytes == 1) {
                    s += std::format("    i8 {}{};\n", c_name(), v);
                } else {
                    s += std::format("    i8 {}[{}];\n", c_name(), bytes);
                }
            } catch (std::exception &e) {
                s += std::format("    i8 *{};\n", c_name());
            }
        } else if (type.starts_with("Int")) {
            auto bits = std::stoi(type.substr(3));
            s += std::format("    i{} {}{};\n", bits, c_name(), v);
        } else if (type.starts_with("String")) {
            s += std::format("    std::string {}{};\n", c_name(), v);
        } else {
            throw std::runtime_error{"unknown type"};
        }
        boost::replace_all(s, "__", "_");
        return s;
    }
    std::string c_name() const {
        auto comment = prepare_string(this->comment);

        std::string s;
        if (comment.starts_with("Identifies the message"sv)) {
            return "type"s;
        }
        if (comment.starts_with("Length of message contents"sv)) {
            return "length"s;
        }
        if (comment.starts_with("Length"sv)) {
            return "length2"s;
        }
        if (comment.starts_with("Specifies that"sv)) {
            return "auth_type"s;
        }
        for (int i = 0; auto c : comment) {
            if (c >= 'A' && c <= 'Z') {
                c = tolower(c);
                if (i) {
                    s += '_';
                }
                s += c;
            } else if (c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
                s += c;
            } else if (c == '.') {
                break;
            } else {
                s += '_';
            }
            ++i;
        }
        if (s.empty() || isdigit(s.front())) {
            s = "_" + s;
        }
        return s;
    }
};
struct type {
    std::string name;
    std::vector<field> fields;

    auto emit() const {
        auto name = prepare_string(this->name);

        std::string s;
        s += std::format("struct {} {{\n", c_name());
        bool fe{};
        if (name.contains("(B)"sv)) {
            s += std::format("    static constexpr inline bool backend_type = true;\n", c_name());
        } else if (name.contains("(F)"sv)) {
            fe = true;
            s += std::format("    static constexpr inline bool frontend_type = true;\n", c_name());
        } else if (name.contains("(F & B)"sv)) {
            fe = true;
            s += std::format("    static constexpr inline bool backend_type  = true;\n", c_name());
            s += std::format("    static constexpr inline bool frontend_type = true;\n", c_name());
        }
        s += "\n";
        for (auto &&f : fields
            //| std::views::drop(fe ? 0 : 0)
            //| std::views::take(2)
            ) {
            s += f.emit();
        }
        s += std::format("}};\n");
        return s;
    }
    std::string c_name() const {
        auto name = prepare_string(this->name);

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
            for (auto &&x : n.next_sibling().select_nodes(pugi::xpath_query{"div/dl/dt"})) {
                auto n = x.node();
                auto &f = t.fields.emplace_back();
                f.type = get_content(n);
                f.comment = get_content(n.next_sibling());
            }
        }
        return ts;
    }
};

int main(int argc, char *argv[]) {
    parser p;
    auto ts = p.parse();
    std::string raw, c;
    for (auto &&t : ts) {
        raw += std::format("{}\n", t.name);
        for (auto &&f : t.fields) {
            raw += std::format("\t{}\n", f.type);
            raw += std::format("\t\t{}\n", f.comment);
        }
        raw += "\n";
        c += std::format("{}\n", t.emit());
    }
    write_file("raw.txt", raw);
    write_file("pg_protocol_messages.h", c);
    write_file("pg_messages.h", c);
    return 0;
}
