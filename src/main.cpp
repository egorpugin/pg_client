#include <boost/asio.hpp>
#include <primitives/sw/main.h>
#include <primitives/templates2/string.h>

#include <string>
#include <variant>
#include <stdint.h>

namespace ip = boost::asio::ip;

template <typename T = void>
using task = boost::asio::awaitable<T>;

#include "pg_messages.h"

struct pg_connection {
    std::map<std::string, std::string> params;

    pg_connection(boost::asio::io_context &ctx, auto &&connstr) {
        auto vec = split_string(connstr, " ");
        for (auto &&v : vec) {
            auto kv = split_string(v, "=");
            params[kv.at(0)] = kv.at(1);
        }
        boost::asio::co_spawn(ctx, start(), boost::asio::detached);
    }
    task<> start() {
        auto ex = co_await boost::asio::this_coro::executor;
        ip::tcp::endpoint e{ip::make_address_v4("127.0.0.1"), 5432};
        ip::tcp::socket s{ex};
        co_await s.async_connect(e, boost::asio::use_awaitable);

        std::vector<boost::asio::const_buffer> buffers;
        i32 length{};
        auto version = startup_message{}.the_protocol_version_number;
        version = std::byteswap(version);
        buffers.emplace_back(&length, sizeof(length));
        buffers.emplace_back(&version, sizeof(version));
        for (auto &&[k,v] : params) {
            if (k == "user") {
                buffers.emplace_back(k.data(), k.size() + 1);
                buffers.emplace_back(v.data(), v.size() + 1);
            }
        }
        i8 null{};
        buffers.emplace_back(&null, sizeof(null));
        for (auto &&b : buffers) {
            length += b.size();
        }
        length = std::byteswap(length);

        co_await s.async_send(buffers, boost::asio::use_awaitable);

        auto msg = co_await auth<
            //error_response,
            authentication_kerberos_v5,
            authentication_cleartext_password,
            authentication_md5_password,
            authentication_gss,
            authentication_sspi,
            authentication_sasl
        >(s);

        int a = 5;
        a++;
    }
    template <typename ... Types>
    task<std::variant<Types...>> auth(ip::tcp::socket &s) {
        auto m = co_await get_message(s);
        std::variant<Types...> ret;
        auto f = [&](auto t) {
            if (t.type != m.h.type) {
                return false;
            }
            auto &a = m.get<authentication_ok>();
            if (t.auth_type != std::byteswap(a.auth_type)) {
                return false;
            }
            ret = t;

            auto &a2 = m.get<authentication_sasl>();
            auto vec = a2.authentication_mechanism();

            return true;
        };
        if (!(f(Types{}) || ... || false)) {
            throw std::runtime_error{"unexpected message: "s + (char)m.h.type};
        }
        co_return ret;
    }
    task<message> get_message(ip::tcp::socket &s) {
        message m;
        co_await s.async_receive(boost::asio::buffer(&m.h, sizeof(m.h)), boost::asio::use_awaitable);
        m.h.length = std::byteswap(m.h.length);
        m.data.resize(m.h.length - sizeof(m.h.length));
        co_await s.async_receive(boost::asio::buffer(m.data.data(), m.data.size()), boost::asio::use_awaitable);
        error_response e{};
        if (m.h.type == e.type) {
            throw std::runtime_error{"error: "};
        }
        co_return m;
    }
};

struct base64 {
    using u8 = unsigned char;
    struct b64 {
        u8 b2 : 2;
        u8 a  : 6;
        u8 c1 : 4;
        u8 b1 : 4;
        u8 d  : 6;
        u8 c2 : 2;

        template <auto N> constexpr void extract(auto &s) {
            // url safe -_
            constexpr auto alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"sv;

            s += alph[a];
            s += alph[b1 + (b2 << 4)];
            if constexpr (N > 2)
            s += alph[(c1 << 2) + c2];
            else
            s += '=';
            if constexpr (N > 3)
            s += alph[d];
            else
            s += '=';
        }
        template <auto N> constexpr void assign(auto data) {
            constexpr u8 alph[] = {
                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62,
                 255, 255, 255, 63,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  255, 255, 255, 254, 255, 255, 255, 0,
                 1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,  22,
                 23,  24,  25,  255, 255, 255, 255, 255, 255, 26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,
                 39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  255, 255, 255, 255, 255};

            b2 = alph[data[1]] >> 4;
            a  = alph[data[0]];
            if constexpr (N > 2)
            c1 = alph[data[2]] >> 2;
            b1 = alph[data[1]];
            if constexpr (N > 3)
            d  = alph[data[3]];
            if constexpr (N > 2)
            c2 = alph[data[2]];
        }
    };
    static_assert(sizeof(b64) == 3);
    static inline constexpr auto b64size = 3;
    static inline constexpr auto b64chars = 4;

    static auto encode(auto &&data) {
        auto sz = data.size();
        std::string s;
        if (sz == 0) {
            return s;
        }
        s.reserve((sz / b64size + (sz % b64size ? 1 : 0)) * b64chars);
        auto until = sz - sz % b64size;
        auto p = (b64*)data.data();
        int i{};
        for (; i < until; i += b64size) {
            p++->extract<b64chars>(s);
        }
        auto tail = sz - i;
        if (tail == 1) {
            p->extract<b64chars-2>(s);
        } else if (tail == 2) {
            p->extract<b64chars-1>(s);
        }
        return s;
    }
    static auto decode(auto &&data) {
        auto sz = data.size();
        if (sz % b64chars) {
            throw std::runtime_error{"bad base64: incorrect length"};
        }
        std::string s;
        if (sz == 0) {
            return s;
        }
        s.resize(sz / b64chars * b64size);
        sz -= data[sz-1] == '=';
        sz -= data[sz-1] == '=';
        auto p = (b64*)s.data();
        int i{};
        for (; i < sz; i += b64chars) {
            p++->assign<b64chars>(&data[i]);
        }
        auto tail = i - sz;
        if (tail == 2) {
            p->assign<b64chars-2>(&data[i]);
        } else if (tail == 1) {
            p->assign<b64chars-1>(&data[i]);
        }
        s.resize(s.size() - tail);
        return s;
    }
};
inline std::string operator""_b64e(const char *s, size_t len) {
    return base64::encode(std::string_view{s,len});
}
inline std::string operator""_b64d(const char *s, size_t len) {
    return base64::decode(std::string_view{s,len});
}

int main(int argc, char *argv[]) {
    auto x1 = base64::encode("Many hands make light work."s);
    auto x2 = base64::encode("Many hands make light work.."s);
    auto x3 = base64::encode("Many hands make light work..."s);
    auto x4 = "Many hands make light work."_b64e;

    auto y1 = base64::decode(x1);
    auto y2 = base64::decode(x2);
    auto y3 = base64::decode(x3);
    auto y4 = "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu"_b64d;

    boost::asio::io_context ctx;
    pg_connection conn(ctx, "host=localhost user=aspia_public_router password=aspia_public_router dbname=aspia_public_router");
    ctx.run();
    return 0;
}
