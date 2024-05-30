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

int main(int argc, char *argv[]) {
    boost::asio::io_context ctx;
    pg_connection conn(ctx, "host=localhost user=aspia_public_router password=aspia_public_router dbname=aspia_public_router");
    ctx.run();
    return 0;
}
