#include <boost/asio.hpp>
#include <primitives/sw/main.h>
#include <primitives/templates2/base64.h>
#include <primitives/templates2/overload.h>
#include <hmac.h>

#include <string>
#include <variant>
#include <stdint.h>

namespace ip = boost::asio::ip;

template <typename T = void>
using task = boost::asio::awaitable<T>;

#include "pg_messages.h"

struct pg_connection {
    struct view_base {
        const i8 *d;
        size_t sz;

        view_base(auto &d) : d{(const i8 *)d.data()}, sz{d.size()} {}

        auto data() const {return d;}
        auto size() const {return sz;}
    };
    struct zero_byte : view_base {};
    struct no_zero_byte : view_base {};

    std::map<std::string, std::string> params;
    backend_key_data key_data;

    pg_connection(boost::asio::io_context &ctx, auto &&connstr) {
        auto vec = split_string(connstr, " ");
        for (auto &&v : vec) {
            auto p = v.find('=');
            if (p == -1) {
                continue;
            }
            params[v.substr(0,p)] = v.substr(p+1);
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
        co_await auth(s);

        while (1) {
            auto m = co_await get_message(s);
            if (backend_key_data{}.type == m.h.type) {
                key_data = m.get<backend_key_data>();
            }
            if (ready_for_query{}.type == m.h.type) {
                break;
            }
        }

        int a = 5;
        a++;
    }
    task<> auth(ip::tcp::socket &s) {
        auto m = co_await get_message<authentication_ok>(s);
        auto &a = m.get<authentication_ok>();
        switch (std::byteswap(a.auth_type)) {
        case authentication_ok{}.auth_type: {
            break;
        }
        case authentication_sasl{}.auth_type: {
            // https://www.rfc-editor.org/rfc/rfc5802
            auto &a = m.get<authentication_sasl>();
            auto type = a.authentication_mechanism().at(0);
            if (type != "SCRAM-SHA-256"sv) {
                throw std::runtime_error{"unknown sasl: "s};
            }
            std::string r;
            r.resize(18, '0');
            std::string str;
            // no channel binding
            auto channel = "n,,"s;
            // pg ignores user and libpq sends empty username
            // pg (and libpq) uses empty user (n=) because username is already sent
            auto user_data = "n=,r=" + base64::encode(r);
            str += channel + user_data;

            int len = str.size();
            len = std::byteswap(len);
            co_await send_message<sasl_initial_response>(s, zero_byte{type}, len, no_zero_byte{str});
            auto sc = co_await get_auth_message<authentication_sasl_continue>(s);
            auto &asc = sc.get<authentication_sasl_continue>();
            auto sd = asc.server_data();
            std::map<std::string, std::string> params;
            auto vec = split_string(std::string{sd}, ",");
            for (auto &&v : vec) {
                auto p = v.find('=');
                if (p == -1) {
                    continue;
                }
                params[v.substr(0,p)] = v.substr(p+1);
            }

            using namespace crypto;
            auto salt = base64::decode(params.at("s"));
            auto Hi = [](auto &&pass, auto &&salt, auto &&i) {
                int i1{1};
                i1 = std::byteswap(i1);
                salt.resize(salt.size() + 4);
                memcpy(salt.data() + salt.size() - 4, &i1, 4);
                auto u = hmac<sha256>(pass, salt);
                --i;
                auto hi = u;
                auto len = hi.size();
                while (i--) {
                    u = hmac<sha256>(pass, u);
                    for (int i = 0; i < len; ++i) {
                        hi[i] ^= u[i];
                    }
                }
                return hi;
            };
            auto salted_password = Hi(this->params["password"], salt, std::stoi(std::string{params.at("i")}));
            auto client_key = hmac<sha256>(salted_password, "Client Key"sv);
            auto server_key = hmac<sha256>(salted_password, "Server Key"sv);
            sha256 sha;
            sha.update(client_key);
            auto stored_key = sha.digest();
            auto new_client = "c=" + base64::encode(channel) + ",r=" + params.at("r");
            auto auth_message = user_data + ","s + std::string{sd} + ","s + new_client;
            auto client_signature = hmac<sha256>(stored_key, auth_message);
            auto server_signature = hmac<sha256>(server_key, auth_message);
            auto client_proof = client_key;
            len = client_proof.size();
            for (int i = 0; i < len; ++i) {
                client_proof[i] ^= client_signature[i];
            }
            new_client += ",p=" + base64::encode(client_proof);

            co_await send_message<sasl_response>(s, no_zero_byte{new_client});
            auto scf = co_await get_auth_message<authentication_sasl_final>(s);
            auto &asf = scf.get<authentication_sasl_final>();
            sd = asf.server_data();
            vec = split_string(std::string{sd}, ",");
            for (auto &&v : vec) {
                auto p = v.find('=');
                if (p == -1) {
                    continue;
                }
                params[v.substr(0,p)] = v.substr(p+1);
            }
            len = server_signature.size();
            auto verifier = base64::decode(params.at("v"));
            if (verifier.size() != len || memcmp(server_signature.data(), verifier.data(), len) != 0) {
                throw std::runtime_error{"bad server signature"};
            }
            co_await get_auth_message<authentication_ok>(s);
            break;
        }
        default:
            throw std::runtime_error{"unknown auth: "s};
        }
    }
    template <typename Type>
    task<> send_message(ip::tcp::socket &s, Type message) {
        message.length = sizeof(message) - 1;
        message.length = std::byteswap(message.length);
        co_await s.async_send(boost::asio::buffer(&message, sizeof(message)), boost::asio::use_awaitable);
    }
    template <typename Type>
    task<> send_message(ip::tcp::socket &s, auto && ... args) {
        i8 zero{};
        Type message{};
        std::vector<boost::asio::const_buffer> buffers;
        buffers.emplace_back(&message, sizeof(message));
        auto f = overload([&](const no_zero_byte &v) {
            buffers.emplace_back(v.data(), v.size());
        },[&](const zero_byte &v) {
            buffers.emplace_back(v.data(), v.size());
            buffers.emplace_back(&zero, sizeof(zero));
        },[&](const auto &v) {
            buffers.emplace_back(&v, sizeof(v));
        });
        (f(args),...);
        for (auto &&b : buffers) {
            message.length += b.size();
        }
        if constexpr (requires {message.type;}) {
            --message.length;
        }
        message.length = std::byteswap(message.length);
        co_await s.async_send(buffers, boost::asio::use_awaitable);
    }
    template <typename Type>
    task<message> get_auth_message(ip::tcp::socket &s) {
        auto m = co_await get_message<Type>(s);
        auto &a = m.get<Type>();
        if (Type{}.auth_type != std::byteswap(a.auth_type)) {
            throw std::runtime_error{"unexpected auth message: "s + (char)m.h.type};
        }
        co_return m;
    }
    template <typename Type>
    task<message> get_message(ip::tcp::socket &s) {
        auto m = co_await get_message(s);
        auto &a = m.get<Type>();
        if (Type{}.type != m.h.type) {
            throw std::runtime_error{"unexpected message: "s + (char)m.h.type};
        }
        co_return m;
    }
    task<message> get_message(ip::tcp::socket &s) {
        message m;
        co_await s.async_receive(boost::asio::buffer(&m.h, sizeof(m.h)), boost::asio::use_awaitable);
        m.h.length = std::byteswap(m.h.length);
        m.data.resize(m.h.length + 1);
        memcpy(m.data.data(), &m.h, sizeof(header));
        co_await s.async_receive(boost::asio::buffer(m.data.data() + sizeof(header), m.h.length - sizeof(m.h.length)), boost::asio::use_awaitable);
        error_response e{};
        if (m.h.type == e.type) {
            auto e = m.get<error_response>().error();
            std::cerr << e.format() << "\n";
            throw std::runtime_error{std::format("error: {}"s, e.format())};
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
