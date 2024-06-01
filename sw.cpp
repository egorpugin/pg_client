void build(Solution &s) {
    auto &pg_message_formats_parser = s.addExecutable("pg_message_formats_parser");
    {
        auto &t = pg_message_formats_parser;
        t += cpp26;
        t.PackageDefinitions = true;
        t += "src/pg_message_formats_parser.cpp";

        t += "pub.egorpugin.primitives.http"_dep;
        t += "pub.egorpugin.primitives.xml"_dep;
        t += "pub.egorpugin.primitives.templates2"_dep;
        t += "pub.egorpugin.primitives.sw.main"_dep;
        t += "org.sw.demo.zeux.pugixml"_dep;
        t += "org.sw.demo.htacg.tidy_html5"_dep;
        t += "org.sw.demo.boost.pfr"_dep;
    }

    auto &pg_client = s.addExecutable("pg_client");
    {
        auto &t = pg_client;
        t += cpp26;
        t.PackageDefinitions = true;
        t += "src/main.cpp";

        /*t.addCommand()
            << cmd::prog(pg_message_formats_parser)
            << cmd::wdir(t.BinaryDir)
            << cmd::end()
            << cmd::out("pg_messages.h")
            ;*/

        //t += router_relay;
        t += "pub.egorpugin.crypto"_dep;
        t += "pub.egorpugin.primitives.templates2"_dep;
        t.Public += "org.sw.demo.boost.asio"_dep;
        t += "pub.egorpugin.primitives.sw.main"_dep;
    }
}
