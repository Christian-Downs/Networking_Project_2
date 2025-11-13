
/*
 * FTP Server Functional Test Suite (Standalone, CLI args respected)
 * -----------------------------------------------------------------
 * Build (Ubuntu):
 *   g++ -std=c++20 -Wall -Wextra -O2 ftp_tests_args_fix.cpp -o ftp_tests
 *
 * Run:
 *   ./ftp_tests 192.168.1.50 2121
 *   # or env fallback:
 *   FTP_HOST=127.0.0.1 FTP_PORT=2121 ./ftp_tests
 */

#include <cassert>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
using socklen_t = int;
static bool winsock_init_done = false;
void winsock_init()
{
    if (!winsock_init_done)
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        {
            std::cerr << "WSAStartup failed\n";
            std::exit(1);
        }
        winsock_init_done = true;
    }
}
int close_socket(SOCKET s) { return closesocket(s); }
using socket_t = SOCKET;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
int close_socket(int s) { return ::close(s); }
using socket_t = int;
#endif

#define SLEEPTIME 5000

// ---- Globals for host/port configured in main() ----
static std::string g_host = "127.0.0.1";
static int g_port = 2121;


std::string envOr(const char *key, const std::string &def)
{
    const char *v = std::getenv(key);
    return v ? std::string(v) : def;
}
const std::string &getHost() { return g_host; }
int getPort() { return g_port; }

// --------- Network IO helpers ---------
socket_t connectTo(const std::string &host, int port)
{
#ifdef _WIN32
    winsock_init();
#endif
    socket_t s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        throw std::runtime_error("socket() failed");
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0)
    {
        // Try DNS
        hostent *he = gethostbyname(host.c_str());
        if (!he)
        {
            close_socket(s);
            throw std::runtime_error("DNS lookup failed for host: " + host);
        }
        std::memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    if (connect(s, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close_socket(s);
        throw std::runtime_error("connect() failed to " + host + ":" + std::to_string(port));
    }
    return s;
}

bool sendAll(socket_t sock, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len)
    {
#ifdef _WIN32
        int n = ::send(sock, buf + sent, (int)(len - sent), 0);
#else
        ssize_t n = ::send(sock, buf + sent, len - sent, 0);
#endif
        if (n <= 0)
            return false;
        sent += (size_t)n;
    }
    return true;
}

bool sendLine(socket_t sock, const std::string &line)
{
    std::string msg = line;
    if (msg.size() < 2 || msg.substr(msg.size() - 2) != "\r\n")
    {
        msg += "\r\n";
    }
    std::cout << "SENDING: " << msg << std::endl;
    return sendAll(sock, msg.c_str(), msg.size());
}

std::optional<std::string> recvLine(socket_t sock, int timeout_ms = SLEEPTIME)
{
#ifdef _WIN32
    winsock_init();
#endif
    std::string line;
    char ch;
    auto start = std::chrono::steady_clock::now();
    for (;;)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        int sel = select((int)sock + 1, &rfds, nullptr, nullptr, &tv);
        if (sel == 0)
        {
            return std::nullopt; // timeout
        }
        else if (sel < 0)
        {
            return std::nullopt;
        }
        int n = recv(sock, &ch, 1, 0);
        if (n <= 0)
        {
            if (line.empty())
                return std::nullopt;
            break;
        }
        if (ch == '\n')
        {
            break;
        }
        if (ch != '\r')
            line.push_back(ch);
        if (line.size() > 8192)
            break;
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count() > timeout_ms * 2)
            break;
    }
    return line;
}

std::string readAll(socket_t sock, int timeout_ms = SLEEPTIME)
{
    std::string out;
    char buf[4096];
    for (;;)
    {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        int sel = select((int)sock + 1, &rfds, nullptr, nullptr, &tv);
        if (sel <= 0)
            break;
        int n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0)
            break;
        out.append(buf, buf + n);
        if (out.size() > (1 << 26))
            break; // 64MB safety
    }
    return out;
}

// --------- Reply parsing ---------
struct Reply
{
    int code = -1;
    std::string line;
};
Reply readReply(socket_t sock, int timeout_ms = SLEEPTIME)
{
    auto opt = recvLine(sock, timeout_ms);
    if (!opt)
        throw std::runtime_error("Timed out waiting for reply");
    std::string line = *opt;
    if (line.size() < 3 || !std::isdigit(line[0]) || !std::isdigit(line[1]) || !std::isdigit(line[2]))
    {
        throw std::runtime_error("Malformed reply: " + line);
    }
    int code = std::atoi(line.substr(0, 3).c_str());
    std::cout << code << line << std::endl;
    return Reply{code, line};
}

// --------- PASV parser ---------
struct PasvEndpoint
{
    std::string ip;
    int port = 0;
};
PasvEndpoint parse227(const std::string &line)
{
    auto lp = line.find('(');
    auto rp = line.find(')', lp == std::string::npos ? 0 : lp + 1);
    if (lp == std::string::npos || rp == std::string::npos)
        throw std::runtime_error("Bad 227 format: " + line);
    auto inside = line.substr(lp + 1, rp - lp - 1);
    int h1, h2, h3, h4, p1, p2;
    char c;
    std::stringstream ss(inside);
    if (!(ss >> h1 >> c >> h2 >> c >> h3 >> c >> h4 >> c >> p1 >> c >> p2))
    {
        throw std::runtime_error("Bad 227 tuple: " + inside);
    }
    std::stringstream ip;
    ip << h1 << "." << h2 << "." << h3 << "." << h4;
    int port = p1 * 256 + p2;
    return PasvEndpoint{ip.str(), port};
}

// --------- Tiny test framework ---------
struct TestResult
{
    std::string name;
    bool pass;
    std::string details;
};
static std::vector<TestResult> g_results;

#define TEST(name)                                         \
    void name();                                           \
    struct name##_registrar                                \
    {                                                      \
        name##_registrar() { register_test(#name, name); } \
    } name##_registrar_instance;                           \
    void name()

using test_fn = void (*)();
static std::vector<std::pair<std::string, test_fn>> g_tests;

void register_test(const std::string &name, test_fn fn) { g_tests.emplace_back(name, fn); }
void record_result(const std::string &name, bool pass, const std::string &details = "") { g_results.push_back({name, pass, details}); }

// --------- Common login / fresh session helper ---------
struct Session
{
    socket_t ctrl = -1;
    std::string host;
    int port;
};

Session openSession(const std::string &host, int port)
{
    Session s;
    s.ctrl = connectTo(host, port);
    s.host = host;
    s.port = port;
    auto r = readReply(s.ctrl); // banner
    if (r.code < 200 || r.code >= 400)
        throw std::runtime_error("Unexpected banner: " + r.line);
    return s;
}
void closeSession(Session &s)
{
    if (s.ctrl >= 0)
    {
        close_socket(s.ctrl);
        s.ctrl = -1;
    }
}
void loginAnonymous(Session &s)
{
    if (!sendLine(s.ctrl, "USER anonymous"))
        throw std::runtime_error("send USER failed");
    auto r = readReply(s.ctrl);
    if (r.code != 230)
        throw std::runtime_error("Expected 230 after USER anonymous, got: " + r.line);
}
PasvEndpoint pasv(Session &s, int expectedCode = 227)
{
    if (!sendLine(s.ctrl, "PASV"))
        throw std::runtime_error("send PASV failed");
    auto r = readReply(s.ctrl);
    if (r.code != expectedCode)
        throw std::runtime_error("PASV expected 227, got: " + r.line);
    return parse227(r.line);
}

// -------------- TESTS --------------
TEST(test_USER_accept_anonymous)
{
    try
    {
        auto sess = openSession(getHost(), getPort());
        bool ok1 = sendLine(sess.ctrl, "USER anonymous");
        auto r = readReply(sess.ctrl);
        bool pass = ok1 && (r.code == 230);
        record_result(__func__, pass, r.line);
        closeSession(sess);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_USER_reject_non_anonymous)
{
    try
    {
        auto sess = openSession(getHost(), getPort());
        bool ok1 = sendLine(sess.ctrl, "USER bob");
        auto r = readReply(sess.ctrl);
        bool pass = ok1 && (r.code == 530);
        record_result(__func__, pass, r.line);
        closeSession(sess);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_PWD_root)
{
    try
    {
        auto sess = openSession(getHost(), getPort());
        loginAnonymous(sess);
        bool ok = sendLine(sess.ctrl, "PWD");
        auto r = readReply(sess.ctrl);
        bool pass = ok && (r.code == 257) && (r.line.find("\"/\"") != std::string::npos);
        record_result(__func__, pass, r.line);
        closeSession(sess);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_CWD_into_valid_then_PWD)
{
    try
    {
        auto sess = openSession(getHost(), getPort());
        loginAnonymous(sess);
        bool ok1 = sendLine(sess.ctrl, "CWD comp.security");
        auto r = readReply(sess.ctrl);
        bool ok_status = (r.code == 250) || (r.code == 550);
        bool ok2 = sendLine(sess.ctrl, "PWD");
        auto r2 = readReply(sess.ctrl);
        bool pass = ok1 && ok2 && ok_status && (r2.code == 257);
        record_result(__func__, pass, r.line + " | " + r2.line);
        closeSession(sess);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_CWD_block_traversal)
{
    try
    {
        auto sess = openSession(getHost(), getPort());
        loginAnonymous(sess);
        bool ok1 = sendLine(sess.ctrl, "CWD ../..");
        auto r = readReply(sess.ctrl);
        bool pass = ok1 && (r.code == 550);
        record_result(__func__, pass, r.line);
        closeSession(sess);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_CDUP_behavior)
{
    try
    {
        auto sess = openSession(getHost(), getPort());
        loginAnonymous(sess);
        (void)sendLine(sess.ctrl, "CWD comp.security");
        auto _ = readReply(sess.ctrl); // ignore if 550
        bool ok = sendLine(sess.ctrl, "CDUP");
        auto r = readReply(sess.ctrl);
        bool pass = ok && ((r.code == 200) || (r.code == 550));
        record_result(__func__, pass, r.line);
        closeSession(sess);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_QUIT_closes)
{
    try
    {
        auto sess = openSession(getHost(), getPort());
        loginAnonymous(sess);
        bool ok = sendLine(sess.ctrl, "QUIT");
        auto r = readReply(sess.ctrl);
        bool pass = ok && (r.code == 221);
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        auto next = recvLine(sess.ctrl, 250);
        bool closed = !next.has_value();
        record_result(__func__, pass && closed, r.line);
        closeSession(sess);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_PASV_well_formed_and_connectable)
{
    try
    {
        auto sess = openSession(getHost(), getPort());
        loginAnonymous(sess);
        auto ep = pasv(sess);
        socket_t data = connectTo(ep.ip, ep.port);
        close_socket(data);
        record_result(__func__, true, "227 -> " + ep.ip + ":" + std::to_string(ep.port));
        closeSession(sess);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_LIST_requires_PASV)
{
    try
    {
        auto sess = openSession(getHost(), getPort());
        loginAnonymous(sess);
        bool ok = sendLine(sess.ctrl, "LIST");
        auto r = readReply(sess.ctrl);
        bool pass = ok && ((r.code == 425) || (r.code == 503));
        record_result(__func__, pass, r.line);
        closeSession(sess);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_LIST_root_happy_path)
{
    try
    {
        std::cout<<"TEST LIST ROOT HAPPY PATH" << std::endl;
        auto sess = openSession(getHost(), getPort());
        loginAnonymous(sess);
        auto ep = pasv(sess);
        socket_t data = connectTo(ep.ip, ep.port);
        bool ok = sendLine(sess.ctrl, "LIST");
        auto pre = readReply(sess.ctrl);
        bool ok150 = ok && (pre.code == 150 || pre.code == 125);
        auto listing = readAll(data);
        close_socket(data);
        auto post = readReply(sess.ctrl);
        bool ok226 = (post.code == 226) || (post.code == 250);
        bool pass = ok150 && ok226 && !listing.empty();
        record_result(__func__, pass, "bytes=" + std::to_string(listing.size()) + " pre=" + pre.line + " post=" + post.line);
        closeSession(sess);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_LIST_traversal_blocked)
{
    try
    {
        auto sess = openSession(getHost(), getPort());
        loginAnonymous(sess);
        auto ep = pasv(sess);
        socket_t data = connectTo(ep.ip, ep.port);
        bool ok = sendLine(sess.ctrl, "LIST ../");
        auto r = readReply(sess.ctrl);
        bool pass = ok && ((r.code == 550) || (r.code == 450));
        close_socket(data);
        record_result(__func__, pass, r.line);
        closeSession(sess);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_RETR_requires_PASV)
{
    try
    {
        auto sess = openSession(getHost(), getPort());
        loginAnonymous(sess);
        bool ok = sendLine(sess.ctrl, "RETR missing.txt");
        auto r = readReply(sess.ctrl);
        bool pass = ok && ((r.code == 425) || (r.code == 503));
        record_result(__func__, pass, r.line);
        closeSession(sess);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_RETR_missing_after_PASV)
{
    try
    {
        auto sess = openSession(getHost(), getPort());
        loginAnonymous(sess);
        auto ep = pasv(sess);
        socket_t data = connectTo(ep.ip, ep.port);
        bool ok = sendLine(sess.ctrl, "RETR __definitely_missing__.txt");
        auto r = readReply(sess.ctrl);
        bool pass = ok && ((r.code == 550) || (r.code == 450) || (r.code == 553));
        close_socket(data);
        record_result(__func__, pass, r.line);
        closeSession(sess);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

// ---- Distributed/P2P (optional) ----
bool peer_tests_enabled() { return envOr("ENABLE_PEER_TESTS", "0") == "1"; }
TEST(test_DIST_LIST_unified_index)
{
    if (!peer_tests_enabled())
    {
        record_result(__func__, true, "SKIPPED (ENABLE_PEER_TESTS!=1)");
        return;
    }
    try
    {
        auto sess = openSession(getHost(), getPort());
        loginAnonymous(sess);
        auto ep = pasv(sess);
        socket_t data = connectTo(ep.ip, ep.port);
        bool ok = sendLine(sess.ctrl, "LIST");
        auto pre = readReply(sess.ctrl);
        auto listing = readAll(data);
        close_socket(data);
        auto post = readReply(sess.ctrl);
        bool pass = ok && (pre.code == 150 || pre.code == 125) && (post.code == 226 || post.code == 250);
        record_result(__func__, pass, "bytes=" + std::to_string(listing.size()));
        closeSession(sess);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_PASV_supersedes_previous)
{
    try
    {
        auto s = openSession(getHost(), getPort());
        loginAnonymous(s);
        auto ep1 = pasv(s); // First PASV
        auto ep2 = pasv(s); // Second PASV should replace the first
        // Second should be connectable
        socket_t d2 = connectTo(ep2.ip, ep2.port);
        close_socket(d2);
        // Old data port should NOT be connectable anymore (most servers close/replace it)
        bool oldClosed = false;
        try
        {
            socket_t d1 = connectTo(ep1.ip, ep1.port);
            close_socket(d1);
        }
        catch (...)
        {
            oldClosed = true;
        }
        record_result(__func__, oldClosed, oldClosed ? "old PASV closed" : "old PASV still open");
        closeSession(s);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_LIST_without_connect_after_PASV)
{
    // Client issues PASV but never connects data socket; then sends LIST.
    // Server should fail the transfer cleanly (425/450) and remain responsive afterward. (One-shot data model)
    try
    {
        auto s = openSession(getHost(), getPort());
        loginAnonymous(s);
        (void)pasv(s); // don't connect to it
        bool ok = sendLine(s.ctrl, "LIST");
        auto r = readReply(s.ctrl);
        bool pass = ok && (r.code == 425 || r.code == 450);
        // Still responsive?
        bool ok2 = sendLine(s.ctrl, "PWD");
        auto r2 = readReply(s.ctrl);
        pass = pass && ok2 && (r2.code == 257);
        record_result(__func__, pass, r.line + " | " + r2.line);
        closeSession(s);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_LIST_then_requires_new_PASV_again)
{
    // After a successful LIST, the server must tear down the PASV listener; a second LIST should require a new PASV.
    try
    {
        auto s = openSession(getHost(), getPort());
        loginAnonymous(s);
        auto ep = pasv(s);
        socket_t d = connectTo(ep.ip, ep.port);
        (void)sendLine(s.ctrl, "LIST");
        auto pre = readReply(s.ctrl);
        auto listing = readAll(d);
        close_socket(d);
        auto post = readReply(s.ctrl);
        bool firstOK = (pre.code == 150 || pre.code == 125) && (post.code == 226 || post.code == 250) && !listing.empty();

        // Try LIST again without a new PASV → should fail (425/503)
        bool ok = sendLine(s.ctrl, "LIST");
        auto r = readReply(s.ctrl);
        bool secondBlocked = ok && (r.code == 425 || r.code == 503);
        record_result(__func__, firstOK && secondBlocked, r.line);
        closeSession(s);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_LIST_absolute_path_blocked)
{
    // Server must be jailed to db/; absolute paths like "/" or "/etc" should be rejected.
    try
    {
        auto s = openSession(getHost(), getPort());
        loginAnonymous(s);
        auto ep = pasv(s);
        socket_t d = connectTo(ep.ip, ep.port);
        bool ok = sendLine(s.ctrl, "LIST /");
        auto r = readReply(s.ctrl);
        bool pass = ok && (r.code == 550 || r.code == 450 || r.code == 553);
        close_socket(d);
        record_result(__func__, pass, r.line);
        closeSession(s);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_CWD_absolute_path_blocked)
{
    // CWD "/" (or absolute) must be blocked by the jail.
    try
    {
        auto s = openSession(getHost(), getPort());
        loginAnonymous(s);
        bool ok = sendLine(s.ctrl, "CWD /");
        auto r = readReply(s.ctrl);
        bool pass = ok && (r.code == 550 || r.code == 501 || r.code == 504);
        record_result(__func__, pass, r.line);
        closeSession(s);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_LIST_dot_directory_ok)
{
    // "LIST ./" should be allowed and list current dir (normalization).
    try
    {
        auto s = openSession(getHost(), getPort());
        loginAnonymous(s);
        auto ep = pasv(s);
        socket_t d = connectTo(ep.ip, ep.port);
        bool ok = sendLine(s.ctrl, "LIST ./");
        auto pre = readReply(s.ctrl);
        auto data = readAll(d);
        close_socket(d);
        auto post = readReply(s.ctrl);
        bool pass = ok && (pre.code == 150 || pre.code == 125) && (post.code == 226 || post.code == 250);
        record_result(__func__, pass && !data.empty(), "bytes=" + std::to_string(data.size()));
        closeSession(s);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_RETR_directory_should_fail)
{
    // RETR on a directory must fail (not a regular file). Jail + semantics.
    try
    {
        auto s = openSession(getHost(), getPort());
        loginAnonymous(s);
        auto ep = pasv(s);
        socket_t d = connectTo(ep.ip, ep.port);
        bool ok = sendLine(s.ctrl, "RETR ."); // common dir alias
        auto r = readReply(s.ctrl);
        bool pass = ok && (r.code == 550 || r.code == 451 || r.code == 553);
        close_socket(d);
        record_result(__func__, pass, r.line);
        closeSession(s);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_PASV_ip_changes_with_bind_interface)
{
    // Basic sanity: returned IP must not be "0.0.0.0" nor the bogus 127.127.127.127 seen earlier mis-parses.
    try
    {
        auto s = openSession(getHost(), getPort());
        loginAnonymous(s);
        auto ep = pasv(s);
        bool ok = (ep.ip != "0.0.0.0") && (ep.ip != "127.127.127.127");
        record_result(__func__, ok, "ip=" + ep.ip);
        closeSession(s);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_two_clients_isolated_pasv)
{
    // Two sessions issue PASV simultaneously; their endpoints must be independently connectable (no cross-talk).
    try
    {
        auto a = openSession(getHost(), getPort());
        auto b = openSession(getHost(), getPort());
        loginAnonymous(a);
        loginAnonymous(b);

        auto epA = pasv(a);
        auto epB = pasv(b);

        socket_t dA = connectTo(epA.ip, epA.port);
        socket_t dB = connectTo(epB.ip, epB.port);

        bool ok = (dA >= 0 && dB >= 0);
        close_socket(dA);
        close_socket(dB);
        closeSession(a);
        closeSession(b);
        record_result(__func__, ok, "A=" + epA.ip + ":" + std::to_string(epA.port) + " B=" + epB.ip + ":" + std::to_string(epB.port));
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

TEST(test_LIST_path_with_double_slash_normalizes)
{
    // "LIST //./" should normalize to current dir or be treated safely, not escape jail.
    try
    {
        auto s = openSession(getHost(), getPort());
        loginAnonymous(s);
        auto ep = pasv(s);
        socket_t d = connectTo(ep.ip, ep.port);
        bool ok = sendLine(s.ctrl, "LIST //./");
        auto pre = readReply(s.ctrl);
        auto data = readAll(d);
        close_socket(d);
        auto post = readReply(s.ctrl);
        bool pass = ok && (pre.code == 150 || pre.code == 125) && (post.code == 226 || post.code == 250);
        record_result(__func__, pass && !data.empty(), "bytes=" + std::to_string(data.size()));
        closeSession(s);
    }
    catch (const std::exception &e)
    {
        record_result(__func__, false, e.what());
    }
}

// -------------- MAIN --------------
int main(int argc, char **argv)
{
    // Resolve host/port from args or env, then store globally
    g_host = (argc > 1) ? argv[1] : envOr("FTP_HOST", g_host);
    std::string portStr = (argc > 2) ? argv[2] : envOr("FTP_PORT", std::to_string(g_port));
    try
    {
        g_port = std::stoi(portStr);
    }
    catch (...)
    {
        std::cerr << "Invalid port: " << portStr << "\n";
        return 2;
    }

    std::cout << "Target: " << g_host << ":" << g_port << "\n";

    // Run all tests
    for (auto &[name, fn] : g_tests)
    {
        try
        {
            fn();
        }
        catch (const std::exception &e)
        {
            record_result(name, false, std::string("Unhandled exception: ") + e.what());
        }
        catch (...)
        {
            record_result(name, false, "Unhandled non-std exception");
        }
    }

    // Report
    int passed = 0, failed = 0;
    std::cout << "==== FTP TEST RESULTS ====\n";
    for (const auto &r : g_results)
    {
        std::cout << (r.pass ? "[PASS] " : "[FAIL] ") << r.name;
        if (!r.details.empty())
            std::cout << " -- " << r.details;
        std::cout << "\n";
        if (r.pass)
            ++passed;
        else
            ++failed;
    }
    std::cout << "==========================\n";
    std::cout << "TOTAL: " << (passed + failed) << ", PASS: " << passed << ", FAIL: " << failed << "\n";
    return failed == 0 ? 0 : 1;
}
