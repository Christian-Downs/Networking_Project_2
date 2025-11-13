
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
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define SLEEPTIME 5000

using namespace std;

using socket_t = int;
struct Session
{
    socket_t ctrl = -1;
    std::string host;
    int port;
};

std::optional<std::string> recvLine(socket_t sock, int timeout_ms = SLEEPTIME)
{

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

socket_t connectTo(const std::string &host, int port)
{
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
            close(s);
            throw std::runtime_error("DNS lookup failed for host: " + host);
        }
        std::memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    if (connect(s, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(s);
        throw std::runtime_error("connect() failed to " + host + ":" + std::to_string(port));
    }
    return s;
}
struct Reply
{
    int code = -1;
    std::string line;
};
Reply readReply(socket_t sock, int timeout_ms = 5000)
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
        close(s.ctrl);
        s.ctrl = -1;
    }
}

bool sendAll(socket_t sock, const char *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len)
    {

        ssize_t n = ::send(sock, buf + sent, len - sent, 0);
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

void loginAnonymous(Session &s)
{
    if (!sendLine(s.ctrl, "USER anonymous"))
        throw std::runtime_error("send USER failed");
    auto r = readReply(s.ctrl);
    if (r.code != 230)
        throw std::runtime_error("Expected 230 after USER anonymous, got: " + r.line);
}
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

PasvEndpoint pasv(Session &s, int expectedCode = 227)
{
    if (!sendLine(s.ctrl, "PASV"))
        throw std::runtime_error("send PASV failed");
    auto r = readReply(s.ctrl);
    if (r.code != expectedCode)
        throw std::runtime_error("PASV expected 227, got: " + r.line);
    return parse227(r.line);
}

void peer_scanner(string interval, string subnet, string port)
{

    int sleep_interval = stoi(interval);

    int sockfd, numbytes;
    char buf[5000];
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    string sub = subnet;
    string startingIp = subnet.substr(0, subnet.rfind("/"));
    int range = stoi(subnet.substr(subnet.rfind("/")+1)); // 192.168.x.x
    int loops = range/256; // 192.168.x
    cout<<range<<endl;
    vector<int> ip;
    while(!startingIp.empty()){
        cout<<startingIp<<endl;
        if(startingIp.find(".") != string::npos){
            ip.push_back(stoi(startingIp.substr(0,startingIp.find("."))));
            startingIp.erase(0,startingIp.find(".")+1);
        } else {
            ip.push_back(stoi(startingIp));
            break;
        }
    }

    vector<string> ips;

    for(int i = 0; i <= loops; i++){
        if(i != loops){
            for(int j = 0; j < 256; j ++){
                string currentIp;
                currentIp = to_string(ip[0]) + "." + to_string(ip[1]) + "." + to_string(i) + "." + to_string(j);
                ips.push_back(currentIp);
            }
        } else {
            for(int j = 0; j < range%256; j ++){
                string currentIp;
                currentIp = to_string(ip[0]) + "." + to_string(ip[1]) + "." + to_string(i) + "." + to_string(j);
                ips.push_back(currentIp);
            }
        }
    }
    while (true)
    {
        for(string ip : ips){
            try{
                auto sess = openSession(ip,stoi(port));
                loginAnonymous(sess);
                auto ep = pasv(sess);
                socket_t data_connection = connectTo(ep.ip, ep.port);
                bool ok = sendLine(sess.ctrl, "LIST");
                auto pre = readReply(sess.ctrl);
                if(pre.code != 150){
                    continue;
                }
                auto listing = readAll(data_connection);
                close(data_connection);
                cout<<listing<<endl;
            } catch (...){
                //ignore
            }
        }   
        
        sleep(sleep_interval);
    }
}
