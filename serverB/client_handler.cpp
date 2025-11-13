#include <iostream>
#include <stdexcept>
#include <string>
#include <sstream>
#include <thread>
#include <vector>
#include <system_error>
#include <map>
#include <fstream>
#include <filesystem>

// C headers for socket API
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include "helper_commands.cpp"

#define MAXDATASIZE 1024
using namespace std;

struct PassiveSession { // set up a PASV Session object
    int listen_socket = -1;
    uint16_t port = 0; 
};

static unordered_map <int, PassiveSession> pasv_map;  // key = controller pid

static std::string local_ip_for_socket(int ctrl_pid)
{
    sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    if (getsockname(ctrl_pid, (sockaddr *)&ss, &len) == 0)
    {
        if (ss.ss_family == AF_INET)
        {
            char ip[INET_ADDRSTRLEN];
            auto *sin = (sockaddr_in *)&ss;
            if (inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip)))
                return std::string(ip);
        }
    }
    return "127.0.0.1";
}

static string ip_tuple_for_ctrl_fd(int ctrl_fd)
{
    sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    if (getsockname(ctrl_fd, (sockaddr *)&ss, &len) == 0 && ss.ss_family == AF_INET)
    {
        auto *sin = (sockaddr_in *)&ss;
        uint32_t addr_be = sin->sin_addr.s_addr; // network byte order
        uint32_t addr_le = ntohl(addr_be);       // host byte order
        int a = (addr_le >> 24) & 0xFF;
        int b = (addr_le >> 16) & 0xFF;
        int c = (addr_le >> 8) & 0xFF;
        int d = (addr_le >> 0) & 0xFF;
        ostringstream returnMessage;
        returnMessage << a << "," << b << "," << c << "," << d;
        return returnMessage.str();
    }
    // Fallback to localhost if something goes wrong
    return "127,0,0,1";
}

static string enter_pasv(int ctrl_pid){
    if (pasv_map.count(ctrl_pid) && pasv_map[ctrl_pid].listen_socket >= 0)
    { // if there is already a data connection to this controller delete that connection
        close(pasv_map[ctrl_pid].listen_socket);
        pasv_map.erase(ctrl_pid);
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0); // IPv4 and TCP socket
    if (sock < 0) return "";

    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)); 
    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(0);
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);

    if(bind(sock, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0){
        close(sock);
        return "";
    }

    if(listen(sock, 5) <0){ //get client info
        close(sock); //client closed
        return "";
    }

    socklen_t slen = sizeof(serverAddress);
    if (getsockname(sock, (sockaddr *)&serverAddress, &slen) < 0)
    {
        close(sock);
        return "";
    }
    uint16_t port = ntohs(serverAddress.sin_port);
    pasv_map[ctrl_pid] = PassiveSession{sock, port};

    string ip = local_ip_for_socket(ctrl_pid);

    int p1 = port/256;
    int p2 = port % 256;
    string ipTuple = ip_tuple_for_ctrl_fd(ctrl_pid);
    ostringstream returnMessage;
    returnMessage << "227 Entering Passive Mode (" << ipTuple << "," << p1 << "," << p2 << ").\r\n";

    return returnMessage.str();
}

// Accept a single data connection from the stored PASV listener; returns -1 if none.
static int accept_pasv_data(int ctrl_pid, int timeout_ms = 5000){
    auto it = pasv_map.find(ctrl_pid);
    if(it == pasv_map.end() || it->second.listen_socket<0) return -1;

    int listen_socket = it->second.listen_socket;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(listen_socket, &rfds);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    int sel = select(listen_socket + 1, &rfds, nullptr, nullptr, &tv);
    if(sel <= 0) return -1;

    sockaddr_in cli{};
    socklen_t len = sizeof(cli);

    int data_fd = accept(listen_socket, (sockaddr*)&cli, &len);
    return data_fd;
}

// close data transfer for the controller pid
static void close_pasv(int ctrl_pid){
    auto it = pasv_map.find(ctrl_pid);
    if(it != pasv_map.end()){
        if(it->second.listen_socket >=0) {
            close(it->second.listen_socket);
        }
        pasv_map.erase(it);
    }
}





void pwd(string current_dir, string parent_dir, int pid, struct sockaddr_storage their_addr)
{
    printf("server: Sending the directory");

    if (current_dir.find(parent_dir) != string::npos)
    {
        current_dir.erase(0, current_dir.find(parent_dir) + parent_dir.length());

        send_back(pid, "257 \"" + current_dir + "/\" is the current directory\r\n");
        return;
    }
    else
    {
        send_back(pid, 550);
        return;
    }
}

void CWD(string path, string *current_dir, string parent_dir, int pid, struct sockaddr_storage their_addr)
{
    filesystem::path currentPath = *current_dir;
    cout << *current_dir << endl;
    vector<string> paths;
    string singlePath;
    size_t pos = 0;
    string temp_path = path;

    while ((pos = temp_path.find("/")) != string::npos)
    {
        singlePath = temp_path.substr(0, pos);
        paths.push_back(singlePath);
        temp_path.erase(0, pos + 1);
    }
    paths.push_back(temp_path);

    for (string path : paths)
    {
        cout<<path<<endl;
        if(path == ".."){
            cout << "GOING UP" << endl;
            currentPath = currentPath.string().substr(0, currentPath.string().rfind("/"));
            cout<<currentPath.string()<<endl;
            if(currentPath.string().find(parent_dir) == string::npos){
                *current_dir = parent_dir;
                send_back(pid, 550);
                return;
            }
            *current_dir = currentPath;
        }
        else if (filesystem::exists(currentPath) && filesystem::is_directory(currentPath))
        {
            bool found = false;
            for (const auto &entry : filesystem::directory_iterator(currentPath))
            {
                cout << entry.path().string().substr(entry.path().string().rfind("/") + 1) << endl;
                if (path == entry.path().string().substr(entry.path().string().rfind("/") + 1))
                {
                    *current_dir = *current_dir + "/" + path;
                    std::cout << "Current dir " << *current_dir << endl;
                    found = true;
                    break;
                }
            }
            if(found){
                continue;
            }
            send_back(pid, 501);
            return;
        }
    }

    send_back(pid, 250);
    return;
}

void list(string message_string, string current_dir, int pid, struct sockaddr_storage their_addr){
    // Require PASV first
    if (!pasv_map.count(pid))
    {
        send_back(pid, 425);
        return;
    }

    // Determine and validate target path BEFORE opening data connection
    string target = current_dir;
    cout << "TARGET: " << target << endl;
    if (message_string.size() > 4)
    {
        string arg = message_string.substr(5);
        if (!arg.empty())
        {
            // basic traversal guard
            if (arg[0] == '/' || arg.find("..") != string::npos)
            {
                send_back(pid, 550);
                close_pasv(pid);
                return;
            }
            target = current_dir + "/" + arg;
        }
    }

    // Validate directory exists
    namespace fs = filesystem;
    if (!(fs::exists(target) && fs::is_directory(target)))
    {
        send_back(pid, 550);
        close_pasv(pid);
        return;
    }

    // Now accept a single data connection; if it fails, report 425 without sending 150
    int data_fd = accept_pasv_data(pid);
    if (data_fd < 0)
    {
        send_back(pid, 425);
        close_pasv(pid);
        return;
    }

    // Data connection is up; send 150 and stream listing
    send_back(pid, 150);

    string listing;
    try
    {
        std::cout << "LIST " << target << endl;
        for (const auto &entry : fs::directory_iterator(target))
        {
            auto p = entry.path();

            ostringstream line;

            if (fs::is_directory(p))
            {
                line << "drwxr-xr-x 1 local 0 ";
            }
            else
            {
                auto sz = fs::is_regular_file(p) ? (long long)fs::file_size(p) : 0ll;
                line << "-rw-r--r-- 1 local " << sz << " ";
            }

            line << p.filename().string() << "\r\n";
            listing += line.str();
        }
    }
    catch (...)
    {
        send_back(pid, 451);
        close(data_fd);
        close_pasv(pid);
        return;
    }

    if (!listing.empty())
    {
        (void)send_all(data_fd, listing.c_str(), listing.size());
    }

    close(data_fd);
    close_pasv(pid);
    send_back(pid, 226);
}


void cdup(string *current_dir, string parent_dir, int pid, struct sockaddr_storage their_addr)
{
    *current_dir = parent_dir;
    send_back(pid, 200);
    return;
}

void client_handle_client(int pid, struct sockaddr_storage their_addr)
{
    string parent_dir = filesystem::current_path().string() + "/db/";
    string current_dir = parent_dir;

    char s[INET6_ADDRSTRLEN];
    inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
    std::cout << "server: got connection from " << s << std::endl;

    filesystem::path basepath = "";

    int numbytes;

    char buf[MAXDATASIZE];

    while (true)
    {
        numbytes = recv(pid, buf, MAXDATASIZE - 1, 0);
        if (numbytes == 0)
        {
            // client closed
            break;
        }
        if (numbytes < 0)
        {
            perror("recv");
            break;
        }
        buf[numbytes] = '\0';

        buf[strcspn(buf, "\r\n")] = '\0'; // Strip newline characters
        string message_string = buf;
        message_string = string_to_lowercase(message_string);

        printf("server: received '%s'\n", buf);

        if (message_string == "pwd")
        {
            pwd(current_dir, parent_dir, pid, their_addr);

            continue;
        }
        else if (message_string.find("cwd") != string::npos)
        {
            cout << "CWD" << endl;
            try
            {
                message_string.erase(0, message_string.find(" ") + 1);
                if (!message_string.empty())
                {
                    CWD(message_string, &current_dir, parent_dir, pid, their_addr);
                    continue;
                }
                else
                {
                    {
                        send_back(pid, 501);
                    }
                }
            }
            catch (...)
            {
                send_back(pid, 501);
                continue;
            }
        }
        else if (message_string == "quit")
        {
            printf("server: ending connection with client");
            send_back(pid, 221);
            return;
        } else if (message_string == "cdup"){
            cdup(&current_dir, parent_dir, pid, their_addr);
            continue;
        } else if (message_string == "pasv"){
            string msg = enter_pasv(pid);
            if(msg == ""){
                send_back(pid, 425);
                continue;
            }
            send_back(pid, msg);
            continue;
        } else if (message_string.rfind("list", 0) == 0){
            list(message_string, current_dir, pid, their_addr);
            continue;
        } else if (message_string.rfind("retr", 0) == 0) {

            if(!pasv_map.count(pid)){
                send_back(pid, 425);
                continue;
            }

            string arg;
            size_t sp = message_string.find(' ');
            if(sp != string::npos) arg= message_string.substr(sp+1);

            if(arg.empty() || arg.find("..") != string::npos){
                send_back(pid, 553);
                close_pasv(pid);
                continue;
            }

            string full = current_dir + "/" + arg;

            int data_fd = accept_pasv_data(pid);

            if(data_fd < 0) {
                send_back(pid, 425);
                close_pasv(pid);
                continue;
            }

            send_back(pid, 150);

            bool ok = false;

            try {
                ifstream in(full, ios::binary);
                if(in) {
                    char buff[8192];
                    while(in.good()){
                        in.read(buff, sizeof(buff));
                        streamsize n = in.gcount();
                        if(n>0 && !send_all(data_fd, buff, (size_t)n)) break;
                    }
                    ok = true;
                }
            } catch (...) { ok = false; }

            close(data_fd);
            close_pasv(pid);
            if(ok) send_back(pid, 226);
            else send_back(pid, 550);

            continue;
        } else {
            send_back(pid, 500);
            continue;
        }
    }
}

void peer_handler(int pid, string their_addr, string message, string subnet)
{
    if (message.find("@") == string::npos || subnet.find("/") == string::npos)
    {
        send_back(pid, 530);
        return;
    }
    size_t at = message.find('@');
    if (at != string::npos) {
        message = message.substr(at + 1);
        // remove all whitespace characters
        string cleaned;
        cleaned.reserve(message.size());
        for (unsigned char c : message) {
            if (!isspace(c)) cleaned.push_back(c);
        }
        message = cleaned;
    }

    if(their_addr != message){
        send_back(pid, 530);
        return;
    }

    send_back(pid, 230); // authenticated
    int numbytes;

    char buf[MAXDATASIZE];
    while(true) {
        numbytes = recv(pid, buf, MAXDATASIZE - 1, 0);

        if (numbytes == 0)
        {
            // client closed
            break;
        }
        if (numbytes < 0)
        {
            perror("recv");
            break;
        }
        buf[numbytes] = '\0';
        buf[strcspn(buf, "\r\n")] = '\0'; // Strip newline characters

        string message_string = buf;
        message_string = string_to_lowercase(message_string);

        printf("server: received '%s'\n", buf);



    }
}