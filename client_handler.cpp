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
#include <unordered_map>
#include <mutex>
#include <optional>

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
// Extern peer aggregation structures (defined in server.cpp)
extern unordered_map<string, vector<string>> peer_root_listing;
extern unordered_map<string, unordered_map<string, vector<string>>> peer_dir_files;
extern mutex peer_mutex;
extern std::string CONTROL_PORT;

// ---- Remote RETR redirect support structures ----
struct RemoteRetrSession {
    int peer_ctrl_fd = -1; // control connection to peer
    std::string peer_ip;
    int peer_port = 0; // passive data port on peer
};
static unordered_map<int, RemoteRetrSession> remote_retr_map; // key = client control pid

static int remote_connect_socket(const std::string &host, int port){
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if(s < 0) return -1;
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons((uint16_t)port);
    if(inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0){ close(s); return -1; }
    if(connect(s, (sockaddr*)&addr, sizeof(addr)) < 0){ close(s); return -1; }
    return s;
}

static std::optional<std::string> remote_recv_line(int sock){
    std::string line; char ch;
    while(true){
        int n = recv(sock, &ch, 1, 0);
        if(n <= 0){ if(line.empty()) return std::nullopt; break; }
        if(ch == '\n') break; if(ch != '\r') line.push_back(ch);
        if(line.size() > 8192) break;
    }
    return line;
}

static int remote_read_reply_code(int sock){
    auto ln = remote_recv_line(sock); if(!ln) return -1;
    std::string line = *ln;
    if(line.size() < 3 || !isdigit(line[0]) || !isdigit(line[1]) || !isdigit(line[2])) return -1;
    return atoi(line.substr(0,3).c_str());
}

static bool remote_send_line(int sock, const std::string &cmd){
    std::string out = cmd;
    if(out.size() <2 || out.substr(out.size()-2) != "\r\n") out += "\r\n";
    return send(sock, out.c_str(), out.size(), 0) == (ssize_t)out.size();
}

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
static int accept_pasv_data(int ctrl_pid, int timeout_ms = 2000){
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
    if(path.empty()){
        send_back(pid, 501);
        return;
    }
    // Absolute paths are forbidden by jail
    if(!path.empty() && path[0] == '/'){
        send_back(pid, 550);
        return;
    }
    // Normalize repeated slashes
    while(path.find("//") != string::npos) path.replace(path.find("//"), 2, "/");
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
        if(path == "." || path.empty()){
            continue; // ignore current directory markers
        }
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
        // trim leading spaces
        while(!arg.empty() && isspace((unsigned char)arg.front())) arg.erase(arg.begin());
        if (!arg.empty())
        {
            // If arg is composed only of '/' and '.' (and not ".."), normalize to current dir
            bool only_slash_dot = (arg.find_first_not_of("/.") == string::npos);
            if (only_slash_dot && arg.find("..") == string::npos)
            {
                // If it's only slashes (no dots), treat as absolute and block; if contains a dot, normalize to current dir
                if (arg.find('.') == string::npos)
                {
                    send_back(pid, 550);
                    close_pasv(pid);
                    return;
                }
                // else: Treat as current directory
            }
            else
            {
                // basic traversal guard
                if (arg[0] == '/' || arg.find("..") != string::npos)
                {
                    send_back(pid, 550);
                    close_pasv(pid);
                    return;
                }
                // Normalize repeated slashes and remove benign './'
                while(arg.find("//") != string::npos) arg.replace(arg.find("//"), 2, "/");
                while(true){
                    size_t p = arg.find("/./");
                    if(p == string::npos) break;
                    arg.replace(p, 3, "/");
                }
                if(arg == ".") arg.clear();
                if(!arg.empty())
                    target = current_dir + "/" + arg;
            }
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

    // Unified aggregation: append peer directory entries at root, or peer file entries within subdirectory
    try {
        lock_guard<mutex> lk(peer_mutex);
        string parent_dir = filesystem::current_path().string() + "/db/"; // reconstruct jail root
        if(current_dir == parent_dir){
            for(const auto &pr : peer_root_listing){
                for(const auto &line : pr.second){
                    if(line.empty()) continue;
                    if(line[0] == 'd'){
                        string mod = line;
                        size_t pos = mod.find(" local ");
                        if(pos != string::npos) mod.replace(pos+1, 5, "peer");
                        listing += mod; // already CRLF terminated
                    }
                }
            }
        } else {
            // Directory name portion after parent_dir
            string dirName = current_dir.substr(current_dir.find_last_of('/') + 1);
            for(const auto &peer : peer_dir_files){
                auto itDir = peer.second.find(dirName);
                if(itDir != peer.second.end()){
                    for(const string &fline : itDir->second){
                        if(fline.empty()) continue;
                        if(fline[0] == '-'){
                            string mod = fline;
                            size_t pos = mod.find(" local ");
                            if(pos != string::npos) mod.replace(pos+1, 5, "peer");
                            listing += mod;
                        }
                    }
                }
            }
        }
    } catch(...){ /* ignore aggregation issues */ }

    if (!listing.empty()) (void)send_all(data_fd, listing.c_str(), listing.size());
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

    // Ensure no stale PASV entry is associated with this control fd (fd reuse could collide)
    pasv_map.erase(pid);

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
            // ensure any PASV listener is torn down when quitting
            close_pasv(pid);
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
            namespace fs = filesystem;
            bool local_exists = fs::exists(full) && fs::is_regular_file(full);

            if(local_exists){
                int data_fd = accept_pasv_data(pid);
                if(data_fd < 0){ send_back(pid, 425); close_pasv(pid); continue; }
                send_back(pid, 150);
                bool ok = false;
                try {
                    ifstream in(full, ios::binary);
                    if(in){
                        char buff[8192];
                        while(in.good()){
                            in.read(buff, sizeof(buff));
                            streamsize n = in.gcount();
                            if(n>0 && !send_all(data_fd, buff, (size_t)n)) break;
                        }
                        ok = true;
                    }
                } catch(...) { ok = false; }
                close(data_fd); close_pasv(pid);
                send_back(pid, ok ? 226 : 550);
                continue;
            }

            // Remote redirect path: find file in peer_dir_files for current directory
            string dirName = current_dir.substr(current_dir.find_last_of('/') + 1);
            string remote_ip;
            {
                lock_guard<mutex> lk(peer_mutex);
                for(const auto &peer : peer_dir_files){
                    auto itD = peer.second.find(dirName);
                    if(itD != peer.second.end()){
                        for(const auto &line : itD->second){
                            // line format: -rw-r--r-- 1 peer size filename\r\n
                            size_t lastSpace = line.find_last_of(' ');
                            if(lastSpace != string::npos){
                                string fname = line.substr(lastSpace + 1);
                                if(!fname.empty() && fname.back()=='\r') fname.pop_back();
                                if(fname == arg){ remote_ip = peer.first; break; }
                            }
                        }
                    }
                    if(!remote_ip.empty()) break;
                }
            }

            if(remote_ip.empty()){
                // Not found anywhere
                send_back(pid, 550);
                close_pasv(pid);
                continue;
            }

            // Negotiate remote PASV with peer
            int peer_ctrl = remote_connect_socket(remote_ip, atoi(CONTROL_PORT.c_str()));
            if(peer_ctrl < 0){ send_back(pid, 425); close_pasv(pid); continue; }
            // Expect banner
            (void)remote_read_reply_code(peer_ctrl);
            if(!remote_send_line(peer_ctrl, std::string("USER peer@") + local_ip_for_socket(pid))){ close(peer_ctrl); send_back(pid, 425); close_pasv(pid); continue; }
            int authCode = remote_read_reply_code(peer_ctrl);
            if(authCode != 230){ close(peer_ctrl); send_back(pid, 530); close_pasv(pid); continue; }
            if(!remote_send_line(peer_ctrl, "PASV")){ close(peer_ctrl); send_back(pid,425); close_pasv(pid); continue; }
            auto ln = remote_recv_line(peer_ctrl);
            if(!ln || ln->rfind("227",0)!=0){ close(peer_ctrl); send_back(pid,425); close_pasv(pid); continue; }
            // Forward peer's 227 directly to client (data redirect)
            send_back(pid, *ln + "\n"); // already formatted with CRLF inside
            close_pasv(pid); // tear down local passive listener (redirect scenario)

            // Forward RETR command to peer now (client will connect to peer data port)
            if(!remote_send_line(peer_ctrl, std::string("RETR ") + arg)) { close(peer_ctrl); send_back(pid, 425); continue; }
            int preCode = remote_read_reply_code(peer_ctrl); // expect 150
            if(preCode == 150 || preCode == 125){ send_back(pid, preCode); } else { send_back(pid, preCode>0?preCode:550); }
            // Wait for completion code (226 or error)
            int finCode = remote_read_reply_code(peer_ctrl);
            if(finCode == 226) send_back(pid, 226); else if(finCode>0) send_back(pid, finCode); else send_back(pid, 550);
            close(peer_ctrl);
            continue;
        } else {
            send_back(pid, 500);
            continue;
        }
    }
    // Ensure PASV state is cleared when control connection ends
    close_pasv(pid);
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