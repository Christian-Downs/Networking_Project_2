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

#define MAXDATASIZE 1000
using namespace std;

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
        if(path == ".."){
            currentPath = currentPath.string().substr(0, currentPath.string().rfind("/"));
            cout<<currentPath.string()<<endl;
            if(currentPath.string().find(parent_dir) == string::npos){
                *current_dir = parent_dir;
                send_back(pid, 550);
                return;
            }
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

void cdup(string *current_dir, string parent_dir, int pid, struct sockaddr_storage their_addr)
{
    *current_dir = parent_dir;
    send_back(pid, 200);
    return;
}

void client_handle_client(int pid, struct sockaddr_storage their_addr)
{
    string parent_dir = filesystem::current_path().string();
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
        cout << message_string << endl;

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
        }
    }
}