
#include <iostream>
#include <stdexcept>
#include <string>
#include <sstream>
#include <thread>
#include <vector>
#include <system_error>
#include <map>
#include <fstream>

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
#include "codes.cpp"

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void send_back(int pid, std::string message)
{
    std::string msg_str = message + "\n";
    const char *msg = msg_str.c_str();
    printf("Server: sending back %s \n", msg);

    if (send(pid, msg, strlen(msg), 0) == -1)
    {
        perror("send");
    }
}

void send_back(int pid, int code){
    std::string msg_str = CODES[code] + "\n";
    const char *msg = msg_str.c_str();
    printf("Server: sending back %s \n", msg);
    if (send(pid, msg, strlen(msg), 0) == -1)
    {
        perror("send");
    }
}

string string_to_lowercase(string message){
    std::transform(message.begin(), message.end(), message.begin(),
                   [](unsigned char c)
                   { return std::tolower(c); });
    return message;
}