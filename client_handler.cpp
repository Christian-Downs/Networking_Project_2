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

void pwd(int pid, struct sockaddr_storage their_addr){

    

}



void client_handle_client(int pid, struct sockaddr_storage their_addr){
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
        printf("server: received '%s'\n", buf);

        if(message_string == "PWD") {
            pwd(pid, their_addr)
            continue;
        }

    }
}