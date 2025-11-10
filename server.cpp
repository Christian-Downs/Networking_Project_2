/*
 * CS447 P2 SERVER STARTER CODE
 * ----------------------------
 *  Author: Christian Downs
 *  Date:   11/08/2025
 *  Licence: MIT Licence
 *  Description: This is the starter code for CS447 Fall 2025 P2 server.This code is based on the simple stream server code
 *      found on Beej's Guide to Network programming at https://beej.us/guide/bgnet/html/#a-simple-stream-server.
 *      The code was adapted to use C++20 features like std::jthread for concurrency.
 *
 *      This code can be compiled using:
 *           g++ -std=c++20 -Wall -pthread server.cpp -o server
 *
 *      Use this code as the base for your server implmentation.
 *
 */

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
#include <algorithm>
#include <cctype>


#include "server_client_handler.cpp"
#include "client_handler.cpp"


#define BACKLOG 10


#include <unordered_map>
using namespace std;



std::string get_local_ip_hostname()
{
  char hostname[256];
  gethostname(hostname, sizeof(hostname));
  addrinfo hints{}, *res;
  hints.ai_family = AF_INET;
  if (getaddrinfo(hostname, nullptr, &hints, &res) == 0)
  {
    sockaddr_in *addr = (sockaddr_in *)res->ai_addr;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    freeaddrinfo(res);
    return ip;
  }
  return "127.0.0.1";
}

void data_controller(int new_fd, struct sockaddr_storage their_addr)
{
}

// Function to handle a single client connection in its own thread
void handle_client(int pid, struct sockaddr_storage their_addr)
{


  // A temporary buffer for the client's IP address string
  char s[INET6_ADDRSTRLEN];
  inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
  std::cout << "server: got connection from " << s << std::endl;
  send_back(pid, 220);

  int numbytes;

  char buf[MAXDATASIZE];
  numbytes = recv(pid, buf, MAXDATASIZE - 1, 0);
  if (numbytes == 0)
  {
    // client closed
    close(pid);
    return;
  }
  if (numbytes < 0)
  {
    perror("recv");
    close(pid);
    return;
  }
  buf[numbytes] = '\0';

  buf[strcspn(buf, "\r\n")] = '\0'; // Strip newline characters
  string message_string = buf;
  message_string = string_to_lowercase(message_string);
  printf("server: received '%s'\n", buf);

  if (message_string.find("user") == string::npos)
  {
    //NOT A USER REQUEST
    send_back(pid, 530);
    close(pid);
    return;
  }

  if (message_string.find("anonymous") != string::npos){
    // client is anonymous
    send_back(pid, 230);
    client_handle_client(pid, their_addr);
    close(pid);
    return;
  } else if (message_string.find("peer") != string::npos){

  } else {
    send_back(pid, 530);
    close(pid);
    return;
  }


  // if (send(pid, msg, strlen(msg), 0) == -1)
  // {
  //   perror("send");
  // }

  // Close the socket for this connection
  close(pid);
  std::cout << "server: connection with " << s << " closed." << std::endl;
}

map<string, string> read_config_file(string fileName)
{
  map<string, string> configMap;
  ifstream file(fileName);
  string str;
  while (getline(file, str))
  {
    string key = str.substr(0, str.find('='));
    string value = str.substr(str.find('=') + 1);
    configMap[key] = value;
  }
  return configMap;
}

int main(int argumentCount, char *argumentArray[])
{
  std::string hostname = get_local_ip_hostname();

  int sockfd, new_fd;
  struct addrinfo hints, *servinfo, *p;
  struct sockaddr_storage their_addr;
  socklen_t sin_size;
  int yes = 1;
  int rv;

  std::map<string, string> configMap = read_config_file(argumentArray[1]);

  const char *PORT = configMap["PORT"].c_str();

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0)
  {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  for (p = servinfo; p != NULL; p = p->ai_next)
  {
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
    {
      perror("server: socket");
      continue;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
    {
      perror("setsockopt");
      exit(1);
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
    {
      close(sockfd);
      perror("server: bind");
      continue;
    }
    break;
  }
  freeaddrinfo(servinfo);

  if (p == NULL)
  {
    fprintf(stderr, "server: failed to bind\n");
    exit(1);
  }
  if (listen(sockfd, BACKLOG) == -1)
  {
    perror("listen");
    exit(1);
  }
  std::cout << "server: waiting for connections on " << hostname << ":" << PORT << "..." << std::endl;

  while (true)
  {
    sin_size = sizeof their_addr;
    new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);

    if (new_fd == -1)
    {
      perror("accept");
      continue;
    }

    // Create a new thread to handle the accepted connection
    // std::jthread automatically joins upon destruction
    std::jthread(handle_client, new_fd, their_addr).detach();
  }

  // The main loop will never exit, so this is unreachable.
  close(sockfd);
  return 0;
}
