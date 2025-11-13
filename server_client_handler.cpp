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
using namespace std;


void p2p(int pid, sockaddr_storage their_addr){
	// Placeholder for future peer-specific command handling (reuse FTP subset)
}

bool authorize(string message){
	// Basic authorize stub to silence warning; can extend for peer@IP later
	if(message.find("anonymous") != string::npos) return true;
	if(message.rfind("peer@",0) == 0) return true; // simplistic peer allowance
	return false;
}


