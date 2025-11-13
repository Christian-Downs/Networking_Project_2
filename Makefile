CXX = g++
CXXFLAGS = -std=c++20 -Wall

all: server

compile: server run
runclient: client clientrun
run_test: test test_run

server: client_handler.cpp helper_commands.cpp server.cpp peer_scanner.cpp
	$(CXX) $(CXXFLAGS) -o server server.cpp
client: client.cpp
	$(CXX) $(CXXFLAGS) -o client client.cpp
clientrun:
	./client 127.0.1.1
test: ftp_tests.cpp
	$(CXX) $(CXXFLAGS) -Wextra -O2 ftp_tests.cpp -o ftp_tests
test_run: 
	./ftp_tests 127.0.1.1 3490
run:
	./server server.conf
clean:
	rm -f server
	rm -f client