#include <iostream>
#include <thread>
#include "socket_manager.h"


int main(int argc, char* argv[]) {

    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <serverIP> <port>" << std::endl;
        return 1;
    }
    std::string serverIP = argv[1];
    int port = std::stoi(argv[2]);

    Info* info = new Info();
    SocketSend* socketsend = new SocketSend(info);
    SocketManager socketManager(serverIP, port, info, socketsend);

    

    while (true) {};
}