#include <iostream>
#include <thread>
#include "socket_manager.h"


int main(int argc, char* argv[]) {
    Info* info = new Info();
    SocketSend* socketsend = new SocketSend(info);
    SocketManager socketManager(1988, 1989, info, socketsend);
    printf("thread is going to open\n");
    std::thread RecieveFunction([&socketManager]() { socketManager.receiveTCP(); });
    socketManager.HandleTaskToServer("GiveInfo");
    RecieveFunction.join();

    while (true) {};
}