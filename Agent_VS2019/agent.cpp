#include <iostream>
#include <thread>
#include "socket_manager.h"

int main(int argc, char* argv[]) {

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <serverIP> <port>" << std::endl;
        return 1;
    }
   
	if (argc == 3) {
		int password = std::stoi(argv[2]);
		DWORD MainPid = (DWORD)std::stoi(argv[1]);
		int count = 0;
		if (password == 12345) {
			while (true) {
				if (!IsHavePID(MainPid)) break;
				if (count > 60) break;
				Sleep(10000);
				count++;
			}
		}
	}
	else {
		std::string serverIP = argv[1];
		int port = std::stoi(argv[2]);
		std::string task = argv[3];
		
		if (task == "Scan") {

		}
		else {
			Info* info = new Info();
			SocketSend socketsend(info);
			SocketManager socketManager(serverIP, port, info, socketsend);
		}

		
	}

	//printf("process finish\n");
    while (true) {};
}