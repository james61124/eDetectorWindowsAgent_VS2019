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
		//std::wstring wideStr = std::wstring(argv[1]);
		//std::string serverIP(wideStr.begin(), wideStr.end());
		std::string serverIP = argv[1];
		int port = std::stoi(argv[2]);
		std::string task = argv[3];

		Info* info = new Info();
		SocketSend* socketsend = new SocketSend(info);
		SocketManager socketManager(serverIP, port, info, socketsend);

		if (task == "Scan") {
			socketManager.HandleTaskToServer("GiveProcessData");
		}
		else if (task == "Collect") {
			socketManager.HandleTaskToServer("CollectionComputerInfo");
		}
		else if (task == "Explorer") {
			char* Drive = argv[4];
			char* FileSystem = argv[5];
			socketManager.task->GiveExplorerData(Drive, FileSystem);
		}
		else if (task == "DetectProcess") {
			socketManager.HandleTaskToServer("CollectionComputerInfo");
		}
		else if (task == "DetectNetwork") {
			socketManager.HandleTaskToServer("CollectionComputerInfo");
		}
		else {
			std::thread receiveThread([&]() { socketManager.receiveTCP(); });
			socketManager.HandleTaskToServer("GiveInfo");
			receiveThread.join();
		}
	}

}