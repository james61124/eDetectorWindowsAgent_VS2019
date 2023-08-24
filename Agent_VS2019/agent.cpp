#include <iostream>
#include <thread>
#include <windows.h>
#include "socket_manager.h"
#include "tools.h"
#include "Log.h"
//
//void SignalHandler(int signal, Info* info) {
//	std::cout << "Received Ctrl-C signal. Terminating processes..." << std::endl;
//
//	for (const auto& pair : info->processMap) {
//		std::cout << "Terminating process with ID: " << pair.first << std::endl;
//		HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pair.first);
//		TerminateProcess(processHandle, 0);
//		CloseHandle(processHandle);
//	}
//
//	exit(signal);
//}

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

		Log log;
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
			socketManager.HandleTaskToServer("DetectProcess");
		}
		else if (task == "DetectNetwork") {
			DWORD MyPid = GetCurrentProcessId();
			socketManager.task->DetectNewNetwork(MyPid);
		}
		else if (task == "Log") {
			log.LogServer();
		}
		else {

			Tool tool;
			DWORD LogProcessPid = 0;
			TCHAR* RunExeStr = new TCHAR[MAX_PATH];
			TCHAR* RunComStr = new TCHAR[512];
			GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

			wstring filename = tool.GetFileName();
			TCHAR MyName[MAX_PATH];
			wcscpy_s(MyName, filename.c_str());

			TCHAR ServerIP[MAX_PATH];
			swprintf_s(ServerIP, MAX_PATH, L"%hs", info->ServerIP);

			swprintf_s(RunComStr, 512, L"\"%s\" %s %d Log", MyName, ServerIP, info->Port);
			wprintf(L"Run Process: %ls\n", RunComStr);
			RunProcessEx(RunExeStr, RunComStr, 1024, FALSE, FALSE, LogProcessPid);

			info->processMap["Log"] = LogProcessPid;

			std::thread receiveThread([&]() { socketManager.receiveTCP(); });
			socketManager.HandleTaskToServer("GiveInfo");
			receiveThread.join();
		}
	}

}