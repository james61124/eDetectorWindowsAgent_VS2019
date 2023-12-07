#include <iostream>
#include <thread>
#include <windows.h>
#include <sstream>
#include "socket_manager.h"
#include "tools.h"
#include "Log.h"

#include "Scan.h"
#include "AllTask.h"
#include "CollectInfo.h"
#include "Explorer.h"
#include "Image.h"
#include "DetectProcess.h"
#include "DetectNetwork.h"
#include "UpdateAgent.h"

bool IsProcessAlive(DWORD pid) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (hProcess == NULL) {
		// OpenProcess failed, process is likely not alive
		return false;
	}

	// Check if the process is still running
	DWORD exitCode;
	if (GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE) {
		// Process is still active
		CloseHandle(hProcess);
		return true;
	}

	CloseHandle(hProcess);
	return false;
}

void CheckProcessStatus(Info* info) {
	Log log;
	while (true) {
		for (const auto& pair : info->processMap) {
			if (!IsProcessAlive(pair.second)) {
				if (info->processMap[pair.first] != 0) {
					string LogMsg = pair.first + " disconnected";
					log.logger("Info", LogMsg);
					info->processMap[pair.first] = 0;
				} 
				if (info->processMap["DetectProcess"] == 0 && info->DetectProcess == 1) {
					std::string Msg = std::to_string(info->DetectProcess);
					std::string LogMsg = "DetectProcess connected" + Msg;
					log.logger("Info", LogMsg);

					Tool tool;
					DWORD DetectProcessPid = 0;
					TCHAR* RunExeStr = new TCHAR[MAX_PATH];
					TCHAR* RunComStr = new TCHAR[512];
					GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

					wstring filename = tool.GetFileName();
					TCHAR MyName[MAX_PATH];
					wcscpy_s(MyName, filename.c_str());

					TCHAR ServerIP[MAX_PATH];
					swprintf_s(ServerIP, MAX_PATH, L"%hs", info->ServerIP);

					swprintf_s(RunComStr, 512, L"\"%s\" %s %d DetectProcess", MyName, ServerIP, info->Port);
					wprintf(L"Run Process: %ls\n", RunComStr);
					RunProcessEx(RunExeStr, RunComStr, 1024, FALSE, FALSE, DetectProcessPid);
					info->processMap["DetectProcess"] = DetectProcessPid;
					log.logger("Debug", "DetectProcess enabled");
					
				}
				
			}
			else {
				string LogMsg = pair.first + " alive";
			}
		}
	}
}

void CheckIfAdmin() {
	Log log;
	DWORD currentProcessId = GetCurrentProcessId();
	HANDLE currentProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, currentProcessId);
	if (currentProcessHandle != NULL) {
		HANDLE tokenHandle;
		if (OpenProcessToken(currentProcessHandle, TOKEN_QUERY, &tokenHandle)) {
			DWORD tokenInformationLength;
			GetTokenInformation(tokenHandle, TokenUser, NULL, 0, &tokenInformationLength);
			TOKEN_USER* tokenUser = (TOKEN_USER*)malloc(tokenInformationLength);
			if (GetTokenInformation(tokenHandle, TokenUser, tokenUser, tokenInformationLength, &tokenInformationLength)) {
				WCHAR* userName;
				if (ConvertSidToStringSidW(tokenUser->User.Sid, &userName)) {
					BOOL isAdmin = FALSE;
					PSID systemSid;
					SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
					if (!AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &systemSid)) {
						std::cerr << "Failed to allocate and initialize SID" << std::endl;
					}

					BOOL isMember;
					if (CheckTokenMembership(NULL, systemSid, &isMember)) {
						if (isMember) {
							log.logger("Debug", "This is admin process");
						}
						else {
							log.logger("Debug", "Terminate non-admin Process");
							exit(0);
							//TerminateProcess(currentProcessHandle, 0);
						}
						
					}

					LocalFree(userName);
				}
			}

			CloseHandle(tokenHandle);
			free(tokenUser);
		}

		CloseHandle(currentProcessHandle);
	}
	else {
		log.logger("Debug", "failed to OpenProcess");
	}
}



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
		DWORD MyPid = GetCurrentProcessId();

		int i = 0;
		int iLen = 0;
		char* Drive = new char[100];
		char* FileSystem = new char[100];
		char* cmd = new char[100];

		if (task == "CollectInfo") {
			i = std::stoi(argv[4]);
			iLen = std::stoi(argv[5]);
		}

		if (task == "Explorer") {
			Drive = argv[4];
			FileSystem = argv[5];
		}

		if (task == "Image") {
			cmd = argv[4];
		}


		Log log;
		Info* info = new Info();
		SocketSend* socketsend = new SocketSend(info);
		SocketManager socketManager(serverIP, port, info, socketsend);

		std::unordered_map<std::string, AllTask*> taskMap{
			{"Scan", new Scan(info, socketsend)},
			{"Collect", new Collect(info, socketsend)},
			{"CollectInfo", new CollectInfo(info, socketsend, i, iLen)},
			{"Explorer", new Explorer(info, socketsend, Drive, FileSystem)},
			{"Image", new Image(info, socketsend, cmd)},
			{"DetectProcess", new DetectProcess(info, socketsend)},
			{"DetectNetwork", new DetectNetwork(info, socketsend, MyPid)},
			{"UpdateAgent", new UpdateAgent(info, socketsend)}
		};


		auto it = taskMap.find(task);
		if (it != taskMap.end()) taskMap[task]->DoTask();
		else if(task == "Log") log.LogServer();
		else {
			// If the user is not admin, kill itself
			CheckIfAdmin();

			// enabled log process
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
			log.logger("Debug", "Log enabled");

			// enabled check process status thread
			std::thread CheckStatusThread([&]() { CheckProcessStatus(info); });
			CheckStatusThread.detach();

			// handshake
			std::thread receiveThread([&]() { socketManager.receiveTCP(); });
			socketManager.HandleTaskToServer("GiveInfo");
			std::thread CheckConnectThread([&]() { socketManager.task->CheckConnect(); });
			CheckConnectThread.detach();
			receiveThread.join();
		}

		//std::unordered_map<std::string, std::function<void()>> taskMap = {
		//	{"Scan", [&]() { HandleScan(socketManager); }},
		//	{"Collect", [&]() { HandleCollect(); }},
		//	{"CollectInfo", [&]() { HandleCollectInfo(std::stoi(argv[4]), std::stoi(argv[5])); }},
		//	{"Explorer", [&]() { HandleExplorer(argv[4], argv[5]); }},
		//	{"Image", [&]() { HandleImage(argv[4]); }},
		//	{"DetectProcess", [&]() { HandleDetectProcess(); }},
		//	{"DetectNetwork", [&]() { HandleDetectNetwork(); }},
		//	{"UpdateAgent", [&]() { HandleUpdateAgent(); }},
		//	{"TerminateAll", [&]() { HandleTerminateAll(); }},
		//	{"Log", [&]() { HandleLog(); }}
		//};



		//if (task == "Scan") {
		//	//socketManager.HandleTaskToServer("GiveProcessData");
		//	taskMap[task]->DoTask();
		//}
		//else if (task == "Collect") {
		//	//socketManager.HandleTaskToServer("CollectionComputerInfo");
		//	taskMap[task]->DoTask();
		//}
		//else if (task == "CollectInfo") {
		//	/*int i = std::stoi(argv[4]);
		//	int iLen = std::stoi(argv[5]);

		//	socketManager.task->CollectData(i, iLen);*/
		//	taskMap[task]->DoTask();
		//}
		//else if (task == "Explorer") {
		//	/*char* Drive = argv[4];
		//	char* FileSystem = argv[5];
		//	socketManager.task->GiveExplorerData(Drive, FileSystem);*/

		//	taskMap[task]->DoTask();
		//}
		//else if (task == "Image") {
		//	//char* cmd = argv[4];
		//	//socketManager.task->LookingForImage(cmd);
		//	taskMap[task]->DoTask();
		//}
		//else if (task == "DetectProcess") {
		//	//socketManager.HandleTaskToServer("DetectProcess");
		//	taskMap[task]->DoTask();
		//}
		//else if (task == "DetectNetwork") {
		//	//DWORD MyPid = GetCurrentProcessId();
		//	//socketManager.task->DetectNewNetwork(MyPid);
		//	taskMap[task]->DoTask();
		//}
		//else if (task == "UpdateAgent") {
		//	//socketManager.HandleTaskToServer("UpdateAgent");
		//	taskMap[task]->DoTask();
		//}
		////else if (task == "TerminateAll") {
		////	socketManager.task->TerminateAllTask();
		////}
		//else if (task == "Log") {
		//	//log.LogServer();
		//	taskMap[task]->DoTask();
		//}
		//else {

		//	// If the user is not admin, kill itself
		//	CheckIfAdmin();

		//	// enabled log process
		//	Tool tool;
		//	DWORD LogProcessPid = 0;
		//	TCHAR* RunExeStr = new TCHAR[MAX_PATH];
		//	TCHAR* RunComStr = new TCHAR[512];
		//	GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

		//	wstring filename = tool.GetFileName();
		//	TCHAR MyName[MAX_PATH];
		//	wcscpy_s(MyName, filename.c_str());

		//	TCHAR ServerIP[MAX_PATH];
		//	swprintf_s(ServerIP, MAX_PATH, L"%hs", info->ServerIP);

		//	swprintf_s(RunComStr, 512, L"\"%s\" %s %d Log", MyName, ServerIP, info->Port);
		//	wprintf(L"Run Process: %ls\n", RunComStr);
		//	RunProcessEx(RunExeStr, RunComStr, 1024, FALSE, FALSE, LogProcessPid);

		//	info->processMap["Log"] = LogProcessPid;
		//	log.logger("Debug", "Log enabled");

		//	

		//	// enabled check process status thread
		//	std::thread CheckStatusThread([&]() { CheckProcessStatus(info); });
		//	CheckStatusThread.detach();

		//	// handshake
		//	std::thread receiveThread([&]() { socketManager.receiveTCP(); });
		//	socketManager.HandleTaskToServer("GiveInfo");
		//	std::thread CheckConnectThread([&]() { socketManager.task->CheckConnect(); });
		//	CheckConnectThread.detach();
		//	//socketManager.HandleTaskToServer("UpdateAgent");
		//	receiveThread.join();
		//}
	}

}