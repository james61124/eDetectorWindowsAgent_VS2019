#include <iostream>
#include <thread>
#include <windows.h>
#include <sstream>
#include "socket_manager.h"
#include "tools.h"
#include "Log.h"


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

//void SearchActivitiesCache(const std::string& directory, const std::string& remainingPath) {
//void SearchActivitiesCache(std::vector<std::string>& parts, int level, string &searchPath, char* FileToSearch) {
//
//	for (int i = level; i < parts.size(); i++) {
//		searchPath += parts[i];
//		level++;
//		if (parts[i].find('*') != std::string::npos) {
//			break;
//		}
//		searchPath += "\\";
//	}
//	
//	if (searchPath.find('*') == std::string::npos) {
//		searchPath += "*";
//	}
//
//	std::cout << "searchPath: " << searchPath << std::endl;
//		
//
//	WIN32_FIND_DATAA findFileData;
//	HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findFileData);
//	if (hFind == INVALID_HANDLE_VALUE) {
//		return;
//	}
//
//	do {
//		if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
//			if (strcmp(findFileData.cFileName, ".") != 0 && strcmp(findFileData.cFileName, "..") != 0) {
//				
//				size_t lastBackslashPos = searchPath.find_last_of('\\');
//				if (lastBackslashPos != std::string::npos) {
//					searchPath.erase(lastBackslashPos + 1);
//				}
//				searchPath = searchPath + findFileData.cFileName + "\\";
//				SearchActivitiesCache(parts, level, searchPath, FileToSearch);
//			}
//		}
//		else {
//			
//			if (strcmp(findFileData.cFileName, FileToSearch) == 0) {
//				size_t lastBackslashPos = searchPath.find_last_of('\\');
//				if (lastBackslashPos != std::string::npos) {
//					searchPath.erase(lastBackslashPos);
//				}
//				printf("Found file: %s\\%s\n", searchPath.c_str(), findFileData.cFileName);
//				return;
//			}
//		}
//	} while (FindNextFileA(hFind, &findFileData) != 0);
//
//	FindClose(hFind);
//}

int main(int argc, char* argv[]) {

	//WCHAR driveStrings[255];
	//DWORD driveStringsLength = GetLogicalDriveStringsW(255, driveStrings);
	//WCHAR* currentDrive;
	//std::string narrowString_currentDrive;
	//if (driveStringsLength > 0 && driveStringsLength < 255) {
	//	currentDrive = driveStrings;
	//	while (*currentDrive) {
	//		int requiredSize = WideCharToMultiByte(CP_UTF8, 0, currentDrive, -1, NULL, 0, NULL, NULL);
	//		narrowString_currentDrive.resize(requiredSize);

	//		if (WideCharToMultiByte(CP_UTF8, 0, currentDrive, -1, &narrowString_currentDrive[0], requiredSize, NULL, NULL)) {
	//			std::cout << "currentDrive: " << narrowString_currentDrive << std::endl;
	//		}

	//		currentDrive += wcslen(currentDrive) + 1;
	//		break;
	//	}
	//}


	//char* searchPath = new char[4];
	//if (strcmp(argv[2], "null")) {
	//	size_t len;
	//	errno_t err = _dupenv_s(&searchPath, &len, argv[2]);

	//	if (err != 0) {
	//		printf("Error getting LOCALAPPDATA environment variable.\n");
	//		return 1;
	//	}

	//	if (searchPath == NULL) {
	//		printf("LOCALAPPDATA environment variable is not set.\n");
	//		return 1;
	//	}
	//}
	//
	//std::string connectedDevicesPlatformPath;
	//if (searchPath != NULL) {
	//	connectedDevicesPlatformPath = searchPath;
	//}
	//std::string argv1(argv[1]);
	//connectedDevicesPlatformPath += argv1;

	//// if end of path has *, remove it
	//size_t lastBackslashPos = connectedDevicesPlatformPath.find_last_of('\\');
	//if (lastBackslashPos != std::string::npos) {
	//	size_t secondLastBackslashPos = connectedDevicesPlatformPath.find_last_of('\\', lastBackslashPos - 1);
	//	if (secondLastBackslashPos != std::string::npos) {
	//		std::string extractedString = connectedDevicesPlatformPath.substr(secondLastBackslashPos + 1, lastBackslashPos - secondLastBackslashPos - 1);
	//		if (extractedString == "*") {
	//			connectedDevicesPlatformPath.erase(secondLastBackslashPos);
	//		}
	//	}
	//}

	//// replace root with root drive
	//std::vector<std::string> parts;
	//std::istringstream iss(connectedDevicesPlatformPath);
	//std::string part;
	//while (std::getline(iss, part, '\\')) {
	//	size_t found = part.find("root");
	//	while (found != std::string::npos) {
	//		part.replace(found, 4, narrowString_currentDrive.substr(0, 1));
	//		found = part.find("root", found + 1);
	//	}
	//	parts.push_back(part);
	//}

	//string Path = "";
	//SearchActivitiesCache(parts, 0, Path, argv[3]);



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

		//char* cmd = argv[4];
		//socketManager.task->LookingForImage(cmd);

		//

		if (task == "Scan") {
			socketManager.HandleTaskToServer("GiveProcessData");
		}
		else if (task == "Collect") {
			socketManager.HandleTaskToServer("CollectionComputerInfo");
		}
		else if (task == "CollectInfo") {
			int i = std::stoi(argv[4]);
			int iLen = std::stoi(argv[5]);

			socketManager.task->CollectData(i, iLen);
		}
		else if (task == "Explorer") {
			char* Drive = argv[4];
			char* FileSystem = argv[5];
			socketManager.task->GiveExplorerData(Drive, FileSystem);
		}
		else if (task == "Image") {
			char* cmd = argv[4];
			socketManager.task->LookingForImage(cmd);
		}
		else if (task == "DetectProcess") {
			socketManager.HandleTaskToServer("DetectProcess");
		}
		else if (task == "DetectNetwork") {
			DWORD MyPid = GetCurrentProcessId();
			socketManager.task->DetectNewNetwork(MyPid);
		}
		else if (task == "UpdateAgent") {
			socketManager.HandleTaskToServer("UpdateAgent");
		}
		else if (task == "TerminateAll") {
			socketManager.task->TerminateAllTask();
		}
		else if (task == "Log") {
			log.LogServer();
		}
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
			//socketManager.HandleTaskToServer("UpdateAgent");
			receiveThread.join();
		}
	}

}