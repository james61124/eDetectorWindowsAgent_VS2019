#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <string>
#include <cstring>
#include <future>
#include <thread>

#include "task.h"



Task::Task(Info* infoInstance, SocketSend* socketSendInstance) {

	// handshake
    functionMap["GiveInfo"] = std::bind(&Task::GiveInfo, this);
	functionFromServerMap["OpenCheckthread"] = &Task::OpenCheckthread;
	functionFromServerMap["UpdateDetectMode"] = &Task::UpdateDetectMode;

	// Scan
	functionFromServerMap["GetScan"] = &Task::GetScan;
	
	// Explorer
    functionFromServerMap["GetDrive"] = &Task::GetDrive; // ExplorerInfo_
	functionMap["GiveDriveInfo"] = std::bind(&Task::GiveDriveInfo, this);
	functionFromServerMap["ExplorerInfo"] = &Task::ExplorerInfo_;

	// Collect
    functionFromServerMap["GetCollectInfo"] = &Task::GetCollectInfo;
    
	// Image
	functionFromServerMap["GetImage"] = &Task::GetImage;

	// Update Agent 
	functionFromServerMap["UpdateAgent"] = &Task::OpenUpdateAgentProcess;

	functionFromServerMap["YaraRule"] = &Task::YaraRule;

	// TerminateAll
	functionFromServerMap["TerminateAll"] = &Task::TerminateAll;

	// RemoveAgent
	functionFromServerMap["RemoveAgent"] = &Task::RemoveAgent;
	functionFromServerMap["RejectAgent"] = &Task::RemoveAgent;

	functionFromServerMap["DataRight"] = &Task::DataRight;
	
    info = infoInstance;
    socketsend = socketSendInstance;
}

void Task::startThread(const std::string& key, std::string functionName) {
    std::any argument;
    auto functionIter = threadMap.find(functionName);
    if (functionIter == threadMap.end()) {
        threadMap[functionName] = std::thread(functionMap[functionName], this, argument);
    }
}

// handshake
int Task::GiveInfo() {

	char* buffer = new char[STRINGMESSAGELEN];
	char* SysInfo = tool.GetSysInfo();
	char* OsStr = GetOSVersion();
	char* cComputerName = tool.GetComputerNameUTF8();
	char* cUserName = tool.GetUserNameUTF8();
	unsigned long long BootTime = tool.GetBootTime();
	DWORD m_DigitalSignatureHash = GetDigitalSignatureHash();
	char* functionName = new char[24];

	// key
	char* KeyNum = new char[36];
	strcpy_s(KeyNum, 36, "NoKey");
	GetThisClientKey(KeyNum);
	strcpy_s(info->UUID, 36, KeyNum);

	// file version
	char* FileVersion = new char[64];
	strcpy_s(FileVersion, 64, "1.0.6");
	strcpy_s(functionName, 24, "GiveInfo");

	int VMret = VirtualMachine(info->MAC);
	if (VMret == 1) snprintf(buffer, STRINGMESSAGELEN, "%s|%s (VM)|%s|%s|%s,%d,%d|%d|%s|%lu", SysInfo, OsStr, cComputerName, cUserName, FileVersion, info->Port, info->DetectPort, BootTime, KeyNum, m_DigitalSignatureHash);
	else if (VMret == 2) snprintf(buffer, STRINGMESSAGELEN, "%s|%s (Oracle)|%s|%s|%s,%d,%d|%d|%s|%lu", SysInfo, OsStr, cComputerName, cUserName, FileVersion, info->Port, info->DetectPort, BootTime, KeyNum, m_DigitalSignatureHash);
	else if (VMret == 3) snprintf(buffer, STRINGMESSAGELEN, "%s|%s (Virtualbox)|%s|%s|%s,%d,%d|%d|%s|%lu", SysInfo, OsStr, cComputerName, cUserName, FileVersion, info->Port, info->DetectPort, BootTime, KeyNum, m_DigitalSignatureHash);
	else snprintf(buffer, STRINGMESSAGELEN, "%s|%s|%s|%s|%s,%d,%d|%d|%s|%lu", SysInfo, OsStr, cComputerName, cUserName, FileVersion, info->Port, info->DetectPort, BootTime, KeyNum, m_DigitalSignatureHash);
    
    return socketsend->SendMessageToServer(functionName, buffer);
}
int Task::OpenCheckthread(StrPacket* udata) {

	// store key into register
	if (strcmp(udata->csMsg, "null")) {
		strcpy_s(info->UUID, 36, udata->csMsg);
		WriteRegisterValue(udata->csMsg);
	}

	return GiveDetectInfoFirst();

}
int Task::GiveDetectInfoFirst() {
	char* buff = new char[STRINGMESSAGELEN];
	char* functionName = new char[24];
	strcpy_s(functionName, 24, "GiveDetectInfoFirst");
	snprintf(buff, STRINGMESSAGELEN, "%d|%d", info->DetectProcess, info->DetectNetwork);
	return socketsend->SendMessageToServer(functionName, buff);
}
int Task::UpdateDetectMode(StrPacket* udata) {

	std::vector<std::string>DetectMode = tool.SplitMsg(udata->csMsg);
	for (int i = 0; i < DetectMode.size(); i++) {
		if (i == 0) info->DetectProcess = DetectMode[i][0] - '0';
		else if (i == 1) info->DetectNetwork = DetectMode[i][0] - '0';
		else log.logger("Error", "UpdateDetectMode parse failed");
	}

	if (info->DetectProcess) {
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
	else {
		auto it = info->processMap.find("DetectProcess");
		if (it != info->processMap.end() && it->second != 0 ) {
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, info->processMap["DetectProcess"]);
			if (hProcess) {
				TerminateProcess(hProcess, 0);
				CloseHandle(hProcess);
			}
		}
	}

	if (info->DetectNetwork) {
		DWORD DetectNetworkPid = 0;
		TCHAR* RunExeStr = new TCHAR[MAX_PATH];
		TCHAR* RunComStr = new TCHAR[512];
		GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

		wstring filename = tool.GetFileName();
		TCHAR MyName[MAX_PATH];
		wcscpy_s(MyName, filename.c_str());
		TCHAR ServerIP[MAX_PATH];
		swprintf_s(ServerIP, MAX_PATH, L"%hs", info->ServerIP);

		swprintf_s(RunComStr, 512, L"\"%s\" %s %d DetectNetwork", MyName, ServerIP, info->Port);
		wprintf(L"Run Process: %ls\n", RunComStr);
		RunProcessEx(RunExeStr, RunComStr, 1024, FALSE, FALSE, DetectNetworkPid);

		info->processMap["DetectNetwork"] = DetectNetworkPid;
		log.logger("Debug", "DetectNetwork enabled");
	}
	else {
		auto it = info->processMap.find("DetectNetwork");
		if (it != info->processMap.end() && it->second != 0) {
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, info->processMap["DetectNetwork"]);
			if (hProcess) {
				TerminateProcess(hProcess, 0);
				CloseHandle(hProcess);
			}
		}
	}

	return GiveDetectInfo();

}
int Task::GiveDetectInfo() {
	char* buff = new char[STRINGMESSAGELEN];
	char* functionName = new char[24];
	strcpy_s(functionName, 24, "GiveDetectInfo");
	snprintf(buff, STRINGMESSAGELEN, "%d|%d", info->DetectProcess, info->DetectNetwork);
	int ret = socketsend->SendMessageToServer(functionName, buff);

	return ret;
}
int Task::CheckConnect() {

     while(true){
		 char* functionName = new char[24];
		 strcpy_s(functionName, 24, "CheckConnect");
		 char* null = new char[1];
		 strcpy_s(null, 1, "");
         if (!socketsend->SendMessageToServer(functionName, null)) {
			 log.logger("Error", "CheckConnect sent failed");
         }
		 std::this_thread::sleep_for(std::chrono::seconds(30));
     }

    // to do
    // check kill time

    return 0;
}

// scan
int Task::GetScan(StrPacket* udata) {
	DWORD m_ScanProcessPid = 0;
	TCHAR* RunExeStr = new TCHAR[MAX_PATH];
	TCHAR* RunComStr = new TCHAR[512];
	GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

	wstring filename = tool.GetFileName();
	TCHAR MyName[MAX_PATH];
	wcscpy_s(MyName, filename.c_str());

	TCHAR ServerIP[MAX_PATH];
	swprintf_s(ServerIP, MAX_PATH, L"%hs", info->ServerIP);

	swprintf_s(RunComStr, 512, L"\"%s\" %s %d Scan", MyName, ServerIP, info->Port);
	wprintf(L"Run Process: %ls\n", RunComStr);
	RunProcessEx(RunExeStr, RunComStr, 1024, FALSE, FALSE, m_ScanProcessPid);

	info->processMap["Scan"] = m_ScanProcessPid;
	log.logger("Debug", "Scan enabled");

	return 1;

}

// Explorer
int Task::GetDrive(StrPacket* udata) { return GiveDriveInfo(); }
int Task::GiveDriveInfo() { 
	char* m_DriveInfo = GetMyPCDrive();
	char* functionName = new char[24];
	strcpy_s(functionName, 24, "GiveDriveInfo");
	int ret = socketsend->SendMessageToServer(functionName, m_DriveInfo);
	return ret;
}
char* Task::GetMyPCDrive()
{
	char* driveStr = new char[STRINGMESSAGELEN];
	driveStr[0] = '\0';

	//strcat_s(driveStr, STRINGMESSAGELEN, "F-FAT32,USB|C-NTFS,HDD|");
	for (int i = 2; i < 26; i++)
	{
		char* drive = new char[10];
		strcpy_s(drive, 10, GetDriveStr(i));
		UINT type = GetDriveTypeA(drive);
		if (!(type == DRIVE_FIXED || type == DRIVE_REMOVABLE))
		{
			delete[] drive;
			continue;
		}
		char* volname = new char[_MAX_FNAME];
		char* filesys = new char[_MAX_FNAME];
		DWORD VolumeSerialNumber, MaximumComponentLength, FileSystemFlags;
		if (GetVolumeInformationA(drive, volname, _MAX_FNAME, &VolumeSerialNumber, &MaximumComponentLength, &FileSystemFlags, filesys, _MAX_FNAME))
		{
			//drive.Remove(L'\\');
			for (int j = (int)strlen(drive) - 1; j >= 0; j--)
			{
				if (drive[j] == ':')
				{
					drive[j] = '\x0';
					break;
				}
			}
			if (type == DRIVE_FIXED)
			{
				if (!strcmp(filesys, "NTFS") || !strcmp(filesys, "FAT32")) {
					strcat_s(driveStr, STRINGMESSAGELEN, drive);
					strcat_s(driveStr, STRINGMESSAGELEN, "-");
					strcat_s(driveStr, STRINGMESSAGELEN, filesys);
					strcat_s(driveStr, STRINGMESSAGELEN, ",HDD");
					strcat_s(driveStr, STRINGMESSAGELEN, "|");
				}

				/*strcat_s(driveStr, STRINGMESSAGELEN, drive);
				strcat_s(driveStr, STRINGMESSAGELEN, "-");
				strcat_s(driveStr, STRINGMESSAGELEN, filesys);
				strcat_s(driveStr, STRINGMESSAGELEN, ",HDD");
				strcat_s(driveStr, STRINGMESSAGELEN, "|");*/
			}
			else if (type == DRIVE_REMOVABLE)
			{
				if (!strcmp(filesys, "NTFS") || !strcmp(filesys, "FAT32")) {
					strcat_s(driveStr, STRINGMESSAGELEN, drive);
					strcat_s(driveStr, STRINGMESSAGELEN, "-");
					strcat_s(driveStr, STRINGMESSAGELEN, filesys);
					strcat_s(driveStr, STRINGMESSAGELEN, ",USB");
					strcat_s(driveStr, STRINGMESSAGELEN, "|");
				}

				/*strcat_s(driveStr, STRINGMESSAGELEN, drive);
				strcat_s(driveStr, STRINGMESSAGELEN, "-");
				strcat_s(driveStr, STRINGMESSAGELEN, filesys);
				strcat_s(driveStr, STRINGMESSAGELEN, ",USB");
				strcat_s(driveStr, STRINGMESSAGELEN, "|");*/
			}
		}
		delete[] filesys;
		delete[] volname;
		delete[] drive;
	}
	return driveStr;
}
int Task::ExplorerInfo_(StrPacket* udata) {

	char delimiter[] = "| ";
	char Drive[2]; 
	//char FileSystem[20];
	char* FileSystem = new char[20];

	char* context; 

	char* token = strtok_s(udata->csMsg, delimiter, &context);
	if (token != nullptr) {
		strncpy_s(Drive, sizeof(Drive), token, _TRUNCATE);

		token = strtok_s(nullptr, delimiter, &context);
		if (token != nullptr) {
			strncpy_s(FileSystem, sizeof(FileSystem), token, _TRUNCATE);
		}
	}

	//char* token = strtok_s(udata->csMsg, &delimiter, &context);
	//if (token != nullptr) {
	//	/*strncpy_s(Drive, sizeof(Drive), token, sizeof(Drive) - 1);
	//	Drive[sizeof(Drive) - 1] = '\0';*/
	//	strncpy_s(Drive, sizeof(Drive), token, _TRUNCATE);
	//	log.logger("Debug token", token);

	//	token = strtok_s(nullptr, &delimiter, &context);
	//	if (token != nullptr) {
	//		//strcpy_s(FileSystem, 20, token);
	//		strncpy_s(FileSystem, sizeof(FileSystem), token, _TRUNCATE);
	//		log.logger("Debug token", token);
	//		//strncpy_s(FileSystem, sizeof(FileSystem), token, sizeof(FileSystem) - 1);
	//		//FileSystem[sizeof(FileSystem) - 1] = '\0';
	//	}
	//}

	DWORD ExplorerProcessPid = 0;
	TCHAR* RunExeStr = new TCHAR[MAX_PATH];
	TCHAR* RunComStr = new TCHAR[512];
	GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

	wstring filename = tool.GetFileName();
	TCHAR MyName[MAX_PATH];
	wcscpy_s(MyName, filename.c_str());
	TCHAR ServerIP[MAX_PATH];
	swprintf_s(ServerIP, MAX_PATH, L"%hs", info->ServerIP);
	TCHAR Drive_[MAX_PATH];
	swprintf_s(Drive_, MAX_PATH, L"%hs", Drive);
	TCHAR FileSystem_[MAX_PATH];
	swprintf_s(FileSystem_, MAX_PATH, L"%hs", FileSystem);

	swprintf_s(RunComStr, 512, L"\"%s\" %s %d Explorer %s %s", MyName, ServerIP, info->Port, Drive_, FileSystem_);
	wprintf(L"Run Process: %ls\n", RunComStr);
	RunProcessEx(RunExeStr, RunComStr, 1024, FALSE, FALSE, ExplorerProcessPid);

	info->processMap["Explorer"] = ExplorerProcessPid;
	log.logger("Debug", "Explorer enabled");

	return 1;
}

// Collect
int Task::GetCollectInfo(StrPacket* udata) { 
	wchar_t* m_Path = new wchar_t[MAX_PATH_EX];
	GetMyPath(m_Path);
	tool.DeleteAllCsvFiles(m_Path);

	DWORD CollectProcessPid = 0;
	TCHAR* RunExeStr = new TCHAR[MAX_PATH];
	TCHAR* RunComStr = new TCHAR[512];
	GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

	wstring filename = tool.GetFileName();
	TCHAR MyName[MAX_PATH];
	wcscpy_s(MyName, filename.c_str());
	TCHAR ServerIP[MAX_PATH];
	swprintf_s(ServerIP, MAX_PATH, L"%hs", info->ServerIP);

	swprintf_s(RunComStr, 512, L"\"%s\" %s %d Collect", MyName, ServerIP, info->Port);
	wprintf(L"Run Process: %ls\n", RunComStr);
	RunProcessEx(RunExeStr, RunComStr, 1024, FALSE, FALSE, CollectProcessPid);

	info->processMap["Collect"] = CollectProcessPid;
	log.logger("Debug", "Collect enabled");
	
	return 1; 
}

// Image
int Task::GetImage(StrPacket* udata) {

	DWORD m_ImageProcessPid = 0;
	TCHAR* RunExeStr = new TCHAR[MAX_PATH];
	TCHAR* RunComStr = new TCHAR[1024];
	GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

	wstring filename = tool.GetFileName();
	TCHAR MyName[MAX_PATH];
	wcscpy_s(MyName, filename.c_str());

	TCHAR ServerIP[MAX_PATH];
	swprintf_s(ServerIP, MAX_PATH, L"%hs", info->ServerIP);

	swprintf_s(RunComStr, 4096, L"\"%s\" %s %d Image %hs", MyName, ServerIP, info->Port, udata->csMsg); // space may not be enough
	RunProcessEx(RunExeStr, RunComStr, 4096, FALSE, FALSE, m_ImageProcessPid);

	info->processMap["Image"] = m_ImageProcessPid;
	log.logger("Debug", "Image enabled");

	return 1;

}

// UpdateAgent
int Task::OpenUpdateAgentProcess(StrPacket* udata) {

	DWORD m_UpdateAgentProcessPid = 0;
	TCHAR* RunExeStr = new TCHAR[MAX_PATH];
	TCHAR* RunComStr = new TCHAR[512];
	GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

	wstring filename = tool.GetFileName();
	TCHAR MyName[MAX_PATH];
	wcscpy_s(MyName, filename.c_str());

	TCHAR ServerIP[MAX_PATH];
	swprintf_s(ServerIP, MAX_PATH, L"%hs", info->ServerIP);

	swprintf_s(RunComStr, 512, L"\"%s\" %s %d UpdateAgent", MyName, ServerIP, info->Port);
	wprintf(L"Run Process: %ls\n", RunComStr);
	RunProcessEx(RunExeStr, RunComStr, 1024, FALSE, FALSE, m_UpdateAgentProcessPid);

	info->processMap["UpdateAgent"] = m_UpdateAgentProcessPid;
	log.logger("Debug", "UpdateAgent enabled");

	return 1;

}

int Task::YaraRule(StrPacket* udata) {
	DWORD m_YaraRuleProcessPid = 0;
	TCHAR* RunExeStr = new TCHAR[MAX_PATH];
	TCHAR* RunComStr = new TCHAR[512];
	GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

	wstring filename = tool.GetFileName();
	TCHAR MyName[MAX_PATH];
	wcscpy_s(MyName, filename.c_str());

	TCHAR ServerIP[MAX_PATH];
	swprintf_s(ServerIP, MAX_PATH, L"%hs", info->ServerIP);

	swprintf_s(RunComStr, 512, L"\"%s\" %s %d YaraRule", MyName, ServerIP, info->Port);
	wprintf(L"Run Process: %ls\n", RunComStr);
	RunProcessEx(RunExeStr, RunComStr, 1024, FALSE, FALSE, m_YaraRuleProcessPid);

	std::wstring wstr = RunExeStr;
	int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
	std::string str(bufferSize, '\0');
	WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], bufferSize, nullptr, nullptr);

	info->processMap["YaraRule"] = m_YaraRuleProcessPid;
	log.logger("Debug", "YaraRule enabled.");

	return 1;
}

// Terminate Task
int Task::TerminateAll(StrPacket* udata) {

	//DWORD m_ImageProcessPid = 0;
	//TCHAR* RunExeStr = new TCHAR[MAX_PATH];
	//TCHAR* RunComStr = new TCHAR[1024];
	//GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

	//wstring filename = tool.GetFileName();
	//TCHAR MyName[MAX_PATH];
	//wcscpy_s(MyName, filename.c_str());

	//TCHAR ServerIP[MAX_PATH];
	//swprintf_s(ServerIP, MAX_PATH, L"%hs", info->ServerIP);

	//swprintf_s(RunComStr, 4096, L"\"%s\" %s %d TerminateAll %hs", MyName, ServerIP, info->Port, udata->csMsg); // space may not be enough
	//RunProcessEx(RunExeStr, RunComStr, 4096, FALSE, FALSE, m_ImageProcessPid);

	//info->processMap["TerminateAll"] = m_ImageProcessPid;
	//log.logger("Debug", "TerminateAll enabled");

	char* null = new char[DATASTRINGMESSAGELEN];
	sprintf_s(null, DATASTRINGMESSAGELEN, "null");

	for (const auto& entry : info->processMap) {
		if (entry.first == "Log" || entry.first == "DetectProcess" || entry.first == "DetectNetwork") continue;
		if (entry.second != 0) {
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, entry.second);
			if (hProcess) {
				TerminateProcess(hProcess, 0);
				CloseHandle(hProcess);
			}
		}
	}

	int ret = SendDataPacketToServer("FinishTerminate", null, info->tcpSocket);

	return 1;

}

// Remove Agent
int Task::RemoveAgent(StrPacket* udata) {
#if defined _M_IX86
	UnloadNTDriver(DRIVER_ENUMPROCESS);
#endif
	wchar_t* myfilepath = new wchar_t[MAX_PATH];
	GetModuleFileName(GetModuleHandle(NULL), myfilepath, MAX_PATH);
	wchar_t Folderpath[MAX_PATH];
#ifndef _M_IX86
	int m_csidl = CSIDL_PROGRAM_FILESX86;
#else
	int m_csidl = CSIDL_PROGRAM_FILES;
#endif
	if (SHGetSpecialFolderPath(NULL, Folderpath, m_csidl, false))
	{
		wcscat_s(Folderpath, MAX_PATH, L"\\eDetectorClient");
		wchar_t* ServicePath = new wchar_t[MAX_PATH];
		swprintf_s(ServicePath, MAX_PATH, L"%s\\iForensicsService.exe", Folderpath);
		if (!_waccess(ServicePath, 00))
		{
			wchar_t* CommandLine = new wchar_t[_MAX_PATH];
			swprintf_s(CommandLine, _MAX_PATH, L"/c \"%s\" /uninstall", ServicePath);
			CmdCommandWork(CommandLine, true);
			swprintf_s(CommandLine, _MAX_PATH, L"/c c:\\windows\\system32\\sc.exe delete iForensics_ClientSearch_Service");
			CmdCommandWork(CommandLine, true);
			//if(FindPID(L"iForensicsService.exe")!=0)
			//{
			swprintf_s(CommandLine, _MAX_PATH, L"/c c:\\windows\\system32\\taskkill.exe /f /im iForensicsService.exe & c:\\windows\\system32\\ping.exe 127.0.0.1 -n 2");
			CmdCommandWork(CommandLine, true);
			//}
			delete[] CommandLine;
		}
		delete[] ServicePath;

		FolderClear(Folderpath, const_cast<TCHAR*>(_T("\\*.*")));

		wchar_t* CommandLine = new wchar_t[512];

		swprintf_s(CommandLine, 512, L"/c c:\\windows\\system32\\taskkill.exe /f /im ClientSearch.exe");
		CmdCommandWork(CommandLine, false);
		swprintf_s(CommandLine, 512, L"/c c:\\windows\\system32\\ping.exe 127.0.0.1 -n 2 & erase /F \"%s\"", myfilepath);
		CmdCommandWork(CommandLine, false);
		swprintf_s(CommandLine, 512, L"/c c:\\windows\\system32\\ping.exe 127.0.0.1 -n 2 & rd \"%s\" /s /q", Folderpath);
		CmdCommandWork(CommandLine, false);

		delete[] CommandLine;
	}
	delete[] myfilepath;
	return 1;
}


int Task::SendDataPacketToServer(const char* function, char* buff, SOCKET* tcpSocket) {
	char* functionName = new char[24];
	strcpy_s(functionName, 24, function);
	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
}
int Task::SendMessagePacketToServer(const char* function, char* buff) {
	char* functionName = new char[24];
	strcpy_s(functionName, 24, function);
	return socketsend->SendMessageToServer(functionName, buff);
}
void Task::SendFileToServer(const char* feature, const TCHAR* FileName, SOCKET* tcpSocket) {

	HANDLE m_File = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (m_File != INVALID_HANDLE_VALUE)
	{
		DWORD m_Filesize = GetFileSize(m_File, NULL);
		int Sendret = 1;
		char* InfoStr = new char[MAX_PATH_EX];
		sprintf_s(InfoStr, MAX_PATH_EX, "%lu", m_Filesize);

		char* TmpBuffer = new char[DATASTRINGMESSAGELEN];
		memset(TmpBuffer, '\x0', DATASTRINGMESSAGELEN);
		memcpy(TmpBuffer, InfoStr, strlen(InfoStr));

		if (!strcmp(feature, "Collect")) Sendret = SendDataPacketToServer("GiveCollectDataInfo", TmpBuffer, tcpSocket);
		else if (!strcmp(feature, "Image")) Sendret = SendDataPacketToServer("GiveImageInfo", TmpBuffer, tcpSocket);

		if (Sendret > 0)
		{
			DWORD readsize;
			BYTE* buffer = new BYTE[m_Filesize];
			ReadFile(m_File, buffer, m_Filesize, &readsize, NULL);
			if (m_Filesize > DATASTRINGMESSAGELEN) {
				DWORD tmplen = m_Filesize;
				for (DWORD i = 0; i < m_Filesize; i += DATASTRINGMESSAGELEN) {
					memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
					if (tmplen < DATASTRINGMESSAGELEN) { memcpy(TmpBuffer, buffer + i, tmplen); }
					else {
						memcpy(TmpBuffer, buffer + i, DATASTRINGMESSAGELEN);
						tmplen -= DATASTRINGMESSAGELEN;
					}
					
					if (!strcmp(feature, "Scan")) Sendret = SendDataPacketToServer("GiveScan", TmpBuffer, tcpSocket);
					else if (!strcmp(feature, "Explorer")) Sendret = SendDataPacketToServer("GiveExplorerData", TmpBuffer, tcpSocket);
					else if (!strcmp(feature, "Collect")) Sendret = SendDataPacketToServer("GiveCollectData", TmpBuffer, tcpSocket);
					else if (!strcmp(feature, "Image")) Sendret = SendDataPacketToServer("GiveImage", TmpBuffer, tcpSocket);
					else log.logger("Error", "feature not found");

					
					if (Sendret == 0 || Sendret == -1) break;
				}
				memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
			}
			else
			{
				memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
				memcpy(TmpBuffer, buffer, m_Filesize);

				if (!strcmp(feature, "Scan")) Sendret = SendDataPacketToServer("GiveScan", TmpBuffer, tcpSocket);
				else if (!strcmp(feature, "Explorer")) Sendret = SendDataPacketToServer("GiveExplorerData", TmpBuffer, tcpSocket);
				else if (!strcmp(feature, "Collect")) Sendret = SendDataPacketToServer("GiveCollectData", TmpBuffer, tcpSocket);
				else if (!strcmp(feature, "Image")) Sendret = SendDataPacketToServer("GiveImage", TmpBuffer, tcpSocket);
				else log.logger("Error", "feature not found");

				memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);

			}
			delete[] buffer;
		}

		if (Sendret > 0)
		{
			memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
			wchar_t* m_Path = new wchar_t[MAX_PATH_EX];
			GetMyPath(m_Path);

			if (!strcmp(feature, "Scan")) Sendret = SendDataPacketToServer("GiveScan", TmpBuffer, tcpSocket);
			else if (!strcmp(feature, "Explorer")) Sendret = SendDataPacketToServer("GiveExplorerEnd", TmpBuffer, tcpSocket);
			else if (!strcmp(feature, "Collect")) { 
				Sendret = SendDataPacketToServer("GiveCollectDataEnd", TmpBuffer, tcpSocket); 
				tool.DeleteAllCsvFiles(m_Path);
			}
			else if (!strcmp(feature, "Image")) Sendret = SendDataPacketToServer("GiveImageEnd", TmpBuffer, tcpSocket);
			else log.logger("Error", "feature not found");

			CloseHandle(m_File);

		}
	}
	else
	{
		log.logger("Error", "failed to send zip file\n");
		BYTE* TmpBuffer = new BYTE[DATASTRINGMESSAGELEN];
		memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
		delete[] TmpBuffer;
	}
}
SOCKET* Task::CreateNewSocket() {
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cerr << "Failed to initialize Winsock." << std::endl;
		return nullptr;
	}

	SOCKET* tcpSocket = new SOCKET;
	*tcpSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (*tcpSocket == INVALID_SOCKET) {
		std::cerr << "Error creating TCP socket: " << WSAGetLastError() << std::endl;
		WSACleanup();
		return nullptr;
	}

	sockaddr_in serverAddr;
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(1989);
	serverAddr.sin_addr.s_addr = inet_addr(info->ServerIP);
	//serverAddr.sin_addr.s_addr = inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);

	if (connect(*tcpSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
		std::cerr << "Error connecting to server: " << WSAGetLastError() << std::endl;
		closesocket(*tcpSocket);
		WSACleanup();
		return nullptr;
	}

	return tcpSocket;
}
int Task::DataRight(StrPacket* udata) { return 1; }
