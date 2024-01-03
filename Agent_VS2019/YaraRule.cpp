#include "YaraRule.h"



// has to deal with libyara64.dll
YaraRule::YaraRule(Info* infoInstance, SocketSend* socketSendInstance) {
	info = infoInstance;
	socketsend = socketSendInstance;
}

void YaraRule::DoTask() {


	TCHAR* YaraRule_exe = new TCHAR[MAX_PATH_EX];
	GetMyPath(YaraRule_exe);
	_tcscat_s(YaraRule_exe, MAX_PATH_EX, _T("\\libyara.exe"));

	DWORD m_YaraRuleProcessPid = 0;
	TCHAR* RunExeStr = new TCHAR[MAX_PATH];
	TCHAR* RunComStr = new TCHAR[512];
	GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

	swprintf_s(RunComStr, 512, L"\"%s\"", YaraRule_exe);
	wprintf(L"Run Process: %ls\n", RunComStr);
	RunProcessEx(YaraRule_exe, RunComStr, 1024, FALSE, FALSE, m_YaraRuleProcessPid);


	//DWORD m_YaraRuleTestProcessPid = 0;
	//LPSTARTUPINFO lpStartupInfo;
	//LPPROCESS_INFORMATION lpProcessInfo;

	//memset(&lpStartupInfo, 0, sizeof(lpStartupInfo));
	//memset(&lpProcessInfo, 0, sizeof(lpProcessInfo));

	//CreateProcess(YaraRule_exe,
	//	NULL, NULL, NULL,
	//	NULL, NULL, NULL, NULL,
	//	lpStartupInfo,
	//	lpProcessInfo
	//);

	//info->processMap["YaraRuleTest"] = m_YaraRuleTestProcessPid;

	//TCHAR command[MAX_PATH_EX * 2];
	//_tcscpy_s(command, MAX_PATH_EX, YaraRule_exe);
	//int result = _tsystem(command);

	//if (result == 0) {
	//	log.logger("Debug", "execute yararule  suucess");
	//}
	//else {

	//	TCHAR errorMessage[256];
	//	strerror_s(reinterpret_cast<char*>(errorMessage), 256, errno);
	//	std::cerr << "Error executing command. Error Code: " << result << ", Error Message: " << errorMessage << std::endl;

	//	log.logger("Error", to_string(result));
	//}


	/*STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	if (CreateProcess(YaraRule_exe, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	else {
		log.logger("Error", "failed to execute yararule");
	}*/

	//info->processMap["YaraRule"] = m_YaraRuleProcessPid;
	log.logger("Debug", "YaraRuleTest enabled");

	//char* null = new char[1];
	//strcpy_s(null, 1, "");

	//SendMessagePacketToServer("ReadyYaraRule", null);

	//int fileSize = GiveYaraRuleInfo();
	//std::thread AgentReceiveThread([&]() { YaraRuleReceive(fileSize); });
	//if (!fileSize) {
	//	log.logger("Error", "Error receiving YaraRule Info");
	//}

	//SendMessagePacketToServer("DataRight", null);
	//AgentReceiveThread.join();
	//SendMessagePacketToServer("DataRight", null);

	//// unzip YaraRule.zip
	//TCHAR* m_FilePath = new TCHAR[MAX_PATH_EX];
	//GetMyPath(m_FilePath);
	//_tcscat_s(m_FilePath, MAX_PATH_EX, _T("\\YaraRule.zip"));
	//HANDLE m_File = CreateFile(m_FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//DWORD m_Filesize = GetFileSize(m_File, NULL);
	//DWORD readsize;
	//BYTE* buffer = new BYTE[m_Filesize];
	//if (m_File != INVALID_HANDLE_VALUE) {
	//	m_Filesize = GetFileSize(m_File, NULL);
	//	ReadFile(m_File, buffer, m_Filesize, &readsize, NULL);
	//}

	//HZIP hz;
	//ZRESULT zr;
	//ZIPENTRY ze;
	//BYTE* buf;
	//DWORD pSize = 0;
	//hz = OpenZip(buffer, m_Filesize, 0);
	//zr = GetZipItem(hz, -1, &ze);
	//int numitems = ze.index;
	//TCHAR* UnZipName = new TCHAR[MAX_PATH];
	//for (int i = 0; i < numitems; i++) {
	//	GetZipItem(hz, i, &ze);
	//	UnzipItem(hz, i, ze.name);
	//}
	//zr = CloseZip(hz);


	//YaraManger* yaraManger = new YaraManger();

	//TCHAR* YaraRule_folder = new TCHAR[MAX_PATH_EX];
	//GetMyPath(YaraRule_folder);
	//_tcscat_s(YaraRule_folder, MAX_PATH_EX, _T("\\YaraRule"));
	//unsigned int FileIndex = 0;
	//SysExplorerSearch(YaraRule_folder, FileIndex, yaraManger, "AddYaraRule");

	//yaraManger->GetRules();
	//FileIndex = 0;

	//TCHAR* drive = new TCHAR[5];
	//swprintf_s(drive, 256, L"%s:\\", L"C");
	//SysExplorerSearch(drive, FileIndex, yaraManger, "CheckIsMatchYaraRule");

	//TCHAR* YaraRule_txt = new TCHAR[MAX_PATH_EX];
	//GetMyPath(YaraRule_txt);
	//_tcscat_s(YaraRule_txt, MAX_PATH_EX, _T("\\YaraRule.txt"));
	//TCHAR* YaraManager_zip = new TCHAR[MAX_PATH_EX];
	//GetMyPath(YaraManager_zip);
	//_tcscat_s(YaraManager_zip, MAX_PATH_EX, _T("\\YaraManager.zip"));
	//DeleteFile(YaraManager_zip);


	//// Compress YaraRule.txt
	//if (tool.CompressFileToZip(YaraManager_zip, YaraRule_txt)) _tprintf(_T("File compressed and added to ZIP successfully.\n"));
	//else log.logger("Error", "failed to add file to Zip");

	//SendFileToServer("YaraRule", YaraManager_zip, info->tcpSocket);




}

//int YaraRule::GiveYaraRuleInfo() {
//	char buff[STRPACKETSIZE];
//	int ret = recv(*info->tcpSocket, buff, sizeof(buff), 0);
//
//	if (ret == SOCKET_ERROR) {
//		std::cerr << "Error receiving ACK: " << WSAGetLastError() << std::endl;
//		return 0;
//	}
//
//	SetKeys(BIT128, AESKey);
//	DecryptBuffer((BYTE*)buff, STRPACKETSIZE);
//
//	StrPacket* udata;
//	udata = (StrPacket*)buff;
//	std::string Task(udata->DoWorking);
//	std::string TaskMsg(udata->csMsg);
//	std::string LogMsg = "Receive: " + Task + " " + TaskMsg;
//	log.logger("Info", LogMsg);
//
//	if (!strcmp(udata->DoWorking, "GiveYaraRuleInfo")) {
//		return std::stoi(TaskMsg);
//	}
//	else {
//		return 0;
//	}
//}
//
//void YaraRule::YaraRuleReceive(int fileSize) {
//	int alreadyReceived = 0;
//	while (true) {
//
//		uint64_t receivedSize = 0;
//		int totalReceivedSize = 0;
//		char* buffer = new char[STRDATAPACKETSIZE];
//
//		while (totalReceivedSize < STRDATAPACKETSIZE) {
//			char* tmpbuffer = new char[STRDATAPACKETSIZE];
//			int bytesRead = recv(*info->tcpSocket, tmpbuffer, STRDATAPACKETSIZE, 0);
//			if (bytesRead == -1) {
//				log.logger("Error", "YaraRule Error receiving data");
//				return;
//			}
//			std::this_thread::sleep_for(std::chrono::milliseconds(500));
//			memcpy(buffer + totalReceivedSize, tmpbuffer, bytesRead);
//			totalReceivedSize += bytesRead;
//			alreadyReceived += bytesRead;
//
//		}
//		alreadyReceived -= 100;
//
//		SetKeys(BIT128, AESKey);
//		DecryptBuffer((BYTE*)buffer, STRDATAPACKETSIZE);
//		StrDataPacket* udata;
//		udata = (StrDataPacket*)buffer;
//
//		std::string Task(udata->DoWorking);
//		std::string TaskMsg(udata->csMsg);
//		std::string LogMsg = "Receive: " + Task;
//		log.logger("Info", LogMsg);
//
//		if (!strcmp(udata->DoWorking, "GiveYaraRule")) {
//			if (alreadyReceived > fileSize) {
//				WriteYaraRuleToFile(udata->csMsg, fileSize % 65436);
//			}
//			else {
//				WriteYaraRuleToFile(udata->csMsg, STRDATAPACKETSIZE - 100);
//			}
//
//		}
//		else {
//			break;
//		}
//
//		delete[] buffer;
//
//	}
//}
//
//void YaraRule::WriteYaraRuleToFile(char* buffer, int totalReceivedSize) {
//	char* null = new char[1];
//	strcpy_s(null, 1, "");
//	TCHAR* YaraRule_filename = new TCHAR[MAX_PATH_EX];
//	GetMyPath(YaraRule_filename);
//	_tcscat_s(YaraRule_filename, MAX_PATH_EX, _T("\\YaraRule.zip"));
//	DeleteFile(YaraRule_filename);
//
//	std::ofstream outFile(YaraRule_filename, std::ios::app | std::ios::binary);
//	if (!outFile.is_open()) {
//		log.logger("Error", "YaraRule.yara open failed");
//	}
//	if (outFile.good()) {
//		outFile.write(buffer, totalReceivedSize);
//	}
//	else {
//		log.logger("Error", "Error write data into NewAgent");
//	}
//	outFile.close();
//	SendMessagePacketToServer("DataRight", null);
//
//	
//
//}
//
//void YaraRule::SysExplorerSearch(TCHAR* m_Path, unsigned int& FileIndex, YaraManger* yaraManger, std::string task)
//{
//
//	TCHAR szTempPath[256];
//	lstrcpy(szTempPath, m_Path);
//	lstrcat(szTempPath, TEXT("*.*"));
//
//	clock_t start, end;
//	start = clock();
//	WIN32_FIND_DATA fd;
//	HANDLE hSearch = FindFirstFile(szTempPath, &fd);
//	if (INVALID_HANDLE_VALUE == hSearch)
//	{
//		printf("INVALID_HANDLE_VALUE\n");
//		return;
//	}
//	do
//	{
//		if ((0 != (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) && (0 != lstrcmp(fd.cFileName, TEXT("."))) && (0 != lstrcmp(fd.cFileName, TEXT(".."))))/*&& (0 == (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) */
//		{
//			FileIndex++;
//			TCHAR szPath[256];
//			swprintf_s(szPath, 256, L"%s%s\\", m_Path, fd.cFileName);
//			SysExplorerSearch(szPath, FileIndex, yaraManger, task);
//
//			std::wcout << FileIndex << L": " << szPath << std::endl;
//
//		}
//		else if ((0 == (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) && (0 != lstrcmp(fd.cFileName, TEXT("."))) && (0 != lstrcmp(fd.cFileName, TEXT(".."))))
//		{
//			FileIndex++;
//			TCHAR* szPath = new TCHAR[256];
//			swprintf_s(szPath, 256, L"%s%s", m_Path, fd.cFileName);
//
//			std::wstring wstr = szPath;
//			int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
//			std::string str(bufferSize, '\0');
//			WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], bufferSize, nullptr, nullptr);
//
//			std::wcout << FileIndex << L": " << szPath << std::endl;
//
//			log.logger("Debug", str);
//
//			if( task == "AddYaraRule" ) if (!yaraManger->AddRuleFromFile(str)) return;
//			else yaraManger->scanFile(str);
//
//		}
//	} while (FindNextFile(hSearch, &fd) != FALSE);
//	FindClose(hSearch);
//
//}