#include "YaraRule.h"



// has to deal with libyara64.dll
YaraRule::YaraRule(Info* infoInstance, SocketSend* socketSendInstance) {
	info = infoInstance;
	socketsend = socketSendInstance;
}

void YaraRule::DoTask() {
	char* null = new char[1];
	strcpy_s(null, 1, "");

	SendMessagePacketToServer("ReadyUpdateAgent", null);

	int fileSize = GiveYaraRuleInfo();
	std::thread AgentReceiveThread([&]() { YaraRuleReceive(fileSize); });
	if (!fileSize) {
		log.logger("Error", "Error receiving YaraRule Info");
	}

	SendMessagePacketToServer("DataRight", null);
	AgentReceiveThread.join();
	SendMessagePacketToServer("DataRight", null);

	// unzip YaraRule.zip
	TCHAR* m_FilePath = new TCHAR[MAX_PATH_EX];
	GetMyPath(m_FilePath);
	_tcscat_s(m_FilePath, MAX_PATH_EX, _T("\\YaraRule.zip"));
	HANDLE m_File = CreateFile(m_FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD m_Filesize = GetFileSize(m_File, NULL);
	DWORD readsize;
	BYTE* buffer = new BYTE[m_Filesize];
	if (m_File != INVALID_HANDLE_VALUE) {
		m_Filesize = GetFileSize(m_File, NULL);
		ReadFile(m_File, buffer, m_Filesize, &readsize, NULL);
	}

	HZIP hz;
	ZRESULT zr;
	ZIPENTRY ze;
	BYTE* buf;
	DWORD pSize = 0;
	hz = OpenZip(buffer, m_Filesize, 0);
	zr = GetZipItem(hz, -1, &ze);
	int numitems = ze.index;
	TCHAR* UnZipName = new TCHAR[MAX_PATH];
	for (int i = 0; i < numitems; i++) {
		GetZipItem(hz, i, &ze);
		UnzipItem(hz, i, ze.name);
	}
	zr = CloseZip(hz);




}

int YaraRule::GiveYaraRuleInfo() {
	char buff[STRPACKETSIZE];
	int ret = recv(*info->tcpSocket, buff, sizeof(buff), 0);

	if (ret == SOCKET_ERROR) {
		std::cerr << "Error receiving ACK: " << WSAGetLastError() << std::endl;
		return 0;
	}

	SetKeys(BIT128, AESKey);
	DecryptBuffer((BYTE*)buff, STRPACKETSIZE);

	StrPacket* udata;
	udata = (StrPacket*)buff;
	std::string Task(udata->DoWorking);
	std::string TaskMsg(udata->csMsg);
	std::string LogMsg = "Receive: " + Task + " " + TaskMsg;
	log.logger("Info", LogMsg);

	if (!strcmp(udata->DoWorking, "GiveYaraRuleInfo")) {
		return std::stoi(TaskMsg);
	}
	else {
		return 0;
	}
}

void YaraRule::YaraRuleReceive(int fileSize) {
	int alreadyReceived = 0;
	while (true) {

		uint64_t receivedSize = 0;
		int totalReceivedSize = 0;
		char* buffer = new char[STRDATAPACKETSIZE];

		while (totalReceivedSize < STRDATAPACKETSIZE) {
			char* tmpbuffer = new char[STRDATAPACKETSIZE];
			int bytesRead = recv(*info->tcpSocket, tmpbuffer, STRDATAPACKETSIZE, 0);
			if (bytesRead == -1) {
				log.logger("Error", "YaraRule Error receiving data");
				return;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
			memcpy(buffer + totalReceivedSize, tmpbuffer, bytesRead);
			totalReceivedSize += bytesRead;
			alreadyReceived += bytesRead;

		}
		alreadyReceived -= 100;

		SetKeys(BIT128, AESKey);
		DecryptBuffer((BYTE*)buffer, STRDATAPACKETSIZE);
		StrDataPacket* udata;
		udata = (StrDataPacket*)buffer;

		std::string Task(udata->DoWorking);
		std::string TaskMsg(udata->csMsg);
		std::string LogMsg = "Receive: " + Task;
		log.logger("Info", LogMsg);

		if (!strcmp(udata->DoWorking, "GiveYaraRule")) {
			if (alreadyReceived > fileSize) {
				WriteYaraRuleToFile(udata->csMsg, fileSize % 65436);
			}
			else {
				WriteYaraRuleToFile(udata->csMsg, STRDATAPACKETSIZE - 100);
			}

		}
		else {
			break;
		}

		delete[] buffer;

	}
}

void YaraRule::WriteYaraRuleToFile(char* buffer, int totalReceivedSize) {
	char* null = new char[1];
	strcpy_s(null, 1, "");
	TCHAR* YaraRule_filename = new TCHAR[MAX_PATH_EX];
	GetMyPath(YaraRule_filename);
	_tcscat_s(YaraRule_filename, MAX_PATH_EX, _T("\\YaraRule.zip"));
	DeleteFile(YaraRule_filename);

	std::ofstream outFile(YaraRule_filename, std::ios::app | std::ios::binary);
	if (!outFile.is_open()) {
		log.logger("Error", "YaraRule.yara open failed");
	}
	if (outFile.good()) {
		outFile.write(buffer, totalReceivedSize);
	}
	else {
		log.logger("Error", "Error write data into NewAgent");
	}
	outFile.close();
	SendMessagePacketToServer("DataRight", null);

	YaraManger* yaraManger = new YaraManger();

	TCHAR* YaraRule_folder = new TCHAR[MAX_PATH_EX];
	GetMyPath(YaraRule_folder);
	_tcscat_s(YaraRule_folder, MAX_PATH_EX, _T("\\YaraRule"));
	unsigned int FileIndex = 0;
	SysExplorerSearch(YaraRule_folder, FileIndex, yaraManger, "AddYaraRule");

	yaraManger->GetRules();
	FileIndex = 0;

	TCHAR* drive = new TCHAR[5];
	swprintf_s(drive, 256, L"%s:\\", L"C");
	SysExplorerSearch(drive, FileIndex, yaraManger, "CheckIsMatchYaraRule");


	/*YaraManger* yaraManger = new YaraManger();
	if (!yaraManger->AddRuleFromFile(rule_name)) return;
	yaraManger->GetRules();*/

}

void YaraRule::SysExplorerSearch(TCHAR* m_Path, unsigned int& FileIndex, YaraManger* yaraManger, std::string task)
{

	TCHAR szTempPath[256];
	lstrcpy(szTempPath, m_Path);
	lstrcat(szTempPath, TEXT("*.*"));

	clock_t start, end;
	start = clock();
	WIN32_FIND_DATA fd;
	HANDLE hSearch = FindFirstFile(szTempPath, &fd);
	if (INVALID_HANDLE_VALUE == hSearch)
	{
		printf("INVALID_HANDLE_VALUE\n");
		return;
	}
	do
	{
		if ((0 != (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) && (0 != lstrcmp(fd.cFileName, TEXT("."))) && (0 != lstrcmp(fd.cFileName, TEXT(".."))))/*&& (0 == (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) */
		{
			FileIndex++;
			TCHAR szPath[256];
			swprintf_s(szPath, 256, L"%s%s\\", m_Path, fd.cFileName);
			SysExplorerSearch(szPath, FileIndex, yaraManger, task);

			std::wcout << FileIndex << L": " << szPath << std::endl;

		}
		else if ((0 == (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) && (0 != lstrcmp(fd.cFileName, TEXT("."))) && (0 != lstrcmp(fd.cFileName, TEXT(".."))))
		{
			FileIndex++;
			TCHAR* szPath = new TCHAR[256];
			swprintf_s(szPath, 256, L"%s%s", m_Path, fd.cFileName);

			std::wstring wstr = szPath;
			int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
			std::string str(bufferSize, '\0');
			WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], bufferSize, nullptr, nullptr);

			std::wcout << FileIndex << L": " << szPath << std::endl;

			if( task == "AddYaraRule" ) if (!yaraManger->AddRuleFromFile(str)) return;
			else yaraManger->scanFile(str);

		}
	} while (FindNextFile(hSearch, &fd) != FALSE);
	FindClose(hSearch);

}