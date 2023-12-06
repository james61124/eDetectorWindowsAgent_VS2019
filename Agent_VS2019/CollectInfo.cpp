#include "CollectInfo.h"

CollectInfo::CollectInfo(Info* infoInstance, SocketSend* socketSendInstance, int input_i, int input_iLen) {
	info = infoInstance;
	socketsend = socketSendInstance;
	i = input_i;
	iLen = input_iLen;
}

void CollectInfo::DoTask() {
	Collect* collect = new Collect();

	char* InfoStr = new char[MAX_PATH_EX];
	char* TmpBuffer = new char[DATASTRINGMESSAGELEN];
	TCHAR* m_FilePath = new TCHAR[MAX_PATH_EX];
	GetMyPath(m_FilePath);
	_tcscat_s(m_FilePath, MAX_PATH_EX, _T("\\Collection.dll")); // Collection-x64.dll
	HMODULE m_lib = LoadLibrary(m_FilePath);
	if (m_lib) {
		printf("load dll success : %d\n", i);
		TCHAR buffer[20]; // Adjust the buffer size as needed
		_sntprintf_s(buffer, sizeof(buffer) / sizeof(TCHAR), _T("%d"), collect->CollectionNums[i]);
		TCHAR* tcharString = buffer;

		try {
			wchar_t* m_FullDbPath = new wchar_t[MAX_PATH_EX];
			GetMyPath(m_FullDbPath);
			_tcscat_s(m_FullDbPath, MAX_PATH_EX, _T("\\collectcomputerinfo.db"));
			collect->CollectionProcess(m_lib, m_FullDbPath, tcharString);
		}
		catch (...) {
			log.logger("Error", "collect failed");
		}

		FreeLibrary(m_lib);
	}
	else {
		printf("load dll failed\n");
		log.logger("Error", "collection load dll failed\n");
	}

	memset(InfoStr, '\0', MAX_PATH_EX);
	sprintf_s(InfoStr, MAX_PATH_EX, "%d/%d", i + 1, iLen);
	memset(TmpBuffer, '\x0', DATASTRINGMESSAGELEN);
	memcpy(TmpBuffer, InfoStr, strlen(InfoStr));

	int ret = SendDataPacketToServer("GiveCollectProgress", TmpBuffer, info->tcpSocket);
}