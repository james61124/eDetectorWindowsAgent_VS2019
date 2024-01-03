#include "AllTask.h"

int AllTask::SendDataPacketToServer(const char* function, char* buff, SOCKET* tcpSocket) {
	char* functionName = new char[24];
	strcpy_s(functionName, 24, function);
	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
}

int AllTask::SendMessagePacketToServer(const char* function, char* buff) {
	char* functionName = new char[24];
	strcpy_s(functionName, 24, function);
	return socketsend->SendMessageToServer(functionName, buff);
}

void AllTask::SendFileToServer(const char* feature, const TCHAR* FileName, SOCKET* tcpSocket) {

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
		else if (!strcmp(feature, "DumpProcess")) Sendret = SendDataPacketToServer("GiveDumpProcessInfo", TmpBuffer, tcpSocket);
		else if (!strcmp(feature, "YaraRule")) Sendret = SendDataPacketToServer("GiveRuleMatchInfo", TmpBuffer, tcpSocket);

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
					else if (!strcmp(feature, "DumpProcess")) Sendret = SendDataPacketToServer("GiveDumpProcess", TmpBuffer, tcpSocket);
					else if (!strcmp(feature, "YaraRule")) Sendret = SendDataPacketToServer("GiveRuleMatch", TmpBuffer, tcpSocket);
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
				else if (!strcmp(feature, "DumpProcess")) Sendret = SendDataPacketToServer("GiveDumpProcess", TmpBuffer, tcpSocket);
				else if (!strcmp(feature, "YaraRule")) Sendret = SendDataPacketToServer("GiveRuleMatch", TmpBuffer, tcpSocket);
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
			else if (!strcmp(feature, "DumpProcess")) Sendret = SendDataPacketToServer("GiveDumpProcessEnd", TmpBuffer, tcpSocket);
			else if (!strcmp(feature, "YaraRule")) Sendret = SendDataPacketToServer("GiveRuleMatchEnd", TmpBuffer, tcpSocket);
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