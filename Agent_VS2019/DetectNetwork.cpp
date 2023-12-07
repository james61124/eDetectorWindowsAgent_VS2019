#include "DetectNetwork.h"

DetectNetwork::DetectNetwork(Info* infoInstance, SocketSend* socketSendInstance, int pid) {
	info = infoInstance;
	socketsend = socketSendInstance;
	pMainProcessid = pid;
}
void DetectNetwork::DoTask() {
	char* functionName = new char[24];
	strcpy_s(functionName, 24, "GiveDetectNetwork");

	MemProcess* m_MemPro = new MemProcess;

	TCHAR* MyPath = new TCHAR[MAX_PATH_EX];
	GetModuleFileName(GetModuleHandle(NULL), MyPath, MAX_PATH_EX);
	clock_t start, end;
	time_t NetworkClock;
	m_MemPro->m_NetworkHistory1.clear();
	m_MemPro->m_NetworkHistory2.clear();
	m_MemPro->pNetworkHistory = &m_MemPro->m_NetworkHistory1;
	m_MemPro->NetworkHistoryNum = 1;

	//pNetworkHistory->push_back(m_HandStr);
	set<u_short> m_ListenPort;
	map<wstring, u_short> StartNetworkInfo;
	map<wstring, u_short> NewNetworkInfo;
	map<wstring, u_short>::iterator nst;
	map<wstring, u_short>::iterator nnt;
	set<u_short>::iterator lt;
	char* OSstr = GetOSVersion();
	if ((strstr(OSstr, "Windows XP") != 0) || (strstr(OSstr, "Windows Server 2003") != 0))
		GetDetectTcpInformationXP(&StartNetworkInfo, &m_ListenPort);
	else
		GetDetectTcpInformation(&StartNetworkInfo, &m_ListenPort);

	time(&NetworkClock);
	for (nst = StartNetworkInfo.begin();nst != StartNetworkInfo.end();nst++)
	{
		DWORD m_Pid = m_MemPro->GetInfoPid(/*(*nst).c_str()*/nst->first.c_str());
		if (m_Pid != 0)
		{
			TCHAR* m_NetworkStr = new TCHAR[2048];
			TCHAR* m_Path = new TCHAR[512];
			//TCHAR * m_ComStr = new TCHAR[512];
			time_t m_Time = 0;
			//TCHAR * m_UserName = new TCHAR[_MAX_FNAME];
			_tcscpy_s(m_Path, 512, _T("null"));
			//_tcscpy_s(m_ComStr,512,_T("null"));
			//_tcscpy_s(m_Time,20,_T("null"));
			//_tcscpy_s(m_UserName,_MAX_FNAME,_T("null"));
			//GetProcessInfo(m_Pid,m_Path,m_Time,m_UserName,m_ComStr);
			m_MemPro->GetProcessOnlyPathAndTime(m_Pid, m_Path, m_Time);
			if (_tcsicmp(m_Path, MyPath))
			{
				int ConnectionINorOUT = 0;
				lt = m_ListenPort.find(nst->second);
				if (lt != m_ListenPort.end())
					ConnectionINorOUT = 1;
				swprintf_s(m_NetworkStr, 2048, _T("%s|%lld|%lld|%d|%u\n"), nst->first.c_str(), NetworkClock, m_Time, ConnectionINorOUT, nst->second);
				char* cNetworkStr = CStringToCharArray(m_NetworkStr, CP_UTF8);
				char m_WriteStr[2048];
				sprintf_s(m_WriteStr, 2048, "%s", cNetworkStr);
				if (m_MemPro->pNetworkHistory->size() >= 3000000)
				{
					m_MemPro->pNetworkHistory->erase(m_MemPro->pNetworkHistory->begin());
					m_MemPro->pNetworkHistory->push_back(m_WriteStr);
				}
				else
					m_MemPro->pNetworkHistory->push_back(m_WriteStr);
				delete[] cNetworkStr;
			}
			//delete [] m_UserName;
			//delete [] m_Time;
			//delete [] m_ComStr;
			delete[] m_Path;
			delete[] m_NetworkStr;
		}
	}
	start = clock();
	for (;;)
	{
		m_ListenPort.clear();
		NewNetworkInfo.clear();
		if ((strstr(OSstr, "Windows XP") != 0) || (strstr(OSstr, "Windows Server 2003") != 0))
			GetDetectTcpInformationXP(&NewNetworkInfo, &m_ListenPort);
		else
			GetDetectTcpInformation(&NewNetworkInfo, &m_ListenPort);

		time(&NetworkClock);
		for (nnt = NewNetworkInfo.begin();nnt != NewNetworkInfo.end();nnt++)
		{
			nst = StartNetworkInfo.find(nnt->first.c_str());
			if (nst == StartNetworkInfo.end())
			{
				DWORD m_Pid = m_MemPro->GetInfoPid(nnt->first.c_str());
				if (m_Pid != 0)
				{
					TCHAR* m_NetworkStr = new TCHAR[2048];
					TCHAR* m_Path = new TCHAR[512];
					time_t m_Time = 0;
					_tcscpy_s(m_Path, 512, _T("null"));
					m_MemPro->GetProcessOnlyPathAndTime(m_Pid, m_Path, m_Time);
					if (_tcsicmp(m_Path, MyPath))
					{
						int ConnectionINorOUT = 0;
						lt = m_ListenPort.find(nnt->second);
						if (lt != m_ListenPort.end())
							ConnectionINorOUT = 1;
						swprintf_s(m_NetworkStr, 2048, _T("%s|%lld|%lld|%d|%u\n"), nnt->first.c_str(), NetworkClock, m_Time, ConnectionINorOUT, nnt->second);
						char* cNetworkStr = CStringToCharArray(m_NetworkStr, CP_UTF8);
						char m_WriteStr[2048];
						sprintf_s(m_WriteStr, 2048, "%s", cNetworkStr);
						if (m_MemPro->pNetworkHistory->size() >= 3000000)
						{
							m_MemPro->pNetworkHistory->erase(m_MemPro->pNetworkHistory->begin());
							m_MemPro->pNetworkHistory->push_back(m_WriteStr);
						}
						else
							m_MemPro->pNetworkHistory->push_back(m_WriteStr);
						delete[] cNetworkStr;
					}
					//delete [] m_UserName;
					//delete [] m_Time;
					//delete [] m_ComStr;
					delete[] m_Path;
					delete[] m_NetworkStr;
				}
			}
		}
		end = clock();
		if ((end - start) > 30000)
		{
			if (!m_MemPro->pNetworkHistory->empty())
			{
				if (m_MemPro->NetworkHistoryNum == 1)
				{
					m_MemPro->ChangeNetworkHistoryNum(1);
					vector<string>* pNetworkHistory = m_MemPro->GetNetworkHistory1();
					if (!pNetworkHistory->empty())
					{
						SendNetworkDetectToServer(pNetworkHistory);
					}

				}
				else if (m_MemPro->NetworkHistoryNum == 2)
				{
					m_MemPro->ChangeNetworkHistoryNum(2);
					vector<string>* pNetworkHistory = m_MemPro->GetNetworkHistory2();
					if (!pNetworkHistory->empty())
					{
						SendNetworkDetectToServer(pNetworkHistory);
					}

				}
			}
			start = clock();
		}
		StartNetworkInfo.clear();
		StartNetworkInfo = NewNetworkInfo;
		if (!IsHavePID(pMainProcessid))
			break;
		Sleep(100);
	}
	m_ListenPort.clear();
	NewNetworkInfo.clear();
	StartNetworkInfo.clear();
	m_MemPro->m_NetworkHistory1.clear();
	m_MemPro->m_NetworkHistory2.clear();
	delete[] MyPath;
}

void DetectNetwork::SendNetworkDetectToServer(vector<string>* pInfo)
{
	int m_Count = 0;
	int ret = 1;
	char* TmpSend = new char[DATASTRINGMESSAGELEN];
	memset(TmpSend, '\0', DATASTRINGMESSAGELEN);

	vector<string>::iterator it;
	for (it = pInfo->begin();it != pInfo->end();it++)
	{
		if ((*it).size() >= DATASTRINGMESSAGELEN)
			continue;
		int TmpSize = (int)strlen(TmpSend);
		if ((TmpSize + (int)(*it).size()) >= DATASTRINGMESSAGELEN)
		{
			ret = SendDataPacketToServer("GiveDetectNetwork", TmpSend, info->tcpSocket);
			if (ret <= 0)
				break;
			else
				memset(TmpSend, '\0', DATASTRINGMESSAGELEN);
		}
		strcat_s(TmpSend, DATASTRINGMESSAGELEN, (*it).c_str());
	}

	if (ret > 0)
	{
		ret = SendDataPacketToServer("GiveDetectNetwork", TmpSend, info->tcpSocket);
		pInfo->clear();
	}

	delete[] TmpSend;
}