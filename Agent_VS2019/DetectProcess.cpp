#include "DetectProcess.h"

DetectProcess::DetectProcess(Info* infoInstance, SocketSend* socketSendInstance) {
	info = infoInstance;
	socketsend = socketSendInstance;
}
void DetectProcess::DoTask() {

	MemProcess* m_MemPro = new MemProcess;
	set<DWORD> m_ApiName;
	tool.LoadApiPattern(&m_ApiName);
	DWORD pMainProcessid = GetCurrentProcessId();

	try {
		DetectProcessRisk(pMainProcessid, false, &m_ApiName, info->tcpSocket);
	}
	catch (...) {}

	m_ApiName.clear();
	delete m_MemPro;
}
int DetectProcess::DetectProcessRisk(int pMainProcessid, bool IsFirst, set<DWORD>* pApiName, SOCKET* tcpSocket)
{
	Log log;
	MemProcess* m_MemPro = new MemProcess;
	TCHAR* MyPath = new TCHAR[MAX_PATH_EX];
	GetModuleFileName(GetModuleHandle(NULL), MyPath, MAX_PATH_EX);
	clock_t start, end;
	clock_t m_BootStart, m_BootEnd;
	m_MemPro->m_RiskArray1.clear();
	m_MemPro->m_RiskArray2.clear();
	m_MemPro->m_UnKnownData1.clear();
	m_MemPro->m_UnKnownData2.clear();
	m_MemPro->pRiskArray = &m_MemPro->m_RiskArray1;
	m_MemPro->RiskArrayNum = 1;
	m_MemPro->pUnKnownData = &m_MemPro->m_UnKnownData1;
	m_MemPro->UnKnownDataNum = 1;

	//char* cBootTime = CStringToCharArray(pBootTime, CP_UTF8);
	bool IsWin10 = false;
	char* OSstr = GetOSVersion();
	if ((strstr(OSstr, "Windows 10") != 0) || (strstr(OSstr, "Windows Server 2016") != 0))
		IsWin10 = true;
	map<DWORD, process_info_Ex> StartProcessID;
	map<DWORD, process_info_Ex> NewProcessID;
	map<DWORD, process_info_Ex>::iterator st;
	map<DWORD, process_info_Ex>::iterator nt;

	//map<DWORD,process_info_Ex>::iterator ft;
	//printf("load now process info start\n");
	m_MemPro->LoadNowProcessInfoDetect(&StartProcessID);
	//printf("load now process info end\n");
	//if (IsFirst)
	//{
	printf("detecting current process...\n");
	log.logger("Info", "detect current process...");
	for (st = StartProcessID.begin(); st != StartProcessID.end(); st++)
	{
		if (!m_MemPro->IsWindowsProcessNormal(&StartProcessID, st->first))
		{
			//log.logger("Debug", "detecting current process...");
			m_MemPro->ParserProcessRisk(&st->second, pApiName, MyPath, m_MemPro->pUnKnownData);
		}
	}
	printf("detect current process finished\n");
	log.logger("Info", "detecting current finished");

	start = clock();
	m_BootStart = clock();
	m_BootEnd = clock();

	for (;;)
	{
		printf("detecting...\n");
		NewProcessID.clear();
		m_MemPro->LoadNowProcessInfoDetect(&NewProcessID);

		for (nt = NewProcessID.begin(); nt != NewProcessID.end(); nt++)
		{
			st = StartProcessID.find(nt->first);
			if (st == StartProcessID.end())
			{
				m_MemPro->ParserProcessRisk(&nt->second, pApiName, MyPath, m_MemPro->pUnKnownData); // LoadAutoRunStartCommand
			}
		}
		end = clock();


		if ((end - start) > 20000)
		{
			if (!m_MemPro->pRiskArray->empty())
			{
				if (m_MemPro->RiskArrayNum == 1)
				{
					m_MemPro->ChangeRiskArrayNum(1);
					vector<ProcessInfoData>* pRiskArray = m_MemPro->GetRiskArray1();
					if (!pRiskArray->empty())
					{
						SendProcessDataToServer(pRiskArray, tcpSocket);
					}
					//if (m_MemPro->UnKnownDataNum == 1)
					//{
					//	vector<UnKnownDataInfo>* pUnKnownData = m_MemPro->GetUnKnownData1();
					//	if (!pUnKnownData->empty())
					//	{
					//		m_MemPro->ChangeUnKnownDataNum(1);
					//		m_MemPro->SendUnKnownDataToServer(pUnKnownData);
					//		pUnKnownData->clear();
					//	}
					//}
					//int ret = socketsend->SendMessageToServer(functionName_GiveDetectProcess, End);
					pRiskArray->clear();
				}
				else if (m_MemPro->RiskArrayNum == 2)
				{
					m_MemPro->ChangeRiskArrayNum(2);
					vector<ProcessInfoData>* pRiskArray = m_MemPro->GetRiskArray2();
					if (!pRiskArray->empty())
					{
						SendProcessDataToServer(pRiskArray, tcpSocket);
					}
					//if (m_MemPro->UnKnownDataNum == 2)
					//{
					//	vector<UnKnownDataInfo>* pUnKnownData = m_MemPro->GetUnKnownData2();
					//	if (!pUnKnownData->empty())
					//	{
					//		m_MemPro->ChangeUnKnownDataNum(2);
					//		SendUnKnownDataToServer(pUnKnownData);
					//		pUnKnownData->clear();
					//	}
					//}
					//int ret = socketsend->SendMessageToServer(functionName_GiveDetectProcess, End);
					pRiskArray->clear();
				}
			}
			//if(!pUnKnownData->empty())
			//{
			//}
			start = clock();
		}
		StartProcessID.clear();
		StartProcessID = NewProcessID;
		if (!IsHavePID(pMainProcessid))
			break;
		if (IsWin10)
		{
			if ((m_BootEnd - m_BootStart) > 60000)
				Sleep(200);
			else
			{
				m_BootEnd = clock();
				Sleep(10);
			}
		}
		else
		{
			if ((m_BootEnd - m_BootStart) > 60000)
				Sleep(50);
			else
			{
				m_BootEnd = clock();
				Sleep(10);
			}
		}
	}
	NewProcessID.clear();
	StartProcessID.clear();
	m_MemPro->m_RiskArray1.clear();
	m_MemPro->m_RiskArray2.clear();
	delete[] MyPath;
	return 1;
}
void DetectProcess::SendProcessDataToServer(vector<ProcessInfoData>* pInfo, SOCKET* tcpSocket)
{
	char* functionName_GiveDetectProcessFrag = new char[24];
	strcpy_s(functionName_GiveDetectProcessFrag, 24, "GiveDetectProcessFrag");

	char* TempStr = new char[DATASTRINGMESSAGELEN];
	vector<ProcessInfoData>::iterator it;

	for (it = pInfo->begin(); it != pInfo->end(); it++)
	{
		if (_tcscmp((*it).ProcessHash, _T("null"))) {
			wchar_t* wTempStr = new wchar_t[DATASTRINGMESSAGELEN];

			// command line
			HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (*it).ProcessID);
			MemProcess* m_MemPro = new MemProcess;
			TCHAR* Comstr = new TCHAR[MAX_PATH_EX];
			DWORD ret1 = m_MemPro->GetRemoteCommandLineW(processHandle, Comstr, MAX_PATH_EX);
			if (ret1 == 0) _tcscpy_s(Comstr, MAX_PATH_EX, _T(""));
			CloseHandle(processHandle);

			TCHAR* ParentName = new TCHAR[MAX_PATH];
			swprintf_s(ParentName, MAX_PATH, L"%s", "null");
			NTSTATUS status;
			PVOID buffer;
			PSYSTEM_PROCESS_INFO spi;
			buffer = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!buffer) printf("failed to allocate for buffer\n");
			spi = (PSYSTEM_PROCESS_INFO)buffer;
			if (!NT_SUCCESS(status = NtQuerySystemInformation(SystemProcessInformation, spi, 1024 * 1024, NULL))) VirtualFree(buffer, 0, MEM_RELEASE);
			while (spi->NextEntryOffset) {
				if ((*it).ParentID == (int)spi->ProcessId) {
					swprintf_s(ParentName, MAX_PATH, L"%s", spi->ImageName.Buffer);
				}
				spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset);
			}


			int Service = 0, AutoRun = 0;
			if ((*it).StartRun == 1) {
				Service = 1;
			}
			else if ((*it).StartRun == 2) {
				AutoRun = 1;
			}
			else if ((*it).StartRun == 3) {
				Service = 1;
				AutoRun = 1;
			}

			swprintf_s(wTempStr, DATASTRINGMESSAGELEN, L"%s|%s|%s|%s|%s|%ld|%s|%s|%s|%ld|%d,%d|%d|%d,%d|%d,%d"
				, (*it).ProcessName, (*it).ProcessCTime, Comstr, (*it).ProcessHash, (*it).ProcessPath,
				(*it).ParentID, ParentName, (*it).ParentPath, (*it).SignerSubjectName, (*it).ProcessID, (*it).InjectionPE, (*it).InjectionOther
				, (*it).Injected, Service, AutoRun, (*it).HideProcess, (*it).HideAttribute
			); // remove ParentName 

			char* cTempStr = CStringToCharArray(wTempStr, CP_UTF8);
			strcpy_s(TempStr, DATASTRINGMESSAGELEN, cTempStr);

			int ret = 1;

			// abnormal dll
			if (!(*it).Abnormal_dll.empty())
			{
				strcat_s(TempStr, DATASTRINGMESSAGELEN, "|");
				set<string>::iterator dllit;
				for (dllit = (*it).Abnormal_dll.begin(); dllit != (*it).Abnormal_dll.end(); dllit++)
				{
					char* dllstr = new char[4096];
					sprintf_s(dllstr, 4096, "%s;", (*dllit).c_str());
					if ((strlen(dllstr) + strlen(TempStr)) >= DATASTRINGMESSAGELEN)
					{
						ret = SendDataPacketToServer("GiveDetectProcessFrag", TempStr, tcpSocket);
						memset(TempStr, '\0', DATASTRINGMESSAGELEN);
						if (ret <= 0)
						{
							delete[] dllstr;
							break;
						}
					}
					strcat_s(TempStr, DATASTRINGMESSAGELEN, dllstr);
					delete[] dllstr;
				}
				if (ret <= 0)
					break;
			}
			else
				strcat_s(TempStr, DATASTRINGMESSAGELEN, "|null");

			// inline hook
			if (!(*it).InlineHookInfo.empty())
			{
				strcat_s(TempStr, DATASTRINGMESSAGELEN, "|");
				set<string>::iterator Inlineit;
				for (Inlineit = (*it).InlineHookInfo.begin(); Inlineit != (*it).InlineHookInfo.end(); Inlineit++)
				{
					char* Inlinestr = new char[4096];
					sprintf_s(Inlinestr, 4096, "%s;", (*Inlineit).c_str());
					if ((strlen(Inlinestr) + strlen(TempStr)) >= DATASTRINGMESSAGELEN)
					{
						ret = SendDataPacketToServer("GiveDetectProcessFrag", TempStr, tcpSocket);
						memset(TempStr, '\0', DATASTRINGMESSAGELEN);
						if (ret <= 0)
						{
							delete[] Inlinestr;
							break;
						}
					}
					strcat_s(TempStr, DATASTRINGMESSAGELEN, Inlinestr);
					delete[] Inlinestr;
				}
				if (ret <= 0)
					break;
			}
			else
				strcat_s(TempStr, DATASTRINGMESSAGELEN, "|null");

			ret = SendDataPacketToServer("GiveDetectProcess", TempStr, tcpSocket);
			if (ret <= 0) break;
			else memset(TempStr, '\0', DATASTRINGMESSAGELEN);

			delete[] m_MemPro;
			delete[] Comstr;
			delete[] cTempStr;
			delete[] wTempStr;
		}

	}
	delete[] TempStr;



	/*senddatamsgtoserver(mymac,myip,"givedetectprocessend","end");
	pinfo->clear();*/
}
