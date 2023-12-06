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

	functionMap["DetectProcess"] = std::bind(&Task::DetectProcess_, this);

    // packet from server
    

	// Scan
	functionFromServerMap["GetScan"] = &Task::GetScan;
	//functionMap["GiveProcessData"] = std::bind(&Task::GiveProcessData, this);
	

	// Explorer
    functionFromServerMap["GetDrive"] = &Task::GetDrive; // ExplorerInfo_
	functionMap["GiveDriveInfo"] = std::bind(&Task::GiveDriveInfo, this);
	functionFromServerMap["ExplorerInfo"] = &Task::ExplorerInfo_;

	// Collect
	//functionMap["CollectionComputerInfo"] = std::bind(&Task::CollectionComputerInfo, this);
    functionFromServerMap["GetCollectInfo"] = &Task::GetCollectInfo;
    functionFromServerMap["DataRight"] = &Task::DataRight;

	// Image
	functionFromServerMap["GetImage"] = &Task::GetImage;

	// Update Agent 
	functionFromServerMap["UpdateAgent"] = &Task::OpenUpdateAgentProcess;
	functionMap["UpdateAgent"] = std::bind(&Task::UpdateAgent, this);

	// TerminateAll
	functionFromServerMap["TerminateAll"] = &Task::TerminateAll;

	// RemoveAgent
	functionFromServerMap["RemoveAgent"] = &Task::RemoveAgent;
	

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
	strcpy_s(FileVersion, 64, "1.0.4");
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

// detect
int Task::DetectProcessRisk(int pMainProcessid, bool IsFirst, set<DWORD>* pApiName, SOCKET* tcpSocket)
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
void Task::SendProcessDataToServer(vector<ProcessInfoData>* pInfo, SOCKET* tcpSocket)
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

			printf("find parent name\n");
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
						ret = GiveDetectProcessFrag(TempStr, tcpSocket);
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
						ret = GiveDetectProcessFrag(TempStr, tcpSocket);
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


			ret = GiveDetectProcess(TempStr, tcpSocket);
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
int Task::DetectProcess_() {

	printf("sending DetectProcess\n");
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
	return 1;
}
int Task::DetectNewNetwork(int pMainProcessid) {
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

	return 1;
}
void Task::SendNetworkDetectToServer(vector<string>* pInfo)
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
			ret = GiveDetectNetwork(TmpSend, info->tcpSocket);
			if (ret <= 0)
				break;
			else
				memset(TmpSend, '\0', DATASTRINGMESSAGELEN);
		}
		strcat_s(TmpSend, DATASTRINGMESSAGELEN, (*it).c_str());
	}

	if (ret > 0)
	{
		ret = GiveDetectNetwork(TmpSend, info->tcpSocket);
		pInfo->clear();
	}
	
	delete[] TmpSend;
}

int Task::GiveDetectProcess(char* buff, SOCKET* tcpSocket) {
	char* functionName = new char[24];
	strcpy_s(functionName, 24, "GiveDetectProcess");
	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
}
int Task::GiveDetectProcessFrag(char* buff, SOCKET* tcpSocket) {
	char* functionName = new char[24];
	strcpy_s(functionName, 24, "GiveDetectProcessFrag");
	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
}
int Task::GiveDetectNetwork(char* buff, SOCKET* tcpSocket) {
	char* functionName = new char[24];
	strcpy_s(functionName, 24, "GiveDetectNetwork");
	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
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
				strcat_s(driveStr, STRINGMESSAGELEN, drive);
				strcat_s(driveStr, STRINGMESSAGELEN, "-");
				strcat_s(driveStr, STRINGMESSAGELEN, filesys);
				strcat_s(driveStr, STRINGMESSAGELEN, ",HDD");
				strcat_s(driveStr, STRINGMESSAGELEN, "|");
			}
			else if (type == DRIVE_REMOVABLE)
			{
				strcat_s(driveStr, STRINGMESSAGELEN, drive);
				strcat_s(driveStr, STRINGMESSAGELEN, "-");
				strcat_s(driveStr, STRINGMESSAGELEN, filesys);
				strcat_s(driveStr, STRINGMESSAGELEN, ",USB");
				strcat_s(driveStr, STRINGMESSAGELEN, "|");
			}
		}
		delete[] filesys;
		delete[] volname;
		delete[] drive;
	}
	return driveStr;
}

int Task::ExplorerInfo_(StrPacket* udata) {

	char delimiter = '|';
	char Drive[2]; 
	char FileSystem[20];

	char* context; 

	char* token = strtok_s(udata->csMsg, &delimiter, &context);
	if (token != nullptr) {
		strncpy_s(Drive, sizeof(Drive), token, sizeof(Drive) - 1);
		Drive[sizeof(Drive) - 1] = '\0';

		token = strtok_s(nullptr, &delimiter, &context);
		if (token != nullptr) {
			strncpy_s(FileSystem, sizeof(FileSystem), token, sizeof(FileSystem) - 1);
			FileSystem[sizeof(FileSystem) - 1] = '\0';
		}
	}

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

//std::string Task::ToUpper(const std::string& str) {
//	std::string result = str;
//	std::transform(result.begin(), result.end(), result.begin(),
//		[](unsigned char c) { return std::toupper(c); });
//	return result;
//}
//void Task::SearchForFile(std::filesystem::path root, std::filesystem::path directory, std::filesystem::path::const_iterator start, std::filesystem::path::const_iterator finish, const std::string& targetFile, HZIP* hz) {
//
//	if (directory.string().find('*') != std::string::npos) {
//
//		while (start != finish && start->string().find('*') == std::string::npos) {
//			root /= *start++;
//			std::cout << root << std::endl;
//		}
//
//		if (!fs::is_directory(root)) {
//			std::string Msg = directory.string() + "is not a directory";
//			log.logger("Error", Msg);
//			return;
//		}
//
//		try {
//
//			for (const auto& entry : fs::directory_iterator(root)) {
//
//				if (ToUpper(entry.path().filename().string()).find(ToUpper(targetFile)) != std::string::npos) {
//					std::string Msg = "Found file: " + entry.path().string();
//					log.logger("Debug", Msg);
//
//					try {
//						TCHAR* targetPath = new TCHAR[MAX_PATH_EX];
//						GetMyPath(targetPath);
//						fs::copy(entry.path(), targetPath, fs::copy_options::recursive);
//						_tcscat_s(targetPath, MAX_PATH_EX, _T("\\image.zip"));
//
//						TCHAR* imageFile = new TCHAR[MAX_PATH_EX];
//						GetMyPath(imageFile);
//						_tcscat_s(imageFile, MAX_PATH_EX, _T("\\"));
//						_tcscat_s(imageFile, MAX_PATH_EX, entry.path().filename().c_str());
//
//						if (ZipAdd(*hz, entry.path().filename().c_str(), imageFile) != 0) {
//							int bufferSize = WideCharToMultiByte(CP_UTF8, 0, imageFile, -1, nullptr, 0, nullptr, nullptr);
//							char* buffer = new char[bufferSize];
//							WideCharToMultiByte(CP_UTF8, 0, imageFile, -1, buffer, bufferSize, nullptr, nullptr);
//							std::string result(buffer);
//
//							string LogMsg = "failed to add " + result + " to zip";
//							log.logger("Error", LogMsg);
//							continue;
//						}
//						else {
//							string LogMsg = "add " + entry.path().filename().string() + " to zip";
//							log.logger("Info", LogMsg);
//						}
//						DeleteFile(imageFile);
//					}
//					catch (const fs::filesystem_error& ex) {
//						std::string errorMessage = ex.what();
//						Msg = "Error during copy: " + errorMessage;
//						log.logger("Error", Msg);
//					}
//
//				}
//				else if (fs::is_directory(entry.path())) {
//					start++;
//					SearchForFile(entry.path(), directory, start, finish, targetFile, hz);
//					start--;
//				}
//			}
//
//		}
//		catch (...) {
//			return;
//		}
//	}
//	else {
//
//		try {
//			for (const auto& entry : fs::directory_iterator(directory)) {
//				if (ToUpper(entry.path().filename().string()).find(ToUpper(targetFile)) != std::string::npos) {
//					std::string Msg = "Found file: " + entry.path().string();
//					log.logger("Debug", Msg);
//					try {
//						TCHAR* targetPath = new TCHAR[MAX_PATH_EX];
//						GetMyPath(targetPath);
//						fs::copy(entry.path(), targetPath, fs::copy_options::recursive);
//						_tcscat_s(targetPath, MAX_PATH_EX, _T("\\image.zip"));
//
//						TCHAR* imageFile = new TCHAR[MAX_PATH_EX];
//						GetMyPath(imageFile);
//						_tcscat_s(imageFile, MAX_PATH_EX, _T("\\"));
//						_tcscat_s(imageFile, MAX_PATH_EX, entry.path().filename().c_str());
//
//						if (ZipAdd(*hz, entry.path().filename().c_str(), imageFile) != 0) {
//							int bufferSize = WideCharToMultiByte(CP_UTF8, 0, imageFile, -1, nullptr, 0, nullptr, nullptr);
//							char* buffer = new char[bufferSize];
//							WideCharToMultiByte(CP_UTF8, 0, imageFile, -1, buffer, bufferSize, nullptr, nullptr);
//							std::string result(buffer);
//
//							string LogMsg = "failed to add " + result + " to zip";
//							log.logger("Error", LogMsg);
//							continue;
//						}
//						else {
//							string LogMsg = "add " + entry.path().filename().string() + " to zip";
//							log.logger("Info", LogMsg);
//						}
//						DeleteFile(imageFile);
//					}
//					catch (const fs::filesystem_error& ex) {
//						std::string errorMessage = ex.what();
//						Msg = "Error during copy: " + errorMessage;
//						log.logger("Error", Msg);
//					}
//
//				}
//				else if (fs::is_directory(entry.path())) {
//					SearchForFile(entry.path(), entry.path(), start, finish, targetFile, hz);
//				}
//			}
//		}
//		catch (...) {
//			return;
//		}
//	}
//}
//int Task::LookingForImage(char* cmd) {
//
//	char* null = new char[1];
//	strcpy_s(null, 1, "");
//	int ret = SendDataPacketToServer("ReadyImage", null, info->tcpSocket);
//
//	string Msg = cmd;
//	string LogMsg = "cmd: " + Msg;
//	log.logger("Debug", LogMsg);
//
//	TCHAR* zipFileName = new TCHAR[MAX_PATH_EX];
//	GetMyPath(zipFileName);
//	_tcscat_s(zipFileName, MAX_PATH_EX, _T("\\image.zip"));
//	HZIP hz = CreateZip(zipFileName, 0);
//	if (hz == 0) {
//		log.logger("Error", "Failed to create image.zip");
//		return false; // Failed to create ZIP file
//	}
//
//	std::vector<ImageType>image;
//	std::vector<std::string> MsgAfterSplit;
//	char* nextToken = nullptr;
//	const char* delimiter = ",";
//	char* token = strtok_s(cmd, delimiter, &nextToken);
//	while (token != nullptr) {
//		MsgAfterSplit.push_back(token);
//		token = strtok_s(nullptr, delimiter, &nextToken);
//	}
//
//	// find root drive
//	//WCHAR driveStrings[255];
//	//DWORD driveStringsLength = GetLogicalDriveStringsW(255, driveStrings);
//	//WCHAR* currentDrive;
//	//std::string narrowString_currentDrive; // here
//	//if (driveStringsLength > 0 && driveStringsLength < 255) {
//	//	currentDrive = driveStrings;
//	//	while (*currentDrive) {
//	//		int requiredSize = WideCharToMultiByte(CP_UTF8, 0, currentDrive, -1, NULL, 0, NULL, NULL);
//	//		narrowString_currentDrive.resize(requiredSize);
//
//	//		if (WideCharToMultiByte(CP_UTF8, 0, currentDrive, -1, &narrowString_currentDrive[0], requiredSize, NULL, NULL)) {
//	//			//std::cout << "currentDrive: " << narrowString_currentDrive << std::endl;
//	//		}
//
//	//		currentDrive += wcslen(currentDrive) + 1;
//	//		break;
//	//	}
//	//}
//
//	for (int i = 0; i < MsgAfterSplit.size(); i++) {
//		std::vector<std::string> FileInfo;
//		nextToken = nullptr;
//		delimiter = "|";
//
//		char* charArray = new char[MsgAfterSplit[i].size() + 1];
//		strcpy_s(charArray, MsgAfterSplit[i].size() + 1, MsgAfterSplit[i].c_str());
//
//		token = strtok_s(charArray, delimiter, &nextToken);
//		while (token != nullptr) {
//			FileInfo.push_back(token);
//			if (nextToken != nullptr && *nextToken == '|') {
//				FileInfo.push_back(""); // Generate an empty string
//			}
//			token = strtok_s(nullptr, delimiter, &nextToken);
//		}
//		delete[] charArray;
//
//		size_t pos = FileInfo[0].find("root");
//		while (pos != std::string::npos) {
//			FileInfo[0].replace(pos, 4, "C");
//			pos = FileInfo[0].find("root", pos + 1);
//		}
//
//		char* searchPath = new char[4];
//		std::string APPDATAPATH;
//
//		if (!FileInfo[1].empty()) {
//			size_t len;
//			errno_t err = _dupenv_s(&searchPath, &len, const_cast<char*>(FileInfo[1].c_str()));
//
//			if (err != 0) {
//				log.logger("Error", "Error getting environment variable");
//				continue;
//			}
//
//			if (searchPath == NULL) {
//				log.logger("Error", "environment variable is not set.");
//				continue;
//			}
//
//			APPDATAPATH = searchPath;
//
//			//printf("search path: %s\n", searchPath);
//			if (FileInfo[0].substr(0, 1) != "\\") APPDATAPATH += "\\";
//
//		}
//
//
//		APPDATAPATH += FileInfo[0];
//		FileInfo[0] = APPDATAPATH;
//
//
//		//printf("%s %s %s\n", FileInfo[0].c_str(), FileInfo[1].c_str(), FileInfo[2].c_str());
//		string Msg = FileInfo[0] + " " + FileInfo[1] + " " + FileInfo[2];
//		log.logger("Debug", Msg);
//
//		fs::path filePath = FileInfo[0];
//		const auto relative_parent = filePath.parent_path().relative_path();
//		std::filesystem::path root = filePath.root_path();
//		std::filesystem::path::const_iterator start = begin(relative_parent);
//		std::filesystem::path::const_iterator finish = end(relative_parent);
//
//		SearchForFile(root, filePath, start, finish, FileInfo[2], &hz);
//
//	}
//
//	CloseZip(hz);
//	SendFileToServer("Image", zipFileName, info->tcpSocket);
//	return 1;
//	
//}

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
void Task::WriteNewAgentToFile(char* buffer, int totalReceivedSize) {
	char* null = new char[1];
	strcpy_s(null, 1, "");
	TCHAR* AgentNewVersion_exe = new TCHAR[MAX_PATH_EX];
	GetMyPath(AgentNewVersion_exe);
	_tcscat_s(AgentNewVersion_exe, MAX_PATH_EX, _T("\\ClientAgent.exe"));
	std::ofstream outFile(AgentNewVersion_exe, std::ios::app | std::ios::binary);
	if (!outFile.is_open()) {
		log.logger("Error", "ClientAgent.exe open failed");
	}
	if (outFile.good()) { 
		outFile.write(buffer, totalReceivedSize);
	}
	else {
		log.logger("Error", "Error write data into NewAgent");
	}
	outFile.close();
	SendACK(null);

}
void Task::AgentReceive(int fileSize) {
	int alreadyReceived = 0;
	while (true) {
		
		uint64_t receivedSize = 0;
		int totalReceivedSize = 0;
		char* buffer = new char[STRDATAPACKETSIZE];

		while (totalReceivedSize < STRDATAPACKETSIZE) {
			char* tmpbuffer = new char[STRDATAPACKETSIZE];
			int bytesRead = recv(*info->tcpSocket, tmpbuffer, STRDATAPACKETSIZE, 0);
			if (bytesRead == -1) {
				log.logger("Error", "UpdateAgent Error receiving data");
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

		if (!strcmp(udata->DoWorking, "GiveUpdate")) {
			if (alreadyReceived > fileSize) {
				WriteNewAgentToFile(udata->csMsg, fileSize % 65436);
			}
			else {
				WriteNewAgentToFile(udata->csMsg, STRDATAPACKETSIZE - 100);
			}
			
		}
		else {
			break;
		}

		delete[] buffer;

	}
}
int Task::UpdateAgent() {
	char* null = new char[1];
	strcpy_s(null, 1, "");

	TCHAR* AgentNewVersion_exe = new TCHAR[MAX_PATH_EX];
	GetMyPath(AgentNewVersion_exe);
	_tcscat_s(AgentNewVersion_exe, MAX_PATH_EX, _T("\\ClientAgent.exe"));
	DeleteFile(AgentNewVersion_exe);

	ReadyUpdateAgent(null);

	int fileSize = GiveUpdateInfo();
	std::thread AgentReceiveThread([&]() { AgentReceive(fileSize); });
	if (!fileSize) {
		log.logger("Error", "Error receiving New Agent Info");
	}
	SendACK(null);
	AgentReceiveThread.join();
	SendACK(null);

	log.logger("Info", "start update agent");

	RunProcess(AgentNewVersion_exe, NULL, FALSE, FALSE);


	return 1;
}
int Task::ReadyUpdateAgent(char* buff) {
	char* functionName = new char[24];
	strcpy_s(functionName, 24, "ReadyUpdateAgent");
	printf("%s\n", buff);
	return socketsend->SendMessageToServer(functionName, buff);
}
int Task::SendACK(char* buff) {
	char* functionName = new char[24];
	strcpy_s(functionName, 24, "DataRight");
	printf("%s\n", buff);
	return socketsend->SendMessageToServer(functionName, buff);
}
int Task::GiveUpdateInfo() {
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

	if (!strcmp(udata->DoWorking, "GiveUpdateInfo")) {
		return std::stoi(TaskMsg);
	}
	else {
		return 0;
	}
}
int Task::GiveUpdateEnd() {
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

	if (!strcmp(udata->DoWorking, "GiveUpdateEnd")) {
		return 1;
	}
	else {
		return 0;
	}
}


int Task::TerminateAllTask() {
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
	return ret;
}

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
