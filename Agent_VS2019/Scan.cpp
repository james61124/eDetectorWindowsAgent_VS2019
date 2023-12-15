#include "Scan.h"


Scan::Scan(Info* infoInstance, SocketSend* socketSendInstance) {
	info = infoInstance;
	socketsend = socketSendInstance;
}

void Scan::DoTask() {

	//DumpMemoryInfo* pInfo = new DumpMemoryInfo;
	//pInfo->ProcessID = 8388;
	//ProcessDump(pInfo);

	char* Scan = new char[5];
	strcpy_s(Scan, 5, "Scan");

	std::set<DWORD> m_ApiName;
	tool.LoadApiPattern(&m_ApiName);
	std::map<DWORD, ProcessInfoData> m_ProcessInfo;
	std::vector<UnKnownDataInfo> m_UnKnownData;

	// start scan
	char* null = new char[1];
	strcpy_s(null, 1, "");
	int ret = SendDataPacketToServer("ReadyScan", null, info->tcpSocket);
	ScanRunNowProcess(this, &m_ProcessInfo, &m_ApiName, &m_UnKnownData, info->tcpSocket);

	// send scan file
	if (!m_ProcessInfo.empty()) {
		try {
			GiveScanDataSendServer(info->MAC, info->IP, Scan, &m_ProcessInfo, &m_UnKnownData, info->tcpSocket);
		}
		catch (...) {
			log.logger("Error", "GiveScanDataSendServer failed");
		}
	}

	m_UnKnownData.clear();
	m_ProcessInfo.clear();
	m_ApiName.clear();
}

BOOL Scan::GetFileVersion_(TCHAR* pPath, wstring* pFileVersionStr)
{
	wchar_t /*cPath[MAX_PATH],*/ cSubBlock[MAX_PATH];
	DWORD dwHandle, dwInfoSize, dwTrans;
	UINT uTranslate = 0, uBytes = 0;
	DWORD* dwTranslation = NULL;
	WCHAR* cpBuffer = NULL;

	//Get file version size 
	dwInfoSize = GetFileVersionInfoSize(pPath, &dwHandle);
	if (dwInfoSize == 0)
	{
		//printf("ERROR : The file resource version size is error.\n");
		return FALSE;
	}

	//Allocate buffer and retrieve version information 
	char* cpInfoBuf = new char[dwInfoSize];
	if (!cpInfoBuf)
	{
		return FALSE;
	}

	if (!GetFileVersionInfo(pPath, 0, dwInfoSize, cpInfoBuf))
	{
		delete[] cpInfoBuf;
		return FALSE;
	}

	//Get the language setting first 
	if (!VerQueryValue(cpInfoBuf, _TEXT("\\VarFileInfo\\Translation"), (LPVOID*)&dwTranslation, &uTranslate))
	{
		delete[] cpInfoBuf;
		return FALSE;
	}

	if (*dwTranslation == NULL)
	{
		delete[] cpInfoBuf;
		return FALSE;
	}

	dwTrans = MAKELONG(HIWORD(dwTranslation[0]), LOWORD(dwTranslation[0]));
	// Read the file description for each language and code page.
	WCHAR* szpVersion[] = { const_cast<TCHAR*>(L"CompanyName"),
		const_cast<TCHAR*>(L"FileVersion"),
		const_cast<TCHAR*>(L"LegalCopyright"),
		const_cast<TCHAR*>(L"PrivateBuild"),
		const_cast<TCHAR*>(L"Comments"),
		const_cast<TCHAR*>(L"InternalName"),
		const_cast<TCHAR*>(L"ProductName"),
		const_cast<TCHAR*>(L"ProductVersion"),
		const_cast<TCHAR*>(L"FileDescription"),
		const_cast<TCHAR*>(L"LegalTrademarks"),
		const_cast<TCHAR*>(L"OriginalFilename"),
		const_cast<TCHAR*>(L"SpecialBuild") };


	for (int i = 0; i < VERSIONCOUNT; i++)
	{
		swprintf_s(cSubBlock, _TEXT("\\StringFileInfo\\%08lx\\%s"), dwTrans, szpVersion[i]);
		if (!VerQueryValue(cpInfoBuf, cSubBlock, (LPVOID*)&cpBuffer, &uBytes))
		{
			continue;
		}
		pFileVersionStr[i] = cpBuffer;
	}

	delete[] cpInfoBuf;
	dwTranslation = NULL;
	cpBuffer = NULL;

	return TRUE;
}
DWORD Scan::GetRemoteCommandLineW(HANDLE hProcess, LPWSTR pszBuffer, UINT bufferLength)
{
	typedef NTSTATUS(NTAPI* NtQueryInformationProcessPtr)(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	typedef ULONG(NTAPI* RtlNtStatusToDosErrorPtr)(NTSTATUS Status);

	// Locating functions
	HINSTANCE hNtDll = GetModuleHandleW(L"ntdll.dll");
	if (hNtDll == NULL)
		return 0;
	NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hNtDll, "NtQueryInformationProcess");
	RtlNtStatusToDosErrorPtr RtlNtStatusToDosError = (RtlNtStatusToDosErrorPtr)GetProcAddress(hNtDll, "RtlNtStatusToDosError");

	if (!NtQueryInformationProcess || !RtlNtStatusToDosError)
	{
		//printf("Functions cannot be located.\n");
		FreeLibrary(hNtDll);
		return 0;
	}

	// Get PROCESS_BASIC_INFORMATION
	PROCESS_BASIC_INFORMATION pbi;
	ULONG len;
	NTSTATUS status = NtQueryInformationProcess(
		hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len);
	SetLastError(RtlNtStatusToDosError(status));
	if (NT_ERROR(status) || !pbi.PebBaseAddress)
	{
		//printf("NtQueryInformationProcess(ProcessBasicInformation) failed.\n");
		FreeLibrary(hNtDll);
		return 0;
	}

	// Read PEB memory block
	SIZE_T bytesRead = 0;
	//PEB_INTERNAL peb;
	_PEB peb;
	if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead))
	{
		//printf("Reading PEB failed.\n");
		FreeLibrary(hNtDll);
		return 0;
	}

	// Obtain size of commandline string
	//RTL_USER_PROCESS_PARAMETERS_I upp;
	RTL_USER_PROCESS_PARAMETERS upp;
	if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), &bytesRead))
	{
		//printf("Reading USER_PROCESS_PARAMETERS failed.\n");
		FreeLibrary(hNtDll);
		return 0;
	}
	//printf("%x\n",peb.BeingDebugged);
	if (!upp.CommandLine.Length)
	{
		//printf("Command line length is 0.\n");
		FreeLibrary(hNtDll);
		return 0;
	}

	// Check the buffer size
	DWORD dwNeedLength = (upp.CommandLine.Length + 1) / sizeof(wchar_t) + 1;
	if (bufferLength < dwNeedLength)
	{
		//printf("Not enough buffer.\n");
		FreeLibrary(hNtDll);
		return 0;//dwNeedLength;
	}

	// Get the actual command line
	pszBuffer[dwNeedLength - 1] = L'\0';
	if (!ReadProcessMemory(hProcess, upp.CommandLine.Buffer, pszBuffer, upp.CommandLine.Length, &bytesRead))
	{
		//printf("Reading command line failed.\n");
		FreeLibrary(hNtDll);
		return 0;
	}
	FreeLibrary(hNtDll);
	return (DWORD)bytesRead / sizeof(wchar_t);
}
void Scan::ScanRunNowProcess(void* argv, map<DWORD, ProcessInfoData>* pInfo, set<DWORD>* pApiName, vector<UnKnownDataInfo>* pMembuf, SOCKET* tcpSocket)
{
	MemProcess* m_MemPro = new MemProcess;
	map<DWORD, process_info_Ex> process_list;
	m_MemPro->LoadNowProcessInfo(&process_list);
	vector<TCPInformation> NetInfo;
	char* OSstr = GetOSVersion();

	if ((strstr(OSstr, "Windows XP") != 0) || (strstr(OSstr, "Windows Server 2003") != 0)) GetTcpInformationXPEx(&NetInfo);
	else if (strstr(OSstr, "Windows 2000") != 0) {}
	else GetTcpInformationEx(&NetInfo);
	delete[] OSstr;
	time_t NetworkClock;
	time(&NetworkClock);

	map<wstring, BOOL> m_ServiceRun;
	set<wstring> m_StartRun;
	AutoRun* m_AutoRun = new AutoRun;
	m_AutoRun->LoadServiceStartCommand(&m_ServiceRun);
	m_AutoRun->LoadAutoRunStartCommand(&m_StartRun);

	int InfoSize = (int)process_list.size();
	int InfoCount = 0;
	map<DWORD, process_info_Ex>::iterator pt;

	char* buff = new char[DATASTRINGMESSAGELEN];
	sprintf_s(buff, DATASTRINGMESSAGELEN, "%d", InfoSize);
	int ret = SendDataPacketToServer("GiveScanInfo", buff, tcpSocket);
	if (!ret) {
		log.logger("Error", "GiveScanInfo send failed");
		return;
	}
	delete[] buff;


	for (pt = process_list.begin(); pt != process_list.end(); pt++, InfoCount++) {
		printf("%d/%d\n", InfoCount, InfoSize);
		char* Progress = new char[DATASTRINGMESSAGELEN];
		sprintf_s(Progress, DATASTRINGMESSAGELEN, "%d/%d", InfoCount, InfoSize);
		int ret = SendDataPacketToServer("GiveScanProgress", Progress, tcpSocket);
		delete[] Progress;

		if (!m_MemPro->IsWindowsProcessNormal(&process_list, pt->first)) {
			ProcessInfoData m_Info;
			m_Info.HideAttribute = FALSE;
			m_Info.HideProcess = pt->second.IsHide;
			lstrcpy(m_Info.ProcessName, pt->second.process_name);
			_tcscpy_s(m_Info.ProcessPath, MAX_PATH_EX, pt->second.process_Path);
			_tcscpy_s(m_Info.ProcessTime, 20, _T("null"));
			_tcscpy_s(m_Info.ProcessCTime, 20, _T("null"));
			_tcscpy_s(m_Info.ParentCTime, 20, _T("null"));
			if (pt->second.ProcessCreateTime > 0) swprintf_s(m_Info.ProcessCTime, 20, _T("%llu"), pt->second.ProcessCreateTime);
			if (pt->second.parentCreateTime > 0) swprintf_s(m_Info.ParentCTime, 20, _T("%llu"), pt->second.parentCreateTime);
			if (!_tcscmp(m_Info.ProcessPath, _T("null"))) m_MemPro->SearchExecutePath(pt->first, m_Info.ProcessPath, pt->second.process_name);

			SYSTEMTIME sys;
			GetLocalTime(&sys);
			swprintf_s(m_Info.ProcessTime, 20, _T("%4d/%02d/%02d %02d:%02d:%02d"), sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond);
			m_Info.ParentID = pt->second.parent_pid;
			if (pt->second.parentCreateTime > 0) m_MemPro->GetProcessPath(pt->second.parent_pid, m_Info.ParentPath, true, NULL, NULL);
			else _tcscpy_s(m_Info.ParentPath, MAX_PATH_EX, _T("null"));
			_tcscpy_s(m_Info.UnKnownHash, 50, _T("null"));
			m_Info.Injected = m_MemPro->CheckIsInjection(pt->first, pMembuf, m_Info.ProcessName, m_Info.UnKnownHash);
			m_Info.StartRun = m_MemPro->CheckIsStartRun(&m_ServiceRun, &m_StartRun, pt->first/*,m_Info.HideService*/);

			m_MemPro->CheckIsInlineHook(pt->first, &m_Info.InlineHookInfo);

			TCHAR Md5Hashstr[50];
			memset(Md5Hashstr, '\0', 50);
			DWORD MD5ret = Md5Hash(m_Info.ProcessPath, Md5Hashstr);
			if (MD5ret == 0) lstrcpy(m_Info.ProcessHash, Md5Hashstr);
			else lstrcpy(m_Info.ProcessHash, _T("null"));

			if (_tcscmp(m_Info.ProcessPath, _T("null"))) {
				DWORD AttRet = GetFileAttributes(m_Info.ProcessPath);
				if ((AttRet & FILE_ATTRIBUTE_HIDDEN) == FILE_ATTRIBUTE_HIDDEN) m_Info.HideAttribute = TRUE;
				DigitalSignatureInfo* DSinfo = new DigitalSignatureInfo;
				_tcscpy_s(DSinfo->SignerSubjectName, 256, _T("null"));
				bool DSret = GetDigitalSignature(m_Info.ProcessPath, DSinfo);
				if (DSret) swprintf_s(m_Info.SignerSubjectName, 256, _T("%s"), DSinfo->SignerSubjectName);
				else lstrcpy(m_Info.SignerSubjectName, _T("null"));
				delete DSinfo;

				//wstring FileVersionStr[12];
				//GetFileVersion_((TCHAR*)m_Info.ProcessPath, FileVersionStr);
				//m_Info.CompanyName = FileVersionStr[COMPANYNAME];
				//m_Info.FileVersion = FileVersionStr[FILESVERSION];
				//m_Info.FileDescription = FileVersionStr[FILEDESCRIPTION];
				//m_Info.ProductName = FileVersionStr[PRODUCTNAME];

				//HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pt->first);
				//if (processHandle != NULL) {
				//	TCHAR* m_FilePath = new TCHAR[512];
				//	memset(m_FilePath, 0, 512);
				//	DWORD ret1 = GetRemoteCommandLineW(processHandle, m_FilePath, 512);
				//	_tcscpy_s(m_FilePath, 512, _T("null"));
				//	GetUserSID(processHandle, m_FilePath);
				//	if (_tcscmp(m_FilePath, _T("null"))) {
				//		SID_NAME_USE SidType;
				//		TCHAR* lpName = new TCHAR[_MAX_FNAME];
				//		TCHAR* lpDomain = new TCHAR[_MAX_FNAME];
				//		DWORD dwSize = _MAX_FNAME;
				//		PSID Sid;
				//		if (ConvertStringSidToSid(m_FilePath, &Sid)) {
				//			if (LookupAccountSid(NULL, Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType))
				//			{
				//				//_tcscpy_s(pUserName,_MAX_FNAME,lpName);
				//				m_Info.user_name = lpName;
				//			}
				//		}
				//		if (m_Info.user_name.empty())
				//			m_Info.user_name = m_FilePath;
				//		LocalFree(Sid);
				//		delete[] lpDomain;
				//		delete[] lpName;
				//	}
				//}
				//m_Info.Priority = GetPriorityClass(processHandle);
				//CloseHandle(processHandle);

			}
			else lstrcpy(m_Info.SignerSubjectName, _T("null"));

			set<DWORD> ApiStringHash;
			m_MemPro->DumpExecute(pt->first, pt->second.process_name, pApiName, &ApiStringHash, m_Info.ProcessPath, &m_Info.Abnormal_dll);
			m_Info.InjectionOther = FALSE;
			m_Info.InjectionPE = FALSE;
			m_MemPro->CheckInjectionPtn(&ApiStringHash, m_Info.InjectionOther, m_Info.InjectionPE);
			ApiStringHash.clear();
			vector<TCPInformation>::iterator Tcpit;
			for (Tcpit = NetInfo.begin(); Tcpit != NetInfo.end(); Tcpit++) {
				if ((*Tcpit).ProcessID == pt->first) {
					WORD add1, add2, add3, add4;
					add1 = (WORD)((*Tcpit).LocalAddr & 255);
					add2 = (WORD)(((*Tcpit).LocalAddr >> 8) & 255);
					add3 = (WORD)(((*Tcpit).LocalAddr >> 16) & 255);
					add4 = (WORD)(((*Tcpit).LocalAddr >> 24) & 255);
					WORD add5, add6, add7, add8;
					add5 = (WORD)((*Tcpit).RemoteAddr & 255);
					add6 = (WORD)(((*Tcpit).RemoteAddr >> 8) & 255);
					add7 = (WORD)(((*Tcpit).RemoteAddr >> 16) & 255);
					add8 = (WORD)(((*Tcpit).RemoteAddr >> 24) & 255);
					char str[65536];
					sprintf_s(str, 65536, "%d.%d.%d.%d,%u,%d.%d.%d.%d,%u,%s>%lld", add1, add2, add3, add4, ntohs((u_short)(*Tcpit).LocalPort), add5, add6, add7, add8, ntohs((u_short)(*Tcpit).RemotePort), Convert2State((*Tcpit).State), NetworkClock);
					m_Info.NetString.insert(str);
				}
			}
			pInfo->insert(pair<DWORD, ProcessInfoData>(pt->first, m_Info));
		}
	}

	delete m_MemPro;
	delete m_AutoRun;
	m_StartRun.clear();
	m_ServiceRun.clear();
	NetInfo.clear();
	process_list.clear();
}
void Scan::GiveScanDataSendServer(char* pMAC, char* pIP, char* pMode, map<DWORD, ProcessInfoData>* pFileInfo, vector<UnKnownDataInfo>* pUnKnownData, SOCKET* tcpSocket)
{
	char* buff = new char[DATASTRINGMESSAGELEN];
	map<DWORD, ProcessInfoData>::iterator vit;
	int AllCount = (int)pFileInfo->size();
	int m_Count = 0;

	TCHAR* Scan_txt = new TCHAR[MAX_PATH_EX];
	GetMyPath(Scan_txt);
	_tcscat_s(Scan_txt, MAX_PATH_EX, _T("\\Scan.txt"));
	DeleteFile(Scan_txt);
	TCHAR* Scan_zip = new TCHAR[MAX_PATH_EX];
	GetMyPath(Scan_zip);
	_tcscat_s(Scan_zip, MAX_PATH_EX, _T("\\Scan.zip"));
	DeleteFile(Scan_zip);
	std::wofstream outFile(Scan_txt, std::ios::app);
	if (!outFile.is_open()) log.logger("Error", "Scan.txt open failed");

	int ret = 1;

	for (vit = pFileInfo->begin(); vit != pFileInfo->end(); vit++)
	{
		if (_tcscmp(vit->second.ProcessHash, _T("null")))
		{
			wchar_t* wTempStr = new wchar_t[DATASTRINGMESSAGELEN];

			// command line
			HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, vit->first);
			MemProcess* m_MemPro = new MemProcess;
			TCHAR* Comstr = new TCHAR[MAX_PATH_EX];
			DWORD ret1 = m_MemPro->GetRemoteCommandLineW(processHandle, Comstr, MAX_PATH_EX);
			if (ret1 == 0) _tcscpy_s(Comstr, MAX_PATH_EX, _T(""));
			CloseHandle(processHandle);

			// parent name, parent path
			TCHAR* ParentName = new TCHAR[MAX_PATH];
			TCHAR* ParentPath = new TCHAR[MAX_PATH];
			_tcscpy_s(ParentName, 259, _T("null"));
			_tcscpy_s(ParentPath, 259, _T("null"));
			auto it = pFileInfo->find(vit->second.ParentID);
			if (it != pFileInfo->end()) {
				_tcscpy_s(ParentName, MAX_PATH, it->second.ProcessName);
				_tcscpy_s(ParentPath, MAX_PATH, it->second.ProcessPath);
			}

			int Service = 0, AutoRun = 0;
			if (vit->second.StartRun == 1) Service = 1;
			else if (vit->second.StartRun == 2) AutoRun = 1;
			else if (vit->second.StartRun == 3) {
				Service = 1;
				AutoRun = 1;
			}

			swprintf_s(wTempStr, DATASTRINGMESSAGELEN, L"%s|%s|%s|%s|%s|%ld|%s|%s|%s|%ld|%d,%d|%d|%d,%d|%d,%d"
					, vit->second.ProcessName, vit->second.ProcessCTime, Comstr, vit->second.ProcessHash, vit->second.ProcessPath,
					vit->second.ParentID, ParentName, ParentPath, vit->second.SignerSubjectName, vit->first, vit->second.InjectionPE, vit->second.InjectionOther
					, vit->second.Injected, Service, AutoRun, vit->second.HideProcess, vit->second.HideAttribute
				);

			/*swprintf_s(wTempStr, DATASTRINGMESSAGELEN, L"%s|%s|%s|%s|%s|%ld|%s|%s|%s|%ld|%d,%d|%d|%d,%d|%d,%d|%s|%s|%s|%s|%s|%d"
				, vit->second.ProcessName, vit->second.ProcessCTime, Comstr, vit->second.ProcessHash, vit->second.ProcessPath,
				vit->second.ParentID, ParentName, ParentPath, vit->second.SignerSubjectName, vit->first, vit->second.InjectionPE, vit->second.InjectionOther
				, vit->second.Injected, Service, AutoRun, vit->second.HideProcess, vit->second.HideAttribute, vit->second.ProductName, vit->second.FileVersion
				, vit->second.FileDescription, vit->second.CompanyName, vit->second.user_name, vit->second.Priority
			);*/

			// abnormal dll
			char* cTempStr = CStringToCharArray(wTempStr, CP_UTF8);
			strcpy_s(buff, DATASTRINGMESSAGELEN, cTempStr);
			if (!vit->second.Abnormal_dll.empty())
			{
				strcat_s(buff, DATASTRINGMESSAGELEN, "|");
				set<string>::iterator dllit;
				for (dllit = vit->second.Abnormal_dll.begin(); dllit != vit->second.Abnormal_dll.end(); dllit++)
				{
					char* dllstr = new char[4096];
					sprintf_s(dllstr, 4096, "%s;", (*dllit).c_str());
					if ((strlen(dllstr) + strlen(buff)) >= DATASTRINGMESSAGELEN)
					{
						if (outFile.good()) outFile << buff;
						else log.logger("Error", "write to Scan.txt failed");
						memset(buff, '\0', DATASTRINGMESSAGELEN);
						if (ret <= 0)
						{
							delete[] dllstr;
							break;
						}
					}
					strcat_s(buff, DATASTRINGMESSAGELEN, dllstr);
					delete[] dllstr;
				}
				if (ret <= 0)
					break;
			}
			else
				strcat_s(buff, DATASTRINGMESSAGELEN, "|null");


			// inline hook
			if (!vit->second.InlineHookInfo.empty())
			{
				strcat_s(buff, DATASTRINGMESSAGELEN, "|");
				set<string>::iterator Inlineit;
				for (Inlineit = vit->second.InlineHookInfo.begin(); Inlineit != vit->second.InlineHookInfo.end(); Inlineit++)
				{
					char* Inlinestr = new char[4096];
					sprintf_s(Inlinestr, 4096, "%s;", (*Inlineit).c_str());
					if ((strlen(Inlinestr) + strlen(buff)) >= DATASTRINGMESSAGELEN)
					{
						if (outFile.good()) outFile << buff;
						else log.logger("Error", "write to Scan.txt failed");
						memset(buff, '\0', DATASTRINGMESSAGELEN);
						if (ret <= 0)
						{
							delete[] Inlinestr;
							break;
						}
					}
					strcat_s(buff, DATASTRINGMESSAGELEN, Inlinestr);
					delete[] Inlinestr;
				}
				if (ret <= 0)
					break;
			}
			else
				strcat_s(buff, DATASTRINGMESSAGELEN, "|null");

			// Network
			if (!vit->second.NetString.empty())
			{
				strcat_s(buff, DATASTRINGMESSAGELEN, "|");
				set<string>::iterator netit;
				for (netit = vit->second.NetString.begin(); netit != vit->second.NetString.end(); netit++)
				{
					char* netstr = new char[4096];
					sprintf_s(netstr, 4096, "%s;", (*netit).c_str());
					if ((strlen(netstr) + strlen(buff)) >= DATASTRINGMESSAGELEN)
					{
						if (outFile.good()) outFile << buff;
						else log.logger("Error", "write to Scan.txt failed");
						memset(buff, '\0', DATASTRINGMESSAGELEN);
						if (ret <= 0)
						{
							delete[] netstr;
							break;
						}
					}
					strcat_s(buff, DATASTRINGMESSAGELEN, netstr);
					delete[] netstr;
				}
				if (ret <= 0)
					break;
			}
			else
				strcat_s(buff, DATASTRINGMESSAGELEN, "|null");


			delete[] ParentName;
			delete[] ParentPath;
			delete[] Comstr;
			delete[] cTempStr;

			if (outFile.good()) outFile << buff << "\n";
			else log.logger("Error", "write to Scan.txt failed");

		}
		m_Count++;
	}
	outFile.close();

	//m_Hash.clear();

	//if (!pUnKnownData->empty())
	//{
	//	printf("pUnKnownData\n");
	//	vector<UnKnownDataInfo>::iterator ut;
	//	memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//	wchar_t* wUnKownInfoStr = new wchar_t[DATASTRINGMESSAGELEN];
	//	int ret = 1;
	//	char* cUnKownInfoStr = NULL;
	//	for (ut = pUnKnownData->begin(); ut != pUnKnownData->end(); ut++)
	//	{
	//		swprintf_s(wUnKownInfoStr, DATASTRINGMESSAGELEN, L"%lu|%s|%d", (*ut).Pid, (*ut).ProcessName, (*ut).SizeInfo);
	//		cUnKownInfoStr = CStringToCharArray(wUnKownInfoStr, CP_UTF8);
	//		sprintf_s(TempStr, DATASTRINGMESSAGELEN, "%s", cUnKownInfoStr);
	//		ret = socketsend->SendMessageToServer(functionName_GiveProcessUnknownInfo, TempStr);
	//		if (ret <= 0)
	//			break;
	//		memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//		if ((*ut).SizeInfo > DATASTRINGMESSAGELEN /*&& ret != -3*/)
	//		{
	//			int tmplen = (*ut).SizeInfo;
	//			for (DWORD i = 0; i < (*ut).SizeInfo; i += DATASTRINGMESSAGELEN)
	//			{
	//				char* TmpBuffer = new char[DATASTRINGMESSAGELEN];
	//				memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
	//				if (tmplen < DATASTRINGMESSAGELEN)
	//					memcpy(TmpBuffer, (*ut).Data + i, tmplen);
	//				else
	//				{
	//					memcpy(TmpBuffer, (*ut).Data + i, DATASTRINGMESSAGELEN);
	//					tmplen -= DATASTRINGMESSAGELEN;
	//				}
	//				ret = socketsend->SendMessageToServer(functionName_GiveProcessUnknownInfo, TmpBuffer);
	//				//Sendret = m_Client->SendDataBufToServer(pInfo->MAC,pInfo->IP,WorkStr,TmpBuffer);
	//				delete[] TmpBuffer;
	//				if (ret <= 0)
	//				{
	//					break;
	//				}
	//			}
	//			if (ret <= 0)
	//				break;
	//		}
	//		else
	//		{
	//			char* TmpBuffer = new char[DATASTRINGMESSAGELEN];
	//			memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
	//			memcpy(TmpBuffer, (*ut).Data, (*ut).SizeInfo);
	//			ret = socketsend->SendMessageToServer(functionName_GiveProcessUnknownInfo, TmpBuffer);
	//			//Sendret = m_Client->SendDataBufToServer(pInfo->MAC,pInfo->IP,WorkStr,TmpBuffer);
	//			delete[] TmpBuffer;
	//			if (ret <= 0)
	//				break;
	//		}
	//		
	//		ret = socketsend->SendMessageToServer(functionName_GiveProcessUnknownEnd, null);
	//		if (ret <= 0)
	//			break;
	//		delete[] cUnKownInfoStr;
	//		cUnKownInfoStr = NULL;
	//	}
	//	if (cUnKownInfoStr != NULL)
	//		delete[] cUnKownInfoStr;
	//	delete[] wUnKownInfoStr;
	//	for (ut = pUnKnownData->begin(); ut != pUnKnownData->end(); ut++)
	//	{
	//		delete[](*ut).Data;
	//	}
	//}

	// Compress Scan.txt
	if (tool.CompressFileToZip(Scan_zip, Scan_txt)) _tprintf(_T("File compressed and added to Scan ZIP successfully.\n"));
	else log.logger("Error", "failed to add file to Scan Zip");

	// Get Scan.txt Size
	std::ifstream file(Scan_zip, std::ios::binary);
	if (!file.is_open()) {
		std::cout << "Failed to open file." << std::endl;
		log.logger("Error", "failed to open zip file");
		return;
	}
	file.seekg(0, std::ios::end);
	std::streampos fileSize = file.tellg();
	file.close();
	long long fileSizeLL = static_cast<long long>(fileSize);

	// send GiveScanInfo
	char* FileSize = new char[DATASTRINGMESSAGELEN];
	sprintf_s(FileSize, DATASTRINGMESSAGELEN, "%lld", fileSizeLL);
	ret = SendDataPacketToServer("GiveScanDataInfo", FileSize, tcpSocket);
	delete[] FileSize;

	// send zip file
	SendFileToServer("Scan", Scan_zip, tcpSocket);

	//DeleteFile(Scan_txt);
	DeleteFile(Scan_zip);


	delete[] buff;
	ret = SendDataPacketToServer("GiveScanEnd", pMode, tcpSocket);
}

int Scan::ProcessDump(DumpMemoryInfo* pInfo) {
	TCHAR* Scan_txt = new TCHAR[MAX_PATH_EX];
	GetMyPath(Scan_txt);
	_tcscat_s(Scan_txt, MAX_PATH_EX, _T("\\Scan.txt"));
	DeleteFile(Scan_txt);
	std::wofstream outFile(Scan_txt, std::ios::app);
	if (!outFile.is_open()) log.logger("Error", "Scan.txt open failed");

	MemProcess* m_MemPro = new MemProcess;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pInfo->ProcessID);
	if (!hProc)
	{
		return -1;
	}
#ifndef _M_IX86
	SIZE_T ptype = m_MemPro->Process32or64(hProc);
	if (!ptype)
	{
		/*AfxMessageBox(_T("IsWow64Process failed."));*/
		CloseHandle(hProc);
		return -1;
	}
	SIZE_T startmem = 0;
	SIZE_T maxmem = 0x7FFF0000;
	if (ptype == 64)
	{
		maxmem = 0x7FFFFFEFFFF;
	}
#else
	SIZE_T ptype = 32;
	SIZE_T startmem = 0;
	SIZE_T maxmem = 0x7FFF0000;
#endif
	int count = 0;
	wchar_t lastfilename[MAX_PATH];
	while (startmem < maxmem)
	{
		MEMORY_BASIC_INFORMATION mbi;
		SIZE_T size = VirtualQueryEx(hProc, (LPVOID)startmem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		if (!size)
		{
			CloseHandle(hProc);
			return -2;
		}
		TCHAR* output = new TCHAR[_MAX_FNAME];
		TCHAR* m_FileName = new TCHAR[_MAX_FNAME];
#ifndef _M_IX86
		if (startmem, ptype == 64)
			swprintf_s(output, _MAX_FNAME, _T("%016I64X-%016I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
		else
			swprintf_s(output, _MAX_FNAME, _T("%08I64X-%08I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
#else
		swprintf_s(output, _MAX_FNAME, _T("%08I64X-%08I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
#endif
		if (mbi.State == MEM_COMMIT)
		{
			char* buffer = new char[mbi.RegionSize];
			SIZE_T nread = 0;
			//DWORD oldprotect;
			//if (VirtualProtectEx(hProc,mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&oldprotect))
			//{
			//	mbi.AllocationProtect = oldprotect;
			//	VirtualProtectEx(hProc,mbi.BaseAddress,mbi.RegionSize,oldprotect,&oldprotect);
			ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &nread);
			swprintf_s(m_FileName, _MAX_FNAME, _T("%.3d_%s"), count, output);
			//output = L"output\\"+output;
			if (nread == mbi.RegionSize)
			{
				bool typeok = false;
				if (pInfo->ReadMode)
				{
					if (((mbi.AllocationProtect & PAGE_READONLY) ||
						(mbi.AllocationProtect & PAGE_READWRITE) ||
						(mbi.AllocationProtect & PAGE_WRITECOPY) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_READ) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_READWRITE) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY))
						)
					{
						typeok = true;
					}
				}
				if (pInfo->WriteMode)
				{
					if (((mbi.AllocationProtect & PAGE_READWRITE) ||
						(mbi.AllocationProtect & PAGE_WRITECOPY) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_READWRITE) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY))
						)
					{
						typeok = true;
					}
				}
				if (pInfo->ExecuteMode)
				{
					if (((mbi.AllocationProtect & PAGE_EXECUTE) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_READ) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_READWRITE) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY))
						)
					{
						typeok = true;
					}
				}
				if (typeok)
				{
					if (m_MemPro->GetProcessMappedFileName(hProc, mbi.BaseAddress, lastfilename))
						swprintf_s(m_FileName, _MAX_FNAME, _T("%s"), lastfilename);
					char* cFileName = CStringToCharArray(m_FileName, CP_UTF8);
					double precentage = (double)100 * startmem / maxmem;
					unsigned int m_Progress = (unsigned int)precentage;
					int Sendret = 1;
					char* InfoStr = new char[MAX_PATH_EX];
#ifndef _M_IX86
					sprintf_s(InfoStr, MAX_PATH_EX, "%llu|%u|%s", mbi.RegionSize, m_Progress, cFileName);
#else
					sprintf_s(InfoStr, MAX_PATH_EX, "%lu|%u|%s", mbi.RegionSize, m_Progress, cFileName);
#endif
					BYTE* TmpBuffer1 = new BYTE[STRDATAPACKETSIZE];
					memset(TmpBuffer1, '\x0', STRDATAPACKETSIZE);
					memcpy(TmpBuffer1, InfoStr, strlen(InfoStr));
					//Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemDataInfo", TmpBuffer1);
					//Sendret = SendDataPacketToServer("GiveMemDataInfo", InfoStr, info->tcpSocket);
					if (outFile.good()) outFile << "GiveMemDataInfo\n";
					if (outFile.good()) outFile << InfoStr;
					if (outFile.good()) outFile << "\n";
					delete[] TmpBuffer1;
					if (Sendret == 0 || Sendret == -1)
					{
						delete[] InfoStr;
						delete[] cFileName;
						delete[] buffer;
						CloseHandle(hProc);
						return -3;
					}
					delete[] InfoStr;
					log.logger("Debug", "mbi.RegionSize start");
					if (mbi.RegionSize > STRDATAPACKETSIZE)
					{
						SIZE_T tmplen = mbi.RegionSize;
						for (SIZE_T i = 0; i < mbi.RegionSize; i += STRDATAPACKETSIZE)
						{
							log.logger("Debug", "mbi.RegionSize");
							BYTE* TmpBuffer = new BYTE[STRDATAPACKETSIZE];
							memset(TmpBuffer, '\x00', STRDATAPACKETSIZE);
							if (tmplen < STRDATAPACKETSIZE)
								memcpy(TmpBuffer, buffer + i, tmplen);
							else
							{
								memcpy(TmpBuffer, buffer + i, STRDATAPACKETSIZE);
								tmplen -= STRDATAPACKETSIZE;
							}
							//Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemData", TmpBuffer);
							char* charBuffer = reinterpret_cast<char*>(TmpBuffer);
							//Sendret = SendDataPacketToServer("GiveMemData", charBuffer, info->tcpSocket);
							if (outFile.good()) outFile << "GiveMemData\n";
							if (outFile.good()) outFile << charBuffer;
							if (outFile.good()) outFile << "\n";
							delete[] TmpBuffer;
							if (Sendret == 0 || Sendret == -1)
							{
								delete[] cFileName;
								delete[] buffer;
								CloseHandle(hProc);
								return -3;
							}
						}
					}
					else
					{
						log.logger("Debug", "mbi.RegionSize failed");
						BYTE* TmpBuffer = new BYTE[STRDATAPACKETSIZE];
						memset(TmpBuffer, '\x00', STRDATAPACKETSIZE);
						memcpy(TmpBuffer, buffer, mbi.RegionSize);
						//Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemData", TmpBuffer);
						char* charBuffer = reinterpret_cast<char*>(TmpBuffer);
						//Sendret = SendDataPacketToServer("GiveMemData", charBuffer, info->tcpSocket);
						if (outFile.good()) outFile << "GiveMemData\n";
						if (outFile.good()) outFile << charBuffer;
						if (outFile.good()) outFile << "\n";
						delete[] TmpBuffer;
						if (Sendret == 0 || Sendret == -1)
						{
							delete[] cFileName;
							delete[] buffer;
							CloseHandle(hProc);
							return -3;
						}
					}
					delete[] cFileName;
					count++;
				}
			}
			//}
			//delete [] buffer;
		}
		startmem = (SIZE_T)mbi.BaseAddress + (SIZE_T)mbi.RegionSize;
		delete[] m_FileName;
		delete[] output;
	}
	CloseHandle(hProc);
	return 0;
}
int Scan::ScanInjectedProcessDump(ScanMemoryInfo* pInfo)
{
	log.logger("Debug", "ScanInjectedProcessDump.");
	MemProcess* m_MemPro = new MemProcess;
	int retNum = 0;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, 8388);
	if (!hProc) {
		log.logger("Error", "OpenProcess failed.");
		retNum = -1;
	}
	else {
		log.logger("Debug", "OpenProcess success.");
#ifndef _M_IX86
		SIZE_T ptype = m_MemPro->Process32or64(hProc);
#else
		SIZE_T ptype = 32;
#endif
		if (!ptype) {
			log.logger("Error", "IsWow64Process failed.");
			retNum = -1;
		}
		else {
			log.logger("Debug", "IsWow64Process success.");
#ifndef _M_IX86
			SIZE_T startmem = 0;
			SIZE_T maxmem = 0x7FFF0000;
			if (ptype == 64) maxmem = 0x7FFFFFEFFFF;
#else
			//SIZE_T ptype = 32;
			SIZE_T startmem = 0;
			SIZE_T maxmem = 0x7FFF0000;
#endif
			//int count = 0;
			wchar_t lastfilename[MAX_PATH];
			while (startmem < maxmem) {
				MEMORY_BASIC_INFORMATION mbi;
				SIZE_T size = VirtualQueryEx(hProc, (LPVOID)startmem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
				if (!size) {
					log.logger("Error", "VirtualQueryEx failed.");
					retNum = -2;
					break;
				}
				TCHAR* output = new TCHAR[_MAX_FNAME];
				TCHAR* m_FileName = new TCHAR[_MAX_FNAME];
#ifndef _M_IX86
				if (startmem, ptype == 64)
					swprintf_s(output, _MAX_FNAME, _T("%016I64X-%016I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
				else
					swprintf_s(output, _MAX_FNAME, _T("%08I64X-%08I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
#else
				swprintf_s(output, _MAX_FNAME, _T("%08I64X-%08I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
#endif
				if (mbi.State == MEM_COMMIT) {
					char* buffer = new char[mbi.RegionSize];
					SIZE_T nread = 0;
					//DWORD oldprotect;
					//if (VirtualProtectEx(hProc,mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&oldprotect))
					//{
					//	mbi.AllocationProtect = oldprotect;
					//	VirtualProtectEx(hProc,mbi.BaseAddress,mbi.RegionSize,oldprotect,&oldprotect);
					ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &nread);
					//swprintf_s(m_FileName,_MAX_FNAME,_T("%.3d_%s"),count,output);
					//output = L"output\\"+output;
					if (nread == mbi.RegionSize)
					{
						bool typeok = false;
						if (mbi.AllocationProtect & PAGE_EXECUTE_READWRITE)
						{
							if (!m_MemPro->GetProcessMappedFileName(hProc, mbi.BaseAddress, lastfilename))
							{
								typeok = true;
								swprintf_s(m_FileName, _MAX_FNAME, _T("PAGE_EXECUTE_READWRITE_%s"), output);
							}
						}
						else if (mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY)
						{
							if (!m_MemPro->GetProcessMappedFileName(hProc, mbi.BaseAddress, lastfilename))
							{
								typeok = true;
								swprintf_s(m_FileName, _MAX_FNAME, _T("PAGE_EXECUTE_WRITECOPY_%s"), output);
							}
						}

						if (typeok)
						{
							log.logger("Debug", "typeok true");
							char* cFileName = CStringToCharArray(m_FileName, CP_UTF8);
							//double precentage = (double)100*startmem/maxmem;
							//unsigned int m_Progress = (unsigned int)precentage;
							int Sendret;
							char* InfoStr = new char[MAX_PATH_EX];
#ifndef _M_IX86
							sprintf_s(InfoStr, MAX_PATH_EX, "%llu|0|%s", mbi.RegionSize, cFileName);
#else
							sprintf_s(InfoStr, MAX_PATH_EX, "%lu|0|%s", mbi.RegionSize, cFileName);
#endif
							BYTE* InfoBuffer = new BYTE[STRDATAPACKETSIZE];
							memset(InfoBuffer, '\x0', STRDATAPACKETSIZE);
							memcpy(InfoBuffer, InfoStr, strlen(InfoStr));
							//Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemScanInfo", InfoBuffer);
							Sendret = SendDataPacketToServer("GiveMemScanInfo", InfoStr, info->tcpSocket);
							delete[] InfoBuffer;
							if (Sendret <= 0)
							{
								delete[] InfoStr;
								delete[] cFileName;
								delete[] buffer;
								delete[] m_FileName;
								delete[] output;
								//CloseHandle(hProc);
								retNum = -3;
								break;
							}
							//delete[] InfoStr;
							if (mbi.RegionSize > STRDATAPACKETSIZE)
							{
								SIZE_T tmplen = mbi.RegionSize;
								for (SIZE_T i = 0; i < mbi.RegionSize; i += STRDATAPACKETSIZE)
								{
									BYTE* TmpBuffer = new BYTE[STRDATAPACKETSIZE];
									memset(TmpBuffer, '\x00', STRDATAPACKETSIZE);
									if (tmplen < STRDATAPACKETSIZE)
										memcpy(TmpBuffer, buffer + i, tmplen);
									else
									{
										memcpy(TmpBuffer, buffer + i, STRDATAPACKETSIZE);
										tmplen -= STRDATAPACKETSIZE;
									}
									//Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemScanData", TmpBuffer);
									Sendret = SendDataPacketToServer("GiveMemScanInfo", InfoStr, info->tcpSocket);
									delete[] TmpBuffer;
									if (Sendret <= 0)
									{
										delete[] cFileName;
										delete[] buffer;
										//CloseHandle(hProc);
										delete[] m_FileName;
										delete[] output;
										retNum = -3;
										break;
									}
								}
							}
							else
							{
								BYTE* TmpBuffer = new BYTE[STRDATAPACKETSIZE];
								memset(TmpBuffer, '\x00', STRDATAPACKETSIZE);
								memcpy(TmpBuffer, buffer, mbi.RegionSize);
								//Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemScanData", TmpBuffer);
								Sendret = SendDataPacketToServer("GiveMemScanInfo", InfoStr, info->tcpSocket);
								delete[] TmpBuffer;
								if (Sendret == 0 || Sendret == -1)
								{
									delete[] cFileName;
									delete[] buffer;
									delete[] m_FileName;
									delete[] output;
									//CloseHandle(hProc);
									retNum = -3;
									break;
								}
							}
							delete[] cFileName;
							//count++;
						}
						else {
							log.logger("Debug", "typeok false");
						}
					}
					//}
					delete[] buffer;
				}
				startmem = (SIZE_T)mbi.BaseAddress + (SIZE_T)mbi.RegionSize;
				delete[] m_FileName;
				delete[] output;
			}
		}
		CloseHandle(hProc);
	}
	return retNum;
}