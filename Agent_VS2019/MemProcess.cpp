#include "MemProcess.h"

//#include "AccessFilesHeader.h"
#include <aclapi.h>
//#include "ProcessAccessFiles.h"

#include <imagehlp.h>

typedef NTSTATUS(__stdcall* PNtQueryVirtualMemory)(
	HANDLE                   ProcessHandle,
	PVOID                    BaseAddress,
	DWORD					 MemoryInformationClass,
	PVOID                    MemoryInformation,
	SIZE_T                   MemoryInformationLength,
	PSIZE_T                  ReturnLength
	);
//typedef struct _LOADED_IMAGE32 {
//	PSTR                  ModuleName;
//	HANDLE                hFile;
//	PUCHAR                MappedAddress;
//
//	PIMAGE_NT_HEADERS32   FileHeader;
//
//	PIMAGE_SECTION_HEADER LastRvaSection;
//	ULONG                 NumberOfSections;
//	PIMAGE_SECTION_HEADER Sections;
//	ULONG                 Characteristics;
//	BOOLEAN               fSystemImage;
//	BOOLEAN               fDOSImage;
//	BOOLEAN               fReadOnly;
//	UCHAR                 Version;
//	LIST_ENTRY            Links;
//	ULONG                 SizeOfImage;
//} LOADED_IMAGE32, * PLOADED_IMAGE32;
//PNtQueryVirtualMemory _NtQueryVirtualMemory = (PNtQueryVirtualMemory)GetProcAddress(LoadLibrary(L"ntdll.dll"),"NtQueryVirtualMemory");
//unsigned __stdcall threadGetFileName(void *argv);
//unsigned __stdcall threadParserProcess(void *argv);
//unsigned __stdcall threadGetFileName(void *argv)
//{
//	ThreadInfo * pInfo = (ThreadInfo *)argv;
//	MemProcess * pClass = (MemProcess*)pInfo->pClass;
//	pClass->ParserProcessOpenHandle(pInfo);
//	//delete pInfo;
//	return 0;
//}
//unsigned __stdcall threadParserProcess(void *argv)
//{
//	ThreadProcessInfo * pInfo = (ThreadProcessInfo *)argv;
//	MemProcess * pClass = (MemProcess*)pInfo->pClass;
//	//TCHAR * str = new TCHAR[50];
//	//swprintf_s(str,50,_T("%d-Start"),pInfo->m_Info.pid);
//	//MessageBox(0,str,0,0);
//	try
//	{
//		pClass->ParserProcessRisk(pInfo);
//	}
//	catch(...){}
//	//swprintf_s(str,50,_T("%d-End"),pInfo->m_Info.pid);
//	delete pInfo;
//	//MessageBox(0,str,0,0);
//	return 0;
//}
unsigned __stdcall threadAccessFiles(void* argv);
unsigned __stdcall threadAccessFiles(void* argv)
{
	ThreadInfo* pInfo = (ThreadInfo*)argv;
	MemProcess* pMemProcess = (MemProcess*)pInfo->pClass;
	pMemProcess->InjectionNewProcess(pInfo);
	delete pInfo;
	return 0;
}
MemProcess::MemProcess()
{

}
MemProcess::~MemProcess()
{

}

void MemProcess::LoadNowProcessInfo(map<DWORD, process_info_Ex>* pInfo)
{
	bool ret = false;
#if defined _M_X64
	ret = EnumProcessEx(pInfo);
#elif defined _M_IX86
	time_t LoadCheckProcessTime = 0;
	time(&LoadCheckProcessTime);
	ret = EnumRing0ProcessEx(pInfo);
	if (!ret)
		ret = EnumProcessEx(pInfo);
	else
	{
		map<DWORD, process_info_Ex> m_CInfo;
		if (EnumProcessEx(&m_CInfo) && LoadCheckProcessTime > 0)
			CheckProcessHideEx(pInfo, &m_CInfo, LoadCheckProcessTime);

	}
#endif
	if (ret)
	{
		map<DWORD, process_info_Ex>::iterator it;
		map<DWORD, process_info_Ex>::iterator st;
		for (it = pInfo->begin(); it != pInfo->end(); it++)
		{
			_tcscpy_s(it->second.process_Path, 512, _T("null"));
			_tcscpy_s(it->second.process_Com, 512, _T("null"));
			_tcscpy_s(it->second.m_SID, 256, _T("null"));
			it->second.parentCreateTime = 0;
			it->second.IsPacked = FALSE;
			st = pInfo->find((DWORD)it->second.parent_pid);
			if (st != pInfo->end())
			{
				if (st->second.ProcessCreateTime <= it->second.ProcessCreateTime)
				{
					//_tcscpy_s(ParentName,MAX_PATH,st->second.process_name);
					it->second.parentCreateTime = st->second.ProcessCreateTime;
				}
			}
			GetProcessInfo(it->first, it->second.process_Path, NULL, it->second.m_SID, it->second.process_Com);
			if (_tcscmp(it->second.process_Path, _T("null")))
			{
				it->second.IsPacked = CheckIsPackedPE(it->second.process_Path);
			}
		}
	}
}
void MemProcess::LoadNowProcessInfoDetect(map<DWORD, process_info_Ex>* pInfo)
{
	BOOL ContinueLoop;
	PROCESSENTRY32 pe32;
	HANDLE SnapshotHandle;
	//HMODULE hModuleHandle;
	//DWORD dwNeeded;
	SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	pe32.dwSize = sizeof(pe32);

	ContinueLoop = Process32First(SnapshotHandle, &pe32);

	while (ContinueLoop)
	{
		process_info_Ex tmp;
		tmp.pid = pe32.th32ProcessID;
		tmp.parent_pid = pe32.th32ParentProcessID;
		wcscpy_s(tmp.process_name, MAX_PATH, pe32.szExeFile);

		TCHAR* m_Path = new TCHAR[512];
		TCHAR* m_ComStr = new TCHAR[512];
		TCHAR* m_Time = new TCHAR[20];
		//TCHAR * ParentName = new TCHAR[MAX_PATH];
		TCHAR* m_UserName = new TCHAR[_MAX_FNAME];
		tmp.IsPacked = FALSE;
		_tcscpy_s(m_Path, 512, _T("null"));
		_tcscpy_s(m_ComStr, 512, _T("null"));
		_tcscpy_s(m_Time, 20, _T("null"));
		//_tcscpy_s(ParentName,MAX_PATH,_T("null"));
		_tcscpy_s(m_UserName, _MAX_FNAME, _T("null"));
		GetProcessInfo(pe32.th32ProcessID, m_Path, m_Time, m_UserName, m_ComStr);
		tmp.ProcessCreateTime = _ttoi64(m_Time);
		wcscpy_s(tmp.m_SID, _MAX_FNAME, m_UserName);
		wcscpy_s(tmp.process_Path, MAX_PATH_EX, m_Path);
		wcscpy_s(tmp.process_Com, MAX_PATH_EX, m_ComStr);
		if (_tcscmp(m_Path, _T("null")))
		{
			tmp.IsPacked = CheckIsPackedPE(m_Path);
		}
		tmp.IsHide = FALSE;
		tmp.parentCreateTime = 0;
		pInfo->insert(pair<DWORD, process_info_Ex>(tmp.pid, tmp));
		delete[] m_UserName;
		//delete [] ParentName;
		delete[] m_Time;
		delete[] m_ComStr;
		delete[] m_Path;
		ContinueLoop = Process32Next(SnapshotHandle, &pe32);
	}
	CloseHandle(SnapshotHandle);
}
void MemProcess::ScanRunNowProcess(void* argv, map<DWORD, ProcessInfoData>* pInfo, set<DWORD>* pApiName, vector<UnKnownDataInfo>* pMembuf)
{
	map<DWORD, process_info_Ex> process_list;
	printf("LoadNowProcessInfo\n");
	LoadNowProcessInfo(&process_list);
	vector<TCPInformation> NetInfo;
	char* OSstr = GetOSVersion();

	printf("GetTcpInformationEx\n");
	if ((strstr(OSstr, "Windows XP") != 0) || (strstr(OSstr, "Windows Server 2003") != 0)) GetTcpInformationXPEx(&NetInfo);
	else if (strstr(OSstr, "Windows 2000") != 0) {}
	else GetTcpInformationEx(&NetInfo);
	delete[] OSstr;
	time_t NetworkClock;
	time(&NetworkClock);
	//int ret = m_Client->SendDataMsgToServer(m_Client->MyMAC, m_Client->MyIP, "GiveScanProgress", "10");

	map<wstring, BOOL> m_ServiceRun;
	set<wstring> m_StartRun;
	AutoRun* m_AutoRun = new AutoRun;
	printf("LoadServiceStartCommand\n");
	m_AutoRun->LoadServiceStartCommand(&m_ServiceRun);
	printf("LoadAutoRunStartCommand\n");
	m_AutoRun->LoadAutoRunStartCommand(&m_StartRun);
	//MessageBox(0,L"168",0,0);
	//if (ret > 0)
	//{

	int InfoSize = (int)process_list.size();
	int InfoCount = 0;
	map<DWORD, process_info_Ex>::iterator pt;
	for (pt = process_list.begin(); pt != process_list.end(); pt++, InfoCount++)
	{
		if (!IsWindowsProcessNormal(&process_list, pt->first))
		{
			ProcessInfoData m_Info;
			m_Info.HideAttribute = FALSE;
			m_Info.HideProcess = pt->second.IsHide;
			lstrcpy(m_Info.ProcessName, pt->second.process_name);
			_tcscpy_s(m_Info.ProcessPath, MAX_PATH_EX, pt->second.process_Path);
			//memset(m_Info.ProcessTime,'\0',20);
			_tcscpy_s(m_Info.ProcessTime, 20, _T("null"));
			_tcscpy_s(m_Info.ProcessCTime, 20, _T("null"));
			_tcscpy_s(m_Info.ParentCTime, 20, _T("null"));
			if (pt->second.ProcessCreateTime > 0)
				swprintf_s(m_Info.ProcessCTime, 20, _T("%llu"), pt->second.ProcessCreateTime);
			if (pt->second.parentCreateTime > 0)
				swprintf_s(m_Info.ParentCTime, 20, _T("%llu"), pt->second.parentCreateTime);
			//GetProcessPath(pt->first,m_Info.ProcessPath,true,NULL,m_Info.ProcessCTime);
			if (!_tcscmp(m_Info.ProcessPath, _T("null")))
			{
				//Sleep(100);
				//GetProcessOnlyPath(pInfo->pid,m_Info.ProcessPath);
				SearchExecutePath(pt->first, m_Info.ProcessPath, pt->second.process_name);
			}
			SYSTEMTIME sys;
			GetLocalTime(&sys);
			swprintf_s(m_Info.ProcessTime, 20, _T("%4d/%02d/%02d %02d:%02d:%02d"), sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond);
			m_Info.ParentID = pt->second.parent_pid;
			if (pt->second.parentCreateTime > 0)
				GetProcessPath(pt->second.parent_pid, m_Info.ParentPath, true, NULL, NULL);
			else
				_tcscpy_s(m_Info.ParentPath, MAX_PATH_EX, _T("null"));
			_tcscpy_s(m_Info.UnKnownHash, 50, _T("null"));
			m_Info.Injected = CheckIsInjection(pt->first, pMembuf, m_Info.ProcessName, m_Info.UnKnownHash);
			//m_Info.Injected = FALSE;
			m_Info.StartRun = CheckIsStartRun(&m_ServiceRun, &m_StartRun, pt->first/*,m_Info.HideService*/);

			CheckIsInlineHook(pt->first, &m_Info.InlineHookInfo);

			TCHAR Md5Hashstr[50];
			memset(Md5Hashstr, '\0', 50);
			DWORD MD5ret = Md5Hash(m_Info.ProcessPath, Md5Hashstr);
			if (MD5ret == 0)
				lstrcpy(m_Info.ProcessHash, Md5Hashstr);
			else
				lstrcpy(m_Info.ProcessHash, _T("null"));

			if (_tcscmp(m_Info.ProcessPath, _T("null")))
			{
				DWORD AttRet = GetFileAttributes(m_Info.ProcessPath);
				if ((AttRet & FILE_ATTRIBUTE_HIDDEN) == FILE_ATTRIBUTE_HIDDEN)
					m_Info.HideAttribute = TRUE;
				DigitalSignatureInfo* DSinfo = new DigitalSignatureInfo;
				_tcscpy_s(DSinfo->SignerSubjectName, 256, _T("null"));
				bool DSret = GetDigitalSignature(m_Info.ProcessPath, DSinfo);
				if (DSret)
				{
					swprintf_s(m_Info.SignerSubjectName, 256, _T("%s"), DSinfo->SignerSubjectName);
				}
				else
				{
					lstrcpy(m_Info.SignerSubjectName, _T("null"));
				}
				delete DSinfo;
			}
			else
			{
				lstrcpy(m_Info.SignerSubjectName, _T("null"));
			}
			set<DWORD> ApiStringHash;
			DumpExecute(pt->first, pt->second.process_name, pApiName, &ApiStringHash, m_Info.ProcessPath, &m_Info.Abnormal_dll);
			m_Info.InjectionOther = FALSE;
			m_Info.InjectionPE = FALSE;
			CheckInjectionPtn(&ApiStringHash, m_Info.InjectionOther, m_Info.InjectionPE);
			ApiStringHash.clear();
			vector<TCPInformation>::iterator Tcpit;
			for (Tcpit = NetInfo.begin(); Tcpit != NetInfo.end(); Tcpit++)
			{
				if ((*Tcpit).ProcessID == pt->first)
				{
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


	delete m_AutoRun;
	m_StartRun.clear();
	m_ServiceRun.clear();
	NetInfo.clear();
	process_list.clear();
}


//void MemProcess::enumallprocess(void* argv, char* pMAC, char* pIP)
//{
//	TransportData* m_Client = (TransportData*)argv;
//	map<DWORD, process_info> process_list;
//	map<DWORD, process_info> Checkprocess_list;
//	bool ret = false;
//	time_t LoadProcessTime = 0;
//#if defined _M_X64
//	ret = EnumProcess(&process_list, LoadProcessTime);
//#elif defined _M_IX86
//	ret = EnumRing0Process(&process_list, LoadProcessTime);
//	if (!ret)
//		ret = EnumProcess(&process_list, LoadProcessTime);
//	else
//	{
//		time_t LoadCheckProcessTime = 0;
//		if (EnumProcess(&Checkprocess_list, LoadCheckProcessTime))
//			CheckProcessHide(&process_list, &Checkprocess_list, LoadProcessTime);
//	}
//#endif
//	if (ret)
//	{
//		char* TempStr = new char[DATASTRINGMESSAGELEN];
//		memset(TempStr, '\0', DATASTRINGMESSAGELEN);
//		int DataCount = 0;
//		map<DWORD, process_info>::iterator it;
//		map<DWORD, process_info>::iterator st;
//		for (it = process_list.begin(); it != process_list.end(); it++)
//		{
//			TCHAR* m_Path = new TCHAR[512];
//			TCHAR* m_ComStr = new TCHAR[512];
//			//TCHAR * m_Time = new TCHAR[20];
//			TCHAR* ParentName = new TCHAR[MAX_PATH];
//			TCHAR* m_UserName = new TCHAR[_MAX_FNAME];
//			BOOL IsPacked = FALSE;
//			time_t ParentTime = 0;
//			_tcscpy_s(m_Path, 512, _T("null"));
//			_tcscpy_s(m_ComStr, 512, _T("null"));
//			//_tcscpy_s(m_Time,20,_T("null"));
//			_tcscpy_s(ParentName, MAX_PATH, _T("null"));
//			_tcscpy_s(m_UserName, _MAX_FNAME, _T("null"));
//			GetProcessInfo(it->first, m_Path, NULL, m_UserName, m_ComStr);
//			if (_tcscmp(m_Path, _T("null")))
//			{
//				IsPacked = CheckIsPackedPE(m_Path);
//			}
//			st = process_list.find(it->second.parent_pid);
//			if (st != process_list.end())
//			{
//				if (st->second.ProcessCreateTime <= it->second.ProcessCreateTime)
//				{
//					_tcscpy_s(ParentName, MAX_PATH, st->second.process_name);
//					ParentTime = st->second.ProcessCreateTime;
//				}
//				//GetProcessOnlyTime(it->second.parent_pid,ParentTime);
//				//if(ParentTime < 0)
//				//	ParentTime = 0;
//			}
//			wchar_t* wstr = new wchar_t[2048];
//			swprintf_s(wstr, 2048, L"%lu|%d|%s|%lld|%s|%lld|%s|%s|%d|%s|%d\n", it->first, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime, ParentName, ParentTime, m_Path, m_UserName, IsPacked, m_ComStr, it->second.IsHide);
//			DataCount++;
//			//wprintf(L"%s\n",wstr);
//			char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
//			strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
//			//int ret = m_Client->SendDataMsgToServer(pMAC,pIP,"GiveExplorerData",m_DataStr);
//			delete[] wstr;
//			delete[] m_UserName;
//			delete[] ParentName;
//			//delete [] m_Time;
//			delete[] m_ComStr;
//			delete[] m_Path;
//			if ((DataCount % 30) == 0 && DataCount >= 30)
//			{
//				int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveProcessData", TempStr);
//				if (ret == 0 || ret == -1)
//				{
//					delete[] m_DataStr;
//					delete[] TempStr;
//					process_list.clear();
//					return;
//				}
//				memset(TempStr, '\0', DATASTRINGMESSAGELEN);
//			}
//			delete[] m_DataStr;
//		}
//		if (TempStr[0] != '\0')
//		{
//			//MessageBoxA(0,TempStr,0,0);
//			int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveProcessData", TempStr);
//			if (ret == 0 || ret == -1)
//			{
//				delete[] TempStr;
//				process_list.clear();
//				return;
//			}
//		}
//		delete[] TempStr;
//	}
//	Checkprocess_list.clear();
//	process_list.clear();
//}
BOOL MemProcess::CheckHaveProcess(wchar_t* ProcessName, int PID)
{
	BOOL HaveProcess = FALSE;
	//HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	//if(hSnapshot != INVALID_HANDLE_VALUE) 
	//{
	//	PROCESSENTRY32 procSentry;
	//	procSentry.dwSize = sizeof(procSentry);
	//	BOOL Proc = Process32First(hSnapshot, &procSentry);
	//	for(; Proc; Proc = Process32Next(hSnapshot, &procSentry)) 
	//	{
	//		if (!_wcsicmp(procSentry.szExeFile,ProcessName))
	//		{
	//			if(procSentry.th32ProcessID == PID)
	//			{
	//				HaveProcess = TRUE;
	//				break;
	//			}
	//		}
	//	}
	//} 
	//CloseHandle(hSnapshot);
	map<DWORD, process_info> process_list;
	bool ret = false;
	time_t LoadProcessTime = 0;
#if defined _M_X64
	ret = EnumProcess(&process_list, LoadProcessTime);
#elif defined _M_IX86
	ret = EnumRing0Process(&process_list, LoadProcessTime);
	if (!ret)
		ret = EnumProcess(&process_list, LoadProcessTime);
#endif
	map<DWORD, process_info>::iterator it;
	it = process_list.find((DWORD)PID);
	if (it != process_list.end())
	{
		if (!_wcsicmp(it->second.process_name, ProcessName))
			HaveProcess = TRUE;
	}
	process_list.clear();
	return HaveProcess;
}
#ifndef _M_IX86
DWORD MemProcess::Process32or64(HANDLE hProcess)
{
	BOOL bIsWow64 = FALSE;
	DWORD returnvalue;
	if (!IsWow64Process(hProcess, &bIsWow64))
	{
		returnvalue = 0;
		return returnvalue;
	}
	if (bIsWow64)
	{
		returnvalue = 32;
	}
	else
	{
		returnvalue = 64;
	}
	return returnvalue;
}
#endif

//int MemProcess::ProcessDump(void* argv, DumpMemoryInfo* pInfo)
//{
//	TransportData* m_Client = (TransportData*)argv;
//
//	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pInfo->ProcessID);
//	if (!hProc)
//	{
//		return -1;
//	}
//#ifndef _M_IX86
//	SIZE_T ptype = Process32or64(hProc);
//	if (!ptype)
//	{
//		/*AfxMessageBox(_T("IsWow64Process failed."));*/
//		CloseHandle(hProc);
//		return -1;
//	}
//	SIZE_T startmem = 0;
//	SIZE_T maxmem = 0x7FFF0000;
//	if (ptype == 64)
//	{
//		maxmem = 0x7FFFFFEFFFF;
//	}
//#else
//	SIZE_T ptype = 32;
//	SIZE_T startmem = 0;
//	SIZE_T maxmem = 0x7FFF0000;
//#endif
//	int count = 0;
//	wchar_t lastfilename[MAX_PATH];
//	while (startmem < maxmem)
//	{
//		MEMORY_BASIC_INFORMATION mbi;
//		SIZE_T size = VirtualQueryEx(hProc, (LPVOID)startmem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
//		if (!size)
//		{
//			CloseHandle(hProc);
//			return -2;
//		}
//		TCHAR* output = new TCHAR[_MAX_FNAME];
//		TCHAR* m_FileName = new TCHAR[_MAX_FNAME];
//#ifndef _M_IX86
//		if (startmem, ptype == 64)
//			swprintf_s(output, _MAX_FNAME, _T("%016I64X-%016I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
//		else
//			swprintf_s(output, _MAX_FNAME, _T("%08I64X-%08I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
//#else
//		swprintf_s(output, _MAX_FNAME, _T("%08I64X-%08I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
//#endif
//		if (mbi.State == MEM_COMMIT)
//		{
//			char* buffer = new char[mbi.RegionSize];
//			SIZE_T nread = 0;
//			//DWORD oldprotect;
//			//if (VirtualProtectEx(hProc,mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&oldprotect))
//			//{
//			//	mbi.AllocationProtect = oldprotect;
//			//	VirtualProtectEx(hProc,mbi.BaseAddress,mbi.RegionSize,oldprotect,&oldprotect);
//			ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &nread);
//			swprintf_s(m_FileName, _MAX_FNAME, _T("%.3d_%s"), count, output);
//			//output = L"output\\"+output;
//			if (nread == mbi.RegionSize)
//			{
//				bool typeok = false;
//				if (pInfo->ReadMode)
//				{
//					if (((mbi.AllocationProtect & PAGE_READONLY) ||
//						(mbi.AllocationProtect & PAGE_READWRITE) ||
//						(mbi.AllocationProtect & PAGE_WRITECOPY) ||
//						(mbi.AllocationProtect & PAGE_EXECUTE_READ) ||
//						(mbi.AllocationProtect & PAGE_EXECUTE_READWRITE) ||
//						(mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY))
//						)
//					{
//						typeok = true;
//					}
//				}
//				if (pInfo->WriteMode)
//				{
//					if (((mbi.AllocationProtect & PAGE_READWRITE) ||
//						(mbi.AllocationProtect & PAGE_WRITECOPY) ||
//						(mbi.AllocationProtect & PAGE_EXECUTE_READWRITE) ||
//						(mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY))
//						)
//					{
//						typeok = true;
//					}
//				}
//				if (pInfo->ExecuteMode)
//				{
//					if (((mbi.AllocationProtect & PAGE_EXECUTE) ||
//						(mbi.AllocationProtect & PAGE_EXECUTE_READ) ||
//						(mbi.AllocationProtect & PAGE_EXECUTE_READWRITE) ||
//						(mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY))
//						)
//					{
//						typeok = true;
//					}
//				}
//				if (typeok)
//				{
//					if (GetProcessMappedFileName(hProc, mbi.BaseAddress, lastfilename))
//						swprintf_s(m_FileName, _MAX_FNAME, _T("%s"), lastfilename);
//					char* cFileName = CStringToCharArray(m_FileName, CP_UTF8);
//					double precentage = (double)100 * startmem / maxmem;
//					unsigned int m_Progress = (unsigned int)precentage;
//					int Sendret;
//					char* InfoStr = new char[MAX_PATH_EX];
//#ifndef _M_IX86
//					sprintf_s(InfoStr, MAX_PATH_EX, "%llu|%u|%s", mbi.RegionSize, m_Progress, cFileName);
//#else
//					sprintf_s(InfoStr, MAX_PATH_EX, "%lu|%u|%s", mbi.RegionSize, m_Progress, cFileName);
//#endif
//					BYTE* TmpBuffer1 = new BYTE[DATABUFFER];
//					memset(TmpBuffer1, '\x0', DATABUFFER);
//					memcpy(TmpBuffer1, InfoStr, strlen(InfoStr));
//					Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemDataInfo", TmpBuffer1);
//					delete[] TmpBuffer1;
//					if (Sendret == 0 || Sendret == -1)
//					{
//						delete[] InfoStr;
//						delete[] cFileName;
//						delete[] buffer;
//						CloseHandle(hProc);
//						return -3;
//					}
//					delete[] InfoStr;
//					if (mbi.RegionSize > DATABUFFER)
//					{
//						SIZE_T tmplen = mbi.RegionSize;
//						for (SIZE_T i = 0; i < mbi.RegionSize; i += DATABUFFER)
//						{
//							BYTE* TmpBuffer = new BYTE[DATABUFFER];
//							memset(TmpBuffer, '\x00', DATABUFFER);
//							if (tmplen < DATABUFFER)
//								memcpy(TmpBuffer, buffer + i, tmplen);
//							else
//							{
//								memcpy(TmpBuffer, buffer + i, DATABUFFER);
//								tmplen -= DATABUFFER;
//							}
//							Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemData", TmpBuffer);
//							delete[] TmpBuffer;
//							if (Sendret == 0 || Sendret == -1)
//							{
//								delete[] cFileName;
//								delete[] buffer;
//								CloseHandle(hProc);
//								return -3;
//							}
//						}
//					}
//					else
//					{
//						BYTE* TmpBuffer = new BYTE[DATABUFFER];
//						memset(TmpBuffer, '\x00', DATABUFFER);
//						memcpy(TmpBuffer, buffer, mbi.RegionSize);
//						Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemData", TmpBuffer);
//						delete[] TmpBuffer;
//						if (Sendret == 0 || Sendret == -1)
//						{
//							delete[] cFileName;
//							delete[] buffer;
//							CloseHandle(hProc);
//							return -3;
//						}
//					}
//					delete[] cFileName;
//					count++;
//				}
//			}
//			//}
//			//delete [] buffer;
//		}
//		startmem = (SIZE_T)mbi.BaseAddress + (SIZE_T)mbi.RegionSize;
//		delete[] m_FileName;
//		delete[] output;
//	}
//	CloseHandle(hProc);
//	return 0;
//}
//
//int MemProcess::OnlyProcessDump(void* argv, char* WorkStr, OnlyMemoryInfo* pInfo)
//{
//	TransportData* m_Client = (TransportData*)argv;
//
//	int ret = 0;
//	if (!_tcsicmp(pInfo->FileName, _T("Unknown")))
//	{
//		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pInfo->ProcessID);
//		if (!hProc)
//			return -1;
//
//#ifndef _M_IX86
//		SIZE_T ptype = Process32or64(hProc);
//		SIZE_T startmem = 0;
//		SIZE_T maxmem = 0x7FFF0000;
//		if (ptype == 64)
//		{
//			maxmem = 0x7FFFFFEFFFF;
//		}
//#else
//		SIZE_T ptype = 32;
//		SIZE_T startmem = 0;
//		SIZE_T maxmem = 0x7FFF0000;
//#endif
//		wchar_t lastfilename[MAX_PATH];
//		while (startmem < maxmem)
//		{
//			MEMORY_BASIC_INFORMATION mbi;
//			SIZE_T size = VirtualQueryEx(hProc, (LPVOID)startmem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
//			if (!size)
//			{
//				CloseHandle(hProc);
//				return -1;
//			}
//			if (mbi.State == MEM_COMMIT)
//			{
//				char* buffer = new char[mbi.RegionSize];
//				SIZE_T nread = 0;
//				//DWORD oldprotect;
//				//if (VirtualProtectEx(hProc,mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&oldprotect))
//				//{
//				//	mbi.AllocationProtect = oldprotect;
//				//	VirtualProtectEx(hProc,mbi.BaseAddress,mbi.RegionSize,oldprotect,&oldprotect);
//				ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &nread);
//				if (nread == mbi.RegionSize)
//				{
//					bool typeok = false;
//					if (mbi.AllocationProtect & PAGE_EXECUTE_READWRITE)
//					{
//						//output1 = L"PAGE_EXECUTE_READWRITE-"+output1;
//						//typeok = true;
//						if (!GetProcessMappedFileName(hProc, mbi.BaseAddress, lastfilename))
//						{
//							typeok = true;
//						}
//					}
//					else if (mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY)
//					{
//						//output1 = L"PAGE_EXECUTE_WRITECOPY-"+output1;
//						//typeok = true;
//						if (!GetProcessMappedFileName(hProc, mbi.BaseAddress, lastfilename))
//						{
//							typeok = true;
//						}
//					}
//					if (typeok)
//					{
//						if (IsPESignature((BYTE*)buffer, (int)mbi.RegionSize))
//						{
//							int Sendret;
//							char* InfoStr = new char[MAX_PATH_EX];
//#ifndef _M_IX86
//							sprintf_s(InfoStr, MAX_PATH_EX, "%llu", mbi.RegionSize);
//#else
//							sprintf_s(InfoStr, MAX_PATH_EX, "%lu", mbi.RegionSize);
//#endif
//							BYTE* TmpBuffer1 = new BYTE[DATABUFFER];
//							memset(TmpBuffer1, '\x0', DATABUFFER);
//							memcpy(TmpBuffer1, InfoStr, strlen(InfoStr));
//							Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveOnlyMemDataInfo", TmpBuffer1);
//							delete[] TmpBuffer1;
//							if (Sendret == 0 || Sendret == -1)
//								ret = -3;
//							delete[] InfoStr;
//							if (ret == -3)
//								break;
//							if (mbi.RegionSize > DATABUFFER /*&& ret != -3*/)
//							{
//								SIZE_T tmplen = mbi.RegionSize;
//								for (SIZE_T i = 0; i < mbi.RegionSize; i += DATABUFFER)
//								{
//									BYTE* TmpBuffer = new BYTE[DATABUFFER];
//									memset(TmpBuffer, '\x00', DATABUFFER);
//									if (tmplen < DATABUFFER)
//										memcpy(TmpBuffer, buffer + i, tmplen);
//									else
//									{
//										memcpy(TmpBuffer, buffer + i, DATABUFFER);
//										tmplen -= DATABUFFER;
//									}
//									Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, TmpBuffer);
//									delete[] TmpBuffer;
//									if (Sendret == 0 || Sendret == -1)
//									{
//										ret = -3;
//										break;
//									}
//								}
//								if (ret == -3)
//									break;
//							}
//							else
//							{
//								BYTE* TmpBuffer = new BYTE[DATABUFFER];
//								memset(TmpBuffer, '\x00', DATABUFFER);
//								memcpy(TmpBuffer, buffer, mbi.RegionSize);
//								Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, TmpBuffer);
//								delete[] TmpBuffer;
//								if (Sendret == 0 || Sendret == -1)
//								{
//									ret = -3;
//								}
//								if (ret == -3)
//									break;
//							}
//						}
//					}
//				}
//				//}
//				//delete [] buffer;
//			}
//			startmem = (SIZE_T)mbi.BaseAddress + (SIZE_T)mbi.RegionSize;
//		}
//		CloseHandle(hProc);
//	}
//	else
//	{
//		HMODULE hResult = NULL;
//		HANDLE hSnapshot;
//		MODULEENTRY32 me32;
//		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (DWORD)pInfo->ProcessID);
//		if (hSnapshot != INVALID_HANDLE_VALUE)
//		{
//			me32.dwSize = sizeof(MODULEENTRY32);
//			if (Module32First(hSnapshot, &me32))
//			{
//				do
//				{
//					if (!_tcsicmp(me32.szExePath, pInfo->FileName))
//					{
//						char* buffer = new char[me32.modBaseSize];
//						//HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pInfo->ProcessID);
//						//ReadProcessMemory(hProcess, me32.modBaseAddr, buffer, me32.modBaseSize, 0);
//						if (Toolhelp32ReadProcessMemory(pInfo->ProcessID, me32.modBaseAddr, buffer, me32.modBaseSize, 0))
//						{
//							//char * cFileName = CStringToCharArray(me32.szModule,CP_UTF8);
//							int Sendret;
//							char* InfoStr = new char[MAX_PATH_EX];
//							sprintf_s(InfoStr, MAX_PATH_EX, "%lu", me32.modBaseSize);
//							BYTE* TmpBuffer1 = new BYTE[DATABUFFER];
//							memset(TmpBuffer1, '\x0', DATABUFFER);
//							memcpy(TmpBuffer1, InfoStr, strlen(InfoStr));
//							Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveOnlyMemDataInfo", TmpBuffer1);
//							delete[] TmpBuffer1;
//							if (Sendret == 0 || Sendret == -1)
//								ret = -3;
//							delete[] InfoStr;
//							if (ret != -3)
//							{
//								if (me32.modBaseSize > DATABUFFER /*&& ret != -3*/)
//								{
//									DWORD tmplen = me32.modBaseSize;
//									for (SIZE_T i = 0; i < me32.modBaseSize; i += DATABUFFER)
//									{
//										BYTE* TmpBuffer = new BYTE[DATABUFFER];
//										memset(TmpBuffer, '\x00', DATABUFFER);
//										if (tmplen < DATABUFFER)
//											memcpy(TmpBuffer, buffer + i, tmplen);
//										else
//										{
//											memcpy(TmpBuffer, buffer + i, DATABUFFER);
//											tmplen -= DATABUFFER;
//										}
//										Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, TmpBuffer);
//										delete[] TmpBuffer;
//										if (Sendret == 0 || Sendret == -1)
//										{
//											ret = -3;
//											break;
//										}
//									}
//								}
//								else
//								{
//									BYTE* TmpBuffer = new BYTE[DATABUFFER];
//									memset(TmpBuffer, '\x00', DATABUFFER);
//									memcpy(TmpBuffer, buffer, me32.modBaseSize);
//									Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, TmpBuffer);
//									delete[] TmpBuffer;
//									if (Sendret == 0 || Sendret == -1)
//									{
//										ret = -3;
//									}
//								}
//							}
//							//delete [] cFileName;
//						}
//						else
//							ret = -1;
//						delete[] buffer;
//						//CloseHandle(hProcess);
//						break;
//					}
//				} while (Module32Next(hSnapshot, &me32));
//			}
//			CloseHandle(hSnapshot);
//		}
//		else
//			ret = -1;
//	}
//	return ret;
//}
//int MemProcess::GetProcessExecute(void* argv, DumpMemoryInfo* pInfo)
//{
//	TransportData* m_Client = (TransportData*)argv;
//	int ret = 0;
//	set<wstring> wtr;
//	HANDLE hSnapshot;
//	MODULEENTRY32 me32;
//	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pInfo->ProcessID);
//	if (hSnapshot != INVALID_HANDLE_VALUE)
//	{
//		me32.dwSize = sizeof(MODULEENTRY32);
//		if (Module32First(hSnapshot, &me32))
//		{
//			do
//			{
//				//m_List.AddString(me32.szModule);
//				wtr.insert(me32.szExePath);
//			} while (Module32Next(hSnapshot, &me32));
//		}
//		CloseHandle(hSnapshot);
//	}
//	int Injected = CheckIsInjection(pInfo->ProcessID, NULL, NULL, NULL);
//	if (Injected == 2)
//		wtr.insert(_T("Unknown"));
//	if (!wtr.empty())
//	{
//		int DataCount = 0;
//		char* TempStr = new char[DATASTRINGMESSAGELEN];
//		memset(TempStr, '\0', DATASTRINGMESSAGELEN);
//		set<wstring>::iterator it;
//		for (it = wtr.begin(); it != wtr.end(); it++)
//		{
//			wchar_t* wstr = new wchar_t[1024];
//			swprintf_s(wstr, 1024, L"%s\n", (*it).c_str());
//			DataCount++;
//			char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
//			strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
//			delete[] wstr;
//			delete[] m_DataStr;
//			if ((DataCount % 255) == 0 && DataCount >= 255)
//			{
//				int ret = m_Client->SendDataMsgToServer(pInfo->MAC, pInfo->IP, "GiveExecuteInfoData", TempStr);
//				if (ret == 0 || ret == -1)
//				{
//					ret = -3;
//					break;
//				}
//				memset(TempStr, '\0', DATASTRINGMESSAGELEN);
//			}
//		}
//		if (TempStr[0] != '\0' && ret != -3)
//		{
//			int ret = m_Client->SendDataMsgToServer(pInfo->MAC, pInfo->IP, "GiveExecuteInfoData", TempStr);
//			if (ret == 0 || ret == -1)
//			{
//				ret = -3;
//			}
//		}
//	}
//	else
//	{
//		ret = -1;
//	}
//	wtr.clear();
//	return ret;
//}
int MemProcess::GetProcessMappedFileName(HANDLE ProcessHandle, PVOID BaseAddress, wchar_t* FileName)
{
	HMODULE m_dll = LoadLibrary(L"ntdll.dll");
	if (m_dll == NULL)
		return 0;
	PNtQueryVirtualMemory _NtQueryVirtualMemory = (PNtQueryVirtualMemory)GetProcAddress(m_dll, "NtQueryVirtualMemory");
	NTSTATUS status;
	char* buffer;
	SIZE_T bufferSize;
	SIZE_T returnLength;
	PUNICODE_STRING unicodeString;

	bufferSize = 0x100;
	buffer = new char[bufferSize];
	status = _NtQueryVirtualMemory(
		ProcessHandle,
		BaseAddress,
		MemoryMappedFilenameInformation,
		buffer,
		bufferSize,
		&returnLength
	);

	if (status == STATUS_BUFFER_OVERFLOW)
	{
		delete[] buffer;
		bufferSize = returnLength;
		buffer = new char[bufferSize];

		status = _NtQueryVirtualMemory(
			ProcessHandle,
			BaseAddress,
			MemoryMappedFilenameInformation,
			buffer,
			bufferSize,
			&returnLength
		);
	}

	if (!NT_SUCCESS(status))
	{
		FileName[0] = '\x0';
		delete[] buffer;
		FreeLibrary(m_dll);
		return 0;
	}
	status = 0;
	unicodeString = (PUNICODE_STRING)buffer;
	if (unicodeString->Length > 0)
	{
		status = 1;
		size_t filename_pos = 0;

		for (size_t i = wcslen(unicodeString->Buffer); i >= 0; i--)
		{
			if (unicodeString->Buffer[i] == '\\')
			{
				filename_pos = i + 1;
				break;
			}
		}
		wcscpy_s(FileName, MAX_PATH, &unicodeString->Buffer[filename_pos]);
	}
	delete[] buffer;
	FreeLibrary(m_dll);
	return status;
}
void MemProcess::LoadingProcessID(map<DWORD, process_info>* pPID)
{
	//map<DWORD,process_info> m_Mpa;
	BOOL ContinueLoop;
	PROCESSENTRY32 pe32;
	HANDLE SnapshotHandle;
	SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	pe32.dwSize = sizeof(pe32);
	ContinueLoop = Process32First(SnapshotHandle, &pe32);
	while (ContinueLoop)
	{
		process_info tmp;
		tmp.pid = pe32.th32ProcessID;
		tmp.parent_pid = pe32.th32ParentProcessID;
		tmp.ProcessCreateTime = 0;
		wcscpy_s(tmp.process_name, MAX_PATH, pe32.szExeFile);
		HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, tmp.pid);
		if (processHandle != NULL)
		{
			FILETIME l1, l2, l3, l4;
			if (GetProcessTimes(processHandle, &l1, &l2, &l3, &l4))
			{
				tmp.ProcessCreateTime = filetime_to_timet(l1);
			}
			CloseHandle(processHandle);
		}
		pPID->insert(pair<DWORD, process_info>(tmp.pid, tmp));
		ContinueLoop = Process32Next(SnapshotHandle, &pe32);
	}
	CloseHandle(SnapshotHandle);

	//m_Mpa.clear();
}

void MemProcess::GetProcessPath(DWORD pid, TCHAR* pPath, bool IsGetTime, TCHAR* pTimeStr, TCHAR* pCTimeStr)
{
	//HMODULE hModuleHandle;
	//DWORD dwNeeded;
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	TCHAR* filename = new TCHAR[MAX_PATH_EX];
	TCHAR* Longfilename = new TCHAR[MAX_PATH_EX];
	TCHAR* m_FilePath = new TCHAR[MAX_PATH_EX];
	if (processHandle != NULL)
	{
		//if (EnumProcessModules(processHandle, &hModuleHandle, sizeof(hModuleHandle), &dwNeeded) == TRUE)
		//{
		if (GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH_EX))
		{
			if (GetLongPathName(filename, Longfilename, MAX_PATH_EX))
			{
				lstrcpy(m_FilePath, Longfilename);
			}
			else
			{
				lstrcpy(m_FilePath, filename);
			}

			BOOL isrightPath = FALSE;
			//MessageBox(0,m_FilePath,0,0);
			for (size_t i = 0; i < wcslen(m_FilePath); i++)
			{
				if (m_FilePath[i] == ':')
				{
					isrightPath = TRUE;
					if ((i - 1) != 0)
						lstrcpy(pPath, m_FilePath + (i - 1));
					else
						lstrcpy(pPath, m_FilePath);
					break;
				}
			}
			if (!isrightPath)
			{//MessageBox(0,m_FilePath,0,0);
				lstrcpy(pPath, _T("null"));
			}
		}
		else
			lstrcpy(pPath, _T("null"));

		if (IsGetTime)
		{
			FILETIME l1, l2, l3, l4;
			if (GetProcessTimes(processHandle, &l1, &l2, &l3, &l4))
			{
				FILETIME localft;
				FileTimeToLocalFileTime(&l1, &localft);
				if (pCTimeStr != NULL)
				{
					time_t ProcessCreateTime = 0;
					ProcessCreateTime = filetime_to_timet(l1);
					swprintf_s(pCTimeStr, 20, _T("%lld"), ProcessCreateTime);
				}
				if (pTimeStr != NULL)
				{
					SYSTEMTIME st;
					FileTimeToSystemTime(&localft, &st);
					swprintf_s(pTimeStr, 20, _T("%4d/%02d/%02d %02d:%02d:%02d"), st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
				}
			}
			else
				lstrcpy(pTimeStr, _T("null"));
		}
		//}
		//else
			//lstrcpy(pPath,_T("null"));
		CloseHandle(processHandle);
	}
	else
		lstrcpy(pPath, _T("null"));
	delete[] m_FilePath;
	delete[] Longfilename;
	delete[] filename;
}
void MemProcess::GetProcessDetectInfo(DWORD pid, TCHAR* pPath, TCHAR* pComStr)
{
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	TCHAR* filename = new TCHAR[MAX_PATH_EX];
	TCHAR* Longfilename = new TCHAR[MAX_PATH_EX];
	TCHAR* m_FilePath = new TCHAR[MAX_PATH_EX];
	if (processHandle != NULL)
	{
		//if (EnumProcessModules(processHandle, &hModuleHandle, sizeof(hModuleHandle), &dwNeeded) == TRUE)
		//{
		if (GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH_EX))
		{
			if (GetLongPathName(filename, Longfilename, MAX_PATH_EX))
			{
				lstrcpy(m_FilePath, Longfilename);
			}
			else
			{
				lstrcpy(m_FilePath, filename);
			}
			for (size_t i = 0; i < wcslen(m_FilePath); i++)
			{
				if (m_FilePath[i] == ':')
				{
					if ((i - 1) != 0)
						lstrcpy(pPath, m_FilePath + (i - 1));
					else
						lstrcpy(pPath, m_FilePath);
					break;
				}
			}
		}
		TCHAR* Comstr = new TCHAR[61440];
		DWORD ret1 = GetRemoteCommandLineW(processHandle, Comstr, 61440);
		if (ret1 != 0)
		{
			lstrcpy(pComStr, Comstr);
		}
		delete[] Comstr;
	}
	CloseHandle(processHandle);

	delete[] m_FilePath;
	delete[] Longfilename;
	delete[] filename;
}
void MemProcess::GetProcessInfo(DWORD pid, TCHAR* pPath, TCHAR* pTimeStr, TCHAR* pUserName, TCHAR* pComStr)
{
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (processHandle != NULL)
	{
		if (pPath != NULL)
		{
			TCHAR* filename = new TCHAR[MAX_PATH_EX];
			TCHAR* Longfilename = new TCHAR[MAX_PATH_EX];
			TCHAR* m_FilePath = new TCHAR[MAX_PATH_EX];
			if (GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH_EX))
			{
				if (GetLongPathName(filename, Longfilename, MAX_PATH_EX))
				{
					lstrcpy(m_FilePath, Longfilename);
				}
				else
				{
					lstrcpy(m_FilePath, filename);
				}
				for (size_t i = 0; i < wcslen(m_FilePath); i++)
				{
					if (m_FilePath[i] == ':')
					{
						if ((i - 1) != 0)
							lstrcpy(pPath, m_FilePath + (i - 1));
						else
							lstrcpy(pPath, m_FilePath);
						break;
					}
				}
			}
			delete[] m_FilePath;
			delete[] Longfilename;
			delete[] filename;
		}
		if (pComStr != NULL)
		{
			TCHAR* Comstr = new TCHAR[MAX_PATH_EX];
			DWORD ret1 = GetRemoteCommandLineW(processHandle, Comstr, MAX_PATH_EX);
			if (ret1 != 0)
			{
				lstrcpy(pComStr, Comstr);
			}
			delete[] Comstr;
		}
		if (pTimeStr != NULL)
		{
			time_t ProcessCreateTime = 0;
			FILETIME l1, l2, l3, l4;
			if (GetProcessTimes(processHandle, &l1, &l2, &l3, &l4))
			{
				ProcessCreateTime = filetime_to_timet(l1);
				if (ProcessCreateTime < 0)
					ProcessCreateTime = 0;
				swprintf_s(pTimeStr, 20, _T("%lld"), ProcessCreateTime);
			}
		}
		if (pUserName != NULL)
		{
			TCHAR* pSIDstr = new TCHAR[128];
			_tcscpy_s(pSIDstr, 128, _T("null"));
			GetUserSID(processHandle, pSIDstr);
			_tcscpy_s(pUserName, _MAX_FNAME, pSIDstr);
			if (_tcscmp(pSIDstr, _T("null")))
			{
				SID_NAME_USE SidType;
				TCHAR* lpName = new TCHAR[_MAX_FNAME];
				TCHAR* lpDomain = new TCHAR[_MAX_FNAME];
				DWORD dwSize = _MAX_FNAME;
				PSID Sid;// = GetBinarySid(pSIDstr);
				if (ConvertStringSidToSid(pSIDstr, &Sid))
				{
					if (LookupAccountSid(NULL, Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType))
					{
						_tcscpy_s(pUserName, _MAX_FNAME, lpName);
					}
				}
				LocalFree(Sid);
				delete[] lpDomain;
				delete[] lpName;
			}
			delete[] pSIDstr;
		}
	}
	CloseHandle(processHandle);
}
void MemProcess::GetUserSID(HANDLE hProcess, TCHAR* szUserSID)
{
	HANDLE hTokenHandle = NULL;
	if (OpenProcessToken(hProcess, TOKEN_QUERY, &hTokenHandle))
	{
		PTOKEN_USER pUserToken = NULL;
		DWORD dwRequiredLength = 0;
		if (!GetTokenInformation(hTokenHandle, TokenUser, pUserToken, 0, &dwRequiredLength))
		{
			pUserToken = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwRequiredLength);
			if (NULL != pUserToken)
			{
				if (GetTokenInformation(hTokenHandle, TokenUser, pUserToken, dwRequiredLength, &dwRequiredLength))
				{
					LPTSTR pszSID;
					ConvertSidToStringSid(pUserToken->User.Sid, &pszSID);
					_tcscpy_s(szUserSID, 128, pszSID);
					//strUserSID = szSID ;
					LocalFree(pszSID);
				}
				HeapFree(GetProcessHeap(), 0, pUserToken);
			}
		}
		CloseHandle(hTokenHandle);
	}
}
BOOL MemProcess::DumpExecute(DWORD pid, wchar_t* pName, set<DWORD>* pApiBace, set<DWORD>* pStr, TCHAR* pProcessPath, set<string>* pIsAbnormal_dll)
{
	BOOL ret = FALSE;
	HMODULE hResult = NULL;
	HANDLE hSnapshot;
	MODULEENTRY32 me32;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		me32.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnapshot, &me32))
		{
			do
			{
				if (!_tcsicmp(me32.szModule, pName))
				{
					BYTE* buffer = new BYTE[me32.modBaseSize];
					if (Toolhelp32ReadProcessMemory(pid, me32.modBaseAddr, buffer, me32.modBaseSize, 0))
					{
						set<DWORD> StringsHash;
						LoadBinaryStringsHash(buffer, me32.modBaseSize, &StringsHash);
						set<DWORD>::iterator it1;
						set<DWORD>::iterator it2;
						for (it1 = pApiBace->begin(); it1 != pApiBace->end(); it1++)
						{
							//char Apibuffer[256];
							//strcpy_s(Apibuffer,256,(*it1).c_str());
							//bool IsMatch = memfind(buffer,Apibuffer,me32.modBaseSize);
							//if(IsMatch)
							//{
							//	pStr->insert(Apibuffer);
							//}
							it2 = StringsHash.find((*it1));
							if (it2 != StringsHash.end())
							{
								pStr->insert((*it1));
							}
						}
						StringsHash.clear();
						ret = TRUE;
					}
					delete[] buffer;
				}
				else
				{
					if (_tcsicmp(pProcessPath, _T("null")))
					{
						CheckModulePath(pProcessPath, me32.szExePath, pIsAbnormal_dll);
					}
				}
			} while (Module32Next(hSnapshot, &me32));
		}
		CloseHandle(hSnapshot);
	}
	return ret;
}
void MemProcess::ParserProcessApi(set<string>* pApiBace, vector<BYTE>* pExecuteData, int pExecuteDataSize, vector<string>* pStr)
{
	BYTE* m_buffer = new BYTE[pExecuteDataSize];
	vector<unsigned char>::iterator it;
	int j = 0;
	for (it = pExecuteData->begin(); it != pExecuteData->end(); it++)
	{
		if (j < pExecuteDataSize)
		{
			m_buffer[j] = *it;
		}
		j++;
	}
	set<string>::iterator it1;
	for (it1 = pApiBace->begin(); it1 != pApiBace->end(); it1++)
	{
		char Apibuffer[256];
		strcpy_s(Apibuffer, 256, (*it1).c_str());
		bool IsMatch = memfind(m_buffer, Apibuffer, pExecuteDataSize);
		if (IsMatch)
		{
			pStr->push_back(Apibuffer);
		}
	}
	delete[] m_buffer;
}

int MemProcess::CheckIsInjection(DWORD pid, vector<UnKnownDataInfo>* pMembuf, TCHAR* pProcessName, TCHAR* pUnKnownHash)
{
	int ret = 0;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (!hProc)
		return ret;

#ifndef _M_IX86
	SIZE_T ptype = Process32or64(hProc);
	//if (!ptype)
	//{
	//
	//}
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
	wchar_t lastfilename[MAX_PATH];
	while (startmem < maxmem)
	{
		MEMORY_BASIC_INFORMATION mbi;
		SIZE_T size = VirtualQueryEx(hProc, (LPVOID)startmem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		if (!size)
		{
			CloseHandle(hProc);
			return ret;
		}
		if (mbi.State == MEM_COMMIT)
		{
			SIZE_T ReadSize = 0;
			if (mbi.RegionSize < 20971520)
				ReadSize = mbi.RegionSize;
			else
				ReadSize = 20971520;
			char* buffer = new char[ReadSize];
			SIZE_T nread = 0;

			ReadProcessMemory(hProc, mbi.BaseAddress, buffer, ReadSize/*mbi.RegionSize*/, &nread);
			if (nread == ReadSize)
			{
				if (mbi.AllocationProtect & PAGE_EXECUTE_READWRITE)
				{
					if (!GetProcessMappedFileName(hProc, mbi.BaseAddress, lastfilename))
					{
						if (IsPESignature((BYTE*)buffer, (unsigned int)ReadSize))
						{
							ret = 2;
							if (pMembuf != NULL)
							{
								if (mbi.RegionSize <= 20971520)
								{
									UnKnownDataInfo m_Info;
									m_Info.Pid = pid;
									if (PeUnmapper((BYTE*)buffer, mbi.RegionSize, (ULONGLONG)mbi.BaseAddress, &m_Info))
									{
										_tcscpy_s(m_Info.ProcessName, MAX_PATH, pProcessName);
										pMembuf->push_back(m_Info);
									}
								}
								//else
								//{
								//	UnKnownDataInfo m_Info;
								//	m_Info.Pid = pid;
								//	//memset(m_Info.Data,'\x0',DATASTRINGMESSAGELEN);
								//	//memcpy(m_Info.Data,buffer,DATASTRINGMESSAGELEN);
								//	m_Info.SizeInfo = DATASTRINGMESSAGELEN;
								//	pMembuf->push_back(m_Info);
								//}
							}
							if (pUnKnownHash != NULL)
							{
								if (mbi.RegionSize <= 20971520)
								{
									try
									{
										GetUnKnownHash((BYTE*)buffer, mbi.RegionSize, pUnKnownHash, ptype);
									}
									catch (...) {}
								}
							}
						}
						else
						{
							if (ret < 2)
								ret = 1;
						}
					}
				}
				else if (mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY)
				{
					if (!GetProcessMappedFileName(hProc, mbi.BaseAddress, lastfilename))
					{
						if (IsPESignature((BYTE*)buffer, (unsigned int)ReadSize))
						{
							ret = 2;
							if (pMembuf != NULL)
							{
								if (mbi.RegionSize <= 20971520)
								{
									UnKnownDataInfo m_Info;
									m_Info.Pid = pid;
									if (PeUnmapper((BYTE*)buffer, mbi.RegionSize, (ULONGLONG)mbi.BaseAddress, &m_Info))
									{
										_tcscpy_s(m_Info.ProcessName, MAX_PATH, pProcessName);
										pMembuf->push_back(m_Info);
									}
								}
								//else
								//{
								//	UnKnownDataInfo m_Info;
								//	m_Info.Pid = pid;
								//	//memset(m_Info.Data,'\x0',DATASTRINGMESSAGELEN);
								//	//memcpy(m_Info.Data,buffer,DATASTRINGMESSAGELEN);
								//	m_Info.SizeInfo = DATASTRINGMESSAGELEN;
								//	pMembuf->push_back(m_Info);
								//}
							}
							if (pUnKnownHash != NULL)
							{
								if (mbi.RegionSize <= 20971520)
								{
									try
									{
										GetUnKnownHash((BYTE*)buffer, mbi.RegionSize, pUnKnownHash, ptype);
									}
									catch (...) {}
								}
							}
						}
						else
						{
							if (ret < 2)
								ret = 1;
						}
					}
				}
			}
			delete[] buffer;
		}
		startmem = (SIZE_T)mbi.BaseAddress + (SIZE_T)mbi.RegionSize;
	}
	CloseHandle(hProc);
	return ret;
}
bool MemProcess::PeUnmapper(BYTE* buffer, size_t pSize, ULONGLONG loadBase, UnKnownDataInfo* pInfo)
{
	BYTE* out_buf = NULL;
	size_t out_size = 0;
	printf("MODE: Virtual -> Raw\n");
	out_buf = pe_virtual_to_raw(buffer, pSize, loadBase, out_size, false);

	if (!out_buf) {
		free_pe_buffer(buffer, pSize);
		return false;
	}
	pInfo->SizeInfo = (DWORD)out_size;
	pInfo->Data = new BYTE[out_size + 1];
	memcpy(pInfo->Data, out_buf, out_size);

	// Write output
	//TCHAR * m_FilePath = new TCHAR[512];
	//GetMyPath(m_FilePath);
	//_tcscat_s(m_FilePath,512,_T("\\"));
	//_tcscat_s(m_FilePath,512,pName);
	//_tcscat_s(m_FilePath,512,_T(".mem"));
 //   bool isOk = dump_to_file(m_FilePath,out_buf,out_size);
	//delete [] m_FilePath;
	//free_pe_buffer(buffer, pSize);
	free_pe_buffer(out_buf, out_size);

	return true;
}
void MemProcess::GetUnKnownHash(BYTE* pBuffer, SIZE_T pBufferSize, TCHAR* pUnKnownHash, SIZE_T ptype)
{
	if (pBufferSize >= 1024)
	{
		if (!IsPackedSignature(pBuffer, 1024))
		{
			if (ptype == 64)
				ParserUnknownIAT(pBuffer, pUnKnownHash);
			else
				ParserUnknownIAT32(pBuffer, pUnKnownHash);
		}
	}
}

void MemProcess::ParserUnknownIAT(BYTE* pBuffer, TCHAR* pUnKnownHash)
{
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pBuffer;
	PLOADED_IMAGE pImage = new LOADED_IMAGE();
	pImage->FileHeader = (PIMAGE_NT_HEADERS)((BYTE*)pBuffer + pDOSHeader->e_lfanew);
	pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;
	pImage->Sections = (PIMAGE_SECTION_HEADER)((BYTE*)pBuffer + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	if (pImage)
	{
		PIMAGE_DATA_DIRECTORY importDirectory = &pImage->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptors = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pBuffer + importDirectory->VirtualAddress);

		if (pImportDescriptors)
		{
			//map<wstring,wstring>::iterator it;
			PIMAGE_THUNK_DATA OriginalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pBuffer + pImportDescriptors->OriginalFirstThunk);
			string HashStr;
			HashStr.clear();
			while (OriginalFirstThunk != 0)
			{
				if (!pImportDescriptors->FirstThunk)
					break;
				//printf("%s\n",((BYTE*)pData + pImportDescriptors->Name));
				char* pName = (char*)((BYTE*)pBuffer + pImportDescriptors->Name);
				//printf("%s\n",pName);
				OriginalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pBuffer + pImportDescriptors->OriginalFirstThunk);
				PIMAGE_IMPORT_BY_NAME NameImg = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBuffer + (DWORD_PTR)OriginalFirstThunk->u1.AddressOfData);
				PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pBuffer + pImportDescriptors->FirstThunk);
				DWORD dwOffset = 0;
				string DllName = pName;
				HashStr += DllName;
				while (NameImg)
				{
					//printf("%lu\n",OriginalFirstThunk->u1.AddressOfData);
#ifndef _M_IX86
					if (!(OriginalFirstThunk->u1.AddressOfData > 9223372036854775807))
#else
					if (!(OriginalFirstThunk->u1.AddressOfData > 2147483647))
#endif
					{
						DWORD_PTR dwOriginalAddress = FirstThunk[dwOffset].u1.AddressOfData;
						if (dwOriginalAddress != 0)
						{
							string FunctionName = (char*)NameImg->Name;
							HashStr += FunctionName;
							FunctionName.clear();
						}
						else
							break;
					}
					dwOffset++;
					OriginalFirstThunk++;
					NameImg = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBuffer + (DWORD_PTR)OriginalFirstThunk->u1.AddressOfData);
				}
				DllName.clear();
				pImportDescriptors++;
			}
			if (Md5StringHash((char*)HashStr.c_str(), pUnKnownHash))
				_tcscpy_s(pUnKnownHash, 50, _T("null"));
			HashStr.clear();
		}
	}
	else
		printf("Error reading remote image\r\n");
	delete pImage;
}
void MemProcess::ParserUnknownIAT32(BYTE* pBuffer, TCHAR* pUnKnownHash)
{
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pBuffer;
	PLOADED_IMAGE32 pImage = new LOADED_IMAGE32();

	pImage->FileHeader = (PIMAGE_NT_HEADERS32)((BYTE*)pBuffer + pDOSHeader->e_lfanew);
	pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;

	pImage->Sections = (PIMAGE_SECTION_HEADER)((BYTE*)pBuffer + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
	if (pImage)
	{
		PIMAGE_DATA_DIRECTORY importDirectory = &pImage->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptors = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pBuffer + importDirectory->VirtualAddress);

		if (pImportDescriptors)
		{
			//map<wstring,wstring>::iterator it;
			PIMAGE_THUNK_DATA32 OriginalFirstThunk = (PIMAGE_THUNK_DATA32)((BYTE*)pBuffer + pImportDescriptors->OriginalFirstThunk);
			string HashStr;
			HashStr.clear();
			while (OriginalFirstThunk != 0)
			{
				if (!pImportDescriptors->FirstThunk)
					break;
				//printf("%s\n",((BYTE*)pData + pImportDescriptors->Name));
				char* pName = (char*)((BYTE*)pBuffer + pImportDescriptors->Name);
				//printf("%s\n",pName);
				OriginalFirstThunk = (PIMAGE_THUNK_DATA32)((BYTE*)pBuffer + pImportDescriptors->OriginalFirstThunk);
				PIMAGE_IMPORT_BY_NAME NameImg = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBuffer + (DWORD)OriginalFirstThunk->u1.AddressOfData);
				PIMAGE_THUNK_DATA32 FirstThunk = (PIMAGE_THUNK_DATA32)((BYTE*)pBuffer + pImportDescriptors->FirstThunk);
				DWORD dwOffset = 0;
				string DllName = pName;
				HashStr += DllName;
				while (NameImg)
				{
					//printf("%lu\n",OriginalFirstThunk->u1.AddressOfData);
					if (!(OriginalFirstThunk->u1.AddressOfData > 2147483647))
					{
						DWORD dwOriginalAddress = FirstThunk[dwOffset].u1.AddressOfData;
						if (dwOriginalAddress != 0)
						{
							string FunctionName = (char*)NameImg->Name;
							HashStr += FunctionName;
							FunctionName.clear();
						}
						else
							break;
					}
					dwOffset++;
					OriginalFirstThunk++;
					NameImg = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBuffer + (DWORD)OriginalFirstThunk->u1.AddressOfData);
				}
				DllName.clear();
				pImportDescriptors++;
			}
			//GetStringsMd5(&HashStr,pUnKnownHash);
			if (Md5StringHash((char*)HashStr.c_str(), pUnKnownHash))
				_tcscpy_s(pUnKnownHash, 50, _T("null"));
			HashStr.clear();
		}
	}
	delete pImage;
}
BOOL MemProcess::IsWindowsProcessNormal(map<DWORD, process_info_Ex>* pInfo, DWORD pid)
{
	BOOL ret = FALSE;
	if (pid == 0 || pid == 4)
		ret = TRUE;
	else
	{
		map<DWORD, process_info_Ex>::iterator it;
		it = pInfo->find(pid);
		if (it != pInfo->end())
		{
			if (!_wcsicmp(it->second.process_name, L"csrss.exe"))
			{
				ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
				if (ret)
					ret = CheckPathMatch(&it->second);
				if (ret)
					ret = CheckSIDMatch(&it->second);
				//if(ret)
				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
			}
			else if (!_wcsicmp(it->second.process_name, L"wininit.exe"))
			{
				ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
				if (ret)
					ret = CheckPathMatch(&it->second);
				if (ret)
					ret = CheckSIDMatch(&it->second);
				//if(ret)
				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
			}
			else if (!_wcsicmp(it->second.process_name, L"winlogon.exe"))
			{
				ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
				if (ret)
					ret = CheckPathMatch(&it->second);
				if (ret)
					ret = CheckSIDMatch(&it->second);
				//if(ret)
				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
			}
			//else if(!_wcsicmp(it->second.process_name,L"explorer.exe"))
			//{
			//	ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
			//	if(ret)
			//		ret = CheckPathMatch(&it->second);
			//	if(ret)
			//		ret = CheckSIDMatch(&it->second);
			//	if(ret)
			//		ret = CheckCreateTimeMatch(pInfo,&it->second);
			//}
			else if (!_wcsicmp(it->second.process_name, L"smss.exe"))
			{
				if (it->second.parent_pid == 4)
					ret = TRUE;
			}
			else if (!_wcsicmp(it->second.process_name, L"services.exe"))
			{
				ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
				if (ret)
					ret = CheckPathMatch(&it->second);
				if (ret)
					ret = CheckSIDMatch(&it->second);
				//if(ret)
				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
			}
			else if (!_wcsicmp(it->second.process_name, L"svchost.exe"))
			{
				ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
				if (ret)
					ret = CheckPathMatch(&it->second);
				if (ret)
					ret = CheckSIDMatch(&it->second);
				//if(ret)
				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
			}
			else if (!_wcsicmp(it->second.process_name, L"taskhost.exe"))
			{
				ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
				if (ret)
					ret = CheckPathMatch(&it->second);
				if (ret)
					ret = CheckSIDMatch(&it->second);
				//if(ret)
				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
			}
			else if (!_wcsicmp(it->second.process_name, L"lsass.exe"))
			{
				ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
				if (ret)
					ret = CheckPathMatch(&it->second);
				if (ret)
					ret = CheckSIDMatch(&it->second);
				//if(ret)
				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
			}
			else if (!_wcsicmp(it->second.process_name, L"lsm.exe"))
			{
				ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
				if (ret)
					ret = CheckPathMatch(&it->second);
				if (ret)
					ret = CheckSIDMatch(&it->second);
				//if(ret)
				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
			}
			else if (!_wcsicmp(it->second.process_name, L"dllhost.exe"))
			{
				ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
				if (ret)
					ret = CheckPathMatch(&it->second);
				if (ret)
					ret = CheckSIDMatch(&it->second);
				//if(ret)
				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
			}
		}
	}
	return ret;
}
BOOL MemProcess::CheckParentProcessNormal(map<DWORD, process_info_Ex>* pInfo, DWORD parentid, wchar_t* process_name, time_t pCreateTime)
{
	BOOL ret = FALSE;
	map<DWORD, process_info_Ex>::iterator it;
	it = pInfo->find(parentid);
	if (it != pInfo->end())
	{
		if (!_wcsicmp(process_name, L"csrss.exe"))
		{
			if (pCreateTime < it->second.ProcessCreateTime)
				ret = TRUE;
			else
			{
				if (!_wcsicmp(it->second.process_name, L"smss.exe"))
					ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
			}
		}
		else if (!_wcsicmp(process_name, L"wininit.exe"))
		{
			if (pCreateTime < it->second.ProcessCreateTime)
				ret = TRUE;
			else
			{
				if (!_wcsicmp(it->second.process_name, L"smss.exe"))
					ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
			}
		}
		else if (!_wcsicmp(process_name, L"winlogon.exe"))
		{
			//if(pCreateTime < it->second.ProcessCreateTime)
			ret = TRUE;
			//else
			//{
			//	if(!_wcsicmp(it->second.process_name,L"smss.exe"))
			//		ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
			//}
		}
		//else if(!_wcsicmp(process_name,L"explorer.exe"))
		//{
		//	if(pCreateTime < it->second.ProcessCreateTime)
		//		ret = TRUE;
		//	else
		//	{
		//		if(!_wcsicmp(it->second.process_name,L"userinit.exe"))
		//			ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
		//	}
		//}
		else if (!_wcsicmp(process_name, L"smss.exe"))
		{
			if (it->second.parent_pid == 4)
				ret = TRUE;
		}
		else if (!_wcsicmp(process_name, L"services.exe"))
		{
			if (!_wcsicmp(it->second.process_name, L"wininit.exe"))
				ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
		}
		else if (!_wcsicmp(process_name, L"svchost.exe"))
		{
			if (!_wcsicmp(it->second.process_name, L"services.exe"))
				ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
		}
		else if (!_wcsicmp(process_name, L"taskhost.exe"))
		{
			if (!_wcsicmp(it->second.process_name, L"services.exe"))
				ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
		}
		else if (!_wcsicmp(process_name, L"lsass.exe"))
		{
			if (!_wcsicmp(it->second.process_name, L"wininit.exe"))
				ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
		}
		else if (!_wcsicmp(process_name, L"lsm.exe"))
		{
			if (!_wcsicmp(it->second.process_name, L"wininit.exe"))
				ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
		}
		else if (!_wcsicmp(process_name, L"dllhost.exe"))
		{
			if (!_wcsicmp(it->second.process_name, L"svchost.exe") || !_wcsicmp(it->second.process_name, L"services.exe"))
				ret = CheckParentProcessNormal(pInfo, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime);
		}
	}
	else
	{
		if (!_wcsicmp(process_name, L"csrss.exe"))
			ret = TRUE;
		else if (!_wcsicmp(process_name, L"wininit.exe"))
			ret = TRUE;
		else if (!_wcsicmp(process_name, L"winlogon.exe"))
			ret = TRUE;
		else if (!_wcsicmp(process_name, L"explorer.exe"))
			ret = TRUE;
	}
	return ret;
}
BOOL MemProcess::CheckPathMatch(process_info_Ex* pInfo)
{
	BOOL ret = TRUE;
	if (_wcsicmp(pInfo->process_Path, L"null"))
	{
		if (!_wcsicmp(pInfo->process_name, _T("smss.exe")))
		{
			if (_wcsicmp(pInfo->process_Path, L"null"))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("csrss.exe")))
		{
			if (_wcsicmp(pInfo->process_Path, L"C:\\Windows\\System32\\csrss.exe"))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("services.exe")))
		{
			if (_wcsicmp(pInfo->process_Path, L"C:\\Windows\\System32\\services.exe"))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("svchost.exe")))
		{
			if (_wcsicmp(pInfo->process_Path, L"C:\\Windows\\System32\\svchost.exe"))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("lsm.exe")))
		{
			if (_wcsicmp(pInfo->process_Path, L"C:\\Windows\\System32\\lsm.exe"))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("explorer.exe")))
		{
			if (_wcsicmp(pInfo->process_Path, L"C:\\Windows\\explorer.exe"))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("iexplore.exe")))
		{
			if (_wcsicmp(pInfo->process_Path, L"C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe") &&
				_wcsicmp(pInfo->process_Path, L"C:\\Program Files\\Internet Explorer\\iexplore.exe"))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("winlogon.exe")))
		{
			if (_wcsicmp(pInfo->process_Path, L"C:\\Windows\\System32\\winlogon.exe"))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("lsass.exe")))
		{
			if (_wcsicmp(pInfo->process_Path, L"C:\\Windows\\System32\\lsass.exe"))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("taskhost.exe")))
		{
			if (_wcsicmp(pInfo->process_Path, L"C:\\Windows\\System32\\taskhost.exe"))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("wininit.exe")))
		{
			if (_wcsicmp(pInfo->process_Path, L"C:\\Windows\\System32\\wininit.exe"))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("dllhost.exe")))
		{
			if (_wcsicmp(pInfo->process_Path, L"C:\\Windows\\System32\\dllhost.exe"))
				ret = FALSE;
		}
	}
	return ret;
}
BOOL MemProcess::CheckSIDMatch(process_info_Ex* pInfo)
{
	BOOL ret = TRUE;
	if (_wcsicmp(pInfo->m_SID, L"null"))
	{
		if (!_wcsicmp(pInfo->process_name, _T("smss.exe")))
		{
			if (_wcsicmp(pInfo->m_SID, _T("SYSTEM")))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("csrss.exe")))
		{
			if (_wcsicmp(pInfo->m_SID, _T("SYSTEM")))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("services.exe")))
		{
			if (_wcsicmp(pInfo->m_SID, _T("SYSTEM")))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("svchost.exe")))
		{
			//if(_wcsicmp(pInfo->m_SID,_T("SYSTEM"))&&_wcsicmp(pInfo->m_SID,_T("LOCAL SERVICE")))
			//	ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("lsm.exe")))
		{
			if (_wcsicmp(pInfo->m_SID, _T("SYSTEM")))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("explorer.exe")))
		{

		}
		else if (!_wcsicmp(pInfo->process_name, _T("iexplore.exe")))
		{

		}
		else if (!_wcsicmp(pInfo->process_name, _T("winlogon.exe")))
		{
			if (_wcsicmp(pInfo->m_SID, _T("SYSTEM")))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("lsass.exe")))
		{
			if (_wcsicmp(pInfo->m_SID, _T("SYSTEM")))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("taskhost.exe")))
		{

		}
		else if (!_wcsicmp(pInfo->process_name, _T("wininit.exe")))
		{
			if (_wcsicmp(pInfo->m_SID, _T("SYSTEM")))
				ret = FALSE;
		}
		else if (!_wcsicmp(pInfo->process_name, _T("dllhost.exe")))
		{
			if (_wcsicmp(pInfo->m_SID, _T("SYSTEM")))
				ret = FALSE;
		}
	}
	return ret;
}
BOOL MemProcess::CheckCreateTimeRight(map<DWORD, process_info_Ex>* pData, __int64 pCreateTime)
{
	BOOL ret = TRUE;
	map<DWORD, process_info_Ex>::iterator it;
	for (it = pData->begin(); it != pData->end(); it++)
	{
		if (!_wcsicmp(it->second.process_name, _T("explorer.exe")) && !_wcsicmp(it->second.process_Path, _T("C:\\Windows\\explorer.exe")))
		{
			if (pCreateTime > it->second.ProcessCreateTime)
				ret = FALSE;
			break;
		}
	}
	return ret;
}
BOOL MemProcess::CheckCreateTimeMatch(map<DWORD, process_info_Ex>* pData, process_info_Ex* pInfo)
{
	BOOL ret = TRUE;
	if (pInfo->ProcessCreateTime != 0)
	{
		if (!_wcsicmp(pInfo->process_name, _T("smss.exe")))
		{
			ret = CheckCreateTimeRight(pData, pInfo->ProcessCreateTime);
		}
		else if (!_wcsicmp(pInfo->process_name, _T("csrss.exe")))
		{
			ret = CheckCreateTimeRight(pData, pInfo->ProcessCreateTime);
		}
		else if (!_wcsicmp(pInfo->process_name, _T("services.exe")))
		{
			ret = CheckCreateTimeRight(pData, pInfo->ProcessCreateTime);
		}
		else if (!_wcsicmp(pInfo->process_name, _T("svchost.exe")))
		{

		}
		else if (!_wcsicmp(pInfo->process_name, _T("lsm.exe")))
		{
			ret = CheckCreateTimeRight(pData, pInfo->ProcessCreateTime);
		}
		else if (!_wcsicmp(pInfo->process_name, _T("explorer.exe")))
		{

		}
		else if (!_wcsicmp(pInfo->process_name, _T("iexplore.exe")))
		{

		}
		else if (!_wcsicmp(pInfo->process_name, _T("winlogon.exe")))
		{
			ret = CheckCreateTimeRight(pData, pInfo->ProcessCreateTime);
		}
		else if (!_wcsicmp(pInfo->process_name, _T("lsass.exe")))
		{
			ret = CheckCreateTimeRight(pData, pInfo->ProcessCreateTime);
		}
		else if (!_wcsicmp(pInfo->process_name, _T("taskhost.exe")))
		{

		}
		else if (!_wcsicmp(pInfo->process_name, _T("wininit.exe")))
		{
			ret = CheckCreateTimeRight(pData, pInfo->ProcessCreateTime);
		}
	}
	return ret;
}
DWORD MemProcess::GetRemoteCommandLineW(HANDLE hProcess, LPWSTR pszBuffer, UINT bufferLength)
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
int MemProcess::CheckIsStartRun(map<wstring, BOOL>* pService, set<wstring>* pStartRun, DWORD pid/*,BOOL & isServiceHide*/)
{
	int ret = 0;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (hProc)
	{
		TCHAR* buffer = new TCHAR[MAX_PATH_EX];
		DWORD ret1 = GetRemoteCommandLineW(hProc, buffer, MAX_PATH_EX);
		//MessageBox(0,buffer,0,0);
		if (ret1 != 0)
		{//MessageBox(0,buffer,0,0);
			map<wstring, BOOL>::iterator ServiceIt;
			//for(ServiceIt = pService->begin();ServiceIt != pService->end();ServiceIt++)
				//MessageBox(0,(*ServiceIt).c_str(),0,0);
			ServiceIt = pService->find(buffer);
			if (ServiceIt != pService->end())
			{
				//if(!ServiceIt->second)
				//	isServiceHide = TRUE;
				ret += 1;
			}
			set<wstring>::iterator StartRunIt;
			StartRunIt = pStartRun->find(buffer);
			if (StartRunIt != pStartRun->end())
				ret += 2;
		}
		delete[] buffer;
		CloseHandle(hProc);
	}
	return ret;
}
//int MemProcess::ScanInjectedProcessDump(void* argv, ScanMemoryInfo* pInfo)
//{
//	TransportData* m_Client = (TransportData*)argv;
//	int retNum = 0;
//	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pInfo->ProcessID);
//	if (!hProc)
//	{
//		retNum = -1;
//	}
//	else
//	{
//#ifndef _M_IX86
//		SIZE_T ptype = Process32or64(hProc);
//#else
//		SIZE_T ptype = 32;
//#endif
//		if (!ptype)
//		{
//			/*AfxMessageBox(_T("IsWow64Process failed."));*/
//			//CloseHandle(hProc);
//			retNum = -1;
//		}
//		else
//		{
//#ifndef _M_IX86
//			SIZE_T startmem = 0;
//			SIZE_T maxmem = 0x7FFF0000;
//			if (ptype == 64)
//			{
//				maxmem = 0x7FFFFFEFFFF;
//			}
//#else
//			//SIZE_T ptype = 32;
//			SIZE_T startmem = 0;
//			SIZE_T maxmem = 0x7FFF0000;
//#endif
//			//int count = 0;
//			wchar_t lastfilename[MAX_PATH];
//			while (startmem < maxmem)
//			{
//				MEMORY_BASIC_INFORMATION mbi;
//				SIZE_T size = VirtualQueryEx(hProc, (LPVOID)startmem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
//				if (!size)
//				{
//					//CloseHandle(hProc);
//					retNum = -2;
//					break;
//				}
//				TCHAR* output = new TCHAR[_MAX_FNAME];
//				TCHAR* m_FileName = new TCHAR[_MAX_FNAME];
//#ifndef _M_IX86
//				if (startmem, ptype == 64)
//					swprintf_s(output, _MAX_FNAME, _T("%016I64X-%016I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
//				else
//					swprintf_s(output, _MAX_FNAME, _T("%08I64X-%08I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
//#else
//				swprintf_s(output, _MAX_FNAME, _T("%08I64X-%08I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
//#endif
//				if (mbi.State == MEM_COMMIT)
//				{
//					char* buffer = new char[mbi.RegionSize];
//					SIZE_T nread = 0;
//					//DWORD oldprotect;
//					//if (VirtualProtectEx(hProc,mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&oldprotect))
//					//{
//					//	mbi.AllocationProtect = oldprotect;
//					//	VirtualProtectEx(hProc,mbi.BaseAddress,mbi.RegionSize,oldprotect,&oldprotect);
//					ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &nread);
//					//swprintf_s(m_FileName,_MAX_FNAME,_T("%.3d_%s"),count,output);
//					//output = L"output\\"+output;
//					if (nread == mbi.RegionSize)
//					{
//						bool typeok = false;
//						if (mbi.AllocationProtect & PAGE_EXECUTE_READWRITE)
//						{
//							if (!GetProcessMappedFileName(hProc, mbi.BaseAddress, lastfilename))
//							{
//								typeok = true;
//								swprintf_s(m_FileName, _MAX_FNAME, _T("PAGE_EXECUTE_READWRITE_%s"), output);
//							}
//						}
//						else if (mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY)
//						{
//							if (!GetProcessMappedFileName(hProc, mbi.BaseAddress, lastfilename))
//							{
//								typeok = true;
//								swprintf_s(m_FileName, _MAX_FNAME, _T("PAGE_EXECUTE_WRITECOPY_%s"), output);
//							}
//						}
//
//						if (typeok)
//						{
//							char* cFileName = CStringToCharArray(m_FileName, CP_UTF8);
//							//double precentage = (double)100*startmem/maxmem;
//							//unsigned int m_Progress = (unsigned int)precentage;
//							int Sendret;
//							char* InfoStr = new char[MAX_PATH_EX];
//#ifndef _M_IX86
//							sprintf_s(InfoStr, MAX_PATH_EX, "%llu|0|%s", mbi.RegionSize, cFileName);
//#else
//							sprintf_s(InfoStr, MAX_PATH_EX, "%lu|0|%s", mbi.RegionSize, cFileName);
//#endif
//							BYTE* InfoBuffer = new BYTE[DATABUFFER];
//							memset(InfoBuffer, '\x0', DATABUFFER);
//							memcpy(InfoBuffer, InfoStr, strlen(InfoStr));
//							Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemScanInfo", InfoBuffer);
//							delete[] InfoBuffer;
//							if (Sendret <= 0)
//							{
//								delete[] InfoStr;
//								delete[] cFileName;
//								delete[] buffer;
//								delete[] m_FileName;
//								delete[] output;
//								//CloseHandle(hProc);
//								retNum = -3;
//								break;
//							}
//							delete[] InfoStr;
//							if (mbi.RegionSize > DATABUFFER)
//							{
//								SIZE_T tmplen = mbi.RegionSize;
//								for (SIZE_T i = 0; i < mbi.RegionSize; i += DATABUFFER)
//								{
//									BYTE* TmpBuffer = new BYTE[DATABUFFER];
//									memset(TmpBuffer, '\x00', DATABUFFER);
//									if (tmplen < DATABUFFER)
//										memcpy(TmpBuffer, buffer + i, tmplen);
//									else
//									{
//										memcpy(TmpBuffer, buffer + i, DATABUFFER);
//										tmplen -= DATABUFFER;
//									}
//									Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemScanData", TmpBuffer);
//									delete[] TmpBuffer;
//									if (Sendret <= 0)
//									{
//										delete[] cFileName;
//										delete[] buffer;
//										//CloseHandle(hProc);
//										delete[] m_FileName;
//										delete[] output;
//										retNum = -3;
//										break;
//									}
//								}
//							}
//							else
//							{
//								BYTE* TmpBuffer = new BYTE[DATABUFFER];
//								memset(TmpBuffer, '\x00', DATABUFFER);
//								memcpy(TmpBuffer, buffer, mbi.RegionSize);
//								Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemScanData", TmpBuffer);
//								delete[] TmpBuffer;
//								if (Sendret == 0 || Sendret == -1)
//								{
//									delete[] cFileName;
//									delete[] buffer;
//									delete[] m_FileName;
//									delete[] output;
//									//CloseHandle(hProc);
//									retNum = -3;
//									break;
//								}
//							}
//							delete[] cFileName;
//							//count++;
//						}
//					}
//					//}
//					delete[] buffer;
//				}
//				startmem = (SIZE_T)mbi.BaseAddress + (SIZE_T)mbi.RegionSize;
//				delete[] m_FileName;
//				delete[] output;
//			}
//		}
//		CloseHandle(hProc);
//	}
//	return retNum;
//}
//int MemProcess::ScanInjectedProcessDumpEx(void* argv, ScanMemoryInfo* pInfo)
//{
//	TransportData* m_Client = (TransportData*)argv;
//	int retNum = 0;
//	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pInfo->ProcessID);
//	if (!hProc)
//	{
//		retNum = -1;
//	}
//	else
//	{
//#ifndef _M_IX86
//		SIZE_T ptype = Process32or64(hProc);
//#else
//		SIZE_T ptype = 32;
//#endif
//		if (!ptype)
//		{
//			/*AfxMessageBox(_T("IsWow64Process failed."));*/
//			//CloseHandle(hProc);
//			retNum = -1;
//		}
//		else
//		{
//#ifndef _M_IX86
//			SIZE_T startmem = 0;
//			SIZE_T maxmem = 0x7FFF0000;
//			if (ptype == 64)
//			{
//				maxmem = 0x7FFFFFEFFFF;
//			}
//#else
//			//SIZE_T ptype = 32;
//			SIZE_T startmem = 0;
//			SIZE_T maxmem = 0x7FFF0000;
//#endif
//			//int count = 0;
//			wchar_t lastfilename[MAX_PATH];
//			while (startmem < maxmem)
//			{
//				MEMORY_BASIC_INFORMATION mbi;
//				SIZE_T size = VirtualQueryEx(hProc, (LPVOID)startmem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
//				if (!size)
//				{
//					//CloseHandle(hProc);
//					retNum = -2;
//					break;
//				}
//				TCHAR* output = new TCHAR[_MAX_FNAME];
//				TCHAR* m_FileName = new TCHAR[_MAX_FNAME];
//#ifndef _M_IX86
//				if (startmem, ptype == 64)
//					swprintf_s(output, _MAX_FNAME, _T("%016I64X-%016I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
//				else
//					swprintf_s(output, _MAX_FNAME, _T("%08I64X-%08I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
//#else
//				swprintf_s(output, _MAX_FNAME, _T("%08I64X-%08I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
//#endif
//				if (mbi.State == MEM_COMMIT)
//				{
//					char* buffer = new char[mbi.RegionSize];
//					SIZE_T nread = 0;
//					//DWORD oldprotect;
//					//if (VirtualProtectEx(hProc,mbi.BaseAddress,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&oldprotect))
//					//{
//					//	mbi.AllocationProtect = oldprotect;
//					//	VirtualProtectEx(hProc,mbi.BaseAddress,mbi.RegionSize,oldprotect,&oldprotect);
//					ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &nread);
//					//swprintf_s(m_FileName,_MAX_FNAME,_T("%.3d_%s"),count,output);
//					//output = L"output\\"+output;
//					if (nread == mbi.RegionSize)
//					{
//						bool typeok = false;
//						if (mbi.AllocationProtect & PAGE_EXECUTE_READWRITE)
//						{
//							if (!GetProcessMappedFileName(hProc, mbi.BaseAddress, lastfilename))
//							{
//								typeok = true;
//								swprintf_s(m_FileName, _MAX_FNAME, _T("PAGE_EXECUTE_READWRITE_%s"), output);
//							}
//						}
//						else if (mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY)
//						{
//							if (!GetProcessMappedFileName(hProc, mbi.BaseAddress, lastfilename))
//							{
//								typeok = true;
//								swprintf_s(m_FileName, _MAX_FNAME, _T("PAGE_EXECUTE_WRITECOPY_%s"), output);
//							}
//						}
//
//						if (typeok)
//						{
//							char* cFileName = CStringToCharArray(m_FileName, CP_UTF8);
//							//double precentage = (double)100*startmem/maxmem;
//							//unsigned int m_Progress = (unsigned int)precentage;
//							int Sendret;
//							char* InfoStr = new char[MAX_PATH_EX];
//#ifndef _M_IX86
//							sprintf_s(InfoStr, MAX_PATH_EX, "%llu|0|%s", mbi.RegionSize, cFileName);
//#else
//							sprintf_s(InfoStr, MAX_PATH_EX, "%lu|0|%s", mbi.RegionSize, cFileName);
//#endif
//							BYTE* InfoBuffer = new BYTE[DATABUFFER];
//							memset(InfoBuffer, '\x0', DATABUFFER);
//							memcpy(InfoBuffer, InfoStr, strlen(InfoStr));
//							Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemScanInfo", InfoBuffer);
//							delete[] InfoBuffer;
//							if (Sendret <= 0)
//							{
//								delete[] InfoStr;
//								delete[] cFileName;
//								delete[] buffer;
//								delete[] m_FileName;
//								delete[] output;
//								//CloseHandle(hProc);
//								retNum = -3;
//								break;
//							}
//							delete[] InfoStr;
//							if (mbi.RegionSize > DATABUFFER)
//							{
//								SIZE_T tmplen = mbi.RegionSize;
//								for (SIZE_T i = 0; i < mbi.RegionSize; i += DATABUFFER)
//								{
//									BYTE* TmpBuffer = new BYTE[DATABUFFER];
//									memset(TmpBuffer, '\x00', DATABUFFER);
//									if (tmplen < DATABUFFER)
//										memcpy(TmpBuffer, buffer + i, tmplen);
//									else
//									{
//										memcpy(TmpBuffer, buffer + i, DATABUFFER);
//										tmplen -= DATABUFFER;
//									}
//									Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemScanData", TmpBuffer);
//									delete[] TmpBuffer;
//									if (Sendret <= 0)
//									{
//										delete[] cFileName;
//										delete[] buffer;
//										//CloseHandle(hProc);
//										delete[] m_FileName;
//										delete[] output;
//										retNum = -3;
//										break;
//									}
//								}
//							}
//							else
//							{
//								BYTE* TmpBuffer = new BYTE[DATABUFFER];
//								memset(TmpBuffer, '\x00', DATABUFFER);
//								memcpy(TmpBuffer, buffer, mbi.RegionSize);
//								Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemScanData", TmpBuffer);
//								delete[] TmpBuffer;
//								if (Sendret == 0 || Sendret == -1)
//								{
//									delete[] cFileName;
//									delete[] buffer;
//									delete[] m_FileName;
//									delete[] output;
//									//CloseHandle(hProc);
//									retNum = -3;
//									break;
//								}
//							}
//							delete[] cFileName;
//							//count++;
//						}
//					}
//					//}
//					delete[] buffer;
//				}
//				startmem = (SIZE_T)mbi.BaseAddress + (SIZE_T)mbi.RegionSize;
//				delete[] m_FileName;
//				delete[] output;
//			}
//		}
//		CloseHandle(hProc);
//
//		HMODULE hResult = NULL;
//		HANDLE hSnapshot;
//		MODULEENTRY32 me32;
//		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (DWORD)pInfo->ProcessID);
//		if (hSnapshot != INVALID_HANDLE_VALUE)
//		{
//			me32.dwSize = sizeof(MODULEENTRY32);
//			if (Module32First(hSnapshot, &me32))
//			{
//				do
//				{
//					char* buffer = new char[me32.modBaseSize];
//					if (Toolhelp32ReadProcessMemory(pInfo->ProcessID, me32.modBaseAddr, buffer, me32.modBaseSize, 0))
//					{
//						char* cFileName = CStringToCharArray(me32.szModule, CP_UTF8);
//						//double precentage = (double)100*startmem/maxmem;
//						//unsigned int m_Progress = (unsigned int)precentage;
//						int Sendret;
//						char* InfoStr = new char[MAX_PATH_EX];
//						sprintf_s(InfoStr, MAX_PATH_EX, "%lu|0|%s", me32.modBaseSize, cFileName);
//						BYTE* InfoBuffer = new BYTE[DATABUFFER];
//						memset(InfoBuffer, '\x0', DATABUFFER);
//						memcpy(InfoBuffer, InfoStr, strlen(InfoStr));
//						Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemScanInfo", InfoBuffer);
//						delete[] InfoBuffer;
//						if (Sendret == 0 || Sendret == -1)
//						{
//							retNum = -3;
//							break;
//						}
//						delete[] InfoStr;
//						if (me32.modBaseSize > DATABUFFER && retNum != -3)
//						{
//							SIZE_T tmplen = me32.modBaseSize;
//							for (SIZE_T i = 0; i < me32.modBaseSize; i += DATABUFFER)
//							{
//								BYTE* TmpBuffer = new BYTE[DATABUFFER];
//								memset(TmpBuffer, '\x00', DATABUFFER);
//								if (tmplen < DATABUFFER)
//									memcpy(TmpBuffer, buffer + i, tmplen);
//								else
//								{
//									memcpy(TmpBuffer, buffer + i, DATABUFFER);
//									tmplen -= DATABUFFER;
//								}
//								Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemScanData", TmpBuffer);
//								delete[] TmpBuffer;
//								if (Sendret == 0 || Sendret == -1)
//								{
//									retNum = -3;
//									break;
//								}
//							}
//						}
//						else
//						{
//							BYTE* TmpBuffer = new BYTE[DATABUFFER];
//							memset(TmpBuffer, '\x00', DATABUFFER);
//							memcpy(TmpBuffer, buffer, me32.modBaseSize);
//							Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, "GiveMemScanData", TmpBuffer);
//							delete[] TmpBuffer;
//							if (Sendret == 0 || Sendret == -1)
//							{
//								retNum = -3;
//								break;
//							}
//						}
//						delete[] cFileName;
//					}
//					delete[] buffer;
//				} while (Module32Next(hSnapshot, &me32));
//			}
//			CloseHandle(hSnapshot);
//		}
//		else
//			retNum = -1;
//	}
//	return retNum;
//}
void MemProcess::CheckModulePath(TCHAR* pProcessPath, TCHAR* pModulePath, set<string>* pIsAbnormal_dll)
{
	TCHAR* Longfilename = new TCHAR[MAX_PATH_EX];
	TCHAR* m_FilePath = new TCHAR[MAX_PATH_EX];
	if (GetLongPathName(pModulePath, Longfilename, MAX_PATH_EX))
	{
		lstrcpy(m_FilePath, Longfilename);
	}
	else
	{
		lstrcpy(m_FilePath, pModulePath);
	}
	for (int i = 0; i < (int)_tcslen(m_FilePath); i++)
	{
		if (m_FilePath[i] == ':')
		{
			if (i > 1)
				_tcscpy_s(Longfilename, MAX_PATH_EX, m_FilePath + (i - 1));
			else
				_tcscpy_s(Longfilename, MAX_PATH_EX, m_FilePath);
			break;
		}
	}
	TCHAR* TempPath = new TCHAR[MAX_PATH_EX];
	_tcscpy_s(TempPath, MAX_PATH_EX, Longfilename);
	wchar_t* pwc;
	wchar_t* next_token = NULL;
	int j = 0;
	bool isMatchSystemFolder = true;
	pwc = wcstok_s(TempPath, L"\\", &next_token);
	while (pwc != NULL)
	{
		if (j == 0)
		{
			if (_wcsicmp(pwc, L"c:"))
			{
				isMatchSystemFolder = false;
				break;
			}
		}
		else if (j == 1)
		{
			if (_wcsicmp(pwc, L"Windows") && _wcsicmp(pwc, L"Program Files") && _wcsicmp(pwc, L"Program Files (x86)"))
			{
				isMatchSystemFolder = false;
			}
			break;
		}
		j++;
		pwc = wcstok_s(NULL, L"\\", &next_token);
	}
	if (!isMatchSystemFolder)
	{
		_tcscpy_s(m_FilePath, MAX_PATH_EX, pProcessPath);
		for (int i = (int)_tcslen(m_FilePath) - 1; i >= 0; i--)
		{
			if (m_FilePath[i] == '\\')
			{
				m_FilePath[i] = '\0';
				break;
			}
		}
		for (int i = (int)_tcslen(Longfilename) - 1; i >= 0; i--)
		{
			if (Longfilename[i] == '\\')
			{
				Longfilename[i] = '\0';
				break;
			}
		}
		if (_tcsicmp(Longfilename, m_FilePath))
		{
			char* str = CStringToCharArray(pModulePath, CP_UTF8);
			char str1[MAX_PATH_EX];
			strcpy_s(str1, MAX_PATH_EX, str);
			if (CheckDigitalSignature(pModulePath))
				strcat_s(str1, MAX_PATH_EX, ":1");
			else
				strcat_s(str1, MAX_PATH_EX, ":0");
			TCHAR Md5Hashstr[50];
			memset(Md5Hashstr, '\0', 50);
			DWORD MD5ret = Md5Hash(pModulePath, Md5Hashstr);
			if (MD5ret == 0)
			{
				char* Hashstr = CStringToCharArray(Md5Hashstr, CP_UTF8);
				strcat_s(str1, MAX_PATH_EX, ",");
				strcat_s(str1, MAX_PATH_EX, Hashstr);
				delete[] Hashstr;
				//lstrcpy(m_Info.ProcessHash,Md5Hashstr);
			}
			pIsAbnormal_dll->insert(str1);
			delete[] str;
		}
	}
	delete[] TempPath;
	delete[] m_FilePath;
	delete[] Longfilename;
}
void MemProcess::CheckIsInlineHook(DWORD pid, set<string>* pInlineHook)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (hProcess)
	{//printf("%lu\n",pid);
#ifndef _M_IX86
		DWORD sysbit = Process32or64(hProcess);
		if (sysbit != 0)
		{
			HANDLE hSnapshot;
			MODULEENTRY32 me32;
			hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
			if (hSnapshot != INVALID_HANDLE_VALUE)
			{
				me32.dwSize = sizeof(MODULEENTRY32);
				if (Module32First(hSnapshot, &me32))
				{
					do
					{
						if (sysbit == 64)
						{
							if (!_tcsicmp(me32.szExePath, _T("C:\\Windows\\System32\\ntdll.dll")) || !_tcsicmp(me32.szExePath, _T("C:\\Windows\\System32\\kernel32.dll")))
							{
								try
								{
									FindFunctionAddress(me32.szExePath, me32.modBaseAddr, hProcess, pInlineHook);
								}
								catch (...) {}
							}
						}
						else
						{
							if (!_tcsicmp(me32.szExePath, _T("C:\\Windows\\SysWOW64\\ntdll.dll")) || !_tcsicmp(me32.szExePath, _T("C:\\Windows\\SysWOW64\\kernel32.dll")))
							{
								try
								{
									FindFunctionAddress32(me32.szExePath, me32.modBaseAddr, hProcess, pInlineHook);
									//CompareAddressMatch(&m_FunctionAddressInfo,me32.szExePath/*,sysbit*/);
								}
								catch (...) {}
							}
						}
					} while (Module32Next(hSnapshot, &me32));
				}
				CloseHandle(hSnapshot);
			}
			//ParserVirtualLibary(pid,&m_ModileAddress,&m_FunctionAddress);
		}
#else
		HANDLE hSnapshot;
		MODULEENTRY32 me32;
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
		if (hSnapshot != INVALID_HANDLE_VALUE)
		{
			me32.dwSize = sizeof(MODULEENTRY32);
			if (Module32First(hSnapshot, &me32))
			{
				do
				{
					if (!_tcsicmp(me32.szExePath, _T("C:\\Windows\\System32\\ntdll.dll")) || !_tcsicmp(me32.szExePath, _T("C:\\Windows\\System32\\kernel32.dll")))
					{
						FindFunctionAddress(me32.szExePath, me32.modBaseAddr, hProcess, pInlineHook);
					}
				} while (Module32Next(hSnapshot, &me32));
			}
			CloseHandle(hSnapshot);
		}
		//ParserVirtualLibary(pid,&m_ModileAddress,&m_FunctionAddress);
#endif
	}
	CloseHandle(hProcess);
}
void MemProcess::_clean_things(HANDLE hFile, HANDLE hMapping, PBYTE pFile, const char* pErrorMessage)
{
	//if (pErrorMessage != NULL)
	//	printf ("%s\n", pErrorMessage);

	if (hFile != NULL)
		CloseHandle(hFile);

	if (pFile != NULL)
		UnmapViewOfFile(pFile);

	if (hMapping != NULL)
		CloseHandle(hMapping);
}
void MemProcess::FindFunctionAddress32(TCHAR* file_path, BYTE* pModBaseAddr, HANDLE pProcess, set<string>* pInlineHook)
{
	HANDLE hFile = 0, hMapping = 0;
	DWORD FileSize = 0, ExportTableRVA = 0, ImageBase = 0;
	PBYTE pFile = 0;
	PWORD pOrdinals = 0;
	PDWORD pFuncs = 0;
	PIMAGE_DOS_HEADER ImageDosHeader = 0;
	PIMAGE_NT_HEADERS32 ImageNtHeaders = 0;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = 0;
	hFile = CreateFile(file_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		_clean_things(NULL, NULL, NULL, "Can't open the required DLL");
		return;
	}

	FileSize = GetFileSize(hFile, NULL);
	if (FileSize == 0)
	{
		_clean_things(hFile, NULL, NULL, "FileSize is 0 !");
		return;
	}

	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (hMapping == NULL)
	{
		_clean_things(hFile, NULL, NULL, "Can't create the file mapping !");
		return;
	}

	pFile = (PBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (pFile == NULL)
	{
		_clean_things(hFile, hMapping, NULL, "Can't map the requested file !");
		return;
	}

	ImageBase = (DWORD)pFile;
	ImageDosHeader = (PIMAGE_DOS_HEADER)pFile;

	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		_clean_things(hFile, hMapping, pFile, "This file isn't a PE file !\n\n Wrong IMAGE_DOS_SIGNATURE");
		return;
	}

	ImageNtHeaders = (PIMAGE_NT_HEADERS32)(ImageDosHeader->e_lfanew + (DWORD)ImageDosHeader);

	if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		_clean_things(hFile, hMapping, pFile, "This file isn't a PE file !\n\n Wrong IMAGE_NT_SIGNATURE");
		return;
	}

	ExportTableRVA = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (ExportTableRVA == 0)
	{
		_clean_things(hFile, hMapping, pFile, "Export table not found !");
		return;
	}

	ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ExportTableRVA + ImageBase);


	pOrdinals = (PWORD)(ImageExportDirectory->AddressOfNameOrdinals + ImageBase);
	pFuncs = (PDWORD)(ImageExportDirectory->AddressOfFunctions + ImageBase);
	DWORD NumOfNames = ImageExportDirectory->NumberOfNames;

	DWORD ExportTableSize = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	DWORD ETUpperBoundarie = ExportTableRVA + ExportTableSize;
	BOOL Isntdll = FALSE;
	if (!_tcsicmp(file_path, _T("C:\\Windows\\SysWOW64\\ntdll.dll")))
		Isntdll = TRUE;
	for (UINT i = 0; i < ImageExportDirectory->NumberOfFunctions; i++)
	{
		//sprintf_s ((char *) buffer1, sizeof (buffer1), "Ord: %04lX (0x%08lX)", ImageExportDirectory->Base + i, pFuncs[i]);

		if (/*pOrdinals[i]*/i < NumOfNames)
		{
			if (i <= ImageExportDirectory->NumberOfNames)
			{
				PDWORD pNamePointerRVA = (PDWORD)(ImageExportDirectory->AddressOfNames + ImageBase);
				PCHAR pFuncName = (PCHAR)(pNamePointerRVA[i] + (DWORD)ImageBase);
				if (pFuncName)
				{
					//ULONGLONG m_FunctionAddress = pFuncs[pOrdinals[i]];
					if (Isntdll)
					{
						if (!strcmp(pFuncName, "NlsAnsiCodePage"))
						{
							continue;
						}
					}
					ULONGLONG m_FunctionMemoryAddressInfo = 0;
					BYTE* mBuf = new BYTE[8];
					memset(mBuf, '\x0', 8);
					BYTE* SourceByte = new BYTE[8];
					memset(SourceByte, '\x0', 8);
					memcpy(SourceByte, pFile + pFuncs[pOrdinals[i]], 6);
					ULONGLONG m_FunctionSourecAddressInfo = ((ULONGLONG*)SourceByte)[0];
					SIZE_T nread = 0;
					if (ReadProcessMemory(pProcess, pModBaseAddr + pFuncs[pOrdinals[i]], mBuf, 6, &nread))
					{
						m_FunctionMemoryAddressInfo = ((ULONGLONG*)mBuf)[0];
						if (m_FunctionSourecAddressInfo != 0 && m_FunctionMemoryAddressInfo != 0)
						{
							if (SourceByte[0] != mBuf[0])
							{
								if (!(SourceByte[5] == mBuf[5] && SourceByte[4] == mBuf[4]))
								{
									//char * cPath = CStringToCharArray(file_path,CP_UTF8);
									//printf("%s %s %08I32X 0x%016I64X 0x%016I64X\n",cPath,pFuncName,m_Info.m_FunctionAddress,m_Info.m_FunctionSourecAddressInfo,m_Info.m_FunctionMemoryAddressInfo);
									//delete [] cPath;
									char str[512];
									sprintf_s(str, 512, "%s:0x%016I64X -> 0x%016I64X", pFuncName, m_FunctionSourecAddressInfo, m_FunctionMemoryAddressInfo);
									pInlineHook->insert(str);
								}
							}
						}
					}
					delete[] SourceByte;
					delete[] mBuf;
				}
			}
		}
		//else
		//	break;
	}
	_clean_things(hFile, hMapping, pFile, NULL);
}
void MemProcess::FindFunctionAddress(TCHAR* file_path, BYTE* pModBaseAddr, HANDLE pProcess, set<string>* pInlineHook)
{
	HANDLE hFile = 0, hMapping = 0;
	DWORD FileSize = 0;
	DWORD_PTR ImageBase = 0, ExportTableRVA = 0;
	PBYTE pFile = 0;
	PWORD pOrdinals = 0;
	PDWORD pFuncs = 0;
	PIMAGE_DOS_HEADER ImageDosHeader = 0;
	PIMAGE_NT_HEADERS ImageNtHeaders = 0;
	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = 0;
	//char * cTimeDate = new char[32];
	hFile = CreateFile(file_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	//wprintf(L"%s\n",file_path);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		_clean_things(NULL, NULL, NULL, "Can't open the required DLL");
		return;
	}

	FileSize = GetFileSize(hFile, NULL);
	if (FileSize == 0)
	{
		_clean_things(hFile, NULL, NULL, "FileSize is 0 !");
		return;
	}

	hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (hMapping == NULL)
	{
		_clean_things(hFile, NULL, NULL, "Can't create the file mapping !");
		return;
	}

	pFile = (PBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (pFile == NULL)
	{
		_clean_things(hFile, hMapping, NULL, "Can't map the requested file !");
		return;
	}

	ImageBase = (DWORD_PTR)pFile;
	ImageDosHeader = (PIMAGE_DOS_HEADER)pFile;

	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		_clean_things(hFile, hMapping, pFile, "This file isn't a PE file !\n\n Wrong IMAGE_DOS_SIGNATURE");
		return;
	}

	ImageNtHeaders = (PIMAGE_NT_HEADERS)(ImageDosHeader->e_lfanew + (DWORD_PTR)ImageDosHeader);

	if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
	{
		_clean_things(hFile, hMapping, pFile, "This file isn't a PE file !\n\n Wrong IMAGE_NT_SIGNATURE");
		return;
	}

	ExportTableRVA = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (ExportTableRVA == 0)
	{
		_clean_things(hFile, hMapping, pFile, "Export table not found !");
		return;
	}
	//HMODULE hMod =  LoadLibraryEx(file_path, NULL, DONT_RESOLVE_DLL_REFERENCES );

	//DWORD_PTR addstr = (DWORD_PTR)GetProcAddress(hMod,(char*)NameImg->Name);
	ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ExportTableRVA + ImageBase);
	pOrdinals = (PWORD)(ImageExportDirectory->AddressOfNameOrdinals + ImageBase);
	pFuncs = (PDWORD)(ImageExportDirectory->AddressOfFunctions + ImageBase);
	DWORD NumOfNames = ImageExportDirectory->NumberOfNames;
	DWORD_PTR ExportTableSize = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	DWORD_PTR ETUpperBoundarie = ExportTableRVA + ExportTableSize;
	//wprintf(L"%s\n",file_path);
	for (UINT i = 0; i < ImageExportDirectory->NumberOfFunctions; i++)
	{
		if (i < NumOfNames)
		{
			if (i <= ImageExportDirectory->NumberOfNames)
			{
				PDWORD pNamePointerRVA = (PDWORD)(ImageExportDirectory->AddressOfNames + ImageBase);
				PCHAR pFuncName = (PCHAR)(pNamePointerRVA[i] + (DWORD_PTR)ImageBase);
				if (pFuncName)
				{
					if (_stricmp(pFuncName, "_aexit_rtn"))
					{
						ULONGLONG m_FunctionMemoryAddressInfo = 0;
						BYTE* mBuf = new BYTE[8];
						memset(mBuf, '\x0', 8);
						BYTE* SourceByte = new BYTE[8];
						memset(SourceByte, '\x0', 8);
						memcpy(SourceByte, pFile + pFuncs[pOrdinals[i]], 6);
						ULONGLONG m_FunctionSourecAddressInfo = ((ULONGLONG*)SourceByte)[0];
						SIZE_T nread = 0;
						if (ReadProcessMemory(pProcess, pModBaseAddr + pFuncs[pOrdinals[i]], mBuf, 6, &nread))
						{
							m_FunctionMemoryAddressInfo = ((ULONGLONG*)mBuf)[0];
							if (m_FunctionSourecAddressInfo != 0 && m_FunctionMemoryAddressInfo != 0)
							{
								if (SourceByte[0] != mBuf[0])
								{
									if (!(SourceByte[5] == mBuf[5] && SourceByte[4] == mBuf[4]))
									{
										//char * cPath = CStringToCharArray(file_path,CP_UTF8);
										//printf("%s %s %08I32X 0x%016I64X 0x%016I64X\n",cPath,pFuncName,m_Info.m_FunctionAddress,m_Info.m_FunctionSourecAddressInfo,m_Info.m_FunctionMemoryAddressInfo);
										//delete [] cPath;
										char str[512];
										sprintf_s(str, 512, "%s:0x%016I64X -> 0x%016I64X", pFuncName, m_FunctionSourecAddressInfo, m_FunctionMemoryAddressInfo);
										pInlineHook->insert(str);
									}
								}
							}
						}
						delete[] SourceByte;
						delete[] mBuf;
					}
				}
			}
		}
	}
	_clean_things(hFile, hMapping, pFile, NULL);
	//getchar();
	//return psc;
}

//void MemProcess::DetectNewOpenProcess(void* argv, int pMainProcessid, TCHAR* pBootTime, bool IsFirst)
//{
//	TransportData* m_Client = (TransportData*)argv;
//	TCHAR* MyPath = new TCHAR[MAX_PATH_EX];
//	GetModuleFileName(GetModuleHandle(NULL), MyPath, MAX_PATH_EX);
//	clock_t start, end;
//	clock_t m_BootStart, m_BootEnd;
//	m_ProcessHistory1.clear();
//	m_ProcessHistory2.clear();
//	pProcessHistory = &m_ProcessHistory1;
//	ProcessHistoryNum = 1;
//	char* cBootTime = CStringToCharArray(pBootTime, CP_UTF8);
//	bool IsWin10 = false;
//	char* OSstr = GetOSVersion();
//	if ((strstr(OSstr, "Windows 10") != 0) || (strstr(OSstr, "Windows Server 2016") != 0))
//		IsWin10 = true;
//	//pProcessHistory->push_back(m_HandStr);
//
//	//map<DWORD,process_info> process_list;
//	//LoadingProcessID(&process_list);
//	map<DWORD, process_info> StartProcessID;
//	map<DWORD, process_info> NewProcessID;
//	map<DWORD, process_info>::iterator st;
//	map<DWORD, process_info>::iterator nt;
//	map<DWORD, process_info>::iterator ft;
//	//LoadNowProcessInfo(&StartProcessID);
//	LoadingProcessID(&StartProcessID);
//	if (IsFirst)
//	{
//		for (st = StartProcessID.begin(); st != StartProcessID.end(); st++)
//		{
//			TCHAR* m_ProcessStr = new TCHAR[2048];
//			TCHAR* m_ParentName = new TCHAR[MAX_PATH];
//			time_t m_ParentTime = 0;
//			_tcscpy_s(m_ParentName, MAX_PATH, _T("null"));
//
//			ft = StartProcessID.find(st->second.parent_pid);
//			if (ft != StartProcessID.end())
//			{
//				if (ft->second.ProcessCreateTime != 0 && st->second.ProcessCreateTime != 0)
//				{
//					if (ft->second.ProcessCreateTime <= st->second.ProcessCreateTime)
//					{
//						_tcscpy_s(m_ParentName, MAX_PATH, ft->second.process_name);
//						m_ParentTime = ft->second.ProcessCreateTime;
//					}
//				}
//			}
//			swprintf_s(m_ProcessStr, 2048, _T("%u|%u|%s|%lld|%s|%lld\n"), st->second.pid, st->second.parent_pid, st->second.process_name
//				, st->second.ProcessCreateTime, m_ParentName, m_ParentTime);
//			char* cProcessStr = CStringToCharArray(m_ProcessStr, CP_UTF8);
//			char m_WriteStr[2048];
//			sprintf_s(m_WriteStr, 2048, "%s", cProcessStr);
//			if (pProcessHistory->size() >= 200000)
//			{
//				pProcessHistory->erase(pProcessHistory->begin());
//				pProcessHistory->push_back(m_WriteStr);
//			}
//			else
//				pProcessHistory->push_back(m_WriteStr);
//			//pProcessHistory->push_back(m_WriteStr);
//			delete[] cProcessStr;
//			delete[] m_ParentName;
//			delete[] m_ProcessStr;
//		}
//	}
//	start = clock();
//	m_BootStart = clock();
//	m_BootEnd = clock();
//	for (;;)
//	{
//		NewProcessID.clear();
//		LoadingProcessID(&NewProcessID);
//		for (nt = NewProcessID.begin(); nt != NewProcessID.end(); nt++)
//		{
//			st = StartProcessID.find(nt->first);
//			if (st == StartProcessID.end())
//			{
//				TCHAR* m_ProcessStr = new TCHAR[2048];
//				TCHAR* m_ParentName = new TCHAR[MAX_PATH];
//				time_t m_ParentTime = 0;
//				_tcscpy_s(m_ParentName, MAX_PATH, _T("null"));
//				ft = NewProcessID.find(nt->second.parent_pid);
//				if (ft != NewProcessID.end())
//				{
//					if (ft->second.ProcessCreateTime != 0 && nt->second.ProcessCreateTime != 0)
//					{
//						if (ft->second.ProcessCreateTime <= nt->second.ProcessCreateTime)
//						{
//							_tcscpy_s(m_ParentName, MAX_PATH, ft->second.process_name);
//							m_ParentTime = ft->second.ProcessCreateTime;
//						}
//					}
//					else
//					{
//						ft = StartProcessID.find(nt->second.parent_pid);
//						if (ft != StartProcessID.end())
//						{
//							if (ft->second.ProcessCreateTime != 0 && nt->second.ProcessCreateTime != 0)
//							{
//								if (ft->second.ProcessCreateTime <= nt->second.ProcessCreateTime)
//								{
//									_tcscpy_s(m_ParentName, MAX_PATH, ft->second.process_name);
//									m_ParentTime = ft->second.ProcessCreateTime;
//								}
//							}
//						}
//					}
//				}
//				else
//				{
//					ft = StartProcessID.find(nt->second.parent_pid);
//					if (ft != StartProcessID.end())
//					{
//						if (ft->second.ProcessCreateTime != 0 && nt->second.ProcessCreateTime != 0)
//						{
//							if (ft->second.ProcessCreateTime <= nt->second.ProcessCreateTime)
//							{
//								_tcscpy_s(m_ParentName, MAX_PATH, ft->second.process_name);
//								m_ParentTime = ft->second.ProcessCreateTime;
//							}
//						}
//					}
//				}
//				swprintf_s(m_ProcessStr, 2048, _T("%u|%u|%s|%lld|%s|%lld\n"), nt->second.pid, nt->second.parent_pid, nt->second.process_name
//					, nt->second.ProcessCreateTime, m_ParentName, m_ParentTime);
//				char* cProcessStr = CStringToCharArray(m_ProcessStr, CP_UTF8);
//				char m_WriteStr[2048];
//				sprintf_s(m_WriteStr, 2048, "%s", cProcessStr);
//				if (pProcessHistory->size() >= 200000)
//				{
//					pProcessHistory->erase(pProcessHistory->begin());
//					pProcessHistory->push_back(m_WriteStr);
//				}
//				else
//					pProcessHistory->push_back(m_WriteStr);
//				//pProcessHistory->push_back(m_WriteStr);
//				delete[] cProcessStr;
//				delete[] m_ParentName;
//				delete[] m_ProcessStr;
//			}
//		}
//		end = clock();
//
//		if ((end - start) > 30000)
//		{
//			if (!pProcessHistory->empty())
//			{
//				m_Client->SendHistoryForServer(this, cBootTime, 1);
//			}
//			start = clock();
//		}
//		StartProcessID.clear();
//		StartProcessID = NewProcessID;
//		if (!IsHavePID(pMainProcessid))
//			break;
//
//		//m_BootEnd = clock();
//		//Sleep(10);
//		if (IsWin10)
//		{
//			if ((m_BootEnd - m_BootStart) > 60000)
//				Sleep(200);
//			else
//			{
//				m_BootEnd = clock();
//				Sleep(10);
//			}
//		}
//		else
//		{
//			if ((m_BootEnd - m_BootStart) > 60000)
//				Sleep(50);
//			else
//			{
//				m_BootEnd = clock();
//				Sleep(10);
//			}
//		}
//	}
//	NewProcessID.clear();
//	StartProcessID.clear();
//	m_ProcessHistory1.clear();
//	m_ProcessHistory2.clear();
//	delete[] cBootTime;
//	delete[] MyPath;
//}
//void MemProcess::DetectNewOpenProcessInfo(void* argv, int pMainProcessid, TCHAR* pBootTime, bool IsFirst)
//{
//	TransportData* m_Client = (TransportData*)argv;
//	TCHAR* MyPath = new TCHAR[MAX_PATH_EX];
//	GetModuleFileName(GetModuleHandle(NULL), MyPath, MAX_PATH_EX);
//	clock_t start, end;
//	clock_t m_BootStart, m_BootEnd;
//	m_ProcessHistoryInfo1.clear();
//	m_ProcessHistoryInfo2.clear();
//	pProcessHistoryInfo = &m_ProcessHistoryInfo1;
//	ProcessHistoryInfoNum = 1;
//	char* cBootTime = CStringToCharArray(pBootTime, CP_UTF8);
//	bool IsWin10 = false;
//	char* OSstr = GetOSVersion();
//	if ((strstr(OSstr, "Windows 10") != 0) || (strstr(OSstr, "Windows Server 2016") != 0))
//		IsWin10 = true;
//	map<DWORD, process_info> StartProcessID;
//	map<DWORD, process_info> NewProcessID;
//	map<DWORD, process_info>::iterator st;
//	map<DWORD, process_info>::iterator nt;
//	//LoadNowProcessInfo(&StartProcessID);
//	LoadingProcessID(&StartProcessID);
//	if (IsFirst)
//	{
//		for (st = StartProcessID.begin(); st != StartProcessID.end(); st++)
//		{
//			//TCHAR * m_ProcessStr = new TCHAR[2048];
//			string m_ProcessStr;
//			TCHAR* m_Path = new TCHAR[512];
//			TCHAR* m_ComStr = new TCHAR[61440];
//			_tcscpy_s(m_Path, 512, _T("null"));
//			_tcscpy_s(m_ComStr, 61440, _T("null"));
//			GetProcessDetectInfo(st->first, m_Path, m_ComStr);
//			if (_tcsicmp(m_Path, MyPath))
//			{
//				char* cstr = new char[2048];
//				sprintf_s(cstr, 2048, "%u|%lld|", st->second.pid, st->second.ProcessCreateTime);
//				m_ProcessStr = cstr;
//				char* cPath = CStringToCharArray(m_Path, CP_UTF8);
//				m_ProcessStr += cPath;
//				m_ProcessStr += "|";
//				char* cComStr = CStringToCharArray(m_ComStr, CP_UTF8);
//				m_ProcessStr += cComStr;
//				m_ProcessStr += "\n";
//				//swprintf_s(m_ProcessStr,2048,_T("%u|%lld|%s|%s\n"),st->second.pid,st->second.ProcessCreateTime,m_Path,m_ComStr);
//				//char * cProcessStr = CStringToCharArray(m_ProcessStr,CP_UTF8);
//				//char m_WriteStr[2048];
//				//sprintf_s(m_WriteStr,2048,"%s",cProcessStr);
//				if (pProcessHistoryInfo->size() >= 100000)
//				{
//					pProcessHistoryInfo->erase(pProcessHistoryInfo->begin());
//					pProcessHistoryInfo->push_back(m_ProcessStr);
//				}
//				else
//					pProcessHistoryInfo->push_back(m_ProcessStr);
//				//pProcessHistoryInfo->push_back(m_WriteStr);
//				delete[] cComStr;
//				delete[] cPath;
//				delete[] cstr;
//			}
//			delete[] m_Path;
//			delete[] m_ComStr;
//			//delete [] m_ProcessStr;
//		}
//	}
//	start = clock();
//	m_BootStart = clock();
//	m_BootEnd = clock();
//	for (;;)
//	{
//		NewProcessID.clear();
//		LoadingProcessID(&NewProcessID);
//		for (nt = NewProcessID.begin(); nt != NewProcessID.end(); nt++)
//		{
//			st = StartProcessID.find(nt->first);
//			if (st == StartProcessID.end())
//			{
//				string m_ProcessStr;
//				TCHAR* m_Path = new TCHAR[512];
//				TCHAR* m_ComStr = new TCHAR[61440];
//				_tcscpy_s(m_Path, 512, _T("null"));
//				_tcscpy_s(m_ComStr, 61440, _T("null"));
//				GetProcessDetectInfo(nt->first, m_Path, m_ComStr);
//				if (_tcsicmp(m_Path, MyPath))
//				{
//					//swprintf_s(m_ProcessStr,2048,_T("%u|%lld|%s|%s\n"),nt->second.pid,nt->second.ProcessCreateTime,m_Path,m_ComStr);
//					//char * cProcessStr = CStringToCharArray(m_ProcessStr,CP_UTF8);
//					//char m_WriteStr[2048];
//					//sprintf_s(m_WriteStr,2048,"%s",cProcessStr);
//					char* cstr = new char[2048];
//					sprintf_s(cstr, 2048, "%u|%lld|", nt->second.pid, nt->second.ProcessCreateTime);
//					m_ProcessStr = cstr;
//					char* cPath = CStringToCharArray(m_Path, CP_UTF8);
//					m_ProcessStr += cPath;
//					m_ProcessStr += "|";
//					char* cComStr = CStringToCharArray(m_ComStr, CP_UTF8);
//					m_ProcessStr += cComStr;
//					m_ProcessStr += "\n";
//					if (pProcessHistoryInfo->size() >= 100000)
//					{
//						pProcessHistoryInfo->erase(pProcessHistoryInfo->begin());
//						pProcessHistoryInfo->push_back(m_ProcessStr);
//					}
//					else
//						pProcessHistoryInfo->push_back(m_ProcessStr);
//					//pProcessHistoryInfo->push_back(m_WriteStr);
//					delete[] cComStr;
//					delete[] cPath;
//					delete[] cstr;
//				}
//				delete[] m_Path;
//				delete[] m_ComStr;
//				//delete [] m_ProcessStr;
//			}
//		}
//		end = clock();
//
//		if ((end - start) > 30000)
//		{
//			if (!pProcessHistoryInfo->empty())
//			{
//				m_Client->SendHistoryForServer(this, cBootTime, 5);
//			}
//			start = clock();
//		}
//		StartProcessID.clear();
//		StartProcessID = NewProcessID;
//		if (!IsHavePID(pMainProcessid))
//			break;
//
//		if (IsWin10)
//		{
//			if ((m_BootEnd - m_BootStart) > 60000)
//				Sleep(200);
//			else
//			{
//				m_BootEnd = clock();
//				Sleep(10);
//			}
//		}
//		else
//		{
//			if ((m_BootEnd - m_BootStart) > 60000)
//				Sleep(50);
//			else
//			{
//				m_BootEnd = clock();
//				Sleep(10);
//			}
//		}
//		//Sleep(10);
//	}
//	NewProcessID.clear();
//	StartProcessID.clear();
//	m_ProcessHistoryInfo1.clear();
//	m_ProcessHistoryInfo2.clear();
//	delete[] cBootTime;
//	delete[] MyPath;
//}
//void MemProcess::DetectNewNetwork(void* argv, int pMainProcessid, TCHAR* pBootTime)
//{
//	TransportData* m_Client = (TransportData*)argv;
//	TCHAR* MyPath = new TCHAR[MAX_PATH_EX];
//	GetModuleFileName(GetModuleHandle(NULL), MyPath, MAX_PATH_EX);
//	clock_t start, end;
//	time_t NetworkClock;
//	m_NetworkHistory1.clear();
//	m_NetworkHistory2.clear();
//	pNetworkHistory = &m_NetworkHistory1;
//	NetworkHistoryNum = 1;
//
//	char* cBootTime = CStringToCharArray(pBootTime, CP_UTF8);
//	//pNetworkHistory->push_back(m_HandStr);
//	set<u_short> m_ListenPort;
//	map<wstring, u_short> StartNetworkInfo;
//	map<wstring, u_short> NewNetworkInfo;
//	map<wstring, u_short>::iterator nst;
//	map<wstring, u_short>::iterator nnt;
//	set<u_short>::iterator lt;
//	char* OSstr = GetOSVersion();
//	if ((strstr(OSstr, "Windows XP") != 0) || (strstr(OSstr, "Windows Server 2003") != 0))
//		GetDetectTcpInformationXP(&StartNetworkInfo, &m_ListenPort);
//	else
//		GetDetectTcpInformation(&StartNetworkInfo, &m_ListenPort);
//
//	time(&NetworkClock);
//	for (nst = StartNetworkInfo.begin(); nst != StartNetworkInfo.end(); nst++)
//	{
//		DWORD m_Pid = GetInfoPid(/*(*nst).c_str()*/nst->first.c_str());
//		if (m_Pid != 0)
//		{
//			TCHAR* m_NetworkStr = new TCHAR[2048];
//			TCHAR* m_Path = new TCHAR[512];
//			//TCHAR * m_ComStr = new TCHAR[512];
//			time_t m_Time = 0;
//			//TCHAR * m_UserName = new TCHAR[_MAX_FNAME];
//			_tcscpy_s(m_Path, 512, _T("null"));
//			//_tcscpy_s(m_ComStr,512,_T("null"));
//			//_tcscpy_s(m_Time,20,_T("null"));
//			//_tcscpy_s(m_UserName,_MAX_FNAME,_T("null"));
//			//GetProcessInfo(m_Pid,m_Path,m_Time,m_UserName,m_ComStr);
//			GetProcessOnlyPathAndTime(m_Pid, m_Path, m_Time);
//			if (_tcsicmp(m_Path, MyPath))
//			{
//				int ConnectionINorOUT = 0;
//				lt = m_ListenPort.find(nst->second);
//				if (lt != m_ListenPort.end())
//					ConnectionINorOUT = 1;
//				swprintf_s(m_NetworkStr, 2048, _T("%s|%lld|%lld|%d|%u\n"), nst->first.c_str(), NetworkClock, m_Time, ConnectionINorOUT, nst->second);
//				char* cNetworkStr = CStringToCharArray(m_NetworkStr, CP_UTF8);
//				char m_WriteStr[2048];
//				sprintf_s(m_WriteStr, 2048, "%s", cNetworkStr);
//				if (pNetworkHistory->size() >= 3000000)
//				{
//					pNetworkHistory->erase(pNetworkHistory->begin());
//					pNetworkHistory->push_back(m_WriteStr);
//				}
//				else
//					pNetworkHistory->push_back(m_WriteStr);
//				delete[] cNetworkStr;
//			}
//			//delete [] m_UserName;
//			//delete [] m_Time;
//			//delete [] m_ComStr;
//			delete[] m_Path;
//			delete[] m_NetworkStr;
//		}
//	}
//	start = clock();
//	for (;;)
//	{
//		m_ListenPort.clear();
//		NewNetworkInfo.clear();
//		if ((strstr(OSstr, "Windows XP") != 0) || (strstr(OSstr, "Windows Server 2003") != 0))
//			GetDetectTcpInformationXP(&NewNetworkInfo, &m_ListenPort);
//		else
//			GetDetectTcpInformation(&NewNetworkInfo, &m_ListenPort);
//
//		time(&NetworkClock);
//		for (nnt = NewNetworkInfo.begin(); nnt != NewNetworkInfo.end(); nnt++)
//		{
//			nst = StartNetworkInfo.find(nnt->first.c_str());
//			if (nst == StartNetworkInfo.end())
//			{
//				DWORD m_Pid = GetInfoPid(nnt->first.c_str());
//				if (m_Pid != 0)
//				{
//					TCHAR* m_NetworkStr = new TCHAR[2048];
//					TCHAR* m_Path = new TCHAR[512];
//					//TCHAR * m_ComStr = new TCHAR[512];
//					time_t m_Time = 0;
//					//TCHAR * m_UserName = new TCHAR[_MAX_FNAME];
//					_tcscpy_s(m_Path, 512, _T("null"));
//					//_tcscpy_s(m_ComStr,512,_T("null"));
//					//_tcscpy_s(m_Time,20,_T("null"));
//					//_tcscpy_s(m_UserName,_MAX_FNAME,_T("null"));
//					GetProcessOnlyPathAndTime(m_Pid, m_Path, m_Time);
//					if (_tcsicmp(m_Path, MyPath))
//					{
//						int ConnectionINorOUT = 0;
//						lt = m_ListenPort.find(nnt->second);
//						if (lt != m_ListenPort.end())
//							ConnectionINorOUT = 1;
//						swprintf_s(m_NetworkStr, 2048, _T("%s|%lld|%lld|%d|%u\n"), nnt->first.c_str(), NetworkClock, m_Time, ConnectionINorOUT, nnt->second);
//						char* cNetworkStr = CStringToCharArray(m_NetworkStr, CP_UTF8);
//						char m_WriteStr[2048];
//						sprintf_s(m_WriteStr, 2048, "%s", cNetworkStr);
//						if (pNetworkHistory->size() >= 3000000)
//						{
//							pNetworkHistory->erase(pNetworkHistory->begin());
//							pNetworkHistory->push_back(m_WriteStr);
//						}
//						else
//							pNetworkHistory->push_back(m_WriteStr);
//						delete[] cNetworkStr;
//					}
//					//delete [] m_UserName;
//					//delete [] m_Time;
//					//delete [] m_ComStr;
//					delete[] m_Path;
//					delete[] m_NetworkStr;
//				}
//			}
//		}
//		end = clock();
//		if ((end - start) > 30000)
//		{
//			if (!pNetworkHistory->empty())
//			{
//				m_Client->SendHistoryForServer(this, cBootTime, 2);
//			}
//			start = clock();
//		}
//		StartNetworkInfo.clear();
//		StartNetworkInfo = NewNetworkInfo;
//		if (!IsHavePID(pMainProcessid))
//			break;
//		Sleep(100);
//	}
//	m_ListenPort.clear();
//	NewNetworkInfo.clear();
//	StartNetworkInfo.clear();
//	m_NetworkHistory1.clear();
//	m_NetworkHistory2.clear();
//	delete[] cBootTime;
//	delete[] MyPath;
//}
//void MemProcess::DetectAccessFiles(void* argv, int pMainProcessid, TCHAR* pBootTime, bool UserMode)
//{
//	//TransportData * m_Client = (TransportData *)argv;
//	//clock_t start,end;
//	//m_AccessFilesHistory1.clear();
//	//m_AccessFilesHistory2.clear();
//	//pAccessFilesHistory = &m_AccessFilesHistory1;
//	//AccessFilesHistoryNum = 1;
//	//char * cBootTime = CStringToCharArray(pBootTime,CP_UTF8);
//	//bool m_IsWorkEnd = false;
//	//DWORD dwRes;
// //   PSID pEveryoneSID = NULL, pAdminSID = NULL;
// //   PACL pACL = NULL;
// //   PSECURITY_DESCRIPTOR pSD = NULL;
// //   EXPLICIT_ACCESS ea[1];
// //   SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
// //   SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
// //   SECURITY_ATTRIBUTES Attributes;
// //   HKEY hkSub = NULL;
// //
// //   // Create a well-known SID for the Everyone group.
// //   BOOL Success = AllocateAndInitializeSid(&SIDAuthWorld, 1,
// //                                           SECURITY_WORLD_RID,
// //                                           0, 0, 0, 0, 0, 0, 0,
// //                                           &pEveryoneSID);
//	//if(Success)
//	//{
//	//	//assert(Success != FALSE, "AllocateAndInitializeSid failed in Pipe::CreatePipe");
//	//
//	//	// Initialize an EXPLICIT_ACCESS structure for an ACE.
//	//	// The ACE will allow Everyone read access to the key.
//	//	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
//	//	ea[0].grfAccessPermissions = FILE_ALL_ACCESS;
//	//	ea[0].grfAccessMode = SET_ACCESS;
//	//	ea[0].grfInheritance= NO_INHERITANCE;
//	//	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
//	//	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
//	//	ea[0].Trustee.ptstrName  = (LPTSTR) pEveryoneSID;
//	//
//	//	// Create a new ACL that contains the new ACEs.
//	//	dwRes = SetEntriesInAcl(1, ea, NULL, &pACL);
//	//	if(dwRes == ERROR_SUCCESS)
//	//	{
//	//	//assert(dwRes == ERROR_SUCCESS, "SetEntriesInAcl failed in Pipe::CreatePipe");
//	//
//	//	// Initialize a security descriptor.  
//	//		pSD = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
//	//		if(pSD != NULL)
//	//		{
//	//			//assert(pSD != NULL, "LocalAlloc failed in Pipe::CreatePipe");
// //   
//	//			Success = InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);
//	//			if(Success != FALSE)
//	//			{
//	//				//assert(Success != FALSE, "InitializeSecurityDescriptor failed in Pipe::CreatePipe");
// //   
//	//				// Add the ACL to the security descriptor. 
//	//				Success = SetSecurityDescriptorDacl(pSD, 
//	//							TRUE,     // bDaclPresent flag
//	//							pACL, 
//	//							FALSE);
//	//				if(Success != FALSE)
//	//				{
//	//					//assert(Success != FALSE, "SetSecurityDescriptorDacl failed in Pipe::CreatePipe");
// //   
//	//					// Initialize a security attributes structure.
//	//					Attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
//	//					Attributes.lpSecurityDescriptor = pSD;
//	//					Attributes.bInheritHandle = FALSE;
//	//					HANDLE hPipe;
//	//					//wchar_t buffer[1024];
//	//					DWORD dwRead;
//	//					hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\ClientSearchPipe"),
//	//											PIPE_ACCESS_DUPLEX,
//	//											PIPE_TYPE_MESSAGE |         // message type pipe 
//	//											PIPE_READMODE_MESSAGE |     // message-read mode 
//	//											PIPE_WAIT,
//	//											PIPE_UNLIMITED_INSTANCES,
//	//											1024 * 16,
//	//											1024 * 16,
//	//											NMPWAIT_USE_DEFAULT_WAIT,
//	//											&Attributes);
//	//					if(hPipe != INVALID_HANDLE_VALUE)
//	//					{
//	//						ThreadInfo * pInfo = new ThreadInfo;
//	//						pInfo->isEnding = &m_IsWorkEnd;
//	//						pInfo->MainPid = pMainProcessid;
//	//						pInfo->pClass = this;
//	//						unsigned int thID;
//	//						HANDLE ht;
//	//						ht = (HANDLE)_beginthreadex(NULL, 0, threadAccessFiles,pInfo, 0, &thID);
//	//						CloseHandle(ht);
//	//						start = clock();
//	//						while (hPipe != INVALID_HANDLE_VALUE)
//	//						{
//	//							if (ConnectNamedPipe(hPipe, NULL) != FALSE)   // wait for someone to connect to the pipe
//	//							{
//	//								char * buffer = new char[1024];
//	//								while (ReadFile(hPipe, buffer, 1024, &dwRead, NULL) != FALSE)
//	//								{
//	//									buffer[dwRead] = '\0';
//	//									if(pAccessFilesHistory->size() >= 100000)
//	//									{
//	//										pAccessFilesHistory->erase(pAccessFilesHistory->begin());
//	//										pAccessFilesHistory->insert(buffer);
//	//									}
//	//									else
//	//										pAccessFilesHistory->insert(buffer);
//	//								}
//	//								delete [] buffer;
//	//							}
//	//							end = clock();
//	//							if((end-start) > 30000)
//	//							{
//	//								if(!pAccessFilesHistory->empty())
//	//								{
//	//									m_Client->SendHistoryForServer(this,cBootTime,3);
//	//								}
//	//								start = clock();
//	//							}
//	//							if(!IsHavePID(pMainProcessid))
//	//								break;
//	//							DisconnectNamedPipe(hPipe);
//	//						}
//	//					}
//	//					CloseHandle(hPipe);
//	//				}
//	//			}
//	//		}
//	//	}
//	//}
//	//
//	//m_IsWorkEnd = true;
//	//m_AccessFilesHistory1.clear();
//	//m_AccessFilesHistory2.clear();
//	//delete [] cBootTime;
//
//	TransportData* m_Client = (TransportData*)argv;
//	clock_t start, end;
//	const int HANDLEARRSIZE = 4096;
//	m_AccessFilesHistory1.clear();
//	m_AccessFilesHistory2.clear();
//	pAccessFilesHistory = &m_AccessFilesHistory1;
//	AccessFilesHistoryNum = 1;
//	char* cBootTime = CStringToCharArray(pBootTime, CP_UTF8);
//	bool m_IsWorkEnd = false;
//	HANDLE hMapFile[HANDLEARRSIZE];
//	wchar_t* MemName = new wchar_t[256];
//	for (int i = 0; i < HANDLEARRSIZE; i++)
//	{
//		swprintf_s(MemName, 256, L"ClientSearchPipe%d", i);
//		hMapFile[i] = CreateFileMapping(
//			INVALID_HANDLE_VALUE,    // use paging file
//			NULL,                    // default security
//			PAGE_READWRITE,          // read/write access
//			0,                       // maximum object size (high-order DWORD)
//			4096,                // maximum object size (low-order DWORD)
//			MemName);                 // name of mapping object
//	}
//	ThreadInfo* pInfo = new ThreadInfo;
//	pInfo->isEnding = &m_IsWorkEnd;
//	pInfo->MainPid = pMainProcessid;
//	pInfo->pClass = this;
//	unsigned int thID;
//	HANDLE ht;
//	ht = (HANDLE)_beginthreadex(NULL, 0, threadAccessFiles, pInfo, 0, &thID);
//	CloseHandle(ht);
//	start = clock();
//	while (true)
//	{
//		for (int i = 0; i < HANDLEARRSIZE; i++)
//		{
//			if (hMapFile[i] != NULL)
//			{
//				LPCTSTR pBuf = (LPTSTR)MapViewOfFile(hMapFile[i],   // handle to map object
//					FILE_MAP_ALL_ACCESS, // read/write permission
//					0,
//					0,
//					4096);
//
//				if (pBuf != NULL)
//				{
//					if ((int)_tcslen(pBuf) != 0)
//					{
//						//wprintf(L"%s",pBuf);
//						//MessageBox(NULL, pBuf, TEXT("Process2"), MB_OK);
//						char* buffer = CStringToCharArray((wchar_t*)pBuf, CP_UTF8);
//						pAccessFilesHistory->insert(buffer);
//						memset((PVOID)pBuf, '\0', 4096);
//						delete[] buffer;
//					}
//					UnmapViewOfFile(pBuf);
//
//				}
//			}
//			if ((i % 512) == 0)
//				Sleep(100);
//		}
//		end = clock();
//		if ((end - start) > 30000)
//		{
//			if (!pAccessFilesHistory->empty())
//			{
//				if (UserMode)
//					m_Client->SendHistoryForServer(this, cBootTime, 6);
//				else
//					m_Client->SendHistoryForServer(this, cBootTime, 3);
//			}
//			start = clock();
//		}
//		if (!IsHavePID(pMainProcessid))
//			break;
//		Sleep(200);
//	}
//	m_IsWorkEnd = true;
//	for (int i = 0; i < HANDLEARRSIZE; i++)
//	{
//		CloseHandle(hMapFile[i]);
//	}
//	delete[] MemName;
//	m_AccessFilesHistory1.clear();
//	m_AccessFilesHistory2.clear();
//	delete[] cBootTime;
//}
void MemProcess::AccessFilesUserMode(DWORD MainPid, DWORD ParentPid)
{
	TCHAR* MyPath = new TCHAR[MAX_PATH_EX];
	GetModuleFileName(GetModuleHandle(NULL), MyPath, MAX_PATH_EX);
	DWORD MyPid = GetCurrentProcessId();
	//DWORD UserModePid = 0;
	map<DWORD, wstring> SystemPID;
	LoadSystemPID(&SystemPID);
	map<DWORD, DWORD> StartProcessID;
	map<DWORD, DWORD> NewProcessID;
	map<DWORD, DWORD>::iterator st;
	map<DWORD, DWORD>::iterator nt;
	map<DWORD, wstring>::iterator ft;
	//StartUserModeCommandProcess(UserModePid);
	//DWORD UserModePid = GetUserModeProcessID();
	LoadingProcessOnlyID(&StartProcessID);
	for (st = StartProcessID.begin(); st != StartProcessID.end(); st++)
	{
		if (!IsHavePID((int)ParentPid) || !IsHavePID((int)MainPid))
			break;
		ft = SystemPID.find(st->first);
		if (ft == SystemPID.end())
		{
			TCHAR* m_Path = new TCHAR[MAX_PATH_EX];
			GetProcessOnlyPath(st->first, m_Path);
			if (_tcsicmp(MyPath, m_Path) && st->second != MyPid && st->second != MainPid)
			{
				if (!WindowsMainProcess(&SystemPID, st->second))
				{
					//char* cURL = new char[64];
					//sprintf_s(cURL,64,"User %lu\n",st->first);
					//WriteLogFile(_T("C:\\Users\\Scan\\Desktop\\987.txt"),cURL);
					//delete [] cURL;
					InjectionProcess(st->first, m_Path);
				}
			}
			delete[] m_Path;
		}
	}
	for (;;)
	{
		if (!IsHavePID((int)ParentPid) || !IsHavePID((int)MainPid))
			break;
		//SystemPID.clear();
		//LoadSystemPID(&SystemPID);
		NewProcessID.clear();
		LoadingProcessOnlyID(&NewProcessID);
		for (nt = NewProcessID.begin(); nt != NewProcessID.end(); nt++)
		{
			st = StartProcessID.find(nt->first);
			if (st == StartProcessID.end())
			{
				ft = SystemPID.find(nt->first);
				if (ft == SystemPID.end())
				{
					TCHAR* m_Path = new TCHAR[MAX_PATH_EX];
					GetProcessOnlyPath(nt->first, m_Path);
					if (_tcsicmp(MyPath, m_Path) && nt->second != MyPid && nt->second != MainPid)
					{
						if (!WindowsMainProcess(&SystemPID, nt->second))
						{
							//char* cURL = new char[64];
							//sprintf_s(cURL,64,"User %lu\n",st->first);
							//WriteLogFile(_T("C:\\Users\\Scan\\Desktop\\987.txt"),cURL);
							//delete [] cURL;
							InjectionProcess(nt->first, m_Path);
						}
					}
					delete[] m_Path;
				}
			}
		}
		StartProcessID.clear();
		StartProcessID = NewProcessID;
		Sleep(100);
	}
	NewProcessID.clear();
	StartProcessID.clear();
	SystemPID.clear();
	delete[] MyPath;
}
//void MemProcess::DetectProcessRisk(void* argv, int pMainProcessid, TCHAR* pBootTime, bool IsFirst, set<DWORD>* pApiName)
//{
//	TransportData* m_Client = (TransportData*)argv;
//	TCHAR* MyPath = new TCHAR[MAX_PATH_EX];
//	GetModuleFileName(GetModuleHandle(NULL), MyPath, MAX_PATH_EX);
//	clock_t start, end;
//	clock_t m_BootStart, m_BootEnd;
//	m_RiskArray1.clear();
//	m_RiskArray2.clear();
//	m_UnKnownData1.clear();
//	m_UnKnownData2.clear();
//	pRiskArray = &m_RiskArray1;
//	RiskArrayNum = 1;
//	pUnKnownData = &m_UnKnownData1;
//	UnKnownDataNum = 1;
//	char* cBootTime = CStringToCharArray(pBootTime, CP_UTF8);
//	bool IsWin10 = false;
//	char* OSstr = GetOSVersion();
//	if ((strstr(OSstr, "Windows 10") != 0) || (strstr(OSstr, "Windows Server 2016") != 0))
//		IsWin10 = true;
//	map<DWORD, process_info_Ex> StartProcessID;
//	map<DWORD, process_info_Ex> NewProcessID;
//	map<DWORD, process_info_Ex>::iterator st;
//	map<DWORD, process_info_Ex>::iterator nt;
//	//map<DWORD,process_info_Ex>::iterator ft;
//	LoadNowProcessInfoDetect(&StartProcessID);
//	if (IsFirst)
//	{
//		for (st = StartProcessID.begin(); st != StartProcessID.end(); st++)
//		{
//			if (!IsWindowsProcessNormal(&StartProcessID, st->first))
//			{
//				ParserProcessRisk(&st->second, pApiName, MyPath, pUnKnownData);
//			}
//		}
//	}
//	start = clock();
//	m_BootStart = clock();
//	m_BootEnd = clock();
//	for (;;)
//	{
//		NewProcessID.clear();
//		LoadNowProcessInfoDetect(&NewProcessID);
//		for (nt = NewProcessID.begin(); nt != NewProcessID.end(); nt++)
//		{
//			st = StartProcessID.find(nt->first);
//			if (st == StartProcessID.end())
//			{
//				ParserProcessRisk(&nt->second, pApiName, MyPath, pUnKnownData);
//			}
//		}
//		end = clock();
//
//		if ((end - start) > 30000)
//		{
//			if (!pRiskArray->empty())
//			{
//				m_Client->SendHistoryForServer(this, cBootTime, 4);
//			}
//			//if(!pUnKnownData->empty())
//			//{
//			//}
//			start = clock();
//		}
//		StartProcessID.clear();
//		StartProcessID = NewProcessID;
//		if (!IsHavePID(pMainProcessid))
//			break;
//		if (IsWin10)
//		{
//			if ((m_BootEnd - m_BootStart) > 60000)
//				Sleep(200);
//			else
//			{
//				m_BootEnd = clock();
//				Sleep(10);
//			}
//		}
//		else
//		{
//			if ((m_BootEnd - m_BootStart) > 60000)
//				Sleep(50);
//			else
//			{
//				m_BootEnd = clock();
//				Sleep(10);
//			}
//		}
//	}
//	NewProcessID.clear();
//	StartProcessID.clear();
//	m_RiskArray1.clear();
//	m_RiskArray2.clear();
//	delete[] cBootTime;
//	delete[] MyPath;
//}
void MemProcess::ParserProcessRisk(/*ThreadProcessInfo * pInfo*/process_info_Ex* pInfo, set<DWORD>* pApiName, TCHAR* pMyPath, vector<UnKnownDataInfo>* pMembuf)
{
	//TCHAR * m_ProcessPath = new TCHAR[MAX_PATH_EX];
	TCHAR* m_ProcessTime = new TCHAR[20];
	TCHAR* m_ProcessCTime = new TCHAR[20];
	_tcscpy_s(m_ProcessTime, 20, _T("null"));
	_tcscpy_s(m_ProcessCTime, 20, _T("null"));

	if (pInfo->ProcessCreateTime > 0) swprintf_s(m_ProcessCTime, 20, _T("%llu"), pInfo->ProcessCreateTime);
	if (!_tcscmp(pInfo->process_Path, _T("null"))) SearchExecutePath(pInfo->pid, pInfo->process_Path, pInfo->process_name);

	SYSTEMTIME sys;
	GetLocalTime(&sys);
	swprintf_s(m_ProcessTime, 20, _T("%4d/%02d/%02d %02d:%02d:%02d"), sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond);
	if (_tcsicmp(pInfo->process_Path, pMyPath)) {
		vector<TCPInformation> NetInfo;
		char* OSstr = GetOSVersion();

		//printf("GetTcpInformationEx\n");
		if ((strstr(OSstr, "Windows XP") != 0) || (strstr(OSstr, "Windows Server 2003") != 0)) GetTcpInformationXPEx(&NetInfo);
		else if (strstr(OSstr, "Windows 2000") != 0) {}
		else GetTcpInformationEx(&NetInfo);

		time_t NetworkClock;
		time(&NetworkClock);
		map<wstring, BOOL> m_ServiceRun;
		set<wstring> m_StartRun;

		//printf("AutoRun\n");
		AutoRun* m_AutoRun = new AutoRun;
		//printf("LoadServiceStartCommand\n");
		m_AutoRun->LoadServiceStartCommand(&m_ServiceRun);
		//printf("LoadAutoRunStartCommand start\n");
		m_AutoRun->LoadAutoRunStartCommand(&m_StartRun);
		//printf("LoadAutoRunStartCommand end\n");
		ProcessInfoData m_Info = { 0 };
		m_Info.ProcessID = pInfo->pid;
		m_Info.HideAttribute = FALSE;
		m_Info.HideProcess = pInfo->IsHide;
		//printf("copy\n");
		lstrcpy(m_Info.ProcessName, pInfo->process_name);
		//memset(m_Info.ProcessTime,'\0',20);
		_tcscpy_s(m_Info.ProcessPath, MAX_PATH_EX, pInfo->process_Path);
		_tcscpy_s(m_Info.ProcessTime, 20, m_ProcessTime);
		_tcscpy_s(m_Info.ProcessCTime, 20, m_ProcessCTime);
		_tcscpy_s(m_Info.ParentCTime, 20, _T("null"));
		_tcscpy_s(m_Info.ParentPath, MAX_PATH_EX, _T("null"));
		m_Info.ParentID = pInfo->parent_pid;
		//printf("GetProcessPath\n");
		GetProcessPath(pInfo->parent_pid, m_Info.ParentPath, true, NULL, m_Info.ParentCTime);
		//printf("CheckIsInjection\n");
		m_Info.Injected = CheckIsInjection(pInfo->pid, pMembuf, m_Info.ProcessName, m_Info.UnKnownHash);
		//printf("CheckIsStartRun\n");
		m_Info.StartRun = CheckIsStartRun(&m_ServiceRun, &m_StartRun, pInfo->pid/*,m_Info.HideService*/);
		//printf("CheckIsInlineHook\n");
		CheckIsInlineHook(pInfo->pid, &m_Info.InlineHookInfo);

		//printf("ProcessHash\n");
		lstrcpy(m_Info.ProcessHash, _T("null"));
		if (_tcscmp(m_Info.ProcessPath, _T("null"))) {
			TCHAR Md5Hashstr[50];
			memset(Md5Hashstr, '\0', 50);
			DWORD MD5ret = Md5Hash(m_Info.ProcessPath, Md5Hashstr);
			if (MD5ret == 0)
				lstrcpy(m_Info.ProcessHash, Md5Hashstr);
			DWORD AttRet = GetFileAttributes(m_Info.ProcessPath);
			if ((AttRet & FILE_ATTRIBUTE_HIDDEN) == FILE_ATTRIBUTE_HIDDEN)
				m_Info.HideAttribute = TRUE;
			DigitalSignatureInfo* DSinfo = new DigitalSignatureInfo;
			_tcscpy_s(DSinfo->SignerSubjectName, 256, _T("null"));
			bool DSret = GetDigitalSignature(m_Info.ProcessPath, DSinfo);
			if (DSret)
			{
				swprintf_s(m_Info.SignerSubjectName, 256, _T("%s"), DSinfo->SignerSubjectName);
			}
			else
			{
				lstrcpy(m_Info.SignerSubjectName, _T("null"));
			}
			delete DSinfo;
		}
		else {
			lstrcpy(m_Info.SignerSubjectName, _T("null"));
		}

		set<DWORD> ApiStringHash;
		DumpExecute(pInfo->pid, pInfo->process_name, pApiName, &ApiStringHash, m_Info.ProcessPath, &m_Info.Abnormal_dll);
		m_Info.InjectionOther = FALSE;
		m_Info.InjectionPE = FALSE;
		CheckInjectionPtn(&ApiStringHash, m_Info.InjectionOther, m_Info.InjectionPE);
		ApiStringHash.clear();
		vector<TCPInformation>::iterator Tcpit;
		for (Tcpit = NetInfo.begin(); Tcpit != NetInfo.end(); Tcpit++)
		{
			if ((*Tcpit).ProcessID == pInfo->pid)
			{
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
		//pInfo->insert(pair<DWORD,ProcessInfoData>(pid.pid,m_Info));
		if (pRiskArray->size() >= 50000)
		{
			pRiskArray->erase(pRiskArray->begin());
			pRiskArray->push_back(m_Info);
		}
		else
			pRiskArray->push_back(m_Info);
		//pRiskArray->push_back(m_Info);
		delete m_AutoRun;
		m_StartRun.clear();
		m_ServiceRun.clear();
		NetInfo.clear();
	}
	//delete [] m_ProcessPath;
	delete[] m_ProcessTime;
	delete[] m_ProcessCTime;
}
void MemProcess::CheckInjectionPtn(set<DWORD>* pStringsHash, BOOL& pIsOther, BOOL& pIsPE)
{
	//set<DWORD>::iterator it;
	//it = pStringsHash->find(3767103601);
	if ((pStringsHash->find(3767103601) != pStringsHash->end()) || (pStringsHash->find(3307083059) != pStringsHash->end()))
	{
		if ((pStringsHash->find(2707265234) != pStringsHash->end()) || (pStringsHash->find(2959245455) != pStringsHash->end())
			|| (pStringsHash->find(1588018759) != pStringsHash->end()))
		{
			if ((pStringsHash->find(2413463320) != pStringsHash->end()) || (pStringsHash->find(1863699581) != pStringsHash->end())
				|| (pStringsHash->find(748668459) != pStringsHash->end()) || (pStringsHash->find(1810605166) != pStringsHash->end()))
			{
				if ((pStringsHash->find(3481317475) != pStringsHash->end()) || (pStringsHash->find(2845710125) != pStringsHash->end()))
					pIsOther = TRUE;
			}
		}
	}

	if ((pStringsHash->find(1789965451) != pStringsHash->end()) || (pStringsHash->find(1383550409) != pStringsHash->end()))
	{
		if ((pStringsHash->find(2923117684) != pStringsHash->end()) || (pStringsHash->find(2922200202) != pStringsHash->end())
			|| (pStringsHash->find(2141139445) != pStringsHash->end()) || (pStringsHash->find(2999148978) != pStringsHash->end()))
		{
			if ((pStringsHash->find(1791678813) != pStringsHash->end()) || (pStringsHash->find(73416223) != pStringsHash->end()))
			{
				if ((pStringsHash->find(963218793) != pStringsHash->end()) || (pStringsHash->find(2806968875) != pStringsHash->end()))
				{
					if ((pStringsHash->find(1588018759) != pStringsHash->end()) || (pStringsHash->find(2707265234) != pStringsHash->end())
						|| (pStringsHash->find(2959245455) != pStringsHash->end()))
					{
						if ((pStringsHash->find(2845710125) != pStringsHash->end()) || (pStringsHash->find(3481317475) != pStringsHash->end()))
						{
							pIsPE = TRUE;
						}
					}
				}
			}
		}
	}

}
DWORD MemProcess::GetInfoPid(const wchar_t* wtr)
{
	DWORD pid = 0;
	wchar_t* TempStr = new wchar_t[512];
	wcscpy_s(TempStr, 512, wtr);
	for (int i = 0; i < (int)wcslen(wtr); i++)
	{
		if (TempStr[i] == '|')
		{
			TempStr[i] = '\0';
			pid = (DWORD)_wtoi(TempStr);
			break;
		}
	}
	delete[] TempStr;
	return pid;
}
void MemProcess::LoadSystemPID(map<DWORD, wstring>* pSystemPID)
{
	map<DWORD, process_info_Ex> process_list;
	LoadNowProcessInfo(&process_list);
	map<DWORD, process_info_Ex>::iterator pt;
	for (pt = process_list.begin(); pt != process_list.end(); pt++)
	{
		if (IsWindowsProcessNormal(&process_list, pt->first))
		{
			if (!_wcsicmp(pt->second.process_name, L"svchost.exe"))
				pSystemPID->insert(pair<DWORD, wstring>(pt->first, pt->second.process_Com));
			else
				pSystemPID->insert(pair<DWORD, wstring>(pt->first, pt->second.process_Path));
			//delete [] m_Path;
		}
	}
	process_list.clear();
}
void MemProcess::InjectionNewProcess(ThreadInfo* pInfo)
{
	TCHAR* MyPath = new TCHAR[MAX_PATH_EX];
	GetModuleFileName(GetModuleHandle(NULL), MyPath, MAX_PATH_EX);
	DWORD MyPid = GetCurrentProcessId();
	//DWORD UserModePid = 0;
	map<DWORD, wstring> SystemPID;
	LoadSystemPID(&SystemPID);
	map<DWORD, DWORD> StartProcessID;
	map<DWORD, DWORD> NewProcessID;
	map<DWORD, DWORD>::iterator st;
	map<DWORD, DWORD>::iterator nt;
	map<DWORD, wstring>::iterator ft;
	bool IsWin10 = false;
	char* OSstr = GetOSVersion();
	if ((strstr(OSstr, "Windows 10") != 0) || (strstr(OSstr, "Windows Server 2016") != 0))
		IsWin10 = true;
	//StartUserModeCommandProcess(UserModePid);
	//DWORD UserModePid = GetUserModeProcessID();
	LoadingProcessOnlyID(&StartProcessID);
	for (st = StartProcessID.begin(); st != StartProcessID.end(); st++)
	{
		if ((*pInfo->isEnding))
			break;
		ft = SystemPID.find(st->first);
		if (ft == SystemPID.end())
		{
			TCHAR* m_Path = new TCHAR[MAX_PATH_EX];
			GetProcessOnlyPath(st->first, m_Path);
			if (_tcsicmp(MyPath, m_Path) && st->second != MyPid && st->second != pInfo->MainPid)
			{
				if (!WindowsMainProcess(&SystemPID, st->second))
				{
					//char* cURL = new char[64];
					//sprintf_s(cURL,64,"System %lu\n",st->first);
					//WriteLogFile(_T("C:\\Users\\Scan\\Desktop\\789.txt"),cURL);
					//delete [] cURL;
					InjectionProcess(st->first, m_Path);
				}
			}
			delete[] m_Path;
		}
	}
	for (;;)
	{
		if ((*pInfo->isEnding))
			break;
		//SystemPID.clear();
		//LoadSystemPID(&SystemPID);
		NewProcessID.clear();
		LoadingProcessOnlyID(&NewProcessID);
		for (nt = NewProcessID.begin(); nt != NewProcessID.end(); nt++)
		{
			st = StartProcessID.find(nt->first);
			if (st == StartProcessID.end())
			{
				ft = SystemPID.find(nt->first);
				if (ft == SystemPID.end())
				{
					TCHAR* m_Path = new TCHAR[MAX_PATH_EX];
					GetProcessOnlyPath(nt->first, m_Path);
					if (_tcsicmp(MyPath, m_Path) && nt->second != MyPid && nt->second != pInfo->MainPid)
					{
						if (!WindowsMainProcess(&SystemPID, nt->second))
						{
							//char* cURL = new char[64];
							//sprintf_s(cURL,64,"System %lu\n",st->first);
							//WriteLogFile(_T("C:\\Users\\Scan\\Desktop\\789.txt"),cURL);
							//delete [] cURL;
							InjectionProcess(nt->first, m_Path);
						}
					}
					delete[] m_Path;
				}
			}
		}
		StartProcessID.clear();
		StartProcessID = NewProcessID;
		//Sleep(100);
		if (IsWin10)
		{
			Sleep(200);
		}
		else
		{
			Sleep(100);
		}
	}
	NewProcessID.clear();
	StartProcessID.clear();
	SystemPID.clear();
	delete[] MyPath;
}
void MemProcess::LoadingProcessOnlyID(map<DWORD, DWORD>* pPID)
{
	BOOL ContinueLoop;
	PROCESSENTRY32 pe32;
	HANDLE SnapshotHandle;
	SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	pe32.dwSize = sizeof(pe32);
	ContinueLoop = Process32First(SnapshotHandle, &pe32);
	while (ContinueLoop)
	{
		//pPID->insert(pe32.th32ProcessID);
		pPID->insert(pair<DWORD, DWORD>(pe32.th32ProcessID, pe32.th32ParentProcessID));
		ContinueLoop = Process32Next(SnapshotHandle, &pe32);
	}
	CloseHandle(SnapshotHandle);
}
void MemProcess::GetProcessOnlyPath(DWORD pid, TCHAR* pPath)
{
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	TCHAR* filename = new TCHAR[MAX_PATH_EX];
	TCHAR* Longfilename = new TCHAR[MAX_PATH_EX];
	TCHAR* m_FilePath = new TCHAR[MAX_PATH_EX];
	if (processHandle != NULL)
	{
		//if (EnumProcessModules(processHandle, &hModuleHandle, sizeof(hModuleHandle), &dwNeeded) == TRUE)
		//{
		if (GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH_EX))
		{
			if (GetLongPathName(filename, Longfilename, MAX_PATH_EX))
			{
				lstrcpy(m_FilePath, Longfilename);
			}
			else
			{
				lstrcpy(m_FilePath, filename);
			}
			for (size_t i = 0; i < wcslen(m_FilePath); i++)
			{
				if (m_FilePath[i] == ':')
				{
					if ((i - 1) != 0)
						lstrcpy(pPath, m_FilePath + (i - 1));
					else
						lstrcpy(pPath, m_FilePath);
					break;
				}
			}
		}
	}
	CloseHandle(processHandle);

	delete[] m_FilePath;
	delete[] Longfilename;
	delete[] filename;
}
void MemProcess::GetProcessOnlyTime(DWORD pid, time_t& pTime)
{
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (processHandle != NULL)
	{
		FILETIME l1, l2, l3, l4;
		if (GetProcessTimes(processHandle, &l1, &l2, &l3, &l4))
		{
			pTime = filetime_to_timet(l1);
		}
		CloseHandle(processHandle);
	}
}
void MemProcess::GetProcessOnlyPathAndTime(DWORD pid, TCHAR* pPath, time_t& pTime)
{
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	TCHAR* filename = new TCHAR[MAX_PATH_EX];
	TCHAR* Longfilename = new TCHAR[MAX_PATH_EX];
	TCHAR* m_FilePath = new TCHAR[MAX_PATH_EX];
	if (processHandle != NULL)
	{
		if (GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH_EX))
		{
			if (GetLongPathName(filename, Longfilename, MAX_PATH_EX))
			{
				lstrcpy(m_FilePath, Longfilename);
			}
			else
			{
				lstrcpy(m_FilePath, filename);
			}
			for (size_t i = 0; i < wcslen(m_FilePath); i++)
			{
				if (m_FilePath[i] == ':')
				{
					if ((i - 1) != 0)
						lstrcpy(pPath, m_FilePath + (i - 1));
					else
						lstrcpy(pPath, m_FilePath);
					break;
				}
			}
		}
		FILETIME l1, l2, l3, l4;
		if (GetProcessTimes(processHandle, &l1, &l2, &l3, &l4))
		{
			pTime = filetime_to_timet(l1);
		}
	}
	CloseHandle(processHandle);

	delete[] m_FilePath;
	delete[] Longfilename;
	delete[] filename;
}
void MemProcess::InjectionProcess(DWORD pid, TCHAR* pPath)
{
	DWORD isSys = 32;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if (!hProc)
	{
		return;
	}
#ifndef _M_IX86
	isSys = Process32or64(hProc);
	if (!isSys)
	{
		CloseHandle(hProc);
		return;
	}
#endif	
	CloseHandle(hProc);
	//if(!IsHavePID(UserModePid))
	//	StartUserModeCommandProcess(UserModePid);
	TCHAR* RunExeStr = new TCHAR[MAX_PATH_EX];
	TCHAR* RunComStr = new TCHAR[512];
	if (isSys == 64)
	{
		GetlocalExePath(_T("CliectSearchTools_x64.exe"), RunExeStr);
		swprintf_s(RunComStr, 512, L"CliectSearchTools_x64.exe %lu", pid);
	}
	else
	{
		GetlocalExePath(_T("CliectSearchTools_x86.exe"), RunExeStr);
		swprintf_s(RunComStr, 512, L"CliectSearchTools_x86.exe %lu", pid);
	}
	if (_tcsicmp(RunExeStr, pPath))
	{
		if (!_waccess(RunExeStr, 00))
		{
			RunProcess(RunExeStr, RunComStr, TRUE, FALSE);
		}
	}
	delete[] RunComStr;
	delete[] RunExeStr;
	//delete [] pSIDstr;
	//delete [] m_UserName;
}
bool MemProcess::WindowsMainProcess(map<DWORD, wstring>* pSystemPID, DWORD pParentId)
{
	bool ret = false;
	map<DWORD, wstring>::iterator it;
	it = pSystemPID->find(pParentId);
	if (it != pSystemPID->end())
	{
		if (_wcsicmp(it->second.c_str(), L"C:\\Windows\\System32\\services.exe") &&
			_wcsicmp(it->second.c_str(), L"C:\\Windows\\explorer.exe") &&
			_wcsicmp(it->second.c_str(), L"C:\\Windows\\System32\\taskeng.exe") &&
			_wcsicmp(it->second.c_str(), L"c:\\windows\\system32\\svchost.exe -k netsvcs -p -s Schedule"))
		{
			ret = true;
		}
	}
	return ret;
}
void MemProcess::SearchExecutePath(DWORD pid, TCHAR* pPath, TCHAR* pName)
{
	HMODULE hResult = NULL;
	HANDLE hSnapshot;
	MODULEENTRY32 me32;
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		me32.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnapshot, &me32))
		{
			do
			{
				if (!_tcsicmp(me32.szModule, pName))
				{
					_tcscpy_s(pPath, MAX_PATH_EX, me32.szExePath);
					break;
				}
			} while (Module32Next(hSnapshot, &me32));
		}
		CloseHandle(hSnapshot);
	}
}
bool MemProcess::EnumProcess(map<DWORD, process_info>* pInfo, time_t& LoadProcessTime)
{
	NTSTATUS status;
	PVOID buffer;
	PSYSTEM_PROCESS_INFO spi;

	buffer = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // We need to allocate a large buffer because the process list can be large.

	if (!buffer)
	{
		//printf("\nError: Unable to allocate memory for process list (%d)\n",GetLastError());
		return false;
	}

	// printf("\nProcess list allocated at address %#x\n",buffer);
	spi = (PSYSTEM_PROCESS_INFO)buffer;
#if defined _M_X64
	if (!NT_SUCCESS(status = NtQuerySystemInformation(SystemProcessInformation, spi, 1024 * 1024, NULL)))
	{
		//printf("\nError: Unable to query process list (%#x)\n",status);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return false;
	}
#elif defined _M_IX86
	pZwQuerySystemInformation ZwQuerySystemInformation = (pZwQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwQuerySystemInformation");
	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemProcessInformation, spi, 1024 * 1024, NULL)))
	{
		//printf("\nError: Unable to query process list (%#x)\n",status);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return false;
	}
#endif
	time(&LoadProcessTime);
	while (spi->NextEntryOffset) // Loop over the list until we reach the last entry.
	{
		if ((int)spi->ProcessId > 0)
		{
			process_info  m_Info = { 0 };
			m_Info.pid = (int)spi->ProcessId;
			m_Info.parent_pid = (int)spi->InheritedFromProcessId;
			//wcscpy_s(m_Info.process_name,MAX_PATH,spi->ImageName.Buffer);
			swprintf_s(m_Info.process_name, MAX_PATH, L"%s", spi->ImageName.Buffer);
			m_Info.ProcessCreateTime = spi->CreateTime.QuadPart / 10000000ULL - 11644473600ULL;
			if (m_Info.ProcessCreateTime < 0)
				m_Info.ProcessCreateTime = 0;
			m_Info.IsHide = FALSE;
			pInfo->insert(pair<DWORD, process_info>((DWORD)m_Info.pid, m_Info));
			//SYSTEMTIME sys = TimetToSystemTimeEx((time_t)m_Ctime);
		}
		else if ((int)spi->ProcessId == 0)
		{
			process_info  m_Info = { 0 };
			m_Info.pid = (int)spi->ProcessId;
			m_Info.parent_pid = -1;
			//wcscpy_s(m_Info.process_name,MAX_PATH,spi->ImageName.Buffer);
			swprintf_s(m_Info.process_name, MAX_PATH, L"[System Process]");
			m_Info.ProcessCreateTime = 0;
			m_Info.IsHide = FALSE;
			pInfo->insert(pair<DWORD, process_info>((DWORD)m_Info.pid, m_Info));
		}
		spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset); // Calculate the address of the next entry.
	}

	//printf("\nPress any key to continue.\n");
	//getchar();
	VirtualFree(buffer, 0, MEM_RELEASE); // Free the allocated buffer.
	return true;
}
bool MemProcess::EnumProcessEx(map<DWORD, process_info_Ex>* pInfo/*,time_t & LoadProcessTime*/)
{
	NTSTATUS status;
	PVOID buffer;
	PSYSTEM_PROCESS_INFO spi;

	buffer = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // We need to allocate a large buffer because the process list can be large.

	if (!buffer)
	{
		//printf("\nError: Unable to allocate memory for process list (%d)\n",GetLastError());
		return false;
	}

	// printf("\nProcess list allocated at address %#x\n",buffer);
	spi = (PSYSTEM_PROCESS_INFO)buffer;
#if defined _M_X64
	if (!NT_SUCCESS(status = NtQuerySystemInformation(SystemProcessInformation, spi, 1024 * 1024, NULL)))
	{
		//printf("\nError: Unable to query process list (%#x)\n",status);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return false;
	}
#elif defined _M_IX86
	pZwQuerySystemInformation ZwQuerySystemInformation = (pZwQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwQuerySystemInformation");
	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemProcessInformation, spi, 1024 * 1024, NULL)))
	{
		//printf("\nError: Unable to query process list (%#x)\n",status);

		VirtualFree(buffer, 0, MEM_RELEASE);
		return false;
	}
#endif
	//time (&LoadProcessTime);
	while (spi->NextEntryOffset) // Loop over the list until we reach the last entry.
	{
		if ((int)spi->ProcessId > 0)
		{
			process_info_Ex  m_Info = { 0 };
			m_Info.pid = (int)spi->ProcessId;
			m_Info.parent_pid = (int)spi->InheritedFromProcessId;
			//wcscpy_s(m_Info.process_name,MAX_PATH,spi->ImageName.Buffer);
			swprintf_s(m_Info.process_name, MAX_PATH, L"%s", spi->ImageName.Buffer);
			m_Info.ProcessCreateTime = spi->CreateTime.QuadPart / 10000000ULL - 11644473600ULL;
			if (m_Info.ProcessCreateTime < 0)
				m_Info.ProcessCreateTime = 0;
			m_Info.IsHide = FALSE;
			pInfo->insert(pair<DWORD, process_info_Ex>((DWORD)m_Info.pid, m_Info));
			//SYSTEMTIME sys = TimetToSystemTimeEx((time_t)m_Ctime);
		}
		else if ((int)spi->ProcessId == 0)
		{
			process_info_Ex  m_Info = { 0 };
			m_Info.pid = (int)spi->ProcessId;
			m_Info.parent_pid = -1;
			//wcscpy_s(m_Info.process_name,MAX_PATH,spi->ImageName.Buffer);
			swprintf_s(m_Info.process_name, MAX_PATH, L"[System Process]");
			m_Info.ProcessCreateTime = 0;
			m_Info.IsHide = FALSE;
			pInfo->insert(pair<DWORD, process_info_Ex>((DWORD)m_Info.pid, m_Info));
		}
		spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset); // Calculate the address of the next entry.
	}

	//printf("\nPress any key to continue.\n");
	//getchar();
	VirtualFree(buffer, 0, MEM_RELEASE); // Free the allocated buffer.
	return true;
}
#if defined _M_IX86
bool MemProcess::EnumRing0Process(map<DWORD, process_info>* pInfo, time_t& LoadProcessTime)
{
	bool ret = false;
	pZwQuerySystemInformation ZwQuerySystemInformation = NULL;
	ZwQuerySystemInformation = (pZwQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwQuerySystemInformation");
	if (ZwQuerySystemInformation)
	{
		DWORD m_Index = GetServiceNumber(ZwQuerySystemInformation);
		DWORD addr = 0;
		SystemModules* m_SysModules = new SystemModules;
		if (m_SysModules->GetOriginalssdt(addr, m_Index))
		{
			BYTE* InBuf = new BYTE[5];
			((DWORD*)InBuf)[0] = addr;
			ret = LoadRing0Process(pInfo, InBuf, 4, LoadProcessTime);
			delete[] InBuf;
		}
		delete m_SysModules;
	}
	return ret;
}
bool MemProcess::EnumRing0ProcessEx(map<DWORD, process_info_Ex>* pInfo)
{
	bool ret = false;
	pZwQuerySystemInformation ZwQuerySystemInformation = NULL;
	ZwQuerySystemInformation = (pZwQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwQuerySystemInformation");
	if (ZwQuerySystemInformation)
	{
		DWORD m_Index = GetServiceNumber(ZwQuerySystemInformation);
		DWORD addr = 0;
		SystemModules* m_SysModules = new SystemModules;
		if (m_SysModules->GetOriginalssdt(addr, m_Index))
		{
			BYTE* InBuf = new BYTE[5];
			((DWORD*)InBuf)[0] = addr;
			ret = LoadRing0ProcessEx(pInfo, InBuf, 4);
			delete[] InBuf;
		}
		delete m_SysModules;
	}
	return ret;
}
bool MemProcess::LoadRing0Process(map<DWORD, process_info>* pInfo, BYTE* pInBuf, DWORD pInBuflen, time_t& LoadProcessTime)
{
	HANDLE hDevice =
		CreateFile(_T("\\\\.\\EnumProcess"),
			GENERIC_READ | GENERIC_WRITE,
			0,		// share mode none
			NULL,	// no security
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);		// no template

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		//char * Estr = new char[64];
		//sprintf_s(Estr,64,"%d\n",(int)GetLastError());
		//WriteLogFile(_T("C:\\Users\\Win7_x86\\Desktop\\789.txt"),Estr);
		//delete [] Estr;
		return false;
	}
	bool ret = false;
	UCHAR OutputBuffer[5];
	//將輸入緩衝區全部置成0XBB
	//memset(InputBuffer,0xBB,10);
	DWORD dwOutput;
	//輸入緩衝區作為輸入，輸出緩衝區作為輸出
	BOOL bRet;
	bRet = DeviceIoControl(hDevice, IOCTL_RESTORE_SERVICE_TABLE, pInBuf, pInBuflen, &OutputBuffer, 4, &dwOutput, NULL);
	if (bRet)
	{
		if (EnumProcess(pInfo, LoadProcessTime))
			ret = true;
		bRet = DeviceIoControl(hDevice, IOCTL_RESTORE_SERVICE_TABLE, &OutputBuffer, 4, NULL, 0, &dwOutput, NULL);
	}
	CloseHandle(hDevice);
	return ret;
}
bool MemProcess::LoadRing0ProcessEx(map<DWORD, process_info_Ex>* pInfo, BYTE* pInBuf, DWORD pInBuflen)
{
	HANDLE hDevice =
		CreateFile(_T("\\\\.\\EnumProcess"),
			GENERIC_READ | GENERIC_WRITE,
			0,		// share mode none
			NULL,	// no security
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);		// no template

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	bool ret = false;
	UCHAR OutputBuffer[5];
	//將輸入緩衝區全部置成0XBB
	//memset(InputBuffer,0xBB,10);
	DWORD dwOutput;
	//輸入緩衝區作為輸入，輸出緩衝區作為輸出
	BOOL bRet;
	bRet = DeviceIoControl(hDevice, IOCTL_RESTORE_SERVICE_TABLE, pInBuf, pInBuflen, &OutputBuffer, 4, &dwOutput, NULL);
	if (bRet)
	{
		if (EnumProcessEx(pInfo))
			ret = true;
		bRet = DeviceIoControl(hDevice, IOCTL_RESTORE_SERVICE_TABLE, &OutputBuffer, 4, NULL, 0, &dwOutput, NULL);
	}
	CloseHandle(hDevice);
	return ret;
}
bool MemProcess::ParserRing0EnumProcessStr(wchar_t* wtr, map<DWORD, process_info>* pInfo)
{
	bool ret = false;
	wchar_t* pwc;
	wchar_t* next_token = NULL;
	int i = 0;
	pwc = wcstok_s(wtr, L"\n", &next_token);
	while (pwc != NULL)
	{
		wchar_t* wtr1 = new wchar_t[4096];
		wcscpy_s(wtr1, 4096, pwc);
		process_info m_Info = { 0 };
		ParserRing0EnumProcessData(wtr1, &m_Info);
		m_Info.IsHide = FALSE;
		pInfo->insert(pair<DWORD, process_info>((DWORD)m_Info.pid, m_Info));
		delete[] wtr1;
		i++;
		pwc = wcstok_s(NULL, L"\n", &next_token);
	}
	if (i > 5)
		ret = true;
	return ret;
}
void MemProcess::ParserRing0EnumProcessData(wchar_t* wtr, process_info* pInfo)
{
	wchar_t* pwc;
	wchar_t* next_token = NULL;
	int i = 0;
	pwc = wcstok_s(wtr, L"|", &next_token);
	while (pwc != NULL)
	{
		if (i == 0)
			pInfo->pid = _wtoi(pwc);
		else if (i == 1)
			pInfo->parent_pid = _wtoi(pwc);
		else if (i == 2)
			wcscpy_s(pInfo->process_name, MAX_PATH, pwc);
		else if (i == 3)
		{
			pInfo->ProcessCreateTime = _wtoi64(pwc);
			break;
		}
		i++;
		pwc = wcstok_s(NULL, L"|", &next_token);
	}
}
void MemProcess::CheckProcessHide(map<DWORD, process_info>* pInfo, map<DWORD, process_info>* pCInfo, time_t LoadProcessTime)
{
	map<DWORD, process_info>::iterator it;
	map<DWORD, process_info>::iterator st;
	for (it = pInfo->begin(); it != pInfo->end(); it++)
	{
		st = pCInfo->find(it->first);
		if (st == pCInfo->end())
		{
			if (it->second.ProcessCreateTime < LoadProcessTime)
			{
				it->second.IsHide = TRUE;
			}
		}
	}
}
void MemProcess::CheckProcessHideEx(map<DWORD, process_info_Ex>* pInfo, map<DWORD, process_info_Ex>* pCInfo, time_t LoadProcessTime)
{
	map<DWORD, process_info_Ex>::iterator it;
	map<DWORD, process_info_Ex>::iterator st;
	for (it = pInfo->begin(); it != pInfo->end(); it++)
	{
		st = pCInfo->find(it->first);
		if (st == pCInfo->end())
		{
			if (it->second.ProcessCreateTime < LoadProcessTime)
			{
				it->second.IsHide = TRUE;
			}
		}
	}
}
#endif
void MemProcess::ChangeProcessHistoryNum(int pNum)
{
	if (pNum == 1)
	{
		pProcessHistory = &m_ProcessHistory2;
		ProcessHistoryNum = 2;
	}
	else if (pNum == 2)
	{
		pProcessHistory = &m_ProcessHistory1;
		ProcessHistoryNum = 1;
	}
}
void MemProcess::ChangeProcessHistoryInfoNum(int pNum)
{
	if (pNum == 1)
	{
		pProcessHistoryInfo = &m_ProcessHistoryInfo2;
		ProcessHistoryInfoNum = 2;
	}
	else if (pNum == 2)
	{
		pProcessHistoryInfo = &m_ProcessHistoryInfo1;
		ProcessHistoryInfoNum = 1;
	}
}
void MemProcess::ChangeNetworkHistoryNum(int pNum)
{
	if (pNum == 1)
	{
		pNetworkHistory = &m_NetworkHistory2;
		NetworkHistoryNum = 2;
	}
	else if (pNum == 2)
	{
		pNetworkHistory = &m_NetworkHistory1;
		NetworkHistoryNum = 1;
	}
}
void MemProcess::ChangeAccessFilesHistoryNum(int pNum)
{
	if (pNum == 1)
	{
		pAccessFilesHistory = &m_AccessFilesHistory2;
		AccessFilesHistoryNum = 2;
	}
	else if (pNum == 2)
	{
		pAccessFilesHistory = &m_AccessFilesHistory1;
		AccessFilesHistoryNum = 1;
	}
}
void MemProcess::ChangeRiskArrayNum(int pNum)
{
	if (pNum == 1)
	{
		pRiskArray = &m_RiskArray2;
		RiskArrayNum = 2;
	}
	else if (pNum == 2)
	{
		pRiskArray = &m_RiskArray1;
		RiskArrayNum = 1;
	}
}
void MemProcess::ChangeUnKnownDataNum(int pNum)
{
	if (pNum == 1)
	{
		pUnKnownData = &m_UnKnownData2;
		UnKnownDataNum = 2;
	}
	else if (pNum == 2)
	{
		pUnKnownData = &m_UnKnownData1;
		UnKnownDataNum = 1;
	}
}
vector<string>* MemProcess::GetProcessHistory1()
{
	return &m_ProcessHistory1;
}
vector<string>* MemProcess::GetProcessHistory2()
{
	return &m_ProcessHistory2;
}
vector<string>* MemProcess::GetProcessHistoryInfo1()
{
	return &m_ProcessHistoryInfo1;
}
vector<string>* MemProcess::GetProcessHistoryInfo2()
{
	return &m_ProcessHistoryInfo2;
}
vector<string>* MemProcess::GetNetworkHistory1()
{
	return &m_NetworkHistory1;
}
vector<string>* MemProcess::GetNetworkHistory2()
{
	return &m_NetworkHistory2;
}
set<string>* MemProcess::GetAccessFilesHistory1()
{
	return &m_AccessFilesHistory1;
}
set<string>* MemProcess::GetAccessFilesHistory2()
{
	return &m_AccessFilesHistory2;
}
vector<ProcessInfoData>* MemProcess::GetRiskArray1()
{
	return &m_RiskArray1;
}
vector<ProcessInfoData>* MemProcess::GetRiskArray2()
{
	return &m_RiskArray2;
}
vector<UnKnownDataInfo>* MemProcess::GetUnKnownData1()
{
	return &m_UnKnownData1;
}
vector<UnKnownDataInfo>* MemProcess::GetUnKnownData2()
{
	return &m_UnKnownData2;
}