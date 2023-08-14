#include "tools.h"
#include <VersionHelpers.h>
//#include <Windows.h>


std::vector<std::string> Tool::SplitMsg(char* msg) {
    std::vector<std::string> MsgAfterSplit;
    char* nextToken = nullptr;
    const char* delimiter = "|";

    // First call to strtok_s
    char* token = strtok_s(msg, delimiter, &nextToken);
    while (token != nullptr) {
        MsgAfterSplit.push_back(token);
        // Subsequent calls to strtok_s using the same context (nextToken)
        token = strtok_s(nullptr, delimiter, &nextToken);
    }
    return MsgAfterSplit;
}

time_t Tool::FileTimeToUnixTime(const FILETIME& ft) {
    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;
    return static_cast<time_t>((ull.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

char* Tool::StringToCharPointer(std::string msg) {
    char* CharPtrMsg = new char[msg.size() + 1];
    strcpy_s(CharPtrMsg, sizeof(CharPtrMsg), msg.c_str());
    return CharPtrMsg;

}

void Tool::DeleteAllCsvFiles(wchar_t* directoryPath) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile((std::wstring(directoryPath) + L"\\*.csv").c_str(), &findFileData);

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring filePath = std::wstring(directoryPath) + L"\\" + findFileData.cFileName;
            if (DeleteFile(filePath.c_str())) {
                std::wcout << L"Deleted: " << filePath << std::endl;
            }
            else {
                std::wcerr << L"Failed to delete: " << filePath << ", Error code: " << GetLastError() << std::endl;
            }
        } while (FindNextFile(hFind, &findFileData) != 0);

        FindClose(hFind);
    }
    else {
        std::wcerr << L"No CSV files found in the directory: " << directoryPath << std::endl;
    }
}

bool Tool::CompressFileToZip(const TCHAR* zipFileName, const TCHAR* fileToAdd, const TCHAR* sourceFilePath) {
    HZIP hz = CreateZip(zipFileName, 0);
    if (hz == 0) {
        return false; // Failed to create ZIP file
    }

    if (ZipAdd(hz, fileToAdd, sourceFilePath) != 0) {
        CloseZip(hz);
        return false; // Failed to add file to ZIP
    }

    CloseZip(hz);
    return true; // Successfully compressed and added file to ZIP
}


// char* Tool::CStringToCharArray(wchar_t* str,UINT m_CodePage) {
// 	char *ptr;
// 	#ifdef _UNICODE
// 	LONG len;
// 	len = WideCharToMultiByte(m_CodePage, 0, str, -1, NULL, 0, NULL, NULL);
// 	ptr = new char [len+1];
// 	memset(ptr,0,len + 1);
// 	WideCharToMultiByte(m_CodePage, 0, str, -1, ptr, len + 1, NULL, NULL);
// 	#else
// 	ptr = new char [str.GetAllocLength()+1];
// 	#endif
// 	return ptr;
// }

char* Tool::WideStringToUTF8(const std::wstring& wideString) {
    int utf8Length = WideCharToMultiByte(CP_UTF8, 0, wideString.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (utf8Length == 0) {
        return nullptr;
    }

    char* utf8String = new char[utf8Length];
    WideCharToMultiByte(CP_UTF8, 0, wideString.c_str(), -1, utf8String, utf8Length, nullptr, nullptr);
    return utf8String;
}

char* Tool::GetSysInfo()
{
    SYSTEM_INFO si;
    PGNSI pGNSI = (PGNSI)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetNativeSystemInfo");
    if (NULL != pGNSI) pGNSI(&si);
    else GetSystemInfo(&si);

    char* Sysinfo = new char[10];
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        strcpy_s(Sysinfo, sizeof(Sysinfo), "x64");
        return Sysinfo;
    }
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        strcpy_s(Sysinfo, sizeof(Sysinfo), "x86");
        return Sysinfo;
    }
    else {
        strcpy_s(Sysinfo, sizeof(Sysinfo), "Unknown");
        return Sysinfo;
    }
}

char* Tool::GetComputerNameUTF8() {
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD computerNameLength = sizeof(computerName) / sizeof(wchar_t);

    if (GetComputerNameW(computerName, &computerNameLength)) {
        return WideStringToUTF8(computerName);
    }

    return nullptr;
}

char* Tool::GetUserNameUTF8() {
    wchar_t userName[UNLEN + 1];
    DWORD userNameLength = sizeof(userName) / sizeof(wchar_t);

    if (GetUserNameW(userName, &userNameLength)) {
        return WideStringToUTF8(userName);
    }

    return nullptr;
}

char* Tool::GetOSVersion() {
    OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    //if (GetVersionEx(&osvi)) {
    //if(VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION, conditionMask)){

    if (IsWindows10OrGreater()) {
        char* versionStr = new char[128];
        sprintf_s(versionStr, 128, "%d.%d.%d", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
        return versionStr;
    }
    else {
        return nullptr;
    }
        
    //}
    //else {
    //    return nullptr;
    //}

}

unsigned long long Tool::GetBootTime() {
    return static_cast<unsigned long long>(GetTickCount64() / 1000);
}

// here


//
void Tool::LoadApiPattern(std::set<DWORD>* pApiName) {
    pApiName->insert(2923117684);//CreateProcessA
    pApiName->insert(2922200202);//CreateProcessW
    pApiName->insert(2413463320);//CreateRemoteThread
    pApiName->insert(1791678813);//GetThreadContext
    pApiName->insert(1588018759);//NtAllocateVirtualMemory
    pApiName->insert(2141139445);//NtCreateProcess
    pApiName->insert(2999148978);//NtCreateProcessEx
    pApiName->insert(1810605166);//NtCreateThread
    pApiName->insert(748668459);//NtCreateThreadEx
    pApiName->insert(73416223);//NtGetContextThread
    pApiName->insert(3307083059);//NtOpenProcess
    pApiName->insert(1789965451);//NtResumeThread
    pApiName->insert(2806968875);//NtSetContextThread
    pApiName->insert(2845710125);//NtWriteVirtualMemory
    pApiName->insert(3767103601);//OpenProcess
    pApiName->insert(1383550409);//ResumeThread
    pApiName->insert(1863699581);//RtlCreateUserThread
    pApiName->insert(963218793);//SetThreadContext
    pApiName->insert(2707265234);//VirtualAlloc
    pApiName->insert(2959245455);//VirtualAllocEx
    pApiName->insert(3481317475);//WriteProcessMemory
}
//
//void Tool::ScanRunNowProcess(void* argv, std::map<DWORD, ProcessInfoData>* pInfo, std::set<DWORD>* pApiName, std::vector<UnKnownDataInfo>* pMembuf) {
//    // TransportData * m_Client = (TransportData *)argv;
//    std::map<DWORD, process_info_Ex> process_list;
//    LoadNowProcessInfo(&process_list);
//
//    // clock_t start,end;
//    // start = clock();
//
//    std::vector<TCPInformation> NetInfo;
//    GetTcpInformationEx(&NetInfo);
//    // char * OSstr = GetOSVersion();
//    // if((strstr(OSstr,"Windows XP") != 0)||(strstr(OSstr,"Windows Server 2003") != 0))
//    // {
//    // 	GetTcpInformationXPEx(&NetInfo);
//    // }
//    // else if(strstr(OSstr,"Windows 2000") != 0){}
//    // else
//    // {
//    // 	GetTcpInformationEx(&NetInfo);
//    // }
//    // delete [] OSstr;
//
//
//    time_t NetworkClock;
//    time(&NetworkClock);
//    // int ret = m_Client->SendDataMsgToServer(m_Client->MyMAC,m_Client->MyIP,"GiveScanProgress","10");
//
//    std::map<std::wstring, BOOL> m_ServiceRun;
//    std::set<std::wstring> m_StartRun;
//    LoadServiceStartCommand(&m_ServiceRun);
//    LoadAutoRunStartCommand(&m_StartRun);
//    //MessageBox(0,L"168",0,0);
//    // if(ret > 0)
//    // {
//
//    int InfoSize = (int)process_list.size();
//    int InfoCount = 0;
//    std::map<DWORD, process_info_Ex>::iterator pt;
//    for (pt = process_list.begin(); pt != process_list.end(); pt++, InfoCount++) {
//        if (!IsWindowsProcessNormal(&process_list, pt->first)) {
//            ProcessInfoData m_Info;
//            m_Info.HideAttribute = FALSE;
//            m_Info.HideProcess = pt->second.IsHide;
//            // lstrcpy(m_Info.ProcessName,pt->second.process_name);
//            // _tcscpy_s(m_Info.ProcessPath,MAX_PATH_EX,pt->second.process_Path);
//
//            wcscpy(m_Info.ProcessName, pt->second.process_name);
//            wcscpy(m_Info.ProcessPath, pt->second.process_Path);
//            wcscpy(m_Info.ProcessTime, L"null");
//            wcscpy(m_Info.ProcessCTime, L"null");
//            wcscpy(m_Info.ParentCTime, L"null");
//            // _tcscpy(m_Info.ProcessName, pt->second.process_name);
//            // _tcscpy_s(m_Info.ProcessPath, MAX_PATH_EX, pt->second.process_Path);
//            // _tcscpy_s(m_Info.ProcessTime,20,_T("null"));
//            // _tcscpy_s(m_Info.ProcessCTime,20,_T("null"));
//            // _tcscpy_s(m_Info.ParentCTime,20,_T("null"));
//
//            // if(pt->second.ProcessCreateTime > 0)
//            //     swprintf_s(m_Info.ProcessCTime,20,_T("%llu"),pt->second.ProcessCr							eateTime);
//            // 		if(pt->second.parentCreateTime > 0)
//            // swprintf_s(m_Info.ParentCTime,20,_T("%llu"),pt->second.parentCreateTime);
//
//            time_t createTime = pt->second.ProcessCreateTime;
//            std::tm timeInfo;
//            localtime_s(&timeInfo, &createTime);
//            std::wcsftime(m_Info.ProcessCTime, 20, L"%Y-%m-%d %H:%M:%S", &timeInfo);
//
//            time_t parent_createTime = pt->second.parentCreateTime;
//            std::tm parent_timeInfo;
//            localtime_s(&parent_timeInfo, &parent_createTime);
//            std::wcsftime(m_Info.ParentCTime, 20, L"%Y-%m-%d %H:%M:%S", &parent_timeInfo);
//
//            // if (!_tcscmp(m_Info.ProcessPath, L"null"))
//            if (!wcscmp(m_Info.ProcessPath, L"null"))
//            {
//                //Sleep(100);
//                //GetProcessOnlyPath(pInfo->pid,m_Info.ProcessPath);
//                SearchExecutePath(pt->first, m_Info.ProcessPath, pt->second.process_name);
//            }
//            SYSTEMTIME sys;
//            GetLocalTime(&sys);
//            // swprintf_s(m_Info.ProcessTime,20,_T("%4d/%02d/%02d %02d:%02d:%02d"),sys.wYear,sys.wMonth,sys.wDay,sys.wHour,sys.wMinute,sys.wSecond);
//            swprintf_s(m_Info.ProcessTime, 20, L"%4d/%02d/%02d %02d:%02d:%02d", sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond);
//
//            m_Info.ParentID = pt->second.parent_pid;
//            if (pt->second.parentCreateTime > 0)
//                GetProcessPath(pt->second.parent_pid, m_Info.ParentPath, true, NULL, NULL);
//            else
//                wcsncpy(m_Info.ProcessPath, L"null", MAX_PATH_EX);
//            // _tcscpy_s(m_Info.ParentPath,MAX_PATH_EX,_T("null"));
//        // _tcscpy_s(m_Info.UnKnownHash,50,_T("null"));
//            wcsncpy(m_Info.UnKnownHash, L"null", 50);
//            m_Info.Injected = CheckIsInjection(pt->first, pMembuf, m_Info.ProcessName, m_Info.UnKnownHash);
//            //m_Info.Injected = FALSE;
//            m_Info.StartRun = CheckIsStartRun(&m_ServiceRun, &m_StartRun, pt->first/*,m_Info.HideService*/);
//
//            CheckIsInlineHook(pt->first, &m_Info.InlineHookInfo);
//
//            wchar_t Md5Hashstr[50];
//            memset(Md5Hashstr, '\0', 50);
//            DWORD MD5ret = Md5Hash(m_Info.ProcessPath, Md5Hashstr);
//            if (MD5ret == 0)
//                wcscpy(m_Info.ProcessHash, Md5Hashstr);
//            // lstrcpy(m_Info.ProcessHash,Md5Hashstr);
//            else
//                wcscpy(m_Info.ProcessHash, L"null");
//            // lstrcpy(m_Info.ProcessHash,_T("null"));
//
//        // if(_tcscmp(m_Info.ProcessPath,_T("null")))
//            if (!wcscmp(m_Info.ProcessPath, L"null"))
//            {
//                DWORD AttRet = GetFileAttributes(WideCharToLPCWSTR(m_Info.ProcessPath));
//                if ((AttRet & FILE_ATTRIBUTE_HIDDEN) == FILE_ATTRIBUTE_HIDDEN)
//                    m_Info.HideAttribute = TRUE;
//                DigitalSignatureInfo* DSinfo = new DigitalSignatureInfo;
//                // _tcscpy_s(DSinfo->SignerSubjectName,256,_T("null"));
//                wcsncpy(m_Info.SignerSubjectName, L"null", 256);
//                bool DSret = GetDigitalSignature(m_Info.ProcessPath, DSinfo);
//                if (DSret)
//                {
//                    swprintf_s(m_Info.SignerSubjectName, 256, L"%s", DSinfo->SignerSubjectName);
//                }
//                else
//                {
//                    // lstrcpy(m_Info.SignerSubjectName,_T("null"));
//                    wcscpy(m_Info.SignerSubjectName, L"null");
//                }
//                delete DSinfo;
//            }
//            else
//            {
//                // lstrcpy(m_Info.SignerSubjectName,_T("null"));
//                wcscpy(m_Info.SignerSubjectName, L"null");
//            }
//            std::set<DWORD> ApiStringHash;
//            DumpExecute(pt->first, pt->second.process_name, pApiName, &ApiStringHash, m_Info.ProcessPath, &m_Info.Abnormal_dll);
//            m_Info.InjectionOther = FALSE;
//            m_Info.InjectionPE = FALSE;
//            CheckInjectionPtn(&ApiStringHash, m_Info.InjectionOther, m_Info.InjectionPE);
//            ApiStringHash.clear();
//            std::vector<TCPInformation>::iterator Tcpit;
//            for (Tcpit = NetInfo.begin(); Tcpit != NetInfo.end(); Tcpit++)
//            {
//                if ((*Tcpit).ProcessID == pt->first)
//                {
//                    WORD add1, add2, add3, add4;
//                    add1 = (WORD)((*Tcpit).LocalAddr & 255);
//                    add2 = (WORD)(((*Tcpit).LocalAddr >> 8) & 255);
//                    add3 = (WORD)(((*Tcpit).LocalAddr >> 16) & 255);
//                    add4 = (WORD)(((*Tcpit).LocalAddr >> 24) & 255);
//                    WORD add5, add6, add7, add8;
//                    add5 = (WORD)((*Tcpit).RemoteAddr & 255);
//                    add6 = (WORD)(((*Tcpit).RemoteAddr >> 8) & 255);
//                    add7 = (WORD)(((*Tcpit).RemoteAddr >> 16) & 255);
//                    add8 = (WORD)(((*Tcpit).RemoteAddr >> 24) & 255);
//                    char str[65536];
//                    sprintf_s(str, 65536, "%d.%d.%d.%d,%u,%d.%d.%d.%d,%u,%s>%lld", add1, add2, add3, add4, ntohs((u_short)(*Tcpit).LocalPort), add5, add6, add7, add8, ntohs((u_short)(*Tcpit).RemotePort), Convert2State((*Tcpit).State), NetworkClock);
//                    m_Info.NetString.insert(str);
//                }
//            }
//            pInfo->insert(std::pair<DWORD, ProcessInfoData>(pt->first, m_Info));
//        }
//        // end = clock();
//        // if((end-start) > 30000)
//        // {
//        //     double precentage = (double)40*InfoCount/InfoSize ;
//        //     int ScanProgressNum = (int)precentage;
//        //     ScanProgressNum += 10;
//        //     char *Numstr = new char[10];
//        //     sprintf_s(Numstr,10,"%d",ScanProgressNum);
//        //     ret = m_Client->SendDataMsgToServer(m_Client->MyMAC,m_Client->MyIP,"GiveScanProgress",Numstr);
//        //     delete [] Numstr;
//        //     if(ret <= 0)
//        //         break;
//        //     start = end;
//        // }
//    }
//
//    // }
//    // delete m_AutoRun;
//    m_StartRun.clear();
//    m_ServiceRun.clear();
//    NetInfo.clear();
//    process_list.clear();
//}
//
//void Tool::GetTcpInformationEx(std::vector<TCPInformation>* pInfo)
//{
//    MIB_TCPTABLE_OWNER_PID* pTCPInfo;
//    MIB_TCPROW_OWNER_PID* owner;
//    DWORD size;
//    DWORD dwResult;
//
//    HMODULE hLib = LoadLibrary(_T("iphlpapi.dll"));
//
//    pGetExtendedTcpTable = (DWORD(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG))
//        GetProcAddress(hLib, "GetExtendedTcpTable");
//
//    if (!pGetExtendedTcpTable)
//    {
//        // printf("Could not load iphlpapi.dll. This application is for Windows XP SP2 and up.\n");
//         //MessageBox(0,L"Could not load iphlpapi.dll. This application is for Windows XP SP2 and up.",0,0);
//        return;
//    }
//
//    dwResult = pGetExtendedTcpTable(NULL, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
//    pTCPInfo = (MIB_TCPTABLE_OWNER_PID*)malloc(size);
//    dwResult = pGetExtendedTcpTable(pTCPInfo, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
//
//    if (dwResult != NO_ERROR)
//    {
//        //printf("Couldn't get our IP table");
//        //MessageBox(0,L"Couldn't get our IP table",0,0);
//        return;
//    }
//
//    //printf("Iterating though table:\n");
//    for (DWORD dwLoop = 0; dwLoop < pTCPInfo->dwNumEntries; dwLoop++)
//    {
//        TCPInformation m_Info;
//        owner = &pTCPInfo->table[dwLoop];
//        m_Info.ProcessID = owner->dwOwningPid;
//        m_Info.LocalAddr = owner->dwLocalAddr;
//        m_Info.LocalPort = owner->dwLocalPort;
//        m_Info.RemoteAddr = owner->dwRemoteAddr;
//        m_Info.RemotePort = owner->dwRemotePort;
//        m_Info.State = owner->dwState;
//
//        pInfo->push_back(m_Info);
//    }
//    FreeLibrary(hLib);
//    free(pTCPInfo);
//    pTCPInfo = NULL;
//}
//
//void Tool::CheckInjectionPtn(std::set<DWORD>* pStringsHash, BOOL& pIsOther, BOOL& pIsPE)
//{
//    //set<DWORD>::iterator it;
//    //it = pStringsHash->find(3767103601);
//    if ((pStringsHash->find(3767103601) != pStringsHash->end()) || (pStringsHash->find(3307083059) != pStringsHash->end()))
//    {
//        if ((pStringsHash->find(2707265234) != pStringsHash->end()) || (pStringsHash->find(2959245455) != pStringsHash->end())
//            || (pStringsHash->find(1588018759) != pStringsHash->end()))
//        {
//            if ((pStringsHash->find(2413463320) != pStringsHash->end()) || (pStringsHash->find(1863699581) != pStringsHash->end())
//                || (pStringsHash->find(748668459) != pStringsHash->end()) || (pStringsHash->find(1810605166) != pStringsHash->end()))
//            {
//                if ((pStringsHash->find(3481317475) != pStringsHash->end()) || (pStringsHash->find(2845710125) != pStringsHash->end()))
//                    pIsOther = TRUE;
//            }
//        }
//    }
//
//    if ((pStringsHash->find(1789965451) != pStringsHash->end()) || (pStringsHash->find(1383550409) != pStringsHash->end()))
//    {
//        if ((pStringsHash->find(2923117684) != pStringsHash->end()) || (pStringsHash->find(2922200202) != pStringsHash->end())
//            || (pStringsHash->find(2141139445) != pStringsHash->end()) || (pStringsHash->find(2999148978) != pStringsHash->end()))
//        {
//            if ((pStringsHash->find(1791678813) != pStringsHash->end()) || (pStringsHash->find(73416223) != pStringsHash->end()))
//            {
//                if ((pStringsHash->find(963218793) != pStringsHash->end()) || (pStringsHash->find(2806968875) != pStringsHash->end()))
//                {
//                    if ((pStringsHash->find(1588018759) != pStringsHash->end()) || (pStringsHash->find(2707265234) != pStringsHash->end())
//                        || (pStringsHash->find(2959245455) != pStringsHash->end()))
//                    {
//                        if ((pStringsHash->find(2845710125) != pStringsHash->end()) || (pStringsHash->find(3481317475) != pStringsHash->end()))
//                        {
//                            pIsPE = TRUE;
//                        }
//                    }
//                }
//            }
//        }
//    }
//
//}
//
//BOOL Tool::DumpExecute(DWORD pid, wchar_t* pName, std::set<DWORD>* pApiBace, std::set<DWORD>* pStr, wchar_t* pProcessPath, std::set<std::string>* pIsAbnormal_dll)
//{
//    BOOL ret = FALSE;
//    HMODULE hResult = NULL;
//    HANDLE hSnapshot;
//    MODULEENTRY32 me32;
//    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
//    if (hSnapshot != INVALID_HANDLE_VALUE)
//    {
//        me32.dwSize = sizeof(MODULEENTRY32);
//        if (Module32First(hSnapshot, &me32))
//        {
//            do
//            {
//                if (!_tcsicmp(me32.szModule, WideCharToConstChar(pName)))
//                {
//                    BYTE* buffer = new BYTE[me32.modBaseSize];
//                    if (Toolhelp32ReadProcessMemory(pid, me32.modBaseAddr, buffer, me32.modBaseSize, 0))
//                    {
//                        std::set<DWORD> StringsHash;
//                        LoadBinaryStringsHash(buffer, me32.modBaseSize, &StringsHash);
//                        std::set<DWORD>::iterator it1;
//                        std::set<DWORD>::iterator it2;
//                        for (it1 = pApiBace->begin(); it1 != pApiBace->end(); it1++)
//                        {
//                            //char Apibuffer[256];
//                            //strcpy_s(Apibuffer,256,(*it1).c_str());
//                            //bool IsMatch = memfind(buffer,Apibuffer,me32.modBaseSize);
//                            //if(IsMatch)
//                            //{
//                            //	pStr->insert(Apibuffer);
//                            //}
//                            it2 = StringsHash.find((*it1));
//                            if (it2 != StringsHash.end())
//                            {
//                                pStr->insert((*it1));
//                            }
//                        }
//                        StringsHash.clear();
//                        ret = TRUE;
//                    }
//                    delete[] buffer;
//                }
//                else
//                {
//                    if (_tcsicmp(WideCharToConstChar(pProcessPath), _T("null")))
//                    {
//                        CheckModulePath(pProcessPath, CharPtrToWideCharPtr(me32.szExePath), pIsAbnormal_dll);
//                    }
//                }
//            } while (Module32Next(hSnapshot, &me32));
//        }
//        CloseHandle(hSnapshot);
//    }
//    return ret;
//}
//
//void Tool::CheckModulePath(wchar_t* pProcessPath, wchar_t* pModulePath, std::set<std::string>* pIsAbnormal_dll)
//{
//    wchar_t* Longfilename = new wchar_t[MAX_PATH_EX];
//    wchar_t* m_FilePath = new wchar_t[MAX_PATH_EX];
//    if (GetLongPathName(WideCharToConstChar(pModulePath), Longfilename, MAX_PATH_EX))
//    {
//        // lstrcpy(m_FilePath,Longfilename);
//        wcscpy(m_FilePath, Longfilename);
//    }
//    else
//    {
//        // lstrcpy(m_FilePath,pModulePath);
//        wcscpy(m_FilePath, pModulePath);
//    }
//    for (int i = 0; i < (int)_tcslen(WideCharToConstChar(m_FilePath)); i++)
//    {
//        if (m_FilePath[i] == ':')
//        {
//            if (i > 1)
//                // _tcscpy_s(Longfilename,MAX_PATH_EX,m_FilePath+(i-1));
//                wcsncpy(Longfilename, m_FilePath + (i - 1), MAX_PATH_EX);
//            else
//                // _tcscpy_s(Longfilename,MAX_PATH_EX,m_FilePath);
//                wcsncpy(Longfilename, m_FilePath, MAX_PATH_EX);
//            break;
//        }
//    }
//    wchar_t* TempPath = new wchar_t[MAX_PATH_EX];
//    _tcscpy_s(TempPath, MAX_PATH_EX, Longfilename);
//    wchar_t* pwc;
//    wchar_t* next_token = NULL;
//    int j = 0;
//    bool isMatchSystemFolder = true;
//    pwc = wcstok_s(TempPath, L"\\", &next_token);
//    while (pwc != NULL)
//    {
//        if (j == 0)
//        {
//            if (_wcsicmp(pwc, L"c:"))
//            {
//                isMatchSystemFolder = false;
//                break;
//            }
//        }
//        else if (j == 1)
//        {
//            if (_wcsicmp(pwc, L"Windows") && _wcsicmp(pwc, L"Program Files") && _wcsicmp(pwc, L"Program Files (x86)"))
//            {
//                isMatchSystemFolder = false;
//            }
//            break;
//        }
//        j++;
//        pwc = wcstok_s(NULL, L"\\", &next_token);
//    }
//    if (!isMatchSystemFolder)
//    {
//        _tcscpy_s(m_FilePath, MAX_PATH_EX, pProcessPath);
//        for (int i = (int)_tcslen(m_FilePath) - 1; i >= 0; i--)
//        {
//            if (m_FilePath[i] == '\\')
//            {
//                m_FilePath[i] = '\0';
//                break;
//            }
//        }
//        for (int i = (int)_tcslen(Longfilename) - 1; i >= 0; i--)
//        {
//            if (Longfilename[i] == '\\')
//            {
//                Longfilename[i] = '\0';
//                break;
//            }
//        }
//        if (_tcsicmp(Longfilename, m_FilePath))
//        {
//            char* str = CStringToCharArray(pModulePath, CP_UTF8);
//            char str1[MAX_PATH_EX];
//            strcpy_s(str1, MAX_PATH_EX, str);
//            if (CheckDigitalSignature(pModulePath))
//                strcat_s(str1, MAX_PATH_EX, ":1");
//            else
//                strcat_s(str1, MAX_PATH_EX, ":0");
//            wchar_t Md5Hashstr[50];
//            memset(Md5Hashstr, '\0', 50);
//            DWORD MD5ret = Md5Hash(pModulePath, Md5Hashstr);
//            if (MD5ret == 0)
//            {
//                char* Hashstr = CStringToCharArray(Md5Hashstr, CP_UTF8);
//                strcat_s(str1, MAX_PATH_EX, ",");
//                strcat_s(str1, MAX_PATH_EX, Hashstr);
//                delete[] Hashstr;
//                //lstrcpy(m_Info.ProcessHash,Md5Hashstr);
//            }
//            pIsAbnormal_dll->insert(str1);
//            delete[] str;
//        }
//    }
//    delete[] TempPath;
//    delete[] m_FilePath;
//    delete[] Longfilename;
//}
//
//bool Tool::CheckDigitalSignature(wchar_t* m_Path)
//{
//    //wchar_t * szFileName = CharArrayToWString(m_Path,CP_ACP);
//    DWORD dwEncoding, dwContentType, dwFormatType;
//    HCERTSTORE hStore = NULL;
//    HCRYPTMSG hMsg = NULL;
//    BOOL fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
//        m_Path,
//        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
//        CERT_QUERY_FORMAT_FLAG_BINARY,
//        0,
//        &dwEncoding,
//        &dwContentType,
//        &dwFormatType,
//        &hStore,
//        &hMsg,
//        NULL);
//    if (!fResult)
//    {
//        if (hStore != NULL) CertCloseStore(hStore, 0);
//        if (hMsg != NULL) CryptMsgClose(hMsg);
//        return false;
//    }
//    else
//    {
//        if (hStore != NULL) CertCloseStore(hStore, 0);
//        if (hMsg != NULL) CryptMsgClose(hMsg);
//        return true;
//    }
//}
//
//void Tool::LoadBinaryStringsHash(BYTE* buf, DWORD pSize, std::set<DWORD>* pStrSet)
//{
//    std::vector<BYTE> m_CharMap;
//    for (DWORD i = 0; i < pSize; i++)
//    {
//        if (buf[i] > 31 && buf[i] < 127)
//        {
//            m_CharMap.push_back(buf[i]);
//        }
//        else
//        {
//            if (!m_CharMap.empty())
//            {
//                if (m_CharMap.size() >= 3)
//                {
//                    std::string WriteStr;
//                    std::vector<BYTE>::iterator it;
//                    for (it = m_CharMap.begin(); it != m_CharMap.end(); it++)
//                    {
//                        WriteStr.push_back((*it));
//                    }
//                    if (WriteStr.size() < 256)
//                    {
//                        char* FuncName = new char[256];
//                        DWORD Hash = 0;
//                        strcpy_s(FuncName, 256, WriteStr.c_str());
//                        PUCHAR ptr = (PUCHAR)FuncName;
//                        while (*ptr)
//                        {
//                            Hash = ((Hash << 8) + Hash + *ptr) ^ (*ptr << 16);
//                            ptr++;
//                        }
//                        if (Hash > 0)
//                            pStrSet->insert(Hash);
//                        delete[] FuncName;
//                    }
//                    WriteStr.clear();
//                    m_CharMap.clear();
//                }
//                else
//                    m_CharMap.clear();
//            }
//        }
//    }
//    m_CharMap.clear();
//}
//
//bool Tool::GetDigitalSignature(wchar_t* m_Path, DigitalSignatureInfo* pInfo)
//{
//    WCHAR szFileName[MAX_PATH];
//    HCERTSTORE hStore = NULL;
//    HCRYPTMSG hMsg = NULL;
//    PCCERT_CONTEXT pCertContext = NULL;
//    BOOL fResult;
//    DWORD dwEncoding, dwContentType, dwFormatType;
//    PCMSG_SIGNER_INFO pSignerInfo = NULL;
//    PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
//    DWORD dwSignerInfo;
//    CERT_INFO CertInfo;
//    SPROG_PUBLISHERINFO ProgPubInfo;
//    SYSTEMTIME st;
//
//    ZeroMemory(&ProgPubInfo, sizeof(ProgPubInfo));
//    bool ret = true;
//    // try
//    do
//    {
//
//#ifdef UNICODE
//        if (_waccess(m_Path, 00))
//        {
//            //_tprintf(_T("No File\n"));
//            return false;
//        }
//        lstrcpynW(szFileName, m_Path, MAX_PATH);
//#else
//        if (mbstowcs(szFileName, m_Path, MAX_PATH) == -1)
//        {
//            printf("Unable to convert to unicode.\n");
//            __leave;
//        }
//#endif
//        // Get message handle and store handle from the signed file.
//        fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
//            szFileName,
//            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
//            CERT_QUERY_FORMAT_FLAG_BINARY,
//            0,
//            &dwEncoding,
//            &dwContentType,
//            &dwFormatType,
//            &hStore,
//            &hMsg,
//            NULL);
//        if (!fResult)
//        {
//            //_tprintf(_T("CryptQueryObject failed with %x\n"), GetLastError());
//            ret = false;
//            // __leave;
//            break;
//        }
//
//        // Get signer information size.
//        fResult = CryptMsgGetParam(hMsg,
//            CMSG_SIGNER_INFO_PARAM,
//            0,
//            NULL,
//            &dwSignerInfo);
//        if (!fResult)
//        {
//            //_tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
//             // __leave;
//            break;
//        }
//
//        // Allocate memory for signer information.
//        pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
//        if (!pSignerInfo)
//        {
//            //_tprintf(_T("Unable to allocate memory for Signer Info.\n"));
//            // __leave;
//            break;
//        }
//
//        // Get Signer Information.
//        fResult = CryptMsgGetParam(hMsg,
//            CMSG_SIGNER_INFO_PARAM,
//            0,
//            (PVOID)pSignerInfo,
//            &dwSignerInfo);
//        if (!fResult)
//        {
//            //_tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
//            // __leave;
//            break;
//        }
//
//        // Get program name and publisher information from 
//        // signer info structure.
//        if (GetProgAndPublisherInfo(pSignerInfo, &ProgPubInfo))
//        {
//            if (ProgPubInfo.lpszProgramName != NULL)
//            {
//                //wprintf(L"Program Name : %s\n",
//                 //   ProgPubInfo.lpszProgramName);
//                swprintf_s(pInfo->ProgramName, 256, L"%s", ProgPubInfo.lpszProgramName);
//            }
//
//            if (ProgPubInfo.lpszPublisherLink != NULL)
//            {
//                //wprintf(L"Publisher Link : %s\n",
//                //    ProgPubInfo.lpszPublisherLink);
//                swprintf_s(pInfo->PublisherLink, 256, L"%s", ProgPubInfo.lpszPublisherLink);
//            }
//
//            if (ProgPubInfo.lpszMoreInfoLink != NULL)
//            {
//                //wprintf(L"MoreInfo Link : %s\n",
//                //    ProgPubInfo.lpszMoreInfoLink);
//                swprintf_s(pInfo->MoreInfoLink, 256, L"%s", ProgPubInfo.lpszMoreInfoLink);
//            }
//        }
//
//        //_tprintf(_T("\n"));
//
//        // Search for the signer certificate in the temporary 
//        // certificate store.
//        CertInfo.Issuer = pSignerInfo->Issuer;
//        CertInfo.SerialNumber = pSignerInfo->SerialNumber;
//
//        pCertContext = CertFindCertificateInStore(hStore,
//            ENCODING,
//            0,
//            CERT_FIND_SUBJECT_CERT,
//            (PVOID)&CertInfo,
//            NULL);
//        if (!pCertContext)
//        {
//            //_tprintf(_T("CertFindCertificateInStore failed with %x\n"),
//            //    GetLastError());
//            // __leave;
//            break;
//        }
//
//        // Print Signer certificate information.
//       // _tprintf(_T("Signer Certificate:\n\n"));        
//        PrintCertificateInfo(pCertContext, pInfo, _T("Signer"));
//        //_tprintf(_T("\n"));
//
//        // Get the timestamp certificate signerinfo structure.
//        if (GetTimeStampSignerInfo(pSignerInfo, &pCounterSignerInfo))
//        {
//            // Search for Timestamp certificate in the temporary
//            // certificate store.
//            CertInfo.Issuer = pCounterSignerInfo->Issuer;
//            CertInfo.SerialNumber = pCounterSignerInfo->SerialNumber;
//
//            pCertContext = CertFindCertificateInStore(hStore,
//                ENCODING,
//                0,
//                CERT_FIND_SUBJECT_CERT,
//                (PVOID)&CertInfo,
//                NULL);
//            if (!pCertContext)
//            {
//                _tprintf(_T("CertFindCertificateInStore failed with %x\n"),
//                    GetLastError());
//                // __leave;
//                break;
//            }
//
//            // Print timestamp certificate information.
//            //_tprintf(_T("TimeStamp Certificate:\n\n"));
//            PrintCertificateInfo(pCertContext, pInfo, _T("TimeStamp"));
//            //_tprintf(_T("\n"));
//
//            // Find Date of timestamp.
//            if (GetDateOfTimeStamp(pCounterSignerInfo, &st))
//            {
//                pInfo->DateofTimeStamp = st;
//                //_tprintf(_T("Date of TimeStamp : %02d/%02d/%04d %02d:%02d\n"),
//                //                            st.wMonth,
//                //                            st.wDay,
//                //                            st.wYear,
//                //                            st.wHour,
//                //                            st.wMinute);
//                //swprintf_s(pInfo->DateofTimeStamp,256,_T("%02d/%02d/%04d %02d:%02d"),st.wMonth,st.wDay,st.wYear,st.wHour,st.wMinute);
//            }
//            //_tprintf(_T("\n"));
//        }
//    } while (false);
//
//    // __finally
//    // {               
//        // Clean up.
//    if (ProgPubInfo.lpszProgramName != NULL)
//        LocalFree(ProgPubInfo.lpszProgramName);
//    if (ProgPubInfo.lpszPublisherLink != NULL)
//        LocalFree(ProgPubInfo.lpszPublisherLink);
//    if (ProgPubInfo.lpszMoreInfoLink != NULL)
//        LocalFree(ProgPubInfo.lpszMoreInfoLink);
//
//    if (pSignerInfo != NULL) LocalFree(pSignerInfo);
//    if (pCounterSignerInfo != NULL) LocalFree(pCounterSignerInfo);
//    if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
//    if (hStore != NULL) CertCloseStore(hStore, 0);
//    if (hMsg != NULL) CryptMsgClose(hMsg);
//    // }
//    return ret;
//}

// BOOL Tool::GetDateOfTimeStamp(PCMSG_SIGNER_INFO pSignerInfo, SYSTEMTIME *st)
// {   
//     BOOL fResult;
//     FILETIME lft, ft;   
//     DWORD dwData;
//     BOOL fReturn = FALSE;

//     // Loop through authenticated attributes and find
//     // szOID_RSA_signingTime OID.
//     for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
//     {           
//         if (lstrcmpA(szOID_RSA_signingTime, 
//                     pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
//         {               
//             // Decode and get FILETIME structure.
//             dwData = sizeof(ft);
//             fResult = CryptDecodeObject(ENCODING,
//                         szOID_RSA_signingTime,
//                         pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
//                         pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
//                         0,
//                         (PVOID)&ft,
//                         &dwData);
//             if (!fResult)
//             {
//                 _tprintf(_T("CryptDecodeObject failed with %x\n"),
//                     GetLastError());
//                 break;
//             }

//             // Convert to local time.
//             FileTimeToLocalFileTime(&ft, &lft);
//             FileTimeToSystemTime(&lft, st);

//             fReturn = TRUE;

//             break; // Break from for loop.

//         } //lstrcmp szOID_RSA_signingTime
//     } // for 

//     return fReturn;
// }

// BOOL Tool::GetTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO *pCounterSignerInfo)
// {   
//     PCCERT_CONTEXT pCertContext = NULL;
//     BOOL fReturn = FALSE;
//     BOOL fResult;       
//     DWORD dwSize;   

//     // __try
// 	do
//     {
//         *pCounterSignerInfo = NULL;

//         // Loop through unathenticated attributes for
//         // szOID_RSA_counterSign OID.
//         for (DWORD n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
//         {
//             if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId, 
//                          szOID_RSA_counterSign) == 0)
//             {
//                 // Get size of CMSG_SIGNER_INFO structure.
//                 fResult = CryptDecodeObject(ENCODING,
//                            PKCS7_SIGNER_INFO,
//                            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
//                            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
//                            0,
//                            NULL,
//                            &dwSize);
//                 if (!fResult)
//                 {
//                     _tprintf(_T("CryptDecodeObject failed with %x\n"),
//                         GetLastError());
//                     // __leave;
// 					break;
//                 }

//                 // Allocate memory for CMSG_SIGNER_INFO.
//                 *pCounterSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
//                 if (!*pCounterSignerInfo)
//                 {
//                     _tprintf(_T("Unable to allocate memory for timestamp info.\n"));
//                     // __leave;
// 					break;
//                 }

//                 // Decode and get CMSG_SIGNER_INFO structure
//                 // for timestamp certificate.
//                 fResult = CryptDecodeObject(ENCODING,
//                            PKCS7_SIGNER_INFO,
//                            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
//                            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
//                            0,
//                            (PVOID)*pCounterSignerInfo,
//                            &dwSize);
//                 if (!fResult)
//                 {
//                     _tprintf(_T("CryptDecodeObject failed with %x\n"),
//                         GetLastError());
//                     // __leave;
// 					break;
//                 }

//                 fReturn = TRUE;

//                 break; // Break from for loop.
//             }           
//         }
//     }while(false);
//     // __finally
//     // {
//         // Clean up.
//         if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
//     // }

//     return fReturn;
// }

// BOOL Tool::PrintCertificateInfo(PCCERT_CONTEXT pCertContext,DigitalSignatureInfo * pInfo,wchar_t * pType)
// {
//     BOOL fReturn = FALSE;
//     LPTSTR szName = NULL;
//     DWORD dwData;

//     // __try
// 	do
//     {
//         // Print Serial Number.
//        // _tprintf(_T("Serial Number: "));
// 		if(!_tcscmp(pType,_T("Signer")))
// 		{
// 			memset(pInfo->SignerSerialNumber,'\0',256);
// 			dwData = pCertContext->pCertInfo->SerialNumber.cbData;
// 			for (DWORD n = 0; n < dwData; n++)
// 			{
// 				//_tprintf(_T("%02x "),
// 				  //pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
// 				wchar_t* cstr = new wchar_t[10];
// 				swprintf_s(cstr,10,_T("%02x "),pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
// 				_tcscat_s(pInfo->SignerSerialNumber,cstr);
// 				delete [] cstr;
// 			}
// 		}
// 		else if(!_tcscmp(pType,_T("TimeStamp")))
// 		{
// 			memset(pInfo->TimeStampSerialNumber,'\0',256);
// 			dwData = pCertContext->pCertInfo->SerialNumber.cbData;
// 			for (DWORD n = 0; n < dwData; n++)
// 			{
// 				//_tprintf(_T("%02x "),
// 				  //pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
// 				wchar_t* cstr = new wchar_t[10];
// 				swprintf_s(cstr,10,_T("%02x "),pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
// 				_tcscat_s(pInfo->TimeStampSerialNumber,cstr);
// 				delete [] cstr;
// 			}
// 		}
//        // _tprintf(_T("\n"));

//         // Get Issuer name size.
//         if (!(dwData = CertGetNameString(pCertContext, 
//                                          CERT_NAME_SIMPLE_DISPLAY_TYPE,
//                                          CERT_NAME_ISSUER_FLAG,
//                                          NULL,
//                                          NULL,
//                                          0)))
//         {
//            // _tprintf(_T("CertGetNameString failed.\n"));
//             // __leave;
// 			break;
//         }

//         // Allocate memory for Issuer name.
//         szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(wchar_t));
//         if (!szName)
//         {
//            // _tprintf(_T("Unable to allocate memory for issuer name.\n"));
//             // __leave;
// 			break;
//         }

//         // Get Issuer name.
//         if (!(CertGetNameString(pCertContext, 
//                                 CERT_NAME_SIMPLE_DISPLAY_TYPE,
//                                 CERT_NAME_ISSUER_FLAG,
//                                 NULL,
//                                 szName,
//                                 dwData)))
//         {
//             //_tprintf(_T("CertGetNameString failed.\n"));
//             // __leave;
// 			break;
//         }

//         // print Issuer name.
//         //_tprintf(_T("Issuer Name: %s\n"), szName);
// 		if(!_tcscmp(pType,_T("Signer")))
// 		{
// 			swprintf_s(pInfo->SignerIssuerName,256,_T("%s"),szName);
// 		}
// 		else if(!_tcscmp(pType,_T("TimeStamp")))
// 		{
// 			swprintf_s(pInfo->TimeStampIssuerName,256,_T("%s"),szName);
// 		}
//         LocalFree(szName);
//         szName = NULL;

//         // Get Subject name size.
//         if (!(dwData = CertGetNameString(pCertContext, 
//                                          CERT_NAME_SIMPLE_DISPLAY_TYPE,
//                                          0,
//                                          NULL,
//                                          NULL,
//                                          0)))
//         {
//             //_tprintf(_T("CertGetNameString failed.\n"));
//             // __leave;
// 			break;
//         }

//         // Allocate memory for subject name.
//         szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(wchar_t));
//         if (!szName)
//         {
//             //_tprintf(_T("Unable to allocate memory for subject name.\n"));
//             // __leave;
// 			break;
//         }

//         // Get subject name.
//         if (!(CertGetNameString(pCertContext, 
//                                 CERT_NAME_SIMPLE_DISPLAY_TYPE,
//                                 0,
//                                 NULL,
//                                 szName,
//                                 dwData)))
//         {
//             //_tprintf(_T("CertGetNameString failed.\n"));
//             // __leave;
// 			break;
//         }

//         // Print Subject Name.
//         //_tprintf(_T("Subject Name: %s\n"), szName);
// 		if(!_tcscmp(pType,_T("Signer")))
// 		{
// 			swprintf_s(pInfo->SignerSubjectName,256,_T("%s"),szName);
// 		}
// 		else if(!_tcscmp(pType,_T("TimeStamp")))
// 		{
// 			swprintf_s(pInfo->TimeStampSubjectName,256,_T("%s"),szName);
// 		}
//         fReturn = TRUE;
//     }while(false);
//     // __finally
//     // {
//         if (szName != NULL) LocalFree(szName);
//     // }

//     return fReturn;
// }

// BOOL Tool::GetProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo, PSPROG_PUBLISHERINFO Info)
// {
//     BOOL fReturn = FALSE;
//     PSPC_SP_OPUS_INFO OpusInfo = NULL;  
//     DWORD dwData;
//     BOOL fResult;

//     // __try
// 	do
//     {
//         // Loop through authenticated attributes and find
//         // SPC_SP_OPUS_INFO_OBJID OID.
//         for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
//         {           
//             if (lstrcmpA(SPC_SP_OPUS_INFO_OBJID,-
//                         pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
//             {
//                 // Get Size of SPC_SP_OPUS_INFO structure.
//                 fResult = CryptDecodeObject(ENCODING,
//                             SPC_SP_OPUS_INFO_OBJID,
//                             pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
//                             pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
//                             0,
//                             NULL,
//                             &dwData);
//                 if (!fResult)
//                 {
//                     _tprintf(_T("CryptDecodeObject failed with %x\n"),
//                         GetLastError());
//                     // __leave;
// 					break;
//                 }

//                 // Allocate memory for SPC_SP_OPUS_INFO structure.
//                 OpusInfo = (PSPC_SP_OPUS_INFO)LocalAlloc(LPTR, dwData);
//                 if (!OpusInfo)
//                 {
//                     _tprintf(_T("Unable to allocate memory for Publisher Info.\n"));
//                     // __leave;
// 					break;
//                 }

//                 // Decode and get SPC_SP_OPUS_INFO structure.
//                 fResult = CryptDecodeObject(ENCODING,
//                             SPC_SP_OPUS_INFO_OBJID,
//                             pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
//                             pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
//                             0,
//                             OpusInfo,
//                             &dwData);
//                 if (!fResult)
//                 {
//                     _tprintf(_T("CryptDecodeObject failed with %x\n"),
//                         GetLastError());
//                     // __leave;
// 					break;
//                 }

//                 // Fill in Program Name if present.
//                 if (OpusInfo->pwszProgramName)
//                 {
//                     Info->lpszProgramName =
//                         AllocateAndCopyWideString(OpusInfo->pwszProgramName);
//                 }
//                 else
//                     Info->lpszProgramName = NULL;

//                 // Fill in Publisher Information if present.
//                 if (OpusInfo->pPublisherInfo)
//                 {

//                     switch (OpusInfo->pPublisherInfo->dwLinkChoice)
//                     {
//                         case SPC_URL_LINK_CHOICE:
//                             Info->lpszPublisherLink =
//                                 AllocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszUrl);
//                             break;

//                         case SPC_FILE_LINK_CHOICE:
//                             Info->lpszPublisherLink =
//                                 AllocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszFile);
//                             break;

//                         default:
//                             Info->lpszPublisherLink = NULL;
//                             break;
//                     }
//                 }
//                 else
//                 {
//                     Info->lpszPublisherLink = NULL;
//                 }

//                 // Fill in More Info if present.
//                 if (OpusInfo->pMoreInfo)
//                 {
//                     switch (OpusInfo->pMoreInfo->dwLinkChoice)
//                     {
//                         case SPC_URL_LINK_CHOICE:
//                             Info->lpszMoreInfoLink =
//                                 AllocateAndCopyWideString(OpusInfo->pMoreInfo->pwszUrl);
//                             break;

//                         case SPC_FILE_LINK_CHOICE:
//                             Info->lpszMoreInfoLink =
//                                 AllocateAndCopyWideString(OpusInfo->pMoreInfo->pwszFile);
//                             break;

//                         default:
//                             Info->lpszMoreInfoLink = NULL;
//                             break;
//                     }
//                 }               
//                 else
//                 {
//                     Info->lpszMoreInfoLink = NULL;
//                 }

//                 fReturn = TRUE;

//                 break; // Break from for loop.
//             } // lstrcmp SPC_SP_OPUS_INFO_OBJID                 
//         } // for 
//     }while(false);
//     // __finally
//     // {
//         if (OpusInfo != NULL) LocalFree(OpusInfo);      
//     // }

//     return fReturn;
// }

// LPWSTR Tool::AllocateAndCopyWideString(LPCWSTR inputString)
// {
//     LPWSTR outputString = NULL;

//     outputString = (LPWSTR)LocalAlloc(LPTR,
//         (wcslen(inputString) + 1) * sizeof(WCHAR));
//     if (outputString != NULL)
//     {
//         lstrcpyW(outputString, inputString);
//     }
//     return outputString;
// }

// int Tool::CheckIsStartRun(std::map<std::wstring,BOOL> * pService,std::set<std::wstring> * pStartRun,DWORD pid/*,BOOL & isServiceHide*/)
// {
// 	int ret = 0;
// 	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
// 	if (hProc)
// 	{
// 		wchar_t * buffer = new wchar_t[MAX_PATH_EX];
// 		DWORD ret1 = GetRemoteCommandLineW(hProc,buffer,MAX_PATH_EX);
// 		//MessageBox(0,buffer,0,0);
// 		if(ret1 != 0)
// 		{//MessageBox(0,buffer,0,0);
// 			std::map<std::wstring,BOOL>::iterator ServiceIt;
// 			//for(ServiceIt = pService->begin();ServiceIt != pService->end();ServiceIt++)
// 				//MessageBox(0,(*ServiceIt).c_str(),0,0);
// 			ServiceIt = pService->find(buffer);
// 			if(ServiceIt != pService->end())
// 			{
// 				//if(!ServiceIt->second)
// 				//	isServiceHide = TRUE;
// 				ret += 1;
// 			}
// 			std::set<std::wstring>::iterator StartRunIt;
// 			StartRunIt = pStartRun->find(buffer);
// 			if(StartRunIt != pStartRun->end())
// 				ret += 2;
// 		}
// 		delete [] buffer;
// 		CloseHandle(hProc);
// 	}
// 	return ret;
// }

// void Tool::CheckIsInlineHook(DWORD pid,std::set<std::string> * pInlineHook)
// {
// 	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
// 	if (hProcess)
// 	{//printf("%lu\n",pid);
// #ifndef _M_IX86
// 		DWORD sysbit = Process32or64(hProcess);
// 		if(sysbit != 0)
// 		{
// 			HANDLE hSnapshot;
// 			MODULEENTRY32 me32;
// 			hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, pid);
// 			if (hSnapshot != INVALID_HANDLE_VALUE)
// 			{
// 				me32.dwSize = sizeof(MODULEENTRY32);
// 				if (Module32First(hSnapshot, &me32))
// 				{
// 					do
// 					{
// 						if(sysbit == 64)
// 						{
// 							if(!_tcsicmp(me32.szExePath,_T("C:\\Windows\\System32\\ntdll.dll"))||!_tcsicmp(me32.szExePath,_T("C:\\Windows\\System32\\kernel32.dll")))
// 							{
// 								try
// 								{
// 									FindFunctionAddress(me32.szExePath,me32.modBaseAddr,hProcess,pInlineHook);
// 								}
// 								catch(...){}
// 							}
// 						}
// 						else
// 						{
// 							if(!_tcsicmp(me32.szExePath,_T("C:\\Windows\\SysWOW64\\ntdll.dll"))||!_tcsicmp(me32.szExePath,_T("C:\\Windows\\SysWOW64\\kernel32.dll")))
// 							{
// 								try
// 								{
// 									FindFunctionAddress32(me32.szExePath,me32.modBaseAddr,hProcess,pInlineHook);
// 									//CompareAddressMatch(&m_FunctionAddressInfo,me32.szExePath/*,sysbit*/);
// 								}
// 								catch(...){}
// 							}
// 						}			
// 					}
// 					while (Module32Next(hSnapshot, &me32));
// 				}
// 				CloseHandle(hSnapshot);			
// 			}
// 			//ParserVirtualLibary(pid,&m_ModileAddress,&m_FunctionAddress);
// 		}
// #else
// 		HANDLE hSnapshot;
// 		MODULEENTRY32 me32;
// 		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, pid);
// 		if (hSnapshot != INVALID_HANDLE_VALUE)
// 		{
// 			me32.dwSize = sizeof(MODULEENTRY32);
// 			if (Module32First(hSnapshot, &me32))
// 			{
// 				do
// 				{
// 					if(!_tcsicmp(me32.szExePath,_T("C:\\Windows\\System32\\ntdll.dll"))||!_tcsicmp(me32.szExePath,_T("C:\\Windows\\System32\\kernel32.dll")))
// 					{
// 						FindFunctionAddress(me32.szExePath,me32.modBaseAddr,hProcess,pInlineHook);
// 					}
// 				}
// 				while (Module32Next(hSnapshot, &me32));
// 			}
// 			CloseHandle(hSnapshot);			
// 		}
// 		//ParserVirtualLibary(pid,&m_ModileAddress,&m_FunctionAddress);
// #endif
// 	}
// 	CloseHandle(hProcess);
// }

// void Tool::FindFunctionAddress32(wchar_t *file_path,BYTE * pModBaseAddr,HANDLE pProcess,std::set<std::string> * pInlineHook)
// {
// 	HANDLE hFile = 0, hMapping = 0;
// 	DWORD FileSize = 0, ExportTableRVA = 0, ImageBase = 0;
// 	PBYTE pFile = 0;
// 	PWORD pOrdinals = 0;
// 	PDWORD pFuncs = 0;
// 	PIMAGE_DOS_HEADER ImageDosHeader = 0;
// 	PIMAGE_NT_HEADERS32 ImageNtHeaders = 0;
// 	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = 0;
// 	hFile = CreateFile(file_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

// 	if (hFile == INVALID_HANDLE_VALUE)
// 	{
// 		_clean_things (NULL, NULL, NULL, "Can't open the required DLL");
// 		return;
// 	}

// 	FileSize = GetFileSize (hFile, NULL);
// 	if (FileSize == 0)
// 	{
// 		_clean_things (hFile, NULL, NULL, "FileSize is 0 !");
// 		return;
// 	}

// 	hMapping = CreateFileMapping (hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
// 	if (hMapping == NULL)
// 	{
// 		_clean_things (hFile, NULL, NULL, "Can't create the file mapping !");
// 		return;
// 	}

// 	pFile = (PBYTE) MapViewOfFile (hMapping, FILE_MAP_READ, 0, 0, 0);
// 	if (pFile == NULL)
// 	{
// 		_clean_things (hFile, hMapping, NULL, "Can't map the requested file !");
// 		return;
// 	}

// 	// uintptr_t ImageBase = reinterpret_cast<uintptr_t>(pFile);
//     // PBYTE pFileAgain = reinterpret_cast<PBYTE>(ImageBase);

// 	ImageBase = (DWORD)pFile;
// 	ImageDosHeader = (PIMAGE_DOS_HEADER) pFile;

// 	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
// 	{
// 		_clean_things (hFile, hMapping, pFile, "This file isn't a PE file !\n\n Wrong IMAGE_DOS_SIGNATURE");
// 		return;
// 	}

// 	ImageNtHeaders = (PIMAGE_NT_HEADERS32)(ImageDosHeader->e_lfanew + (DWORD) ImageDosHeader);

// 	if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
// 	{
// 		_clean_things (hFile, hMapping, pFile, "This file isn't a PE file !\n\n Wrong IMAGE_NT_SIGNATURE");
// 		return;
// 	}

// 	ExportTableRVA = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
// 	if (ExportTableRVA == 0)
// 	{
// 		_clean_things (hFile, hMapping, pFile, "Export table not found !");
// 		return;
// 	}

// 	ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY) (ExportTableRVA + ImageBase);


// 	pOrdinals = (PWORD) (ImageExportDirectory->AddressOfNameOrdinals + ImageBase);
// 	pFuncs = (PDWORD) (ImageExportDirectory->AddressOfFunctions + ImageBase);
// 	DWORD NumOfNames = ImageExportDirectory->NumberOfNames;

// 	DWORD ExportTableSize = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
// 	DWORD ETUpperBoundarie = ExportTableRVA + ExportTableSize;
// 	BOOL Isntdll = FALSE;
// 	if(!_tcsicmp(file_path,_T("C:\\Windows\\SysWOW64\\ntdll.dll")))
// 		Isntdll = TRUE;
// 	for (UINT i = 0; i < ImageExportDirectory->NumberOfFunctions; i++)
// 	{
// 		//sprintf_s ((char *) buffer1, sizeof (buffer1), "Ord: %04lX (0x%08lX)", ImageExportDirectory->Base + i, pFuncs[i]);

// 		if (/*pOrdinals[i]*/i < NumOfNames)
// 		{
// 			if(i <= ImageExportDirectory->NumberOfNames)
// 			{
// 				PDWORD pNamePointerRVA =(PDWORD)(ImageExportDirectory->AddressOfNames + ImageBase);
// 				PCHAR pFuncName = (PCHAR) (pNamePointerRVA[i] + (DWORD) ImageBase);
// 				if(pFuncName)
// 				{
// 					//ULONGLONG m_FunctionAddress = pFuncs[pOrdinals[i]];
// 					if(Isntdll)
// 					{
// 						if(!strcmp(pFuncName,"NlsAnsiCodePage"))
// 						{
// 							continue;
// 						}
// 					}
// 					ULONGLONG m_FunctionMemoryAddressInfo = 0;
// 					BYTE * mBuf = new BYTE[8];
// 					memset(mBuf,'\x0',8);
// 					BYTE * SourceByte = new BYTE[8];
// 					memset(SourceByte,'\x0',8);
// 					memcpy(SourceByte,pFile+pFuncs[pOrdinals[i]],6);
// 					ULONGLONG m_FunctionSourecAddressInfo = ((ULONGLONG *)SourceByte)[0];
// 					SIZE_T nread = 0;
// 					if(ReadProcessMemory(pProcess, pModBaseAddr+pFuncs[pOrdinals[i]], mBuf, 6, &nread))
// 					{
// 						m_FunctionMemoryAddressInfo = ((ULONGLONG *)mBuf)[0];
// 						if(m_FunctionSourecAddressInfo != 0 && m_FunctionMemoryAddressInfo != 0)
// 						{
// 							if(SourceByte[0] != mBuf[0])
// 							{
// 								if(!(SourceByte[5] == mBuf[5] && SourceByte[4] == mBuf[4]))
// 								{
// 									//char * cPath = CStringToCharArray(file_path,CP_UTF8);
// 									//printf("%s %s %08I32X 0x%016I64X 0x%016I64X\n",cPath,pFuncName,m_Info.m_FunctionAddress,m_Info.m_FunctionSourecAddressInfo,m_Info.m_FunctionMemoryAddressInfo);
// 									//delete [] cPath;
// 									char str[512];
// 									sprintf_s(str,512,"%s:0x%016I64X -> 0x%016I64X",pFuncName,m_FunctionSourecAddressInfo,m_FunctionMemoryAddressInfo);
// 									pInlineHook->insert(str);
// 								}
// 							}
// 						}
// 					}
// 					delete [] SourceByte;
// 					delete [] mBuf;				
// 				}	
// 			}
// 		}
// 		//else
// 		//	break;
// 	}
// 	_clean_things (hFile, hMapping, pFile, NULL);
// }

// void Tool::FindFunctionAddress(wchar_t *file_path,BYTE * pModBaseAddr,HANDLE pProcess,std::set<std::string> * pInlineHook)
// {
// 	HANDLE hFile = 0, hMapping = 0;
// 	DWORD FileSize = 0;
// 	DWORD_PTR ImageBase = 0, ExportTableRVA = 0;
// 	PBYTE pFile = 0;
// 	PWORD pOrdinals = 0;
// 	PDWORD pFuncs = 0;
// 	PIMAGE_DOS_HEADER ImageDosHeader = 0;
// 	PIMAGE_NT_HEADERS ImageNtHeaders = 0;
// 	PIMAGE_EXPORT_DIRECTORY ImageExportDirectory = 0;
// 	//char * cTimeDate = new char[32];
// 	hFile = CreateFile(file_path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
// 	//wprintf(L"%s\n",file_path);
// 	if (hFile == INVALID_HANDLE_VALUE)
// 	{
// 		_clean_things (NULL, NULL, NULL, "Can't open the required DLL");
// 		return;
// 	}

// 	FileSize = GetFileSize (hFile, NULL);
// 	if (FileSize == 0)
// 	{
// 		_clean_things (hFile, NULL, NULL, "FileSize is 0 !");
// 		return;
// 	}

// 	hMapping = CreateFileMapping (hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
// 	if (hMapping == NULL)
// 	{
// 		_clean_things (hFile, NULL, NULL, "Can't create the file mapping !");
// 		return;
// 	}

// 	pFile = (PBYTE) MapViewOfFile (hMapping, FILE_MAP_READ, 0, 0, 0);
// 	if (pFile == NULL)
// 	{
// 		_clean_things (hFile, hMapping, NULL, "Can't map the requested file !");
// 		return;
// 	}

// 	ImageBase = (DWORD_PTR)pFile;
// 	ImageDosHeader = (PIMAGE_DOS_HEADER) pFile;

// 	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
// 	{
// 		_clean_things (hFile, hMapping, pFile, "This file isn't a PE file !\n\n Wrong IMAGE_DOS_SIGNATURE");
// 		return;
// 	}

// 	ImageNtHeaders = (PIMAGE_NT_HEADERS)(ImageDosHeader->e_lfanew + (DWORD_PTR) ImageDosHeader);

// 	if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
// 	{
// 		_clean_things (hFile, hMapping, pFile, "This file isn't a PE file !\n\n Wrong IMAGE_NT_SIGNATURE");
// 		return;
// 	}

// 	ExportTableRVA = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
// 	if (ExportTableRVA == 0)
// 	{
// 		_clean_things (hFile, hMapping, pFile, "Export table not found !");
// 		return;
// 	}
// 	//HMODULE hMod =  LoadLibraryEx(file_path, NULL, DONT_RESOLVE_DLL_REFERENCES );

// 	//DWORD_PTR addstr = (DWORD_PTR)GetProcAddress(hMod,(char*)NameImg->Name);
// 	ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY) (ExportTableRVA + ImageBase);
// 	pOrdinals = (PWORD) (ImageExportDirectory->AddressOfNameOrdinals + ImageBase);
// 	pFuncs = (PDWORD) (ImageExportDirectory->AddressOfFunctions + ImageBase);
// 	DWORD NumOfNames = ImageExportDirectory->NumberOfNames;
// 	DWORD_PTR ExportTableSize = ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
// 	DWORD_PTR ETUpperBoundarie = ExportTableRVA + ExportTableSize;
// 	//wprintf(L"%s\n",file_path);
// 	for (UINT i = 0; i < ImageExportDirectory->NumberOfFunctions; i++)
// 	{
// 		if (i < NumOfNames)
// 		{
// 			if(i <= ImageExportDirectory->NumberOfNames)
// 			{
// 				PDWORD pNamePointerRVA =(PDWORD)(ImageExportDirectory->AddressOfNames + ImageBase);
// 				PCHAR pFuncName = (PCHAR) (pNamePointerRVA[i] + (DWORD_PTR) ImageBase);
// 				if(pFuncName)
// 				{
// 					if(_stricmp(pFuncName,"_aexit_rtn"))
// 					{
// 						ULONGLONG m_FunctionMemoryAddressInfo = 0;
// 						BYTE * mBuf = new BYTE[8];
// 						memset(mBuf,'\x0',8);
// 						BYTE * SourceByte = new BYTE[8];
// 						memset(SourceByte,'\x0',8);
// 						memcpy(SourceByte,pFile+pFuncs[pOrdinals[i]],6);
// 						ULONGLONG m_FunctionSourecAddressInfo = ((ULONGLONG *)SourceByte)[0];
// 						SIZE_T nread = 0;
// 						if(ReadProcessMemory(pProcess, pModBaseAddr+pFuncs[pOrdinals[i]], mBuf, 6, &nread))
// 						{
// 							m_FunctionMemoryAddressInfo = ((ULONGLONG *)mBuf)[0];
// 							if(m_FunctionSourecAddressInfo != 0 && m_FunctionMemoryAddressInfo != 0)
// 							{
// 								if(SourceByte[0] != mBuf[0])
// 								{
// 									if(!(SourceByte[5] == mBuf[5] && SourceByte[4] == mBuf[4]))
// 									{
// 										//char * cPath = CStringToCharArray(file_path,CP_UTF8);
// 										//printf("%s %s %08I32X 0x%016I64X 0x%016I64X\n",cPath,pFuncName,m_Info.m_FunctionAddress,m_Info.m_FunctionSourecAddressInfo,m_Info.m_FunctionMemoryAddressInfo);
// 										//delete [] cPath;
// 										char str[512];
// 										sprintf_s(str,512,"%s:0x%016I64X -> 0x%016I64X",pFuncName,m_FunctionSourecAddressInfo,m_FunctionMemoryAddressInfo);
// 										pInlineHook->insert(str);
// 									}
// 								}
// 							}
// 						}
// 						delete [] SourceByte;
// 						delete [] mBuf;
// 					}
// 				}
// 			}
// 		}		
// 	}
// 	_clean_things (hFile, hMapping, pFile, NULL);
// 	//gewchar_t();
// 	//return psc;
// }

// void Tool::_clean_things (HANDLE hFile, HANDLE hMapping, PBYTE pFile, const char *pErrorMessage)
// {
// 	//if (pErrorMessage != NULL)
// 	//	printf ("%s\n", pErrorMessage);

// 	if (hFile != NULL)
// 		CloseHandle (hFile);

// 	if (pFile != NULL)
// 		UnmapViewOfFile (pFile);

// 	if (hMapping != NULL)
// 		CloseHandle (hMapping);
// }

// void Tool::SearchExecutePath(DWORD pid,wchar_t* pPath,wchar_t* pName)
// {
// 	HMODULE hResult = NULL;
//     HANDLE hSnapshot;
//     MODULEENTRY32 me32;
// 	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, pid);
//     if (hSnapshot != INVALID_HANDLE_VALUE)
//     {
//         me32.dwSize = sizeof(MODULEENTRY32);
//         if (Module32First(hSnapshot, &me32))
//         {
//             do
//             {
// 				if(!_tcsicmp(me32.szModule,pName))
// 				{
// 					_tcscpy_s(pPath,MAX_PATH_EX,me32.szExePath);
// 					break;
// 				}
//             }
//             while (Module32Next(hSnapshot, &me32));
//         }
//         CloseHandle(hSnapshot);
//     }
// }

// void Tool::GetProcessPath(DWORD pid, wchar_t* pPath, bool IsGetTime, wchar_t* pTimeStr,wchar_t * pCTimeStr)
// {
// 	//HMODULE hModuleHandle;
// 	//DWORD dwNeeded;
// 	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
// 	wchar_t *filename = new wchar_t[MAX_PATH_EX];
// 	wchar_t *Longfilename = new wchar_t[MAX_PATH_EX];
// 	wchar_t *m_FilePath = new wchar_t[MAX_PATH_EX];
// 	if (processHandle != NULL) 
// 	{
// 		//if (EnumProcessModules(processHandle, &hModuleHandle, sizeof(hModuleHandle), &dwNeeded) == TRUE)
//         //{
// 			if (GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH_EX)) 
// 			{			
// 				if(GetLongPathName(filename,Longfilename,MAX_PATH_EX))
// 				{
// 					lstrcpy(m_FilePath,Longfilename);
// 				}
// 				else
// 				{
// 					lstrcpy(m_FilePath,filename);
// 				}

// 				BOOL isrightPath = FALSE;
// 				//MessageBox(0,m_FilePath,0,0);
// 				for(size_t i=0;i<wcslen(m_FilePath);i++)
// 				{
// 					if(m_FilePath[i]==':')
// 					{
// 						isrightPath = TRUE;
// 						if( (i-1) != 0)
// 							lstrcpy(pPath,m_FilePath+(i-1));
// 						else
// 							lstrcpy(pPath,m_FilePath);
// 						break;
// 					}
// 				}
// 				if(!isrightPath)
// 				{//MessageBox(0,m_FilePath,0,0);
// 					lstrcpy(pPath,_T("null"));
// 				}
// 			}
// 			else
// 				lstrcpy(pPath,_T("null"));

// 			if(IsGetTime)
// 			{
// 				FILETIME l1,l2,l3,l4;
// 				if(GetProcessTimes(processHandle,&l1,&l2,&l3,&l4))
// 				{
// 					FILETIME localft;  
// 					FileTimeToLocalFileTime(&l1, &localft);
// 					if(pCTimeStr != NULL)
// 					{
// 						time_t ProcessCreateTime = 0;
// 						ProcessCreateTime = filetime_to_timet(l1);
// 						swprintf_s(pCTimeStr,20,_T("%lld"),ProcessCreateTime);
// 					}
// 					if(pTimeStr != NULL)
// 					{
// 						SYSTEMTIME st;  
// 						FileTimeToSystemTime(&localft, &st);
// 						swprintf_s(pTimeStr,20,_T("%4d/%02d/%02d %02d:%02d:%02d"),st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond);
// 					}
// 				}
// 				else
// 					lstrcpy(pTimeStr,_T("null"));
// 			}	
// 		//}
// 		//else
// 			//lstrcpy(pPath,_T("null"));
// 		CloseHandle(processHandle);
// 	}
// 	else
// 		lstrcpy(pPath,_T("null"));
// 	delete [] m_FilePath;
// 	delete [] Longfilename;
// 	delete [] filename;
// }

// int Tool::CheckIsInjection(DWORD pid,std::vector<UnKnownDataInfo> * pMembuf,wchar_t * pProcessName,wchar_t * pUnKnownHash)
// {
// 	int ret = 0;
// 	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
// 	if (!hProc)	
// 		return ret;

// 	#ifndef _M_IX86
// 	SIZE_T ptype = Process32or64(hProc);
// 	SIZE_T startmem = 0;
// 	SIZE_T maxmem = 0x7FFF0000;
// 	if (ptype == 64)
// 	{
// 		maxmem = 0x7FFFFFEFFFF;
// 	}
// 	#else

// 	SIZE_T ptype = 32;
// 	SIZE_T startmem = 0;
// 	SIZE_T maxmem = 0x7FFF0000;
// 	#endif
// 	wchar_t lastfilename[MAX_PATH];
// 	while ( startmem < maxmem)
// 	{
// 		MEMORY_BASIC_INFORMATION mbi;
// 		SIZE_T size = VirtualQueryEx(hProc,(LPVOID)startmem,&mbi,sizeof(MEMORY_BASIC_INFORMATION));
// 		if (!size)
// 		{
// 			CloseHandle(hProc);
// 			return ret;
//         }
// 		if (mbi.State == MEM_COMMIT)
// 		{
// 			SIZE_T ReadSize = 0;
// 			if(mbi.RegionSize < 20971520)
// 				ReadSize = mbi.RegionSize;
// 			else
// 				ReadSize = 20971520;
// 			char *buffer = new char [ReadSize];
// 			SIZE_T nread = 0;

// 			ReadProcessMemory(hProc, mbi.BaseAddress, buffer, ReadSize/*mbi.RegionSize*/, &nread);
// 			if (nread == ReadSize)
// 			{	
// 				if(mbi.AllocationProtect & PAGE_EXECUTE_READWRITE)
// 				{
// 					if (!GetProcessMappedFileName(hProc,mbi.BaseAddress,lastfilename))
// 					{
// 						if(IsPESignature((BYTE*)buffer,(unsigned int)ReadSize))
// 						{
// 							ret = 2;
// 							if(pMembuf != NULL)
// 							{
// 								if(mbi.RegionSize <= 20971520)
// 								{
// 									UnKnownDataInfo m_Info;
// 									m_Info.Pid = pid;
// 									if(PeUnmapper((BYTE*)buffer,mbi.RegionSize,(ULONGLONG)mbi.BaseAddress,&m_Info))
// 									{
// 										_tcscpy_s(m_Info.ProcessName,MAX_PATH,pProcessName);
// 										pMembuf->push_back(m_Info);
// 									}
// 								}
// 								//else
// 								//{
// 								//	UnKnownDataInfo m_Info;
// 								//	m_Info.Pid = pid;
// 								//	//memset(m_Info.Data,'\x0',DATASTRINGMESSAGELEN);
// 								//	//memcpy(m_Info.Data,buffer,DATASTRINGMESSAGELEN);
// 								//	m_Info.SizeInfo = DATASTRINGMESSAGELEN;
// 								//	pMembuf->push_back(m_Info);
// 								//}
// 							}
// 							if(pUnKnownHash != NULL)
// 							{
// 								if(mbi.RegionSize <= 20971520)
// 								{
// 									try
// 									{
// 										GetUnKnownHash((BYTE*)buffer,mbi.RegionSize,pUnKnownHash,ptype);
// 									}
// 									catch(...){}
// 								}
// 							}
// 						}
// 						else
// 						{
// 							if(ret < 2)
// 								ret = 1;
// 						}
// 					}
// 				}
// 				else if(mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY)
// 				{
// 					if (!GetProcessMappedFileName(hProc,mbi.BaseAddress,lastfilename))
// 					{
// 						if(IsPESignature((BYTE*)buffer,(unsigned int)ReadSize))
// 						{
// 							ret = 2;
// 							if(pMembuf != NULL)
// 							{
// 								if(mbi.RegionSize <= 20971520)
// 								{
// 									UnKnownDataInfo m_Info;
// 									m_Info.Pid = pid;
// 									if(PeUnmapper((BYTE*)buffer,mbi.RegionSize,(ULONGLONG)mbi.BaseAddress,&m_Info))
// 									{
// 										_tcscpy_s(m_Info.ProcessName,MAX_PATH,pProcessName);
// 										pMembuf->push_back(m_Info);
// 									}
// 								}
// 								//else
// 								//{
// 								//	UnKnownDataInfo m_Info;
// 								//	m_Info.Pid = pid;
// 								//	//memset(m_Info.Data,'\x0',DATASTRINGMESSAGELEN);
// 								//	//memcpy(m_Info.Data,buffer,DATASTRINGMESSAGELEN);
// 								//	m_Info.SizeInfo = DATASTRINGMESSAGELEN;
// 								//	pMembuf->push_back(m_Info);
// 								//}
// 							}
// 							if(pUnKnownHash != NULL)
// 							{
// 								if(mbi.RegionSize <= 20971520)
// 								{
// 									try
// 									{
// 										GetUnKnownHash((BYTE*)buffer,mbi.RegionSize,pUnKnownHash,ptype);
// 									}
// 									catch(...){}
// 								}
// 							}
// 						}
// 						else
// 						{
// 							if(ret < 2)
// 								ret = 1;
// 						}
// 					}
// 				}
// 			}			
// 			delete [] buffer;
// 		}
// 		startmem = (SIZE_T)mbi.BaseAddress + (SIZE_T)mbi.RegionSize;
// 	}
// 	CloseHandle(hProc);
// 	return ret;
// }

// #ifndef _M_IX86
// DWORD Tool::Process32or64(HANDLE hProcess)
// {
// 	BOOL bIsWow64 = FALSE;
// 	DWORD returnvalue;
// 	if (!IsWow64Process(hProcess,&bIsWow64))
// 	{
// 		returnvalue = 0;
// 		return returnvalue;
// 	}
// 	if (bIsWow64)
// 	{
// 		returnvalue = 32;
// 	}
// 	else
// 	{
// 		returnvalue = 64;
// 	}
// 	return returnvalue;
// }
// #endif

// void Tool::GetUnKnownHash(BYTE * pBuffer,SIZE_T pBufferSize,wchar_t * pUnKnownHash,SIZE_T ptype)
// {
// 	if(pBufferSize >= 1024)
// 	{
// 		if(!IsPackedSignature(pBuffer,1024))
// 		{
// 			if(ptype == 64)
// 				ParserUnknownIAT(pBuffer,pUnKnownHash);
// 			else
// 				ParserUnknownIAT32(pBuffer,pUnKnownHash);
// 		}
// 	}
// }

// void Tool::ParserUnknownIAT(BYTE * pBuffer,wchar_t * pUnKnownHash)
// {
// 	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pBuffer;
// 	PLOADED_IMAGE pImage = new LOADED_IMAGE();
// 	pImage->FileHeader = (PIMAGE_NT_HEADERS)((BYTE*)pBuffer + pDOSHeader->e_lfanew);
// 	pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;
// 	pImage->Sections = (PIMAGE_SECTION_HEADER)((BYTE*)pBuffer + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
// 	if (pImage)
// 	{
// 		PIMAGE_DATA_DIRECTORY importDirectory = &pImage->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

// 		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptors = (PIMAGE_IMPORT_DESCRIPTOR) ((BYTE*)pBuffer + importDirectory->VirtualAddress);

// 		if(pImportDescriptors)
// 		{
// 			//map<wstring,wstring>::iterator it;
// 			PIMAGE_THUNK_DATA OriginalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pBuffer + pImportDescriptors->OriginalFirstThunk);
// 			std::string HashStr;
// 			HashStr.clear();
// 			while(OriginalFirstThunk != 0)
// 			{
// 				if(!pImportDescriptors->FirstThunk)
// 					break;
// 				//printf("%s\n",((BYTE*)pData + pImportDescriptors->Name));
// 				char * pName = (char*)((BYTE*)pBuffer + pImportDescriptors->Name);
// 				//printf("%s\n",pName);
// 				OriginalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pBuffer + pImportDescriptors->OriginalFirstThunk);
// 				PIMAGE_IMPORT_BY_NAME NameImg = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBuffer + (DWORD_PTR)OriginalFirstThunk->u1.AddressOfData);
// 				PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)pBuffer + pImportDescriptors->FirstThunk);
// 				DWORD dwOffset = 0;
// 				std::string DllName = pName;
// 				HashStr += DllName;
// 				while(NameImg)
// 				{
// 					//printf("%lu\n",OriginalFirstThunk->u1.AddressOfData);
// 					#ifndef _M_IX86
// 					if(!(OriginalFirstThunk->u1.AddressOfData > 9223372036854775807))
// 					#else
// 					if(!(OriginalFirstThunk->u1.AddressOfData > 2147483647))
// 					#endif
// 					{
// 						DWORD_PTR dwOriginalAddress = FirstThunk[dwOffset].u1.AddressOfData;	
// 						if(dwOriginalAddress != 0)
// 						{
// 							std::string FunctionName = (char*)NameImg->Name;
// 							HashStr += FunctionName;
// 							FunctionName.clear();
// 						}
// 						else
// 							break;
// 					}
// 					dwOffset++;
// 					OriginalFirstThunk++;
// 					NameImg = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBuffer + (DWORD_PTR)OriginalFirstThunk->u1.AddressOfData);
// 				}
// 				DllName.clear();
// 				pImportDescriptors++;
// 			}
// 			if(Md5StringHash((char*)HashStr.c_str(),pUnKnownHash))
// 				_tcscpy_s(pUnKnownHash,50,_T("null"));
// 			HashStr.clear();
// 		}
// 	}
// 	else
// 		printf("Error reading remote image\r\n");
// 	delete pImage;
// }

// void Tool::ParserUnknownIAT32(BYTE * pBuffer,wchar_t * pUnKnownHash)
// {
// 	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pBuffer;
// 	PLOADED_IMAGE32 pImage = new LOADED_IMAGE32();

// 	pImage->FileHeader = (PIMAGE_NT_HEADERS32)((BYTE*)pBuffer + pDOSHeader->e_lfanew);
// 	pImage->NumberOfSections = pImage->FileHeader->FileHeader.NumberOfSections;

// 	pImage->Sections = (PIMAGE_SECTION_HEADER)((BYTE*)pBuffer + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));
// 	if (pImage)
// 	{
// 		PIMAGE_DATA_DIRECTORY importDirectory = &pImage->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

// 		PIMAGE_IMPORT_DESCRIPTOR pImportDescriptors = (PIMAGE_IMPORT_DESCRIPTOR) ((BYTE*)pBuffer + importDirectory->VirtualAddress);

// 		if(pImportDescriptors)
// 		{
// 			//map<wstring,wstring>::iterator it;
// 			PIMAGE_THUNK_DATA32 OriginalFirstThunk = (PIMAGE_THUNK_DATA32)((BYTE*)pBuffer + pImportDescriptors->OriginalFirstThunk);
// 			std::string HashStr;
// 			HashStr.clear();
// 			while(OriginalFirstThunk != 0)
// 			{
// 				if(!pImportDescriptors->FirstThunk)
// 					break;
// 				//printf("%s\n",((BYTE*)pData + pImportDescriptors->Name));
// 				char * pName = (char*)((BYTE*)pBuffer + pImportDescriptors->Name);
// 				//printf("%s\n",pName);
// 				OriginalFirstThunk = (PIMAGE_THUNK_DATA32)((BYTE*)pBuffer + pImportDescriptors->OriginalFirstThunk);
// 				PIMAGE_IMPORT_BY_NAME NameImg = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBuffer + (DWORD)OriginalFirstThunk->u1.AddressOfData);
// 				PIMAGE_THUNK_DATA32 FirstThunk = (PIMAGE_THUNK_DATA32)((BYTE*)pBuffer + pImportDescriptors->FirstThunk);
// 				DWORD dwOffset = 0;
// 				std::string DllName = pName;
// 				HashStr += DllName;
// 				while(NameImg)
// 				{
// 					//printf("%lu\n",OriginalFirstThunk->u1.AddressOfData);
// 					if(!(OriginalFirstThunk->u1.AddressOfData > 2147483647))
// 					{
// 						DWORD dwOriginalAddress = FirstThunk[dwOffset].u1.AddressOfData;	
// 						if(dwOriginalAddress != 0)
// 						{
// 							std::string FunctionName = (char*)NameImg->Name;
// 							HashStr += FunctionName;
// 							FunctionName.clear();
// 						}
// 						else
// 							break;
// 					}
// 					dwOffset++;
// 					OriginalFirstThunk++;
// 					NameImg = (PIMAGE_IMPORT_BY_NAME)((BYTE*)pBuffer + (DWORD)OriginalFirstThunk->u1.AddressOfData);
// 				}
// 				DllName.clear();				
// 				pImportDescriptors++;
// 			}
// 			//GetStringsMd5(&HashStr,pUnKnownHash);
// 			if(Md5StringHash((char*)HashStr.c_str(),pUnKnownHash))
// 				_tcscpy_s(pUnKnownHash,50,_T("null"));
// 			HashStr.clear();
// 		}
// 	}
// 	delete pImage;
// }

// DWORD Tool::Md5StringHash(char * SourceStr,wchar_t * HashStr)
// {
// 	memset(HashStr,'\0',50);
// 	DWORD dwStatus = 0;
//     BOOL bResult = FALSE;
//     HCRYPTPROV hProv = 0;
//     HCRYPTHASH hHash = 0;
//     BYTE rgbHash[16];
//     DWORD cbHash = 0;
//     CHAR rgbDigits[] = "0123456789abcdef";

// 	if (!CryptAcquireContext(&hProv,NULL, NULL,PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
//     {
//         dwStatus = GetLastError();
//         printf("CryptAcquireContext failed: %d\n", dwStatus); 
//         return dwStatus;
//     }
// 	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
//     {
//         dwStatus = GetLastError();
//         printf("CryptAcquireContext failed: %d\n", dwStatus); 
//         CryptReleaseContext(hProv, 0);
//         return dwStatus;
//     }
// 	if (!CryptHashData(hHash, (BYTE*)SourceStr,(DWORD)strlen(SourceStr), 0))
//     {
// 		dwStatus = GetLastError();
//         printf("CryptHashData failed: %d\n", dwStatus); 
//         CryptReleaseContext(hProv, 0);
//         CryptDestroyHash(hHash);
//         return dwStatus;
//     }
// 	cbHash = 16;
//     if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
//     {
//         for (DWORD i = 0; i < cbHash; i++)
//         {
// 			wchar_t* cstr = new wchar_t[10];
// 			swprintf_s(cstr,10,_T("%c%c"),rgbDigits[rgbHash[i] >> 4],rgbDigits[rgbHash[i] & 0xf]);
// 			lstrcat(HashStr,cstr);
// 			delete [] cstr;
//         }
//     }
//     else
//     {
//         dwStatus = GetLastError();
//         printf("CryptGetHashParam failed: %d\n", dwStatus); 
//     }

// 	CryptDestroyHash(hHash);
//     CryptReleaseContext(hProv, 0);
//     return dwStatus; 
// }

// int Tool::GetProcessMappedFileName(HANDLE ProcessHandle,PVOID BaseAddress,wchar_t *FileName)
// {
// 	HMODULE m_dll = LoadLibrary(L"ntdll.dll");
// 	if(m_dll == NULL)
// 		return 0;
// 	PNtQueryVirtualMemory _NtQueryVirtualMemory = (PNtQueryVirtualMemory)GetProcAddress(m_dll ,"NtQueryVirtualMemory");
// 	NTSTATUS status;
// 	char *buffer;
// 	SIZE_T bufferSize;
// 	SIZE_T returnLength;
// 	PUNICODE_STRING unicodeString;

// 	bufferSize = 0x100;
// 	buffer = new char [bufferSize];
// 	status = _NtQueryVirtualMemory(
// 		ProcessHandle,
// 		BaseAddress,
// 		MemoryMappedFilenameInformation,
// 		buffer,
// 		bufferSize,
// 		&returnLength
// 		);

// 	if (status == STATUS_BUFFER_OVERFLOW)
// 	{
// 		delete [] buffer;
// 		bufferSize = returnLength;
// 		buffer = new char[bufferSize];

// 		status = _NtQueryVirtualMemory(
// 			ProcessHandle,
// 			BaseAddress,
// 			MemoryMappedFilenameInformation,
// 			buffer,
// 			bufferSize,
// 			&returnLength
// 			);
// 	}

//     if (!NT_SUCCESS(status))
// 	{
// 		FileName[0] = '\x0';
// 		delete [] buffer;
// 		FreeLibrary(m_dll);
// 		return 0;
//     }
// 	status = 0;
// 	unicodeString = (PUNICODE_STRING)buffer;
// 	if (unicodeString->Length>0)
// 	{
// 		status = 1;
// 		size_t filename_pos = 0;

// 		for (size_t i=wcslen(unicodeString->Buffer);i>=0;i--)
// 		{
// 			if (unicodeString->Buffer[i] == '\\')
// 			{
// 				filename_pos = i+1;
// 				break;
// 			}
// 		}
// 		wcscpy_s(FileName,MAX_PATH,&unicodeString->Buffer[filename_pos]);
// 	}
// 	delete [] buffer;
// 	FreeLibrary(m_dll);
//     return status;
// }

// BOOL Tool::IsPESignature(BYTE * buffer,unsigned int buflen)
// {
// 	for(unsigned int i = 0;i<buflen;i++)
// 	{
// 		if(i+5 > buflen)
// 			break;
// 		else
// 		{
// 			if(buffer[i]==80)
// 			{
// 				if(buffer[i+1]==69 && buffer[i+2]==0 && buffer[i+3]==0)
// 				{
// 					if((buffer[i+4]==100&&buffer[i+5]==134) || (buffer[i+4]==76&&buffer[i+5]==1))
// 					{
// 						return TRUE;
// 					}
// 					else
// 						continue;
// 				}
// 				else
// 					continue;
// 			}
// 		}
// 	}
// 	return FALSE;
// }

// bool Tool::PeUnmapper(BYTE * buffer,size_t pSize, ULONGLONG loadBase,UnKnownDataInfo * pInfo)
// {
// 	BYTE* out_buf = NULL; 
//     size_t out_size = 0;
//     printf("MODE: Virtual -> Raw\n");
//     out_buf = pe_virtual_to_raw(buffer, pSize, loadBase, out_size, false);

//     if (!out_buf) {
//         free_pe_buffer(buffer, pSize);
//         return false;
//     }
// 	pInfo->SizeInfo = (DWORD)out_size;
// 	pInfo->Data = new BYTE[out_size+1];
// 	memcpy(pInfo->Data,out_buf,out_size);

//     // Write output
// 	//wchar_t * m_FilePath = new wchar_t[512];
// 	//GetMyPath(m_FilePath);
// 	//_tcscat_s(m_FilePath,512,_T("\\"));
// 	//_tcscat_s(m_FilePath,512,pName);
// 	//_tcscat_s(m_FilePath,512,_T(".mem"));
//  //   bool isOk = dump_to_file(m_FilePath,out_buf,out_size);
// 	//delete [] m_FilePath;
//     //free_pe_buffer(buffer, pSize);
//     free_pe_buffer(out_buf, out_size);

//     return true;
// }

// // BYTE* Tool::pe_virtual_to_raw(BYTE* payload, size_t in_size, ULONGLONG loadBase, size_t &out_size, bool rebuffer)
// // {
// //     BYTE* in_buf = payload;
// //     if (rebuffer) {
// //         in_buf = (BYTE*) alloc_pe_buffer(in_size, PAGE_READWRITE);
// //         if (in_buf == NULL) return NULL;
// //         memcpy(in_buf, payload, in_size);
// //     }

// //     BYTE* out_buf = (BYTE*) alloc_pe_buffer(in_size, PAGE_READWRITE);
// //     ULONGLONG oldBase = get_image_base(in_buf);
// //     bool isOk = true;
// //     // from the loadBase go back to the original base
// //     if (!relocate_module(in_buf, in_size, oldBase, loadBase)) {
// //         //Failed relocating the module! Changing image base instead...
// //         if (!update_image_base(in_buf, (ULONGLONG)loadBase)) {
// //             //std::cerr << "[-] Failed relocating the module!" << std::endl;
// // 			printf("[-] Failed relocating the module!\n");
// //             isOk = false;
// //         } else {
// // #ifdef _DEBUG
// //             //std::cerr << "[!] WARNING: The module could not be relocated, so the ImageBase has been changed instead!" << std::endl;
// // 			printf("[!] WARNING: The module could not be relocated, so the ImageBase has been changed instead!\n");
// // #endif
// //         }
// //     }
// //     SIZE_T raw_size = 0;
// //     if (isOk) {
// //         if (!sections_virtual_to_raw(in_buf, in_size, out_buf, &raw_size)) {
// //             isOk = false;
// //         }
// //     }
// //     if (rebuffer && in_buf != NULL) {
// //         free_pe_buffer(in_buf, in_size);
// //         in_buf = NULL;
// //     }
// //     if (!isOk) {
// //         free_pe_buffer(out_buf, in_size);
// //         out_buf = NULL;
// //     }
// //     out_size = raw_size;
// //     return out_buf;
// // }

// // ALIGNED_BUF Tool::alloc_pe_buffer(size_t buffer_size, DWORD protect, ULONGLONG desired_base)
// // {
// //     return alloc_aligned(buffer_size, protect, desired_base);
// // }

// // ALIGNED_BUF Tool::alloc_aligned(size_t buffer_size, DWORD protect, ULONGLONG desired_base)
// // {
// //     PBYTE buf = (PBYTE) VirtualAlloc((LPVOID) desired_base, buffer_size, MEM_COMMIT | MEM_RESERVE, protect);
// //     return buf;
// // }

// // ULONGLONG Tool::get_image_base(const BYTE *pe_buffer)
// // {
// //     bool is64b = is64bit(pe_buffer);
// //     //update image base in the written content:
// //     BYTE* payload_nt_hdr = get_nt_hrds(pe_buffer);
// //     if (payload_nt_hdr == NULL) {
// //         return 0;
// //     }
// //     ULONGLONG img_base = 0;
// //     if (is64b) {
// //         IMAGE_NT_HEADERS64* payload_nt_hdr64 = (IMAGE_NT_HEADERS64*)payload_nt_hdr;
// //         img_base = payload_nt_hdr64->OptionalHeader.ImageBase;
// //     } else {
// //         IMAGE_NT_HEADERS32* payload_nt_hdr32 = (IMAGE_NT_HEADERS32*)payload_nt_hdr;
// //         img_base = static_cast<ULONGLONG>(payload_nt_hdr32->OptionalHeader.ImageBase);
// //     }
// //     return img_base;
// // }

// // bool Tool::is64bit(const BYTE *pe_buffer)
// // {
// //     WORD arch = get_nt_hdr_architecture(pe_buffer);
// //     if (arch == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
// //         return true;
// //     }
// //     return false;
// // }

// // WORD Tool::get_nt_hdr_architecture(const BYTE *pe_buffer)
// // {
// //     void *ptr = get_nt_hrds(pe_buffer);
// //     if (ptr == NULL) return 0;

// //     IMAGE_NT_HEADERS32 *inh = static_cast<IMAGE_NT_HEADERS32*>(ptr);
// //     if (IsBadReadPtr(inh, sizeof(IMAGE_NT_HEADERS32))) {
// //         return 0;
// //     }
// //     return inh->OptionalHeader.Magic;
// // }

// // BYTE* Tool::get_nt_hrds(const BYTE *pe_buffer, size_t buffer_size)
// // {
// //     if (pe_buffer == NULL) return NULL;

// //     IMAGE_DOS_HEADER *idh = (IMAGE_DOS_HEADER*)pe_buffer;
// //     if (buffer_size != 0) {
// //         if (!validate_ptr((LPVOID)pe_buffer, buffer_size, (LPVOID)idh, sizeof(IMAGE_DOS_HEADER))) {
// //             return NULL;
// //         }
// //     }
// //     if (IsBadReadPtr(idh, sizeof(IMAGE_DOS_HEADER))) {
// //         return NULL;
// //     }
// //     if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
// //         return NULL;
// //     }
// //     const LONG kMaxOffset = 1024;
// //     LONG pe_offset = idh->e_lfanew;

// //     if (pe_offset > kMaxOffset) return NULL;

// //     IMAGE_NT_HEADERS32 *inh = (IMAGE_NT_HEADERS32 *)(pe_buffer + pe_offset);
// //     if (buffer_size != 0) {
// //         if (!validate_ptr((LPVOID)pe_buffer, buffer_size, (LPVOID)inh, sizeof(IMAGE_NT_HEADERS32))) {
// //             return NULL;
// //         }
// //     }
// //     if (IsBadReadPtr(inh, sizeof(IMAGE_NT_HEADERS32))) {
// //         return NULL;
// //     }
// //     if (inh->Signature != IMAGE_NT_SIGNATURE) {
// //         return NULL;
// //     }
// //     return (BYTE*)inh;
// // }

// // bool Tool::validate_ptr(const LPVOID buffer_bgn, SIZE_T buffer_size, const LPVOID field_bgn, SIZE_T field_size)
// // {
// //     if (buffer_bgn == nullptr || field_bgn == nullptr) {
// //         return false;
// //     }
// //     ULONGLONG start = (ULONGLONG)buffer_bgn;
// //     ULONGLONG end = start + buffer_size;

// //     ULONGLONG field_end = (ULONGLONG)field_bgn + field_size;

// //     if ((ULONGLONG)field_bgn < start) {
// //         return false;
// //     }
// //     if (field_end > end) {
// //         return false;
// //     }
// //     return true;
// // }

// // bool Tool::relocate_module(BYTE* modulePtr, SIZE_T moduleSize, ULONGLONG newBase, ULONGLONG oldBase)
// // {
// //     if (modulePtr == NULL) {
// //         return false;
// //     }
// //     if (oldBase == NULL) {
// //         oldBase = get_image_base(modulePtr);
// //     }
// // #ifdef _DEBUG
// //     printf("New Base: %llx\n", newBase);
// //     printf("Old Base: %llx\n", oldBase);
// // #endif
// //     if (newBase == oldBase) {
// // #ifdef _DEBUG
// //         printf("Nothing to relocate! oldBase is the same as the newBase!\n");
// // #endif
// //         return true; //nothing to relocate
// //     }
// //     if (apply_relocations(modulePtr, moduleSize, newBase, oldBase)) {
// //         return true;
// //     }
// // #ifdef _DEBUG
// //     printf("Could not relocate the module!\n");
// // #endif
// //     return false;
// // }

// // bool Tool::apply_relocations(PVOID modulePtr, SIZE_T moduleSize, ULONGLONG newBase, ULONGLONG oldBase)
// // {
// //     IMAGE_DATA_DIRECTORY* relocDir = get_directory_entry((const BYTE*) modulePtr, IMAGE_DIRECTORY_ENTRY_BASERELOC);
// //     if (relocDir == NULL) {
// // #ifdef _DEBUG
// //         printf("[!] WARNING: no relocation table found!\n");
// // #endif
// //         return false;
// //     }
// //     if (!validate_ptr(modulePtr, moduleSize, relocDir, sizeof(IMAGE_DATA_DIRECTORY))) {
// //         return false;
// //     }
// //     DWORD maxSize = relocDir->Size;
// //     DWORD relocAddr = relocDir->VirtualAddress;
// //     bool is64b = is64bit((BYTE*)modulePtr);

// //     IMAGE_BASE_RELOCATION* reloc = NULL;

// //     DWORD parsedSize = 0;
// //     while (parsedSize < maxSize) {
// //         reloc = (IMAGE_BASE_RELOCATION*)(relocAddr + parsedSize + (ULONG_PTR)modulePtr);
// //         if (!validate_ptr(modulePtr, moduleSize, reloc, sizeof(IMAGE_BASE_RELOCATION))) {
// //             printf("[-] Invalid address of relocations\n");
// //             return false;
// //         }
// //         parsedSize += reloc->SizeOfBlock;

// //         if (reloc->VirtualAddress == NULL || reloc->SizeOfBlock == 0) {
// //             break;
// //         }

// //         size_t entriesNum = (reloc->SizeOfBlock - 2 * sizeof(DWORD)) / sizeof(WORD);
// //         DWORD page = reloc->VirtualAddress;

// //         BASE_RELOCATION_ENTRY* block = (BASE_RELOCATION_ENTRY*)((ULONG_PTR)reloc + sizeof(DWORD) + sizeof(DWORD));
// //         if (!validate_ptr(modulePtr, moduleSize, block, sizeof(BASE_RELOCATION_ENTRY))) {
// //             printf("[-] Invalid address of relocations block\n");
// //             return false;
// //         }
// //         if (apply_reloc_block(block, entriesNum, page, oldBase, newBase, modulePtr, moduleSize, is64b) == false) {
// //             return false;
// //         }
// //     }
// //     return (parsedSize != 0);
// // }

// // IMAGE_DATA_DIRECTORY* Tool::get_directory_entry(const BYTE *pe_buffer, DWORD dir_id)
// // {
// //     if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

// //     BYTE* nt_headers = get_nt_hrds((BYTE*)pe_buffer);
// //     if (nt_headers == NULL) return NULL;

// //     IMAGE_DATA_DIRECTORY* peDir = NULL;
// //     if (is64bit((BYTE*)pe_buffer)) {
// //         IMAGE_NT_HEADERS64* nt_headers64 = (IMAGE_NT_HEADERS64*)nt_headers;
// //         peDir = &(nt_headers64->OptionalHeader.DataDirectory[dir_id]);
// //     }
// //     else {
// //         IMAGE_NT_HEADERS32* nt_headers64 = (IMAGE_NT_HEADERS32*)nt_headers;
// //         peDir = &(nt_headers64->OptionalHeader.DataDirectory[dir_id]);
// //     }
// //     if (peDir->VirtualAddress == NULL) {
// //         return NULL;
// //     }
// //     return peDir;
// // }

// void Tool::LoadNowProcessInfo(std::map<DWORD,process_info_Ex>* pInfo) {
// 	bool ret = false;
// 	ret = EnumProcessEx(pInfo);
// 	if(ret)
// 	{
// 		std::map<DWORD,process_info_Ex>::iterator it;
// 		std::map<DWORD,process_info_Ex>::iterator st;
// 		for(it = pInfo->begin();it != pInfo->end();it++)
// 		{
// 			_tcscpy_s(it->second.process_Path,512,_T("null"));
// 			_tcscpy_s(it->second.process_Com,512,_T("null"));
// 			_tcscpy_s(it->second.m_SID,256,_T("null"));
// 			it->second.parentCreateTime = 0;
// 			it->second.IsPacked = FALSE;
// 			st = pInfo->find((DWORD)it->second.parent_pid);
// 			if(st != pInfo->end())
// 			{
// 				if(st->second.ProcessCreateTime <= it->second.ProcessCreateTime)
// 				{
// 					//_tcscpy_s(ParentName,MAX_PATH,st->second.process_name);
// 					it->second.parentCreateTime = st->second.ProcessCreateTime;
// 				}
// 			}
// 			GetProcessInfo(it->first,it->second.process_Path,NULL,it->second.m_SID,it->second.process_Com);
// 			if(_tcscmp(it->second.process_Path,_T("null")))
// 			{
// 				it->second.IsPacked = CheckIsPackedPE(it->second.process_Path);
// 			}
// 		}
// 	}
// }

// BOOL Tool::IsWindowsProcessNormal(std::map<DWORD,process_info_Ex> * pInfo,DWORD pid) {
// 	BOOL ret = FALSE;
// 	if(pid == 0 || pid == 4)
// 		ret = TRUE;
// 	else
// 	{
// 		std::map<DWORD,process_info_Ex>::iterator it;
// 		it = pInfo->find(pid);
// 		if(it != pInfo->end())
// 		{
// 			if(!_wcsicmp(it->second.process_name,L"csrss.exe"))
// 			{
// 				ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 				if(ret)
// 					ret = CheckPathMatch(&it->second);
// 				if(ret)
// 					ret = CheckSIDMatch(&it->second);
// 				//if(ret)
// 				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
// 			}
// 			else if(!_wcsicmp(it->second.process_name,L"wininit.exe"))
// 			{
// 				ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 				if(ret)
// 					ret = CheckPathMatch(&it->second);
// 				if(ret)
// 					ret = CheckSIDMatch(&it->second);
// 				//if(ret)
// 				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
// 			}
// 			else if(!_wcsicmp(it->second.process_name,L"winlogon.exe"))
// 			{
// 				ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 				if(ret)
// 					ret = CheckPathMatch(&it->second);
// 				if(ret)
// 					ret = CheckSIDMatch(&it->second);
// 				//if(ret)
// 				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
// 			}
// 			//else if(!_wcsicmp(it->second.process_name,L"explorer.exe"))
// 			//{
// 			//	ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 			//	if(ret)
// 			//		ret = CheckPathMatch(&it->second);
// 			//	if(ret)
// 			//		ret = CheckSIDMatch(&it->second);
// 			//	if(ret)
// 			//		ret = CheckCreateTimeMatch(pInfo,&it->second);
// 			//}
// 			else if(!_wcsicmp(it->second.process_name,L"smss.exe"))
// 			{
// 				if(it->second.parent_pid == 4)
// 					ret = TRUE;
// 			}
// 			else if(!_wcsicmp(it->second.process_name,L"services.exe"))
// 			{
// 				ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 				if(ret)
// 					ret = CheckPathMatch(&it->second);
// 				if(ret)
// 					ret = CheckSIDMatch(&it->second);
// 				//if(ret)
// 				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
// 			}
// 			else if(!_wcsicmp(it->second.process_name,L"svchost.exe"))
// 			{
// 				ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 				if(ret)
// 					ret = CheckPathMatch(&it->second);
// 				if(ret)
// 					ret = CheckSIDMatch(&it->second);
// 				//if(ret)
// 				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
// 			}
// 			else if(!_wcsicmp(it->second.process_name,L"taskhost.exe"))
// 			{
// 				ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 				if(ret)
// 					ret = CheckPathMatch(&it->second);
// 				if(ret)
// 					ret = CheckSIDMatch(&it->second);
// 				//if(ret)
// 				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
// 			}
// 			else if(!_wcsicmp(it->second.process_name,L"lsass.exe"))
// 			{
// 				ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 				if(ret)
// 					ret = CheckPathMatch(&it->second);
// 				if(ret)
// 					ret = CheckSIDMatch(&it->second);
// 				//if(ret)
// 				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
// 			}
// 			else if(!_wcsicmp(it->second.process_name,L"lsm.exe"))
// 			{
// 				ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 				if(ret)
// 					ret = CheckPathMatch(&it->second);
// 				if(ret)
// 					ret = CheckSIDMatch(&it->second);
// 				//if(ret)
// 				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
// 			}
// 			else if(!_wcsicmp(it->second.process_name,L"dllhost.exe"))
// 			{
// 				ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 				if(ret)
// 					ret = CheckPathMatch(&it->second);
// 				if(ret)
// 					ret = CheckSIDMatch(&it->second);
// 				//if(ret)
// 				//	ret = CheckCreateTimeMatch(pInfo,&it->second);
// 			}
// 		}
// 	}
// 	return ret;
// }

// BOOL Tool::CheckParentProcessNormal(std::map<DWORD,process_info_Ex> * pInfo,DWORD parentid,wchar_t * process_name,time_t pCreateTime)
// {
// 	BOOL ret = FALSE;
// 	std::map<DWORD,process_info_Ex>::iterator it;
// 	it = pInfo->find(parentid);
// 	if(it != pInfo->end())
// 	{
// 		if(!_wcsicmp(process_name,L"csrss.exe"))
// 		{
// 			if(pCreateTime < it->second.ProcessCreateTime)
// 				ret = TRUE;
// 			else
// 			{
// 				if(!_wcsicmp(it->second.process_name,L"smss.exe"))
// 					ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 			}
// 		}
// 		else if(!_wcsicmp(process_name,L"wininit.exe"))
// 		{
// 			if(pCreateTime < it->second.ProcessCreateTime)
// 				ret = TRUE;
// 			else
// 			{
// 				if(!_wcsicmp(it->second.process_name,L"smss.exe"))
// 					ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 			}
// 		}
// 		else if(!_wcsicmp(process_name,L"winlogon.exe"))
// 		{
// 			//if(pCreateTime < it->second.ProcessCreateTime)
// 				ret = TRUE;
// 			//else
// 			//{
// 			//	if(!_wcsicmp(it->second.process_name,L"smss.exe"))
// 			//		ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 			//}
// 		}
// 		//else if(!_wcsicmp(process_name,L"explorer.exe"))
// 		//{
// 		//	if(pCreateTime < it->second.ProcessCreateTime)
// 		//		ret = TRUE;
// 		//	else
// 		//	{
// 		//		if(!_wcsicmp(it->second.process_name,L"userinit.exe"))
// 		//			ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 		//	}
// 		//}
// 		else if(!_wcsicmp(process_name,L"smss.exe"))
// 		{
// 			if(it->second.parent_pid == 4)
// 				ret = TRUE;
// 		}
// 		else if(!_wcsicmp(process_name,L"services.exe"))
// 		{
// 			if(!_wcsicmp(it->second.process_name,L"wininit.exe"))
// 				ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 		}
// 		else if(!_wcsicmp(process_name,L"svchost.exe"))
// 		{
// 			if(!_wcsicmp(it->second.process_name,L"services.exe"))
// 				ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 		}
// 		else if(!_wcsicmp(process_name,L"taskhost.exe"))
// 		{
// 			if(!_wcsicmp(it->second.process_name,L"services.exe"))
// 				ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 		}
// 		else if(!_wcsicmp(process_name,L"lsass.exe"))
// 		{
// 			if(!_wcsicmp(it->second.process_name,L"wininit.exe"))
// 				ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 		}
// 		else if(!_wcsicmp(process_name,L"lsm.exe"))
// 		{
// 			if(!_wcsicmp(it->second.process_name,L"wininit.exe"))
// 				ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 		}
// 		else if(!_wcsicmp(process_name,L"dllhost.exe"))
// 		{
// 			if(!_wcsicmp(it->second.process_name,L"svchost.exe")||!_wcsicmp(it->second.process_name,L"services.exe"))
// 				ret = CheckParentProcessNormal(pInfo,it->second.parent_pid,it->second.process_name,it->second.ProcessCreateTime);
// 		}
// 	}
// 	else
// 	{
// 		if(!_wcsicmp(process_name,L"csrss.exe"))
// 			ret = TRUE;
// 		else if(!_wcsicmp(process_name,L"wininit.exe"))
// 			ret = TRUE;
// 		else if(!_wcsicmp(process_name,L"winlogon.exe"))
// 			ret = TRUE;
// 		else if(!_wcsicmp(process_name,L"explorer.exe"))
// 			ret = TRUE;
// 	}
// 	return ret;
// }

// BOOL Tool::CheckPathMatch(process_info_Ex * pInfo)
// {
// 	BOOL ret = TRUE;
// 	if(_wcsicmp(pInfo->process_Path,L"null"))
// 	{
// 		if(!_wcsicmp(pInfo->process_name,_T("smss.exe")))
// 		{
// 			if(_wcsicmp(pInfo->process_Path,L"null"))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("csrss.exe")))
// 		{
// 			if(_wcsicmp(pInfo->process_Path,L"C:\\Windows\\System32\\csrss.exe"))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("services.exe")))
// 		{
// 			if(_wcsicmp(pInfo->process_Path,L"C:\\Windows\\System32\\services.exe"))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("svchost.exe")))
// 		{
// 			if(_wcsicmp(pInfo->process_Path,L"C:\\Windows\\System32\\svchost.exe"))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("lsm.exe")))
// 		{
// 			if(_wcsicmp(pInfo->process_Path,L"C:\\Windows\\System32\\lsm.exe"))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("explorer.exe")))
// 		{
// 			if(_wcsicmp(pInfo->process_Path,L"C:\\Windows\\explorer.exe"))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("iexplore.exe")))
// 		{
// 			if(_wcsicmp(pInfo->process_Path,L"C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe") &&
// 				_wcsicmp(pInfo->process_Path,L"C:\\Program Files\\Internet Explorer\\iexplore.exe"))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("winlogon.exe")))
// 		{
// 			if(_wcsicmp(pInfo->process_Path,L"C:\\Windows\\System32\\winlogon.exe"))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("lsass.exe")))
// 		{
// 			if(_wcsicmp(pInfo->process_Path,L"C:\\Windows\\System32\\lsass.exe"))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("taskhost.exe")))
// 		{
// 			if(_wcsicmp(pInfo->process_Path,L"C:\\Windows\\System32\\taskhost.exe"))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("wininit.exe")))
// 		{
// 			if(_wcsicmp(pInfo->process_Path,L"C:\\Windows\\System32\\wininit.exe"))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("dllhost.exe")))
// 		{
// 			if(_wcsicmp(pInfo->process_Path,L"C:\\Windows\\System32\\dllhost.exe"))
// 				ret = FALSE;
// 		}
// 	}
// 	return ret;
// }

// BOOL Tool::CheckSIDMatch(process_info_Ex * pInfo)
// {
// 	BOOL ret = TRUE;
// 	if(_wcsicmp(pInfo->m_SID,L"null"))
// 	{
// 		if(!_wcsicmp(pInfo->process_name,_T("smss.exe")))
// 		{
// 			if(_wcsicmp(pInfo->m_SID,_T("SYSTEM")))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("csrss.exe")))
// 		{
// 			if(_wcsicmp(pInfo->m_SID,_T("SYSTEM")))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("services.exe")))
// 		{
// 			if(_wcsicmp(pInfo->m_SID,_T("SYSTEM")))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("svchost.exe")))
// 		{
// 			//if(_wcsicmp(pInfo->m_SID,_T("SYSTEM"))&&_wcsicmp(pInfo->m_SID,_T("LOCAL SERVICE")))
// 			//	ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("lsm.exe")))
// 		{
// 			if(_wcsicmp(pInfo->m_SID,_T("SYSTEM")))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("explorer.exe")))
// 		{

// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("iexplore.exe")))
// 		{

// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("winlogon.exe")))
// 		{
// 			if(_wcsicmp(pInfo->m_SID,_T("SYSTEM")))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("lsass.exe")))
// 		{
// 			if(_wcsicmp(pInfo->m_SID,_T("SYSTEM")))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("taskhost.exe")))
// 		{

// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("wininit.exe")))
// 		{
// 			if(_wcsicmp(pInfo->m_SID,_T("SYSTEM")))
// 				ret = FALSE;
// 		}
// 		else if(!_wcsicmp(pInfo->process_name,_T("dllhost.exe")))
// 		{
// 			if(_wcsicmp(pInfo->m_SID,_T("SYSTEM")))
// 				ret = FALSE;
// 		}
// 	}
// 	return ret;
// }

// bool Tool::EnumProcessEx(std::map<DWORD,process_info_Ex>* pInfo) {
// 	NTSTATUS status;
//     PVOID buffer;
//     PSYSTEM_PROCESS_INFO spi;

//     // We need to allocate a large buffer because the process list can be large.
//     buffer=VirtualAlloc(NULL,1024*1024,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE); 
//     if(!buffer) {
//         printf("\nError: Unable to allocate memory for process list (%d)\n",GetLastError());
//         return false;
//     }

//    // printf("\nProcess list allocated at address %#x\n",buffer);
//     spi = (PSYSTEM_PROCESS_INFO)buffer;
//     if(!NT_SUCCESS(status=NtQuerySystemInformation(SystemProcessInformation,spi,1024*1024,NULL))) {
//         printf("\nError: Unable to query process list (%#x)\n",status);
//         VirtualFree(buffer,0,MEM_RELEASE);
//         return false;
//     }

//     // #elif defined _M_IX86
// 	// pZwQuerySystemInformation ZwQuerySystemInformation = (pZwQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"),"ZwQuerySystemInformation");
// 	// if(!NT_SUCCESS(status=ZwQuerySystemInformation(SystemProcessInformation,spi,1024*1024,NULL)))
//     // {
//     //     //printf("\nError: Unable to query process list (%#x)\n",status);

//     //     VirtualFree(buffer,0,MEM_RELEASE);
//     //     return false;
//     // }
// 	// #endif

// 	// Loop over the list until we reach the last entry.
//     while(spi->NextEntryOffset) {
// 		if((int)spi->ProcessId > 0) {
// 			process_info_Ex  m_Info = {0};
// 			m_Info.pid = (int)spi->ProcessId;
// 			m_Info.parent_pid = (int)spi->InheritedFromProcessId;
// 			swprintf_s(m_Info.process_name,MAX_PATH,L"%s",spi->ImageName.Buffer);
// 			m_Info.ProcessCreateTime = spi->CreateTime.QuadPart/ 10000000ULL - 11644473600ULL;
// 			if(m_Info.ProcessCreateTime < 0)
// 				m_Info.ProcessCreateTime = 0;
// 			m_Info.IsHide = FALSE;
// 			pInfo->insert(std::pair<DWORD,process_info_Ex>((DWORD)m_Info.pid,m_Info));
// 		}
// 		else if((int)spi->ProcessId == 0) {
// 			process_info_Ex  m_Info = {0};
// 			m_Info.pid = (int)spi->ProcessId;
// 			m_Info.parent_pid = -1;
// 			swprintf_s(m_Info.process_name,MAX_PATH,L"[System Process]");
// 			m_Info.ProcessCreateTime = 0;
// 			m_Info.IsHide = FALSE;
// 			pInfo->insert(std::pair<DWORD,process_info_Ex>((DWORD)m_Info.pid,m_Info));
// 		}
// 		spi=(PSYSTEM_PROCESS_INFO)((LPBYTE)spi+spi->NextEntryOffset); // Calculate the address of the next entry.
//     }

//     // Free the allocated buffer.
//     VirtualFree(buffer,0,MEM_RELEASE); 
// 	return true;
// }

// void Tool::GetProcessInfo(DWORD pid,wchar_t* pPath,wchar_t * pTimeStr,wchar_t * pUserName,wchar_t * pComStr) {
// 	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
// 	if (processHandle != NULL) {
// 		if (pPath != NULL) {
// 			wchar_t *filename = new wchar_t[MAX_PATH_EX];
// 			wchar_t *Longfilename = new wchar_t[MAX_PATH_EX];
// 			wchar_t *m_FilePath = new wchar_t[MAX_PATH_EX];
// 			if (GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH_EX)) {			
// 				if(GetLongPathName(filename,Longfilename,MAX_PATH_EX)) lstrcpy(m_FilePath,Longfilename);
// 				else lstrcpy(m_FilePath,filename);

// 				for(size_t i=0;i<wcslen(m_FilePath);i++) {
// 					if(m_FilePath[i]==':') {
// 						if( (i-1) != 0) lstrcpy(pPath,m_FilePath+(i-1));
// 						else lstrcpy(pPath,m_FilePath);
// 						break;
// 					}
// 				}
// 			}
// 			delete [] m_FilePath;
// 			delete [] Longfilename;
// 			delete [] filename;
// 		}
// 		if(pComStr != NULL) {
// 			wchar_t * Comstr = new wchar_t[MAX_PATH_EX];
// 			DWORD ret1 = GetRemoteCommandLineW(processHandle,Comstr,MAX_PATH_EX);
// 			if(ret1 != 0) lstrcpy(pComStr,Comstr);
// 			delete [] Comstr;
// 		}
// 		if(pTimeStr != NULL) {
// 			time_t ProcessCreateTime = 0;
// 			FILETIME l1,l2,l3,l4;
// 			if(GetProcessTimes(processHandle,&l1,&l2,&l3,&l4))
// 			{
// 				ProcessCreateTime = filetime_to_timet(l1);
// 				if(ProcessCreateTime < 0)
// 					ProcessCreateTime = 0;
// 				swprintf_s(pTimeStr,20,_T("%lld"),ProcessCreateTime);
// 			}
// 		}
// 		if(pUserName != NULL) {
// 			wchar_t * pSIDstr = new wchar_t[128];
// 			_tcscpy_s(pSIDstr,128,_T("null"));
// 			GetUserSID(processHandle,pSIDstr);
// 			_tcscpy_s(pUserName,_MAX_FNAME,pSIDstr);
// 			if(_tcscmp(pSIDstr,_T("null")))
// 			{
// 				SID_NAME_USE SidType;
// 				wchar_t * lpName = new wchar_t[_MAX_FNAME];
// 				wchar_t * lpDomain = new wchar_t[_MAX_FNAME];
// 				DWORD dwSize = _MAX_FNAME;
// 				PSID Sid;// = GetBinarySid(pSIDstr);
// 				if(ConvertStringSidToSid(pSIDstr,&Sid))
// 				{
// 					if(LookupAccountSid( NULL , Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType ) )                                    
// 					{
// 						_tcscpy_s(pUserName,_MAX_FNAME,lpName);
// 					}
// 				}
// 				LocalFree(Sid);
// 				delete [] lpDomain;
// 				delete [] lpName;
// 			}
// 			delete [] pSIDstr;
// 		}
// 	}
// 	CloseHandle(processHandle);	
// }

// DWORD Tool::GetRemoteCommandLineW(HANDLE hProcess, LPWSTR pszBuffer, UINT bufferLength) {
//     typedef NTSTATUS (NTAPI* NtQueryInformationProcessPtr)(
//         IN HANDLE ProcessHandle,
//         IN PROCESSINFOCLASS ProcessInformationClass,
//         OUT PVOID ProcessInformation,
//         IN ULONG ProcessInformationLength,
//         OUT PULONG ReturnLength OPTIONAL);

//     typedef ULONG (NTAPI* RtlNtStatusToDosErrorPtr)(NTSTATUS Status);

//     // Locating functions
//     HINSTANCE hNtDll = GetModuleHandleW(L"ntdll.dll");
//     if(hNtDll == NULL) return 0;

//     NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(hNtDll, "NtQueryInformationProcess");
//     RtlNtStatusToDosErrorPtr RtlNtStatusToDosError = (RtlNtStatusToDosErrorPtr)GetProcAddress(hNtDll, "RtlNtStatusToDosError");

//     if(!NtQueryInformationProcess || !RtlNtStatusToDosError) {
//         // printf("Functions cannot be located.\n");
//         FreeLibrary(hNtDll);
//         return 0;
//     }

//     // Get PROCESS_BASIC_INFORMATION
//     PROCESS_BASIC_INFORMATION pbi;
//     ULONG len;
//     NTSTATUS status = NtQueryInformationProcess(
//         hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len);
//     SetLastError(RtlNtStatusToDosError(status));
//     if(NT_ERROR(status) || !pbi.PebBaseAddress) {
//         //printf("NtQueryInformationProcess(ProcessBasicInformation) failed.\n");
//         FreeLibrary(hNtDll);
//         return 0;
//     }

//     // Read PEB memory block
//     SIZE_T bytesRead = 0;
//     //PEB_INTERNAL peb;
//     _PEB peb;
//     if(!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
//         //printf("Reading PEB failed.\n");
//         FreeLibrary(hNtDll);
//         return 0;
//     }

//     // Obtain size of commandline string
//     //RTL_USER_PROCESS_PARAMETERS_I upp;
//     RTL_USER_PROCESS_PARAMETERS upp;
//     if(!ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), &bytesRead)) {
//         //printf("Reading USER_PROCESS_PARAMETERS failed.\n");
//         FreeLibrary(hNtDll);
//         return 0;
//     }

//     //printf("%x\n",peb.BeingDebugged);
//     if(!upp.CommandLine.Length) {
//         //printf("Command line length is 0.\n");
//         FreeLibrary(hNtDll);
//         return 0;
//     }

//     // Check the buffer size
//     DWORD dwNeedLength = (upp.CommandLine.Length+1) / sizeof(wchar_t) +1;
//     if(bufferLength < dwNeedLength) {
//         //printf("Not enough buffer.\n");
//         FreeLibrary(hNtDll);
//         return 0;//dwNeedLength;
//     }

//     // Get the actual command line
//     pszBuffer[dwNeedLength - 1] = L'\0';
//     if(!ReadProcessMemory(hProcess, upp.CommandLine.Buffer, pszBuffer, upp.CommandLine.Length, &bytesRead)) {
//         //printf("Reading command line failed.\n");
//         FreeLibrary(hNtDll);
//         return 0;
//     }
//     FreeLibrary(hNtDll);
//     return (DWORD)bytesRead / sizeof(wchar_t);
// }

// void Tool::GetUserSID(HANDLE hProcess, wchar_t *szUserSID) {
// 	HANDLE hTokenHandle = NULL ;
// 	if(OpenProcessToken(hProcess, TOKEN_QUERY, &hTokenHandle))
// 	{
// 		PTOKEN_USER pUserToken = NULL ;
// 		DWORD dwRequiredLength = 0 ;
// 		if(!GetTokenInformation(hTokenHandle, TokenUser, pUserToken, 0, &dwRequiredLength))
// 		{
// 			pUserToken = (PTOKEN_USER) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwRequiredLength) ;
// 			if(NULL != pUserToken)
// 			{
// 				if(GetTokenInformation(hTokenHandle, TokenUser, pUserToken, dwRequiredLength, &dwRequiredLength))
// 				{
// 					LPTSTR pszSID ;
// 					ConvertSidToStringSid(pUserToken->User.Sid, &pszSID) ;
// 					_tcscpy_s(szUserSID,128,pszSID) ; 
// 					//strUserSID = szSID ;
// 					LocalFree(pszSID) ;
// 				}
// 				HeapFree(GetProcessHeap(), 0, pUserToken) ;
// 			}
// 		}
// 		CloseHandle(hTokenHandle) ;
// 	}
// }

// void Tool::LoadServiceStartCommand(std::map<std::wstring,BOOL> * pImagePath) {
// 	std::map<std::wstring,SerivceInformation> ServiceMap;
// 	LoadInstallService(&ServiceMap);
// 	if(!ServiceMap.empty())
// 	{
// 		std::vector<std::wstring> RegHistorySerivceName;
// 		LoadRegHistorySubKeys(HKEY_LOCAL_MACHINE,TEXT("SYSTEM\\CurrentControlSet\\Services"),&RegHistorySerivceName);
// 		std::map<std::wstring,SerivceInformation>::iterator st;
// 		std::vector<std::wstring>::iterator it;
// 		for(it = RegHistorySerivceName.begin();it != RegHistorySerivceName.end();it++)
// 		{
// 			st = ServiceMap.find((*it).c_str());
// 			if(st == ServiceMap.end())
// 			{
// 				SerivceInformation m_info = {0};
// 				_tcscpy_s(m_info.SerivceName,1024,(*it).c_str());
// 				_tcscpy_s(m_info.DisplayName,1024,(*it).c_str());
// 				_tcscpy_s(m_info.lpBinaryPathName,1024,_T("null"));
// 				_tcscpy_s(m_info.lpDependencies,1024,_T("null"));
// 				_tcscpy_s(m_info.lpDescription,1024,_T("null"));
// 				_tcscpy_s(m_info.lpLoadOrderGroup,1024,_T("null"));
// 				_tcscpy_s(m_info.lpServiceStartName,1024,_T("null"));
// 				//_tcscpy_s(m_info.SerivceName,512,_T("null"));
// 				m_info.dwCurrentState = 0;
// 				m_info.dwErrorControl = 0;
// 				m_info.dwServiceType = 0;
// 				m_info.dwStartType = 0;
// 				m_info.dwTagId = 0;
// 				m_info.IsInstall = FALSE;
// 				wchar_t * m_Path = new wchar_t[MAX_PATH];
// 				swprintf_s(m_Path,MAX_PATH,_T("SYSTEM\\CurrentControlSet\\Services\\%s"),(*it).c_str());
// 				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE,m_Path,_T("ImagePath"),REG_EXPAND_SZ,m_info.lpBinaryPathName);
// 				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE,m_Path,_T("DisplayName"),REG_SZ,m_info.DisplayName);
// 				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE,m_Path,_T("ObjectName"),REG_SZ,m_info.lpServiceStartName);
// 				GetRegHistoryREG_DWORDValue(HKEY_LOCAL_MACHINE,m_Path,_T("Start"),m_info.dwStartType);
// 				GetRegHistoryREG_DWORDValue(HKEY_LOCAL_MACHINE,m_Path,_T("Type"),m_info.dwServiceType);
// 				if(_tcscmp(m_info.lpBinaryPathName,_T("null")))
// 				{
// 					ServiceMap.insert(std::pair<std::wstring,SerivceInformation>(m_info.SerivceName,m_info));
// 				}
// 				delete [] m_Path;
// 				//GetRegHistoryDisplayName((*it),&ServiceMap);
// 			}
// 		}
// 		RegHistorySerivceName.clear();
// 		for(st = ServiceMap.begin();st != ServiceMap.end();st++)
// 		{
// 			if(_tcscmp(st->second.lpBinaryPathName,_T("null"))&&(st->second.dwServiceType != 1 && st->second.dwServiceType != 2) && st->second.dwStartType != 1)
// 				pImagePath->insert(std::pair<std::wstring,BOOL>(st->second.lpBinaryPathName,st->second.IsInstall));
// 		}
// 	}
// 	ServiceMap.clear();
// }

// void Tool::LoadRegHistorySubKeys(HKEY pKey,wchar_t * pPath,std::vector<std::wstring> * wtr)
// {
// 	HKEY hTestKey;
// 	if( RegOpenKeyEx(pKey,
//         pPath,
//         0,
//         KEY_READ,
//         &hTestKey) == ERROR_SUCCESS
//       )
// 	{
// 		QueryKey(hTestKey,wtr);
// 	}
// 	RegCloseKey(hTestKey);
// }

// void Tool::LoadAutoRunStartCommand(std::set<std::wstring> * pImagePath) {
// 	std::vector<AutoRunInfo> m_StartRunInfo;
// 	wchar_t * Pathstr = new wchar_t[MAX_PATH_EX];
// 	if(GetAllUserStartUp(Pathstr))
// 	{
// 		SearchAutoRunFile(&m_StartRunInfo,Pathstr);
// 	}

// 	LoadRegisterAutoRun(&m_StartRunInfo);

// 	delete [] Pathstr;
// 	std::vector<std::wstring> ThisPCAllUser;
// 	GetThisPCAllUser(&ThisPCAllUser);
// 	if(!ThisPCAllUser.empty())
// 	{
// 		wchar_t * UserName = new wchar_t[256];
// 		std::vector<std::wstring>::iterator ut;
// 		for(ut = ThisPCAllUser.begin();ut != ThisPCAllUser.end();ut++)
// 		{
// 			swprintf_s(UserName,256,L"%s",(*ut).c_str());
// 			wchar_t * m_Path = new wchar_t[MAX_PATH];
// 			if(GetUserStartUp(UserName,L"Startup",m_Path))
// 			{
// 				SearchAutoRunFile(&m_StartRunInfo,m_Path);
// 			}
// 			delete [] m_Path;
// 			LoadRegisterAutoRunFromUser(&m_StartRunInfo,UserName);
// 		}
// 		delete [] UserName;
// 	}
// 	ThisPCAllUser.clear();
// 	std::vector<AutoRunInfo>::iterator it;
// 	for(it = m_StartRunInfo.begin();it != m_StartRunInfo.end();it++)
// 	{
// 		if(_tcscmp((*it).m_Command,_T("null")))
// 			pImagePath->insert((*it).m_Command);
// 	}
// 	m_StartRunInfo.clear();
// }

// void Tool::GetThisPCAllUser(std::vector<std::wstring> * wtr)
// {
// 	HKEY hTestKey;
// 	if( RegOpenKeyEx(HKEY_LOCAL_MACHINE,
//         TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"),
//         0,
//         KEY_READ,
//         &hTestKey) == ERROR_SUCCESS
//       )
// 	{
// 		QueryKey(hTestKey,wtr);
// 	}
// 	RegCloseKey(hTestKey);
// }

// BOOL Tool::GetUserStartUp(wchar_t * pUserName,wchar_t * pDirectory,wchar_t * pPath)
// {
// 	//if(SHGetSpecialFolderPath( NULL, wtr, CSIDL_STARTUP, false ))
// 	//	return TRUE;
// 	//else
// 	//	return FALSE;
// 	BOOL ret = FALSE;
// 	HKEY hKey = NULL;
// 	LONG lResult;
// 	wchar_t * RegPath = new wchar_t[512];
// 	swprintf_s(RegPath,512,_T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"),pUserName);
// 	//HKEY_CURRENT_USER,_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
// 	lResult = RegOpenKeyEx(HKEY_USERS,RegPath, 0, KEY_QUERY_VALUE, &hKey);

// 	if (lResult == ERROR_SUCCESS) 
// 	{

// 		DWORD dwValues, dwMaxValueNameLen, dwMaxValueLen;
// 		LONG lRet = ::RegQueryInfoKey(hKey, 
// 									NULL, NULL,    // lpClass, lpcClass
// 									NULL,          // lpReserved
// 									NULL, NULL,    // lpcSubKeys, lpcMaxSubKeyLen
// 									NULL,          // lpcMaxClassLen
// 									&dwValues,
// 									&dwMaxValueNameLen,
// 									&dwMaxValueLen,
// 									NULL,          // lpcbSecurityDescriptor
// 									NULL);         // lpftLastWriteTime
// 		if(ERROR_SUCCESS == lRet)
// 		{  
// 			// allocate enough to fit max. length name and value
// 			LPTSTR pszName = new wchar_t[dwMaxValueNameLen + 1];
// 			LPBYTE lpData   = new BYTE[dwMaxValueLen+1];
// 			memset(lpData,'\0',dwMaxValueLen+1);
// 			for(DWORD dwIndex = 0; dwIndex < dwValues; dwIndex++)
// 			{
// 				DWORD dwNameSize  = dwMaxValueNameLen + 1;
// 				DWORD dwValueSize = dwMaxValueLen;
// 				DWORD dwType;
// 				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize, 0, &dwType, lpData, &dwValueSize);
// 				//wprintf(L"1-%s\n",pszName);
// 				if(REG_SZ == dwType && !wcscmp(pszName,pDirectory))
// 				{
// 					ret = TRUE;
// 					//memcpy(pPath,lpData,MAX_PATH);
// 					swprintf_s(pPath,MAX_PATH,_T("%s"),lpData);
// 				}
// 			}
// 			delete []pszName;
// 			delete []lpData;
// 		}
// 	}
// 	RegCloseKey(hKey);
// 	delete [] RegPath;
// 	return ret;
// }

// void Tool::LoadRegisterAutoRun(std::vector<AutoRunInfo> *pInfo)
// {
// 	#ifndef _M_IX86
// 	LoadRegisterInfo(pInfo,HKEY_LOCAL_MACHINE,_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
// 	LoadRegisterInfo(pInfo,HKEY_LOCAL_MACHINE,_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
// 	LoadRegisterInfo(pInfo,HKEY_LOCAL_MACHINE,_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"));
// 	LoadRegisterInfo(pInfo,HKEY_LOCAL_MACHINE,_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"));
// 	LoadRegisterInfo(pInfo,HKEY_LOCAL_MACHINE,_T("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"));
// 	LoadRegisterInfo(pInfo,HKEY_LOCAL_MACHINE,_T("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
// 	LoadRegisterInfoEx(pInfo,HKEY_LOCAL_MACHINE,_T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"),_T("AlternateShell"),false,false);
// 	LoadRegisterInfoEx(pInfo,HKEY_LOCAL_MACHINE,_T("SOFTWARE\\Microsoft\\Active Setup\\Installed Components"),_T("StubPath"),true,false);
// 	LoadRegisterInfoEx(pInfo,HKEY_LOCAL_MACHINE,_T("SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components"),_T("StubPath"),true,false);

// 	LoadRegisterInfox32(pInfo,HKEY_LOCAL_MACHINE,_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
// 	LoadRegisterInfox32(pInfo,HKEY_LOCAL_MACHINE,_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
// 	LoadRegisterInfox32(pInfo,HKEY_LOCAL_MACHINE,_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"));
// 	LoadRegisterInfox32(pInfo,HKEY_LOCAL_MACHINE,_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"));
// 	LoadRegisterInfoEx(pInfo,HKEY_LOCAL_MACHINE,_T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"),_T("StubPath"),true,true);
// 	LoadRegisterInfoEx(pInfo,HKEY_LOCAL_MACHINE,_T("SOFTWARE\\Microsoft\\Active Setup\\Installed Components"),_T("StubPath"),true,true);
// 	LoadRegisterInfoEx(pInfo,HKEY_LOCAL_MACHINE,_T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"),_T("AlternateShell"),false,true);
// 	#else

// 	LoadRegisterInfo(pInfo,HKEY_LOCAL_MACHINE,_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
// 	LoadRegisterInfo(pInfo,HKEY_LOCAL_MACHINE,_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
// 	LoadRegisterInfo(pInfo,HKEY_LOCAL_MACHINE,_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"));
// 	LoadRegisterInfo(pInfo,HKEY_LOCAL_MACHINE,_T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"));
// 	LoadRegisterInfoEx(pInfo,HKEY_LOCAL_MACHINE,_T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"),_T("StubPath"),true);
// 	LoadRegisterInfoEx(pInfo,HKEY_LOCAL_MACHINE,_T("SOFTWARE\\Microsoft\\Active Setup\\Installed Components"),_T("StubPath"),true);
// 	LoadRegisterInfoEx(pInfo,HKEY_LOCAL_MACHINE,_T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"),_T("AlternateShell"),false,false);
// 	#endif
// }

// void Tool::LoadRegisterInfoEx(std::vector<AutoRunInfo> *pInfo,HKEY pKey,wchar_t * RegPath,wchar_t * KeyStr,bool IsChildItem,bool Is32Bit)
// {
// 	if(IsChildItem)
// 	{
// 		std::vector<std::wstring> strInfo;
// 		LoadRegisterChildItem(&strInfo,pKey,RegPath,Is32Bit);
// 		if(!strInfo.empty())
// 		{
// 			std::vector<std::wstring>::iterator it;
// 			for(it = strInfo.begin();it != strInfo.end();it++)
// 			{
// 				wchar_t * m_RegPath = new wchar_t[MAX_PATH_EX];
// 				swprintf_s(m_RegPath,MAX_PATH_EX,L"%s\\%s",RegPath,(*it).c_str());
// 				LoadRegisterDataEx(pInfo,pKey,m_RegPath,KeyStr,Is32Bit);
// 				delete [] m_RegPath;
// 			}
// 		}
// 		strInfo.clear();
// 	}
// 	else
// 	{
// 		LoadRegisterDataEx(pInfo,pKey,RegPath,KeyStr,Is32Bit);
// 	}
// }

// void Tool::LoadRegisterChildItem(std::vector<std::wstring> * pStrInfo,HKEY pKey,wchar_t * RegPath,bool Is32Bit)
// {
// 	if(Is32Bit)
// 	{
// 		HKEY hTestKey;
// 		if( RegOpenKeyEx(pKey,
// 			RegPath,
// 			0,
// 			KEY_READ| KEY_WOW64_32KEY,
// 			&hTestKey) == ERROR_SUCCESS
// 		  )
// 		{
// 			QueryKey(hTestKey,pStrInfo);
// 		}
// 		RegCloseKey(hTestKey);
// 	}
// 	else
// 	{
// 		HKEY hTestKey;
// 		if( RegOpenKeyEx(pKey,
// 			RegPath,
// 			0,
// 			KEY_READ,
// 			&hTestKey) == ERROR_SUCCESS
// 		  )
// 		{
// 			QueryKey(hTestKey,pStrInfo);
// 		}
// 		RegCloseKey(hTestKey);
// 	}
// }

// void Tool::QueryKey(HKEY hKey,std::vector<std::wstring> *pSub) 
// { 
//     wchar_t    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
//     DWORD    cbName;                   // size of name string 
//     wchar_t    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
//     DWORD    cchClassName = MAX_PATH;  // size of class string 
//     DWORD    cSubKeys=0;               // number of subkeys 
//     DWORD    cbMaxSubKey;              // longest subkey size 
//     DWORD    cchMaxClass;              // longest class string 
//     DWORD    cValues;              // number of values for key 
//     DWORD    cchMaxValue;          // longest value name 
//     DWORD    cbMaxValueData;       // longest value data 
//     DWORD    cbSecurityDescriptor; // size of security descriptor 
//     FILETIME ftLastWriteTime;      // last write time 

//     DWORD i, retCode; 

//     //wchar_t  achValue[MAX_VALUE_NAME]; 
//     DWORD cchValue = MAX_VALUE_NAME; 

//     // Get the class name and the value count. 
//     retCode = RegQueryInfoKey(
//         hKey,                    // key handle 
//         achClass,                // buffer for class name 
//         &cchClassName,           // size of class string 
//         NULL,                    // reserved 
//         &cSubKeys,               // number of subkeys 
//         &cbMaxSubKey,            // longest subkey size 
//         &cchMaxClass,            // longest class string 
//         &cValues,                // number of values for this key 
//         &cchMaxValue,            // longest value name 
//         &cbMaxValueData,         // longest value data 
//         &cbSecurityDescriptor,   // security descriptor 
//         &ftLastWriteTime);       // last write time 

//     // Enumerate the subkeys, until RegEnumKeyEx fails.

//     if (cSubKeys)
//     {
//        // printf( "\nNumber of subkeys: %d\n", cSubKeys);

//         for (i=0; i<cSubKeys; i++) 
//         { 
//             cbName = MAX_KEY_LENGTH;
//             retCode = RegEnumKeyEx(hKey, i,
//                      achKey, 
//                      &cbName, 
//                      NULL, 
//                      NULL, 
//                      NULL, 
//                      &ftLastWriteTime); 
//             if (retCode == ERROR_SUCCESS) 
//             {
//                // _tprintf(TEXT("(%d) %s\n"), i+1, achKey);
// 				pSub->push_back(achKey);
//             }
//         }
//     } 

// }

// void Tool::LoadRegisterDataEx(std::vector<AutoRunInfo> *pInfo,HKEY pKey,wchar_t * RegPath,wchar_t * KeyStr,bool Is32Bit)
// {
// 	HKEY hKey = NULL;
// 	LONG lResult;
// 	if(Is32Bit)
// 		lResult = RegOpenKeyEx(pKey,RegPath, 0, KEY_QUERY_VALUE| KEY_WOW64_32KEY, &hKey);
// 	else
// 		lResult = RegOpenKeyEx(pKey,RegPath, 0, KEY_QUERY_VALUE, &hKey);
// 	if (lResult == ERROR_SUCCESS) 
// 	{

// 		DWORD dwValues, dwMaxValueNameLen, dwMaxValueLen;
// 		LONG lRet = ::RegQueryInfoKey(hKey, 
// 									NULL, NULL,    // lpClass, lpcClass
// 									NULL,          // lpReserved
// 									NULL, NULL,    // lpcSubKeys, lpcMaxSubKeyLen
// 									NULL,          // lpcMaxClassLen
// 									&dwValues,
// 									&dwMaxValueNameLen,
// 									&dwMaxValueLen,
// 									NULL,          // lpcbSecurityDescriptor
// 									NULL);         // lpftLastWriteTime
// 		if(ERROR_SUCCESS == lRet)
// 		{  
// 			// allocate enough to fit max. length name and value
// 			LPTSTR pszName = new wchar_t[dwMaxValueNameLen + 1];
// 			LPBYTE lpData   = new BYTE[dwMaxValueLen+1];
// 			memset(lpData,'\0',dwMaxValueLen+1);
// 			for(DWORD dwIndex = 0; dwIndex < dwValues; dwIndex++)
// 			{
// 				DWORD dwNameSize  = dwMaxValueNameLen + 1;
// 				DWORD dwValueSize = dwMaxValueLen;
// 				DWORD dwType;
// 				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize, 0, &dwType, lpData, &dwValueSize);
// 				//wprintf(L"1-%s\n",pszName);
// 				if(REG_SZ == dwType || REG_EXPAND_SZ == dwType)
// 				{
// 					if(!_tcscmp(KeyStr,_T("*")))
// 					{
// 						AutoRunInfo m_Info;
// 						wcscpy_s(m_Info.StartName,MAX_PATH,pszName);
// 						wchar_t pCom[MAX_PATH_EX];//= new wchar_t[MAX_PATH_EX];
// 						try
// 						{
// 							//memcpy(pCom ,lpData,MAX_PATH_EX);
// 							swprintf_s(pCom,MAX_PATH_EX,_T("%s"),lpData);
// 						}
// 						catch(...)
// 						{
// 							_tcscpy_s(pCom,MAX_PATH_EX,_T("null"));
// 						}
// 						if(_tcscmp(pCom,_T("null")))
// 						{
// 							ExpandEnvironmentStrings(pCom, m_Info.m_Command, MAX_PATH_EX);
// 							/*memcpy(m_Info.m_Command,lpData,MAX_PATH_EX);*/
// 							if(Is32Bit)
// 							{
// 								if(pKey == HKEY_USERS)
// 									swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("x86:HKEY_USERS\\%s"),RegPath);
// 								else if(pKey == HKEY_LOCAL_MACHINE)
// 									swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("x86:HKEY_LOCAL_MACHINE\\%s"),RegPath);
// 								else
// 									swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("x86:%s"),RegPath);
// 								pInfo->push_back(m_Info);
// 							}
// 							else
// 							{
// 								if(pKey == HKEY_USERS)
// 								{
// 									swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("HKEY_USERS\\%s"),RegPath);
// 								}
// 								else if(pKey == HKEY_LOCAL_MACHINE)
// 								{
// 									swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("HKEY_LOCAL_MACHINE\\%s"),RegPath);
// 								}
// 								else
// 								{
// 									swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("%s"),RegPath);
// 								}
// 								pInfo->push_back(m_Info);
// 							}
// 						}
// 					}
// 					else
// 					{
// 						if(!_tcsicmp(KeyStr,pszName))
// 						{
// 							AutoRunInfo m_Info;
// 							wcscpy_s(m_Info.StartName,MAX_PATH,pszName);
// 							wchar_t pCom[MAX_PATH_EX];//= new wchar_t[MAX_PATH_EX];
// 							try
// 							{
// 								memcpy(pCom ,lpData,MAX_PATH_EX);
// 							}
// 							catch(...)
// 							{
// 								_tcscpy_s(pCom,MAX_PATH_EX,_T("null"));
// 							}
// 							if(_tcscmp(pCom,_T("null")))
// 							{
// 								ExpandEnvironmentStrings(pCom, m_Info.m_Command, MAX_PATH_EX);
// 								if(Is32Bit)
// 								{
// 									if(pKey == HKEY_USERS)
// 										swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("x86:HKEY_USERS\\%s"),RegPath);
// 									else if(pKey == HKEY_LOCAL_MACHINE)
// 										swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("x86:HKEY_LOCAL_MACHINE\\%s"),RegPath);
// 									else
// 										swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("x86:%s"),RegPath);
// 									pInfo->push_back(m_Info);
// 								}
// 								else
// 								{
// 									if(pKey == HKEY_USERS)
// 									{
// 										swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("HKEY_USERS\\%s"),RegPath);
// 									}
// 									else if(pKey == HKEY_LOCAL_MACHINE)
// 									{
// 										swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("HKEY_LOCAL_MACHINE\\%s"),RegPath);
// 									}
// 									else
// 									{
// 										swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("%s"),RegPath);
// 									}
// 									pInfo->push_back(m_Info);
// 								}
// 							}
// 						}
// 					}	
// 				}
// 			}
// 			delete []pszName;
// 			delete []lpData;
// 		}
// 	}
// 	RegCloseKey(hKey);
// }

// void Tool::LoadInstallService(std::map<std::wstring,SerivceInformation> * pServiceMap) {
// 	SC_HANDLE hHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
//     if (NULL == hHandle) return;

// 	//map<wstring,wstring> ServiceMap;
//     ENUM_SERVICE_STATUS service;

//     DWORD dwBytesNeeded = 0;
//     DWORD dwServicesReturned = 0;
//     DWORD dwResumedHandle = 0;
//     DWORD dwServiceType = SERVICE_WIN32 | SERVICE_DRIVER;
//     // Query services
//     BOOL retVal = EnumServicesStatus(hHandle, dwServiceType, SERVICE_STATE_ALL, 
//         &service, sizeof(ENUM_SERVICE_STATUS), &dwBytesNeeded, &dwServicesReturned,
//         &dwResumedHandle);
//     if (!retVal) 
// 	{
//         // Need big buffer
//         if (ERROR_MORE_DATA == GetLastError()) 
// 		{
//             // Set the buffer
//             DWORD dwBytes = sizeof(ENUM_SERVICE_STATUS) + dwBytesNeeded;
//             ENUM_SERVICE_STATUS* pServices = NULL;
//             pServices = new ENUM_SERVICE_STATUS [dwBytes];
//             // Now query again for services
//             EnumServicesStatus(hHandle, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL, 
//                 pServices, dwBytes, &dwBytesNeeded, &dwServicesReturned, &dwResumedHandle);
//             // now traverse each service to get information
//             for (unsigned iIndex = 0; iIndex < dwServicesReturned; iIndex++) 
// 			{
// 				//(pServices + iIndex)->ServiceStatus.
// 				SerivceInformation m_info = {0};
// 				_tcscpy_s(m_info.DisplayName,1024,_T("null"));
// 				_tcscpy_s(m_info.lpBinaryPathName,1024,_T("null"));
// 				_tcscpy_s(m_info.lpDependencies,1024,_T("null"));
// 				_tcscpy_s(m_info.lpDescription,1024,_T("null"));
// 				_tcscpy_s(m_info.lpLoadOrderGroup,1024,_T("null"));
// 				_tcscpy_s(m_info.lpServiceStartName,1024,_T("null"));
// 				_tcscpy_s(m_info.SerivceName,1024,_T("null"));
// 				m_info.dwCurrentState = 0;
// 				m_info.dwErrorControl = 0;
// 				m_info.dwServiceType = 0;
// 				m_info.dwStartType = 0;
// 				m_info.dwTagId = 0;
// 				//(pServices + iIndex)->ServiceStatus.
// 				//m_info.SerivceName.Format(_T("%s"),(pServices + iIndex)->lpServiceName);
// 				swprintf_s(m_info.SerivceName,1024,_T("%s"),(pServices + iIndex)->lpServiceName);
// 				//m_info.DisplayName.Format(_T("%s"),(pServices + iIndex)->lpDisplayName);
// 				swprintf_s(m_info.DisplayName,1024,_T("%s"),(pServices + iIndex)->lpDisplayName);
// 				m_info.dwCurrentState = (pServices + iIndex)->ServiceStatus.dwCurrentState;
// 				DoQuerySvc(&m_info);
// 				m_info.IsInstall = TRUE;
// 				//wcscpy_s(ServiceName,MAX_PATH,(pServices + iIndex)->lpServiceName);
// 				//wcscpy_s(DisplayName,MAX_PATH,(pServices + iIndex)->lpDisplayName);
// 				pServiceMap->insert(std::pair<std::wstring,SerivceInformation>(m_info.SerivceName,m_info));
//             }
//             delete [] pServices;
//             pServices = NULL;
//         }
//         // there is any other reason
//         else 
// 		{
//             //ErrorDescription(GetLastError());
//         }
//     }
//     if (!CloseServiceHandle(hHandle)) 
// 	{
//         //ErrorDescription(GetLastError());
//     }
//     else 
// 	{
//         //cout << "Close SCM sucessfully" << endl;
// 		//wprintf(_T("Close SCM sucessfully\n"));
// 	}
// // get the description of error
// 	//ServiceMap.clear();
// }

// void Tool::DoQuerySvc(SerivceInformation* pInfo) {
// 	SC_HANDLE schSCManager;
//     SC_HANDLE schService;
//     LPQUERY_SERVICE_CONFIG lpsc = NULL; 
//     LPSERVICE_DESCRIPTION lpsd = NULL;
//     DWORD dwBytesNeeded, cbBufSize, dwError; 

//     // Get a handle to the SCM database. 

//     schSCManager = OpenSCManager( 
//         NULL,                    // local computer
//         NULL,                    // ServicesActive database 
//         SC_MANAGER_ALL_ACCESS);  // full access rights 

//     if (NULL == schSCManager) 
//     {
//        // printf("OpenSCManager failed (%d)\n", GetLastError());
//         return;
//     }

//     // Get a handle to the service.

//     schService = OpenService( 
//         schSCManager,          // SCM database 
//         pInfo->SerivceName,             // name of service 
//         SERVICE_QUERY_CONFIG); // need query config access 

//     if (schService == NULL)
//     { 
//        // printf("OpenService failed (%d)\n", GetLastError()); 
//         CloseServiceHandle(schSCManager);
//         return;
//     }

//     // Get the configuration information.

//     if( !QueryServiceConfig( 
//         schService, 
//         NULL, 
//         0, 
//         &dwBytesNeeded))
//     {
//         dwError = GetLastError();
//         if( ERROR_INSUFFICIENT_BUFFER == dwError )
//         {
//             cbBufSize = dwBytesNeeded;
//             lpsc = (LPQUERY_SERVICE_CONFIG) LocalAlloc(LMEM_FIXED, cbBufSize);
//         }
//         else
//         {
//            // printf("QueryServiceConfig failed (%d)", dwError);
//             goto cleanup; 
//         }
//     }

//     if( !QueryServiceConfig( 
//         schService, 
//         lpsc, 
//         cbBufSize, 
//         &dwBytesNeeded) ) 
//     {
//         //printf("QueryServiceConfig failed (%d)", GetLastError());
//         goto cleanup;
//     }

//     if( !QueryServiceConfig2( 
//         schService, 
//         SERVICE_CONFIG_DESCRIPTION,
//         NULL, 
//         0, 
//         &dwBytesNeeded))
//     {
//         dwError = GetLastError();
//         if( ERROR_INSUFFICIENT_BUFFER == dwError )
//         {
//             cbBufSize = dwBytesNeeded;
//             lpsd = (LPSERVICE_DESCRIPTION) LocalAlloc(LMEM_FIXED, cbBufSize);
//         }
//         else
//         {
//            // printf("QueryServiceConfig2 failed (%d)", dwError);
//             goto cleanup; 
//         }
//     }

//     if (! QueryServiceConfig2( 
//         schService, 
//         SERVICE_CONFIG_DESCRIPTION,
//         (LPBYTE) lpsd, 
//         cbBufSize, 
//         &dwBytesNeeded) ) 
//     {
//        // printf("QueryServiceConfig2 failed (%d)", GetLastError());
//         goto cleanup;
//     }

//     // Print the configuration information.

//    // _tprintf(TEXT("%s configuration: \n"), szSvcName);
// 	pInfo->dwServiceType = lpsc->dwServiceType;
//     //_tprintf(TEXT("  Type: 0x%x\n"), lpsc->dwServiceType);
// 	pInfo->dwStartType = lpsc->dwStartType;
//     //_tprintf(TEXT("  Start Type: 0x%x\n"), lpsc->dwStartType);
// 	pInfo->dwErrorControl = lpsc->dwErrorControl;
//     //_tprintf(TEXT("  Error Control: 0x%x\n"), lpsc->dwErrorControl);
// 	swprintf_s(pInfo->lpBinaryPathName,1024,_T("%s"),lpsc->lpBinaryPathName);
// 	//pInfo->lpBinaryPathName.Format(_T("%s"),lpsc->lpBinaryPathName);
//     //_tprintf(TEXT("  Binary path: %s\n"), lpsc->lpBinaryPathName);
// 	swprintf_s(pInfo->lpServiceStartName,1024,_T("%s"),lpsc->lpServiceStartName);
// 	//pInfo->lpServiceStartName.Format(_T("%s"),lpsc->lpServiceStartName);
//     //_tprintf(TEXT("  Account: %s\n"), lpsc->lpServiceStartName);

//     if (lpsd->lpDescription != NULL && lstrcmp(lpsd->lpDescription, TEXT("")) != 0)
// 		swprintf_s(pInfo->lpDescription,1024,_T("%s"),lpsd->lpDescription);
// 		//pInfo->lpDescription.Format(_T("%s"),lpsd->lpDescription);
//        // _tprintf(TEXT("  Description: %s\n"), lpsd->lpDescription);
//     if (lpsc->lpLoadOrderGroup != NULL && lstrcmp(lpsc->lpLoadOrderGroup, TEXT("")) != 0)
// 		swprintf_s(pInfo->lpLoadOrderGroup,1024,_T("%s"),lpsc->lpLoadOrderGroup);
// 		//pInfo->lpLoadOrderGroup.Format(_T("%s"),lpsc->lpLoadOrderGroup);
//         //_tprintf(TEXT("  Load order group: %s\n"), lpsc->lpLoadOrderGroup);
//     if (lpsc->dwTagId != 0)
// 		pInfo->dwTagId = lpsc->dwTagId;
//        // _tprintf(TEXT("  Tag ID: %d\n"), lpsc->dwTagId);
//     if (lpsc->lpDependencies != NULL && lstrcmp(lpsc->lpDependencies, TEXT("")) != 0)
// 		swprintf_s(pInfo->lpDependencies,1024,_T("%s"),lpsc->lpDependencies);
// 		//pInfo->lpDependencies.Format(_T("%s"),lpsc->lpDependencies);
//         //_tprintf(TEXT("  Dependencies: %s\n"), lpsc->lpDependencies);

//     LocalFree(lpsc); 
//     LocalFree(lpsd);

// cleanup:
//     CloseServiceHandle(schService); 
//     CloseServiceHandle(schSCManager);
// }

// bool Tool::GetRegHistoryREG_SZValue(HKEY pKey,wchar_t * pPath,wchar_t * pName,DWORD pType,wchar_t * pValue) {
// 	bool ret = true;
// 	HKEY hKey = NULL;
// 	LONG lResult;


// 	lResult = RegOpenKeyEx(pKey,pPath, 0, KEY_QUERY_VALUE, &hKey);

// 	if (lResult == ERROR_SUCCESS) 
// 	{

// 		DWORD dwValues, dwMaxValueNameLen, dwMaxValueLen;
// 		LONG lRet = ::RegQueryInfoKey(hKey, 
// 									NULL, NULL,    // lpClass, lpcClass
// 									NULL,          // lpReserved
// 									NULL, NULL,    // lpcSubKeys, lpcMaxSubKeyLen
// 									NULL,          // lpcMaxClassLen
// 									&dwValues,
// 									&dwMaxValueNameLen,
// 									&dwMaxValueLen,
// 									NULL,          // lpcbSecurityDescriptor
// 									NULL);         // lpftLastWriteTime
// 		if(ERROR_SUCCESS == lRet)
// 		{  
// 			// allocate enough to fit max. length name and value
// 			LPTSTR pszName = new wchar_t[dwMaxValueNameLen + 1];
// 			LPBYTE lpData   = new BYTE[dwMaxValueLen+1];
// 			memset(lpData,'\0',dwMaxValueLen+1);
// 			for(DWORD dwIndex = 0; dwIndex < dwValues; dwIndex++)
// 			{
// 				DWORD dwNameSize  = dwMaxValueNameLen + 1;
// 				DWORD dwValueSize = dwMaxValueLen;
// 				DWORD dwType;
// 				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize, 0, &dwType, lpData, &dwValueSize);
// 				//wprintf(L"1-%s\n",pszName);
// 				if(pType == dwType && !wcscmp(pszName,pName))
// 				{
// 					swprintf_s(pValue,512,_T("%s"),lpData);
// 					//memcpy(pPath,lpData,MAX_PATH);
// 				}
// 			}
// 			delete []pszName;
// 			delete []lpData;
// 		}
// 	}
// 	RegCloseKey(hKey);
// 	return ret;
// }

// bool Tool::GetRegHistoryREG_DWORDValue(HKEY pKey,wchar_t * pPath,wchar_t * pName,DWORD & pValue) {
// 	bool ret = true;
// 	long lRet;
// 	HKEY hKey;
// 	DWORD m_Value;
// 	DWORD dwType = REG_DWORD;
// 	DWORD dwValue;
// 	lRet = RegOpenKeyEx(pKey,pPath,0,KEY_QUERY_VALUE, &hKey);   
// 	if(lRet == ERROR_SUCCESS)
// 	{
// 		lRet = RegQueryValueEx(hKey,pName,0, &dwType,(LPBYTE)&m_Value,&dwValue);   
// 		if(lRet == ERROR_SUCCESS)
// 		{
// 			pValue = m_Value;
// 		}
// 		else
// 		{
// 			ret = false;
// 		}
// 	}
// 	else
// 	{
// 		ret = false;
// 	}
// 	RegCloseKey(hKey);
// 	return ret;
// }

// BOOL Tool::GetAllUserStartUp(wchar_t * wtr) {
// 	//if(SHGetSpecialFolderPath( NULL, wtr, CSIDL_COMMON_STARTUP, false ))
// 	//	return TRUE;
// 	//else
// 	//	return FALSE;
// 	BOOL ret = FALSE;
// 	HKEY hKey = NULL;
// 	LONG lResult;
// 	wchar_t * RegPath = new wchar_t[512];
// 	swprintf_s(RegPath,512,_T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"));
// 	//HKEY_CURRENT_USER,_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
// 	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE,RegPath, 0, KEY_QUERY_VALUE, &hKey);

// 	if (lResult == ERROR_SUCCESS) 
// 	{

// 		DWORD dwValues, dwMaxValueNameLen, dwMaxValueLen;
// 		LONG lRet = ::RegQueryInfoKey(hKey, 
// 									NULL, NULL,    // lpClass, lpcClass
// 									NULL,          // lpReserved
// 									NULL, NULL,    // lpcSubKeys, lpcMaxSubKeyLen
// 									NULL,          // lpcMaxClassLen
// 									&dwValues,
// 									&dwMaxValueNameLen,
// 									&dwMaxValueLen,
// 									NULL,          // lpcbSecurityDescriptor
// 									NULL);         // lpftLastWriteTime
// 		if(ERROR_SUCCESS == lRet)
// 		{  
// 			// allocate enough to fit max. length name and value
// 			LPTSTR pszName = new wchar_t[dwMaxValueNameLen + 1];
// 			LPBYTE lpData   = new BYTE[dwMaxValueLen+1];
// 			memset(lpData,'\0',dwMaxValueLen+1);
// 			for(DWORD dwIndex = 0; dwIndex < dwValues; dwIndex++)
// 			{
// 				DWORD dwNameSize  = dwMaxValueNameLen + 1;
// 				DWORD dwValueSize = dwMaxValueLen;
// 				DWORD dwType;
// 				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize, 0, &dwType, lpData, &dwValueSize);
// 				//wprintf(L"1-%s\n",pszName);
// 				if(REG_SZ == dwType && !wcscmp(pszName,L"Common Startup"))
// 				{
// 					ret = TRUE;
// 					//memcpy(wtr,lpData,MAX_PATH_EX);
// 					swprintf_s(wtr,MAX_PATH_EX,_T("%s"),lpData);
// 				}
// 			}
// 			delete []pszName;
// 			delete []lpData;
// 		}
// 	}
// 	RegCloseKey(hKey);
// 	delete [] RegPath;
// 	return ret;
// }

// void Tool::SearchAutoRunFile(std::vector<AutoRunInfo> *pInfo,wchar_t * m_Path) {
// 	wchar_t *szTempPath = new wchar_t[MAX_PATH_EX];
//     lstrcpy(szTempPath, m_Path);
//     lstrcat(szTempPath, TEXT("\\*.*"));
// 	WIN32_FIND_DATA fd;
// 	HANDLE hSearch = FindFirstFile(szTempPath, &fd);
// 	if (INVALID_HANDLE_VALUE != hSearch) 
// 	{
// 		do
// 		{
// 			if((0 == (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) && (0 != lstrcmp(fd.cFileName, TEXT(".")))&& (0 != lstrcmp(fd.cFileName, TEXT(".."))))
// 			{
// 				wchar_t *szPath = new wchar_t[MAX_PATH_EX];
// 				swprintf_s(szPath,MAX_PATH_EX,L"%s\\%s",m_Path,fd.cFileName);
// 				try
// 				{
// 					ParsingStartupFile(pInfo,szPath,fd.cFileName);
// 				}
// 				catch(...){}
// 				delete [] szPath;
// 			}
// 		} while (FindNextFile(hSearch, &fd) != FALSE);
// 		FindClose(hSearch);
// 	}
// 	delete [] szTempPath;
// }

// void Tool::ParsingStartupFile(std::vector<AutoRunInfo> *pInfo,wchar_t * m_Path,wchar_t *m_Name) {
// 	wchar_t * ExtStr = new wchar_t[100];
// 	for (int i = (int)wcslen(m_Name)-1;i>=0;i--)
// 	{
// 		if (m_Name[i] == '.')
// 		{
// 			wcscpy_s(ExtStr,100,m_Name+(i+1));
// 			break;
// 		}
// 	}
// 	if(!_wcsicmp(ExtStr,_T("lnk")))
// 	{
// 		AutoRunInfo m_Info;
// 		wcscpy_s(m_Info.StartName,MAX_PATH,m_Name);
// 		wcscpy_s(m_Info.InfoLocation,MAX_PATH_EX,m_Path);
// 		CoInitialize(NULL);  
// 		ResolveIt(NULL, m_Path, m_Info.m_Command, MAX_PATH_EX);   
// 		CoUninitialize();
// 		pInfo->push_back(m_Info);
// 	}
// 	else if(!_wcsicmp(ExtStr,_T("ini")))
// 	{
// 	}
// 	else 
// 	{
// 		AutoRunInfo m_Info;
// 		wcscpy_s(m_Info.m_Command,MAX_PATH_EX,m_Path);
// 		wcscpy_s(m_Info.StartName,MAX_PATH,m_Name);
// 		wcscpy_s(m_Info.InfoLocation,MAX_PATH_EX,m_Path);
// 		pInfo->push_back(m_Info);
// 	}
// 	delete [] ExtStr;
// }

// HRESULT Tool::ResolveIt(HWND hwnd, wchar_t *lpszLinkFile, wchar_t *lpszPath, int iPathBufferSize)   
// {   
//     HRESULT hres;   
//     IShellLink* psl;   
//     WIN32_FIND_DATA wfd;   

//     *lpszPath = 0; // Assume failure   

//     // Get a pointer to the IShellLink interface. It is assumed that CoInitialize  
//     // has already been called.   
//     hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);   
//     if (SUCCEEDED(hres))   
//     {   
//         IPersistFile* ppf;   

//         // Get a pointer to the IPersistFile interface.   
//         hres = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);   

//         if (SUCCEEDED(hres))   
//         {  
//             // Add code here to check return value from MultiByteWideChar   
//             // for success.  

//             // Load the shortcut.   
//             hres = ppf->Load(lpszLinkFile, STGM_READ);   

//             if (SUCCEEDED(hres))   
//             {   
//                 // Resolve the link.   
//                 hres = psl->Resolve(hwnd, SLR_NO_UI);   

//                 if (SUCCEEDED(hres))   
//                 {   
//                     // Get the path to the link target.   
//                     hres = psl->GetPath(lpszPath, MAX_PATH, (WIN32_FIND_DATA*)&wfd, SLGP_RAWPATH);   
//                 }   
//             }   

//             // Release the pointer to the IPersistFile interface.   
//             ppf->Release();   
//         }   

//         // Release the pointer to the IShellLink interface.   
//         psl->Release();   
//     }   
//     return hres;   
// } 

// void Tool::LoadRegisterAutoRunFromUser(std::vector<AutoRunInfo> *pInfo,wchar_t * pUserName)
// {
// 	wchar_t * RegPath = new wchar_t[512];
// 	#ifndef _M_IX86
// 	swprintf_s(RegPath,512,_T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),pUserName);
// 	LoadRegisterInfo(pInfo,HKEY_USERS,RegPath);
// 	LoadRegisterInfox32(pInfo,HKEY_USERS,RegPath);
// 	swprintf_s(RegPath,512,_T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),pUserName);
// 	LoadRegisterInfo(pInfo,HKEY_USERS,RegPath);
// 	LoadRegisterInfox32(pInfo,HKEY_USERS,RegPath);
// 	swprintf_s(RegPath,512,_T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"),pUserName);
// 	LoadRegisterInfo(pInfo,HKEY_USERS,RegPath);
// 	LoadRegisterInfox32(pInfo,HKEY_USERS,RegPath);
// 	swprintf_s(RegPath,512,_T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"),pUserName);
// 	LoadRegisterInfo(pInfo,HKEY_USERS,RegPath);
// 	LoadRegisterInfox32(pInfo,HKEY_USERS,RegPath);

// 	#else
// 	swprintf_s(RegPath,512,_T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),pUserName);
// 	LoadRegisterInfo(pInfo,HKEY_USERS,RegPath);
// 	swprintf_s(RegPath,512,_T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),pUserName);
// 	LoadRegisterInfo(pInfo,HKEY_USERS,RegPath);
// 	swprintf_s(RegPath,512,_T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"),pUserName);
// 	LoadRegisterInfo(pInfo,HKEY_USERS,RegPath);
// 	swprintf_s(RegPath,512,_T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"),pUserName);
// 	LoadRegisterInfo(pInfo,HKEY_USERS,RegPath);

// 	#endif
// 	delete [] RegPath;
// }

// void Tool::LoadRegisterInfo(std::vector<AutoRunInfo> *pInfo,HKEY pKey,wchar_t * RegPath)
// {
// 	HKEY hKey = NULL;
// 	LONG lResult;
// 	lResult = RegOpenKeyEx(pKey,RegPath, 0, KEY_QUERY_VALUE, &hKey);

// 	if (lResult == ERROR_SUCCESS) 
// 	{

// 		DWORD dwValues, dwMaxValueNameLen, dwMaxValueLen;
// 		LONG lRet = ::RegQueryInfoKey(hKey, 
// 									NULL, NULL,    // lpClass, lpcClass
// 									NULL,          // lpReserved
// 									NULL, NULL,    // lpcSubKeys, lpcMaxSubKeyLen
// 									NULL,          // lpcMaxClassLen
// 									&dwValues,
// 									&dwMaxValueNameLen,
// 									&dwMaxValueLen,
// 									NULL,          // lpcbSecurityDescriptor
// 									NULL);         // lpftLastWriteTime
// 		if(ERROR_SUCCESS == lRet)
// 		{  
// 			// allocate enough to fit max. length name and value
// 			LPTSTR pszName = new wchar_t[dwMaxValueNameLen + 1];
// 			LPBYTE lpData   = new BYTE[dwMaxValueLen+1];
// 			memset(lpData,'\0',dwMaxValueLen+1);
// 			for(DWORD dwIndex = 0; dwIndex < dwValues; dwIndex++)
// 			{
// 				DWORD dwNameSize  = dwMaxValueNameLen + 1;
// 				DWORD dwValueSize = dwMaxValueLen;
// 				DWORD dwType;
// 				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize, 0, &dwType, lpData, &dwValueSize);
// 				//wprintf(L"1-%s\n",pszName);
// 				if(REG_SZ == dwType || REG_EXPAND_SZ == dwType)
// 				{
// 					AutoRunInfo m_Info;
// 					wcscpy_s(m_Info.StartName,MAX_PATH,pszName);
// 					wchar_t pCom[MAX_PATH_EX];//= new wchar_t[MAX_PATH_EX];
// 					try
// 					{
// 						//memcpy(pCom ,lpData,MAX_PATH_EX);
// 						swprintf_s(pCom,MAX_PATH_EX,_T("%s"),lpData);
// 					}
// 					catch(...)
// 					{
// 						_tcscpy_s(pCom,MAX_PATH_EX,_T("null"));
// 					}
// 					if(_tcscmp(pCom,_T("null")))
// 					{
// 						ExpandEnvironmentStrings(pCom, m_Info.m_Command, MAX_PATH_EX);
// 						/*memcpy(m_Info.m_Command,lpData,MAX_PATH_EX);*/

// 						if(pKey == HKEY_USERS)
// 						{
// 							swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("HKEY_USERS\\%s"),RegPath);
// 						}
// 						else if(pKey == HKEY_LOCAL_MACHINE)
// 						{
// 							swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("HKEY_LOCAL_MACHINE\\%s"),RegPath);
// 						}
// 						else
// 						{
// 							swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("%s"),RegPath);
// 						}
// 						pInfo->push_back(m_Info);
// 					}
// 					//delete [] pCom;	
// 				}
// 			}
// 			delete []pszName;
// 			delete []lpData;
// 		}
// 	}
// 	RegCloseKey(hKey);
// }
// void Tool::LoadRegisterInfox32(std::vector<AutoRunInfo> *pInfo,HKEY pKey,wchar_t * RegPath)
// {
// 	HKEY hKey = NULL;
// 	LONG lResult;

// 	lResult = RegOpenKeyEx(pKey,RegPath, 0, KEY_QUERY_VALUE| KEY_WOW64_32KEY, &hKey);

// 	if (lResult == ERROR_SUCCESS) 
// 	{

// 		DWORD dwValues, dwMaxValueNameLen, dwMaxValueLen;
// 		LONG lRet = ::RegQueryInfoKey(hKey, 
// 									NULL, NULL,    // lpClass, lpcClass
// 									NULL,          // lpReserved
// 									NULL, NULL,    // lpcSubKeys, lpcMaxSubKeyLen
// 									NULL,          // lpcMaxClassLen
// 									&dwValues,
// 									&dwMaxValueNameLen,
// 									&dwMaxValueLen,
// 									NULL,          // lpcbSecurityDescriptor
// 									NULL);         // lpftLastWriteTime
// 		if(ERROR_SUCCESS == lRet)
// 		{  
// 			// allocate enough to fit max. length name and value
// 			LPTSTR pszName = new wchar_t[dwMaxValueNameLen + 1];
// 			LPBYTE lpData   = new BYTE[dwMaxValueLen+1];
// 			memset(lpData,'\0',dwMaxValueLen+1);
// 			for(DWORD dwIndex = 0; dwIndex < dwValues; dwIndex++)
// 			{
// 				DWORD dwNameSize  = dwMaxValueNameLen + 1;
// 				DWORD dwValueSize = dwMaxValueLen;
// 				DWORD dwType;
// 				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize, 0, &dwType, lpData, &dwValueSize);
// 				//wprintf(L"1-%s\n",pszName);
// 				if(REG_SZ == dwType || REG_EXPAND_SZ == dwType)
// 				{
// 					AutoRunInfo m_Info;
// 					wcscpy_s(m_Info.StartName,MAX_PATH,pszName);
// 					wchar_t * pCom = new wchar_t[MAX_PATH_EX];
// 					//memcpy(pCom ,lpData,MAX_PATH_EX);
// 					swprintf_s(pCom,MAX_PATH_EX,_T("%s"),lpData);
// 					ExpandEnvironmentStrings(pCom, m_Info.m_Command, MAX_PATH_EX);
// 					//memcpy(m_Info.m_Command,lpData,MAX_PATH_EX);

// 					if(pKey == HKEY_USERS)
// 						swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("x86:HKEY_USERS\\%s"),RegPath);
// 					else if(pKey == HKEY_LOCAL_MACHINE)
// 						swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("x86:HKEY_LOCAL_MACHINE\\%s"),RegPath);
// 					else
// 						swprintf_s(m_Info.InfoLocation,MAX_PATH_EX,_T("x86:%s"),RegPath);

// 					delete [] pCom;
// 					pInfo->push_back(m_Info);
// 				}
// 			}
// 			delete []pszName;
// 			delete []lpData;
// 		}
// 	}
// 	RegCloseKey(hKey);
// }

// time_t Tool::filetime_to_timet(const FILETIME& ft) {
//    ULARGE_INTEGER ull;
//    ull.LowPart = ft.dwLowDateTime;
//    ull.HighPart = ft.dwHighDateTime;
//    return ull.QuadPart / 10000000ULL - 11644473600ULL;
// }

// DWORD Tool::Md5Hash(wchar_t * FileName,wchar_t * HashStr/*,size_t HashStrlen*/)
// {
// 	DWORD dwStatus = 0;
//     BOOL bResult = FALSE;
//     HCRYPTPROV hProv = 0;
//     HCRYPTHASH hHash = 0;
//     HANDLE hFile = NULL;
//     BYTE rgbFile[1024];
//     DWORD cbRead = 0;
//     BYTE rgbHash[16];
//     DWORD cbHash = 0;
//     CHAR rgbDigits[] = "0123456789abcdef";
//    // LPCWSTR filename=L"C:\\Users\\RexLin\\Pictures\\Saved Pictures\\Koala.jpg";
// 	hFile = CreateFile(FileName,GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

//     if (INVALID_HANDLE_VALUE == hFile)
//     {
//         dwStatus = GetLastError();
//        // printf("Error opening file %s\nError: %d\n", FileName,dwStatus); 
//         return dwStatus;
//     }
// 	//DWORD m_Filesize = GetFileSize(hFile, NULL);
// 	//if(m_Filesize > SCAN_MAX_SIZE)
// 	//{
// 	//	dwStatus = 1382;
//  //       printf("Exceed MAX Size: %d\n", dwStatus); 
//  //       CloseHandle(hFile);
//  //       return dwStatus;
// 	//}
// 	if (!CryptAcquireContext(&hProv,NULL, NULL,PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
//     {
//         dwStatus = GetLastError();
//        // printf("CryptAcquireContext failed: %d\n", dwStatus); 
//         CloseHandle(hFile);
//         return dwStatus;
//     }
// 	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
//     {
//         dwStatus = GetLastError();
//        // printf("CryptAcquireContext failed: %d\n", dwStatus); 
//         CloseHandle(hFile);
//         CryptReleaseContext(hProv, 0);
//         return dwStatus;
//     }
// 	while (bResult = ReadFile(hFile, rgbFile, 1024, &cbRead, NULL))
//     {
//         if (0 == cbRead)
//         {
//             break;
//         }

//         if (!CryptHashData(hHash, rgbFile, cbRead, 0))
//         {
//             dwStatus = GetLastError();
//            // printf("CryptHashData failed: %d\n", dwStatus); 
//             CryptReleaseContext(hProv, 0);
//             CryptDestroyHash(hHash);
//             CloseHandle(hFile);
//             return dwStatus;
//         }
//     }
// 	if (!bResult)
//     {
//         dwStatus = GetLastError();
//        // printf("ReadFile failed: %d\n", dwStatus); 
//         CryptReleaseContext(hProv, 0);
//         CryptDestroyHash(hHash);
//         CloseHandle(hFile);
//         return dwStatus;
//     }
// 	cbHash = 16;
//     if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
//     {
//        // printf("MD5 hash of file %s is: ", FileName);
//         for (DWORD i = 0; i < cbHash; i++)
//         {
// 			wchar_t* cstr = new wchar_t[10];
// 			swprintf_s(cstr,10,_T("%c%c"),rgbDigits[rgbHash[i] >> 4],rgbDigits[rgbHash[i] & 0xf]);
// 			lstrcat(HashStr,cstr);
// 			delete [] cstr;
//            // printf("%c%c", rgbDigits[rgbHash[i] >> 4],rgbDigits[rgbHash[i] & 0xf]);
// 			//swprintf_s(HashStr,HashStrlen,_T("%s%c%c"),HashStr,rgbDigits[rgbHash[i] >> 4],rgbDigits[rgbHash[i] & 0xf]);
//         }
//        // printf("\n");
//     }
//     else
//     {
//         dwStatus = GetLastError();
//        // printf("CryptGetHashParam failed: %d\n", dwStatus); 
//     }

// 	CryptDestroyHash(hHash);
//     CryptReleaseContext(hProv, 0);
//     CloseHandle(hFile);
//     return dwStatus; 
// }

// BOOL Tool::CheckIsPackedPE(wchar_t * pPath) {
// 	BOOL ret = FALSE;
// 	HANDLE m_File = CreateFile(pPath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
// 	if(m_File != INVALID_HANDLE_VALUE)
// 	{
// 		DWORD m_Filesize = GetFileSize(m_File, NULL);
// 		if(m_Filesize >= 1024)
// 		{
// 			DWORD readsize;
// 			BYTE *buffer = new BYTE[1024];
// 			ReadFile(m_File, buffer,1024, &readsize, NULL);
// 			ret = IsPackedSignature(buffer,1024);
// 			delete [] buffer;
// 		}	
// 		CloseHandle(m_File);
// 	}			
// 	return ret;
// }

// BOOL Tool::IsPackedSignature(BYTE * buffer,unsigned int buflen) {
// 	for(unsigned int i = 0;i<buflen;i++)
// 	{
// 		if(i+4 > buflen)
// 			break;
// 		else
// 		{
// 			if(buffer[i]==46 && buffer[i+1]==116 && buffer[i+2]==101 && buffer[i+3]==120 &&buffer[i+4]==116)
// 			{
// 				return FALSE;
// 			}
// 		}
// 	}
// 	return TRUE;
// }


//here

//const char* Tool::WideCharToConstChar(const wchar_t* wideString)
//{
//    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideString, -1, nullptr, 0, nullptr, nullptr);
//    if (bufferSize == 0)
//    {
//        // Error handling, conversion failed
//        return nullptr;
//    }
//
//    static std::string multiByteString;
//    multiByteString.resize(bufferSize, '\0');
//    WideCharToMultiByte(CP_UTF8, 0, wideString, -1, &multiByteString[0], bufferSize, nullptr, nullptr);
//
//    return multiByteString.c_str();
//}
//
//LPCSTR Tool::WideCharToLPCWSTR(wchar_t* wideString) {
//    // convert wide string to LPCSTR
//    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wideString, -1, nullptr, 0, nullptr, nullptr);
//    if (bufferSize == 0)
//    {
//        // Error handling, conversion failed
//        return nullptr;
//    }
//
//    static std::string multiByteString;
//    multiByteString.resize(bufferSize, '\0');
//    WideCharToMultiByte(CP_UTF8, 0, wideString, -1, &multiByteString[0], bufferSize, nullptr, nullptr);
//
//    return multiByteString.c_str();
//}
//
//wchar_t* Tool::CharPtrToWideCharPtr(char* narrowString) {
//    if (narrowString == nullptr)
//        return nullptr;
//
//    // Determine the length of the wide character string
//    int length = MultiByteToWideChar(CP_UTF8, 0, narrowString, -1, nullptr, 0);
//    if (length == 0)
//        return nullptr; // Conversion failed
//
//    // Allocate memory for the wide character string
//    wchar_t* wideString = new wchar_t[length];
//
//    // Perform the conversion
//    MultiByteToWideChar(CP_UTF8, 0, narrowString, -1, wideString, length);
//
//    return wideString;
//}
//
//char* Tool::Convert2State(DWORD dwState)
//{
//    switch (dwState)
//    {
//    case MIB_TCP_STATE_CLOSED:
//        return "CLOSED";
//
//    case MIB_TCP_STATE_LISTEN:
//        return "LISTEN";
//
//    case MIB_TCP_STATE_SYN_SENT:
//        return "SYN_SENT";
//
//    case MIB_TCP_STATE_SYN_RCVD:
//        return "SYN_RCVD";
//
//    case MIB_TCP_STATE_ESTAB:
//        return "ESTABLISHED";
//
//    case MIB_TCP_STATE_FIN_WAIT1:
//        return "FIN_WAIT1";
//
//    case MIB_TCP_STATE_FIN_WAIT2:
//        return "FIN_WAIT2";
//
//    case MIB_TCP_STATE_CLOSE_WAIT:
//        return "CLOSE_WAIT";
//
//    case MIB_TCP_STATE_CLOSING:
//        return "CLOSING";
//
//    case MIB_TCP_STATE_LAST_ACK:
//        return "LAST_ACK";
//
//    case MIB_TCP_STATE_TIME_WAIT:
//        return "TIME_WAIT";
//
//    case MIB_TCP_STATE_DELETE_TCB:
//        return "DELETE_TCB";
//
//    default:
//        return "UNKNOWN";
//    }
//}



bool Tool::SetRegistryValue(const wchar_t* valueName, const wchar_t* valueData) {
    HKEY hKey;
    const wchar_t* subKey = L"Software\\eDetector";

    // Open or create the registry subkey
    LONG result = RegCreateKeyExW(HKEY_CURRENT_USER, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);

    if (result == ERROR_SUCCESS) {
        // Set the value to the registry subkey
        result = RegSetValueExW(hKey, valueName, 0, REG_SZ, reinterpret_cast<const BYTE*>(valueData), sizeof(wchar_t) * (lstrlenW(valueData) + 1));

        if (result == ERROR_SUCCESS) {
            std::wcout << L"Registry value set successfully!" << std::endl;
        }
        else {
            std::wcerr << L"Error setting registry value: " << result << std::endl;
        }

        // Close the registry key
        RegCloseKey(hKey);
    }
    else {
        std::wcerr << L"Error creating registry subkey: " << result << std::endl;
    }

    return result == ERROR_SUCCESS;
}




std::wstring Tool::GetRegistryValue(const wchar_t* valueName) {
    HKEY hKey;
    const wchar_t* subKey = L"Software\\eDetector";

    // Open the registry subkey
    LONG result = RegOpenKeyExW(HKEY_CURRENT_USER, subKey, 0, KEY_QUERY_VALUE, &hKey);

    if (result == ERROR_SUCCESS) {
        DWORD dataSize = 0;
        // Get the size of the value
        result = RegQueryValueExW(hKey, valueName, NULL, NULL, NULL, &dataSize);

        if (result == ERROR_SUCCESS) {
            // Allocate buffer to store the value
            std::wstring valueData;
            valueData.resize(dataSize / sizeof(wchar_t));

            // Read the value into the buffer
            result = RegQueryValueExW(hKey, valueName, NULL, NULL, reinterpret_cast<LPBYTE>(&valueData[0]), &dataSize);

            if (result == ERROR_SUCCESS) {
                // Close the registry key
                RegCloseKey(hKey);
                return valueData;
            }
        }

        // Close the registry key
        RegCloseKey(hKey);
    }

    // If reading fails or the key doesn't exist, return an empty string
    return L"";
}








// void Tool::GetFileVersion(const char* FilePath, std::string& pVersion) {
//     DWORD verHandle = 0;
//     UINT size = 0;
//     LPBYTE lpBuffer = nullptr;
//     DWORD verSize = GetFileVersionInfoSize(FilePath, &verHandle);
//     if (verSize != 0) {
//         std::unique_ptr<char[]> verData(new char[verSize]);
//         if (GetFileVersionInfo(FilePath, verHandle, verSize, verData.get())) {
//             if (VerQueryValue(verData.get(), "\\",(VOID FAR* FAR*)&lpBuffer, &size)) {
//                 if (size && reinterpret_cast<VS_FIXEDFILEINFO*>(lpBuffer)->dwSignature == 0xfeef04bd) {
//                     char version[64];
//                     sprintf_s(version, "%d.%d.%d.%d",
//                         (reinterpret_cast<VS_FIXEDFILEINFO*>(lpBuffer)->dwFileVersionMS >> 16) & 0xffff,
//                         (reinterpret_cast<VS_FIXEDFILEINFO*>(lpBuffer)->dwFileVersionMS >> 0) & 0xffff,
//                         (reinterpret_cast<VS_FIXEDFILEINFO*>(lpBuffer)->dwFileVersionLS >> 16) & 0xffff,
//                         (reinterpret_cast<VS_FIXEDFILEINFO*>(lpBuffer)->dwFileVersionLS >> 0) & 0xffff);
//                     pVersion = version;
//                 }
//             }
//         }
//     }
// }

// char * GetOSVersion()
// {
// 	char * MyVersion = NULL;
// 	HKEY hKey = NULL;
// 	LONG lResult;

// 	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &hKey);

// 	if (lResult == ERROR_SUCCESS)// return 0;
// 	{

// 		DWORD dwValues, dwMaxValueNameLen, dwMaxValueLen;
// 		LONG lRet = ::RegQueryInfoKey(hKey, 
// 									  NULL, NULL,    // lpClass, lpcClass
// 									  NULL,          // lpReserved
// 									  NULL, NULL,    // lpcSubKeys, lpcMaxSubKeyLen
// 									  NULL,          // lpcMaxClassLen
// 									  &dwValues,
// 									  &dwMaxValueNameLen,
// 									  &dwMaxValueLen,
// 									  NULL,          // lpcbSecurityDescriptor
// 									  NULL);         // lpftLastWriteTime
// 		if(ERROR_SUCCESS == lRet)
// 		{  
// 		   // allocate enough to fit max. length name and value
// 			LPTSTR pszName = new wchar_t[dwMaxValueNameLen + 1];
// 			LPBYTE lpData   = new BYTE[dwMaxValueLen+1];
// 			memset(lpData,'\0',dwMaxValueLen+1);
// 		   for(DWORD dwIndex = 0; dwIndex < dwValues; dwIndex++)
// 		   {
// 			  DWORD dwNameSize  = dwMaxValueNameLen + 1;
// 			  DWORD dwValueSize = dwMaxValueLen;
// 			  DWORD dwType;
// 			  lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize,
// 									0, &dwType, lpData, &dwValueSize);
// 			  if(!lstrcmp(pszName,_T("ProductName"))&&REG_SZ == dwType)
// 			  {
// 				  //wprintf(L"%s\n",lpData);
// 				  MyVersion = CStringToCharArray((wchar_t*)lpData,CP_UTF8);
// 				  break;
// 			  }
// 		   }
// 		   delete []pszName;
// 		   delete []lpData;
// 		}
// 	}
// 	RegCloseKey(hKey);
// 	if( MyVersion == NULL)
// 	{
// 		//delete [] MyVersion;
// 		MyVersion = new char[10];
// 		strcpy_s(MyVersion,10,"Unknown");
// 		return MyVersion;
// 	}
// 	else
// 		return MyVersion;
// }