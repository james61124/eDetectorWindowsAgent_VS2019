#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include "GlobalFunction.h"
#include <Sddl.h>
#include <Setupapi.h>
#include <initguid.h> 
#include <algorithm>
#pragma comment(lib,"version.lib")
#pragma comment(lib,"setupapi.lib")
DEFINE_GUID(GUID_DEVINTERFACE_USB_DISK,
	0x53f56307L, 0xb6bf, 0x11d0, 0x94, 0xf2,
	0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b);
typedef void (WINAPI* PGNSI)(LPSYSTEM_INFO);

DWORD(WINAPI* pGetExtendedTcpTable)(
	PVOID pTcpTable,
	PDWORD pdwSize,
	BOOL bOrder,
	ULONG ulAf,
	TCP_TABLE_CLASS TableClass,
	ULONG Reserved
	);
DWORD(WINAPI* pGetExtendedUdpTable)(
	PVOID pUdpTable,
	PDWORD pdwSize,
	BOOL bOrder,
	ULONG ulAf,
	UDP_TABLE_CLASS TableClass,
	ULONG Reserved
	);
typedef struct _MIB_TCPROW_EX
{
	DWORD dwState;
	DWORD dwLocalAddr;
	DWORD dwLocalPort;
	DWORD dwRemoteAddr;
	DWORD dwRemotePort;
	DWORD dwProcessId;
} MIB_TCPROW_EX, * PMIB_TCPROW_EX;

typedef struct _MIB_TCPTABLE_EX
{
	DWORD dwNumEntries;
	MIB_TCPROW_EX table[ANY_SIZE];
} MIB_TCPTABLE_EX, * PMIB_TCPTABLE_EX;
typedef DWORD(WINAPI* pAllocateAndGetTcpExTableFromStack)(
	PMIB_TCPTABLE_EX* pTcpTableEx,
	BOOL,
	HANDLE,
	DWORD,	  //0
	DWORD);	  //2
char* wcharTochar(wchar_t* WStr)
{
	size_t len = wcslen(WStr) + 1;
	size_t converted = 0;
	char* CStr;
	CStr = (char*)malloc(len * sizeof(char));
	wcstombs_s(&converted, CStr, len, WStr, _TRUNCATE);
	return CStr;
}

wchar_t* charTowchar(char* CStr)
{
	size_t len = strlen(CStr) + 1;
	size_t converted = 0;
	wchar_t* WStr;
	WStr = (wchar_t*)malloc(len * sizeof(wchar_t));
	mbstowcs_s(&converted, WStr, len, CStr, _TRUNCATE);
	return WStr;
}

wchar_t* CharArrayToWString(char* CStr, UINT m_CodePage)
{
	int size = MultiByteToWideChar(m_CodePage, 0, CStr, -1, NULL, 0);
	wchar_t* WStr = new wchar_t[size + 1];
	MultiByteToWideChar(m_CodePage, 0, CStr, -1, WStr, size);
	//outCString->Format(L"%s",WStr);
	return WStr;
}
char* CStringToCharArray(wchar_t* str, UINT m_CodePage)
{
	char* ptr;
#ifdef _UNICODE
	LONG len;
	len = WideCharToMultiByte(m_CodePage, 0, str, -1, NULL, 0, NULL, NULL);
	ptr = new char[len + 1];
	memset(ptr, 0, len + 1);
	WideCharToMultiByte(m_CodePage, 0, str, -1, ptr, len + 1, NULL, NULL);
#else
	ptr = new char[str.GetAllocLength() + 1];
#endif
	return ptr;
}
bool GetMacByGetAdaptersInfo(char* MACstr, unsigned int StrSize)//取得MAC
{
	bool ret = false;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL)
		return false;
	// Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL)
			return false;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR)
	{
		for (PIP_ADAPTER_INFO pAdapter = pAdapterInfo; pAdapter != NULL; pAdapter = pAdapter->Next)
		{

			if (pAdapter->Type != MIB_IF_TYPE_ETHERNET)
				continue;

			if (pAdapter->AddressLength != 6)
				continue;
			sprintf_s(MACstr, StrSize, "%02X-%02X-%02X-%02X-%02X-%02X",
				int(pAdapter->Address[0]),
				int(pAdapter->Address[1]),
				int(pAdapter->Address[2]),
				int(pAdapter->Address[3]),
				int(pAdapter->Address[4]),
				int(pAdapter->Address[5]));
			ret = true;
			break;
		}
	}

	free(pAdapterInfo);
	return ret;
}
void GetThisIP(char* Ipstr, unsigned int StrSize)//取得內部IP
{
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) == SOCKET_ERROR)
	{
		//exit(0);  
		return;
	}
	int nLen = 256;
	char hostname[20];
	gethostname(hostname, nLen);
	hostent* pHost = gethostbyname(hostname);
	LPSTR lpAddr = pHost->h_addr_list[0];
	struct in_addr inAddr;
	memmove(&inAddr, lpAddr, 4);
	strcpy_s(Ipstr, StrSize, inet_ntoa(inAddr));
	//return inet_ntoa(inAddr);
}
void RunProcess(TCHAR* AppName, TCHAR* CmdLine, BOOL isWait, BOOL isShow)
{
	//PROCESS_INFORMATION processInformation;
	//STARTUPINFO startupInfo;
	//memset(&processInformation, 0, sizeof(processInformation));
	//memset(&startupInfo, 0, sizeof(startupInfo));
	//startupInfo.cb = sizeof(startupInfo);

	//BOOL result;
	//TCHAR tempCmdLine[MAX_PATH_EX * 2];  //Needed since CreateProcessW may change the contents of CmdLine
	//if (CmdLine != NULL)
	//{
	//	_tcscpy_s(tempCmdLine, MAX_PATH_EX * 2, CmdLine);
	//	if (isShow)
	//		result = ::CreateProcess(AppName, tempCmdLine, NULL, NULL, FALSE, g_ProcessLevel, NULL, NULL, &startupInfo, &processInformation);
	//	else
	//		result = ::CreateProcess(AppName, tempCmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW | g_ProcessLevel, NULL, NULL, &startupInfo, &processInformation);
	//}
	//else
	//{
	//	if (isShow)
	//		result = ::CreateProcess(AppName, CmdLine, NULL, NULL, FALSE, g_ProcessLevel, NULL, NULL, &startupInfo, &processInformation);
	//	else
	//		result = ::CreateProcess(AppName, CmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW | g_ProcessLevel, NULL, NULL, &startupInfo, &processInformation);
	//}

	//if (result == 0)
	//{
	//	wprintf(L"ERROR: CreateProcess failed!");
	//}
	//else
	//{
	//	if (isWait)
	//		WaitForSingleObject(processInformation.hProcess, INFINITE);
	//	CloseHandle(processInformation.hProcess);
	//	CloseHandle(processInformation.hThread);
	//}
}
//bool RunProcessEx(TCHAR* AppName, TCHAR* CmdLine, size_t CmdLineLen, BOOL isWait, BOOL isShow, DWORD& pid, int m_TimeOut)
//{
//	bool ret = true;
//	PROCESS_INFORMATION processInformation;
//	STARTUPINFO startupInfo;
//	memset(&processInformation, 0, sizeof(processInformation));
//	memset(&startupInfo, 0, sizeof(startupInfo));
//	startupInfo.cb = sizeof(startupInfo);
//
//	BOOL result;
//	TCHAR* tempCmdLine = new TCHAR[CmdLineLen * 2];  //Needed since CreateProcessW may change the contents of CmdLine
//	if (CmdLine != NULL)
//	{
//		_tcscpy_s(tempCmdLine, CmdLineLen * 2, CmdLine);
//		if (isShow)
//			result = ::CreateProcess(AppName, tempCmdLine, NULL, NULL, FALSE, g_ProcessLevel, NULL, NULL, &startupInfo, &processInformation);
//		else
//			result = ::CreateProcess(AppName, tempCmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW | g_ProcessLevel, NULL, NULL, &startupInfo, &processInformation);
//	}
//	else
//	{
//		if (isShow)
//			result = ::CreateProcess(AppName, CmdLine, NULL, NULL, FALSE, g_ProcessLevel, NULL, NULL, &startupInfo, &processInformation);
//		else
//			result = ::CreateProcess(AppName, CmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW | g_ProcessLevel, NULL, NULL, &startupInfo, &processInformation);
//	}
//
//	if (result == 0)
//	{
//		wprintf(L"ERROR: CreateProcess failed!");
//		ret = false;
//	}
//	else
//	{
//		pid = processInformation.dwProcessId;
//		if (isWait)
//		{
//			if (m_TimeOut > 0)
//				WaitForSingleObject(processInformation.hProcess, m_TimeOut);
//			else
//				WaitForSingleObject(processInformation.hProcess, INFINITE);
//		}
//		CloseHandle(processInformation.hProcess);
//		CloseHandle(processInformation.hThread);
//	}
//	delete[] tempCmdLine;
//	return ret;
//}
bool dirExists(wchar_t* dirPath)
{
	DWORD ftyp = GetFileAttributes(dirPath);
	if (ftyp == INVALID_FILE_ATTRIBUTES)
		return false;  //something is wrong with your path!

	if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
		return true;   // this is a directory!

	return false;    // this is not a directory!
}
int MatchFileName(const _TCHAR* string, const _TCHAR* wild)
{
	const _TCHAR* cp = NULL, * mp = NULL;
	while ((*string) && (*wild != _T('*')))
	{
		if ((toupper(*wild) != toupper(*string)) && (*wild != _T('?')))
			return 0;
		wild++;
		string++;
	}

	while (*string)
	{
		if (*wild == '*') {
			if (!*++wild)
				return 1;
			mp = wild;
			cp = string + 1;
		}
		else if ((toupper(*wild) == toupper(*string)) || (*wild == _T('?'))) {
			wild++;
			string++;
		}
		else {
			wild = mp;
			string = cp++;
		}
	}

	while (*wild == _T('*')) {
		wild++;
	}
	return !*wild;
}
bool MatchKeyword(TCHAR* pKeywordStr, TCHAR* NameStr)
{
	TCHAR* KeywordStr = new TCHAR[1024];
	lstrcpy(KeywordStr, pKeywordStr);
	int isMatch = 0;
	wchar_t* pwc;
	wchar_t* next_token = NULL;
	pwc = wcstok_s(KeywordStr, L"|", &next_token);
	while (pwc != NULL)
	{
		if (MatchFileName(NameStr, pwc))
		{
			isMatch++;
		}
		pwc = wcstok_s(NULL, L"|", &next_token);
	}
	delete[] KeywordStr;
	if (isMatch == 0)
		return false;
	else
		return true;

}
char* GetSysInfo()
{
	SYSTEM_INFO si;
	PGNSI pGNSI = (PGNSI) GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetNativeSystemInfo");
 
	if(NULL != pGNSI)
		pGNSI(&si);
	else 
		GetSystemInfo(&si);

	char* result = nullptr;

	if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64 )
	{
		result = new char[4]; 
		strcpy_s(result, 4, "x64");
		return result;
	}
	else if (si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_INTEL )
	{
		result = new char[4]; 
		strcpy_s(result, 4, "x86");
		return result;
	}
	else
	{
		result = new char[8]; 
		strcpy_s(result, 8, "Unknown");
		return result;
	}
}
char* GetDriveStr(int num)
{
	char* result = nullptr;
	result = new char[5];
	switch (num)
	{
	case 0:
		strcpy_s(result, 5, "A:\\");
		return result;
	case 1:
		strcpy_s(result, 5, "B:\\");
		return result;
	case 2:
		strcpy_s(result, 5, "C:\\");
		return result;
	case 3:
		strcpy_s(result, 5, "D:\\");
		return result;
	case 4:
		strcpy_s(result, 5, "E:\\");
		return result;
	case 5:
		strcpy_s(result, 5, "F:\\");
		return result;
	case 6:
		strcpy_s(result, 5, "G:\\");
		return result;
	case 7:
		strcpy_s(result, 5, "H:\\");
		return result;
	case 8:
		strcpy_s(result, 5, "I:\\");
		return result;
	case 9:
		strcpy_s(result, 5, "J:\\");
		return result;
	case 10:
		strcpy_s(result, 5, "K:\\");
		return result;
	case 11:
		strcpy_s(result, 5, "L:\\");
		return result;
	case 12:
		strcpy_s(result, 5, "M:\\");
		return result;
	case 13:
		strcpy_s(result, 5, "N:\\");
		return result;
	case 14:
		strcpy_s(result, 5, "O:\\");
		return result;
	case 15:
		strcpy_s(result, 5, "P:\\");
		return result;
	case 16:
		strcpy_s(result, 5, "Q:\\");
		return result;
	case 17:
		strcpy_s(result, 5, "R:\\");
		return result;
	case 18:
		strcpy_s(result, 5, "S:\\");
		return result;
	case 19:
		strcpy_s(result, 5, "T:\\");
		return result;
	case 20:
		strcpy_s(result, 5, "U:\\");
		return result;
	case 21:
		strcpy_s(result, 5, "V:\\");
		return result;
	case 22:
		strcpy_s(result, 5, "W:\\");
		return result;
	case 23:
		strcpy_s(result, 5, "X:\\");
		return result;
	case 24:
		strcpy_s(result, 5, "Y:\\");
		return result;
	case 25:
		strcpy_s(result, 5, "Z:\\");
		return result;
	}
	return NULL;
}
int FindPID(wchar_t* processname)
{
	int pid = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procSentry;
		procSentry.dwSize = sizeof(procSentry);
		BOOL Proc = Process32First(hSnapshot, &procSentry);
		for (; Proc; Proc = Process32Next(hSnapshot, &procSentry))
		{
			if (!_wcsicmp(procSentry.szExeFile, processname))
			{
				pid = procSentry.th32ProcessID;
				break;
			}
		}
	}
	CloseHandle(hSnapshot);
	return pid;
}
bool FindThisPID(wchar_t* processname, DWORD pid)
{
	bool ret = false;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procSentry;
		procSentry.dwSize = sizeof(procSentry);
		BOOL Proc = Process32First(hSnapshot, &procSentry);
		for (; Proc; Proc = Process32Next(hSnapshot, &procSentry))
		{
			if (!_wcsicmp(procSentry.szExeFile, processname))
			{
				if (pid == procSentry.th32ProcessID)
				{
					ret = true;
					break;
				}
			}
		}
	}
	CloseHandle(hSnapshot);
	return ret;
}
int GetPIDCount(wchar_t* processname)
{
	int count = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procSentry;
		procSentry.dwSize = sizeof(procSentry);
		BOOL Proc = Process32First(hSnapshot, &procSentry);
		for (; Proc; Proc = Process32Next(hSnapshot, &procSentry))
		{
			if (!_wcsicmp(procSentry.szExeFile, processname))
			{
				count++;
				break;
			}
		}
	}
	CloseHandle(hSnapshot);
	return count;
}
char* GetOSVersion()
{
	char* MyVersion = NULL;
	HKEY hKey = NULL;
	LONG lResult;

	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_QUERY_VALUE, &hKey);

	if (lResult == ERROR_SUCCESS)// return 0;
	{

		DWORD dwValues, dwMaxValueNameLen, dwMaxValueLen;
		LONG lRet = ::RegQueryInfoKey(hKey,
			NULL, NULL,    // lpClass, lpcClass
			NULL,          // lpReserved
			NULL, NULL,    // lpcSubKeys, lpcMaxSubKeyLen
			NULL,          // lpcMaxClassLen
			&dwValues,
			&dwMaxValueNameLen,
			&dwMaxValueLen,
			NULL,          // lpcbSecurityDescriptor
			NULL);         // lpftLastWriteTime
		if (ERROR_SUCCESS == lRet)
		{
			// allocate enough to fit max. length name and value
			LPTSTR pszName = new TCHAR[dwMaxValueNameLen + 1];
			LPBYTE lpData = new BYTE[dwMaxValueLen + 1];
			memset(lpData, '\0', dwMaxValueLen + 1);
			for (DWORD dwIndex = 0; dwIndex < dwValues; dwIndex++)
			{
				DWORD dwNameSize = dwMaxValueNameLen + 1;
				DWORD dwValueSize = dwMaxValueLen;
				DWORD dwType;
				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize,
					0, &dwType, lpData, &dwValueSize);
				if (!lstrcmp(pszName, _T("ProductName")) && REG_SZ == dwType)
				{
					//wprintf(L"%s\n",lpData);
					MyVersion = CStringToCharArray((wchar_t*)lpData, CP_UTF8);
					break;
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
	if (MyVersion == NULL)
	{
		//delete [] MyVersion;
		MyVersion = new char[10];
		strcpy_s(MyVersion, 10, "Unknown");
		return MyVersion;
	}
	else
		return MyVersion;
}
//unsigned int GetDriveFormatNumW(wchar_t* formatStr)
//{
//	if (!wcscmp(formatStr,L"NTFS"))
//		return 0;
//	else if(!wcscmp(formatStr,L"FAT32"))
//		return 1;
//	else
//		return 9;
//}
//unsigned int GetDriveFormatNumA(char* formatStr)
//{
//	if (!strcmp(formatStr,"NTFS"))
//		return 0;
//	else if(!strcmp(formatStr,"FAT32"))
//		return 1;
//	else
//		return 9;
//}

DWORD Md5Hash(TCHAR* FileName, TCHAR* HashStr/*,size_t HashStrlen*/)
{
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HANDLE hFile = NULL;
	BYTE rgbFile[1024];
	DWORD cbRead = 0;
	BYTE rgbHash[16];
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";
	// LPCWSTR filename=L"C:\\Users\\RexLin\\Pictures\\Saved Pictures\\Koala.jpg";
	hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		dwStatus = GetLastError();
		// printf("Error opening file %s\nError: %d\n", FileName,dwStatus); 
		return dwStatus;
	}
	//DWORD m_Filesize = GetFileSize(hFile, NULL);
	//if(m_Filesize > SCAN_MAX_SIZE)
	//{
	//	dwStatus = 1382;
 //       printf("Exceed MAX Size: %d\n", dwStatus); 
 //       CloseHandle(hFile);
 //       return dwStatus;
	//}
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		// printf("CryptAcquireContext failed: %d\n", dwStatus); 
		CloseHandle(hFile);
		return dwStatus;
	}
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		dwStatus = GetLastError();
		// printf("CryptAcquireContext failed: %d\n", dwStatus); 
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}
	while (bResult = ReadFile(hFile, rgbFile, 1024, &cbRead, NULL))
	{
		if (0 == cbRead)
		{
			break;
		}

		if (!CryptHashData(hHash, rgbFile, cbRead, 0))
		{
			dwStatus = GetLastError();
			// printf("CryptHashData failed: %d\n", dwStatus); 
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			return dwStatus;
		}
	}
	if (!bResult)
	{
		dwStatus = GetLastError();
		// printf("ReadFile failed: %d\n", dwStatus); 
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		CloseHandle(hFile);
		return dwStatus;
	}
	cbHash = 16;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		// printf("MD5 hash of file %s is: ", FileName);
		for (DWORD i = 0; i < cbHash; i++)
		{
			TCHAR* cstr = new TCHAR[10];
			swprintf_s(cstr, 10, _T("%c%c"), rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
			lstrcat(HashStr, cstr);
			delete[] cstr;
			// printf("%c%c", rgbDigits[rgbHash[i] >> 4],rgbDigits[rgbHash[i] & 0xf]);
			 //swprintf_s(HashStr,HashStrlen,_T("%s%c%c"),HashStr,rgbDigits[rgbHash[i] >> 4],rgbDigits[rgbHash[i] & 0xf]);
		}
		// printf("\n");
	}
	else
	{
		dwStatus = GetLastError();
		// printf("CryptGetHashParam failed: %d\n", dwStatus); 
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);
	return dwStatus;
}
BOOL ReceiveTempData(BYTE* pTmpBuffer, long& pTmpSize, BYTE* RecvBuffer, long Recvlen, long DataSize)
{
	long tempSize = pTmpSize + Recvlen;
	if (tempSize < DataSize)
	{
		for (long i = pTmpSize, j = 0; i < tempSize, j < Recvlen; i++, j++)
		{
			pTmpBuffer[i] = RecvBuffer[j];
		}
		pTmpSize = tempSize;

		return FALSE;
	}
	else if (tempSize == DataSize)
	{
		for (long i = pTmpSize, j = 0; i < tempSize, j < Recvlen; i++, j++)
		{
			pTmpBuffer[i] = RecvBuffer[j];
		}
	}
	else
		printf("tempRecvSize > 65536\n");
	return TRUE;
}
time_t filetime_to_timet(const FILETIME& ft)
{
	ULARGE_INTEGER ull;
	ull.LowPart = ft.dwLowDateTime;
	ull.HighPart = ft.dwHighDateTime;

	return ull.QuadPart / 10000000ULL - 11644473600ULL;
}
BOOL EnableDebugPrivilege(BOOL fEnable)
{
	BOOL fOk = FALSE;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}
BOOL IsPESignature(BYTE* buffer, unsigned int buflen)
{
	for (unsigned int i = 0; i < buflen; i++)
	{
		if (i + 5 > buflen)
			break;
		else
		{
			if (buffer[i] == 80)
			{
				if (buffer[i + 1] == 69 && buffer[i + 2] == 0 && buffer[i + 3] == 0)
				{
					if ((buffer[i + 4] == 100 && buffer[i + 5] == 134) || (buffer[i + 4] == 76 && buffer[i + 5] == 1))
					{
						return TRUE;
					}
					else
						continue;
				}
				else
					continue;
			}
		}
	}
	return FALSE;
}
BOOL IsPEExt(TCHAR* FileName)
{
	TCHAR* ExtName = new TCHAR[MAX_PATH];
	BOOL isExt = FALSE;
	BOOL ret = FALSE;
	TCHAR* ReversetName = new TCHAR[10];
	BOOL IsReverset = FALSE;
	//memset(TestName,'\x0',MAX_PATH*3);
	for (int i = (int)wcslen(FileName) - 1; i >= 0; i--)
	{
		swprintf_s(ReversetName, MAX_PATH, _T("%02x"), FileName[i]);
		if (!_wcsicmp(ReversetName, L"202e"))
		{
			IsReverset = TRUE;
			break;
		}
	}

	for (int i = (int)wcslen(FileName) - 1; i >= 0; i--)
	{
		if (FileName[i] == '.')
		{
			//NewName[i] = '\x0';
			isExt = TRUE;
			swprintf_s(ExtName, MAX_PATH, _T("%s"), FileName + (i));
			break;
		}
	}
	if (isExt)
	{
		if (!_wcsicmp(ExtName, L".exe"))//
			ret = TRUE;
		else if (!_wcsicmp(ExtName, L".com"))
			ret = TRUE;
		else if (!_wcsicmp(ExtName, L".dll"))//
			ret = TRUE;
		else if (!_wcsicmp(ExtName, L".drv"))//
			ret = TRUE;
		//else if(!_wcsicmp(ExtName,L".vxd"))
		//	ret = TRUE;
		else if (!_wcsicmp(ExtName, L".sys"))//
			ret = TRUE;
		else if (!_wcsicmp(ExtName, L".ax"))//
			ret = TRUE;
		else if (!_wcsicmp(ExtName, L".vbx"))
			ret = TRUE;
		//else if(!_wcsicmp(ExtName,L".flt"))
		//	ret = TRUE;
		else if (!_wcsicmp(ExtName, L".scr"))//
			ret = TRUE;
		//else if(!_wcsicmp(ExtName,L".fon"))
		//	ret = TRUE;
		//else if(!_wcsicmp(ExtName,L".aol"))
		//	ret = TRUE;
		else if (!_wcsicmp(ExtName, L".cpl"))//
			ret = TRUE;
		else if (!_wcsicmp(ExtName, L".acm"))//
			ret = TRUE;
		//else if(!_wcsicmp(ExtName,L".tsk"))
		//	ret = TRUE;
		else if (!_wcsicmp(ExtName, L".tsp"))//
			ret = TRUE;
		else if (!_wcsicmp(ExtName, L".mui"))//
			ret = TRUE;
		//else if(!_wcsicmp(ExtName,L".hls"))
		//	ret = TRUE;
		//else if(!_wcsicmp(ExtName,L".tlb"))
		//	ret = TRUE;
		else if (!_wcsicmp(ExtName, L".efi"))//
			ret = TRUE;
		//else if(!_wcsicmp(ExtName,L".dic"))
		//	ret = TRUE;
		else if (!_wcsicmp(ExtName, L".ocx"))//
			ret = TRUE;
		//else if(!_wcsicmp(ExtName,L".olb"))
		//	ret = TRUE;

		if (ret && IsReverset)
			ret = FALSE;
	}
	delete[] ReversetName;
	delete[] ExtName;
	return ret;
}
DWORD Md5HashAndSignature(TCHAR* FileName, TCHAR* HashStr, size_t HashStrlen, BOOL& IsSignature)
{
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HANDLE hFile = NULL;
	BYTE rgbFile[65536];
	DWORD cbRead = 0;
	BYTE rgbHash[16];
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";
	hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		dwStatus = GetLastError();
		// printf("Error opening file %s\nError: %d\n", FileName,dwStatus); 
		return dwStatus;
	}
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		// printf("CryptAcquireContext failed: %d\n", dwStatus); 
		CloseHandle(hFile);
		return dwStatus;
	}
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		dwStatus = GetLastError();
		// printf("CryptAcquireContext failed: %d\n", dwStatus); 
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}
	while (bResult = ReadFile(hFile, rgbFile, 65536, &cbRead, NULL))
	{
		if (0 == cbRead)
		{
			break;
		}
		if (!IsSignature)
			IsSignature = IsPESignature(rgbFile, (unsigned int)cbRead);
		if (!CryptHashData(hHash, rgbFile, cbRead, 0))
		{
			dwStatus = GetLastError();
			// printf("CryptHashData failed: %d\n", dwStatus); 
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			return dwStatus;
		}
	}
	if (!bResult)
	{
		dwStatus = GetLastError();
		//  printf("ReadFile failed: %d\n", dwStatus); 
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		CloseHandle(hFile);
		return dwStatus;
	}
	cbHash = 16;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		for (DWORD i = 0; i < cbHash; i++)
		{
			TCHAR* cstr = new TCHAR[10];
			swprintf_s(cstr, 10, _T("%c%c"), rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
			lstrcat(HashStr, cstr);
			delete[] cstr;
		}
	}
	else
	{
		dwStatus = GetLastError();
		//  printf("CryptGetHashParam failed: %d\n", dwStatus); 
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);
	return dwStatus;
}
BOOL GetIPAndMAC(char* pMAC, char* pIP, char* ServerIP)
{
	BOOL ret = FALSE;
	//	TCHAR * RegistryPath = new TCHAR[MAX_PATH_EX];
	//	swprintf_s(RegistryPath,MAX_PATH_EX,_T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards"));
	//	HKEY hTestKey;
	//	vector<wstring> SubStr;
	//	//ErrorLog("RegOpenKeyEx-Start\n");
	//	if( RegOpenKeyEx(HKEY_LOCAL_MACHINE,
	//        TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards"),
	//        0,
	//        KEY_READ,
	//        &hTestKey) == ERROR_SUCCESS
	//      )
	//	{
	//		QueryKey(hTestKey,&SubStr);
	//	}
	//	RegCloseKey(hTestKey);
	//	//ErrorLog("RegOpenKeyEx-End\n");
	//	if(SubStr.empty())
	//		ret = FALSE;
	//	else
	//	{
	//		vector<NetworkCards> NCInfo;
	//		vector<wstring>::iterator it;
	//		for(it = SubStr.begin();it != SubStr.end();it++)
	//		{
	//			swprintf_s(RegistryPath,MAX_PATH_EX,_T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards\\%s"),(*it).c_str());
	//			//ErrorLog("RegisterInfo-Start\n");
	//			RegisterInfo(&NCInfo,RegistryPath);
	//			//ErrorLog("RegisterInfo-End\n");
	//		}
	//		if(NCInfo.empty())
	//			ret = FALSE;
	//		else
	//		{
	//			//ErrorLog("Searchphysicaladdresses-Start\n");
	//			if(Searchphysicaladdresses(&NCInfo))
	//			{
	//				int MatchNum = 0;
	//				vector<NetworkCards>::iterator NCit;
	//				for(NCit = NCInfo.begin();NCit != NCInfo.end();NCit++)
	//				{
	//					//int aa = strcmp((*NCit).IP,ServerIP);
	//					//printf("Web-%s\n%s\n%s\n%s\n",(*NCit).ServiceName,(*NCit).Description,(*NCit).MAC,(*NCit).IP);
	//					int IsMatch = 0;
	//					int s1,s2,s3,s4;
	//					IPtoken(ServerIP,s1,s2,s3,s4);
	//					int d1,d2,d3,d4;
	//					IPtoken((*NCit).IP,d1,d2,d3,d4);
	//					if(s1 == d1)
	//						IsMatch += 4;
	//					if(s2 == d2)
	//						IsMatch += 2;
	//					if(s3 == d3)
	//						IsMatch += 1;
	//					if(IsMatch > MatchNum)
	//					{
	//						MatchNum = IsMatch;
	//						strcpy_s(pMAC,20,(*NCit).MAC);
	//						strcpy_s(pIP,20,(*NCit).IP);
	//					}
	//				}
	//			}
	//			else
	//				ret = FALSE;
	//			//ErrorLog("Searchphysicaladdresses-End\n");
	//		}
	//		NCInfo.clear();
	//	}
	//	SubStr.clear();
	//	delete [] RegistryPath;
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL)
		return false;
	// Make an initial call to GetAdaptersInfo to get the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL)
			return false;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR)
	{
		int MatchNum = -1;
		int s1, s2, s3, s4;
		IPtoken(ServerIP, s1, s2, s3, s4);
		for (PIP_ADAPTER_INFO pAdapter = pAdapterInfo; pAdapter != NULL; pAdapter = pAdapter->Next)
		{
			//if(pAdapter->Type != MIB_IF_TYPE_ETHERNET)
			//	continue;
			if (pAdapter->AddressLength != 6)
				continue;
			if (!strcmp(pAdapter->IpAddressList.IpAddress.String, "0.0.0.0"))
				continue;
			//sprintf_s(MACstr,StrSize,"%02X-%02X-%02X-%02X-%02X-%02X",
			//int (pAdapter->Address[0]),
			//int (pAdapter->Address[1]),
			//int (pAdapter->Address[2]),
			//int (pAdapter->Address[3]),
			//int (pAdapter->Address[4]),
			//int (pAdapter->Address[5]));
			int IsMatch = 0;
			char* ThisIp = new char[20];
			strcpy_s(ThisIp, 20, pAdapter->IpAddressList.IpAddress.String);
			int d1, d2, d3, d4;
			IPtoken(ThisIp, d1, d2, d3, d4);
			if (s1 == d1)
				IsMatch += 4;
			if (s2 == d2)
				IsMatch += 2;
			if (s3 == d3)
				IsMatch += 1;
			if (IsMatch > MatchNum)
			{
				MatchNum = IsMatch;
				//strcpy_s(pMAC,20,(*NCit).MAC);
				sprintf_s(pMAC, 20, "%02X-%02X-%02X-%02X-%02X-%02X", int(pAdapter->Address[0]), int(pAdapter->Address[1]), int(pAdapter->Address[2]),
					int(pAdapter->Address[3]), int(pAdapter->Address[4]), int(pAdapter->Address[5]));
				strcpy_s(pIP, 20, pAdapter->IpAddressList.IpAddress.String);
			}
			delete[] ThisIp;
			ret = TRUE;
			//break;
		}
	}

	free(pAdapterInfo);
	return ret;
}
void IPtoken(char* IPstr, int& IP1, int& IP2, int& IP3, int& IP4)
{
	char* Str = new char[20];
	strcpy_s(Str, 20, IPstr);
	char* psc;
	char* next_token = NULL;
	int i = 0;
	psc = strtok_s(Str, ".", &next_token);
	while (psc != NULL)
	{
		if (i == 0)
		{
			IP1 = atoi(psc);
		}
		else if (i == 1)
		{
			IP2 = atoi(psc);
		}
		else if (i == 2)
		{
			IP3 = atoi(psc);
		}
		else if (i == 3)
		{
			IP4 = atoi(psc);
			break;
		}
		i++;
		psc = strtok_s(NULL, ".", &next_token);
	}
	delete[] Str;
}
//BOOL Searchphysicaladdresses(vector<NetworkCards> *pInfo)
//{
//	PIP_ADAPTER_INFO pAdapterInfo;
//    PIP_ADAPTER_INFO pAdapter = NULL;
//    DWORD dwRetVal = 0;
//    UINT i;
//
//    //struct tm newtime;
//    //char buffer[32];
//    //errno_t error;
//
//    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);
//    pAdapterInfo = (IP_ADAPTER_INFO *) MALLOC(sizeof (IP_ADAPTER_INFO));
//    if (pAdapterInfo == NULL) 
//	{
//        //printf("Error allocating memory needed to call GetAdaptersinfo\n");
//        return FALSE;
//    }
//
//    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) 
//	{
//        FREE(pAdapterInfo);
//        pAdapterInfo = (IP_ADAPTER_INFO *) MALLOC(ulOutBufLen);
//        if (pAdapterInfo == NULL) {
//            //printf("Error allocating memory needed to call GetAdaptersinfo\n");
//            return FALSE;
//        }
//    }
//	BOOL ret = TRUE;
//    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) 
//	{
//        pAdapter = pAdapterInfo;
//        while (pAdapter) 
//		{
//           // printf("\tComboIndex: \t%d\n", pAdapter->ComboIndex);
//			vector<NetworkCards>::iterator it;
//			for(it = pInfo->begin();it != pInfo->end();it++)
//			{
//				//printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
//				//printf("\tAdapter Desc: \t%s\n", pAdapter->Description);
//				if(!_stricmp((*it).ServiceName,pAdapter->AdapterName) /*&& !_stricmp((*it).Description,pAdapter->Description)*/)
//				{
//					//printf("\tAdapter Addr: \t");
//					memset((*it).MAC,'\0',20);
//					for (i = 0; i < pAdapter->AddressLength; i++) 
//					{
//						if (i == (pAdapter->AddressLength - 1))
//						{
//							char * str = new char[10];
//							//printf("%.2X\n", (int) pAdapter->Address[i]);
//							sprintf_s(str,10,"%.2X",(int) pAdapter->Address[i]);
//							strcat_s((*it).MAC,str);
//							delete [] str;
//						}
//						else
//						{
//							char * str = new char[10];
//							//printf("%.2X-", (int) pAdapter->Address[i]);
//							sprintf_s(str,10,"%.2X-",(int) pAdapter->Address[i]);
//							strcat_s((*it).MAC,str);
//							delete [] str;
//						}
//					}
//            //printf("\tIndex: \t%d\n", pAdapter->Index);
//            //printf("\tType: \t");
//            //switch (pAdapter->Type) {
//            //case MIB_IF_TYPE_OTHER:
//            //    printf("Other\n");
//            //    break;
//            //case MIB_IF_TYPE_ETHERNET:
//            //    printf("Ethernet\n");
//            //    break;
//            //case MIB_IF_TYPE_TOKENRING:
//            //    printf("Token Ring\n");
//            //    break;
//            //case MIB_IF_TYPE_FDDI:
//            //    printf("FDDI\n");
//            //    break;
//            //case MIB_IF_TYPE_PPP:
//            //    printf("PPP\n");
//            //    break;
//            //case MIB_IF_TYPE_LOOPBACK:
//            //    printf("Lookback\n");
//            //    break;
//            //case MIB_IF_TYPE_SLIP:
//            //    printf("Slip\n");
//            //    break;
//            //default:
//            //    printf("Unknown type %ld\n", pAdapter->Type);
//            //    break;
//            //}
//
//					//printf("\tIP Address: \t%s\n", pAdapter->IpAddressList.IpAddress.String);
//					strcpy_s((*it).IP,20,pAdapter->IpAddressList.IpAddress.String);
//					break;
//				}
//            //printf("\tIP Mask: \t%s\n", pAdapter->IpAddressList.IpMask.String);
//			//
//           // printf("\tGateway: \t%s\n", pAdapter->GatewayList.IpAddress.String);
//           // printf("\t***\n");
//			//
//            //if (pAdapter->DhcpEnabled) {
//            //    printf("\tDHCP Enabled: Yes\n");
//            //    printf("\t  DHCP Server: \t%s\n",
//            //           pAdapter->DhcpServer.IpAddress.String);
//			//
//            //    printf("\t  Lease Obtained: ");
//            //    /* Display local time */
//            //    error = _localtime32_s(&newtime, (__time32_t*) &pAdapter->LeaseObtained);
//            //    if (error)
//            //        printf("Invalid Argument to _localtime32_s\n");
//            //    else {
//            //        // Convert to an ASCII representation 
//            //        error = asctime_s(buffer, 32, &newtime);
//            //        if (error)
//            //            printf("Invalid Argument to asctime_s\n");
//            //        else
//            //            /* asctime_s returns the string terminated by \n\0 */
//            //            printf("%s", buffer);
//            //    }
//			//
//              //  printf("\t  Lease Expires:  ");
//              //  error = _localtime32_s(&newtime, (__time32_t*) &pAdapter->LeaseExpires);
//               // if (error)
//               //     printf("Invalid Argument to _localtime32_s\n");
//               // else {
//                    // Convert to an ASCII representation 
//                //    error = asctime_s(buffer, 32, &newtime);
//                 //   if (error)
//                  //      printf("Invalid Argument to asctime_s\n");
//                  //  else
//                     //
//                   //     printf("%s", buffer);
//                //}
//           // } else
//             //   printf("\tDHCP Enabled: No\n");
//			//
//            //if (pAdapter->HaveWins) {
//            //    printf("\tHave Wins: Yes\n");
//            //    printf("\t  Primary Wins Server:    %s\n",
//            //           pAdapter->PrimaryWinsServer.IpAddress.String);
//            //    printf("\t  Secondary Wins Server:  %s\n",
//            //           pAdapter->SecondaryWinsServer.IpAddress.String);
//            //} else
//            //    printf("\tHave Wins: No\n");
//			}
//            pAdapter = pAdapter->Next;
//            //printf("\n");
//        }
//    } 
//	else 
//	{
//       // printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);
//		ret = FALSE;
//    }
//    if (pAdapterInfo)
//        FREE(pAdapterInfo);
//	return ret;
//}
void QueryKey(HKEY hKey, vector<wstring>* pSub)
{
	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
	DWORD    cbName;                   // size of name string 
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
	DWORD    cchClassName = MAX_PATH;  // size of class string 
	DWORD    cSubKeys = 0;               // number of subkeys 
	DWORD    cbMaxSubKey;              // longest subkey size 
	DWORD    cchMaxClass;              // longest class string 
	DWORD    cValues;              // number of values for key 
	DWORD    cchMaxValue;          // longest value name 
	DWORD    cbMaxValueData;       // longest value data 
	DWORD    cbSecurityDescriptor; // size of security descriptor 
	FILETIME ftLastWriteTime;      // last write time 

	DWORD i, retCode;

	//TCHAR  achValue[MAX_VALUE_NAME]; 
	DWORD cchValue = MAX_VALUE_NAME;

	// Get the class name and the value count. 
	retCode = RegQueryInfoKey(
		hKey,                    // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		&cbMaxSubKey,            // longest subkey size 
		&cchMaxClass,            // longest class string 
		&cValues,                // number of values for this key 
		&cchMaxValue,            // longest value name 
		&cbMaxValueData,         // longest value data 
		&cbSecurityDescriptor,   // security descriptor 
		&ftLastWriteTime);       // last write time 

	// Enumerate the subkeys, until RegEnumKeyEx fails.

	if (cSubKeys)
	{
		// printf( "\nNumber of subkeys: %d\n", cSubKeys);

		for (i = 0; i < cSubKeys; i++)
		{
			cbName = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				achKey,
				&cbName,
				NULL,
				NULL,
				NULL,
				&ftLastWriteTime);
			if (retCode == ERROR_SUCCESS)
			{
				// _tprintf(TEXT("(%d) %s\n"), i+1, achKey);
				pSub->push_back(achKey);
			}
		}
	}

	// Enumerate the key values. 
	//
	//if (cValues) 
	//{
	//    printf( "\nNumber of values: %d\n", cValues);
	//
	//    for (i=0, retCode=ERROR_SUCCESS; i<cValues; i++) 
	//    { 
	//        cchValue = MAX_VALUE_NAME; 
	//        achValue[0] = '\0'; 
	//        retCode = RegEnumValue(hKey, i, 
	//            achValue, 
	//            &cchValue, 
	//            NULL, 
	//            NULL,
	//            NULL,
	//            NULL);
	//
	//        if (retCode == ERROR_SUCCESS ) 
	//        { 
	//            _tprintf(TEXT("(%d) %s\n"), i+1, achValue); 
	//        } 
	//    }
	//}
}
//void RegisterInfo(vector<NetworkCards> *pInfo,TCHAR * RegPath)
//{
//	HKEY hKey = NULL;
//	LONG lResult;
//	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE,RegPath, 0, KEY_QUERY_VALUE, &hKey);
// 
//	if (lResult == ERROR_SUCCESS) 
//	{
//		//return;
//
//		DWORD dwValues, dwMaxValueNameLen, dwMaxValueLen;
//		LONG lRet = ::RegQueryInfoKey(hKey, 
//									NULL, NULL,    // lpClass, lpcClass
//									NULL,          // lpReserved
//									NULL, NULL,    // lpcSubKeys, lpcMaxSubKeyLen
//									NULL,          // lpcMaxClassLen
//									&dwValues,
//									&dwMaxValueNameLen,
//									&dwMaxValueLen,
//									NULL,          // lpcbSecurityDescriptor
//									NULL);         // lpftLastWriteTime
//		if(ERROR_SUCCESS == lRet)
//		{  
//			// allocate enough to fit max. length name and value
//			NetworkCards m_NC;
//			LPTSTR pszName = new TCHAR[dwMaxValueNameLen + 1];
//			LPBYTE lpData   = new BYTE[dwMaxValueLen+1];
//			memset(lpData,'\0',dwMaxValueLen+1);
//			for(DWORD dwIndex = 0; dwIndex < dwValues; dwIndex++)
//			{
//				DWORD dwNameSize  = dwMaxValueNameLen + 1;
//				DWORD dwValueSize = dwMaxValueLen;
//				DWORD dwType;
//				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize, 0, &dwType, lpData, &dwValueSize);
//				//wprintf(L"1-%s\n",pszName);
//				if(!_wcsicmp(pszName,_T("Description")))
//				{
//					if(REG_SZ == dwType)
//					{
//						TCHAR * str = new TCHAR[MAX_PATH];
//						swprintf_s(str,MAX_PATH,_T("%s"),lpData);
//						//memcpy(str,lpData,MAX_PATH);
//						char *cstr = CStringToCharArray(str,CP_UTF8);
//						strcpy_s(m_NC.Description,MAX_PATH_EX,cstr);
//						delete [] cstr;
//						delete [] str;
//					}
//				}
//				else if(!_wcsicmp(pszName,_T("ServiceName")))
//				{
//					if(REG_SZ == dwType)
//					{
//						TCHAR * str = new TCHAR[MAX_PATH];
//						swprintf_s(str,MAX_PATH,_T("%s"),lpData);
//						//memcpy(str,lpData,MAX_PATH);
//						char *cstr = CStringToCharArray(str,CP_UTF8);
//						strcpy_s(m_NC.ServiceName,MAX_PATH_EX,cstr);
//						delete [] cstr;
//						delete [] str;
//					}
//				}
//			}
//			pInfo->push_back(m_NC);
//			delete [] pszName;
//			delete [] lpData;
//		}
//	}
//	RegCloseKey(hKey);
//}

//bool IsWin2000()
//{
//	OSVERSIONINFOEX osver = {0};
//	osver.dwOSVersionInfoSize = sizeof(osver);
//    ::GetVersionEx((OSVERSIONINFO*)&osver);
//	
//	if(osver.dwMajorVersion < 5)
//		return true;
//	else if(osver.dwMajorVersion == 5 && osver.dwMinorVersion < 1)
//		return true;
//	else
//		return false;
//}
void FolderClear(TCHAR* FilePath, TCHAR* Extstr)
{
	TCHAR* szTempPath = new TCHAR[MAX_PATH_EX];
	lstrcpy(szTempPath, FilePath);
	lstrcat(szTempPath, Extstr);

	WIN32_FIND_DATA fd;
	HANDLE hSearch = FindFirstFile(szTempPath, &fd);
	if (INVALID_HANDLE_VALUE == hSearch)
	{
		delete[] szTempPath;
		return;
	}
	do
	{
		if ((0 == (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) && (0 != lstrcmp(fd.cFileName, TEXT("."))) && (0 != lstrcmp(fd.cFileName, TEXT(".."))))
		{
			TCHAR* szPath = new TCHAR[MAX_PATH_EX];
			swprintf_s(szPath, MAX_PATH_EX, L"%s\\%s", FilePath, fd.cFileName);
			DeleteFile(szPath);
			delete[] szPath;
		}
	} while (FindNextFile(hSearch, &fd) != FALSE);
	FindClose(hSearch);
	delete[] szTempPath;
}
DWORD CmdCommandWork(wchar_t* COMstr, bool IsWait, unsigned int pSec)
{
	DWORD ret = 0;
	SHELLEXECUTEINFOW ShExecInfo = { 0 };
	ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.hwnd = NULL;
	ShExecInfo.lpVerb = L"open";
	ShExecInfo.lpFile = L"c:\\windows\\system32\\cmd.exe";
	ShExecInfo.lpDirectory = NULL;
	ShExecInfo.nShow = SW_HIDE;
	ShExecInfo.hInstApp = NULL;
	ShExecInfo.lpParameters = COMstr;
	ShellExecuteExW(&ShExecInfo);
	if (IsWait)
	{
		if (pSec == 0)
			ret = WaitForSingleObject(ShExecInfo.hProcess, INFINITE);
		else
			ret = WaitForSingleObject(ShExecInfo.hProcess, pSec);
	}
	return ret;
}
bool memfind(BYTE* Sce, char* ApiStr, int scelen)
{
	int ApiStrlen = (int)strlen(ApiStr);
	for (int i = 0; i < scelen; i++)
	{
		if (i + ApiStrlen > scelen)
			break;
		else
		{
			if (Sce[i] == ApiStr[0])
			{
				bool IsMatch = true;
				for (int j = 0; j < ApiStrlen; j++)
				{
					if (Sce[i + j] != ApiStr[j])
					{
						IsMatch = false;
						break;
					}
				}
				if (IsMatch)
					return true;
			}
		}
	}
	return false;
}
char* Convert2State(DWORD dwState)
{
	char* result = nullptr;

	switch (dwState)
	{
	case MIB_TCP_STATE_CLOSED:
		result = new char[7]; // "x64" + null terminator
		strcpy_s(result, 7, "CLOSED");
		return result;

	case MIB_TCP_STATE_LISTEN:
		result = new char[7]; // "x64" + null terminator
		strcpy_s(result, 7, "LISTEN");
		return result;

	case MIB_TCP_STATE_SYN_SENT:
		result = new char[9]; // "x64" + null terminator
		strcpy_s(result, 9, "SYN_SENT");
		return result;

	case MIB_TCP_STATE_SYN_RCVD:
		result = new char[9]; // "x64" + null terminator
		strcpy_s(result, 9, "SYN_RCVD");
		return result;

	case MIB_TCP_STATE_ESTAB:
		result = new char[12]; // "x64" + null terminator
		strcpy_s(result, 12, "ESTABLISHED");
		return result;

	case MIB_TCP_STATE_FIN_WAIT1:
		result = new char[10]; // "x64" + null terminator
		strcpy_s(result, 10, "FIN_WAIT1");
		return result;

	case MIB_TCP_STATE_FIN_WAIT2:
		result = new char[10]; // "x64" + null terminator
		strcpy_s(result, 10, "FIN_WAIT2");
		return result;

	case MIB_TCP_STATE_CLOSE_WAIT:
		result = new char[11]; // "x64" + null terminator
		strcpy_s(result, 11, "CLOSE_WAIT");
		return result;

	case MIB_TCP_STATE_CLOSING:
		result = new char[8]; // "x64" + null terminator
		strcpy_s(result, 8, "CLOSING");
		return result;

	case MIB_TCP_STATE_LAST_ACK:
		result = new char[9]; // "x64" + null terminator
		strcpy_s(result, 9, "LAST_ACK");
		return result;

	case MIB_TCP_STATE_TIME_WAIT:
		result = new char[10]; // "x64" + null terminator
		strcpy_s(result, 10, "TIME_WAIT");
		return result;

	case MIB_TCP_STATE_DELETE_TCB:
		result = new char[11]; // "x64" + null terminator
		strcpy_s(result, 11, "DELETE_TCB");
		return result;

	default:
		result = new char[8]; // "x64" + null terminator
		strcpy_s(result, 8, "UNKNOWN");
		return result;
	}
}
void GetTcpInformation(vector<string>* pInfo, DWORD Processid)
{
	MIB_TCPTABLE_OWNER_PID* pTCPInfo;
	MIB_TCPROW_OWNER_PID* owner;
	DWORD size;
	DWORD dwResult;

	HMODULE hLib = LoadLibrary(_T("iphlpapi.dll"));

	pGetExtendedTcpTable = (DWORD(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG))
		GetProcAddress(hLib, "GetExtendedTcpTable");

	if (!pGetExtendedTcpTable)
	{
		// printf("Could not load iphlpapi.dll. This application is for Windows XP SP2 and up.\n");
		 //MessageBox(0,L"Could not load iphlpapi.dll. This application is for Windows XP SP2 and up.",0,0);
		return;
	}

	dwResult = pGetExtendedTcpTable(NULL, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	pTCPInfo = (MIB_TCPTABLE_OWNER_PID*)malloc(size);
	dwResult = pGetExtendedTcpTable(pTCPInfo, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

	if (dwResult != NO_ERROR)
	{
		//printf("Couldn't get our IP table");
		//MessageBox(0,L"Couldn't get our IP table",0,0);
		return;
	}

	printf("Iterating though table:\n");
	for (DWORD dwLoop = 0; dwLoop < pTCPInfo->dwNumEntries; dwLoop++)
	{
		owner = &pTCPInfo->table[dwLoop];
		if (owner->dwOwningPid == Processid)
		{
			WORD add1, add2, add3, add4;
			add1 = (WORD)(owner->dwLocalAddr & 255);
			add2 = (WORD)((owner->dwLocalAddr >> 8) & 255);
			add3 = (WORD)((owner->dwLocalAddr >> 16) & 255);
			add4 = (WORD)((owner->dwLocalAddr >> 24) & 255);
			WORD add5, add6, add7, add8;
			add5 = (WORD)(owner->dwRemoteAddr & 255);
			add6 = (WORD)((owner->dwRemoteAddr >> 8) & 255);
			add7 = (WORD)((owner->dwRemoteAddr >> 16) & 255);
			add8 = (WORD)((owner->dwRemoteAddr >> 24) & 255);
			char str[65536];
			sprintf_s(str, 65536, "Net:%d.%d.%d.%d|%u|%d.%d.%d.%d|%u|%s\n", add1, add2, add3, add4, ntohs((u_short)owner->dwLocalPort), add5, add6, add7, add8, ntohs((u_short)owner->dwRemotePort), Convert2State(owner->dwState));
			pInfo->push_back(str);
			//delete [] str;
			//printf("TCP PID: %5u - Local Address: %d.%d.%d.%d - Local Port: %5u - Remote Address: %d.%d.%d.%d - Remote Port: %5u - State:%s\n",owner->dwOwningPid, add1,add2,add3,add4,ntohs((u_short)owner->dwLocalPort),
			//	add5,add6,add7,add8,ntohs((u_short)owner->dwRemotePort),Convert2State(owner->dwState));
		}
	}
	FreeLibrary(hLib);
	free(pTCPInfo);
	pTCPInfo = NULL;
}
void GetTcpInformationEx(vector<TCPInformation>* pInfo)
{
	MIB_TCPTABLE_OWNER_PID* pTCPInfo;
	MIB_TCPROW_OWNER_PID* owner;
	DWORD size;
	DWORD dwResult;

	HMODULE hLib = LoadLibrary(_T("iphlpapi.dll"));

	pGetExtendedTcpTable = (DWORD(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG))
		GetProcAddress(hLib, "GetExtendedTcpTable");

	if (!pGetExtendedTcpTable)
	{
		// printf("Could not load iphlpapi.dll. This application is for Windows XP SP2 and up.\n");
		 //MessageBox(0,L"Could not load iphlpapi.dll. This application is for Windows XP SP2 and up.",0,0);
		return;
	}

	dwResult = pGetExtendedTcpTable(NULL, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	pTCPInfo = (MIB_TCPTABLE_OWNER_PID*)malloc(size);
	dwResult = pGetExtendedTcpTable(pTCPInfo, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

	if (dwResult != NO_ERROR)
	{
		//printf("Couldn't get our IP table");
		//MessageBox(0,L"Couldn't get our IP table",0,0);
		return;
	}

	//printf("Iterating though table:\n");
	for (DWORD dwLoop = 0; dwLoop < pTCPInfo->dwNumEntries; dwLoop++)
	{
		TCPInformation m_Info;
		owner = &pTCPInfo->table[dwLoop];
		m_Info.ProcessID = owner->dwOwningPid;
		m_Info.LocalAddr = owner->dwLocalAddr;
		m_Info.LocalPort = owner->dwLocalPort;
		m_Info.RemoteAddr = owner->dwRemoteAddr;
		m_Info.RemotePort = owner->dwRemotePort;
		m_Info.State = owner->dwState;

		pInfo->push_back(m_Info);
	}
	FreeLibrary(hLib);
	free(pTCPInfo);
	pTCPInfo = NULL;
}
void GetTcpInformationXP(vector<string>* pInfo, DWORD Processid)
{
	pAllocateAndGetTcpExTableFromStack pGetTcpTableEx = NULL;
	HMODULE hLib = LoadLibrary(_T("iphlpapi.dll"));
	if (hLib == NULL)
	{
		return;
	}
	PMIB_TCPTABLE_EX m_pBuffTcpTableEx;

	//point to the magic method
	pGetTcpTableEx = (pAllocateAndGetTcpExTableFromStack)GetProcAddress(
		hLib, "AllocateAndGetTcpExTableFromStack");
	if (pGetTcpTableEx == NULL)
	{
		//MessageBox(0,"B",0,0);
		return;
	}
	(pGetTcpTableEx)(&m_pBuffTcpTableEx, TRUE, GetProcessHeap(), 0, 2);

	for (int i = 0; i < (int)m_pBuffTcpTableEx->dwNumEntries; i++)
	{
		if (m_pBuffTcpTableEx->table[i].dwProcessId == Processid)
		{
			WORD add1, add2, add3, add4;

			add1 = (WORD)(m_pBuffTcpTableEx->table[i].dwLocalAddr & 255);
			add2 = (WORD)((m_pBuffTcpTableEx->table[i].dwLocalAddr >> 8) & 255);
			add3 = (WORD)((m_pBuffTcpTableEx->table[i].dwLocalAddr >> 16) & 255);
			add4 = (WORD)((m_pBuffTcpTableEx->table[i].dwLocalAddr >> 24) & 255);
			WORD add5, add6, add7, add8;
			add5 = (WORD)(m_pBuffTcpTableEx->table[i].dwRemoteAddr & 255);
			add6 = (WORD)((m_pBuffTcpTableEx->table[i].dwRemoteAddr >> 8) & 255);
			add7 = (WORD)((m_pBuffTcpTableEx->table[i].dwRemoteAddr >> 16) & 255);
			add8 = (WORD)((m_pBuffTcpTableEx->table[i].dwRemoteAddr >> 24) & 255);
			char str[65536];
			sprintf_s(str, 65536, "Net:%d.%d.%d.%d|%u|%d.%d.%d.%d|%u|%s\n", add1, add2, add3, add4, ntohs((u_short)m_pBuffTcpTableEx->table[i].dwLocalPort), add5, add6, add7, add8, ntohs((u_short)m_pBuffTcpTableEx->table[i].dwRemotePort), Convert2State(m_pBuffTcpTableEx->table[i].dwState));
			pInfo->push_back(str);
			//printf("TCP PID: %5u - Local Address: %d.%d.%d.%d - Local Port: %5u - Remote Address: %d.%d.%d.%d - Remote Port: %5u - State:%s\n",m_pBuffTcpTableEx->table[i].dwProcessId, add1,add2,add3,add4,ntohs((u_short)m_pBuffTcpTableEx->table[i].dwLocalPort),
			//	add5,add6,add7,add8,ntohs((u_short)m_pBuffTcpTableEx->table[i].dwRemotePort),Convert2State(m_pBuffTcpTableEx->table[i].dwState));
		}
	}

	FreeLibrary(hLib);
}
void GetTcpInformationXPEx(vector<TCPInformation>* pInfo)
{
	pAllocateAndGetTcpExTableFromStack pGetTcpTableEx = NULL;
	HMODULE hLib = LoadLibrary(_T("iphlpapi.dll"));
	if (hLib == NULL)
	{
		return;
	}
	PMIB_TCPTABLE_EX m_pBuffTcpTableEx;

	//point to the magic method
	pGetTcpTableEx = (pAllocateAndGetTcpExTableFromStack)GetProcAddress(
		hLib, "AllocateAndGetTcpExTableFromStack");
	if (pGetTcpTableEx == NULL)
	{
		return;
	}
	(pGetTcpTableEx)(&m_pBuffTcpTableEx, TRUE, GetProcessHeap(), 0, 2);

	for (int i = 0; i < (int)m_pBuffTcpTableEx->dwNumEntries; i++)
	{
		TCPInformation m_Info;
		m_Info.ProcessID = m_pBuffTcpTableEx->table[i].dwProcessId;
		m_Info.LocalAddr = m_pBuffTcpTableEx->table[i].dwLocalAddr;
		m_Info.LocalPort = m_pBuffTcpTableEx->table[i].dwLocalPort;
		m_Info.RemoteAddr = m_pBuffTcpTableEx->table[i].dwRemoteAddr;
		m_Info.RemotePort = m_pBuffTcpTableEx->table[i].dwRemotePort;
		m_Info.State = m_pBuffTcpTableEx->table[i].dwState;

		pInfo->push_back(m_Info);
	}
	FreeLibrary(hLib);
}
DWORD Md5HashAndData(TCHAR* FileName, TCHAR* HashStr, vector<BYTE>* pbuf)
{
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HANDLE hFile = NULL;
	BYTE rgbFile[1024];
	DWORD cbRead = 0;
	BYTE rgbHash[16];
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";
	// LPCWSTR filename=L"C:\\Users\\RexLin\\Pictures\\Saved Pictures\\Koala.jpg";
	hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		dwStatus = GetLastError();
		// printf("Error opening file %s\nError: %d\n", FileName,dwStatus); 
		return dwStatus;
	}
	DWORD m_Filesize = GetFileSize(hFile, NULL);

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		// printf("CryptAcquireContext failed: %d\n", dwStatus); 
		CloseHandle(hFile);
		return dwStatus;
	}
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		dwStatus = GetLastError();
		// printf("CryptAcquireContext failed: %d\n", dwStatus); 
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}
	while (bResult = ReadFile(hFile, rgbFile, 1024, &cbRead, NULL))
	{
		if (0 == cbRead)
		{
			break;
		}

		if (!CryptHashData(hHash, rgbFile, cbRead, 0))
		{
			dwStatus = GetLastError();
			// printf("CryptHashData failed: %d\n", dwStatus); 
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			return dwStatus;
		}
		else
		{
			if (m_Filesize <= 10485760)
			{
				//pbuf
				for (DWORD i = 0; i < cbRead; i++)
				{
					pbuf->push_back(rgbFile[i]);
				}
			}
		}
	}
	if (!bResult)
	{
		dwStatus = GetLastError();
		// printf("ReadFile failed: %d\n", dwStatus); 
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		CloseHandle(hFile);
		return dwStatus;
	}
	cbHash = 16;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		// printf("MD5 hash of file %s is: ", FileName);
		for (DWORD i = 0; i < cbHash; i++)
		{
			TCHAR* cstr = new TCHAR[10];
			swprintf_s(cstr, 10, _T("%c%c"), rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
			lstrcat(HashStr, cstr);
			delete[] cstr;
			// printf("%c%c", rgbDigits[rgbHash[i] >> 4],rgbDigits[rgbHash[i] & 0xf]);
			 //swprintf_s(HashStr,HashStrlen,_T("%s%c%c"),HashStr,rgbDigits[rgbHash[i] >> 4],rgbDigits[rgbHash[i] & 0xf]);
		}
		// printf("\n");
	}
	else
	{
		dwStatus = GetLastError();
		// printf("CryptGetHashParam failed: %d\n", dwStatus); 
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);
	return dwStatus;
}
bool GetDigitalSignature(TCHAR* m_Path, DigitalSignatureInfo* pInfo)
{
	WCHAR szFileName[MAX_PATH];
	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	BOOL fResult;
	DWORD dwEncoding, dwContentType, dwFormatType;
	PCMSG_SIGNER_INFO pSignerInfo = NULL;
	PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
	DWORD dwSignerInfo;
	CERT_INFO CertInfo;
	SPROG_PUBLISHERINFO ProgPubInfo;
	SYSTEMTIME st;

	ZeroMemory(&ProgPubInfo, sizeof(ProgPubInfo));
	bool ret = true;
	__try
	{

#ifdef UNICODE
		if (_waccess(m_Path, 00))
		{
			//_tprintf(_T("No File\n"));
			return false;
		}
		lstrcpynW(szFileName, m_Path, MAX_PATH);
#else
		if (mbstowcs(szFileName, m_Path, MAX_PATH) == -1)
		{
			printf("Unable to convert to unicode.\n");
			__leave;
		}
#endif
		// Get message handle and store handle from the signed file.
		fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
			szFileName,
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
			CERT_QUERY_FORMAT_FLAG_BINARY,
			0,
			&dwEncoding,
			&dwContentType,
			&dwFormatType,
			&hStore,
			&hMsg,
			NULL);
		if (!fResult)
		{
			//_tprintf(_T("CryptQueryObject failed with %x\n"), GetLastError());
			ret = false;
			__leave;
		}

		// Get signer information size.
		fResult = CryptMsgGetParam(hMsg,
			CMSG_SIGNER_INFO_PARAM,
			0,
			NULL,
			&dwSignerInfo);
		if (!fResult)
		{
			//_tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
			__leave;
		}

		// Allocate memory for signer information.
		pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
		if (!pSignerInfo)
		{
			//_tprintf(_T("Unable to allocate memory for Signer Info.\n"));
			__leave;
		}

		// Get Signer Information.
		fResult = CryptMsgGetParam(hMsg,
			CMSG_SIGNER_INFO_PARAM,
			0,
			(PVOID)pSignerInfo,
			&dwSignerInfo);
		if (!fResult)
		{
			//_tprintf(_T("CryptMsgGetParam failed with %x\n"), GetLastError());
			__leave;
		}

		// Get program name and publisher information from 
		// signer info structure.
		if (GetProgAndPublisherInfo(pSignerInfo, &ProgPubInfo))
		{
			if (ProgPubInfo.lpszProgramName != NULL)
			{
				//wprintf(L"Program Name : %s\n",
				 //   ProgPubInfo.lpszProgramName);
				swprintf_s(pInfo->ProgramName, 256, L"%s", ProgPubInfo.lpszProgramName);
			}

			if (ProgPubInfo.lpszPublisherLink != NULL)
			{
				//wprintf(L"Publisher Link : %s\n",
				//    ProgPubInfo.lpszPublisherLink);
				swprintf_s(pInfo->PublisherLink, 256, L"%s", ProgPubInfo.lpszPublisherLink);
			}

			if (ProgPubInfo.lpszMoreInfoLink != NULL)
			{
				//wprintf(L"MoreInfo Link : %s\n",
				//    ProgPubInfo.lpszMoreInfoLink);
				swprintf_s(pInfo->MoreInfoLink, 256, L"%s", ProgPubInfo.lpszMoreInfoLink);
			}
		}

		//_tprintf(_T("\n"));

		// Search for the signer certificate in the temporary 
		// certificate store.
		CertInfo.Issuer = pSignerInfo->Issuer;
		CertInfo.SerialNumber = pSignerInfo->SerialNumber;

		pCertContext = CertFindCertificateInStore(hStore,
			ENCODING,
			0,
			CERT_FIND_SUBJECT_CERT,
			(PVOID)&CertInfo,
			NULL);
		if (!pCertContext)
		{
			//_tprintf(_T("CertFindCertificateInStore failed with %x\n"),
			//    GetLastError());
			__leave;
		}

		// Print Signer certificate information.
	   // _tprintf(_T("Signer Certificate:\n\n"));        
		PrintCertificateInfo(pCertContext, pInfo, _T("Signer"));
		//_tprintf(_T("\n"));

		// Get the timestamp certificate signerinfo structure.
		if (GetTimeStampSignerInfo(pSignerInfo, &pCounterSignerInfo))
		{
			// Search for Timestamp certificate in the temporary
			// certificate store.
			CertInfo.Issuer = pCounterSignerInfo->Issuer;
			CertInfo.SerialNumber = pCounterSignerInfo->SerialNumber;

			pCertContext = CertFindCertificateInStore(hStore,
				ENCODING,
				0,
				CERT_FIND_SUBJECT_CERT,
				(PVOID)&CertInfo,
				NULL);
			if (!pCertContext)
			{
				_tprintf(_T("CertFindCertificateInStore failed with %x\n"),
					GetLastError());
				__leave;
			}

			// Print timestamp certificate information.
			//_tprintf(_T("TimeStamp Certificate:\n\n"));
			PrintCertificateInfo(pCertContext, pInfo, _T("TimeStamp"));
			//_tprintf(_T("\n"));

			// Find Date of timestamp.
			if (GetDateOfTimeStamp(pCounterSignerInfo, &st))
			{
				pInfo->DateofTimeStamp = st;
				//_tprintf(_T("Date of TimeStamp : %02d/%02d/%04d %02d:%02d\n"),
				//                            st.wMonth,
				//                            st.wDay,
				//                            st.wYear,
				//                            st.wHour,
				//                            st.wMinute);
				//swprintf_s(pInfo->DateofTimeStamp,256,_T("%02d/%02d/%04d %02d:%02d"),st.wMonth,st.wDay,st.wYear,st.wHour,st.wMinute);
			}
			//_tprintf(_T("\n"));
		}
	}
	__finally
	{
		// Clean up.
		if (ProgPubInfo.lpszProgramName != NULL)
			LocalFree(ProgPubInfo.lpszProgramName);
		if (ProgPubInfo.lpszPublisherLink != NULL)
			LocalFree(ProgPubInfo.lpszPublisherLink);
		if (ProgPubInfo.lpszMoreInfoLink != NULL)
			LocalFree(ProgPubInfo.lpszMoreInfoLink);

		if (pSignerInfo != NULL) LocalFree(pSignerInfo);
		if (pCounterSignerInfo != NULL) LocalFree(pCounterSignerInfo);
		if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
		if (hStore != NULL) CertCloseStore(hStore, 0);
		if (hMsg != NULL) CryptMsgClose(hMsg);
	}
	return ret;
}
BOOL PrintCertificateInfo(PCCERT_CONTEXT pCertContext, DigitalSignatureInfo* pInfo, const wchar_t* pType)
{
	BOOL fReturn = FALSE;
	LPTSTR szName = NULL;
	DWORD dwData;

	__try
	{
		// Print Serial Number.
	   // _tprintf(_T("Serial Number: "));
		if (!_tcscmp(pType, _T("Signer")))
		{
			memset(pInfo->SignerSerialNumber, '\0', 256);
			dwData = pCertContext->pCertInfo->SerialNumber.cbData;
			for (DWORD n = 0; n < dwData; n++)
			{
				//_tprintf(_T("%02x "),
				  //pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
				TCHAR* cstr = new TCHAR[10];
				swprintf_s(cstr, 10, _T("%02x "), pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
				_tcscat_s(pInfo->SignerSerialNumber, cstr);
				delete[] cstr;
			}
		}
		else if (!_tcscmp(pType, _T("TimeStamp")))
		{
			memset(pInfo->TimeStampSerialNumber, '\0', 256);
			dwData = pCertContext->pCertInfo->SerialNumber.cbData;
			for (DWORD n = 0; n < dwData; n++)
			{
				//_tprintf(_T("%02x "),
				  //pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
				TCHAR* cstr = new TCHAR[10];
				swprintf_s(cstr, 10, _T("%02x "), pCertContext->pCertInfo->SerialNumber.pbData[dwData - (n + 1)]);
				_tcscat_s(pInfo->TimeStampSerialNumber, cstr);
				delete[] cstr;
			}
		}
		// _tprintf(_T("\n"));

		 // Get Issuer name size.
		if (!(dwData = CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			CERT_NAME_ISSUER_FLAG,
			NULL,
			NULL,
			0)))
		{
			// _tprintf(_T("CertGetNameString failed.\n"));
			__leave;
		}

		// Allocate memory for Issuer name.
		szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
		if (!szName)
		{
			// _tprintf(_T("Unable to allocate memory for issuer name.\n"));
			__leave;
		}

		// Get Issuer name.
		if (!(CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			CERT_NAME_ISSUER_FLAG,
			NULL,
			szName,
			dwData)))
		{
			//_tprintf(_T("CertGetNameString failed.\n"));
			__leave;
		}

		// print Issuer name.
		//_tprintf(_T("Issuer Name: %s\n"), szName);
		if (!_tcscmp(pType, _T("Signer")))
		{
			swprintf_s(pInfo->SignerIssuerName, 256, _T("%s"), szName);
		}
		else if (!_tcscmp(pType, _T("TimeStamp")))
		{
			swprintf_s(pInfo->TimeStampIssuerName, 256, _T("%s"), szName);
		}
		LocalFree(szName);
		szName = NULL;

		// Get Subject name size.
		if (!(dwData = CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			NULL,
			0)))
		{
			//_tprintf(_T("CertGetNameString failed.\n"));
			__leave;
		}

		// Allocate memory for subject name.
		szName = (LPTSTR)LocalAlloc(LPTR, dwData * sizeof(TCHAR));
		if (!szName)
		{
			//_tprintf(_T("Unable to allocate memory for subject name.\n"));
			__leave;
		}

		// Get subject name.
		if (!(CertGetNameString(pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			szName,
			dwData)))
		{
			//_tprintf(_T("CertGetNameString failed.\n"));
			__leave;
		}

		// Print Subject Name.
		//_tprintf(_T("Subject Name: %s\n"), szName);
		if (!_tcscmp(pType, _T("Signer")))
		{
			swprintf_s(pInfo->SignerSubjectName, 256, _T("%s"), szName);
		}
		else if (!_tcscmp(pType, _T("TimeStamp")))
		{
			swprintf_s(pInfo->TimeStampSubjectName, 256, _T("%s"), szName);
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (szName != NULL) LocalFree(szName);
	}

	return fReturn;
}

LPWSTR AllocateAndCopyWideString(LPCWSTR inputString)
{
	LPWSTR outputString = NULL;

	outputString = (LPWSTR)LocalAlloc(LPTR,
		(wcslen(inputString) + 1) * sizeof(WCHAR));
	if (outputString != NULL)
	{
		lstrcpyW(outputString, inputString);
	}
	return outputString;
}

BOOL GetProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo,
	PSPROG_PUBLISHERINFO Info)
{
	BOOL fReturn = FALSE;
	PSPC_SP_OPUS_INFO OpusInfo = NULL;
	DWORD dwData;
	BOOL fResult;

	__try
	{
		// Loop through authenticated attributes and find
		// SPC_SP_OPUS_INFO_OBJID OID.
		for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
		{
			if (lstrcmpA(SPC_SP_OPUS_INFO_OBJID,
				pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
			{
				// Get Size of SPC_SP_OPUS_INFO structure.
				fResult = CryptDecodeObject(ENCODING,
					SPC_SP_OPUS_INFO_OBJID,
					pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
					pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
					0,
					NULL,
					&dwData);
				if (!fResult)
				{
					_tprintf(_T("CryptDecodeObject failed with %x\n"),
						GetLastError());
					__leave;
				}

				// Allocate memory for SPC_SP_OPUS_INFO structure.
				OpusInfo = (PSPC_SP_OPUS_INFO)LocalAlloc(LPTR, dwData);
				if (!OpusInfo)
				{
					_tprintf(_T("Unable to allocate memory for Publisher Info.\n"));
					__leave;
				}

				// Decode and get SPC_SP_OPUS_INFO structure.
				fResult = CryptDecodeObject(ENCODING,
					SPC_SP_OPUS_INFO_OBJID,
					pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
					pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
					0,
					OpusInfo,
					&dwData);
				if (!fResult)
				{
					_tprintf(_T("CryptDecodeObject failed with %x\n"),
						GetLastError());
					__leave;
				}

				// Fill in Program Name if present.
				if (OpusInfo->pwszProgramName)
				{
					Info->lpszProgramName =
						AllocateAndCopyWideString(OpusInfo->pwszProgramName);
				}
				else
					Info->lpszProgramName = NULL;

				// Fill in Publisher Information if present.
				if (OpusInfo->pPublisherInfo)
				{

					switch (OpusInfo->pPublisherInfo->dwLinkChoice)
					{
					case SPC_URL_LINK_CHOICE:
						Info->lpszPublisherLink =
							AllocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszUrl);
						break;

					case SPC_FILE_LINK_CHOICE:
						Info->lpszPublisherLink =
							AllocateAndCopyWideString(OpusInfo->pPublisherInfo->pwszFile);
						break;

					default:
						Info->lpszPublisherLink = NULL;
						break;
					}
				}
				else
				{
					Info->lpszPublisherLink = NULL;
				}

				// Fill in More Info if present.
				if (OpusInfo->pMoreInfo)
				{
					switch (OpusInfo->pMoreInfo->dwLinkChoice)
					{
					case SPC_URL_LINK_CHOICE:
						Info->lpszMoreInfoLink =
							AllocateAndCopyWideString(OpusInfo->pMoreInfo->pwszUrl);
						break;

					case SPC_FILE_LINK_CHOICE:
						Info->lpszMoreInfoLink =
							AllocateAndCopyWideString(OpusInfo->pMoreInfo->pwszFile);
						break;

					default:
						Info->lpszMoreInfoLink = NULL;
						break;
					}
				}
				else
				{
					Info->lpszMoreInfoLink = NULL;
				}

				fReturn = TRUE;

				break; // Break from for loop.
			} // lstrcmp SPC_SP_OPUS_INFO_OBJID                 
		} // for 
	}
	__finally
	{
		if (OpusInfo != NULL) LocalFree(OpusInfo);
	}

	return fReturn;
}

BOOL GetDateOfTimeStamp(PCMSG_SIGNER_INFO pSignerInfo, SYSTEMTIME* st)
{
	BOOL fResult;
	FILETIME lft, ft;
	DWORD dwData;
	BOOL fReturn = FALSE;

	// Loop through authenticated attributes and find
	// szOID_RSA_signingTime OID.
	for (DWORD n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
	{
		if (lstrcmpA(szOID_RSA_signingTime,
			pSignerInfo->AuthAttrs.rgAttr[n].pszObjId) == 0)
		{
			// Decode and get FILETIME structure.
			dwData = sizeof(ft);
			fResult = CryptDecodeObject(ENCODING,
				szOID_RSA_signingTime,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
				pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
				0,
				(PVOID)&ft,
				&dwData);
			if (!fResult)
			{
				_tprintf(_T("CryptDecodeObject failed with %x\n"),
					GetLastError());
				break;
			}

			// Convert to local time.
			FileTimeToLocalFileTime(&ft, &lft);
			FileTimeToSystemTime(&lft, st);

			fReturn = TRUE;

			break; // Break from for loop.

		} //lstrcmp szOID_RSA_signingTime
	} // for 

	return fReturn;
}

BOOL GetTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO* pCounterSignerInfo)
{
	PCCERT_CONTEXT pCertContext = NULL;
	BOOL fReturn = FALSE;
	BOOL fResult;
	DWORD dwSize;

	__try
	{
		*pCounterSignerInfo = NULL;

		// Loop through unathenticated attributes for
		// szOID_RSA_counterSign OID.
		for (DWORD n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
		{
			if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId,
				szOID_RSA_counterSign) == 0)
			{
				// Get size of CMSG_SIGNER_INFO structure.
				fResult = CryptDecodeObject(ENCODING,
					PKCS7_SIGNER_INFO,
					pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
					pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
					0,
					NULL,
					&dwSize);
				if (!fResult)
				{
					_tprintf(_T("CryptDecodeObject failed with %x\n"),
						GetLastError());
					__leave;
				}

				// Allocate memory for CMSG_SIGNER_INFO.
				*pCounterSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSize);
				if (!*pCounterSignerInfo)
				{
					_tprintf(_T("Unable to allocate memory for timestamp info.\n"));
					__leave;
				}

				// Decode and get CMSG_SIGNER_INFO structure
				// for timestamp certificate.
				fResult = CryptDecodeObject(ENCODING,
					PKCS7_SIGNER_INFO,
					pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
					pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
					0,
					(PVOID)*pCounterSignerInfo,
					&dwSize);
				if (!fResult)
				{
					_tprintf(_T("CryptDecodeObject failed with %x\n"),
						GetLastError());
					__leave;
				}

				fReturn = TRUE;

				break; // Break from for loop.
			}
		}
	}
	__finally
	{
		// Clean up.
		if (pCertContext != NULL) CertFreeCertificateContext(pCertContext);
	}

	return fReturn;
}
void GetMyPath(wchar_t* wtr)
{
	GetModuleFileName(GetModuleHandle(NULL), wtr, MAX_PATH_EX);
	for (int i = (int)wcslen(wtr) - 1; i >= 0; i--)
	{
		if (wtr[i] == '\\')
		{
			wtr[i] = '\x0';
			break;
		}
	}
}
void GetMyPathA(char* str)
{
	GetModuleFileNameA(GetModuleHandle(NULL), str, 512);
	for (int i = (int)strlen(str) - 1; i >= 0; i--)
	{
		if (str[i] == '\\')
		{
			str[i] = '\x0';
			break;
		}
	}
}
DWORD Md5StringHash(char* SourceStr, TCHAR* HashStr)
{
	memset(HashStr, '\0', 50);
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE rgbHash[16];
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		return dwStatus;
	}
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}
	if (!CryptHashData(hHash, (BYTE*)SourceStr, (DWORD)strlen(SourceStr), 0))
	{
		dwStatus = GetLastError();
		printf("CryptHashData failed: %d\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return dwStatus;
	}
	cbHash = 16;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		for (DWORD i = 0; i < cbHash; i++)
		{
			TCHAR* cstr = new TCHAR[10];
			swprintf_s(cstr, 10, _T("%c%c"), rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
			lstrcat(HashStr, cstr);
			delete[] cstr;
		}
	}
	else
	{
		dwStatus = GetLastError();
		printf("CryptGetHashParam failed: %d\n", dwStatus);
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	return dwStatus;
}
void DeleteExt(TCHAR* str)
{
	for (int i = (int)wcslen(str) - 1; i >= 0; i--)
	{
		if (str[i] == '.')
		{
			str[i] = '\x0';
			break;
		}
	}
}
void DeleteSys(TCHAR* str)
{
	for (int i = (int)wcslen(str) - 1; i >= 0; i--)
	{
		if (str[i] == '-')
		{
			str[i] = '\x0';
			break;
		}
	}
}
void ClearMyFolderOtherFile()
{
	TCHAR* m_Path = new TCHAR[MAX_PATH];
	TCHAR* szTempPath = new TCHAR[MAX_PATH];
	GetMyPath(m_Path);
	lstrcpy(szTempPath, m_Path);
	lstrcat(szTempPath, TEXT("\\*.*"));
	WIN32_FIND_DATA fd;
	HANDLE hSearch = FindFirstFile(szTempPath, &fd);
	if (INVALID_HANDLE_VALUE != hSearch)
	{
		do
		{
			if ((0 == (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) && (0 != lstrcmp(fd.cFileName, TEXT("."))) && (0 != lstrcmp(fd.cFileName, TEXT(".."))))
			{
				if (!_tcsicmp(fd.cFileName, _T("ClientSearch.exe")) || !_tcsicmp(fd.cFileName, _T("StartSearch.exe")) ||
					!_tcsicmp(fd.cFileName, _T("Detector")) || !_tcsicmp(fd.cFileName, _T("eDetector.ptn")) || !_tcsicmp(fd.cFileName, _T("Detectdriver.sys"))
					|| !_tcsicmp(fd.cFileName, _T("iForensicsService.exe")) || !_tcsicmp(fd.cFileName, _T("iForensicsService.cfg")) || !_tcsicmp(fd.cFileName, _T("ClientSearch.cfg"))
					|| !_tcsicmp(fd.cFileName, _T("EnumProcess.sys")) || !_tcsicmp(fd.cFileName, _T("WhiteList.dll")))
					continue;
				TCHAR* szPath = new TCHAR[_MAX_PATH];
				swprintf_s(szPath, _MAX_PATH, L"%s\\%s", m_Path, fd.cFileName);
				DeleteFile(szPath);
				delete[] szPath;
			}
		} while (FindNextFile(hSearch, &fd) != FALSE);
		FindClose(hSearch);
	}
	delete[] szTempPath;
	delete[] m_Path;
}
void LoadRegHistorySubKeys(HKEY pKey, const wchar_t* pPath, vector<wstring>* wtr)
{
	HKEY hTestKey;
	if (RegOpenKeyEx(pKey,
		pPath,
		0,
		KEY_READ,
		&hTestKey) == ERROR_SUCCESS
		)
	{
		QueryKey(hTestKey, wtr);
	}
	RegCloseKey(hTestKey);
}
bool GetRegHistoryREG_DWORDValue(HKEY pKey, const wchar_t* pPath, const wchar_t* pName, DWORD& pValue)
{
	bool ret = true;
	long lRet;
	HKEY hKey;
	DWORD m_Value;
	DWORD dwType = REG_DWORD;
	DWORD dwValue;
	lRet = RegOpenKeyEx(pKey, pPath, 0, KEY_QUERY_VALUE, &hKey);
	if (lRet == ERROR_SUCCESS)
	{
		lRet = RegQueryValueEx(hKey, pName, 0, &dwType, (LPBYTE)&m_Value, &dwValue);
		if (lRet == ERROR_SUCCESS)
		{
			pValue = m_Value;
		}
		else
		{
			ret = false;
		}
	}
	else
	{
		ret = false;
	}
	RegCloseKey(hKey);
	return ret;
}
bool GetRegHistoryREG_SZValue(HKEY pKey, const wchar_t* pPath, const wchar_t* pName, DWORD pType, TCHAR* pValue)
{
	bool ret = true;
	//HKEY  hKey = NULL;
	//DWORD dwSize = 0;
	//DWORD dwDataType = pType;
	//LPBYTE lpValue   = NULL;
	//LPCTSTR const lpValueName = pName;
 //
	//LONG lRet = ::RegOpenKeyEx(pKey,pPath,0,KEY_QUERY_VALUE,&hKey);
	//if(ERROR_SUCCESS == lRet)
	//{
	//	::RegQueryValueEx(hKey,lpValueName,0,&dwDataType,lpValue,&dwSize); 
	//	lpValue = (LPBYTE)malloc(dwSize);
	//	lRet = ::RegQueryValueEx(hKey,lpValueName,0,&dwDataType,lpValue,&dwSize);
	//	if(ERROR_SUCCESS == lRet)
	//	{
	//		swprintf_s(pValue,512,_T("%s"),lpValue);
	//	}
	//	else
	//	{
	//		ret = false;
	//	}
	//	free(lpValue);
	//}
	//else
	//{
	//	ret = false;
	//}
	//::RegCloseKey(hKey);
	HKEY hKey = NULL;
	LONG lResult;


	lResult = RegOpenKeyEx(pKey, pPath, 0, KEY_QUERY_VALUE, &hKey);

	if (lResult == ERROR_SUCCESS)
	{

		DWORD dwValues, dwMaxValueNameLen, dwMaxValueLen;
		LONG lRet = ::RegQueryInfoKey(hKey,
			NULL, NULL,    // lpClass, lpcClass
			NULL,          // lpReserved
			NULL, NULL,    // lpcSubKeys, lpcMaxSubKeyLen
			NULL,          // lpcMaxClassLen
			&dwValues,
			&dwMaxValueNameLen,
			&dwMaxValueLen,
			NULL,          // lpcbSecurityDescriptor
			NULL);         // lpftLastWriteTime
		if (ERROR_SUCCESS == lRet)
		{
			// allocate enough to fit max. length name and value
			LPTSTR pszName = new TCHAR[dwMaxValueNameLen + 1];
			LPBYTE lpData = new BYTE[dwMaxValueLen + 1];
			memset(lpData, '\0', dwMaxValueLen + 1);
			for (DWORD dwIndex = 0; dwIndex < dwValues; dwIndex++)
			{
				DWORD dwNameSize = dwMaxValueNameLen + 1;
				DWORD dwValueSize = dwMaxValueLen;
				DWORD dwType;
				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize, 0, &dwType, lpData, &dwValueSize);
				//wprintf(L"1-%s\n",pszName);
				if (pType == dwType && !wcscmp(pszName, pName))
				{
					swprintf_s(pValue, 512, _T("%s"), lpData);
					//memcpy(pPath,lpData,MAX_PATH);
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
	return ret;
}
HRESULT ResolveIt(HWND hwnd, TCHAR* lpszLinkFile, TCHAR* lpszPath, int iPathBufferSize)
{
	HRESULT hres;
	IShellLink* psl;
	WIN32_FIND_DATA wfd;

	*lpszPath = 0; // Assume failure   

	// Get a pointer to the IShellLink interface. It is assumed that CoInitialize  
	// has already been called.   
	hres = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);
	if (SUCCEEDED(hres))
	{
		IPersistFile* ppf;

		// Get a pointer to the IPersistFile interface.   
		hres = psl->QueryInterface(IID_IPersistFile, (void**)&ppf);

		if (SUCCEEDED(hres))
		{
			// Add code here to check return value from MultiByteWideChar   
			// for success.  

			// Load the shortcut.   
			hres = ppf->Load(lpszLinkFile, STGM_READ);

			if (SUCCEEDED(hres))
			{
				// Resolve the link.   
				hres = psl->Resolve(hwnd, SLR_NO_UI);

				if (SUCCEEDED(hres))
				{
					// Get the path to the link target.   
					hres = psl->GetPath(lpszPath, MAX_PATH, (WIN32_FIND_DATA*)&wfd, SLGP_RAWPATH);
				}
			}

			// Release the pointer to the IPersistFile interface.   
			ppf->Release();
		}

		// Release the pointer to the IShellLink interface.   
		psl->Release();
	}
	return hres;
}
void DeleteUpdateFile()
{
	TCHAR* m_FilePath = new TCHAR[MAX_PATH_EX];
	GetMyPath(m_FilePath);
	_tcscat_s(m_FilePath, MAX_PATH_EX, _T("\\ClientAgent.exe"));
	if (!_waccess(m_FilePath, 00))
	{
		DeleteFile(m_FilePath);
	}
	delete[] m_FilePath;
}
BOOL CheckIsPackedPE(TCHAR* pPath)
{
	BOOL ret = FALSE;
	HANDLE m_File = CreateFile(pPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (m_File != INVALID_HANDLE_VALUE)
	{
		DWORD m_Filesize = GetFileSize(m_File, NULL);
		if (m_Filesize >= 1024)
		{
			DWORD readsize;
			BYTE* buffer = new BYTE[1024];
			ReadFile(m_File, buffer, 1024, &readsize, NULL);
			ret = IsPackedSignature(buffer, 1024);
			delete[] buffer;
		}
		CloseHandle(m_File);
	}
	return ret;
}
BOOL IsPackedSignature(BYTE* buffer, unsigned int buflen)
{
	for (unsigned int i = 0; i < buflen; i++)
	{
		if (i + 4 > buflen)
			break;
		else
		{
			if (buffer[i] == 46 && buffer[i + 1] == 116 && buffer[i + 2] == 101 && buffer[i + 3] == 120 && buffer[i + 4] == 116)
			{
				return FALSE;
			}
		}
	}
	return TRUE;
}
bool IsHavePID(int pid)
{
	bool ret = false;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procSentry;
		procSentry.dwSize = sizeof(procSentry);
		BOOL Proc = Process32First(hSnapshot, &procSentry);

		while (Proc)
		{
			if (procSentry.th32ProcessID == (DWORD)pid)
			{
				ret = true;
				break;
			}
			Proc = Process32Next(hSnapshot, &procSentry);
		}
	}
	CloseHandle(hSnapshot);
	return ret;
}
void GetDetectTcpInformation(map<wstring, u_short>* pInfo, set<u_short>* pLintenPort)
{
	MIB_TCPTABLE_OWNER_PID* pTCPInfo;
	MIB_TCPROW_OWNER_PID* owner;
	DWORD size;
	DWORD dwResult;

	HMODULE hLib = LoadLibrary(_T("iphlpapi.dll"));

	pGetExtendedTcpTable = (DWORD(WINAPI*)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG))
		GetProcAddress(hLib, "GetExtendedTcpTable");

	if (!pGetExtendedTcpTable)
	{
		// printf("Could not load iphlpapi.dll. This application is for Windows XP SP2 and up.\n");
		 //MessageBox(0,L"Could not load iphlpapi.dll. This application is for Windows XP SP2 and up.",0,0);
		return;
	}

	dwResult = pGetExtendedTcpTable(NULL, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	pTCPInfo = (MIB_TCPTABLE_OWNER_PID*)malloc(size);
	dwResult = pGetExtendedTcpTable(pTCPInfo, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

	if (dwResult != NO_ERROR)
	{
		//printf("Couldn't get our IP table");
		//MessageBox(0,L"Couldn't get our IP table",0,0);
		FreeLibrary(hLib);
		free(pTCPInfo);
		return;
	}

	//printf("Iterating though table:\n");
	for (DWORD dwLoop = 0; dwLoop < pTCPInfo->dwNumEntries; dwLoop++)
	{
		owner = &pTCPInfo->table[dwLoop];
		WORD add1, add2, add3, add4;
		add1 = (WORD)(owner->dwRemoteAddr & 255);
		add2 = (WORD)((owner->dwRemoteAddr >> 8) & 255);
		add3 = (WORD)((owner->dwRemoteAddr >> 16) & 255);
		add4 = (WORD)((owner->dwRemoteAddr >> 24) & 255);
		if (owner->dwState == MIB_TCP_STATE_LISTEN)
			pLintenPort->insert(ntohs((u_short)owner->dwLocalPort));
		if ((add1 == 0 && add2 == 0 && add3 == 0 && add4 == 0) || (add1 == 127 && add2 == 0 && add3 == 0 && add4 == 1))
		{
		}
		else
		{
			wchar_t* m_Info = new wchar_t[50];
			swprintf_s(m_Info, 50, L"%lu|%d.%d.%d.%d:%u", owner->dwOwningPid, add1, add2, add3, add4, ntohs((u_short)owner->dwRemotePort));
			pInfo->insert(pair<wstring, u_short>(m_Info, ntohs((u_short)owner->dwLocalPort)));
			delete[] m_Info;
		}
	}
	FreeLibrary(hLib);
	free(pTCPInfo);
	pTCPInfo = NULL;
}
void GetDetectTcpInformationXP(map<wstring, u_short>* pInfo, set<u_short>* pLintenPort)
{
	pAllocateAndGetTcpExTableFromStack pGetTcpTableEx = NULL;
	HMODULE hLib = LoadLibrary(_T("iphlpapi.dll"));
	if (hLib == NULL)
	{
		return;
	}
	PMIB_TCPTABLE_EX m_pBuffTcpTableEx;

	//point to the magic method
	pGetTcpTableEx = (pAllocateAndGetTcpExTableFromStack)GetProcAddress(
		hLib, "AllocateAndGetTcpExTableFromStack");
	if (pGetTcpTableEx == NULL)
	{
		return;
	}
	(pGetTcpTableEx)(&m_pBuffTcpTableEx, TRUE, GetProcessHeap(), 0, 2);

	for (int i = 0; i < (int)m_pBuffTcpTableEx->dwNumEntries; i++)
	{
		WORD add1, add2, add3, add4;
		add1 = (WORD)(m_pBuffTcpTableEx->table[i].dwRemoteAddr & 255);
		add2 = (WORD)((m_pBuffTcpTableEx->table[i].dwRemoteAddr >> 8) & 255);
		add3 = (WORD)((m_pBuffTcpTableEx->table[i].dwRemoteAddr >> 16) & 255);
		add4 = (WORD)((m_pBuffTcpTableEx->table[i].dwRemoteAddr >> 24) & 255);
		if (m_pBuffTcpTableEx->table[i].dwState == MIB_TCP_STATE_LISTEN)
			pLintenPort->insert(ntohs((u_short)m_pBuffTcpTableEx->table[i].dwLocalPort));
		if ((add1 == 0 && add2 == 0 && add3 == 0 && add4 == 0) || (add1 == 127 && add2 == 0 && add3 == 0 && add4 == 1))
		{
		}
		else
		{
			wchar_t m_Info[50];
			swprintf_s(m_Info, 50, L"%lu|%d.%d.%d.%d:%u", m_pBuffTcpTableEx->table[i].dwProcessId, add1, add2, add3, add4, ntohs((u_short)m_pBuffTcpTableEx->table[i].dwRemotePort));
			pInfo->insert(pair<wstring, u_short>(m_Info, ntohs((u_short)m_pBuffTcpTableEx->table[i].dwLocalPort)));
		}
	}
	free(m_pBuffTcpTableEx);
	FreeLibrary(hLib);
}
PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}
bool replace(std::wstring& str, const std::wstring& from, const std::wstring& to)
{
	size_t start_pos = str.find(from);
	if (start_pos == std::wstring::npos)
		return false;
	str.replace(start_pos, from.length(), to);
	return true;
}
int impuser(TCHAR* processPathName, TCHAR* cmdline, DWORD Pid, DWORD& StartProcessPid, BOOL isWait, int m_TimeOut)
{
	//HANDLE hToken;
	//HANDLE   hExp = OpenProcess(PROCESS_ALL_ACCESS, TRUE, Pid);//GetProcessHandle(L"calc.EXE");     
	//if (hExp == NULL)
	//	return   -1;

	//OpenProcessToken(hExp, TOKEN_ALL_ACCESS, &hToken);
	//if (hToken == NULL)
	//{
	//	CloseHandle(hExp);
	//	return   -1;
	//}
	//int ret = 0;
	//STARTUPINFO si;
	//PROCESS_INFORMATION pi;
	//ZeroMemory(&si, sizeof(STARTUPINFO));
	//si.cb = sizeof(STARTUPINFO);
	//si.lpDesktop = _T("winsta0\\default");
	//si.wShowWindow = SW_SHOW;
	//si.dwFlags = STARTF_USESHOWWINDOW;

	////TCHAR   szParameter[256]   =   _T("/c ");  
	////lstrcat(szParameter,cmdline);  
	////printf("szParameter=%s\n",szParameter);  

	////TCHAR path[MAX_PATH];  
	////GetSystemWindowsDirectory(path,MAX_PATH);   
	////lstrcat(path,_T("\\system32\\cmd.exe"));   
	////lstrcpy(path,_T("C:\\Users\\Scan\\Desktop\\cports.exe"));
	//if (CreateProcessAsUser(hToken, processPathName, cmdline, NULL,
	//	NULL, FALSE, CREATE_NO_WINDOW | CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &si, &pi))
	//{
	//	//printf("CreateProcessAsUser sucessed!%d\n",GetLastError());
	//	//TCHAR * str = new TCHAR[1024];
	//	//swprintf_s(str,1024,_T("%s|%s\n"),processPathName,cmdline);
	//	//char * cstr = CStringToCharArray(str,CP_UTF8);
	//	//WriteLogFile(_T("C:\\Users\\Scan\\Desktop\\789.txt"),cstr);
	//	//delete [] cstr;
	//	//delete [] str;
	//	StartProcessPid = pi.dwProcessId;
	//	if (isWait)
	//	{
	//		if (m_TimeOut > 0)
	//			ret = WaitForSingleObject(pi.hProcess, m_TimeOut);
	//		else
	//			ret = WaitForSingleObject(pi.hProcess, INFINITE);
	//	}
	//	CloseHandle(pi.hProcess);
	//	CloseHandle(pi.hThread);
	//}
	//CloseHandle(hToken);
	//CloseHandle(hExp);
	//return ret;
	return 0;
}
void StartUserModeCommandProcess(TCHAR* RunExeStr, TCHAR* RunComStr, DWORD& pid)
{
	set<DWORD> ProcessID;
	//LoadingProcessOnlyID(&ProcessID);
	BOOL ContinueLoop;
	PROCESSENTRY32 pe32;
	HANDLE SnapshotHandle;
	SnapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	pe32.dwSize = sizeof(pe32);
	ContinueLoop = Process32First(SnapshotHandle, &pe32);
	while (ContinueLoop)
	{
		//pPID->insert(pe32.th32ProcessID);
		ProcessID.insert(pe32.th32ProcessID);
		ContinueLoop = Process32Next(SnapshotHandle, &pe32);
	}
	CloseHandle(SnapshotHandle);
	set<DWORD>::iterator it;
	for (it = ProcessID.begin(); it != ProcessID.end(); it++)
	{
		if (IsSystemProcess((*it)) == 0)
		{
			impuser(RunExeStr, RunComStr, (*it), pid, FALSE);
			Sleep(100);
			if (IsHavePID(pid))
				break;
			else
				pid = 0;
		}
	}
	ProcessID.clear();
	//delete [] RunComStr;
	//delete [] RunExeStr;
}
int StartUserModeProcessFromPid(TCHAR* RunExeStr, TCHAR* RunComStr, DWORD pid, int pTimeOut)
{
	int ret = 0;
	if (IsHavePID(pid))
	{
		DWORD ProcessID = 0;
		ret = impuser(RunExeStr, RunComStr, pid, ProcessID, TRUE, pTimeOut);
	}
	else
		ret = -1;
	//delete [] RunComStr;
	//delete [] RunExeStr;
	return ret;
}
int IsSystemProcess(DWORD pid)
{
	int ret = -1;
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (processHandle != NULL)
	{
		TCHAR* pSIDstr = new TCHAR[128];
		_tcscpy_s(pSIDstr, 128, _T("null"));
		GetUserSID(processHandle, pSIDstr);
		//TCHAR * m_UserName = new TCHAR[_MAX_FNAME];
		//_tcscpy_s(m_UserName,_MAX_FNAME,_T("null"));
		if (_tcscmp(pSIDstr, _T("null")))
		{
			ret = 0;
			SID_NAME_USE SidType;
			TCHAR* lpName = new TCHAR[_MAX_FNAME];
			TCHAR* lpDomain = new TCHAR[_MAX_FNAME];
			DWORD dwSize = _MAX_FNAME;
			PSID Sid;// = GetBinarySid(pSIDstr);
			if (ConvertStringSidToSid(pSIDstr, &Sid))
			{
				if (LookupAccountSid(NULL, Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType))
				{
					if (!_tcsicmp(lpName, _T("SYSTEM")) || !_tcsicmp(lpName, _T("LOCAL SERVICE"))
						|| !_tcsicmp(lpName, _T("NETWORK SERVICE")))
						ret = 1;
				}
			}
			LocalFree(Sid);
			delete[] lpDomain;
			delete[] lpName;
		}
		delete[] pSIDstr;
		//delete [] m_UserName;
	}
	return ret;
}
void GetUserSID(HANDLE hProcess, TCHAR* szUserSID)
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
void GetlocalExePath(const wchar_t* ExeName, LPWSTR str)
{
	GetModuleFileName(GetModuleHandle(NULL), str, MAX_PATH_EX);
	for (int i = (int)wcslen(str) - 1; i >= 0; i--)
	{
		if (str[i] == '\\')
		{
			str[i] = '\x0';
			break;
		}
	}
	lstrcat(str, _T("\\"));
	lstrcat(str, ExeName);
}
void GetFileVersion(TCHAR* FilePath, char* pVersion)
{
	DWORD  verHandle = 0;
	UINT   size = 0;
	LPBYTE lpBuffer = NULL;
	DWORD  verSize = GetFileVersionInfoSize(FilePath, &verHandle);
	if (verSize != NULL)
	{
		LPSTR verData = new char[verSize];
		if (GetFileVersionInfo(FilePath, verHandle, verSize, verData))
		{
			if (VerQueryValue(verData, _T("\\"), (VOID FAR * FAR*) & lpBuffer, &size))
			{
				if (size)
				{
					VS_FIXEDFILEINFO* verInfo = (VS_FIXEDFILEINFO*)lpBuffer;
					if (verInfo->dwSignature == 0xfeef04bd)
					{
						sprintf_s(pVersion, 64, "%d.%d.%d.%d",
							(verInfo->dwFileVersionMS >> 16) & 0xffff,
							(verInfo->dwFileVersionMS >> 0) & 0xffff,
							(verInfo->dwFileVersionLS >> 16) & 0xffff,
							(verInfo->dwFileVersionLS >> 0) & 0xffff);
					}
				}
			}
		}
		delete[] verData;
	}
}
int CheckVirtualMachineDrive()
{
	int ret = 0;
	HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVINTERFACE_USB_DISK, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
	if (hDevInfo == INVALID_HANDLE_VALUE)
		return 0/*NULL*/;

	// Get a context structure for the device interface
	// of a device information set.
	BYTE Buf[1024];
	PSP_DEVICE_INTERFACE_DETAIL_DATA pspdidd = (PSP_DEVICE_INTERFACE_DETAIL_DATA)Buf;
	SP_DEVICE_INTERFACE_DATA         spdid;
	SP_DEVINFO_DATA                  spdd;

	spdid.cbSize = sizeof(spdid);

	DWORD dwIndex = 0;
	//wchar_t *SerialNumber = NULL;
	while (true)
	{
		if (!SetupDiEnumDeviceInterfaces(hDevInfo, NULL, &GUID_DEVINTERFACE_USB_DISK, dwIndex, &spdid))
			break;

		DWORD dwSize = 0;
		SetupDiGetDeviceInterfaceDetail(hDevInfo, &spdid, NULL, 0, &dwSize, NULL);

		if ((dwSize != 0) && (dwSize <= sizeof(Buf)))
		{
			pspdidd->cbSize = sizeof(*pspdidd); // 5 Bytes!

			ZeroMemory((PVOID)&spdd, sizeof(spdd));
			spdd.cbSize = sizeof(spdd);

			long res = SetupDiGetDeviceInterfaceDetail(hDevInfo, &spdid, pspdidd, dwSize, &dwSize, &spdd);
			if (res)
			{
				wstring wtr = pspdidd->DevicePath;
				//transform(wtr.begin(), wtr.end(), wtr.begin(), toupper);
				transform(wtr.begin(), wtr.end(), wtr.begin(), tolower);
				if (wtr.find(L"_vmware") != -1)
				{
					ret = 1;
					break;
				}
				else if (wtr.find(L"_vbox") != -1)
				{
					ret = 3;
					break;
				}
			}
		}
		dwIndex++;
	}

	SetupDiDestroyDeviceInfoList(hDevInfo);
	return ret;
}
int VirtualMachine(char* pMAC)
{
	int ret = 0;
	ret = CheckVirtualMachineDrive();
	if (ret == 0)
	{
		char* str = new char[20];
		char* str1 = new char[20];
		strcpy_s(str, 20, pMAC);
		char* psc;
		char* next_token = NULL;
		int i = 0;
		psc = strtok_s(str, "-", &next_token);
		while (psc != NULL)
		{
			if (i == 0)
			{
				strcpy_s(str1, 20, psc);
			}
			else if (i == 1)
			{
				strcat_s(str1, 20, psc);
			}
			else if (i == 2)
			{
				strcat_s(str1, 20, psc);
				break;
			}
			i++;
			psc = strtok_s(NULL, "-", &next_token);
		}
		if (!_stricmp(str1, "001C14") || !_stricmp(str1, "005056") || !_stricmp(str1, "000569") || !_stricmp(str1, "000C29")) // VMWare
		{
			ret = 1;
		}
		else if (!_stricmp(str1, "000782") || !_stricmp(str1, "000F4B") || !_stricmp(str1, "00104F"))// Oracle
		{
			ret = 2;
		}
		else if (!_stricmp(str1, "080027"))// Cadmus: Virtualbox
		{
			ret = 3;
		}
		delete[] str1;
		delete[] str;
	}
	return ret;
}
//BOOL MySystemShutdown()
//{
//	HANDLE hToken;
//	TOKEN_PRIVILEGES tkp;
//
//	// Get a token for this process. 
//
//	if (!OpenProcessToken(GetCurrentProcess(),
//		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
//		return(FALSE);
//
//	// Get the LUID for the shutdown privilege. 
//
//	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME,
//		&tkp.Privileges[0].Luid);
//
//	tkp.PrivilegeCount = 1;  // one privilege to set    
//	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
//
//	// Get the shutdown privilege for this process. 
//
//	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0,
//		(PTOKEN_PRIVILEGES)NULL, 0);
//
//	if (GetLastError() != ERROR_SUCCESS)
//		return FALSE;
//
//	// Shut down the system and force all applications to close. 
//
//	if (!ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE,
//		SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
//		SHTDN_REASON_MINOR_UPGRADE |
//		SHTDN_REASON_FLAG_PLANNED))
//		return FALSE;
//
//	//shutdown was successful
//	return TRUE;
//}
//void WriteLogFile(TCHAR* m_Path, char* Str)
//{
//	if (!_waccess(m_Path, 00))
//	{
//		fstream file;
//		file.open(m_Path, ios::app);
//		file.write(Str, strlen(Str));   //將str寫入檔案
//		file.close();
//	}
//	else
//	{
//		fstream file;
//		file.open(m_Path, ios::out | ios::trunc);
//		file.write(Str, strlen(Str));   //將str寫入檔案
//		file.close();
//	}
//}
//BOOL LoadNTDriver(char* lpszDriverName, char* lpszDriverPath)
//{
//	char szDriverImagePath[256];
//	//得到完整的驅動路徑
//	GetFullPathNameA(lpszDriverPath, 256, szDriverImagePath, NULL);
//	BOOL bRet = FALSE;
//
//	SC_HANDLE hServiceMgr = NULL;//SCM管理器的控制碼
//	SC_HANDLE hServiceDDK = NULL;//NT驅動程式的服務控制碼
//
//	//打開服務控制管理器
//	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
//
//	if (hServiceMgr == NULL)
//	{
//		//OpenSCManager失敗
//		printf("OpenSCManager() Faild %d ! \n", GetLastError());
//		bRet = FALSE;
//		goto BeforeLeave;
//	}
//	else
//	{
//		////OpenSCManager成功
//		printf("OpenSCManager() ok ! \n");
//	}
//
//	//新建驅動所對應的服務
//	hServiceDDK = CreateServiceA(hServiceMgr,
//		lpszDriverName, //驅動程式的在登錄表中的名字 
//		lpszDriverName, // 登錄表驅動程式的 DisplayName 值 
//		SERVICE_ALL_ACCESS, // 載入驅動程式的存取權限
//		SERVICE_KERNEL_DRIVER,// 表示載入的服務是驅動程式
//		SERVICE_DEMAND_START, // 登錄表驅動程式的 Start 值
//		SERVICE_ERROR_IGNORE, // 登錄表驅動程式的 ErrorControl 值
//		szDriverImagePath, // 登錄表驅動程式的 ImagePath 值
//		NULL,
//		NULL,
//		NULL,
//		NULL,
//		NULL);
//
//	DWORD dwRtn;
//	//判斷服務是否失敗
//	if (hServiceDDK == NULL)
//	{
//		dwRtn = GetLastError();
//		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_EXISTS)
//		{
//			//由於其他原因新建服務失敗
//			printf("CrateService() Faild %d ! \n", dwRtn);
//			bRet = FALSE;
//			goto BeforeLeave;
//		}
//		else
//		{
//			//服務新建失敗，是由於服務已經創立過
//			printf("CrateService() Faild Service is ERROR_IO_PENDING or ERROR_SERVICE_EXISTS! \n");
//		}
//
//		// 驅動程式已經載入，只需要打開
//		hServiceDDK = OpenServiceA(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
//		if (hServiceDDK == NULL)
//		{
//			//如果打開服務也失敗，則意味錯誤
//			dwRtn = GetLastError();
//			printf("OpenService() Faild %d ! \n", dwRtn);
//			bRet = FALSE;
//			goto BeforeLeave;
//		}
//		else
//		{
//			printf("OpenService() ok ! \n");
//		}
//	}
//	else
//	{
//		printf("CrateService() ok ! \n");
//	}
//
//	//開啟此項服務
//	bRet = StartService(hServiceDDK, NULL, NULL);
//	if (!bRet)
//	{
//		DWORD dwRtn = GetLastError();
//		if (dwRtn != ERROR_IO_PENDING && dwRtn != ERROR_SERVICE_ALREADY_RUNNING)
//		{
//			printf("StartService() Faild %d ! \n", dwRtn);
//			bRet = FALSE;
//			goto BeforeLeave;
//		}
//		else
//		{
//			if (dwRtn == ERROR_IO_PENDING)
//			{
//				//裝置被掛住
//				printf("StartService() Faild ERROR_IO_PENDING ! \n");
//				bRet = FALSE;
//				goto BeforeLeave;
//			}
//			else
//			{
//				//服務已經開啟
//				printf("StartService() Faild ERROR_SERVICE_ALREADY_RUNNING ! \n");
//				bRet = TRUE;
//				goto BeforeLeave;
//			}
//		}
//	}
//	bRet = TRUE;
//	//離開前關閉控制碼
//BeforeLeave:
//	if (hServiceDDK)
//	{
//		CloseServiceHandle(hServiceDDK);
//	}
//	if (hServiceMgr)
//	{
//		CloseServiceHandle(hServiceMgr);
//	}
//	return bRet;
//}
//BOOL UnloadNTDriver(char* szSvrName)
//{
//	BOOL bRet = FALSE;
//	SC_HANDLE hServiceMgr = NULL;//SCM管理器的控制碼
//	SC_HANDLE hServiceDDK = NULL;//NT驅動程式的服務控制碼
//	SERVICE_STATUS SvrSta;
//	//打開SCM管理器
//	hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
//	if (hServiceMgr == NULL)
//	{
//		//帶開SCM管理器失敗
//		//printf( "OpenSCManager() Faild %d ! \n", GetLastError() );  
//		bRet = FALSE;
//		goto BeforeLeave;
//	}
//	//else  
//	//{
//	//	//帶開SCM管理器失敗成功
//	//	printf( "OpenSCManager() ok ! \n" );  
//	//}
//	//打開驅動所對應的服務
//	hServiceDDK = OpenServiceA(hServiceMgr, szSvrName, SERVICE_ALL_ACCESS);
//
//	if (hServiceDDK == NULL)
//	{
//		//打開驅動所對應的服務失敗
//		//printf( "OpenService() Faild %d ! \n", GetLastError() );  
//		bRet = FALSE;
//		goto BeforeLeave;
//	}
//	//else  
//	//{  
//	//	printf( "OpenService() ok ! \n" );  
//	//}  
//	//停止驅動程式，如果停止失敗，只有重新開機才能，再動態載入。  
//	if (!ControlService(hServiceDDK, SERVICE_CONTROL_STOP, &SvrSta))
//	{
//		//printf( "ControlService() Faild %d !\n", GetLastError() );  
//	}
//	else
//	{
//		//打開驅動所對應的失敗
//		//printf( "ControlService() ok !\n" );  
//	}
//	//動態卸載驅動程式。  
//	if (!DeleteService(hServiceDDK))
//	{
//		//卸載失敗
//		//printf( "DeleteSrevice() Faild %d !\n", GetLastError() );  
//	}
//	else
//	{
//		//卸載成功
//		//printf( "DelServer:eleteSrevice() ok !\n" );  
//	}
//	bRet = TRUE;
//BeforeLeave:
//	//離開前關閉打開的控制碼
//	if (hServiceDDK)
//	{
//		CloseServiceHandle(hServiceDDK);
//	}
//	if (hServiceMgr)
//	{
//		CloseServiceHandle(hServiceMgr);
//	}
//	return bRet;
//}
void GetThisClientKey(char* pKeyStr)
{
	HKEY hKey = NULL;
	LONG lResult;
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("Software\\eDetector"), 0, KEY_QUERY_VALUE, &hKey);

	if (lResult == ERROR_SUCCESS)
	{

		DWORD dwValues, dwMaxValueNameLen, dwMaxValueLen;
		LONG lRet = ::RegQueryInfoKey(hKey,
			NULL, NULL,    // lpClass, lpcClass
			NULL,          // lpReserved
			NULL, NULL,    // lpcSubKeys, lpcMaxSubKeyLen
			NULL,          // lpcMaxClassLen
			&dwValues,
			&dwMaxValueNameLen,
			&dwMaxValueLen,
			NULL,          // lpcbSecurityDescriptor
			NULL);         // lpftLastWriteTime
		if (ERROR_SUCCESS == lRet)
		{
			// allocate enough to fit max. length name and value
			LPTSTR pszName = new TCHAR[dwMaxValueNameLen + 1];
			LPBYTE lpData = new BYTE[dwMaxValueLen + 1];
			memset(lpData, '\0', dwMaxValueLen + 1);
			for (DWORD dwIndex = 0; dwIndex < dwValues; dwIndex++)
			{
				DWORD dwNameSize = dwMaxValueNameLen + 1;
				DWORD dwValueSize = dwMaxValueLen;
				DWORD dwType;
				lRet = ::RegEnumValue(hKey, dwIndex, pszName, &dwNameSize, 0, &dwType, lpData, &dwValueSize);
				//wprintf(L"1-%s\n",pszName);
				if (REG_SZ == dwType /*|| REG_EXPAND_SZ == dwType*/)
				{
					if (!_tcscmp(pszName, _T("Key")))
					{
						TCHAR pCom[MAX_PATH_EX];
						swprintf_s(pCom, MAX_PATH_EX, _T("%s"), lpData);
						char* str = CStringToCharArray(pCom, CP_UTF8);
						if (CheckRightKey(str))
							strcpy_s(pKeyStr, 33, str);
						delete[] str;
						break;
					}
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
}
bool CheckRightKey(char* pKeyStr)
{
	bool ret = true;
	if (strlen(pKeyStr) == 32)
	{
		for (int i = 0; i < (int)strlen(pKeyStr); i++)
		{
			if (!OtherHashch(pKeyStr[i]))
			{
				ret = false;
				break;
			}
		}
	}
	else
		ret = false;
	return ret;
}
bool OtherHashch(char ch)
{
	switch (ch)
	{
	case '0':
		return true;
	case '1':
		return true;
	case '2':
		return true;
	case '3':
		return true;
	case '4':
		return true;
	case '5':
		return true;
	case '6':
		return true;
	case '7':
		return true;
	case '8':
		return true;
	case '9':
		return true;
	case 'a':
		return true;
	case 'b':
		return true;
	case 'c':
		return true;
	case 'd':
		return true;
	case 'e':
		return true;
	case 'f':
		return true;
	default:
		return false;
	}
}
void WriteRegisterValue(char* pKeyStr)
{
	HKEY hKey = NULL;
	LONG lResult = 0;
	BOOL fSuccess = TRUE;
	DWORD dwSize;

	//const size_t count = MAX_PATH*2;
	wchar_t* szValue = CharArrayToWString(pKeyStr, CP_UTF8);


	lResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Software\\eDetector", 0, NULL, 0, (KEY_WRITE | KEY_READ), NULL, &hKey, NULL);

	fSuccess = (lResult == 0);

	if (fSuccess)
	{
		dwSize = (DWORD)(wcslen(szValue) + 1) * 2;
		lResult = RegSetValueExW(hKey, L"Key", 0, REG_SZ, (BYTE*)szValue, dwSize);
		fSuccess = (lResult == 0);
	}

	if (hKey != NULL)
	{
		RegCloseKey(hKey);
		hKey = NULL;
	}
	delete[] szValue;
}
void LoadBinaryStringsHash(BYTE* buf, DWORD pSize, set<DWORD>* pStrSet)
{
	vector<BYTE> m_CharMap;
	for (DWORD i = 0; i < pSize; i++)
	{
		if (buf[i] > 31 && buf[i] < 127)
		{
			m_CharMap.push_back(buf[i]);
		}
		else
		{
			if (!m_CharMap.empty())
			{
				if (m_CharMap.size() >= 3)
				{
					string WriteStr;
					vector<BYTE>::iterator it;
					for (it = m_CharMap.begin(); it != m_CharMap.end(); it++)
					{
						WriteStr.push_back((*it));
					}
					if (WriteStr.size() < 256)
					{
						char* FuncName = new char[256];
						DWORD Hash = 0;
						strcpy_s(FuncName, 256, WriteStr.c_str());
						PUCHAR ptr = (PUCHAR)FuncName;
						while (*ptr)
						{
							Hash = ((Hash << 8) + Hash + *ptr) ^ (*ptr << 16);
							ptr++;
						}
						if (Hash > 0)
							pStrSet->insert(Hash);
						delete[] FuncName;
					}
					WriteStr.clear();
					m_CharMap.clear();
				}
				else
					m_CharMap.clear();
			}
		}
	}
	m_CharMap.clear();
}
DWORD GetDigitalSignatureHash()
{
	DWORD Hash = 0;
	TCHAR* m_MyPath = new TCHAR[MAX_PATH_EX];
	if (GetModuleFileName(GetModuleHandle(NULL), m_MyPath, MAX_PATH_EX))
	{
		DigitalSignatureInfo* DSinfo = new DigitalSignatureInfo;
		_tcscpy_s(DSinfo->SignerSubjectName, 256, _T("null"));
		bool DSret = GetDigitalSignature(m_MyPath, DSinfo);
		if (DSret)
		{
			char* cDS = CStringToCharArray(DSinfo->SignerSubjectName, CP_UTF8);
			PUCHAR ptr = (PUCHAR)cDS;
			while (*ptr)
			{
				Hash = ((Hash << 8) + Hash + *ptr) ^ (*ptr << 16);
				ptr++;
			}
			delete[] cDS;
		}
		delete DSinfo;
	}
	delete[] m_MyPath;
	return Hash;
}
void ParserConfigLog(char* str, char* strA, char* strB)
{
	char* psc;
	char* next_token = NULL;
	int i = 0;
	psc = strtok_s(str, ":", &next_token);
	while (psc != NULL)
	{
		if (i == 0)
			strcpy_s(strA, 64, psc);
		else if (i == 1)
		{
			strcpy_s(strB, 1024, psc);
			break;
		}
		i++;
		psc = strtok_s(NULL, ":", &next_token);
	}
}
bool CheckDigitalSignature(TCHAR* m_Path)
{
	//wchar_t * szFileName = CharArrayToWString(m_Path,CP_ACP);
	DWORD dwEncoding, dwContentType, dwFormatType;
	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	BOOL fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
		m_Path,
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&dwEncoding,
		&dwContentType,
		&dwFormatType,
		&hStore,
		&hMsg,
		NULL);
	if (!fResult)
	{
		if (hStore != NULL) CertCloseStore(hStore, 0);
		if (hMsg != NULL) CryptMsgClose(hMsg);
		return false;
	}
	else
	{
		if (hStore != NULL) CertCloseStore(hStore, 0);
		if (hMsg != NULL) CryptMsgClose(hMsg);
		return true;
	}
}
//void SetProcessPriority(TCHAR* m_Path)
//{
//	fstream fin;
//	fin.open(m_Path, ios::in);
//	{
//		char* linestr = new char[64];
//		while (fin.getline(linestr, 64, '\n'))
//		{
//			char* strA = new char[64];
//			char* strB = new char[1024];
//			ParserConfigLog(linestr, strA, strB);
//			if (!_stricmp(strA, "Priority"))
//			{
//				//atoi(strB) == 0 ? pInfo->DetectProcess = FALSE : pInfo->DetectProcess = TRUE;
//				int ret = atoi(strB);
//				if (ret == 1)
//					g_ProcessLevel = BELOW_NORMAL_PRIORITY_CLASS;
//				else if (ret == 2)
//					g_ProcessLevel = IDLE_PRIORITY_CLASS;
//				else
//					g_ProcessLevel = NORMAL_PRIORITY_CLASS;
//			}
//			delete[] strB;
//			delete[] strA;
//		}
//		fin.close();
//		delete[] linestr;
//	}
//}

wstring GetMyTempPath(TCHAR* pdnPathName)
{
	wstring ret;
	TCHAR* NewPath = new TCHAR[512];
	_tcscpy_s(NewPath, 512, pdnPathName);
	for (int i = (int)_tcslen(NewPath) - 1; i >= 0; i--)
	{
		if (NewPath[i] == '\\')
		{
			NewPath[i] = '\0';
			break;
		}
	}
	ret = NewPath;
	delete[] NewPath;
	return ret;
}

