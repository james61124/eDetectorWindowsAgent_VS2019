#include "AutoRun.h"
#include <comdef.h>
//  Include the task header file.
#include <taskschd.h>
#include <Sddl.h>
#include <Windows.h>
#include <tchar.h>

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
AutoRun::AutoRun()
{

}
AutoRun::~AutoRun()
{

}
BOOL AutoRun::GetUserStartUp(wchar_t* pUserName, const wchar_t* pDirectory, TCHAR* pPath)
{
	//if(SHGetSpecialFolderPath( NULL, wtr, CSIDL_STARTUP, false ))
	//	return TRUE;
	//else
	//	return FALSE;
	BOOL ret = FALSE;
	HKEY hKey = NULL;
	LONG lResult;
	TCHAR* RegPath = new TCHAR[512];
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"), pUserName);
	//HKEY_CURRENT_USER,_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
	lResult = RegOpenKeyEx(HKEY_USERS, RegPath, 0, KEY_QUERY_VALUE, &hKey);

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
				if (REG_SZ == dwType && !wcscmp(pszName, pDirectory))
				{
					ret = TRUE;
					//memcpy(pPath,lpData,MAX_PATH);
					swprintf_s(pPath, MAX_PATH, _T("%s"), lpData);
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
	delete[] RegPath;
	return ret;
}
BOOL AutoRun::GetAllUserStartUp(TCHAR* wtr)
{
	//if(SHGetSpecialFolderPath( NULL, wtr, CSIDL_COMMON_STARTUP, false ))
	//	return TRUE;
	//else
	//	return FALSE;
	BOOL ret = FALSE;
	HKEY hKey = NULL;
	LONG lResult;
	TCHAR* RegPath = new TCHAR[512];
	swprintf_s(RegPath, 512, _T("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"));
	//HKEY_CURRENT_USER,_T("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, RegPath, 0, KEY_QUERY_VALUE, &hKey);

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
				if (REG_SZ == dwType && !wcscmp(pszName, L"Common Startup"))
				{
					ret = TRUE;
					//memcpy(wtr,lpData,MAX_PATH_EX);
					swprintf_s(wtr, MAX_PATH_EX, _T("%s"), lpData);
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
	delete[] RegPath;
	return ret;
}

void AutoRun::GetThisPCAllUser(vector<wstring>* wtr)
{
	HKEY hTestKey;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"),
		0,
		KEY_READ,
		&hTestKey) == ERROR_SUCCESS
		)
	{
		QueryKey(hTestKey, wtr);
	}
	RegCloseKey(hTestKey);
}

void AutoRun::GetUserNamePath(wchar_t* pUserName, TCHAR* pPath)
{
	HKEY hKey = NULL;
	LONG lResult;
	TCHAR* RegPath = new TCHAR[MAX_PATH];
	swprintf_s(RegPath, MAX_PATH, _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%s"), pUserName);
	lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, RegPath, 0, KEY_QUERY_VALUE, &hKey);

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
				if (REG_EXPAND_SZ == dwType && !_tcscmp(pszName, _T("ProfileImagePath")))
				{
					//memcpy(pPath,lpData,MAX_PATH);
					swprintf_s(pPath, MAX_PATH, _T("%s"), lpData);
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
	delete[] RegPath;
}
//void AutoRun::StartupAutoRunInfo(void* argv, char* pMAC, char* pIP)
//{
//	TransportData* m_Client = (TransportData*)argv;
//	vector<AutoRunInfo> m_StartRunInfo;
//	TCHAR* Pathstr = new TCHAR[MAX_PATH_EX];
//	if (GetAllUserStartUp(Pathstr))
//	{
//		SearchAutoRunFile(&m_StartRunInfo, Pathstr);
//	}
//
//	LoadRegisterAutoRun(&m_StartRunInfo);
//
//	delete[] Pathstr;
//	vector<wstring> ThisPCAllUser;
//	GetThisPCAllUser(&ThisPCAllUser);
//	if (!ThisPCAllUser.empty())
//	{
//		wchar_t* UserName = new wchar_t[256];
//		vector<wstring>::iterator ut;
//		for (ut = ThisPCAllUser.begin(); ut != ThisPCAllUser.end(); ut++)
//		{
//			swprintf_s(UserName, 256, L"%s", (*ut).c_str());
//			TCHAR* m_Path = new TCHAR[MAX_PATH];
//			if (GetUserStartUp(UserName, L"Startup", m_Path))
//			{
//				SearchAutoRunFile(&m_StartRunInfo, m_Path);
//			}
//			delete[] m_Path;
//			LoadRegisterAutoRunFromUser(&m_StartRunInfo, UserName);
//		}
//		delete[] UserName;
//	}
//	ThisPCAllUser.clear();
//	if (!m_StartRunInfo.empty())
//	{
//		char* TempStr = new char[DATASTRINGMESSAGELEN];
//		memset(TempStr, '\0', DATASTRINGMESSAGELEN);
//		int DataCount = 0;
//		int ret = 1;
//		vector<AutoRunInfo>::iterator it;
//		for (it = m_StartRunInfo.begin(); it != m_StartRunInfo.end(); it++)
//		{
//			wchar_t* wstr = new wchar_t[2048];
//			swprintf_s(wstr, 2048, L"%s|%s|%s\n", (*it).StartName, (*it).m_Command, (*it).InfoLocation);
//			DataCount++;
//			char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
//			strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
//			delete[] wstr;
//			if ((DataCount % 30) == 0 && DataCount >= 30)
//			{
//				ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveStartupData", TempStr);
//				if (ret == 0 || ret == -1)
//				{
//					delete[] m_DataStr;
//					break;
//				}
//				memset(TempStr, '\0', DATASTRINGMESSAGELEN);
//			}
//			delete[] m_DataStr;
//		}
//		if (TempStr[0] != '\0' && ret > 0)
//		{
//			ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveStartupData", TempStr);
//			if (ret > 0)
//			{
//				ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveStartupDataEnd", "");
//			}
//		}
//		delete[] TempStr;
//	}
//	m_StartRunInfo.clear();
//}
void AutoRun::SearchAutoRunFile(vector<AutoRunInfo>* pInfo, wchar_t* m_Path)
{
	TCHAR* szTempPath = new TCHAR[MAX_PATH_EX];
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
				TCHAR* szPath = new TCHAR[MAX_PATH_EX];
				swprintf_s(szPath, MAX_PATH_EX, L"%s\\%s", m_Path, fd.cFileName);
				try
				{
					ParsingStartupFile(pInfo, szPath, fd.cFileName);
				}
				catch (...) {}
				delete[] szPath;
			}
		} while (FindNextFile(hSearch, &fd) != FALSE);
		FindClose(hSearch);
	}
	delete[] szTempPath;
}
void AutoRun::ParsingStartupFile(vector<AutoRunInfo>* pInfo, TCHAR* m_Path, TCHAR* m_Name)
{
	TCHAR* ExtStr = new TCHAR[100];
	for (int i = (int)wcslen(m_Name) - 1; i >= 0; i--)
	{
		if (m_Name[i] == '.')
		{
			wcscpy_s(ExtStr, 100, m_Name + (i + 1));
			break;
		}
	}
	if (!_wcsicmp(ExtStr, _T("lnk")))
	{
		AutoRunInfo m_Info;
		wcscpy_s(m_Info.StartName, MAX_PATH, m_Name);
		wcscpy_s(m_Info.InfoLocation, MAX_PATH_EX, m_Path);
		CoInitialize(NULL);
		ResolveIt(NULL, m_Path, m_Info.m_Command, MAX_PATH_EX);
		CoUninitialize();
		pInfo->push_back(m_Info);
	}
	else if (!_wcsicmp(ExtStr, _T("ini")))
	{
	}
	else
	{
		AutoRunInfo m_Info;
		wcscpy_s(m_Info.m_Command, MAX_PATH_EX, m_Path);
		wcscpy_s(m_Info.StartName, MAX_PATH, m_Name);
		wcscpy_s(m_Info.InfoLocation, MAX_PATH_EX, m_Path);
		pInfo->push_back(m_Info);
	}
	delete[] ExtStr;
}
void AutoRun::LoadRegisterAutoRun(vector<AutoRunInfo>* pInfo)
{
#ifndef _M_IX86
	printf("Software\\Microsoft\\Windows\\CurrentVersion\\Run\n");
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
	printf("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n");
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"));
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"));
	printf("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\n");
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"));
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
	printf("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\n");
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"), _T("AlternateShell"), false, false);
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Active Setup\\Installed Components"), _T("StubPath"), true, false);
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Wow6432Node\\Microsoft\\Active Setup\\Installed Components"), _T("StubPath"), true, false);

	printf("Software\\Microsoft\\Windows\\CurrentVersion\\Run\n");
	LoadRegisterInfox32(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
	LoadRegisterInfox32(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
	LoadRegisterInfox32(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"));
	LoadRegisterInfox32(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"));
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"), _T("StubPath"), true, true);
	printf("SOFTWARE\\Microsoft\\Active Setup\\Installed Components\n");
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Active Setup\\Installed Components"), _T("StubPath"), true, true);
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"), _T("AlternateShell"), false, true);
	printf("\n");
#else

	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"));
	LoadRegisterInfo(pInfo, HKEY_LOCAL_MACHINE, _T("Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"));
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"), _T("StubPath"), true);
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Active Setup\\Installed Components"), _T("StubPath"), true);
	LoadRegisterInfoEx(pInfo, HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Control\\SafeBoot"), _T("AlternateShell"), false, false);
#endif
}

void AutoRun::LoadRegisterAutoRunFromUser(vector<AutoRunInfo>* pInfo, wchar_t* pUserName)
{
	TCHAR* RegPath = new TCHAR[512];
#ifndef _M_IX86
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);
	LoadRegisterInfox32(pInfo, HKEY_USERS, RegPath);
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);
	LoadRegisterInfox32(pInfo, HKEY_USERS, RegPath);
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);
	LoadRegisterInfox32(pInfo, HKEY_USERS, RegPath);
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);
	LoadRegisterInfox32(pInfo, HKEY_USERS, RegPath);

#else
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);
	swprintf_s(RegPath, 512, _T("%s\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"), pUserName);
	LoadRegisterInfo(pInfo, HKEY_USERS, RegPath);

#endif
	delete[] RegPath;
}
void AutoRun::LoadRegisterInfo(vector<AutoRunInfo>* pInfo, HKEY pKey, const wchar_t* RegPath)
{
	HKEY hKey = NULL;
	LONG lResult;
	lResult = RegOpenKeyEx(pKey, RegPath, 0, KEY_QUERY_VALUE, &hKey);

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
				if (REG_SZ == dwType || REG_EXPAND_SZ == dwType)
				{
					AutoRunInfo m_Info;
					wcscpy_s(m_Info.StartName, MAX_PATH, pszName);
					TCHAR pCom[MAX_PATH_EX];//= new TCHAR[MAX_PATH_EX];
					try
					{
						//memcpy(pCom ,lpData,MAX_PATH_EX);
						swprintf_s(pCom, MAX_PATH_EX, _T("%s"), lpData);
					}
					catch (...)
					{
						_tcscpy_s(pCom, MAX_PATH_EX, _T("null"));
					}
					if (_tcscmp(pCom, _T("null")))
					{
						ExpandEnvironmentStrings(pCom, m_Info.m_Command, MAX_PATH_EX);
						/*memcpy(m_Info.m_Command,lpData,MAX_PATH_EX);*/

						if (pKey == HKEY_USERS)
						{
							swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("HKEY_USERS\\%s"), RegPath);
						}
						else if (pKey == HKEY_LOCAL_MACHINE)
						{
							swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("HKEY_LOCAL_MACHINE\\%s"), RegPath);
						}
						else
						{
							swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("%s"), RegPath);
						}
						pInfo->push_back(m_Info);
					}
					//delete [] pCom;	
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
}
void AutoRun::LoadRegisterInfox32(vector<AutoRunInfo>* pInfo, HKEY pKey, const wchar_t* RegPath)
{
	HKEY hKey = NULL;
	LONG lResult;

	lResult = RegOpenKeyEx(pKey, RegPath, 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &hKey);

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
				if (REG_SZ == dwType || REG_EXPAND_SZ == dwType)
				{
					AutoRunInfo m_Info;
					wcscpy_s(m_Info.StartName, MAX_PATH, pszName);
					TCHAR* pCom = new TCHAR[MAX_PATH_EX];
					//memcpy(pCom ,lpData,MAX_PATH_EX);
					swprintf_s(pCom, MAX_PATH_EX, _T("%s"), lpData);
					ExpandEnvironmentStrings(pCom, m_Info.m_Command, MAX_PATH_EX);
					//memcpy(m_Info.m_Command,lpData,MAX_PATH_EX);

					if (pKey == HKEY_USERS)
						swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:HKEY_USERS\\%s"), RegPath);
					else if (pKey == HKEY_LOCAL_MACHINE)
						swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:HKEY_LOCAL_MACHINE\\%s"), RegPath);
					else
						swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:%s"), RegPath);

					delete[] pCom;
					pInfo->push_back(m_Info);
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
}
//void AutoRun::StartupServiceInfo(void* argv, char* pMAC, char* pIP)
//{
//	TransportData* m_Client = (TransportData*)argv;
//	map<wstring, SerivceInformation> ServiceMap;
//	LoadInstallService(&ServiceMap);
//	if (!ServiceMap.empty())
//	{
//		//MessageBox(0,L"data",0,0);
//		vector<wstring> RegHistorySerivceName;
//		LoadRegHistorySubKeys(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Services"), &RegHistorySerivceName);
//		map<wstring, SerivceInformation>::iterator st;
//		vector<wstring>::iterator it;
//		for (it = RegHistorySerivceName.begin(); it != RegHistorySerivceName.end(); it++)
//		{
//			st = ServiceMap.find((*it).c_str());
//			if (st == ServiceMap.end())
//			{
//				SerivceInformation m_info = { 0 };
//				_tcscpy_s(m_info.SerivceName, 1024, (*it).c_str());
//				_tcscpy_s(m_info.DisplayName, 1024, (*it).c_str());
//				_tcscpy_s(m_info.lpBinaryPathName, 1024, _T("null"));
//				_tcscpy_s(m_info.lpDependencies, 1024, _T("null"));
//				_tcscpy_s(m_info.lpDescription, 1024, _T("null"));
//				_tcscpy_s(m_info.lpLoadOrderGroup, 1024, _T("null"));
//				_tcscpy_s(m_info.lpServiceStartName, 1024, _T("null"));
//				//_tcscpy_s(m_info.SerivceName,512,_T("null"));
//				m_info.dwCurrentState = 0;
//				m_info.dwErrorControl = 0;
//				m_info.dwServiceType = 0;
//				m_info.dwStartType = 0;
//				m_info.dwTagId = 0;
//				m_info.IsInstall = FALSE;
//				TCHAR* m_Path = new TCHAR[MAX_PATH];
//				swprintf_s(m_Path, MAX_PATH, _T("SYSTEM\\CurrentControlSet\\Services\\%s"), (*it).c_str());
//				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE, m_Path, _T("ImagePath"), REG_EXPAND_SZ, m_info.lpBinaryPathName);
//				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE, m_Path, _T("DisplayName"), REG_SZ, m_info.DisplayName);
//				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE, m_Path, _T("ObjectName"), REG_SZ, m_info.lpServiceStartName);
//				GetRegHistoryREG_DWORDValue(HKEY_LOCAL_MACHINE, m_Path, _T("Start"), m_info.dwStartType);
//				GetRegHistoryREG_DWORDValue(HKEY_LOCAL_MACHINE, m_Path, _T("Type"), m_info.dwServiceType);
//				swprintf_s(m_Path, MAX_PATH, _T("SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters"), (*it).c_str());
//				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE, m_Path, _T("ServiceDll"), REG_EXPAND_SZ, m_info.lpServiceDll);
//				if (_tcscmp(m_info.lpBinaryPathName, _T("null")))
//				{
//					ServiceMap.insert(pair<wstring, SerivceInformation>(m_info.SerivceName, m_info));
//				}
//				delete[] m_Path;
//				//GetRegHistoryDisplayName((*it),&ServiceMap);
//			}
//			else
//			{
//				TCHAR* m_Path = new TCHAR[MAX_PATH];
//				swprintf_s(m_Path, MAX_PATH, _T("SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters"), (*it).c_str());
//				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE, m_Path, _T("ServiceDll"), REG_EXPAND_SZ, st->second.lpServiceDll);
//				delete[] m_Path;
//			}
//		}
//		char* TempStr = new char[DATASTRINGMESSAGELEN];
//		memset(TempStr, '\0', DATASTRINGMESSAGELEN);
//		int DataCount = 0;
//		int ret = 1;
//		for (st = ServiceMap.begin(); st != ServiceMap.end(); st++)
//		{
//			if (st->second.IsInstall)
//			{//MessageBox(0,st->first.c_str(),0,0);
//				if ((st->second.dwServiceType != 1 && st->second.dwServiceType != 2) && st->second.dwStartType != 1)
//				{
//					wchar_t* wstr = new wchar_t[2048];
//					swprintf_s(wstr, 2048, L"%s|%s|%lu|%lu|%s|%s|%s|%d|%s\n", st->first.c_str(), st->second.DisplayName, st->second.dwCurrentState, st->second.dwStartType, st->second.lpDescription, st->second.lpServiceStartName, st->second.lpBinaryPathName, st->second.IsInstall, st->second.lpServiceDll);
//					DataCount++;
//					char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
//					strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
//					delete[] wstr;
//					if ((DataCount % 30) == 0 && DataCount >= 30)
//					{
//						ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveStartupData", TempStr);
//						if (ret == 0 || ret == -1)
//						{
//							delete[] m_DataStr;
//							break;
//						}
//						memset(TempStr, '\0', DATASTRINGMESSAGELEN);
//					}
//					delete[] m_DataStr;
//				}
//			}
//			else
//			{
//				wchar_t* wstr = new wchar_t[2048];
//				swprintf_s(wstr, 2048, L"%s|%s|%lu|%lu|%s|%s|%s|%d|%s\n", st->first.c_str(), st->second.DisplayName, st->second.dwCurrentState, st->second.dwStartType, st->second.lpDescription, st->second.lpServiceStartName, st->second.lpBinaryPathName, st->second.IsInstall, st->second.lpServiceDll);
//				DataCount++;
//				char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
//				strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
//				delete[] wstr;
//				if ((DataCount % 30) == 0 && DataCount >= 30)
//				{
//					ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveStartupData", TempStr);
//					if (ret == 0 || ret == -1)
//					{
//						delete[] m_DataStr;
//						break;
//					}
//					memset(TempStr, '\0', DATASTRINGMESSAGELEN);
//				}
//				delete[] m_DataStr;
//			}
//
//		}
//
//		if (TempStr[0] != '\0' && ret > 0)
//		{
//			//MessageBoxA(0,TempStr,0,0);
//			ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveStartupData", TempStr);
//			if (ret > 0)
//			{
//				ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveStartupDataEnd", "");
//			}
//		}
//		delete[] TempStr;
//		RegHistorySerivceName.clear();
//	}
//	//else
//	//{
//	//	MessageBox(0,L"Anull",0,0);
//	//}
//	ServiceMap.clear();
//}
void AutoRun::LoadInstallService(map<wstring, SerivceInformation>* pServiceMap)
{
	SC_HANDLE hHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == hHandle)
	{
		//ErrorDescription(GetLastError());
		return;
	}
	else
	{
		//cout << "Open SCM sucessfully" << endl;
		//wprintf(_T("Open SCM sucessfully\n"));
	}
	//map<wstring,wstring> ServiceMap;
	ENUM_SERVICE_STATUS service;

	DWORD dwBytesNeeded = 0;
	DWORD dwServicesReturned = 0;
	DWORD dwResumedHandle = 0;
	DWORD dwServiceType = SERVICE_WIN32 | SERVICE_DRIVER;
	// Query services
	BOOL retVal = EnumServicesStatus(hHandle, dwServiceType, SERVICE_STATE_ALL,
		&service, sizeof(ENUM_SERVICE_STATUS), &dwBytesNeeded, &dwServicesReturned,
		&dwResumedHandle);
	if (!retVal)
	{
		// Need big buffer
		if (ERROR_MORE_DATA == GetLastError())
		{
			// Set the buffer
			DWORD dwBytes = sizeof(ENUM_SERVICE_STATUS) + dwBytesNeeded;
			ENUM_SERVICE_STATUS* pServices = NULL;
			pServices = new ENUM_SERVICE_STATUS[dwBytes];
			// Now query again for services
			EnumServicesStatus(hHandle, SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL,
				pServices, dwBytes, &dwBytesNeeded, &dwServicesReturned, &dwResumedHandle);
			// now traverse each service to get information
			for (unsigned iIndex = 0; iIndex < dwServicesReturned; iIndex++)
			{
				//(pServices + iIndex)->ServiceStatus.
				SerivceInformation m_info = { 0 };
				_tcscpy_s(m_info.DisplayName, 1024, _T("null"));
				_tcscpy_s(m_info.lpBinaryPathName, 1024, _T("null"));
				_tcscpy_s(m_info.lpDependencies, 1024, _T("null"));
				_tcscpy_s(m_info.lpDescription, 1024, _T("null"));
				_tcscpy_s(m_info.lpLoadOrderGroup, 1024, _T("null"));
				_tcscpy_s(m_info.lpServiceStartName, 1024, _T("null"));
				_tcscpy_s(m_info.SerivceName, 1024, _T("null"));
				m_info.dwCurrentState = 0;
				m_info.dwErrorControl = 0;
				m_info.dwServiceType = 0;
				m_info.dwStartType = 0;
				m_info.dwTagId = 0;
				//(pServices + iIndex)->ServiceStatus.
				//m_info.SerivceName.Format(_T("%s"),(pServices + iIndex)->lpServiceName);
				swprintf_s(m_info.SerivceName, 1024, _T("%s"), (pServices + iIndex)->lpServiceName);
				//m_info.DisplayName.Format(_T("%s"),(pServices + iIndex)->lpDisplayName);
				swprintf_s(m_info.DisplayName, 1024, _T("%s"), (pServices + iIndex)->lpDisplayName);
				m_info.dwCurrentState = (pServices + iIndex)->ServiceStatus.dwCurrentState;
				DoQuerySvc(&m_info);
				m_info.IsInstall = TRUE;
				//wcscpy_s(ServiceName,MAX_PATH,(pServices + iIndex)->lpServiceName);
				//wcscpy_s(DisplayName,MAX_PATH,(pServices + iIndex)->lpDisplayName);
				pServiceMap->insert(pair<wstring, SerivceInformation>(m_info.SerivceName, m_info));
			}
			delete[] pServices;
			pServices = NULL;
		}
		// there is any other reason
		else
		{
			//ErrorDescription(GetLastError());
		}
	}
	if (!CloseServiceHandle(hHandle))
	{
		//ErrorDescription(GetLastError());
	}
	else
	{
		//cout << "Close SCM sucessfully" << endl;
		//wprintf(_T("Close SCM sucessfully\n"));
	}
	// get the description of error
		//ServiceMap.clear();
}
void AutoRun::DoQuerySvc(SerivceInformation* pInfo)
{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;
	LPQUERY_SERVICE_CONFIG lpsc = NULL;
	LPSERVICE_DESCRIPTION lpsd = NULL;
	DWORD dwBytesNeeded, cbBufSize, dwError;

	// Get a handle to the SCM database. 

	schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // ServicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	if (NULL == schSCManager)
	{
		// printf("OpenSCManager failed (%d)\n", GetLastError());
		return;
	}

	// Get a handle to the service.

	schService = OpenService(
		schSCManager,          // SCM database 
		pInfo->SerivceName,             // name of service 
		SERVICE_QUERY_CONFIG); // need query config access 

	if (schService == NULL)
	{
		// printf("OpenService failed (%d)\n", GetLastError()); 
		CloseServiceHandle(schSCManager);
		return;
	}

	// Get the configuration information.

	if (!QueryServiceConfig(
		schService,
		NULL,
		0,
		&dwBytesNeeded))
	{
		dwError = GetLastError();
		if (ERROR_INSUFFICIENT_BUFFER == dwError)
		{
			cbBufSize = dwBytesNeeded;
			lpsc = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LMEM_FIXED, cbBufSize);
		}
		else
		{
			// printf("QueryServiceConfig failed (%d)", dwError);
			goto cleanup;
		}
	}

	if (!QueryServiceConfig(
		schService,
		lpsc,
		cbBufSize,
		&dwBytesNeeded))
	{
		//printf("QueryServiceConfig failed (%d)", GetLastError());
		goto cleanup;
	}

	if (!QueryServiceConfig2(
		schService,
		SERVICE_CONFIG_DESCRIPTION,
		NULL,
		0,
		&dwBytesNeeded))
	{
		dwError = GetLastError();
		if (ERROR_INSUFFICIENT_BUFFER == dwError)
		{
			cbBufSize = dwBytesNeeded;
			lpsd = (LPSERVICE_DESCRIPTION)LocalAlloc(LMEM_FIXED, cbBufSize);
		}
		else
		{
			// printf("QueryServiceConfig2 failed (%d)", dwError);
			goto cleanup;
		}
	}

	if (!QueryServiceConfig2(
		schService,
		SERVICE_CONFIG_DESCRIPTION,
		(LPBYTE)lpsd,
		cbBufSize,
		&dwBytesNeeded))
	{
		// printf("QueryServiceConfig2 failed (%d)", GetLastError());
		goto cleanup;
	}

	// Print the configuration information.

   // _tprintf(TEXT("%s configuration: \n"), szSvcName);
	pInfo->dwServiceType = lpsc->dwServiceType;
	//_tprintf(TEXT("  Type: 0x%x\n"), lpsc->dwServiceType);
	pInfo->dwStartType = lpsc->dwStartType;
	//_tprintf(TEXT("  Start Type: 0x%x\n"), lpsc->dwStartType);
	pInfo->dwErrorControl = lpsc->dwErrorControl;
	//_tprintf(TEXT("  Error Control: 0x%x\n"), lpsc->dwErrorControl);
	swprintf_s(pInfo->lpBinaryPathName, 1024, _T("%s"), lpsc->lpBinaryPathName);
	//pInfo->lpBinaryPathName.Format(_T("%s"),lpsc->lpBinaryPathName);
	//_tprintf(TEXT("  Binary path: %s\n"), lpsc->lpBinaryPathName);
	swprintf_s(pInfo->lpServiceStartName, 1024, _T("%s"), lpsc->lpServiceStartName);
	//pInfo->lpServiceStartName.Format(_T("%s"),lpsc->lpServiceStartName);
	//_tprintf(TEXT("  Account: %s\n"), lpsc->lpServiceStartName);

	if (lpsd->lpDescription != NULL && lstrcmp(lpsd->lpDescription, TEXT("")) != 0)
		swprintf_s(pInfo->lpDescription, 1024, _T("%s"), lpsd->lpDescription);
	//pInfo->lpDescription.Format(_T("%s"),lpsd->lpDescription);
   // _tprintf(TEXT("  Description: %s\n"), lpsd->lpDescription);
	if (lpsc->lpLoadOrderGroup != NULL && lstrcmp(lpsc->lpLoadOrderGroup, TEXT("")) != 0)
		swprintf_s(pInfo->lpLoadOrderGroup, 1024, _T("%s"), lpsc->lpLoadOrderGroup);
	//pInfo->lpLoadOrderGroup.Format(_T("%s"),lpsc->lpLoadOrderGroup);
	//_tprintf(TEXT("  Load order group: %s\n"), lpsc->lpLoadOrderGroup);
	if (lpsc->dwTagId != 0)
		pInfo->dwTagId = lpsc->dwTagId;
	// _tprintf(TEXT("  Tag ID: %d\n"), lpsc->dwTagId);
	if (lpsc->lpDependencies != NULL && lstrcmp(lpsc->lpDependencies, TEXT("")) != 0)
		swprintf_s(pInfo->lpDependencies, 1024, _T("%s"), lpsc->lpDependencies);
	//pInfo->lpDependencies.Format(_T("%s"),lpsc->lpDependencies);
	//_tprintf(TEXT("  Dependencies: %s\n"), lpsc->lpDependencies);

	LocalFree(lpsc);
	LocalFree(lpsd);

cleanup:
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
}

void AutoRun::LoadServiceStartCommand(map<wstring, BOOL>* pImagePath)
{
	map<wstring, SerivceInformation> ServiceMap;
	LoadInstallService(&ServiceMap);
	if (!ServiceMap.empty())
	{
		vector<wstring> RegHistorySerivceName;
		LoadRegHistorySubKeys(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Services"), &RegHistorySerivceName);
		map<wstring, SerivceInformation>::iterator st;
		vector<wstring>::iterator it;
		for (it = RegHistorySerivceName.begin(); it != RegHistorySerivceName.end(); it++)
		{
			st = ServiceMap.find((*it).c_str());
			if (st == ServiceMap.end())
			{
				SerivceInformation m_info = { 0 };
				_tcscpy_s(m_info.SerivceName, 1024, (*it).c_str());
				_tcscpy_s(m_info.DisplayName, 1024, (*it).c_str());
				_tcscpy_s(m_info.lpBinaryPathName, 1024, _T("null"));
				_tcscpy_s(m_info.lpDependencies, 1024, _T("null"));
				_tcscpy_s(m_info.lpDescription, 1024, _T("null"));
				_tcscpy_s(m_info.lpLoadOrderGroup, 1024, _T("null"));
				_tcscpy_s(m_info.lpServiceStartName, 1024, _T("null"));
				//_tcscpy_s(m_info.SerivceName,512,_T("null"));
				m_info.dwCurrentState = 0;
				m_info.dwErrorControl = 0;
				m_info.dwServiceType = 0;
				m_info.dwStartType = 0;
				m_info.dwTagId = 0;
				m_info.IsInstall = FALSE;
				TCHAR* m_Path = new TCHAR[MAX_PATH];
				swprintf_s(m_Path, MAX_PATH, _T("SYSTEM\\CurrentControlSet\\Services\\%s"), (*it).c_str());
				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE, m_Path, _T("ImagePath"), REG_EXPAND_SZ, m_info.lpBinaryPathName);
				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE, m_Path, _T("DisplayName"), REG_SZ, m_info.DisplayName);
				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE, m_Path, _T("ObjectName"), REG_SZ, m_info.lpServiceStartName);
				GetRegHistoryREG_DWORDValue(HKEY_LOCAL_MACHINE, m_Path, _T("Start"), m_info.dwStartType);
				GetRegHistoryREG_DWORDValue(HKEY_LOCAL_MACHINE, m_Path, _T("Type"), m_info.dwServiceType);
				if (_tcscmp(m_info.lpBinaryPathName, _T("null")))
				{
					ServiceMap.insert(pair<wstring, SerivceInformation>(m_info.SerivceName, m_info));
				}
				delete[] m_Path;
				//GetRegHistoryDisplayName((*it),&ServiceMap);
			}
		}
		RegHistorySerivceName.clear();
		for (st = ServiceMap.begin(); st != ServiceMap.end(); st++)
		{
			if (_tcscmp(st->second.lpBinaryPathName, _T("null")) && (st->second.dwServiceType != 1 && st->second.dwServiceType != 2) && st->second.dwStartType != 1)
				pImagePath->insert(pair<wstring, BOOL>(st->second.lpBinaryPathName, st->second.IsInstall));
		}
	}
	ServiceMap.clear();
}
void AutoRun::LoadAutoRunStartCommand(set<wstring>* pImagePath)
{
	vector<AutoRunInfo> m_StartRunInfo;
	TCHAR* Pathstr = new TCHAR[MAX_PATH_EX];
	//printf("GetAllUserStartUp\n");
	if (GetAllUserStartUp(Pathstr))
	{
		SearchAutoRunFile(&m_StartRunInfo, Pathstr);
	}

	//printf("LoadRegisterAutoRun\n");
	try {
		LoadRegisterAutoRun(&m_StartRunInfo);
	}
	catch (...) {
		printf("LoadRegisterAutoRun failed\n");
	}
	

	//printf("delete Pathstr\n");
	delete[] Pathstr;
	vector<wstring> ThisPCAllUser;
	//printf("GetThisPCAllUser\n");
	GetThisPCAllUser(&ThisPCAllUser);
	if (!ThisPCAllUser.empty())
	{
		wchar_t* UserName = new wchar_t[256];
		vector<wstring>::iterator ut;
		for (ut = ThisPCAllUser.begin(); ut != ThisPCAllUser.end(); ut++)
		{
			swprintf_s(UserName, 256, L"%s", (*ut).c_str());
			TCHAR* m_Path = new TCHAR[MAX_PATH];
			//printf("GetUserStartUp\n");
			if (GetUserStartUp(UserName, L"Startup", m_Path))
			{
				SearchAutoRunFile(&m_StartRunInfo, m_Path);
			}
			delete[] m_Path;
			//printf("LoadRegisterAutoRunFromUser\n");
			LoadRegisterAutoRunFromUser(&m_StartRunInfo, UserName);
		}
		delete[] UserName;
	}
	ThisPCAllUser.clear();
	vector<AutoRunInfo>::iterator it;
	for (it = m_StartRunInfo.begin(); it != m_StartRunInfo.end(); it++)
	{
		if (_tcscmp((*it).m_Command, _T("null")))
			pImagePath->insert((*it).m_Command);
	}
	m_StartRunInfo.clear();
}
//void AutoRun::StartupTaskSchedulerInfo(void* argv, char* pMAC, char* pIP)
//{
//	TransportData* m_Client = (TransportData*)argv;
//	vector<TaskSchedulerInfo> m_Info;
//	set<wstring> ThisPCAllUser;
//	vector<wstring> ThisPCAllUservector;
//	GetThisPCAllUser(&ThisPCAllUservector);
//	if (!ThisPCAllUservector.empty())
//	{
//		vector<wstring>::iterator it;
//		for (it = ThisPCAllUservector.begin(); it != ThisPCAllUservector.end(); it++)
//		{
//			ThisPCAllUser.insert((*it).c_str());
//		}
//	}
//	LoadTaskSchedulerInfo(&m_Info, &ThisPCAllUser);
//	if (!m_Info.empty())
//	{
//		char* TempStr = new char[DATASTRINGMESSAGELEN];
//		memset(TempStr, '\0', DATASTRINGMESSAGELEN);
//		int DataCount = 0;
//		int ret = 1;
//		vector<TaskSchedulerInfo>::iterator it;
//		for (it = m_Info.begin(); it != m_Info.end(); it++)
//		{
//			wchar_t* wstr = new wchar_t[16384];
//			swprintf_s(wstr, 16384, L"%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n", (*it).TaskName, (*it).Status, (*it).LastRunTime, (*it).NextRunTime, (*it).Triggers, (*it).HighPrivilege, (*it).RunOnNetwork, (*it).Author, (*it).Command, (*it).Argument, (*it).UserId);
//			DataCount++;
//			char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
//			strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
//			delete[] wstr;
//			if ((DataCount % 30) == 0 && DataCount >= 30)
//			{
//				ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveStartupData", TempStr);
//				if (ret == 0 || ret == -1)
//				{
//					delete[] m_DataStr;
//					break;
//				}
//				memset(TempStr, '\0', DATASTRINGMESSAGELEN);
//			}
//			delete[] m_DataStr;
//		}
//		if (TempStr[0] != '\0' && ret > 0)
//		{
//			ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveStartupData", TempStr);
//			if (ret > 0)
//			{
//				ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveStartupDataEnd", "");
//			}
//		}
//		delete[] TempStr;
//	}
//	ThisPCAllUservector.clear();
//	ThisPCAllUser.clear();
//	m_Info.clear();
//}
void AutoRun::LoadTaskSchedulerInfo(vector<TaskSchedulerInfo>* pInfo, set<wstring>* pstr)
{
	TaskSchedulerInfoProcessor Process;
	Process.GetTaskSchedulerInfo(pInfo);
}

void AutoRun::LoadRegisterInfoEx(vector<AutoRunInfo>* pInfo, HKEY pKey, const wchar_t* RegPath, const wchar_t* KeyStr, bool IsChildItem, bool Is32Bit)
{
	if (IsChildItem)
	{
		vector<wstring> strInfo;
		LoadRegisterChildItem(&strInfo, pKey, RegPath, Is32Bit);
		if (!strInfo.empty())
		{
			vector<wstring>::iterator it;
			for (it = strInfo.begin(); it != strInfo.end(); it++)
			{
				TCHAR* m_RegPath = new TCHAR[MAX_PATH_EX];
				swprintf_s(m_RegPath, MAX_PATH_EX, _T("%s\\%s"), RegPath, (*it).c_str());
				LoadRegisterDataEx(pInfo, pKey, m_RegPath, KeyStr, Is32Bit);
				delete[] m_RegPath;
			}
		}
		strInfo.clear();
	}
	else
	{
		LoadRegisterDataEx(pInfo, pKey, RegPath, KeyStr, Is32Bit);
	}
}
void AutoRun::LoadRegisterChildItem(vector<wstring>* pStrInfo, HKEY pKey, const wchar_t* RegPath, bool Is32Bit)
{
	if (Is32Bit)
	{
		HKEY hTestKey;
		if (RegOpenKeyEx(pKey,
			RegPath,
			0,
			KEY_READ | KEY_WOW64_32KEY,
			&hTestKey) == ERROR_SUCCESS
			)
		{
			QueryKey(hTestKey, pStrInfo);
		}
		RegCloseKey(hTestKey);
	}
	else
	{
		HKEY hTestKey;
		if (RegOpenKeyEx(pKey,
			RegPath,
			0,
			KEY_READ,
			&hTestKey) == ERROR_SUCCESS
			)
		{
			QueryKey(hTestKey, pStrInfo);
		}
		RegCloseKey(hTestKey);
	}
}
void AutoRun::LoadRegisterDataEx(vector<AutoRunInfo>* pInfo, HKEY pKey, const wchar_t* RegPath, const wchar_t* KeyStr, bool Is32Bit)
{
	HKEY hKey = NULL;
	LONG lResult;
	if (Is32Bit)
		lResult = RegOpenKeyEx(pKey, RegPath, 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &hKey);
	else
		lResult = RegOpenKeyEx(pKey, RegPath, 0, KEY_QUERY_VALUE, &hKey);
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
				if (REG_SZ == dwType || REG_EXPAND_SZ == dwType)
				{
					if (!_tcscmp(KeyStr, _T("*")))
					{
						AutoRunInfo m_Info;
						wcscpy_s(m_Info.StartName, MAX_PATH, pszName);
						TCHAR pCom[MAX_PATH_EX];//= new TCHAR[MAX_PATH_EX];
						try
						{
							//memcpy(pCom ,lpData,MAX_PATH_EX);
							swprintf_s(pCom, MAX_PATH_EX, _T("%s"), lpData);
						}
						catch (...)
						{
							_tcscpy_s(pCom, MAX_PATH_EX, _T("null"));
						}
						if (_tcscmp(pCom, _T("null")))
						{
							ExpandEnvironmentStrings(pCom, m_Info.m_Command, MAX_PATH_EX);
							/*memcpy(m_Info.m_Command,lpData,MAX_PATH_EX);*/
							if (Is32Bit)
							{
								if (pKey == HKEY_USERS)
									swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:HKEY_USERS\\%s"), RegPath);
								else if (pKey == HKEY_LOCAL_MACHINE)
									swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:HKEY_LOCAL_MACHINE\\%s"), RegPath);
								else
									swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:%s"), RegPath);
								pInfo->push_back(m_Info);
							}
							else
							{
								if (pKey == HKEY_USERS)
								{
									swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("HKEY_USERS\\%s"), RegPath);
								}
								else if (pKey == HKEY_LOCAL_MACHINE)
								{
									swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("HKEY_LOCAL_MACHINE\\%s"), RegPath);
								}
								else
								{
									swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("%s"), RegPath);
								}
								pInfo->push_back(m_Info);
							}
						}
					}
					else
					{
						if (!_tcsicmp(KeyStr, pszName))
						{
							AutoRunInfo m_Info;
							wcscpy_s(m_Info.StartName, MAX_PATH, pszName);
							TCHAR pCom[MAX_PATH_EX];//= new TCHAR[MAX_PATH_EX];
							try
							{
								memcpy(pCom, lpData, MAX_PATH_EX);
							}
							catch (...)
							{
								_tcscpy_s(pCom, MAX_PATH_EX, _T("null"));
							}
							if (_tcscmp(pCom, _T("null")))
							{
								ExpandEnvironmentStrings(pCom, m_Info.m_Command, MAX_PATH_EX);
								if (Is32Bit)
								{
									if (pKey == HKEY_USERS)
										swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:HKEY_USERS\\%s"), RegPath);
									else if (pKey == HKEY_LOCAL_MACHINE)
										swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:HKEY_LOCAL_MACHINE\\%s"), RegPath);
									else
										swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("x86:%s"), RegPath);
									pInfo->push_back(m_Info);
								}
								else
								{
									if (pKey == HKEY_USERS)
									{
										swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("HKEY_USERS\\%s"), RegPath);
									}
									else if (pKey == HKEY_LOCAL_MACHINE)
									{
										swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("HKEY_LOCAL_MACHINE\\%s"), RegPath);
									}
									else
									{
										swprintf_s(m_Info.InfoLocation, MAX_PATH_EX, _T("%s"), RegPath);
									}
									pInfo->push_back(m_Info);
								}
							}
						}
					}
				}
			}
			delete[]pszName;
			delete[]lpData;
		}
	}
	RegCloseKey(hKey);
}
void AutoRun::LoadAllStartRunInfo(vector<StartRunInfoData>* pStartRunInfo)
{
	LoadStartRunServiceInfo(pStartRunInfo);
	LoadStartRunAutoRunInfo(pStartRunInfo);
	LoadStartRunTaskSchedulerInfo(pStartRunInfo);
}
void AutoRun::LoadStartRunServiceInfo(vector<StartRunInfoData>* pStartRunInfo)
{
	map<wstring, SerivceInformation> ServiceMap;
	LoadInstallService(&ServiceMap);
	if (!ServiceMap.empty())
	{
		vector<wstring> RegHistorySerivceName;
		LoadRegHistorySubKeys(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Services"), &RegHistorySerivceName);
		map<wstring, SerivceInformation>::iterator st;
		vector<wstring>::iterator it;
		for (it = RegHistorySerivceName.begin(); it != RegHistorySerivceName.end(); it++)
		{
			st = ServiceMap.find((*it).c_str());
			if (st == ServiceMap.end())
			{
				SerivceInformation m_info = { 0 };
				_tcscpy_s(m_info.SerivceName, 1024, (*it).c_str());
				_tcscpy_s(m_info.DisplayName, 1024, (*it).c_str());
				_tcscpy_s(m_info.lpBinaryPathName, 1024, _T("null"));
				_tcscpy_s(m_info.lpDependencies, 1024, _T("null"));
				_tcscpy_s(m_info.lpDescription, 1024, _T("null"));
				_tcscpy_s(m_info.lpLoadOrderGroup, 1024, _T("null"));
				_tcscpy_s(m_info.lpServiceStartName, 1024, _T("null"));
				m_info.dwCurrentState = 0;
				m_info.dwErrorControl = 0;
				m_info.dwServiceType = 0;
				m_info.dwStartType = 0;
				m_info.dwTagId = 0;
				m_info.IsInstall = FALSE;
				TCHAR* m_Path = new TCHAR[MAX_PATH];
				swprintf_s(m_Path, MAX_PATH, _T("SYSTEM\\CurrentControlSet\\Services\\%s"), (*it).c_str());
				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE, m_Path, _T("ImagePath"), REG_EXPAND_SZ, m_info.lpBinaryPathName);
				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE, m_Path, _T("DisplayName"), REG_SZ, m_info.DisplayName);
				GetRegHistoryREG_SZValue(HKEY_LOCAL_MACHINE, m_Path, _T("ObjectName"), REG_SZ, m_info.lpServiceStartName);
				GetRegHistoryREG_DWORDValue(HKEY_LOCAL_MACHINE, m_Path, _T("Start"), m_info.dwStartType);
				GetRegHistoryREG_DWORDValue(HKEY_LOCAL_MACHINE, m_Path, _T("Type"), m_info.dwServiceType);
				if (_tcscmp(m_info.lpBinaryPathName, _T("null")))
				{
					ServiceMap.insert(pair<wstring, SerivceInformation>(m_info.SerivceName, m_info));
				}
				delete[] m_Path;
			}
		}
		for (st = ServiceMap.begin(); st != ServiceMap.end(); st++)
		{
			if (st->second.IsInstall)
			{//MessageBox(0,st->first.c_str(),0,0);
				if ((st->second.dwServiceType != 1 && st->second.dwServiceType != 2) && st->second.dwStartType != 1)
				{
					//pStartRunInfo->insert(pair<wstring,StartRunInfoData>(st->,m_info));
					TCHAR* str = new TCHAR[1024];
					TCHAR* str1 = new TCHAR[1024];
					TCHAR* pCom = new TCHAR[1024];
					_tcscpy_s(str, 1024, st->second.lpBinaryPathName);
					int j = 0;
					int n = 0;
					for (int i = 0; i < (int)wcslen(str); i++)
					{
						if (str[i] == '\"' && j == 0)
						{
							n = i;
							j++;
						}
						else if (str[i] == '\"' && j == 1)
						{
							str[i] = '\x0';
							break;
						}
						else if (j == 0 && str[i] == ' ')
						{
							str[i] = '\x0';
							break;
						}
					}
					if (j != 0)
						lstrcpy(pCom, str + (n + 1));
					else
						lstrcpy(pCom, str);
					ExpandEnvironmentStrings(pCom, str1, 1024);
					if (!_waccess(str1, 00) && str1[1] == ':')
					{
						BOOL IsHavePath = FALSE;
						vector<StartRunInfoData>::iterator vit;
						for (vit = pStartRunInfo->begin(); vit != pStartRunInfo->end(); vit++)
						{
							if (!_wcsicmp((*vit).FilePath, str1))
							{
								IsHavePath = TRUE;
								break;
							}
						}
						if (!IsHavePath)
						{
							StartRunInfoData m_PInfo;
							int id = 0;
							lstrcpy(m_PInfo.FilePath, str1);
							lstrcpy(m_PInfo.FileHash, _T("null"));
							for (int i = (int)wcslen(str1) - 1; i >= 0; i--)
							{
								if (str1[i] == '\\')
								{
									wcscpy_s(m_PInfo.FileName, MAX_PATH, str1 + (i + 1));
									break;
								}
							}
							pStartRunInfo->push_back(m_PInfo);
						}
					}
					delete[] pCom;
					delete[] str1;
					delete[] str;
				}
			}
			else
			{
				//pStartRunInfo->insert(pair<wstring,StartRunInfoData>(st->,m_info));
				TCHAR* str = new TCHAR[1024];
				TCHAR* str1 = new TCHAR[1024];
				TCHAR* pCom = new TCHAR[1024];
				_tcscpy_s(str, 1024, st->second.lpBinaryPathName);
				int j = 0;
				int n = 0;
				for (int i = 0; i < (int)wcslen(str); i++)
				{
					if (str[i] == '\"' && j == 0)
					{
						n = i;
						j++;
					}
					else if (str[i] == '\"' && j == 1)
					{
						str[i] = '\x0';
						break;
					}
					else if (j == 0 && str[i] == ' ')
					{
						str[i] = '\x0';
						break;
					}
				}
				if (j != 0)
					lstrcpy(pCom, str + (n + 1));
				else
					lstrcpy(pCom, str);
				ExpandEnvironmentStrings(pCom, str1, 1024);
				if (!_waccess(str1, 00) && str1[1] == ':')
				{
					BOOL IsHavePath = FALSE;
					vector<StartRunInfoData>::iterator vit;
					for (vit = pStartRunInfo->begin(); vit != pStartRunInfo->end(); vit++)
					{
						if (!_wcsicmp((*vit).FilePath, str1))
						{
							IsHavePath = TRUE;
							break;
						}
					}
					if (!IsHavePath)
					{
						StartRunInfoData m_PInfo;
						int id = 0;
						lstrcpy(m_PInfo.FilePath, str1);
						lstrcpy(m_PInfo.FileHash, _T("null"));
						for (int i = (int)wcslen(str1) - 1; i >= 0; i--)
						{
							if (str1[i] == '\\')
							{
								wcscpy_s(m_PInfo.FileName, MAX_PATH, str1 + (i + 1));
								break;
							}
						}
						pStartRunInfo->push_back(m_PInfo);
					}
				}
				delete[] pCom;
				delete[] str1;
				delete[] str;
			}
		}
		RegHistorySerivceName.clear();
	}
	ServiceMap.clear();
}
void AutoRun::LoadStartRunAutoRunInfo(vector<StartRunInfoData>* pStartRunInfo)
{
	vector<AutoRunInfo> m_StartRunInfo;
	TCHAR* Pathstr = new TCHAR[MAX_PATH_EX];
	if (GetAllUserStartUp(Pathstr))
	{
		SearchAutoRunFile(&m_StartRunInfo, Pathstr);
	}

	LoadRegisterAutoRun(&m_StartRunInfo);

	delete[] Pathstr;
	vector<wstring> ThisPCAllUser;
	GetThisPCAllUser(&ThisPCAllUser);
	if (!ThisPCAllUser.empty())
	{
		wchar_t* UserName = new wchar_t[256];
		vector<wstring>::iterator ut;
		for (ut = ThisPCAllUser.begin(); ut != ThisPCAllUser.end(); ut++)
		{
			swprintf_s(UserName, 256, L"%s", (*ut).c_str());
			TCHAR* m_Path = new TCHAR[MAX_PATH];
			if (GetUserStartUp(UserName, L"Startup", m_Path))
			{
				SearchAutoRunFile(&m_StartRunInfo, m_Path);
			}
			delete[] m_Path;
			LoadRegisterAutoRunFromUser(&m_StartRunInfo, UserName);
		}
		delete[] UserName;
	}
	ThisPCAllUser.clear();
	if (!m_StartRunInfo.empty())
	{
		vector<AutoRunInfo>::iterator it;
		for (it = m_StartRunInfo.begin(); it != m_StartRunInfo.end(); it++)
		{
			//pStartRunInfo->insert(pair<wstring,StartRunInfoData>(st->,m_info));
			TCHAR* str = new TCHAR[1024];
			TCHAR* str1 = new TCHAR[1024];
			TCHAR* pCom = new TCHAR[1024];
			_tcscpy_s(str, 1024, (*it).m_Command);
			int j = 0;
			int n = 0;
			for (int i = 0; i < (int)wcslen(str); i++)
			{
				if (str[i] == '\"' && j == 0)
				{
					n = i;
					j++;
				}
				else if (str[i] == '\"' && j == 1)
				{
					str[i] = '\x0';
					break;
				}
				else if (j == 0 && str[i] == ' ')
				{
					str[i] = '\x0';
					break;
				}
			}
			if (j != 0)
				lstrcpy(pCom, str + (n + 1));
			else
				lstrcpy(pCom, str);
			ExpandEnvironmentStrings(pCom, str1, 1024);
			if (!_waccess(str1, 00) && str1[1] == ':')
			{
				BOOL IsHavePath = FALSE;
				vector<StartRunInfoData>::iterator vit;
				for (vit = pStartRunInfo->begin(); vit != pStartRunInfo->end(); vit++)
				{
					if (!_wcsicmp((*vit).FilePath, str1))
					{
						IsHavePath = TRUE;
						break;
					}
				}
				if (!IsHavePath)
				{
					StartRunInfoData m_PInfo;
					int id = 0;
					lstrcpy(m_PInfo.FilePath, str1);
					lstrcpy(m_PInfo.FileHash, _T("null"));
					for (int i = (int)wcslen(str1) - 1; i >= 0; i--)
					{
						if (str1[i] == '\\')
						{
							wcscpy_s(m_PInfo.FileName, MAX_PATH, str1 + (i + 1));
							break;
						}
					}
					pStartRunInfo->push_back(m_PInfo);
				}
			}
			delete[] pCom;
			delete[] str1;
			delete[] str;
		}
	}
	m_StartRunInfo.clear();
}
void AutoRun::LoadStartRunTaskSchedulerInfo(vector<StartRunInfoData>* pStartRunInfo)
{
	vector<TaskSchedulerInfo> m_Info;
	set<wstring> ThisPCAllUser;
	vector<wstring> ThisPCAllUservector;
	GetThisPCAllUser(&ThisPCAllUservector);
	if (!ThisPCAllUservector.empty())
	{
		vector<wstring>::iterator it;
		for (it = ThisPCAllUservector.begin(); it != ThisPCAllUservector.end(); it++)
		{
			ThisPCAllUser.insert((*it).c_str());
		}
	}
	LoadTaskSchedulerInfo(&m_Info, &ThisPCAllUser);
	if (!m_Info.empty())
	{
		vector<TaskSchedulerInfo>::iterator it;
		for (it = m_Info.begin(); it != m_Info.end(); it++)
		{
			//pStartRunInfo->insert(pair<wstring,StartRunInfoData>(st->,m_info));
			TCHAR* str = new TCHAR[1024];
			TCHAR* str1 = new TCHAR[1024];
			TCHAR* pCom = new TCHAR[1024];
			_tcscpy_s(str, 1024, (*it).Command);
			int j = 0;
			int n = 0;
			for (int i = 0; i < (int)wcslen(str); i++)
			{
				if (str[i] == '\"' && j == 0)
				{
					n = i;
					j++;
				}
				else if (str[i] == '\"' && j == 1)
				{
					str[i] = '\x0';
					break;
				}
				else if (j == 0 && str[i] == ' ')
				{
					str[i] = '\x0';
					break;
				}
			}
			if (j != 0)
				lstrcpy(pCom, str + (n + 1));
			else
				lstrcpy(pCom, str);
			ExpandEnvironmentStrings(pCom, str1, 1024);
			if (!_waccess(str1, 00) && str1[1] == ':')
			{
				BOOL IsHavePath = FALSE;
				vector<StartRunInfoData>::iterator vit;
				for (vit = pStartRunInfo->begin(); vit != pStartRunInfo->end(); vit++)
				{
					if (!_wcsicmp((*vit).FilePath, str1))
					{
						IsHavePath = TRUE;
						break;
					}
				}
				if (!IsHavePath)
				{
					StartRunInfoData m_PInfo;
					int id = 0;
					lstrcpy(m_PInfo.FilePath, str1);
					lstrcpy(m_PInfo.FileHash, _T("null"));
					for (int i = (int)wcslen(str1) - 1; i >= 0; i--)
					{
						if (str1[i] == '\\')
						{
							wcscpy_s(m_PInfo.FileName, MAX_PATH, str1 + (i + 1));
							break;
						}
					}
					pStartRunInfo->push_back(m_PInfo);
				}
			}
			delete[] pCom;
			delete[] str1;
			delete[] str;
		}
	}
	ThisPCAllUservector.clear();
	ThisPCAllUser.clear();
	m_Info.clear();
}

TaskSchedulerInfoProcessor::TaskSchedulerInfoProcessor() :m_pInfo(nullptr)
{
}

void TaskSchedulerInfoProcessor::GetTaskSchedulerInfo(vector<TaskSchedulerInfo>* pInfo)
{
	if (nullptr != pInfo)
	{
		m_pInfo = pInfo;
	}
	else
	{
		return;
	}

	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		//printf("\nCoInitializeEx failed: %x", hr);
		return;
	}

	//  Set general COM security levels.
	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		0,
		NULL);

	if (FAILED(hr))
	{
		//printf("\nCoInitializeSecurity failed: %x", hr);
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Create an instance of the Task Service. 
	ITaskService* pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pService);
	if (FAILED(hr))
	{
		//printf("Failed to CoCreate an instance of the TaskService class: %x", hr);
		CoUninitialize();
		return;
	}

	//  Connect to the task service.
	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if (FAILED(hr))
	{
		//printf("ITaskService::Connect failed: %x", hr);
		pService->Release();
		CoUninitialize();
		return;
	}

	//  ------------------------------------------------------
	//  Get the pointer to the root task folder.
	ITaskFolder* pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);

	pService->Release();
	if (FAILED(hr))
	{
		//printf("Cannot get Root Folder pointer: %x", hr);
		CoUninitialize();
		return;
	}

	//  -------------------------------------------------------
	//  Get the registered tasks in the folder.
	RecTaskSchedulerFolder(pRootFolder, 0);
	pRootFolder->Release();

	CoUninitialize();
}

HRESULT TaskSchedulerInfoProcessor::RecTaskSchedulerFolder(ITaskFolder* pParentFolder, int level)
{
	HRESULT hr = S_OK;
	LONG ChildCount = 0;
	LONG TaskCount = 0;
	LONG idx = 0;
	IRegisteredTask* pTask = NULL;
	ITaskFolder* pFolder = NULL;

	if (level > MAX_LEVEL)
	{
		return hr;
	}

	hr = GetFolderCount(pParentFolder, &ChildCount);
	hr = GetTaskCount(pParentFolder, &TaskCount);

	for (idx = 0; idx < TaskCount; idx++)
	{
		pTask = GetTask(pParentFolder, idx);
		hr = GetTaskProperty(pTask);
		pTask->Release();
	}

	for (idx = 0; idx < ChildCount; idx++)
	{
		pFolder = GetTaskFolder(pParentFolder, idx);
		hr = RecTaskSchedulerFolder(pFolder, level + 1);
		pFolder->Release();
	}

	return hr;
}

HRESULT TaskSchedulerInfoProcessor::GetFolderCount(ITaskFolder* pTaskFolder, LONG* pCount)
{
	HRESULT hr = S_OK;
	ITaskFolderCollection* pFolderCollection = NULL;

	hr = pTaskFolder->GetFolders(0,						// reserved, should be 0
		&pFolderCollection);	// this pointer should be NULL

	if (FAILED(hr))
	{
		//wprintf(L"Failed to get folder collection: 0x%x\n", hr);
		return hr;
	}

	hr = pFolderCollection->get_Count(pCount);
	if (FAILED(hr))
	{
		//wprintf(L"Failed to get folder count: 0x%x\n", hr);
		pFolderCollection->Release();
		return hr;
	}

	//wprintf(L"Number of Folders : %d\n", *pCount);

	pFolderCollection->Release();

	return hr;
}

HRESULT TaskSchedulerInfoProcessor::GetTaskCount(ITaskFolder* pTaskFolder, LONG* pCount)
{
	HRESULT hr = S_OK;
	IRegisteredTaskCollection* pTaskCollection = NULL;

	hr = pTaskFolder->GetTasks(TASK_ENUM_HIDDEN,		// include HIDDEN task
		&pTaskCollection);		// this pointer should be NULL
	if (FAILED(hr)) {
		//wprintf(L"Failed to get task collection: 0x%x\n", hr);
		return hr;
	}

	hr = pTaskCollection->get_Count(pCount);
	if (FAILED(hr)) {
		//wprintf(L"Failed to get task count: 0x%x\n", hr);
		pTaskCollection->Release();
		return hr;
	}

	//wprintf(L"Number of Tasks : %d\n", *pCount);

	pTaskCollection->Release();

	return hr;
}

ITaskFolder* TaskSchedulerInfoProcessor::GetTaskFolder(ITaskFolder* pParentTaskFolder, LONG idx)
{
	HRESULT hr = S_OK;
	ITaskFolderCollection* pFolderCollection = NULL;
	ITaskFolder* pTaskFolder = NULL;

	hr = pParentTaskFolder->GetFolders(0,					// reserved, should be 0
		&pFolderCollection);	// this pointer should be NULL
	if (FAILED(hr)) {
		//wprintf(L"Failed to get folder collection: 0x%x\n", hr);
		return NULL;
	}

	// get child folder object 
	hr = pFolderCollection->get_Item(_variant_t(idx + 1),	// VARIANT index
		&pTaskFolder);	// this pointer should be NULL;
	if (FAILED(hr)) {
		//wprintf(L"Failed to get child folder: 0x%x\n", hr);
	}

	pFolderCollection->Release();

	return pTaskFolder;
}

IRegisteredTask* TaskSchedulerInfoProcessor::GetTask(ITaskFolder* pParentTaskFolder, LONG idx)
{
	HRESULT hr = S_OK;
	IRegisteredTaskCollection* pTaskCollection = NULL;
	IRegisteredTask* pTask = NULL;

	hr = pParentTaskFolder->GetTasks(TASK_ENUM_HIDDEN,		// include HIDDEN task
		&pTaskCollection);	// this pointer should be NULL
	if (FAILED(hr)) {
		//wprintf(L"Failed to get task collection: 0x%x\n", hr);
		return NULL;
	}

	// get child folder object 
	hr = pTaskCollection->get_Item(_variant_t(idx + 1),			// VARIANT index
		&pTask);					// this pointer should be NULL;
	if (FAILED(hr)) {
		//wprintf(L"Failed to get registered task: 0x%x\n", hr);
	}

	pTaskCollection->Release();

	return pTask;
}

HRESULT TaskSchedulerInfoProcessor::GetTaskProperty(IRegisteredTask* pRegisteredTask)
{
	HRESULT hr = S_OK;
	TaskSchedulerInfo Info = { 0 };

	BSTR taskName = NULL;
	hr = pRegisteredTask->get_Name(&taskName);
	if (SUCCEEDED(hr))
	{
		swprintf_s(Info.TaskName, MAX_PATH, _T("%s"), taskName);
		//printf("\nTask Name: %S", taskName);
		SysFreeString(taskName);
	}
	else
	{
		//printf("\nCannot get the registered task name: %x", hr);
		return hr;
	}

	TASK_STATE taskState;
	hr = pRegisteredTask->get_State(&taskState);
	if (SUCCEEDED(hr))
	{
		//printf("\n\tState: %d", taskState);
	}
	else
	{
		//printf("\n\tCannot get the registered task state: %x", hr);
	}
	GetStatusString(Info.Status, taskState);

	BSTR LastRunTimeSTR = NULL;
	DATE LastRunTime;
	hr = pRegisteredTask->get_LastRunTime(&LastRunTime);
	if (SUCCEEDED(hr) && 0 != LastRunTime && 36494 != LastRunTime)
	{
		VarBstrFromDate(LastRunTime, 0, LOCALE_NOUSEROVERRIDE, &LastRunTimeSTR);
		swprintf_s(Info.LastRunTime, 64, _T("%s"), LastRunTimeSTR);
		SysFreeString(LastRunTimeSTR);
	}

	BSTR NextRunTimeSTR = NULL;
	DATE NextRunTime;
	hr = pRegisteredTask->get_NextRunTime(&NextRunTime);
	if (SUCCEEDED(hr) && 0 != NextRunTime)
	{
		VarBstrFromDate(NextRunTime, 0, LOCALE_NOUSEROVERRIDE, &NextRunTimeSTR);
		swprintf_s(Info.NextRunTime, 64, _T("%s"), NextRunTimeSTR);
		SysFreeString(NextRunTimeSTR);
	}

	ITaskDefinition* pDefinition = NULL;
	hr = pRegisteredTask->get_Definition(&pDefinition);
	if (SUCCEEDED(hr))
	{
		hr = GetDefinitionProperty(pDefinition, &Info);
	}
	else
	{
		//wprintf(L"Failed to get definition property : 0x%x\n", hr);
	}

	BSTR taskXml = NULL;
	hr = pRegisteredTask->get_Xml(&taskXml);
	if (SUCCEEDED(hr))
	{
		wchar_t* wtr = new wchar_t[65536];
		swprintf_s(wtr, 65536, L"%s", taskXml);
		char* cstr = CStringToCharArray(wtr, CP_UTF8);
		ParsingXmlData(&Info, cstr);
		m_pInfo->push_back(Info);
		delete[] cstr;
		delete[] wtr;
		SysFreeString(taskXml);
	}

	return hr;
}

void TaskSchedulerInfoProcessor::GetStatusString(wchar_t* StatusString, TASK_STATE& state)
{
	switch (state)
	{
	case TASK_STATE_UNKNOWN:
		swprintf_s(StatusString, 32, _T("Unknow"));
		break;
	case TASK_STATE_DISABLED:
		swprintf_s(StatusString, 32, _T("Disabled"));
		break;
	case TASK_STATE_QUEUED:
		swprintf_s(StatusString, 32, _T("Queued"));
		break;
	case TASK_STATE_READY:
		swprintf_s(StatusString, 32, _T("Ready"));
		break;
	case TASK_STATE_RUNNING:
		swprintf_s(StatusString, 32, _T("Running"));
		break;
	}
}

HRESULT TaskSchedulerInfoProcessor::GetDefinitionProperty(ITaskDefinition* pDefinition, TaskSchedulerInfo* pInfo)
{
	HRESULT hr = S_OK;
	IRegistrationInfo* pRegistrationInfo = NULL;
	ITriggerCollection* pTriggerCollection = NULL;


	hr = pDefinition->get_RegistrationInfo(&pRegistrationInfo);
	if (SUCCEEDED(hr))
	{
		BSTR Author = NULL;
		hr = pRegistrationInfo->get_Author(&Author);

		if (SUCCEEDED(hr))
		{
			if (Author)
			{
				swprintf_s(pInfo->Author, 1024, _T("%s"), Author);
				SysFreeString(Author);
			}
		}
		else
		{
			//wprintf(L"Failed to get Author property: 0x%x, ", hr);
		}
	}
	else
	{
		//wprintf(L"Failed to get RegistrationInfo property: 0x%x, ", hr);
	}


	hr = pDefinition->get_Triggers(&pTriggerCollection);
	if (SUCCEEDED(hr))
	{
		LONG TriggersCount = 0;
		ITrigger* pTrigger = NULL;
		pTriggerCollection->get_Count(&TriggersCount);
		wstring triggers_result;
		bool commaflag = false;
		set<TASK_TRIGGER_TYPE2> trigger_set;
		for (int idx = 0; idx < TriggersCount; idx++)
		{
			hr = pTriggerCollection->get_Item(variant_t(idx + 1),
				&pTrigger);
			TASK_TRIGGER_TYPE2 trigger_type;
			pTrigger->get_Type(&trigger_type);
			trigger_set.insert(trigger_type);
			pTrigger->Release();
		}
		for (auto trigger_type : trigger_set)
		{
			wstring TriggerStr = GetTriggerString(trigger_type);
			if (TriggerStr != L"")
			{
				if (!commaflag)
				{
					commaflag = true;
				}
				else
				{
					triggers_result += L",";
				}
				triggers_result += TriggerStr;
			}
		}
		swprintf_s(pInfo->Triggers, 1024, L"%s", triggers_result.c_str());
	}
	else
	{
		//wprintf(L"Failed to get TriggerCollection pointer: 0x%x, ", hr);
	}

	pRegistrationInfo->Release();

	return hr;
}

wstring TaskSchedulerInfoProcessor::GetTriggerString(TASK_TRIGGER_TYPE2& trigger_type)
{
	switch (trigger_type)
	{
	case TASK_TRIGGER_EVENT:
		return L"Event";
	case TASK_TRIGGER_TIME:
		return L"Time";
	case TASK_TRIGGER_DAILY:
		return L"Daily";
	case TASK_TRIGGER_WEEKLY:
		return L"Weekly";
	case TASK_TRIGGER_MONTHLY:
		return L"Monthly";
	case TASK_TRIGGER_MONTHLYDOW:
		return L"MonthlyDow";
	case TASK_TRIGGER_IDLE:
		return L"Idle";
	case TASK_TRIGGER_REGISTRATION:
		return L"Registration";
	case TASK_TRIGGER_BOOT:
		return L"Boot";
	case TASK_TRIGGER_LOGON:
		return L"Logon";
	case TASK_TRIGGER_SESSION_STATE_CHANGE:
		return L"Session State Change";
	default:
		return L"";
	}
}

void TaskSchedulerInfoProcessor::ParsingXmlData(TaskSchedulerInfo* pInfo, char* m_Xmlstr)
{
	//pugi::xml_document doc;
	//pugi::xml_parse_result result = doc.load(m_Xmlstr);
	//if (result)
	//{
	//	pugi::xml_node tools = doc.child("Task")/*.child("Actions").child("Exec")*/;
	//	//MessageBoxA(0,tools.child("Actions").child("Exec").child_value("Command"),0,0);
	//	//MessageBoxA(0,tools.child("Triggers").child("TimeTrigger").child_value("StartBoundary"),0,0);
	//	//MessageBoxA(0,tools.child("Principals").child("Principal").child_value("UserId"),0,0);
	//	char* str = new char[MAX_PATH_EX];
	//	sprintf_s(str, MAX_PATH_EX, "%s", tools.child("Actions").child("Exec").child_value("Command"));
	//	wchar_t* wtr = CharArrayToWString(str, CP_UTF8);
	//	_tcscpy_s(pInfo->Command, MAX_PATH_EX, wtr);

	//	if (!tools.child("Actions").child("Exec").child("Command").empty())
	//	{
	//		swprintf_s(pInfo->Argument, MAX_PATH_EX, L"%S", tools.child("Actions").child("Exec").child_value("Arguments"));
	//	}

	//	if (!tools.child("Settings").child("RunOnlyIfNetworkAvailable").empty())
	//	{
	//		if (!strcmp("true", tools.child("Settings").child_value("RunOnlyIfNetworkAvailable")))
	//		{
	//			swprintf_s(pInfo->RunOnNetwork, MAX_PATH_EX, L"%s", L"Yes");
	//		}
	//		else
	//		{
	//			swprintf_s(pInfo->RunOnNetwork, MAX_PATH_EX, L"%s", L"No");
	//		}
	//	}
	//	else
	//	{
	//		swprintf_s(pInfo->RunOnNetwork, MAX_PATH_EX, L"%s", L"No");
	//	}

	//	if (!tools.child("Principals").child("Principal").child("RunLevel").empty())
	//	{
	//		if (!strcmp("HighestAvailable", tools.child("Principals").child("Principal").child_value("RunLevel")))
	//		{
	//			swprintf_s(pInfo->HighPrivilege, MAX_PATH_EX, L"%s", L"Yes");
	//		}
	//		else
	//		{
	//			swprintf_s(pInfo->HighPrivilege, MAX_PATH_EX, L"%s", L"No");
	//		}
	//	}
	//	else
	//	{
	//		swprintf_s(pInfo->HighPrivilege, MAX_PATH_EX, L"%s", L"No");
	//	}

	//	if (tools.child("Principals").child("Principal").child("UserId").empty())
	//	{
	//		sprintf_s(str, MAX_PATH_EX, "%s", tools.child("Principals").child("Principal").child_value("GroupId"));
	//	}
	//	else
	//	{
	//		sprintf_s(str, MAX_PATH_EX, "%s", tools.child("Principals").child("Principal").child_value("UserId"));
	//	}

	//	wchar_t* wtr1 = CharArrayToWString(str, CP_UTF8);
	//	_tcscpy_s(pInfo->UserId, _MAX_FNAME, wtr1);
	//	set<wstring>::iterator it;
	//	//it = pstr->find(wtr1);
	//	//if(it != pstr->end())
	//	{
	//		SID_NAME_USE SidType;
	//		TCHAR* lpName = new TCHAR[_MAX_FNAME];
	//		TCHAR* lpDomain = new TCHAR[_MAX_FNAME];
	//		DWORD dwSize = _MAX_FNAME;
	//		PSID Sid = NULL;// = GetBinarySid(pSIDstr);
	//		if (ConvertStringSidToSid(wtr1, &Sid))
	//		{
	//			if (LookupAccountSid(NULL, Sid, lpName, &dwSize, lpDomain, &dwSize, &SidType))
	//			{
	//				_tcscpy_s(pInfo->UserId, _MAX_FNAME, lpName);
	//			}
	//		}
	//		LocalFree(Sid);
	//		delete[] lpDomain;
	//		delete[] lpName;
	//	}
	//	delete[] wtr1;
	//	delete[] wtr;
	//	delete[] str;
	//}
}
