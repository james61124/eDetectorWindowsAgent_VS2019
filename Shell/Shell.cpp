// Shell.cpp : 定義主控台應用程式的進入點。
//

#include "stdafx.h"

#include <shlobj.h>
#include <vector>
#include <string>
#include <iostream>
using namespace std;
//#define IsService //
#define IsDeleteMySelf
#define startupkeyname L"ClientSearch"
#define SERVICE_NAME _T("iForensics_ClientSearch_Service")
vector<wstring> RunFilePath;
char* SysInfo = NULL;
//bool OSInfo = true;
unsigned char chnbit(unsigned char c)
{
	return (c >> 4) | (c << 4);
}
unsigned char _rol(unsigned char c, unsigned int num)
{
	return (c << num) | (c >> (8 - num));
}
unsigned char _ror(unsigned char c, unsigned int num)
{
	return (c >> num) | (c << (8 - num));
}
void mydecrypt(unsigned char* input, unsigned char* output, int len)
{
	int j = 0;
	for (int i = 0; i < len; i++)
	{
		output[i] = input[len - 1 - i];
		output[i] ^= 0x92 + i % 256;
		output[i] = _rol(output[i], (3 + i) % 8);
		output[i] = chnbit(output[i]);
	}
}
bool dirExists(wchar_t* dirPath)
{
	DWORD ftyp = GetFileAttributesW(dirPath);
	if (ftyp == INVALID_FILE_ATTRIBUTES)
		return false;  //something is wrong with your path!

	if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
		return true;   // this is a directory!

	return false;    // this is not a directory!
}
void FolderClear(TCHAR* FilePath, TCHAR* Extstr)
{
	TCHAR* szTempPath = new TCHAR[512];
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
			TCHAR* szPath = new TCHAR[512];
			swprintf_s(szPath, 512, L"%s\\%s", FilePath, fd.cFileName);
			DeleteFile(szPath);
			delete[] szPath;
		}
	} while (FindNextFile(hSearch, &fd) != FALSE);
	FindClose(hSearch);
	delete[] szTempPath;
}
void CmdCommandWork(wchar_t* COMstr, bool IsWait)
{
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
		WaitForSingleObject(ShExecInfo.hProcess, INFINITE);
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
BOOL CALLBACK EnumResNameProc(HMODULE hModule, LPCTSTR lpszType, LPTSTR lpszName, LONG_PTR lParam)
{
	wchar_t outputpath[MAX_PATH];
	if (SHGetSpecialFolderPath(NULL, outputpath, CSIDL_PROGRAM_FILES, false))
	{
		HRSRC hRes = FindResource(NULL, lpszName, lpszType);
		if ((int)lpszName >= 1 && (int)lpszName <= 100)
			if (hRes)
			{
				char* tmpbuffer = (char*)LockResource(LoadResource(0, hRes));
				int reslen = SizeofResource(0, hRes);
				char* buffer = new char[reslen];
				mydecrypt((unsigned char*)tmpbuffer, (unsigned char*)buffer, reslen);

				wcscat_s(outputpath, L"\\eDetectorClient\\");
				wcscat_s(outputpath, (wchar_t*)buffer);
				int len = (int)wcslen(outputpath);
				if (len > 0)
				{
					wchar_t* FilePathStr = new wchar_t[MAX_PATH];
					wchar_t* ComStr = new wchar_t[128];
					wchar_t* pwc;
					wchar_t* next_token = NULL;
					int i = 0;
					pwc = wcstok_s(outputpath, L"|", &next_token);
					while (pwc != NULL)
					{
						if (i == 0)
						{
							wcscpy_s(FilePathStr, MAX_PATH, pwc);
						}
						else if (i == 1)
						{
							wcscpy_s(ComStr, 128, pwc);
							break;
						}
						i++;
						pwc = wcstok_s(NULL, L"|", &next_token);
					}

					int Pathlen = 0;
					for (int j = (int)wcslen(FilePathStr) - 1; j >= 0; j--)
					{
						if (FilePathStr[j] == '\\')
						{
							Pathlen = j;
							break;
						}
					}
					if (Pathlen == 0)
					{
						delete[] ComStr;
						delete[] FilePathStr;
						return true;
					}

					if (!strcmp(SysInfo, "x64"))
					{
						if (wcscmp(FilePathStr + (Pathlen + 1), L"ClientSearch-x64.exe"))
						{
							std::vector<const wchar_t*> replacements = {
								L"Detector",
								L"iForensicsService.exe",
								L"WhiteList-x64.dll",
								L"api-ms-win-core-heap-l1-1-0.dll",
								L"api-ms-win-crt-convert-l1-1-0.dll",
								L"api-ms-win-crt-heap-l1-1-0.dll",
								L"api-ms-win-crt-locale-l1-1-0.dll",
								L"api-ms-win-crt-math-l1-1-0.dll",
								L"api-ms-win-crt-private-l1-1-0.dll",
								L"api-ms-win-crt-runtime-l1-1-0.dll",
								L"api-ms-win-crt-stdio-l1-1-0.dll",
								L"api-ms-win-crt-string-l1-1-0.dll",
								L"concrt140.dll",
								L"msvcp_win.dll",
								L"msvcp140.dll",
								L"msvcp140_1.dll",
								L"msvcrt.dll",
								L"ucrtbase.dll",
								L"vcruntime140.dll",
								L"wlanapi.dll",
								L"api-ms-win-core-heap-l2-1-0.dll",
								L"vcruntime140d.dll",
								L"vcruntime140_1d.dll",
								L"ucrtbased.dll",
								L"msvcp140d.dll",
								L"libyara64.dll",
								L"libyara.exe"
							};

							bool matchFound = false;
							for (const wchar_t* replacement : replacements) {
								if (!wcscmp(FilePathStr + Pathlen + 1, replacement)) {
									matchFound = true;
									FilePathStr[Pathlen + 1] = '\x0';
									wcscat_s(FilePathStr, MAX_PATH, replacement);
									break;
								}
							}

							if (!matchFound) {
								delete[] ComStr;
								delete[] FilePathStr;
								return true;
							}







							//if (!wcscmp(FilePathStr + (Pathlen + 1), L"Detector"))
							//{
							//	FilePathStr[Pathlen + 1] = '\x0';
							//	wcscat_s(FilePathStr, MAX_PATH, L"Detector");
							//}
							//else if (!wcscmp(FilePathStr + (Pathlen + 1), L"iForensicsService.exe"))
							//{
							//	FilePathStr[Pathlen + 1] = '\x0';
							//	wcscat_s(FilePathStr, MAX_PATH, L"iForensicsService.exe");
							//}
							//else if (!wcscmp(FilePathStr + (Pathlen + 1), L"WhiteList-x64.dll"))
							//{
							//	FilePathStr[Pathlen + 1] = '\x0';
							//	wcscat_s(FilePathStr, MAX_PATH, L"WhiteList.dll");
							//}
							//else if (!wcscmp(FilePathStr + (Pathlen + 1), L"api-ms-win-core-heap-l1-1-0.dll"))
							//{
							//	FilePathStr[Pathlen + 1] = '\x0';
							//	wcscat_s(FilePathStr, MAX_PATH, L"api-ms-win-core-heap-l1-1-0.dll");
							//}
							//else if (!wcscmp(FilePathStr + (Pathlen + 1), L"api-ms-win-crt-convert-l1-1-0.dll"))
							//{
							//	FilePathStr[Pathlen + 1] = '\x0';
							//	wcscat_s(FilePathStr, MAX_PATH, L"api-ms-win-crt-convert-l1-1-0.dll");
							//}
							//else if (!wcscmp(FilePathStr + (Pathlen + 1), L"api-ms-win-crt-heap-l1-1-0.dll"))
							//{
							//	FilePathStr[Pathlen + 1] = '\x0';
							//	wcscat_s(FilePathStr, MAX_PATH, L"api-ms-win-crt-locale-l1-1-0.dll");
							//}
							//else if (!wcscmp(FilePathStr + (Pathlen + 1), L"api-ms-win-crt-locale-l1-1-0.dll"))
							//{
							//	FilePathStr[Pathlen + 1] = '\x0';
							//	wcscat_s(FilePathStr, MAX_PATH, L"api-ms-win-crt-heap-l1-1-0.dll");
							//}
							//else if (!wcscmp(FilePathStr + (Pathlen + 1), L"api-ms-win-crt-math-l1-1-0.dll"))
							//{
							//	FilePathStr[Pathlen + 1] = '\x0';
							//	wcscat_s(FilePathStr, MAX_PATH, L"api-ms-win-crt-math-l1-1-0.dll");
							//}
							//else
							//{
							//	delete[] ComStr;
							//	delete[] FilePathStr;
							//	return true;
							//}
						}
						else
						{
							FilePathStr[Pathlen + 1] = '\x0';
							wcscat_s(FilePathStr, MAX_PATH, L"ClientSearch.exe");
						}
					}
					else
					{
						if (wcscmp(FilePathStr + (Pathlen + 1), L"ClientSearch-x86.exe"))
						{
							//if(!wcscmp(FilePathStr+(Pathlen+1),L"eDetector.ptn"))
							//{
							//	FilePathStr[Pathlen+1] = '\x0';
							//	wcscat_s(FilePathStr,MAX_PATH,L"eDetector.ptn");
							//}
							if (!wcscmp(FilePathStr + (Pathlen + 1), L"Detector"))
							{
								FilePathStr[Pathlen + 1] = '\x0';
								wcscat_s(FilePathStr, MAX_PATH, L"Detector");
							}
							else if (!wcscmp(FilePathStr + (Pathlen + 1), L"Detectdriver.sys"))
							{
								FilePathStr[Pathlen + 1] = '\x0';
								wcscat_s(FilePathStr, MAX_PATH, L"Detectdriver.sys");
							}
							else if (!wcscmp(FilePathStr + (Pathlen + 1), L"EnumProcess.sys"))
							{
								FilePathStr[Pathlen + 1] = '\x0';
								wcscat_s(FilePathStr, MAX_PATH, L"EnumProcess.sys");
							}
							else if (!wcscmp(FilePathStr + (Pathlen + 1), L"iForensicsService.exe"))
							{
								FilePathStr[Pathlen + 1] = '\x0';
								wcscat_s(FilePathStr, MAX_PATH, L"iForensicsService.exe");
							}
							else if (!wcscmp(FilePathStr + (Pathlen + 1), L"WhiteList-x86.dll"))
							{
								FilePathStr[Pathlen + 1] = '\x0';
								wcscat_s(FilePathStr, MAX_PATH, L"WhiteList.dll");
							}
							//else if(!wcscmp(FilePathStr+(Pathlen+1),L"CliectSearchTools_x86.exe"))
							//{
							//	FilePathStr[Pathlen+1] = '\x0';
							//	wcscat_s(FilePathStr,MAX_PATH,L"CliectSearchTools_x86.exe");
							//}
							//else if(!wcscmp(FilePathStr+(Pathlen+1),L"DetectAccessFile_x86.dll"))
							//{
							//	FilePathStr[Pathlen+1] = '\x0';
							//	wcscat_s(FilePathStr,MAX_PATH,L"DetectAccessFile_x86.dll");
							//}
							else
							{
								delete[] ComStr;
								delete[] FilePathStr;
								return true;
							}
						}
						else
						{
							FilePathStr[Pathlen + 1] = '\x0';
							wcscat_s(FilePathStr, MAX_PATH, L"ClientSearch.exe");
						}
					}
					//}

					FILE* fp;
					fp = NULL;
					_wfopen_s(&fp, FilePathStr, L"wb");
					if (fp)
					{
						fwrite((void*)((SIZE_T)buffer + MAX_PATH * sizeof(wchar_t)), 1, SizeofResource(0, hRes) - MAX_PATH * sizeof(wchar_t), fp);
						fclose(fp);
						int wtrlen = (int)wcslen(FilePathStr);
						if (wcsstr(FilePathStr, L"ClientSearch.exe") != 0)
						{
							if (wcscmp(ComStr, L"null"))
							{
								wchar_t CommandLine[_MAX_PATH];
								swprintf_s(CommandLine, _MAX_PATH, L"/c \"%s\" %s", FilePathStr, ComStr);
								wstring wstr = CommandLine;
								RunFilePath.push_back(CommandLine);
							}
						}
						else if (wcsstr(FilePathStr, L"iForensicsService.exe") != 0)
						{
							wchar_t CommandLine[_MAX_PATH];
							swprintf_s(CommandLine, _MAX_PATH, L"/c \"%s\" %s", FilePathStr, ComStr);
							wstring wstr = CommandLine;
							RunFilePath.push_back(CommandLine);
						}
						//}
					}
					delete[] ComStr;
					delete[] FilePathStr;
				}
			}
	}
	return true;
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

int _tmain(int argc, _TCHAR* argv[])
{
	printf("shell start\n");
	SysInfo = GetSysInfo();
	//OSInfo = GetOSVersion();
	int ret = 0;
	wchar_t* CreateFolderpath = new wchar_t[MAX_PATH];
	if (SHGetSpecialFolderPath(NULL, CreateFolderpath, CSIDL_PROGRAM_FILES, false))
	{
		const wchar_t processName[] = L"ClientSearch.exe";
		std::wcout << "Program File Path: " << CreateFolderpath << std::endl;
		if (FindPID(const_cast<wchar_t*>(processName)) != 0)
		{
			wchar_t* CommandLine = new wchar_t[_MAX_PATH];
			swprintf_s(CommandLine, _MAX_PATH, L"/c c:\\windows\\system32\\taskkill.exe /f /im ClientSearch.exe & c:\\windows\\system32\\sc.exe delete iForensics_ClientSearch_Service & c:\\windows\\system32\\ping.exe 127.0.0.1 -n 2");
			CmdCommandWork(CommandLine, true);
			delete[] CommandLine;
		}
		else
		{
			wchar_t* CommandLine = new wchar_t[_MAX_PATH];
			swprintf_s(CommandLine, _MAX_PATH, L"/c c:\\windows\\system32\\sc.exe delete iForensics_ClientSearch_Service");
			CmdCommandWork(CommandLine, true);
			delete[] CommandLine;
		}
		wchar_t* ServicePath = new wchar_t[MAX_PATH];
		swprintf_s(ServicePath, MAX_PATH, L"%s\\eDetector\\iForensicsService.exe", CreateFolderpath);

		if (!_waccess(ServicePath, 00))
		{
			wchar_t* CommandLine = new wchar_t[_MAX_PATH];
			swprintf_s(CommandLine, _MAX_PATH, L"/c \"%s\" /uninstall", ServicePath);
			CmdCommandWork(CommandLine, true);
			swprintf_s(CommandLine, _MAX_PATH, L"/c sc delete iForensics_ClientSearch_Service");
			CmdCommandWork(CommandLine, true);
			//if(FindPID(L"iForensicsService.exe")!=0)
			//{
			swprintf_s(CommandLine, _MAX_PATH, L"/c c:\\windows\\system32\\taskkill.exe /f /im iForensicsService.exe & c:\\windows\\system32\\ping.exe 127.0.0.1 -n 2");
			CmdCommandWork(CommandLine, true);
			//}
			delete[] CommandLine;
		}
		swprintf_s(ServicePath, MAX_PATH, L"%s\\eDetectorClient\\iForensicsService.exe", CreateFolderpath);
		if (!_waccess(ServicePath, 00))
		{
			wchar_t* CommandLine = new wchar_t[_MAX_PATH];
			swprintf_s(CommandLine, _MAX_PATH, L"/c \"%s\" /uninstall", ServicePath);
			CmdCommandWork(CommandLine, true);
			//if(FindPID(L"iForensicsService.exe")!=0)
			//{
			swprintf_s(CommandLine, _MAX_PATH, L"/c c:\\windows\\system32\\taskkill.exe /f /im iForensicsService.exe & c:\\windows\\system32\\ping.exe 127.0.0.1 -n 2");
			CmdCommandWork(CommandLine, true);
			//}
			delete[] CommandLine;
		}
		delete[] ServicePath;

		wcscat_s(CreateFolderpath, MAX_PATH, L"\\eDetectorClient");
		if (dirExists(CreateFolderpath))
		{
			const wchar_t folderPath[] = L"\\*.*";
			FolderClear(CreateFolderpath, const_cast<TCHAR*>(folderPath));
			RemoveDirectory(CreateFolderpath);
		}
		CreateDirectory(CreateFolderpath, NULL);
		wcscat_s(CreateFolderpath, MAX_PATH, L"\\StartSearch.exe");

		if (_waccess(CreateFolderpath, 00))
		{
			printf("%s\n", "開始安裝");
			wchar_t* myfilepath = new wchar_t[MAX_PATH];
			GetModuleFileName(GetModuleHandle(NULL), myfilepath, MAX_PATH);
			if (CopyFile(myfilepath, CreateFolderpath, false))
			{
				wchar_t* CommandLine = new wchar_t[512];
				swprintf_s(CommandLine, 512, L"/c \"%s\"", CreateFolderpath);
				CmdCommandWork(CommandLine, false);
#ifdef IsDeleteMySelf
				swprintf_s(CommandLine, 512, L"/c c:\\windows\\system32\\ping.exe 127.0.0.1 -n 2 & erase /F %s", GetCommandLine());
				CmdCommandWork(CommandLine, false);
#endif
				delete[] CommandLine;
			}
		}
		else
		{
			wchar_t* myfilepath = new wchar_t[MAX_PATH];
			GetModuleFileName(GetModuleHandle(NULL), myfilepath, MAX_PATH);
			if (!_wcsicmp(myfilepath, CreateFolderpath))
			{
				if (EnumResourceNames(0, RT_RCDATA, EnumResNameProc, 0))
				{
					vector<wstring>::iterator it;
					for (it = RunFilePath.begin(); it != RunFilePath.end(); it++)
					{
						std::wcout << *it << std::endl;
						const wchar_t processName[] = L"ClientSearch.exe";
						if (FindPID(const_cast<wchar_t*>(processName)) == 0)
						{
							wchar_t* CommandLine = new wchar_t[_MAX_PATH];
							swprintf_s(CommandLine, _MAX_PATH, L"%s", it->c_str());
							//MessageBox(0,CommandLine,0,0);
							CmdCommandWork(CommandLine, false);
							delete[] CommandLine;
						}
					}
				}
			}
			else
			{
				if (CopyFile(myfilepath, CreateFolderpath, false))
				{
					wchar_t* CommandLine = new wchar_t[512];
					swprintf_s(CommandLine, 512, L"/c c:\\windows\\system32\\taskkill.exe /f /im ClientSearch.exe & c:\\windows\\system32\\ping.exe 127.0.0.1 -n 2");
					CmdCommandWork(CommandLine, true);
					swprintf_s(CommandLine, 512, L"/c \"%s\"", CreateFolderpath);
					CmdCommandWork(CommandLine, false);
#ifdef IsDeleteMySelf
					swprintf_s(CommandLine, 512, L"/c c:\\windows\\system32\\ping.exe 127.0.0.1 -n 2 & erase /F %s", GetCommandLine());
					CmdCommandWork(CommandLine, false);
#endif
					delete[] CommandLine;
				}
			}
			delete[] myfilepath;
		}
	}
	else {
		DWORD errorCode = GetLastError();
		wprintf(L"SHGetSpecialFolderPath failed with error code: %lu\n", errorCode);
	}
	delete[] CreateFolderpath;
	return ret;
}

