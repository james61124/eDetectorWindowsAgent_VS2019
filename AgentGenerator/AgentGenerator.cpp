#include <iostream>
#include <afx.h> 
#include <shlwapi.h>
#include <cstring>


using namespace std;

struct ResourceInfo
{
	CString path;
	LPCWSTR filename;
	LPCWSTR commandStr;
	int index;
};



CString GetMyPath()
{
	wchar_t path[MAX_PATH];
	GetModuleFileName(NULL, path, MAX_PATH);
	CString directory;
	PathRemoveFileSpec(path);
	directory = path;
	return directory;
}

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

void myencrypt(unsigned char* input, unsigned char* output, int len)
{
	int j = 0;
	for (int i = 0; i < len; i++)
	{
		output[len - i - 1] = input[i];
		output[len - i - 1] = chnbit(output[len - i - 1]);
		output[len - i - 1] = _ror(output[len - i - 1], (3 + i) % 8);
		output[len - i - 1] ^= 0x92 + i % 256;
	}
}


bool ImportResource(HANDLE pRes, CString ImportFile, wchar_t* pFileName, CString pCommand, unsigned int ret)
{
	bool retn = true;
	FILE* fp = NULL;
	_wfopen_s(&fp, ImportFile.AllocSysString(), L"rb");
	if (fp)
	{
		fseek(fp, 0, SEEK_END);
		unsigned int filesize = ftell(fp);
		rewind(fp);
		char* buffer = new char[filesize + MAX_PATH * sizeof(wchar_t)];
		//wchar_t *filename = L"ClientSearch-x64.exe";
		if (fread((void*)((SIZE_T)buffer + MAX_PATH * sizeof(wchar_t)), 1, filesize, fp) == filesize)
		{
			wchar_t newfilename[MAX_PATH];
			wcscpy_s(newfilename, MAX_PATH, pFileName);
			wcscat_s(newfilename, MAX_PATH, L"|");
			wcscat_s(newfilename, MAX_PATH, pCommand);
			memcpy(buffer, newfilename, MAX_PATH * sizeof(wchar_t));
			char* encrypted = new char[filesize + MAX_PATH * sizeof(wchar_t)];
			myencrypt((unsigned char*)buffer, (unsigned char*)encrypted, filesize + MAX_PATH * sizeof(wchar_t));
			UpdateResource(pRes, RT_RCDATA, MAKEINTRESOURCE(ret), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), encrypted, filesize + MAX_PATH * sizeof(wchar_t));
			delete[] encrypted;
		}
		else
			retn = false;
		delete[] buffer;
		fclose(fp);
	}
	else
		retn = false;
	return retn;
}

void ImportResourceIfExists(HANDLE hRes, const CString& filePath, const wchar_t* resourceName, const wchar_t* commandStr, int resourceId)
{
	if (!_waccess(filePath, 00))
	{
		wchar_t filename[MAX_PATH];
		wcscpy_s(filename, MAX_PATH, resourceName);
		if (!ImportResource(hRes, filePath, filename, commandStr, resourceId))
		{
			printf("Error importing resource: %s\n", resourceName);
		}
	}
	else
	{
		printf("File does not exist: %d\n", resourceId);
	}
}


int main(int argc, char* argv[]) {

	/*const wchar_t* m_x64Str = GetMyPath() + _T("\\Client\\ClientSearch_x64.exe");
	const wchar_t* m_x86Str = GetMyPath() + _T("\\Client\\ClientSearch_x86.exe");*/
	if (argc < 3) {
		std::cout << "usage: ./generate_onlinesearch.exe IP Port DetectPort\n";
		return 1;
	}

	std::remove("ClientSearch_x64.exe");
	const wchar_t* oldFileName = L"Agent_VS2019.exe";
	const wchar_t* newFileName = L"ClientSearch_x64.exe";
	if (MoveFile(oldFileName, newFileName)) {
		std::wcout << "File renamed successfully." << std::endl;
	}
	else {
		std::wcerr << "Error renaming file. Error code: " << GetLastError() << std::endl;
	}

	CString basePath = _T("C:\\james\\eDetectorWindowsAgent_VS2019");
	CString cstr_m_x64Str = basePath + _T("\\ClientSearch_x64.exe");
	wchar_t* m_x64Str = cstr_m_x64Str.GetBuffer();

	CString m_CommandStr;
	CString m_CommandStr1;
	CString strIP(argv[1]);
	//m_ServerIP.GetWindowText(strIP);
	//m_GInfo.m_IP = strIP;

	CString strPort;
	strPort.Format(L"%u", std::atoi(argv[2]));
	//printf("%u\n", std::atoi(argv[2]));
	//strPort.Format(L"%u", m_ServerPort);
	//m_GInfo.m_Port = strPort;

	CString strDetectPort(argv[3]);
	strDetectPort.Format(L"%u", std::atoi(argv[3]));
	//printf("%u\n", std::atoi(argv[3]));
	//strDetectPort.Format(L"%u", m_DetectPort);
	//m_GInfo.m_DetectPort = strDetectPort;

	CString KillStr = _T("null");

	CTime m_Date;
	CTime m_Time;
	//CTime m_KillDateTime = CTime(m_Date.GetYear(), m_Date.GetMonth(), m_Date.GetDay(), m_Time.GetHour(), m_Time.GetMinute(), m_Time.GetSecond());
	//time_t KillBinaryTime = m_KillDateTime.GetTime();
	//KillStr.Format(_T("%lld"), KillBinaryTime);

	//m_CommandStr.Format(_T("%s %s %s %s 24680"), strIP, strPort, strDetectPort, KillStr);

	//m_CommandStr.Format(_T("%s %s %s %s 24680"), strIP, strPort, strDetectPort, KillStr);
	m_CommandStr.Format(_T("%s %s"), strIP, strPort);

	CString StartClinetNum = _T("24680");
	m_CommandStr1.Format(_T("/install %s %s %s %s %s"), strIP, strPort, strDetectPort, KillStr, StartClinetNum);


	CString m_SavePath = basePath + _T("\\x64\\Debug\\Agent.exe");
	CString StubPath;
	//StubPath = L"\\Shellnd.exe";
	StubPath = basePath + "\\Shellnd.exe";
	if (_waccess(StubPath.GetString(), 00))
	{
		printf("no shell.exe\n");
		return 0;
	}


	if (CopyFile(StubPath, m_SavePath, false))
	{
		HANDLE hRes = BeginUpdateResource(m_SavePath, false);
		if (hRes != NULL)
		{
			wchar_t* filename = new wchar_t[MAX_PATH];

			ResourceInfo resources[] = {
				{ basePath + _T("\\x64\\Debug\\ClientSearch_x64.exe"), L"ClientSearch-x64.exe", m_CommandStr, 1 },
				//{ basePath + _T("\\Agent_VS2019.exe"), L"Agent_VS2019.exe", m_CommandStr, 1 },
				{ basePath + _T("\\MemoryPattern\\Detectdriver.sys"), L"Detectdriver.sys", L"null", 3 },
				{ basePath + _T("\\Detector\\Collection-x64.dll"), L"Collection-x64.dll", L"null", 4 },
				{ basePath + _T("\\eDetectorobject\\ClientSearchTools\\EnumProcess.sys"), L"EnumProcess.sys", L"null", 5 },
				{ basePath + _T("\\eDetectorobject\\WhiteList\\WhiteList-x64.dll"), L"WhiteList-x64.dll", L"null", 6 },
				{ basePath + _T("\\eDetectorobject\\WhiteList\\WhiteList-x86.dll"), L"WhiteList-x86.dll", L"null", 7 },
				{ basePath + _T("\\iForensicsService.exe"), L"iForensicsService.exe", m_CommandStr1, 8 },
				{ basePath + _T("\\Detector\\Collection-x86.dll"), L"Collection-x86.dll", L"null", 9 },

				{ basePath + _T("\\dll\\x86\\api-ms-win-core-heap-l1-1-0.dll"), L"api-ms-win-core-heap-l1-1-0.dll", L"null", 11 },
				{ basePath + _T("\\dll\\x86\\api-ms-win-crt-convert-l1-1-0.dll"), L"api-ms-win-crt-convert-l1-1-0.dll", L"null", 12 },
				{ basePath + _T("\\dll\\x86\\api-ms-win-crt-heap-l1-1-0.dll"), L"api-ms-win-crt-heap-l1-1-0.dll", L"null", 13 },
				{ basePath + _T("\\dll\\x86\\api-ms-win-crt-locale-l1-1-0.dll"), L"api-ms-win-crt-locale-l1-1-0.dll", L"null", 14 },
				{ basePath + _T("\\dll\\x86\\api-ms-win-crt-math-l1-1-0.dll"), L"api-ms-win-crt-math-l1-1-0.dll", L"null", 15 },
				{ basePath + _T("\\dll\\x86\\api-ms-win-crt-private-l1-1-0.dll"), L"api-ms-win-crt-private-l1-1-0.dll", L"null", 16 },
				{ basePath + _T("\\dll\\x86\\api-ms-win-crt-runtime-l1-1-0.dll"), L"api-ms-win-crt-runtime-l1-1-0.dll", L"null", 17 },
				{ basePath + _T("\\dll\\x86\\api-ms-win-crt-stdio-l1-1-0.dll"), L"api-ms-win-crt-stdio-l1-1-0.dll", L"null", 18 },
				{ basePath + _T("\\dll\\x86\\api-ms-win-crt-string-l1-1-0.dll"), L"api-ms-win-crt-string-l1-1-0.dll", L"null", 19 },
				{ basePath + _T("\\dll\\x86\\concrt140.dll"), L"concrt140.dll", L"null", 20 },
				{ basePath + _T("\\dll\\x86\\msvcp_win.dll"), L"msvcp_win.dll", L"null", 20 },
				{ basePath + _T("\\dll\\x86\\msvcp140.dll"), L"msvcp140.dll", L"null", 22 },
				{ basePath + _T("\\dll\\x86\\msvcp140_1.dll"), L"msvcp140_1.dll", L"null", 23 },
				{ basePath + _T("\\dll\\x86\\msvcrt.dll"), L"msvcrt.dll", L"null", 24 },
				{ basePath + _T("\\dll\\x86\\ucrtbase.dll"), L"ucrtbase.dll", L"null", 25 },
				{ basePath + _T("\\dll\\x86\\vcruntime140.dll"), L"vcruntime140.dll", L"null", 26 },
				{ basePath + _T("\\dll\\x86\\wlanapi.dll"), L"wlanapi.dll", L"null", 27 },

				{ basePath + _T("\\dll\\x64\\api-ms-win-core-heap-l1-1-0.dll"), L"api-ms-win-core-heap-l1-1-0.dll", L"null", 28 },
				{ basePath + _T("\\dll\\x64\\api-ms-win-crt-convert-l1-1-0.dll"), L"api-ms-win-crt-convert-l1-1-0.dll", L"null", 29 },
				{ basePath + _T("\\dll\\x64\\api-ms-win-crt-heap-l1-1-0.dll"), L"api-ms-win-crt-heap-l1-1-0.dll", L"null", 30 },
				{ basePath + _T("\\dll\\x64\\api-ms-win-crt-locale-l1-1-0.dll"), L"api-ms-win-crt-locale-l1-1-0.dll", L"null", 31 },
				{ basePath + _T("\\dll\\x64\\api-ms-win-crt-math-l1-1-0.dll"), L"api-ms-win-crt-math-l1-1-0.dll", L"null", 32 },
				{ basePath + _T("\\dll\\x64\\api-ms-win-crt-private-l1-1-0.dll"), L"api-ms-win-crt-private-l1-1-0.dll", L"null", 33 },
				{ basePath + _T("\\dll\\x64\\api-ms-win-crt-runtime-l1-1-0.dll"), L"api-ms-win-crt-runtime-l1-1-0.dll", L"null", 34 },
				{ basePath + _T("\\dll\\x64\\api-ms-win-crt-stdio-l1-1-0.dll"), L"api-ms-win-crt-stdio-l1-1-0.dll", L"null", 35 },
				{ basePath + _T("\\dll\\x64\\api-ms-win-crt-string-l1-1-0.dll"), L"api-ms-win-crt-string-l1-1-0.dll", L"null", 36 },
				{ basePath + _T("\\dll\\x64\\concrt140.dll"), L"concrt140.dll", L"null", 37 },
				{ basePath + _T("\\dll\\x64\\msvcp_win.dll"), L"msvcp_win.dll", L"null", 38 },
				{ basePath + _T("\\dll\\x64\\msvcp140.dll"), L"msvcp140.dll", L"null", 39 },
				{ basePath + _T("\\dll\\x64\\msvcp140_1.dll"), L"msvcp140_1.dll", L"null", 40 },
				{ basePath + _T("\\dll\\x64\\msvcrt.dll"), L"msvcrt.dll", L"null", 41 },
				{ basePath + _T("\\dll\\x64\\ucrtbase.dll"), L"ucrtbase.dll", L"null", 42 },
				{ basePath + _T("\\dll\\x64\\vcruntime140.dll"), L"vcruntime140.dll", L"null", 43 },
				{ basePath + _T("\\dll\\x64\\wlanapi.dll"), L"wlanapi.dll", L"null", 44 },
				{ basePath + _T("\\dll\\x64\\api-ms-win-core-heap-l2-1-0.dll"), L"api-ms-win-core-heap-l2-1-0.dll", L"null", 45 }

			};

			for (const auto& resource : resources)
			{
				ImportResourceIfExists(hRes, resource.path, resource.filename, resource.commandStr, resource.index);
			}

			delete[] filename;
			EndUpdateResource(hRes, false);

			// Detectdriver.sys : Cover Driver To Agent
			// EnumProcess.sys : Cover EnumProcess To Agent
			// WhiteList-x64.dll : Cover WhiteList To Agent
			// WhiteList-x86.dll : Cover WhiteList To Agent
			// iForensicsService.exe : Cover iForensicsService To Agent
			// Collection-x86.dll : Cover Collection-x86 To Agent
			// Cover Predefine.config To Agent { basePath + _T("\\predefine.config"), L"predefine.config", L"null", 10 }, -> haven't been put into the program, It can keep working even if predefine.config doesn't exist
			// api-ms-win-core-heap-l1-1-0.dll : Cover api-ms-win-core-heap-l1-1-0 To Agent
			// api-ms-win-crt-convert-l1-1-0.dll : Cover api-ms-win-crt-convert-l1-1-0 To Agent
			// api-ms-win-crt-heap-l1-1-0.dll : Cover api-ms-win-crt-heap-l1-1-0 To Agent
			// api-ms-win-crt-locale-l1-1-0.dll : Cover api-ms-win-crt-locale-l1-1-0 To Agent
			// api-ms-win-crt-math-l1-1-0.dll : Cover api-ms-win-crt-math-l1-1-0 To Agent
			// api-ms-win-crt-private-l1-1-0.dll : Cover api-ms-win-crt-private-l1-1-0 To Agent
			// api-ms-win-crt-runtime-l1-1-0.dll : Cover api-ms-win-crt-runtime-l1-1-0 To Agent
			// api-ms-win-crt-stdio-l1-1-0.dll : Cover api-ms-win-crt-stdio-l1-1-0 To Agent
			// api-ms-win-crt-string-l1-1-0.dll : Cover api-ms-win-crt-string-l1-1-0 To Agent
			// concrt140.dll : Cover concrt140 To Agent
			// msvcp_win.dll : Cover msvcp_win To Agent
			// msvcp140.dll : Cover msvcp140 To Agent
			// msvcp140_1.dll : Cover msvcp140_1 To Agent
			// msvcrt.dll : Cover msvcrt To Agent
			// ucrtbase.dll : Cover ucrtbase To Agent
			// vcruntime140.dll : Cover vcruntime140 To Agent
			// wlanapi.dll : Cover wlanapi To Agent
			// api-ms-win-core-heap-l1-1-0.dll : Cover api-ms-win-core-heap-l1-1-0 To Agent
			// api-ms-win-crt-convert-l1-1-0.dll : Cover api-ms-win-crt-convert-l1-1-0 To Agent
			// api-ms-win-crt-heap-l1-1-0.dll : Cover api-ms-win-crt-heap-l1-1-0 To Agent
			// api-ms-win-crt-locale-l1-1-0.dll : Cover api-ms-win-crt-locale-l1-1-0 To AgentEndUpdateResource
			// api-ms-win-crt-math-l1-1-0.dll : Cover api-ms-win-crt-math-l1-1-0 To Agent
			// api-ms-win-crt-private-l1-1-0.dll : Cover api-ms-win-crt-private-l1-1-0 To Agent
			//api-ms-win-crt-runtime-l1-1-0.dll : Cover api-ms-win-crt-runtime-l1-1-0 To Agent
			// api-ms-win-crt-stdio-l1-1-0.dll : Cover api-ms-win-crt-stdio-l1-1-0 To Agent
			// api-ms-win-crt-string-l1-1-0.dll : Cover api-ms-win-crt-string-l1-1-0 To Agent
			// concrt140.dll : Cover concrt140 To Agent
			// msvcp_win.dll : Cover msvcp_win To Agent
			// msvcp140.dll : Cover msvcp140 To Agent
			// msvcp140_1.dll : Cover msvcp140_1 To Agent
			// msvcrt.dll : Cover msvcrt To Agent
			// ucrtbase.dll : Cover ucrtbase To Agent
			// vcruntime140.dll : Cover vcruntime140 To Agent
			// wlanapi.dll : Cover wlanapi To Agent
			// api-ms-win-core-heap-l2-1-0.dll : Cover api-ms-win-core-heap-l2-1-0 To Agent


		}
	}
	else printf("copy fail\n");

	return 0;
}

