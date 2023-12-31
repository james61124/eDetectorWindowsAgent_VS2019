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
        //printf("token %s\n", token);
        MsgAfterSplit.push_back(token);

        // Check if the next token is empty
        if (nextToken != nullptr && *nextToken == '|') {
            MsgAfterSplit.push_back(""); // Generate an empty string
        }

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

bool Tool::CompressFileToZip(const TCHAR* zipFileName, const TCHAR* sourceFilePath) {
    HZIP hz = CreateZip(zipFileName, 0);
    if (hz == 0) {
        printf("Failed to create ZIP file\n");
        return false; // Failed to create ZIP file
    }

    //TCHAR* ZipDir = new TCHAR[MAX_PATH];
    //GetMyPath(ZipDir);
    //TCHAR* szPath = new TCHAR[_MAX_PATH];
    //swprintf_s(szPath, _MAX_PATH, L"%s\\%s", ZipDir, sourceFilePath);

    if (ZipAdd(hz, sourceFilePath, sourceFilePath) != 0) {
        printf("Failed to add file to ZIP\n");
        CloseZip(hz);
        return false; // Failed to add file to ZIP
    }

    CloseZip(hz);
    return true; // Successfully compressed and added file to ZIP


}



wstring Tool::GetFileName() {
    TCHAR moduleName[MAX_PATH];
    GetModuleFileName(NULL, moduleName, MAX_PATH);

    std::wstring moduleNameStr(moduleName);
    size_t lastSlash = moduleNameStr.find_last_of(L"\\");
    std::wstring fileName;
    if (lastSlash != std::wstring::npos) {
        fileName = moduleNameStr.substr(lastSlash + 1);
        std::wcout << "Current executable filename: " << fileName << std::endl;
    }
    else {
        std::wcerr << "Unable to extract filename." << std::endl;
    }
    return fileName;
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





