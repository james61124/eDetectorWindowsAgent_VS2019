#ifndef TOOLS_H
#define TOOLS_H

#include <vector>
#include <string>
#include <cstring>
#include <Windows.h>
#include <codecvt>
#include <lmcons.h>
#include <memory>
#include <iostream>
#include <set>
#include <map>

#include <Ntstatus.h>
#include <winternl.h>  
#include <Psapi.h> 
#include <tchar.h>
#include <Sddl.h>
#include <Shobjidl.h>
#include <wintrust.h>
#include <dbghelp.h>
#include <Iphlpapi.h>
#include <ctime>   // For std::time
#include <cwchar>  // For std::wcsftime

#include <fstream>

#include "zip.h"

// #include "StrPacket.h"
//#include "Process.h"
// #include "PeFunction.h"





typedef void (WINAPI* PGNSI)(LPSYSTEM_INFO);

class Tool {
public:

    std::vector<std::string> SplitMsg(char* msg);
    time_t FileTimeToUnixTime(const FILETIME& ft);

    char* StringToCharPointer(std::string msg);
    char* CStringToCharArray(wchar_t* str, UINT m_CodePage);
    char* WideStringToUTF8(const std::wstring& wideString);
    void DeleteAllCsvFiles(wchar_t* directoryPath);

    // Get System Info
    char* GetSysInfo();
    char* GetComputerNameUTF8();
    char* GetUserNameUTF8();
    char* GetOSVersion();
    unsigned long long GetBootTime();
    bool CompressFileToZip(const TCHAR* zipFileName, const TCHAR* fileToAdd, const TCHAR* sourceFilePath);

    // Process

    void LoadApiPattern(std::set<DWORD>* pApiName);
    //void ScanRunNowProcess(void* argv, std::map<DWORD, ProcessInfoData>* pInfo, std::set<DWORD>* pApiName, std::vector<UnKnownDataInfo>* pMembuf);
    //void GetTcpInformationEx(std::vector<TCPInformation>* pInfo);
    //int CheckIsStartRun(std::map<std::wstring, BOOL>* pService, std::set<std::wstring>* pStartRun, DWORD pid/*,BOOL & isServiceHide*/);
    //void CheckIsInlineHook(DWORD pid, std::set<std::string>* pInlineHook);
    //bool GetDigitalSignature(wchar_t* m_Path, DigitalSignatureInfo* pInfo);
    //BOOL PrintCertificateInfo(PCCERT_CONTEXT pCertContext, DigitalSignatureInfo* pInfo, wchar_t* pType);
    //BOOL GetProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo, PSPROG_PUBLISHERINFO Info);
    //BOOL GetTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO* pCounterSignerInfo);
    //BOOL GetDateOfTimeStamp(PCMSG_SIGNER_INFO pSignerInfo, SYSTEMTIME* st);
    //void CheckInjectionPtn(std::set<DWORD>* pStringsHash, BOOL& pIsOther, BOOL& pIsPE);
    //void FindFunctionAddress32(wchar_t* file_path, BYTE* pModBaseAddr, HANDLE pProcess, std::set<std::string>* pInlineHook);
    //void FindFunctionAddress(wchar_t* file_path, BYTE* pModBaseAddr, HANDLE pProcess, std::set<std::string>* pInlineHook);
    //void _clean_things(HANDLE hFile, HANDLE hMapping, PBYTE pFile, const char* pErrorMessage);
    //void SearchExecutePath(DWORD pid, wchar_t* pPath, wchar_t* pName);
    //void GetProcessPath(DWORD pid, wchar_t* pPath, bool IsGetTime, wchar_t* pTimeStr, wchar_t* pCTimeStr);
    //int CheckIsInjection(DWORD pid, std::vector<UnKnownDataInfo>* pMembuf, wchar_t* pProcessName, wchar_t* pUnKnownHash);
    //int GetProcessMappedFileName(HANDLE ProcessHandle, PVOID BaseAddress, wchar_t* FileName);
    //BOOL IsPESignature(BYTE* buffer, unsigned int buflen);
    //bool PeUnmapper(BYTE* buffer, size_t pSize, ULONGLONG loadBase, UnKnownDataInfo* pInfo);
    //void GetUnKnownHash(BYTE* pBuffer, SIZE_T pBufferSize, wchar_t* pUnKnownHash, SIZE_T ptype);
    //void ParserUnknownIAT(BYTE* pBuffer, wchar_t* pUnKnownHash);
    //void ParserUnknownIAT32(BYTE* pBuffer, wchar_t* pUnKnownHash);
    //DWORD Md5StringHash(char* SourceStr, wchar_t* HashStr);
    //DWORD Process32or64(HANDLE hProcess);
    //LPWSTR AllocateAndCopyWideString(LPCWSTR inputString);
    //BOOL DumpExecute(DWORD pid, wchar_t* pName, std::set<DWORD>* pApiBace, std::set<DWORD>* pStr, wchar_t* pProcessPath, std::set<std::string>* pIsAbnormal_dll);
    //void LoadBinaryStringsHash(BYTE* buf, DWORD pSize, std::set<DWORD>* pStrSet);
    //void CheckModulePath(wchar_t* pProcessPath, wchar_t* pModulePath, std::set<std::string>* pIsAbnormal_dll);
    //void LoadNowProcessInfo(std::map<DWORD, process_info_Ex>* pInfo);
    //BOOL IsWindowsProcessNormal(std::map<DWORD, process_info_Ex>* pInfo, DWORD pid);
    //BOOL CheckParentProcessNormal(std::map<DWORD, process_info_Ex>* pInfo, DWORD parentid, wchar_t* process_name, time_t pCreateTime);
    //BOOL CheckPathMatch(process_info_Ex* pInfo);
    //BOOL CheckSIDMatch(process_info_Ex* pInfo);
    //bool EnumProcessEx(std::map<DWORD, process_info_Ex>* pInfo);
    //void GetProcessInfo(DWORD pid, wchar_t* pPath, wchar_t* pTimeStr, wchar_t* pUserName, wchar_t* pComStr);
    //DWORD GetRemoteCommandLineW(HANDLE hProcess, LPWSTR pszBuffer, UINT bufferLength);
    //void GetUserSID(HANDLE hProcess, wchar_t* szUserSID);
    //void LoadServiceStartCommand(std::map<std::wstring, BOOL>* pImagePath);
    //void GetThisPCAllUser(std::vector<std::wstring>* wtr);
    //BOOL GetUserStartUp(wchar_t* pUserName, wchar_t* pDirectory, wchar_t* pPath);
    //void LoadRegHistorySubKeys(HKEY pKey, wchar_t* pPath, std::vector<std::wstring>* wtr);
    //void LoadAutoRunStartCommand(std::set<std::wstring>* pImagePath);
    //void LoadRegisterAutoRun(std::vector<AutoRunInfo>* pInfo);
    //void LoadRegisterInfoEx(std::vector<AutoRunInfo>* pInfo, HKEY pKey, wchar_t* RegPath, wchar_t* KeyStr, bool IsChildItem, bool Is32Bit);
    //void LoadRegisterChildItem(std::vector<std::wstring>* pStrInfo, HKEY pKey, wchar_t* RegPath, bool Is32Bit);
    //void LoadRegisterDataEx(std::vector<AutoRunInfo>* pInfo, HKEY pKey, wchar_t* RegPath, wchar_t* KeyStr, bool Is32Bit);
    //void LoadInstallService(std::map<std::wstring, SerivceInformation>* pServiceMap);
    //void DoQuerySvc(SerivceInformation* pInfo);
    //bool GetRegHistoryREG_SZValue(HKEY pKey, wchar_t* pPath, wchar_t* pName, DWORD pType, wchar_t* pValue);
    //bool GetRegHistoryREG_DWORDValue(HKEY pKey, wchar_t* pPath, wchar_t* pName, DWORD& pValue);
    //BOOL GetAllUserStartUp(wchar_t* wtr);
    //void SearchAutoRunFile(std::vector<AutoRunInfo>* pInfo, wchar_t* m_Path);
    //void ParsingStartupFile(std::vector<AutoRunInfo>* pInfo, wchar_t* m_Path, wchar_t* m_Name);
    //HRESULT ResolveIt(HWND hwnd, wchar_t* lpszLinkFile, wchar_t* lpszPath, int iPathBufferSize);
    //void LoadRegisterAutoRunFromUser(std::vector<AutoRunInfo>* pInfo, wchar_t* pUserName);
    //bool CheckDigitalSignature(wchar_t* m_Path);
    //void LoadRegisterInfo(std::vector<AutoRunInfo>* pInfo, HKEY pKey, wchar_t* RegPath);
    //void QueryKey(HKEY hKey, std::vector<std::wstring>* pSub);
    //void LoadRegisterInfox32(std::vector<AutoRunInfo>* pInfo, HKEY pKey, wchar_t* RegPath);
    //time_t filetime_to_timet(const FILETIME& ft);
    //DWORD Md5Hash(wchar_t* FileName, wchar_t* HashStr/*,size_t HashStrlen*/);
    //BOOL CheckIsPackedPE(wchar_t* pPath);
    //BOOL IsPackedSignature(BYTE* buffer, unsigned int buflen);


    // BYTE* pe_virtual_to_raw(BYTE* payload, size_t in_size, ULONGLONG loadBase, size_t &out_size, bool rebuffer);
    // ALIGNED_BUF alloc_pe_buffer(size_t buffer_size, DWORD protect, ULONGLONG desired_base);
    // ALIGNED_BUF alloc_aligned(size_t buffer_size, DWORD protect, ULONGLONG desired_base);
    // ULONGLONG get_image_base(const BYTE *pe_buffer);
    // bool is64bit(const BYTE *pe_buffer);
    // WORD get_nt_hdr_architecture(const BYTE *pe_buffer);
    // BYTE* get_nt_hrds(const BYTE *pe_buffer, size_t buffer_size);
    // bool validate_ptr(const LPVOID buffer_bgn, SIZE_T buffer_size, const LPVOID field_bgn, SIZE_T field_size);
    // bool relocate_module(BYTE* modulePtr, SIZE_T moduleSize, ULONGLONG newBase, ULONGLONG oldBase);
    // bool apply_relocations(PVOID modulePtr, SIZE_T moduleSize, ULONGLONG newBase, ULONGLONG oldBase);
    // IMAGE_DATA_DIRECTORY* get_directory_entry(const BYTE *pe_buffer, DWORD dir_id);

    const char* WideCharToConstChar(const wchar_t* wideString);
    LPCSTR WideCharToLPCWSTR(wchar_t* wideString);
    wchar_t* CharPtrToWideCharPtr(char* multiByteString);
    char* Convert2State(DWORD dwState);
    bool SetRegistryValue(const wchar_t* valueName, const wchar_t* valueData);
    std::wstring GetRegistryValue(const wchar_t* valueName);

    // void GetFileVersion(const char* FilePath, std::string& pVersion);
};


#endif