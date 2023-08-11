#pragma once
#ifndef GLOBALFUNCTION_H
#define GLOBALFUNCTION_H
#include <Windows.h>
#include <Wintrust.h>
#include <Shellapi.h>
#include <Shobjidl.h>
#include <ShlGuid.h>

#include <map>
#include <set>
#include <vector>
#include <string>
#include <cstring>
#include <wincrypt.h>
#include <winsock2.h>
#include <tchar.h>

#include <Iphlpapi.h>


#include "Process.h"
#include "PeFunction.h"

using namespace std;
#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

#pragma comment(lib, "iphlpapi.lib")

//typedef struct {
//	LPWSTR lpszProgramName;
//	LPWSTR lpszPublisherLink;
//	LPWSTR lpszMoreInfoLink;
//} SPROG_PUBLISHERINFO, * PSPROG_PUBLISHERINFO;
struct NetworkCards
{
	char Description[512];
	char ServiceName[512];
	char MAC[20];
	char IP[20];
};
char* wcharTochar(wchar_t* WStr);
wchar_t* charTowchar(char* CStr);
wchar_t* CharArrayToWString(char* CStr, UINT m_CodePage);
char* CStringToCharArray(wchar_t* str, UINT m_CodePage);
bool GetMacByGetAdaptersInfo(char* MACstr, unsigned int StrSize);
void GetThisIP(char* Ipstr, unsigned int StrSize);//取得內部IP
void RunProcess(TCHAR* AppName, TCHAR* CmdLine, BOOL isWait, BOOL isShow);
bool RunProcessEx(TCHAR* AppName, TCHAR* CmdLine, size_t CmdLineLen, BOOL isWait, BOOL isShow, DWORD& pid, int m_TimeOut = 0);
bool dirExists(wchar_t* dirPath);
int MatchFileName(const _TCHAR* string, const _TCHAR* wild);
bool MatchKeyword(TCHAR* pKeywordStr, TCHAR* NameStr);
char* GetSysInfo();
char* GetDriveStr(int num);
int FindPID(wchar_t* processname);
bool FindThisPID(wchar_t* processname, DWORD pid);
int GetPIDCount(wchar_t* processname);
char* GetOSVersion();
//unsigned int GetDriveFormatNumW(wchar_t* formatStr);
//unsigned int GetDriveFormatNumA(char* formatStr);
DWORD Md5Hash(TCHAR* FileName, TCHAR* HashStr/*,size_t HashStrlen*/);
BOOL ReceiveTempData(BYTE* pTmpBuffer, long& pTmpSize, BYTE* RecvBuffer, long Recvlen, long DataSize);
time_t filetime_to_timet(const FILETIME& ft);
BOOL EnableDebugPrivilege(BOOL fEnable);
BOOL IsPESignature(BYTE* buffer, unsigned int buflen);
BOOL IsPEExt(TCHAR* FileName);
DWORD Md5HashAndSignature(TCHAR* FileName, TCHAR* HashStr, size_t HashStrlen, BOOL& IsSignature);
BOOL GetIPAndMAC(char* pMAC, char* pIP, char* ServerIP);
void QueryKey(HKEY hKey, vector<wstring>* pSub);
//void RegisterInfo(vector<NetworkCards> *pInfo,TCHAR * RegPath);
//BOOL Searchphysicaladdresses(vector<NetworkCards> *pInfo);
void IPtoken(char* IPstr, int& IP1, int& IP2, int& IP3, int& IP4);
//bool IsWin2000();
void FolderClear(TCHAR* FilePath, TCHAR* Extstr);
DWORD CmdCommandWork(wchar_t* COMstr, bool IsWait, unsigned int pSec = 0);
bool memfind(BYTE* Sce, char* ApiStr, int scelen);
char* Convert2State(DWORD dwState);
void GetTcpInformation(vector<string>* pInfo, DWORD Processid);
void GetTcpInformationXP(vector<string>* pInfo, DWORD Processid);
DWORD Md5HashAndData(TCHAR* FileName, TCHAR* HashStr, vector<BYTE>* pbuf);
bool GetDigitalSignature(TCHAR* m_Path, DigitalSignatureInfo* pInfo);
BOOL GetProgAndPublisherInfo(PCMSG_SIGNER_INFO pSignerInfo, PSPROG_PUBLISHERINFO Info);
LPWSTR AllocateAndCopyWideString(LPCWSTR inputString);
BOOL GetDateOfTimeStamp(PCMSG_SIGNER_INFO pSignerInfo, SYSTEMTIME* st);
BOOL PrintCertificateInfo(PCCERT_CONTEXT pCertContext, DigitalSignatureInfo* pInfo, const wchar_t* pType);
BOOL GetTimeStampSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO* pCounterSignerInfo);
void GetTcpInformationEx(vector<TCPInformation>* pInfo);
void GetTcpInformationXPEx(vector<TCPInformation>* pInfo);
void GetMyPath(wchar_t* wtr);
void GetMyPathA(char* str);
DWORD Md5StringHash(char* SourceStr, TCHAR* HashStr);
void DeleteExt(TCHAR* str);
void DeleteSys(TCHAR* str);
void ClearMyFolderOtherFile();
void LoadRegHistorySubKeys(HKEY pKey, const wchar_t* pPath, vector<wstring>* wtr);
bool GetRegHistoryREG_DWORDValue(HKEY pKey, const wchar_t* pPath, const wchar_t* pName, DWORD& pValue);
bool GetRegHistoryREG_SZValue(HKEY pKey, const wchar_t* pPath, const wchar_t* pName, DWORD pType, TCHAR* pValue);
HRESULT ResolveIt(HWND hwnd, TCHAR* lpszLinkFile, TCHAR* lpszPath, int iPathBufferSize);
void DeleteUpdateFile();
BOOL CheckIsPackedPE(TCHAR* pPath);
BOOL IsPackedSignature(BYTE* buffer, unsigned int buflen);
bool IsHavePID(int pid);
void GetDetectTcpInformation(map<wstring, u_short>* pInfo, set<u_short>* pLintenPort);
void GetDetectTcpInformationXP(map<wstring, u_short>* pInfo, set<u_short>* pLintenPort);
PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName);
bool replace(std::wstring& str, const std::wstring& from, const std::wstring& to);
int impuser(TCHAR* processPathName, TCHAR* cmdline, DWORD Pid, DWORD& StartProcessPid, BOOL isWait, int m_TimeOut = 0);
void StartUserModeCommandProcess(TCHAR* RunExeStr, TCHAR* RunComStr, DWORD& pid);
int StartUserModeProcessFromPid(TCHAR* RunExeStr, TCHAR* RunComStr, DWORD pid, int pTimeOut);
int IsSystemProcess(DWORD pid);
void GetUserSID(HANDLE hProcess, TCHAR* szUserSID);
void GetlocalExePath(const wchar_t* ExeName, LPWSTR str);
void GetFileVersion(TCHAR* FilePath, char* pVersion);
int CheckVirtualMachineDrive();
int VirtualMachine(char* pMAC);
//BOOL MySystemShutdown();
//void WriteLogFile(TCHAR* m_Path, char* Str);
//BOOL LoadNTDriver(char* lpszDriverName, char* lpszDriverPath);
//BOOL UnloadNTDriver(char* szSvrName);
void GetThisClientKey(char* pKeyStr);
bool CheckRightKey(char* pKeyStr);
bool OtherHashch(char ch);
void WriteRegisterValue(char* pKeyStr);
void LoadBinaryStringsHash(BYTE* buf, DWORD pSize, set<DWORD>* pStrSet);
DWORD GetDigitalSignatureHash();
void ParserConfigLog(char* str, char* strA, char* strB);
bool CheckDigitalSignature(TCHAR* m_Path);
void SetProcessPriority(TCHAR* m_Path);
//void ErrorLog(char * Str);
wstring GetMyTempPath(TCHAR* pdnPathName);


#endif