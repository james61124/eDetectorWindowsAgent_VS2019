#pragma once
//#include <Subauth.h>
//#include <Winternl.h>
#include <Windows.h>
#include <sddl.h>

#include <map>

#pragma comment(lib, "kernel32.lib")

#include "AutoRun.h"
#include "PeFunction.h"

using namespace std;

#if defined _M_X64
#pragma comment(lib,"ntdll.lib")
#elif defined _M_IX86
typedef NTSTATUS(NTAPI* pZwQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
#define GetServiceNumber(Function)(*(PULONG)((PUCHAR)Function+1));
#define IOCTL_TYPE 40000
//#define IOCTL_GET_ENUM_PROCESS \
//    CTL_CODE( IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define IOCTL_RECOVERY_SERVICE_TABLE \
    CTL_CODE( IOCTL_TYPE, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS  )
#define IOCTL_RESTORE_SERVICE_TABLE \
    CTL_CODE( IOCTL_TYPE, 0x902, METHOD_BUFFERED , FILE_ANY_ACCESS  )
#endif
#define MemoryMappedFilenameInformation 2
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)


//typedef struct _SYSTEM_PROCESS_INFO
//{
//	ULONG                   NextEntryOffset;
//	ULONG                   NumberOfThreads;
//	LARGE_INTEGER           Reserved[3];
//	LARGE_INTEGER           CreateTime;
//	LARGE_INTEGER           UserTime;
//	LARGE_INTEGER           KernelTime;
//	UNICODE_STRING          ImageName;
//	ULONG                   BasePriority;
//	HANDLE                  ProcessId;
//	HANDLE                  InheritedFromProcessId;
//}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

typedef struct
{
	int MainPid;
	bool* isEnding;
	void* pClass;
}ThreadInfo;
//typedef struct 
//{
//	DWORD ProcessID;
//	DWORD ParentID;
//	wchar_t ProcessName[MAX_PATH];
//	time_t ProcessCreateTime;
//}EnumProcessInfo;
class MemProcess
{
public:
	MemProcess();
	virtual ~MemProcess();
	void enumallprocess(void* argv, char* pMAC, char* pIP);
	BOOL CheckHaveProcess(wchar_t* ProcessName, int PID);
	//int GetProcessExecute(void* argv, DumpMemoryInfo* pInfo);
#ifndef _M_IX86
	DWORD Process32or64(HANDLE hProcess);
#endif
	//int ProcessDump(void* argv, DumpMemoryInfo* pInfo);
	//int OnlyProcessDump(void* argv, char* WorkStr, OnlyMemoryInfo* pInfo);
	void LoadingProcessID(map<DWORD, process_info>* pPID);
	//void DetectNewProcess(void *argv,set<string>* pApiBace);
	//void GetProcessCreateTime(DWORD pid,char * pTimeStr);
	void LoadNowProcessInfo(map<DWORD, process_info_Ex>* pInfo);
	void LoadNowProcessInfoDetect(map<DWORD, process_info_Ex>* pInfo);
	void ScanRunNowProcess(void* argv, map<DWORD, ProcessInfoData>* pInfo, set<DWORD>* pApiName, vector<UnKnownDataInfo>* pMembuf);

	//int ScanInjectedProcessDump(void* argv, ScanMemoryInfo* pInfo);
	//int ScanInjectedProcessDumpEx(void* argv, ScanMemoryInfo* pInfo);
	void DetectNewOpenProcess(void* argv, int pMainProcessid, TCHAR* pBootTime, bool IsFirst);
	void DetectNewOpenProcessInfo(void* argv, int pMainProcessid, TCHAR* pBootTime, bool IsFirst);
	void DetectNewNetwork(void* argv, int pMainProcessid, TCHAR* pBootTime);
	void DetectAccessFiles(void* argv, int pMainProcessid, TCHAR* pBootTime, bool UserMode);
	void AccessFilesUserMode(DWORD MainPid, DWORD ParentPid);
	void DetectProcessRisk(void* argv, int pMainProcessid, TCHAR* pBootTime, bool IsFirst, set<DWORD>* pApiName);
	vector<string>* pProcessHistory;
	int ProcessHistoryNum;
	vector<string>* pProcessHistoryInfo;
	int ProcessHistoryInfoNum;
	vector<string>* pNetworkHistory;
	int NetworkHistoryNum;
	set<string>* pAccessFilesHistory;
	int AccessFilesHistoryNum;
	vector<ProcessInfoData>* pRiskArray;
	int RiskArrayNum;
	vector<UnKnownDataInfo>* pUnKnownData;
	int UnKnownDataNum;
	void ChangeProcessHistoryNum(int pNum);
	void ChangeProcessHistoryInfoNum(int pNum);
	void ChangeNetworkHistoryNum(int pNum);
	void ChangeAccessFilesHistoryNum(int pNum);
	void ChangeRiskArrayNum(int pNum);
	void ChangeUnKnownDataNum(int pNum);
	vector<string>* GetProcessHistory1();
	vector<string>* GetProcessHistory2();
	vector<string>* GetProcessHistoryInfo1();
	vector<string>* GetProcessHistoryInfo2();
	vector<string>* GetNetworkHistory1();
	vector<string>* GetNetworkHistory2();
	set<string>* GetAccessFilesHistory1();
	set<string>* GetAccessFilesHistory2();
	vector<ProcessInfoData>* GetRiskArray1();
	vector<ProcessInfoData>* GetRiskArray2();
	vector<UnKnownDataInfo>* GetUnKnownData1();
	vector<UnKnownDataInfo>* GetUnKnownData2();
	void ParserProcessRisk(/*ThreadProcessInfo * pInfo*/process_info_Ex* pInfo, set<DWORD>* pApiName, TCHAR* pMyPath, vector<UnKnownDataInfo>* pMembuf);
	void InjectionNewProcess(ThreadInfo* pInfo);
	void LoadingProcessOnlyID(map<DWORD, DWORD>* pPID);

	bool EnumProcess(map<DWORD, process_info>* pInfo, time_t& LoadProcessTime);
	void GetProcessInfo(DWORD pid, TCHAR* pPath, TCHAR* pTimeStr, TCHAR* pUserName, TCHAR* pComStr);
	DWORD GetRemoteCommandLineW(HANDLE hProcess, LPWSTR pszBuffer, UINT bufferLength);

private:
	vector<string> m_ProcessHistory1;
	vector<string> m_ProcessHistory2;
	vector<string> m_ProcessHistoryInfo1;
	vector<string> m_ProcessHistoryInfo2;
	vector<string> m_NetworkHistory1;
	vector<string> m_NetworkHistory2;
	set<string> m_AccessFilesHistory1;
	set<string> m_AccessFilesHistory2;
	vector<ProcessInfoData> m_RiskArray1;
	vector<ProcessInfoData> m_RiskArray2;
	vector<UnKnownDataInfo> m_UnKnownData1;
	vector<UnKnownDataInfo> m_UnKnownData2;
	int GetProcessMappedFileName(HANDLE ProcessHandle, PVOID BaseAddress, wchar_t* FileName);
	void GetProcessPath(DWORD pid, TCHAR* pPath, bool IsGetTime, TCHAR* pTimeStr = NULL, TCHAR* pCTimeStr = NULL);
	
	void GetProcessDetectInfo(DWORD pid, TCHAR* pPath, TCHAR* pComStr);
	BOOL DumpExecute(DWORD pid, wchar_t* pName, set<DWORD>* pApiBace, set<DWORD>* pStr, TCHAR* pProcessPath, set<string>* pIsAbnormal_dll);
	void ParserProcessApi(set<string>* pApiBace, vector<BYTE>* pExecuteData, int pExecuteDataSize, vector<string>* pStr);
	//void ParserProcessidInfo(map<DWORD,ProcessInfoData> * pInfo,vector<TCPInformation> *pNetInfo,process_info pid,set<string>* pApiBace);
	//void GiveDetectProcessSendServer(map<DWORD,ProcessInfoData> * pInfo,void *argv);
	int CheckIsInjection(DWORD pid, vector<UnKnownDataInfo>* pMembuf, TCHAR* pProcessName, TCHAR* pUnKnownHash);
	bool PeUnmapper(BYTE* buffer, size_t pSize, ULONGLONG loadBase, UnKnownDataInfo* pInfo);
	BOOL IsWindowsProcessNormal(map<DWORD, process_info_Ex>* pInfo, DWORD pid);
	BOOL CheckParentProcessNormal(map<DWORD, process_info_Ex>* pInfo, DWORD parentid, wchar_t* process_name, time_t pCreateTime);
	BOOL CheckPathMatch(process_info_Ex* pInfo);
	BOOL CheckSIDMatch(process_info_Ex* pInfo);
	BOOL CheckCreateTimeRight(map<DWORD, process_info_Ex>* pData, __int64 pCreateTime);
	BOOL CheckCreateTimeMatch(map<DWORD, process_info_Ex>* pData, process_info_Ex* pInfo);
	int CheckIsStartRun(map<wstring, BOOL>* pService, set<wstring>* pStartRun, DWORD pid/*,BOOL & isServiceHide*/);
	
	void CheckModulePath(TCHAR* pProcessPath, TCHAR* pModulePath, set<string>* pIsAbnormal_dll);
	void CheckIsInlineHook(DWORD pid, set<string>* pInlineHook);
	//void EnumExportedFunctions(wchar_t *szFilename,wchar_t * Filename,DWORD psys,DWORD pid,set<string> * pInlineHook);
	//int Rva2Offset(unsigned int rva/*,sectionHeader * psections,unsigned int & NumberOfSections*/);
	//void mycallback (wchar_t* Filename,char* szName,DWORD psys,DWORD pid,set<string> * pInlineHook);
	void GetUserSID(HANDLE hProcess, TCHAR* szUserSID);
	DWORD GetInfoPid(const wchar_t* wtr);
	//void LoadProcessOpenHandle(set<wstring> * pStrInfo,set<DWORD> * pSystemPID);
	//void ParserProcessOpenHandle(set<wstring> * pStrInfo,map<wstring,wstring> * pDriverVolume,DWORD pid);
	//void LoadThisPCDriveVolume(map<wstring,wstring> * pDriveVolume);
	//void DisplayVolumePaths( __in PWCHAR VolumeName,TCHAR * pLogicalPath);
	void LoadSystemPID(map<DWORD, wstring>* pSystemPID);
	void GetProcessOnlyPath(DWORD pid, TCHAR* pPath);
	void GetProcessOnlyTime(DWORD pid, time_t& pTime);
	void GetProcessOnlyPathAndTime(DWORD pid, TCHAR* pPath, time_t& pTime);
	void InjectionProcess(DWORD pid, TCHAR* pPath);
	bool WindowsMainProcess(map<DWORD, wstring>* pSystemPID, DWORD pParentId);
	void SearchExecutePath(DWORD pid, TCHAR* pPath, TCHAR* pName);
	
	bool EnumProcessEx(map<DWORD, process_info_Ex>* pInfo/*,time_t & LoadProcessTime*/);
	void CheckInjectionPtn(set<DWORD>* pStringsHash, BOOL& pIsOther, BOOL& pIsPE);
	void GetUnKnownHash(BYTE* pBuffer, SIZE_T pBufferSize, TCHAR* pUnKnownHash, SIZE_T ptype);
	void ParserUnknownIAT(BYTE* pBuffer, TCHAR* pUnKnownHash);
	void ParserUnknownIAT32(BYTE* pBuffer, TCHAR* pUnKnownHash);
	static void _clean_things(HANDLE hFile, HANDLE hMapping, PBYTE pFile, const char* pErrorMessage);
	void FindFunctionAddress32(TCHAR* file_path, BYTE* pModBaseAddr, HANDLE pProcess, set<string>* pInlineHook);
	void FindFunctionAddress(TCHAR* file_path, BYTE* pModBaseAddr, HANDLE pProcess, set<string>* pInlineHook);
#if defined _M_IX86
	bool EnumRing0Process(map<DWORD, process_info>* pInfo, time_t& LoadProcessTime);
	bool EnumRing0ProcessEx(map<DWORD, process_info_Ex>* pInfo);
	bool LoadRing0Process(map<DWORD, process_info>* pInfo, BYTE* pInBuf, DWORD pInBuflen, time_t& LoadProcessTime);
	bool LoadRing0ProcessEx(map<DWORD, process_info_Ex>* pInfo, BYTE* pInBuf, DWORD pInBuflen);
	bool ParserRing0EnumProcessStr(wchar_t* wtr, map<DWORD, process_info>* pInfo);
	void ParserRing0EnumProcessData(wchar_t* wtr, process_info* pInfo);
	void CheckProcessHide(map<DWORD, process_info>* pInfo, map<DWORD, process_info>* pCInfo, time_t LoadProcessTime);
	void CheckProcessHideEx(map<DWORD, process_info_Ex>* pInfo, map<DWORD, process_info_Ex>* pCInfo, time_t LoadProcessTime);
#endif
};