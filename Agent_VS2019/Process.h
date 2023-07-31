#ifndef PROCESS_H
#define PROCESS_H

#pragma comment(lib, "Crypt32.lib")
#include <string>
#include <cstring>
#include <set>
#include <vector>
#include <Windows.h>
#include <Sddl.h>
#include <Psapi.h>
#include <winternl.h>
#include <TlHelp32.h>
//#include <ntdef.h>

//#include <Ntdef.h> 

#include <Mstcpip.h>
#include <IPHlpApi.h>

#define MAX_PATH 260
#define MAX_PATH_EX 512
#define MemoryMappedFilenameInformation 2
#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383

struct ProcessInfoData
{
	DWORD ProcessID;
	wchar_t ProcessName[MAX_PATH]; // 1
	DWORD ParentID;
	wchar_t ParentPath[MAX_PATH_EX];
	wchar_t ProcessPath[MAX_PATH_EX];
	wchar_t ProcessHash[40];
	wchar_t ProcessTime[20];
	wchar_t SignerSubjectName[256];
	wchar_t ProcessCTime[20];
	wchar_t ParentCTime[20];
	int Injected;
	int StartRun;
	BOOL HideAttribute;
	//BOOL HideService;
	BOOL HideProcess;
	//set<DWORD> ApiString;
	BOOL InjectionOther;
	BOOL InjectionPE;
	std::set<std::string> NetString;
	std::set<std::string> Abnormal_dll;
	std::set<std::string> InlineHookInfo;
	wchar_t UnKnownHash[50];
	//vector<UnKnownDataInfo> UnKnownData;
};

struct UnKnownDataInfo
{
	BYTE* Data;
	DWORD SizeInfo;
	DWORD Pid;
	wchar_t ProcessName[MAX_PATH];
};

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

struct process_info_Ex {
	int pid;
	int parent_pid;
	wchar_t process_name[MAX_PATH];
	time_t ProcessCreateTime;
	time_t parentCreateTime;
	//wchar_t parent_name[MAX_PATH];
	wchar_t process_Path[MAX_PATH_EX];
	wchar_t m_SID[_MAX_FNAME];
	BOOL IsPacked;
	wchar_t process_Com[MAX_PATH_EX];
	BOOL IsHide;
};

struct SerivceInformation
{
	wchar_t SerivceName[1024];
	wchar_t DisplayName[1024];
	DWORD dwCurrentState;
	DWORD dwServiceType;
	DWORD dwStartType;
	DWORD dwErrorControl;
	wchar_t lpBinaryPathName[1024];
	wchar_t lpServiceStartName[1024];
	wchar_t lpDescription[1024];
	wchar_t lpLoadOrderGroup[1024];
	DWORD dwTagId;
	wchar_t lpDependencies[1024];
	BOOL IsInstall;
	wchar_t lpServiceDll[1024];
};

typedef struct AutoRunInfo_ {
	wchar_t m_Command[MAX_PATH_EX];
	wchar_t StartName[MAX_PATH];
	wchar_t InfoLocation[MAX_PATH_EX];
}AutoRunInfo;

struct DigitalSignatureInfo
{
	wchar_t ProgramName[256];
	wchar_t PublisherLink[256];
	wchar_t MoreInfoLink[256];
	wchar_t SignerSerialNumber[256];
	wchar_t SignerIssuerName[256];
	wchar_t SignerSubjectName[256];
	wchar_t TimeStampSerialNumber[256];
	wchar_t TimeStampIssuerName[256];
	wchar_t TimeStampSubjectName[256];
	SYSTEMTIME DateofTimeStamp;
};

struct TCPInformation
{
	DWORD ProcessID;
	DWORD LocalAddr;
	DWORD LocalPort;
	DWORD RemoteAddr;
	DWORD RemotePort;
	DWORD State;
};

struct process_info
{
	int pid;
	int parent_pid;
	wchar_t process_name[MAX_PATH];
	time_t ProcessCreateTime;
	BOOL IsHide;
};

typedef NTSTATUS(__stdcall* PNtQueryVirtualMemory)(
	HANDLE                   ProcessHandle,
	PVOID                    BaseAddress,
	DWORD					 MemoryInformationClass,
	PVOID                    MemoryInformation,
	SIZE_T                   MemoryInformationLength,
	PSIZE_T                  ReturnLength
	);

typedef struct {
	LPWSTR lpszProgramName;
	LPWSTR lpszPublisherLink;
	LPWSTR lpszMoreInfoLink;
} SPROG_PUBLISHERINFO, * PSPROG_PUBLISHERINFO;

typedef struct _LOADED_IMAGE32 {
	PSTR                  ModuleName;
	HANDLE                hFile;
	PUCHAR                MappedAddress;

	PIMAGE_NT_HEADERS32   FileHeader;

	PIMAGE_SECTION_HEADER LastRvaSection;
	ULONG                 NumberOfSections;
	PIMAGE_SECTION_HEADER Sections;
	ULONG                 Characteristics;
	BOOLEAN               fSystemImage;
	BOOLEAN               fDOSImage;
	BOOLEAN               fReadOnly;
	UCHAR                 Version;
	LIST_ENTRY            Links;
	ULONG                 SizeOfImage;
} LOADED_IMAGE32, * PLOADED_IMAGE32;



//DWORD(WINAPI* pGetExtendedTcpTable)(
//	PVOID pTcpTable,
//	PDWORD pdwSize,
//	BOOL bOrder,
//	ULONG ulAf,
//	TCP_TABLE_CLASS TableClass,
//	ULONG Reserved
//	);



typedef PBYTE ALIGNED_BUF;


// add 

struct StartRunInfoData
{
	TCHAR FileName[MAX_PATH];
	TCHAR FilePath[MAX_PATH_EX];
	TCHAR FileHash[40];
};

struct TaskSchedulerInfo
{
	TCHAR Command[MAX_PATH_EX];
	TCHAR TaskName[MAX_PATH];
	TCHAR UserId[_MAX_FNAME];
	TCHAR LastRunTime[64];
	TCHAR NextRunTime[64];
	TCHAR Triggers[64];
	TCHAR Status[32];
	TCHAR Argument[1024];
	TCHAR HighPrivilege[32];
	TCHAR Author[1024];
	TCHAR RunOnNetwork[32];
};

#endif // PROCESS_H
