#pragma once

#include "AllTask.h"

enum {
    COMPANYNAME,
    FILESVERSION,
    LEGALCOPYRIGHT,
    PRIVATEBUILD,
    COMMENTS,
    INTERNALNAME,
    PRODUCTNAME,
    PRODUCTSVERSION,
    FILEDESCRIPTION,
    LEGALTRADEMARKS,
    ORIGINALFILENAME,
    SPECIALBUILD,
    VERSIONCOUNT
};

class Scan : public AllTask {
public:
	Scan(Info* infoInstance, SocketSend* socketSendInstance);
	void DoTask() override;

	void ScanRunNowProcess(void* argv, map<DWORD, ProcessInfoData>* pInfo, set<DWORD>* pApiName, vector<UnKnownDataInfo>* pMembuf, SOCKET* tcpSocket);
	void GiveScanDataSendServer(char* pMAC, char* pIP, char* pMode, map<DWORD, ProcessInfoData>* pFileInfo, vector<UnKnownDataInfo>* pUnKnownData, SOCKET* tcpSocket);
	BOOL GetFileVersion_(TCHAR* pPath, wstring* pFileVersionStr);
	DWORD GetRemoteCommandLineW(HANDLE hProcess, LPWSTR pszBuffer, UINT bufferLength);

    int ProcessDump(DumpMemoryInfo* pInfo);
    int ScanInjectedProcessDump(ScanMemoryInfo* pInfo);
};
