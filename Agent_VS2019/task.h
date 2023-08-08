#ifndef TASK_H
#define TASK_H


#include <unordered_map>
#include <functional>
#include <any>
#include <set>
#include <map>

#include "tools.h"
#include "socket_send.h"
#include "MemProcess.h"

//#include "File.h"
#include "NTFSSearchCore.h"


//#include "NTFS.h"

class Task {
public:

    Task(Info* infoInstance, SocketSend* socketSendInstance);
    Info* info;
    SocketSend* socketsend;

    using FunctionPtr = std::function<int(Task*, std::any)>;
    using FunctionPtrFromServer = std::function<int(Task*, StrPacket*)>;

    std::unordered_map<std::string, FunctionPtr> functionMap;
    std::unordered_map<std::string, FunctionPtrFromServer> functionFromServerMap;

    std::unordered_map<std::string, std::thread> threadMap;
    void startThread(const std::string& key, std::string functionName);

    // handshake
    int GiveInfo();
    int GiveDetectInfoFirst();
    int GiveDetectInfo();
    int OpenCheckthread(StrPacket* udata);
    int CheckConnect();

    // detect
    int DetectProcess();
    

    // scan
    int GiveScanInfo(char* buff, SOCKET* tcpSocket);
    int GiveProcessData(SOCKET* tcpSocket);
    int GiveScan(char* buff, SOCKET* tcpSocket);
    int GiveScanDataEnd(char* buff, SOCKET* tcpSocket);


    int GiveDriveInfo();
    int Explorer();
    int GiveExplorerData();
    int GiveExplorerEnd();
    int CollectInfo();
    int GiveCollectProgress();
    int GiveCollectDataInfo();
    int GiveCollectData();
    int GiveCollectDataEnd();

    
    int UpdateDetectMode(StrPacket* udata);
    int GetScanInfoData_(StrPacket* udata);
    int GetScan(StrPacket* udata);
    int GetProcessInfo(StrPacket* udata);
    int GetDrive(StrPacket* udata);
    //int ExplorerInfo(StrPacket* udata);
    int TransportExplorer(StrPacket* udata);
    int GetCollectInfo(StrPacket* udata);
    int GetCollectInfoData(StrPacket* udata);
    int DataRight(StrPacket* udata);

    SOCKET* CreateNewSocket();

private:
    
    Tool tool;

    // scan
    void GiveScanDataSendServer(char* pMAC, char* pIP, char* pMode, map<DWORD, ProcessInfoData>* pFileInfo, vector<UnKnownDataInfo>* pUnKnownData, SOCKET* tcpSocket);

    // detect
    int DetectProcessRisk(int pMainProcessid, bool IsFirst, set<DWORD>* pApiName, SOCKET* tcpSocket);
    void SendProcessDataToServer(vector<ProcessInfoData>* pInfo, SOCKET* tcpSocket);

    int NTFSSearch(wchar_t vol_name, char* pMAC, char* pIP, SOCKET* tcpSocket);

    
    
    char* GetMyPCDrive();

};

#endif