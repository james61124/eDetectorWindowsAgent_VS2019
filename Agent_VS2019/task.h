#ifndef TASK_H
#define TASK_H


#include <unordered_map>
#include <functional>
#include <any>
#include <set>
#include <map>
#include <fstream>

#include "tools.h"
#include "socket_send.h"
#include "MemProcess.h"

//#include "File.h"
#include "NTFSSearchCore.h"

#include "sqlite3.h"

#include "Collect.h"


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
    int GiveScanFragment(char* buff, SOCKET* tcpSocket);
    int GiveScanEnd(char* buff, SOCKET* tcpSocket);

    int ExplorerInfo_(StrPacket* udata);


    int GiveDriveInfo();
    int Explorer();
    int GiveExplorerData(char* Drive, char* FileSystem);
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

    int DetectNewNetwork(int pMainProcessid);
    void SendNetworkDetectToServer(vector<string>* pInfo);

    // collect
    void CollectionComputerInfo(); 
    bool LoadPredefineConfig(TCHAR* ConfigPath, map<string, vector<PredefineObj>>* mapPredefine); 
    void SendDbFileToServer(TCHAR* DBName); 
    void CollectionComputeInfo(DWORD UserModePid); 
    bool GetQueryByTable(string* query, string TableName, string QueryFilter);
    void GiveScanDataSendServer(char* pMAC, char* pIP, char* pMode, map<DWORD, ProcessInfoData>* pFileInfo, vector<UnKnownDataInfo>* pUnKnownData);
    void ParsePredefineConfig(char* str, string* defineName, vector<PredefineObj>* Vmp);
    void CreateProcessForCollection(TCHAR* DBName); 
    bool InsertFromToInCombination(TCHAR* DBName, const map<string, vector<PredefineObj>>* mapPredefine);


};

#endif