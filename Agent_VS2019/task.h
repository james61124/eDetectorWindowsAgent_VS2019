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

    Task(Info* infoInstance, SocketSend socketSendInstance);
    Info* info;
    SocketSend socketsend;

    using FunctionPtr = std::function<int(Task*, std::any)>;
    using FunctionPtrFromServer = std::function<int(Task*, StrPacket*, SOCKET*)>;

    std::unordered_map<std::string, FunctionPtr> functionMap;
    std::unordered_map<std::string, FunctionPtrFromServer> functionFromServerMap;

    std::unordered_map<std::string, std::thread> threadMap;
    void startThread(const std::string& key, std::string functionName);

    // handshake
    int GiveInfo();
    int GiveDetectInfoFirst(SOCKET* tcpSocket);
    int GiveDetectInfo(SOCKET* tcpSocket);
    int OpenCheckthread(StrPacket* udata, SOCKET* tcpSocket);
    int UpdateDetectMode(StrPacket* udata, SOCKET* tcpSocket);
    int CheckConnect();

    // detect
    int DetectProcess();
    

    // scan
    int GiveScanInfo(char* buff, SOCKET* tcpSocket);
    int GiveProcessData(SOCKET* tcpSocket);
    void ScanRunNowProcess(void* argv, map<DWORD, ProcessInfoData>* pInfo, set<DWORD>* pApiName, vector<UnKnownDataInfo>* pMembuf, SOCKET* tcpSocket);
    int GiveScan(char* buff, SOCKET* tcpSocket);
    int GiveScanFragment(char* buff, SOCKET* tcpSocket);
    int GiveScanEnd(char* buff, SOCKET* tcpSocket);
    int GiveScanProgress(char* buff, SOCKET* tcpSocket);

    // explorer
    int ExplorerInfo_(StrPacket* udata, SOCKET* tcpSocket);
    int GiveDriveInfo(SOCKET* tcpSocket);
    int Explorer(char* buff, SOCKET* tcpSocket);
    int GiveExplorerInfo(char* buff, SOCKET* tcpSocket);
    int GiveExplorerData(char* Drive, char* FileSystem, SOCKET* tcpSocket);
    int GiveExplorerProgress(char* buff, SOCKET* tcpSocket);
    int GiveExplorerData(char* buff, SOCKET* tcpSocket);
    int GiveExplorerEnd(char* buff, SOCKET* tcpSocket);
    int GiveExplorerError(char* buff, SOCKET* tcpSocket);

    //collect
    int GiveCollectDataInfo(char* buff, SOCKET* tcpSocket);
    int GiveCollectProgress(char* buff, SOCKET* tcpSocket);
    int GiveCollectData(char* buff, SOCKET* tcpSocket);
    int GiveCollectDataEnd(char* buff, SOCKET* tcpSocket);


   
    
    
    int GetScanInfoData_(StrPacket* udata);
    int GetScan(StrPacket* udata, SOCKET* tcpSocket);
    int GetProcessInfo(StrPacket* udata);
    int GetDrive(StrPacket* udata, SOCKET* tcpSocket);
    //int ExplorerInfo(StrPacket* udata);
    int GetCollectInfo(StrPacket* udata, SOCKET* tcpSocket);
    int GetCollectInfoData(StrPacket* udata);
    int DataRight(StrPacket* udata, SOCKET* tcpSocket);

    SOCKET* CreateNewSocket();

private:
    
    Tool tool;

    // scan
    void GiveScanDataSendServer(char* pMAC, char* pIP, char* pMode, map<DWORD, ProcessInfoData>* pFileInfo, vector<UnKnownDataInfo>* pUnKnownData, SOCKET* tcpSocket);

    // detect
    int DetectProcessRisk(int pMainProcessid, bool IsFirst, set<DWORD>* pApiName, SOCKET* tcpSocket);
    void SendProcessDataToServer(vector<ProcessInfoData>* pInfo, SOCKET* tcpSocket);

    int NTFSSearch(wchar_t vol_name, char* pMAC, char* pIP, SOCKET* tcpSocket, char* Drive, char* FileSystem);
    void SendZipFileToServer(const TCHAR* DBName, SOCKET* tcpSocket);

    
    char* GetMyPCDrive();

    int DetectNewNetwork(int pMainProcessid);
    void SendNetworkDetectToServer(vector<string>* pInfo);

    // collect
    int CollectionComputerInfo(SOCKET* tcpSocket);
    bool LoadPredefineConfig(TCHAR* ConfigPath, map<string, vector<PredefineObj>>* mapPredefine); 
    void SendDbFileToServer(const TCHAR* DBName, SOCKET* tcpSocket);
    bool GetQueryByTable(string* query, string TableName, string QueryFilter);
    void ParsePredefineConfig(char* str, string* defineName, vector<PredefineObj>* Vmp);
    void CreateProcessForCollection(TCHAR* DBName, SOCKET* tcpSocket);
    bool InsertFromToInCombination(TCHAR* DBName, const map<string, vector<PredefineObj>>* mapPredefine, SOCKET* tcpSocket);
    


};

#endif