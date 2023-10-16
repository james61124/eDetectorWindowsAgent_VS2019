#ifndef TASK_H
#define TASK_H
#pragma comment(lib, "vssapi.lib")


#include <unordered_map>
#include <functional>
#include <any>
#include <set>
#include <map>
#include <fstream>
#include <sstream>

#include <filesystem>

#include <objbase.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <comdef.h>

#include "tools.h"
#include "socket_send.h"
#include "MemProcess.h"

//#include "File.h"
#include "NTFSSearchCore.h"

#include "sqlite3.h"

#include "Collect.h"


//#include "NTFS.h"

namespace fs = std::filesystem;




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

    std::ofstream AgentFile;
    char* AgentBuffer;

    // handshake
    int GiveInfo();
    int GiveDetectInfoFirst();
    int GiveDetectInfo();
    int OpenCheckthread(StrPacket* udata);
    int CheckConnect();

    // detect
    int DetectProcess_();
    int GiveDetectProcess(char* buff, SOCKET* tcpSocket);
    int GiveDetectProcessFrag(char* buff, SOCKET* tcpSocket);
    int GiveDetectNetwork(char* buff, SOCKET* tcpSocket);
    

    // scan
    int GiveScanInfo(char* buff, SOCKET* tcpSocket);
    int GiveProcessData();
    void ScanRunNowProcess(void* argv, map<DWORD, ProcessInfoData>* pInfo, set<DWORD>* pApiName, vector<UnKnownDataInfo>* pMembuf, SOCKET* tcpSocket);
    void SendScanFileToServer(const TCHAR* zipFileName, SOCKET* tcpSocket);
    int ReadyScan(char* buff, SOCKET* tcpSocket);
    int GiveScan(char* buff, SOCKET* tcpSocket);
    int GiveScanFragment(char* buff, SOCKET* tcpSocket);
    int GiveScanEnd(char* buff, SOCKET* tcpSocket);
    int GiveScanProgress(char* buff, SOCKET* tcpSocket);
    int GiveScanDataInfo(char* buff, SOCKET* tcpSocket);

    // explorer
    int ExplorerInfo_(StrPacket* udata);
    int GiveDriveInfo();
    int Explorer(char* buff, SOCKET* tcpSocket);
    int GiveExplorerInfo(char* buff, SOCKET* tcpSocket);
    int GiveExplorerData(char* Drive, char* FileSystem);
    int GiveExplorerProgress(char* buff, SOCKET* tcpSocket);
    int GiveExplorerData(char* buff, SOCKET* tcpSocket);
    int GiveExplorerEnd(char* buff, SOCKET* tcpSocket);
    int GiveExplorerError(char* buff, SOCKET* tcpSocket);

    //collect
    int GiveCollectDataInfo(char* buff, SOCKET* tcpSocket);
    int GiveCollectProgress(char* buff, SOCKET* tcpSocket);
    int GiveCollectData(char* buff, SOCKET* tcpSocket);
    int GiveCollectDataEnd(char* buff, SOCKET* tcpSocket);
    void CollectData(int i, int iLen);


   
    
    int UpdateDetectMode(StrPacket* udata);
    int GetScan(StrPacket* udata);
    int GetDrive(StrPacket* udata);
    //int ExplorerInfo(StrPacket* udata);
    int GetCollectInfo(StrPacket* udata);
    int GetCollectInfoData(StrPacket* udata);
    int DataRight(StrPacket* udata);

    SOCKET* CreateNewSocket();
    int DetectNewNetwork(int pMainProcessid);

    // image
    int GetImage(StrPacket* udata);
    int LookingForImage(char* cmd);
    void SearchImageFile(std::vector<std::string>& parts, int level, string searchPath, char* FileToSearch, HZIP* hz);
    void SendImageFileToServer(const TCHAR* DBName, SOCKET* tcpSocket);
    int GiveImageInfo(char* buff, SOCKET* tcpSocket);
    int GiveImage(char* buff, SOCKET* tcpSocket);
    int GiveImageEnd(char* buff, SOCKET* tcpSocket);

    // update agent
    int OpenUpdateAgentProcess(StrPacket* udata);
    int UpdateAgent();
    void AgentReceive(int fileSize);
    void WriteNewAgentToFile(char* buffer, int totalReceivedSize);
    int ReadyUpdateAgent(char* buff);
    int SendACK(char* buff);
    int GiveUpdateInfo();
    int GiveUpdateEnd();

private:
    
    Tool tool;
    Log log;
    const char* AESKey = "AES Encrypt Decrypt";

    // scan
    void GiveScanDataSendServer(char* pMAC, char* pIP, char* pMode, map<DWORD, ProcessInfoData>* pFileInfo, vector<UnKnownDataInfo>* pUnKnownData, SOCKET* tcpSocket);

    // detect
    int DetectProcessRisk(int pMainProcessid, bool IsFirst, set<DWORD>* pApiName, SOCKET* tcpSocket);
    void SendProcessDataToServer(vector<ProcessInfoData>* pInfo, SOCKET* tcpSocket);

    int NTFSSearch(wchar_t vol_name, char* pMAC, char* pIP, SOCKET* tcpSocket, char* Drive, char* FileSystem);
    void SendZipFileToServer(const TCHAR* DBName, SOCKET* tcpSocket);

    
    char* GetMyPCDrive();

    
    void SendNetworkDetectToServer(vector<string>* pInfo);

    // collect
    int CollectionComputerInfo(); 
    bool LoadPredefineConfig(TCHAR* ConfigPath, map<string, vector<PredefineObj>>* mapPredefine); 
    void SendDbFileToServer(const TCHAR* DBName, SOCKET* tcpSocket);
    bool GetQueryByTable(string* query, string TableName, string QueryFilter);
    void ParsePredefineConfig(char* str, string* defineName, vector<PredefineObj>* Vmp);
    void CreateProcessForCollection(TCHAR* DBName, SOCKET* tcpSocket);
    bool InsertFromToInCombination(TCHAR* DBName, const map<string, vector<PredefineObj>>* mapPredefine, SOCKET* tcpSocket);

    int SendDataPacketToServer(const char* function, char* buff, SOCKET* tcpSocket);
    int SendMessagePacketToServer(const char* function, char* buff);
    void SendFileToServer(const char* function, const TCHAR* FileName, SOCKET* tcpSocket);
    


};

#endif