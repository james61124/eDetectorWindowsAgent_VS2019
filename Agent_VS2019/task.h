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
#include <ctime>
#include <chrono>

#include "tools.h"
#include "socket_send.h"
#include "MemProcess.h"

//#include "File.h"

#include "sqlite3.h"
#include "Collect.h"


//#include "NTFS.h"

namespace fs = std::filesystem;

//struct ImageType {
//    char path[512];
//    char APPTYPE[512];
//    char filename[512];
//};


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
    //int DetectProcess_();
    //int GiveDetectProcess(char* buff, SOCKET* tcpSocket);
    //int GiveDetectProcessFrag(char* buff, SOCKET* tcpSocket);
    //int GiveDetectNetwork(char* buff, SOCKET* tcpSocket);

    // explorer
    int ExplorerInfo_(StrPacket* udata);
    int GiveDriveInfo();
    //int GiveExplorerData(char* Drive, char* FileSystem);
    //void SysExplorerSearch(TCHAR* m_Path, unsigned int FatherNum, unsigned int& FileIndex, char* TmpSend, unsigned int& m_ProgressCount, unsigned int& m_Count);

    //collect
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
    //int LookingForImage(char* cmd);
    //void SearchForFile(std::filesystem::path root, std::filesystem::path directory, std::filesystem::path::const_iterator start, std::filesystem::path::const_iterator finish, const std::string& targetFile, HZIP* hz);
    //std::string ToUpper(const std::string& str);

    // update agent
    int OpenUpdateAgentProcess(StrPacket* udata);
    //int UpdateAgent();
    //void AgentReceive(int fileSize);
    //void WriteNewAgentToFile(char* buffer, int totalReceivedSize);
    //int ReadyUpdateAgent(char* buff);
    //int SendACK(char* buff);
    //int GiveUpdateInfo();
    //int GiveUpdateEnd();

    int TerminateAll(StrPacket* udata);
    int RemoveAgent(StrPacket* udata);
    //int TerminateAllTask();

private:
    
    Tool tool;
    Log log;
    const char* AESKey = "AES Encrypt Decrypt";

    // detect
    //int DetectProcessRisk(int pMainProcessid, bool IsFirst, set<DWORD>* pApiName, SOCKET* tcpSocket);
    //void SendProcessDataToServer(vector<ProcessInfoData>* pInfo, SOCKET* tcpSocket);

    //int NTFSSearch(wchar_t vol_name, char* pMAC, char* pIP, SOCKET* tcpSocket, char* Drive, char* FileSystem);
    void SendZipFileToServer(const TCHAR* DBName, SOCKET* tcpSocket);

    
    char* GetMyPCDrive();

    
    //void SendNetworkDetectToServer(vector<string>* pInfo);

    int SendDataPacketToServer(const char* function, char* buff, SOCKET* tcpSocket);
    int SendMessagePacketToServer(const char* function, char* buff);
    void SendFileToServer(const char* function, const TCHAR* FileName, SOCKET* tcpSocket);
    


};

#endif