#include <unordered_map>
#include <functional>
#include <any>
#include <set>
#include <map>

#include "tools.h"
#include "socket_send.h"
#include "MemProcess.h"

//#include "File.h"
//#include "NTFSSearchCore.h"


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

    int GiveInfo();
    int CheckConnect();
    int GiveDetectInfoFirst();
    int GiveDetectInfo();

    int DetectProcess();
    

    int GetScanInfoData();
    int GiveProcessData();
    int GiveProcessDataEnd();
    int GiveScanProgress();
    int GiveDriveInfo();
    int Explorer();
    int GiveExplorerData();
    int GiveExplorerEnd();
    int CollectInfo();
    int GiveCollectProgress();
    int GiveCollectDataInfo();
    int GiveCollectData();
    int GiveCollectDataEnd();

    int OpenCheckthread(StrPacket* udata);
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

private:
    Tool tool;
    void GiveScanDataSendServer(char* pMAC, char* pIP, char* pMode, map<DWORD, ProcessInfoData>* pFileInfo, vector<UnKnownDataInfo>* pUnKnownData);
    int NTFSSearch(wchar_t vol_name, char* pMAC, char* pIP);

    int DetectProcessRisk(int pMainProcessid, bool IsFirst, set<DWORD>* pApiName);
    void SendProcessDataToServer(vector<ProcessInfoData>* pInfo);
};