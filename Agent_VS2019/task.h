#include <unordered_map>
#include <functional>
#include <any>
#include <set>
#include <map>

#include "tools.h"
#include "socket_send.h"
#include "MemProcess.h"
#include "File.h"
//#include "NTFSSearchCore.h"
//#include "CFileSystem.h"

class PredefineObj //Yen
{
public:
    string TableName;
    string vecFilterCondition;
};

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
    int GiveCollectData(StrPacket* Mgs);
    //int GiveCollectDataEnd();

    int OpenCheckthread(StrPacket* udata);
    int UpdateDetectMode(StrPacket* udata);
    int GetScanInfoData_(StrPacket* udata);
    int GetProcessInfo(StrPacket* udata);
    int GetDrive(StrPacket* udata);
    //int ExplorerInfo(StrPacket* udata);
    int TransportExplorer(StrPacket* udata);
    int GetCollectInfo(StrPacket* udata);
    int GetCollectInfoData(StrPacket* udata);
    int DataRight(StrPacket* udata);
    char MyMAC[20]; //Yen
    char MyIP[20]; //Yen


private:
    // Not Sure public or private
    Tool tool;
    void CollectionComputerInfo(DWORD UserModePid);  //Yen
    bool LoadPredefineConfig(TCHAR* ConfigPath, map<string, vector<PredefineObj>>* mapPredefine); //Yen
    void SendDbFileToServer(TCHAR* DBName); //Yen
    int SendDataBufToServer(char* m_MAC, char* m_IP, char* m_Work, BYTE* buf); //Yen
    void CollectionComputeInfo(DWORD UserModePid); //Yen
    bool GetQueryByTable(string* query, string TableName, string QueryFilter);
    void GiveScanDataSendServer(char* pMAC, char* pIP, char* pMode, map<DWORD, ProcessInfoData>* pFileInfo, vector<UnKnownDataInfo>* pUnKnownData);
    void ParsePredefineConfig(char* str, string* defineName, vector<PredefineObj>* Vmp);
    int IsSendDataRight(StrPacket* Mgs); //Yen
    void CreateProcessForCollection(TCHAR* DBName); //Yen
    bool InsertFromToInCombination(TCHAR* DBName, const map<string, vector<PredefineObj>>* mapPredefine, char* MAC, char* IP);//Yen
    //bool GetDataByQuery(const string& query, sqlite3* m_db, vector<CombineObj>* vecCombineObj); //Yen
    //bool WriteDataSetToDB(sqlite3* m_db, const vector<CombineObj> vecCombineObj, const string DefineName, const string MAC, const string IP, const string TableName, int id); //Yen;;
        //bool WriteSQLiteDB(sqlite3* pdb, char* pQuery); //Yen
};


class TableFilter //Yen
{
public:
    string TableName;
    string ConnectCondition;
    vector<string> vecFilterCondition;
};

class CombineObj
{
public:
    string IP;
    string MAC;
    string Table_id;
    string Item;
    string ETC;
    string Date;
};
