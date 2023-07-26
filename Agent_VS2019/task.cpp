#include <iostream>
#include <string>
#include <cstring>
#include <future>

#include "task.h"


Task::Task(Info* infoInstance, SocketSend* socketSendInstance) {
    functionMap["GiveInfo"] = std::bind(&Task::GiveInfo, this);
    functionMap["GiveDetectInfoFirst"] = std::bind(&Task::GiveDetectInfoFirst, this);
    functionMap["GiveDetectInfo"] = std::bind(&Task::GiveDetectInfo, this);
    // functionMap["Process"] = std::bind(&Task::Process, this);
    functionMap["GetScanInfoData"] = std::bind(&Task::GetScanInfoData, this);
    functionMap["GiveProcessData"] = std::bind(&Task::GiveProcessData, this);
    functionMap["GiveProcessDataEnd"] = std::bind(&Task::GiveProcessDataEnd, this);
    functionMap["GiveScanProgress"] = std::bind(&Task::GiveScanProgress, this);
    functionMap["GiveDriveInfo"] = std::bind(&Task::GiveDriveInfo, this);
    functionMap["Explorer"] = std::bind(&Task::Explorer, this);
    functionMap["GiveExplorerData"] = std::bind(&Task::GiveExplorerData, this);
    functionMap["GiveExplorerEnd"] = std::bind(&Task::GiveExplorerEnd, this);
    functionMap["CollectInfo"] = std::bind(&Task::CollectInfo, this);
    functionMap["GiveCollectProgress"] = std::bind(&Task::GiveCollectProgress, this);
    functionMap["GiveCollectDataInfo"] = std::bind(&Task::GiveCollectDataInfo, this);
    functionMap["GiveCollectData"] = std::bind(&Task::GiveCollectData, this);
    functionMap["GiveCollectDataEnd"] = std::bind(&Task::GiveCollectDataEnd, this);

    // packet from server
    functionFromServerMap["OpenCheckthread"] = &Task::OpenCheckthread;
    functionFromServerMap["UpdateDetectMode"] = &Task::UpdateDetectMode;
    functionFromServerMap["GetScanInfoData"] = &Task::GetScanInfoData_;
    functionFromServerMap["GetProcessInfo"] = &Task::GetProcessInfo;
    functionFromServerMap["GetDrive"] = &Task::GetDrive;
    functionFromServerMap["ExplorerInfo"] = &Task::ExplorerInfo;
    functionFromServerMap["TransportExplorer"] = &Task::TransportExplorer;
    functionFromServerMap["GetCollectInfo"] = &Task::GetCollectInfo;
    functionFromServerMap["GetCollectInfoData"] = &Task::GetCollectInfoData;
    functionFromServerMap["DataRight"] = &Task::DataRight;

    info = infoInstance;
    socketsend = socketSendInstance;
}

void Task::startThread(const std::string& key, std::string functionName) {
    std::any argument;
    auto functionIter = threadMap.find(functionName);
    if (functionIter == threadMap.end()) {
        threadMap[functionName] = std::thread(functionMap[functionName], this, argument);
    }
}

int Task::GiveInfo() {
    // getSystemInfo();
    char* buffer = new char[STRINGMESSAGELEN];
    char* SysInfo = tool.GetSysInfo();
    char* OsStr = tool.GetOSVersion();
    char* cComputerName = tool.GetComputerNameUTF8();
    char* cUserName = tool.GetUserNameUTF8();
    char* FileVersion = new char[10];
    unsigned long long BootTime = tool.GetBootTime();
    char* Key = new char[10];
    char* DigitalSignatureHash = new char[10];
    char* functionName = new char[24];

    strcpy_s(FileVersion, sizeof(FileVersion), "0.0.0.0");

    if (strcpy_s(Key, sizeof(Key), "") == 0) printf("copy key success\n");
    else printf("copy key failed\n");

    if (strcpy_s(DigitalSignatureHash, sizeof(DigitalSignatureHash), "123456") == 0) printf("copy sign success\n");
    else printf("copy sign failed\n");

    if (strcpy_s(functionName, sizeof(functionName), "GiveInfo\0") == 0) printf("copy function success\n");
    else printf("copy function failed\n");

    //char* WorkNew = new char[WorkSize+1];
    //printf("sizeof work %d", WorkSize);
    //strncpy_s(WorkNew, sizeof(WorkNew), Work, sizeof(Work));
    //WorkNew[sizeof(WorkNew) - 1] = '\0';
    //printf("sizeof newwork %d %s", sizeof(WorkNew), WorkNew);

    snprintf(buffer, STRINGMESSAGELEN, "%s|%s|%s|%s|%s,%d,%d|%d|%s|%lu", SysInfo, OsStr, cComputerName, cUserName, FileVersion, 1988, 1989, BootTime, Key, DigitalSignatureHash);
    
    return socketsend->SendMessageToServer(functionName, buffer);
}

int Task::CheckConnect() {

    // while(true){
    //     std::this_thread::sleep_for(std::chrono::seconds(2));
    //     if (!socketmanager->SendMessageToServer("CheckConnect", "")) {
    //         printf("CheckConnect sent failed\n");
    //     } else {
    //         printf("CheckConnect sent\n");
    //     }
    // }

    // to do
    // open a thread to send it forever
    // check kill time

    return 0;
}

int Task::GiveDetectInfoFirst() {
    char* buff = new char[STRINGMESSAGELEN];
    char* functionName = new char[100];
    strcpy_s(functionName, 100, "GiveDetectInfoFirst\0");
    snprintf(buff, STRINGMESSAGELEN, "%d|%d", info->DetectProcess, info->DetectNetwork);
    return socketsend->SendMessageToServer(functionName, buff);
}

int Task::GiveDetectInfo() {
    char* buff = new char[STRINGMESSAGELEN];
    char* functionName = new char[40];
    strcpy_s(functionName, 40, "GiveDetectInfo");
    snprintf(buff, STRINGMESSAGELEN, "%d|%d", info->DetectProcess, info->DetectNetwork);
    return socketsend->SendMessageToServer(functionName, buff);
}


int Task::GetScanInfoData() {
    // return socketmanager->SendMessageToServer("GetScanInfoData","Ring0Process");
    return 0;
}
int Task::GiveProcessData() {
    // std::set<DWORD> m_ApiName;
    // tool.LoadApiPattern(&m_ApiName);
    // std::map<DWORD,ProcessInfoData> m_ProcessInfo;
    // std::vector<UnKnownDataInfo> m_UnKnownData;
    // MemProcess * m_MemPro = new MemProcess;
    // tool.ScanRunNowProcess(this,&m_ProcessInfo,&m_ApiName,&m_UnKnownData);
    // delete m_MemPro;


    // printf("GiveProcessData");
    // Process process;
    // int ret = 1;
    // char buff[STRDATAPACKETSIZE];
    // buff[0] = '\0';
    // int count = 0;

    // for (const auto& it : process.ProcessInfoMap) {
    //     char temp[DATASTRINGMESSAGELEN];
    //     std::sprintf(temp, "%d|%d|%s|%lld|%s|%lld|%s|%s|||\n",
    //              it.second.pid,
    //              it.second.ppid,
    //              it.second.process_name,
    //              it.second.start_time,
    //              it.second.parent_process_name,
    //              it.second.parent_start_time,
    //              it.second.path,
    //              it.second.username);
    //     std::strcat(buff, temp);
    //     count += 1;
    //     if(count>30) 
    //         if(!SendDataToServer("GiveProcessData",buff)){
    //             perror("GiveProcessData failed");
    //             ret = 0;
    //             break;
    //         } else {
    //             count = 0;
    //             std::memset(buff, 0, sizeof(buff));
    //         }
    // }

    // if(!SendDataToServer("GiveProcessData",buff)) {
    //     ret = 0;
    //     perror("GiveProcessData failed");
    // }

    // if(!GiveProcessDataEnd()) {
    //     ret = 0;
    //     perror("GiveProcessDataEnd failed");
    // }

    // int ret = 0;

    // return ret;
    return 0;
}

int Task::GiveProcessDataEnd() {
    // return socketmanager->SendDataToServer("GiveProcessDataEnd","");
    return 0;
}
int Task::GiveScanProgress() { return 0; }
int Task::GiveDriveInfo() { return 0; }
int Task::Explorer() { return 0; }
int Task::GiveExplorerData() {
    return 0;

}
int Task::GiveExplorerEnd() { return 0; }
int Task::CollectInfo() { return 0; }
int Task::GiveCollectProgress() { return 0; }
int Task::GiveCollectDataInfo() { return 0; }
int Task::GiveCollectData() { return 0; }
int Task::GiveCollectDataEnd() { return 0; }


int Task::OpenCheckthread(StrPacket* udata) {
    // strcpy(UUID,udata->csMsg);
    // GiveDetectInfoFirst();

    // std::thread CheckConnectThread(&SocketManager::CheckConnect, this);
    // CheckConnectThread.join();

    // store key into registry

    return GiveDetectInfoFirst();

}

int Task::UpdateDetectMode(StrPacket* udata) {

    std::vector<std::string>DetectMode = tool.SplitMsg(udata->csMsg);
    for (int i = 0; i < DetectMode.size(); i++) {
        if (i == 0) info->DetectProcess = DetectMode[i][0] - '0';
        else if (i == 1) info->DetectNetwork = DetectMode[i][0] - '0';
        else printf("UpdateDetectMode parse failed\n");
    }
    return GiveDetectInfo();

}

int Task::GetProcessInfo(StrPacket* udata) { return 0; }
int Task::GetDrive(StrPacket* udata) { return 0; }
int Task::GetScanInfoData_(StrPacket* udata) { return 0; }
int Task::ExplorerInfo(StrPacket* udata) { return 0; }
int Task::TransportExplorer(StrPacket* udata) { return 0; }
int Task::GetCollectInfo(StrPacket* udata) { return 0; }
int Task::GetCollectInfoData(StrPacket* udata) { return 0; }
int Task::DataRight(StrPacket* udata) { return 0; }