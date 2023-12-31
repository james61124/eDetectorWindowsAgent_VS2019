#ifndef SOCKETMANAGER_H
#define SOCKETMANAGER_H
#pragma comment(lib, "ws2_32.lib")


#include <string>
#include <map>
#include <unordered_map>
#include <functional>
#include <any>


#include <vector>
#include <thread>
#include <winsock2.h>
#include <WS2tcpip.h>
#include <mutex>

#include "task.h"
#include "Log.h"

#define MACLEN 20
#define IPLEN 20
#define UUIDLEN 36

class SocketManager {
public:
    SocketManager(std::string& serverIP, int port, Info* infoInstance, SocketSend* socketSendInstance);
    Info* InfoInstance;
    SOCKET tcpSocket;

    std::mutex mapMutex;

    int Port;
    int DetectPort;
    char MAC[MACLEN];
    char IP[IPLEN];
    char UUID[UUIDLEN];
    const char* AESKey = "AES Encrypt Decrypt";
    int DetectProcess = 0;
    int DetectNetwork = 0;

    // std::unordered_map<std::string, std::thread> threadMap;
    // void startThread(const std::string& key, std::string functionName);
    std::unordered_map<std::string, DWORD> processMap;
    

    void getSystemInfo();
    bool connectTCP(const std::string& serverIP, int port);
    void receiveTCP();
    void closeTCP();

    void HandleTaskToServer(std::string functionName);
    int HandleTaskFromServer(StrPacket* udata);

    bool CheckTaskStatus(std::string task);
    void UpdateTaskStatus(std::string task, std::thread::id thread_id);
    void FinishTask(std::string task);

    Task* task;



private:
    Tool tool;
    Log log;
    

};

#endif
