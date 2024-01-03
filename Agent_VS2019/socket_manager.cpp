#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "socket_manager.h"
#include "caes.h"
#include <iostream>
//#include <unistd.h>
#include <string>
#include <cstring>
#include <future>



SocketManager::SocketManager(std::string& serverIP, int port, Info* infoInstance, SocketSend* socketSendInstance) {

    Port = port;
    InfoInstance = infoInstance;
    task = new Task(infoInstance, socketSendInstance);
    InfoInstance->tcpSocket = &tcpSocket;
    InfoInstance->Port = port;
    strcpy_s(InfoInstance->ServerIP, sizeof(InfoInstance->ServerIP), serverIP.c_str());


    // strcpy(UUID,key);
    
    // 192.168.200.153

    if (!connectTCP(serverIP, port)) perror("connection failed\n");
    else printf("connect success\n");

    getSystemInfo();

    // until the end
    // closesocket(tcpSocket);
    // WSACleanup();

}

void SocketManager::getSystemInfo() {
    GetIPAndMAC(InfoInstance->MAC, InfoInstance->IP, InfoInstance->ServerIP);
}

bool SocketManager::connectTCP(const std::string& serverIP, int port) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Failed to initialize Winsock." << std::endl;
        return 1;
    }

    tcpSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcpSocket == INVALID_SOCKET) {
        std::cerr << "Error creating TCP socket: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(serverIP.c_str());
    //serverAddr.sin_addr.s_addr = inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);

    while (connect(tcpSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    //sockaddr_in localAddr;
    //int len = sizeof(localAddr);
    //if (getsockname(tcpSocket, (struct sockaddr*)&localAddr, &len) == 0) {
    //    std::cout << "Connected from local port: " << ntohs(localAddr.sin_port) << std::endl;
    //}

    InfoInstance->tcpSocket = &tcpSocket;
    return true;
}
void SocketManager::receiveTCP() {
    Log log;
    printf("Receive Thread Enabled\n");
    int FirstTime = 0;
    while (true) {
        if (FirstTime) {
            printf("wait for server to reconnect...");
            log.logger("Info", "wait for server to reconnect...\n");

            InfoInstance->DetectProcess = 0;
            InfoInstance->DetectNetwork = 0;

            for (auto& pair : InfoInstance->processMap) {
                if (pair.first != "Log" && pair.second != 0) {
                    string LogMsg = "kill " + pair.first + " process";
                    log.logger("Debug", LogMsg);
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pair.second);
                    if (hProcess) {
                        TerminateProcess(hProcess, 0);
                        CloseHandle(hProcess);
                    }
                }
            }

            closesocket(*InfoInstance->tcpSocket);
            if (!connectTCP(InfoInstance->ServerIP, InfoInstance->Port)) perror("connection failed\n");
            else log.logger("Info", "server reconnect success");
            HandleTaskToServer("GiveInfo");
        }

        FirstTime = 1;
        while (true) {
            char buff[STRPACKETSIZE];
            int ret = recv(tcpSocket, buff, sizeof(buff), 0);
            if (ret == SOCKET_ERROR) {
                std::cerr << "Error receiving data: " << WSAGetLastError() << std::endl;
                break;
            }

            SetKeys(BIT128, AESKey);
            DecryptBuffer((BYTE*)buff, STRPACKETSIZE);
            StrPacket* udata;
            udata = (StrPacket*)buff;

            cout << "Receive: " << udata->DoWorking << endl;

            std::string Task(udata->DoWorking);
            std::string LogMsg = "Receive: " + Task;
            log.logger("Info", LogMsg);

            if (!HandleTaskFromServer(udata)) break;
        }
    }
    
    printf("Receive Thread Close\n");


}
void SocketManager::closeTCP() {
    if (tcpSocket != -1) closesocket(tcpSocket);
}
void SocketManager::HandleTaskToServer(std::string functionName) {
    
    if (task->functionMap.count(functionName) > 0) {
        int ret;
        std::any argument;
        ret = task->functionMap[functionName](task, argument);
        if (!ret) {
            std::cout << functionName << " send failed" << std::endl;
            log.logger("Error", functionName + " send failed");
        }
    }
    else { 
        log.logger("Error", functionName + " Function not found");
        std::cout << functionName << " Function not found" << std::endl; 
    }
}
int SocketManager::HandleTaskFromServer(StrPacket* udata) {
    //printf("receive: %s, %s\n", udata->DoWorking, udata->csMsg);
   /* std::string LogMessage = "receive -> " + std::string(udata->DoWorking) + " : " + std::string(udata->csMsg) + "";
    tool.log(LogMessage);*/
    //std::cout << "Thread ID: " << std::this_thread::get_id() << std::endl;

    //UpdateTaskStatus(udata->DoWorking, std::this_thread::get_id());

    int ret = 0;
    if (task->functionFromServerMap.count(udata->DoWorking) > 0) {
        ret = task->functionFromServerMap[udata->DoWorking](task, udata);
    }
    else std::cout << "Function not found" << std::endl;

    //FinishTask(udata->DoWorking);


    return ret;
}


//bool SocketManager::CheckTaskStatus(std::string task) {
//    std::lock_guard<std::mutex> lock(mapMutex);
//    auto it = threadMap.find(task);
//    if (it != threadMap.end()) {
//        return true; // task is doing
//    }
//    else {
//        return false; // task isn't doing
//    }
//}
//void SocketManager::UpdateTaskStatus(std::string task, std::thread::id thread_id) {
//    std::lock_guard<std::mutex> lock(mapMutex);
//    auto it = threadMap.find(task);
//    if (it != threadMap.end()) {
//        it->second = thread_id;
//    }
//}
//void SocketManager::FinishTask(std::string task) {
//    std::lock_guard<std::mutex> lock(mapMutex);
//    auto it = threadMap.find(task);
//    if (it != threadMap.end()) {
//        threadMap.erase(task);
//    }
//}



// void SocketManager::startThread(const std::string& key, std::string functionName) {
//     // threadMap[key] = std::thread(HandleTaskToServer(functionName), key);
//     threadMap[key] = std::thread([this, functionName, key]() {
//             HandleTaskToServer(functionName);
//         });
// }




