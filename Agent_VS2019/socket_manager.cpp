#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "socket_manager.h"
#include "caes.h"
#include <iostream>
//#include <unistd.h>
#include <string>
#include <cstring>
#include <future>




SocketManager::SocketManager(int port, int detect_port, Info* infoInstance, SocketSend* socketSendInstance) {

    Port = port;
    DetectPort = detect_port;
    InfoInstance = infoInstance;
    task = new Task(infoInstance, socketSendInstance);
    InfoInstance->tcpSocket = &tcpSocket;

    // strcpy(UUID,key);

    if (!connectTCP("192.168.200.153", 1988)) perror("connection failed\n");
    else printf("connect success\n");
    getSystemInfo();

    // until the end
    // closesocket(tcpSocket);
    // WSACleanup();

}

void SocketManager::getSystemInfo() {
    strcpy_s(InfoInstance->MAC, sizeof(InfoInstance->MAC), "08:00:27:4e:66:ef");
    strcpy_s(InfoInstance->IP, sizeof(InfoInstance->IP), "127.0.0.1");
    strcpy_s(InfoInstance->UUID, sizeof(InfoInstance->UUID), "fe369d13f9f44565bad2ef70d8a328a0");
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

    if (connect(tcpSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Error connecting to server: " << WSAGetLastError() << std::endl;
        closesocket(tcpSocket);
        WSACleanup();
        return 1;
    }

    InfoInstance->tcpSocket = &tcpSocket;

    return true;
}

void SocketManager::receiveTCP() {
    printf("receive thread open\n");
    while (true) {
        char buff[STRPACKETSIZE];
        int ret = recv(tcpSocket, buff, sizeof(buff), 0);
        if (ret == SOCKET_ERROR) {
            std::cerr << "Error receiving data: " << WSAGetLastError() << std::endl;
            return;
        }

        SetKeys(BIT128, AESKey);
        DecryptBuffer((BYTE*)buff, STRPACKETSIZE);
        StrPacket* udata;
        udata = (StrPacket*)buff;
        if (!HandleTaskFromServer(udata)) break;
    }


}

void SocketManager::closeTCP() {
    if (tcpSocket != -1) closesocket(tcpSocket);
}

void SocketManager::HandleTaskToServer(std::string functionName) {
    
    if (task->functionMap.count(functionName) > 0) {
        int ret;
        std::any argument;
        ret = task->functionMap[functionName](task, argument);
        if (!ret) std::cout << functionName << " send failed" << std::endl;
    }
    else std::cout << functionName << " Function not found" << std::endl;
}

int SocketManager::HandleTaskFromServer(StrPacket* udata) {
    printf("receive: %s, %s\n", udata->DoWorking, udata->csMsg);
    int ret = 0;
    if (task->functionFromServerMap.count(udata->DoWorking) > 0) ret = task->functionFromServerMap[udata->DoWorking](task, udata);
    else std::cout << "Function not found" << std::endl;
    return ret;
}

// void SocketManager::startThread(const std::string& key, std::string functionName) {
//     // threadMap[key] = std::thread(HandleTaskToServer(functionName), key);
//     threadMap[key] = std::thread([this, functionName, key]() {
//             HandleTaskToServer(functionName);
//         });
// }




