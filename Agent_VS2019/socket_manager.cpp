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
    strcpy_s(InfoInstance->UUID, sizeof(InfoInstance->UUID), "58f033ed05e34ebb82bb2ac879940ddc");
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

// bool SocketManager::sendTCP(char* data, long len) {
//     int ret = send(tcpSocket, data, strlen(data), 0);
//     if (ret == SOCKET_ERROR) {
//         std::cerr << "Error sending data: " << WSAGetLastError() << std::endl;
//     } else {
//         std::cout << "Data sent successfully." << std::endl;
//     }

//     return ret;
// }

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

// int SocketManager::SendMessageToServer(char* Work,char* Mgs) {
//     StrPacket GetServerMessage;
// 	strcpy(GetServerMessage.MAC,MAC);
// 	strcpy(GetServerMessage.IP,IP);
//     strcpy(GetServerMessage.UUID,UUID);
// 	strcpy(GetServerMessage.DoWorking,Work);
// 	strcpy(GetServerMessage.csMsg,Mgs);

// 	char *buff=(char*)&GetServerMessage;
// 	SetKeys(BIT128,AESKey);
// 	EncryptBuffer((BYTE*)buff,STRPACKETSIZE);
// 	int ret= sendTCP(buff,STRPACKETSIZE);
// 	return ret;
// }

// int SocketManager::SendDataToServer(char* Work,char* Mgs) {
//     StrDataPacket GetServerMessage;
// 	strcpy(GetServerMessage.MAC,MAC);
// 	strcpy(GetServerMessage.IP,IP);
//     strcpy(GetServerMessage.UUID,UUID);
// 	strcpy(GetServerMessage.DoWorking,Work);
// 	strcpy(GetServerMessage.csMsg,Mgs);

// 	char *buff=(char*)&GetServerMessage;
// 	SetKeys(BIT128,AESKey);
// 	EncryptBuffer((BYTE*)buff,STRDATAPACKETSIZE);
// 	int ret= sendTCP(buff,STRDATAPACKETSIZE);
// 	return ret;
// }

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


// void SocketManager::CheckConnect() {printf("haha\n");}
// int SocketManager::GiveDetectInfoFirst() {printf("haha\n");}
// int SocketManager::GiveDetectInfo() {printf("haha\n");}
// // int SocketManager::Process() {printf("haha\n");}
// int SocketManager::GetScanInfoData() {printf("haha\n");}
// int SocketManager::GiveProcessData() {printf("haha\n");}
// int SocketManager::GiveProcessDataEnd() {printf("haha\n");}
// void SocketManager::GiveScanProgress(){printf("hehe\n");}
// void SocketManager::GiveDriveInfo(){printf("hehe\n");}
// int SocketManager::Explorer(){printf("hehe\n");}
// int SocketManager::GiveExplorerData() {printf("haha\n");}
// void SocketManager::GiveExplorerEnd(){printf("hehe\n");}
// void SocketManager::CollectInfo(){printf("hehe\n");}
// void SocketManager::GiveCollectProgress(){printf("hehe\n");}
// void SocketManager::GiveCollectDataInfo(){printf("hehe\n");}
// void SocketManager::GiveCollectData(){printf("hehe\n");}
// void SocketManager::GiveCollectDataEnd(){printf("hehe\n");}

// void SocketManager::OpenCheckthread(StrPacket* udata) {printf("haha\n");}
// void SocketManager::UpdateDetectMode(StrPacket* udata) {printf("haha\n");}
// void SocketManager::GetProcessInfo(StrPacket* udata) {printf("haha\n");}
// void SocketManager::GetDrive(StrPacket* udata) {printf("haha\n");}
// void SocketManager::GetScanInfoData_(StrPacket* udata) {printf("haha\n");}
// void SocketManager::ExplorerInfo(StrPacket* udata){printf("hehe\n");}
// void SocketManager::TransportExplorer(StrPacket* udata){printf("hehe\n");}
// void SocketManager::GetCollectInfo(StrPacket* udata){printf("hehe\n");}
// void SocketManager::GetCollectInfoData(StrPacket* udata){printf("hehe\n");}
// void SocketManager::DataRight(StrPacket* udata){return;}



