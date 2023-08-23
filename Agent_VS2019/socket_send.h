#ifndef SOCKETSEND_H
#define SOCKETSEND_H

#include "info.h"
#include "caes.h"
#include "tools.h"

#include <iostream>

class SocketSend {
public:
    SocketSend();
    SocketSend(Info* infoInstance);

    int Port;
    int DetectPort;
    char MAC[MACLEN];
    char IP[IPLEN];
    char UUID[UUIDLEN];

    const char* AESKey = "AES Encrypt Decrypt";
    Info* info;
    bool sendTCP(char* data, long len, SOCKET* tcpSocket);
    int SendDataToServer(char* Work, char* Mgs, SOCKET* tcpSocket);
    int SendMessageToServer(char* Work, char* Mgs, SOCKET* tcpSocket);

    int receiveTCP(SOCKET* tcpSocket);

private:
    Tool tool;
};

#endif