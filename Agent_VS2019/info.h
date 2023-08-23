#pragma once
#ifndef INFO_H
#define INFO_H

#include "StrPacket.h"
#include <winsock2.h>

class Info {
public:
    Info();

    int Port;
    int DetectPort;
    char MAC[MACLEN];
    char IP[IPLEN];
    char UUID[UUIDLEN];

    int DetectProcess = 0;
    int DetectNetwork = 0;

    char ServerIP[IPLEN];

    SOCKET* tcpSocket;

};

#endif