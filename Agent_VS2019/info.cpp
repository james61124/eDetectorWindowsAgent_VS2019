#include "info.h"

Info::Info() {
    DetectProcess = 0;
    DetectNetwork = 0;
    Port = 1988;
    DetectPort = 1989;
    tcpSocket = new SOCKET;

    char* KeyNum = new char[36];
    strcpy_s(KeyNum, 36, "NoKey");
    GetThisClientKey(KeyNum);
    strcpy_s(UUID, 36, KeyNum);

    //GetIPAndMAC(MAC, IP, ServerIP);
    //strcpy_s(MAC, sizeof(MAC), "08:00:27:4e:66:ef");
    //strcpy_s(IP, sizeof(IP), "127.0.0.1");
}