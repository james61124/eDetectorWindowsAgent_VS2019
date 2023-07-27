#include "info.h"

Info::Info() {
    DetectProcess = 0;
    DetectNetwork = 0;
    Port = 1234;
    DetectPort = 1235;
    tcpSocket = new SOCKET;
    strcpy_s(MAC, sizeof(MAC), "08:00:27:4e:66:ef");
    strcpy_s(IP, sizeof(IP), "127.0.0.1");
    strcpy_s(UUID, sizeof(UUID), "fe369d13f9f44565bad2ef70d8a328a0");
}