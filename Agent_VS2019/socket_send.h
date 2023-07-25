#include "info.h"
#include "caes.h"

#include <iostream>

class SocketSend {
public:
    SocketSend(Info* infoInstance);
    const char* AESKey = "AES Encrypt Decrypt";
    Info* info;
    bool sendTCP(char* data, long len);
    int SendDataToServer(char* Work, char* Mgs);
    int SendMessageToServer(char* Work, char* Mgs);
};