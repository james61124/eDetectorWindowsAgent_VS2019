#pragma once
#include "AllTask.h"

class UpdateAgent : public AllTask {
public:

    UpdateAgent(Info* infoInstance, SocketSend* socketSendInstance);
    void DoTask() override;

    void WriteNewAgentToFile(char* buffer, int totalReceivedSize);
    void AgentReceive(int fileSize);
    //int ReadyUpdateAgent(char* buff);
    //int SendACK(char* buff);
    int GiveUpdateInfo();
    int GiveUpdateEnd();

private:
    const char* AESKey = "AES Encrypt Decrypt";

};
