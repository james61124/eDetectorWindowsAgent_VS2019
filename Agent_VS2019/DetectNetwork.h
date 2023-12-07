#pragma once
#include "AllTask.h"

class DetectNetwork : public AllTask {
public:

    DetectNetwork(Info* infoInstance, SocketSend* socketSendInstance, int pid);
    void DoTask() override;

    void SendNetworkDetectToServer(vector<string>* pInfo);

    int pMainProcessid;

};