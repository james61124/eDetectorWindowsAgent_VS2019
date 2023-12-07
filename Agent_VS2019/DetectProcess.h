#pragma once
#include "AllTask.h"

class DetectProcess : public AllTask {
public:

    DetectProcess(Info* infoInstance, SocketSend* socketSendInstance);
    void DoTask() override;

    int DetectProcessRisk(int pMainProcessid, bool IsFirst, set<DWORD>* pApiName, SOCKET* tcpSocket);
    void SendProcessDataToServer(vector<ProcessInfoData>* pInfo, SOCKET* tcpSocket);


};