#pragma once

#include "AllTask.h"
#include "Collect.h"

class CollectInfo : public AllTask {
public:
    
    CollectInfo(Info* infoInstance, SocketSend* socketSendInstance, int input_i, int input_iLen);
    void DoTask() override;

    int i;
    int iLen;
};
