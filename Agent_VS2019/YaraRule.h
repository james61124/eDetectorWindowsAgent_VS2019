#pragma once

#include "AllTask.h"
#include "YaraManager.h"

//#include <yara.h>
#include "unzip.h"


class YaraRule : public AllTask {
public:

    YaraRule(Info* infoInstance, SocketSend* socketSendInstance);
    void DoTask() override;

    int GiveYaraRuleInfo();
    void YaraRuleReceive(int fileSize);
    void WriteYaraRuleToFile(char* buffer, int totalReceivedSize);
    //void SysExplorerSearch(TCHAR* m_Path, unsigned int& FileIndex, YaraManger* yaraManger, std::string task);

private:
    const char* AESKey = "AES Encrypt Decrypt";

};