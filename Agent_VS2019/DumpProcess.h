#pragma once
#include "AllTask.h"

class DumpProcess : public AllTask {
public:
    DumpProcess(Info* infoInstance, SocketSend* socketSendInstance, int pid);
    void DoTask() override;

    int ProcessID;

    const wchar_t* DumpProcess_txt_filename = _T("\\DumpProcess.txt");
    const wchar_t* DumpProcess_zip_filename = _T("\\DumpProcess.zip");
    std::wofstream outFile;
    HZIP *hz;
};
