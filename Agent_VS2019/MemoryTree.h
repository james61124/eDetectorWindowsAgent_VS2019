#pragma once
#include "AllTask.h"

class MemoryTree : public AllTask {
public:
    MemoryTree(Info* infoInstance, SocketSend* socketSendInstance);
    void DoTask() override;

    TCHAR* MemoryTree_txt;
    TCHAR* MemoryTree_zip;
    const wchar_t* MemoryTree_txt_filename = _T("\\MemoryTree.txt");
    const wchar_t* MemoryTree_zip_filename = _T("\\MemoryTree.zip");
    std::wofstream outFile;
};