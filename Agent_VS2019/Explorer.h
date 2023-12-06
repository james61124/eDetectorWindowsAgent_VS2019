#pragma once

#include "AllTask.h"
#include "NTFSSearchCore.h"

class Explorer : public AllTask {
public:

    Explorer(Info* infoInstance, SocketSend* socketSendInstance, char* input_drive, char* input_filesystem);
    void DoTask() override;

    int NTFSSearch(wchar_t vol_name, char* pMAC, char* pIP, SOCKET* tcpSocket, char* Drive, char* FileSystem);
    void SysExplorerSearch(TCHAR* m_Path, unsigned int FatherNum, unsigned int& FileIndex, char* TmpSend, unsigned int& m_ProgressCount, unsigned int& m_Count);

    char* Drive;
    char* FileSystem;
};