#pragma once
#pragma comment(lib, "vssapi.lib")

#include <unordered_map>
#include <functional>
#include <any>
#include <set>
#include <map>
#include <fstream>
#include <sstream>

#include <filesystem>

#include <objbase.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <comdef.h>
#include <ctime>
#include <chrono>

#include "tools.h"
#include "socket_send.h"
#include "MemProcess.h"

//#include "File.h"
//#include "NTFSSearchCore.h"
//#include "sqlite3.h"
//#include "Collect.h"



class AllTask {
public:
	virtual void DoTask() = 0;
	int SendDataPacketToServer(const char* function, char* buff, SOCKET* tcpSocket);
	int SendMessagePacketToServer(const char* function, char* buff);
	void SendFileToServer(const char* feature, const TCHAR* FileName, SOCKET* tcpSocket);

	SocketSend* socketsend;
	Info* info;
	Log log;
	Tool tool;

	TCHAR* filename;
	TCHAR* zip_filename;

private:
	
	
};
